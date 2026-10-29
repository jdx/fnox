//! Request policy: which secret may be injected where, and redaction of
//! echoed values in responses.

use super::*;

/// Where in a request a rule allows its placeholder to be replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Target {
    /// Lowercased header name.
    Header(String),
    /// Decoded, case-sensitive query parameter name.
    Query(String),
}

impl Target {
    pub(super) fn for_rule(rule: &ProxyRule) -> Self {
        match &rule.query {
            Some(name) => Self::Query(name.clone()),
            None => Self::Header(
                rule.header
                    .as_deref()
                    .unwrap_or(DEFAULT_HEADER)
                    .to_ascii_lowercase(),
            ),
        }
    }
}

/// Describes where a rule substitutes its placeholder, such as `header=authorization`.
pub fn target_label(rule: &ProxyRule) -> String {
    match Target::for_rule(rule) {
        Target::Header(name) => format!("header={name}"),
        Target::Query(name) => format!("query={name}"),
    }
}

/// Whether a rule's `domain` pattern covers a CONNECT target. A leading `*.`
/// matches exactly one subdomain label, never the apex or deeper names.
pub(super) fn domain_matches(pattern: &str, domain: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => domain
            .strip_suffix(suffix)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => pattern == domain,
    }
}

#[derive(Debug)]
pub(super) struct PreparedRule {
    pub(super) secret: String,
    pub(super) domain: String,
    pub(super) target: Target,
    pub(super) methods: HashSet<String>,
    pub(super) paths: Option<GlobSet>,
    pub(super) placeholder: String,
}

impl PreparedRule {
    pub(super) fn route_matches(&self, method: &str, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method))
            && self
                .paths
                .as_ref()
                .is_none_or(|patterns| patterns.is_match(path))
    }
}

pub(super) struct ProxyPolicy {
    pub(super) egress: ProxyEgress,
    pub(super) audit: bool,
    pub(super) rules: Vec<PreparedRule>,
    pub(super) allow_domains: Vec<String>,
    pub(super) destinations: Arc<DestinationPolicy>,
    /// Password clients must send in `Proxy-Authorization`. Without it, other
    /// users' processes on a shared host could have credentials injected into
    /// their requests. It is not hidden from processes of the same user, which
    /// can read it from the child's environment.
    pub(super) token: String,
    pub(super) secrets: Arc<ProxySecrets>,
    /// Where `CONNECT` requests for [`MCP_TARGET`] go, when enabled
    pub(super) mcp: std::sync::OnceLock<McpEndpoint>,
    pub(super) client: reqwest::Client,
}

/// A request target that is safe to log. A client sending plain HTTP through
/// the proxy uses an absolute URL as its target, which can carry a password
/// or a secret in the query string, so keep only the scheme, host, port, and
/// path. Other targets lose any query string and anything before an `@`.
pub(super) fn loggable_target(target: &str) -> String {
    if let Ok(url) = reqwest::Url::parse(target)
        && let Some(host) = url.host_str()
    {
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        return format!("{}://{host}{port}{}", url.scheme(), url.path());
    }
    let target = target.split(['?', '#']).next().unwrap_or_default();
    target
        .rsplit_once('@')
        .map_or(target, |(_, rest)| rest)
        .to_string()
}

#[derive(Debug)]
pub(super) struct Redaction {
    pub(super) value: Vec<u8>,
    pub(super) placeholder: Vec<u8>,
    /// Also match the value written with percent escapes (any hex case, any
    /// subset of bytes escaped) and `+` for a space, as a server may echo a
    /// query secret back in a `Location` header or body.
    pub(super) lenient: bool,
}

impl Redaction {
    /// Length of the input prefix that spells this redaction's value, if any.
    pub(super) fn match_len(&self, input: &[u8]) -> Option<usize> {
        if !self.lenient {
            return input.starts_with(&self.value).then_some(self.value.len());
        }
        Self::match_lenient(&self.value, input)
    }

    /// Matches `value` against `input` where each value byte may appear
    /// literally, as `+` for a space, or as a `%XX` escape. A literal `%` in the
    /// value can be either itself or the start of `%25`, so a failed branch
    /// backtracks and tries the other reading.
    pub(super) fn match_lenient(value: &[u8], input: &[u8]) -> Option<usize> {
        let (&expected, rest_value) = match value.split_first() {
            Some(split) => split,
            None => return Some(0),
        };
        let first = *input.first()?;
        let escaped = (first == b'%' && input.len() >= 3)
            .then(|| decode_hex_pair(input[1], input[2]))
            .flatten()
            .filter(|decoded| *decoded == expected);
        if escaped.is_some()
            && let Some(rest) = Self::match_lenient(rest_value, &input[3..])
        {
            return Some(rest + 3);
        }
        if first == expected || (first == b'+' && expected == b' ') {
            return Self::match_lenient(rest_value, &input[1..]).map(|rest| rest + 1);
        }
        None
    }
}

pub(super) fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    let digit = |byte: u8| char::from(byte).to_digit(16);
    Some((digit(high)? * 16 + digit(low)?) as u8)
}

pub(super) fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(byte) = decode_hex_pair(bytes[index + 1], bytes[index + 2])
        {
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

impl ProxyPolicy {
    pub(super) fn has_domain(&self, domain: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| domain_matches(&rule.domain, domain))
    }

    /// Whether a destination without a rule may be tunneled uninspected.
    pub(super) fn allows_tunnel(&self, domain: &str) -> bool {
        self.egress == ProxyEgress::Permissive
            || self
                .allow_domains
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
    }

    /// Checks a `Proxy-Authorization` header value. Only `Basic` is accepted;
    /// the user name is ignored and the password must be the session token.
    pub(super) fn accepts_credentials(&self, header: &str) -> bool {
        let Some((scheme, encoded)) = header.trim().split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let password = decoded
            .iter()
            .position(|byte| *byte == b':')
            .map_or(&[][..], |colon| &decoded[colon + 1..]);
        constant_time_eq(password, self.token.as_bytes())
    }

    /// Logs a request the proxy turned away. Like `proxied request` lines,
    /// it never includes headers, bodies, or values, and the destination is
    /// stripped of user information and query strings.
    pub(super) fn audit_refused(
        &self,
        method: &str,
        destination: &str,
        path: Option<&str>,
        reason: &str,
    ) {
        if self.audit {
            tracing::info!(
                target: "fnox::proxy",
                method,
                destination = %loggable_target(destination),
                path = path.unwrap_or("-"),
                reason,
                "refused request"
            );
        }
    }

    pub(super) fn authorize(
        &self,
        domain: &str,
        method: &str,
        url: &mut reqwest::Url,
        headers: &mut [(String, String)],
    ) -> Result<Vec<String>> {
        let path = url.path().to_string();
        let domain_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| domain_matches(&rule.domain, domain))
            .collect();
        if domain_rules.is_empty() {
            return Err(proxy_error(format!(
                "destination '{domain}' is not allowed"
            )));
        }

        if !domain_rules
            .iter()
            .any(|rule| rule.route_matches(method, &path))
        {
            return Err(proxy_error(format!(
                "{method} {domain}{path} does not match an allowed route"
            )));
        }

        let values = self.secrets.current();
        let mut injected = Vec::new();
        let mut checked = HashSet::new();
        for rule in &domain_rules {
            if !checked.insert(rule.placeholder.as_str()) {
                continue;
            }

            let query = QuerySegments::parse(url.query());
            let in_headers: usize = headers
                .iter()
                .map(|(_, value)| value.matches(&rule.placeholder).count())
                .sum();
            let in_path = path
                .matches(&rule.placeholder)
                .count()
                .max(percent_decode(&path).matches(&rule.placeholder).count());
            let in_query = query.occurrences(&rule.placeholder);
            let occurrences = in_headers + in_path + in_query;
            if occurrences == 0 {
                continue;
            }
            if occurrences > 1 {
                return Err(proxy_error(format!(
                    "placeholder for '{}' appeared more than once",
                    rule.secret
                )));
            }
            let value = values.get(&rule.secret).ok_or_else(|| {
                proxy_error(format!(
                    "secret '{}' has no value yet; an agent can ask the user for it with the fnox MCP tool request_secret",
                    rule.secret
                ))
            })?;

            let outside = || {
                proxy_error(format!(
                    "placeholder for '{}' appeared outside its allowed route or target",
                    rule.secret
                ))
            };
            let allows = |target: &dyn Fn(&Target) -> bool| {
                domain_rules.iter().any(|candidate| {
                    candidate.placeholder == rule.placeholder
                        && candidate.route_matches(method, &path)
                        && target(&candidate.target)
                })
            };

            if in_path > 0 {
                return Err(outside());
            } else if in_headers > 0 {
                let (header_name, header_value) = headers
                    .iter_mut()
                    .find(|(_, value)| value.contains(&rule.placeholder))
                    .expect("placeholder occurrence was counted");
                if !allows(
                    &|target| matches!(target, Target::Header(name) if header_name.eq_ignore_ascii_case(name)),
                ) {
                    return Err(outside());
                }
                *header_value = header_value.replacen(&rule.placeholder, value, 1);
            } else {
                let name = query
                    .param_containing(&rule.placeholder)
                    .ok_or_else(outside)?;
                if !allows(&|target| matches!(target, Target::Query(allowed) if *allowed == name)) {
                    return Err(outside());
                }
                url.set_query(Some(&query.replaced(&rule.placeholder, value)));
            }
            injected.push(rule.secret.clone());
        }
        Ok(injected)
    }
}

/// A request's raw query string split on `&`, keeping the original bytes of
/// every segment so that only the substituted one is re-encoded.
pub(super) struct QuerySegments {
    pub(super) raw: Vec<String>,
}

impl QuerySegments {
    pub(super) fn parse(query: Option<&str>) -> Self {
        Self {
            raw: query
                .map(|query| query.split('&').map(str::to_string).collect())
                .unwrap_or_default(),
        }
    }

    pub(super) fn decoded(segment: &str) -> Option<(String, String)> {
        url::form_urlencoded::parse(segment.as_bytes())
            .next()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
    }

    pub(super) fn occurrences(&self, placeholder: &str) -> usize {
        self.raw
            .iter()
            .filter_map(|segment| Self::decoded(segment))
            .map(|(name, value)| {
                name.matches(placeholder).count() + value.matches(placeholder).count()
            })
            .sum()
    }

    /// The decoded name of the parameter whose value holds the placeholder, or
    /// `None` when the placeholder is in a parameter name instead.
    pub(super) fn param_containing(&self, placeholder: &str) -> Option<String> {
        self.raw
            .iter()
            .filter_map(|segment| Self::decoded(segment))
            .find(|(_, value)| value.contains(placeholder))
            .map(|(name, _)| name)
    }

    pub(super) fn replaced(&self, placeholder: &str, value: &str) -> String {
        self.raw
            .iter()
            .map(|segment| match Self::decoded(segment) {
                Some((_, decoded)) if decoded.contains(placeholder) => {
                    let name = segment.split_once('=').map_or(segment.as_str(), |(n, _)| n);
                    let replaced = decoded.replacen(placeholder, value, 1);
                    let encoded: String =
                        url::form_urlencoded::byte_serialize(replaced.as_bytes()).collect();
                    format!("{name}={encoded}")
                }
                _ => segment.clone(),
            })
            .collect::<Vec<_>>()
            .join("&")
    }
}

pub(super) fn has_ambiguous_path_encoding(target: &str) -> bool {
    let path = target
        .split('?')
        .next()
        .unwrap_or(target)
        .to_ascii_lowercase();
    path.contains('\\')
        || path.contains("%2e")
        || path.contains("%2f")
        || path.contains("%5c")
        || path.contains("%25")
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

pub(super) fn redact_values(body: &mut Vec<u8>, redactions: &[Redaction]) {
    *body = redact_bytes(body, redactions);
}

pub(super) fn redact_string(value: &str, redactions: &[Redaction]) -> String {
    String::from_utf8(redact_bytes(value.as_bytes(), redactions))
        .expect("redacting UTF-8 values with UTF-8 placeholders preserves UTF-8")
}

pub(super) fn redact_bytes(input: &[u8], redactions: &[Redaction]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        if let Some((redaction, length)) = redactions.iter().find_map(|redaction| {
            redaction
                .match_len(&input[offset..])
                .map(|length| (redaction, length))
        }) {
            output.extend_from_slice(&redaction.placeholder);
            offset += length;
        } else {
            output.push(input[offset]);
            offset += 1;
        }
    }
    output
}
