use crate::config::{ProxyConfig, ProxyEgress, ProxyRule};
use crate::error::{FnoxError, Result};
use base64::Engine;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use indexmap::IndexMap;
use ipnet::IpNet;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, Issuer, KeyPair};
use reqwest::Method;
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_HEADER: &str = "authorization";
/// Clients such as git first connect without credentials and retry after a
/// 407 on the same connection; give up after this many unauthenticated tries.
const MAX_AUTH_ATTEMPTS: usize = 3;

fn proxy_error(message: impl Into<String>) -> FnoxError {
    FnoxError::Config(format!("proxy: {}", message.into()))
}

/// Where in a request a rule allows its placeholder to be replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Lowercased header name.
    Header(String),
    /// Decoded, case-sensitive query parameter name.
    Query(String),
}

impl Target {
    fn for_rule(rule: &ProxyRule) -> Self {
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
fn domain_matches(pattern: &str, domain: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => domain
            .strip_suffix(suffix)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => pattern == domain,
    }
}

#[derive(Debug)]
struct PreparedRule {
    secret: String,
    domain: String,
    target: Target,
    methods: HashSet<String>,
    paths: Option<GlobSet>,
    placeholder: String,
    value: String,
}

impl PreparedRule {
    fn route_matches(&self, method: &str, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method))
            && self
                .paths
                .as_ref()
                .is_none_or(|patterns| patterns.is_match(path))
    }
}

#[derive(Debug)]
struct ProxyPolicy {
    egress: ProxyEgress,
    audit: bool,
    rules: Vec<PreparedRule>,
    allow_domains: Vec<String>,
    destinations: Arc<DestinationPolicy>,
    /// Password clients must send in `Proxy-Authorization`. Without it, other
    /// users' processes on a shared host could have credentials injected into
    /// their requests. It is not hidden from processes of the same user, which
    /// can read it from the child's environment.
    token: String,
    redactions: Vec<Redaction>,
    client: reqwest::Client,
}

/// Address ranges that are not reachable on the public internet: loopback,
/// private, link-local (which holds cloud metadata endpoints), shared, and
/// reserved space. IPv4-mapped IPv6 addresses are canonicalized before this
/// check, and NAT64 and 6to4 addresses are checked by their embedded IPv4.
static NON_PUBLIC_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:2::/48",
        "2001:db8::/32",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|network| network.parse().expect("static network is valid"))
    .collect()
});

fn is_public(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    if let IpAddr::V6(v6) = ip
        && let Some(embedded) = embedded_ipv4(v6)
    {
        return is_public(IpAddr::V4(embedded));
    }
    !NON_PUBLIC_NETWORKS
        .iter()
        .any(|network| network.contains(&ip))
}

/// The IPv4 address a NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address
/// reaches.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    let octets = ip.octets();
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else if segments[0] == 0x2002 {
        Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]))
    } else {
        None
    }
}

/// Which resolved addresses the proxy may connect to.
#[derive(Debug, Default)]
struct DestinationPolicy {
    allowed: Vec<IpNet>,
}

#[derive(Debug)]
enum DestinationError {
    Lookup(std::io::Error),
    /// Every address the name resolved to is non-public and not allowed.
    Refused,
}

impl std::fmt::Display for DestinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lookup(error) => write!(f, "failed to resolve destination: {error}"),
            Self::Refused => f.write_str("destination resolves to a non-public address"),
        }
    }
}

impl std::error::Error for DestinationError {}

impl DestinationPolicy {
    fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        is_public(ip) || self.allowed.iter().any(|network| network.contains(&ip))
    }

    /// Resolves `host` and keeps only addresses the proxy may connect to.
    /// Callers connect to these addresses, never to the name again, so a
    /// second lookup cannot rebind it to a refused address.
    async fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Vec<SocketAddr>, DestinationError> {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(DestinationError::Lookup)?
            .collect();
        if resolved.is_empty() {
            return Err(DestinationError::Lookup(std::io::Error::other(
                "no addresses found",
            )));
        }
        let permitted: Vec<_> = resolved
            .into_iter()
            .filter(|address| self.permits(address.ip()))
            .collect();
        if permitted.is_empty() {
            return Err(DestinationError::Refused);
        }
        Ok(permitted)
    }
}

/// Applies the destination policy to the upstream client's own lookups.
struct DestinationResolver(Arc<DestinationPolicy>);

impl reqwest::dns::Resolve for DestinationResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let destinations = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = destinations.resolve(&host, 0).await?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn parse_network(entry: &str) -> Result<IpNet> {
    entry
        .parse::<IpNet>()
        .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
        .map(|network| canonical_network(network.trunc()))
        .map_err(|_| {
            proxy_error(format!(
                "allow_private entry '{entry}' is not an IP address or CIDR block"
            ))
        })
}

/// Rewrites an IPv4-mapped IPv6 network (`::ffff:a.b.c.d/96+n`) as the IPv4
/// network it covers, since destinations are canonicalized the same way
/// before they are checked against the allow list.
fn canonical_network(network: IpNet) -> IpNet {
    if let IpNet::V6(v6) = network
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.addr().to_ipv4_mapped()
    {
        return IpNet::V4(
            ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96).expect("a prefix of 32 or less is valid"),
        );
    }
    network
}

/// A request target that is safe to log. A client sending plain HTTP through
/// the proxy uses an absolute URL as its target, which can carry a password
/// or a secret in the query string, so keep only the scheme, host, port, and
/// path. Other targets lose any query string and anything before an `@`.
fn loggable_target(target: &str) -> String {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

#[derive(Debug)]
struct Redaction {
    value: Vec<u8>,
    placeholder: Vec<u8>,
    /// Also match the value written with percent escapes (any hex case, any
    /// subset of bytes escaped) and `+` for a space, as a server may echo a
    /// query secret back in a `Location` header or body.
    lenient: bool,
}

impl Redaction {
    /// Length of the input prefix that spells this redaction's value, if any.
    fn match_len(&self, input: &[u8]) -> Option<usize> {
        if !self.lenient {
            return input.starts_with(&self.value).then_some(self.value.len());
        }
        Self::match_lenient(&self.value, input)
    }

    /// Matches `value` against `input` where each value byte may appear
    /// literally, as `+` for a space, or as a `%XX` escape. A literal `%` in the
    /// value can be either itself or the start of `%25`, so a failed branch
    /// backtracks and tries the other reading.
    fn match_lenient(value: &[u8], input: &[u8]) -> Option<usize> {
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

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    let digit = |byte: u8| char::from(byte).to_digit(16);
    Some((digit(high)? * 16 + digit(low)?) as u8)
}

fn percent_decode(input: &str) -> String {
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
    fn has_domain(&self, domain: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| domain_matches(&rule.domain, domain))
    }

    /// Whether a destination without a rule may be tunneled uninspected.
    fn allows_tunnel(&self, domain: &str) -> bool {
        self.egress == ProxyEgress::Permissive
            || self
                .allow_domains
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
    }

    /// Checks a `Proxy-Authorization` header value. Only `Basic` is accepted;
    /// the user name is ignored and the password must be the session token.
    fn accepts_credentials(&self, header: &str) -> bool {
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
    fn audit_refused(&self, method: &str, destination: &str, path: Option<&str>, reason: &str) {
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

    fn authorize(
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
                *header_value = header_value.replacen(&rule.placeholder, &rule.value, 1);
            } else {
                let name = query
                    .param_containing(&rule.placeholder)
                    .ok_or_else(outside)?;
                if !allows(&|target| matches!(target, Target::Query(allowed) if *allowed == name)) {
                    return Err(outside());
                }
                url.set_query(Some(&query.replaced(&rule.placeholder, &rule.value)));
            }
            injected.push(rule.secret.clone());
        }
        Ok(injected)
    }
}

/// A request's raw query string split on `&`, keeping the original bytes of
/// every segment so that only the substituted one is re-encoded.
struct QuerySegments {
    raw: Vec<String>,
}

impl QuerySegments {
    fn parse(query: Option<&str>) -> Self {
        Self {
            raw: query
                .map(|query| query.split('&').map(str::to_string).collect())
                .unwrap_or_default(),
        }
    }

    fn decoded(segment: &str) -> Option<(String, String)> {
        url::form_urlencoded::parse(segment.as_bytes())
            .next()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
    }

    fn occurrences(&self, placeholder: &str) -> usize {
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
    fn param_containing(&self, placeholder: &str) -> Option<String> {
        self.raw
            .iter()
            .filter_map(|segment| Self::decoded(segment))
            .find(|(_, value)| value.contains(placeholder))
            .map(|(name, _)| name)
    }

    fn replaced(&self, placeholder: &str, value: &str) -> String {
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

pub struct ProxyPlan {
    policy: Arc<ProxyPolicy>,
    pub child_env: IndexMap<String, String>,
}

/// Stops other processes of the same user, including the proxied command,
/// from reading this process's memory or environment through `/proc` or a
/// debugger. A child returns to the default when it execs a new program.
pub fn deny_inspection() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_DUMPABLE takes only integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            tracing::warn!(
                "failed to protect proxy memory from inspection: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH ignores its pid, address, and data arguments.
        if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
            tracing::warn!(
                "failed to protect proxy memory from inspection: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

pub fn validate_config(config: &ProxyConfig) -> Result<()> {
    if config.rules.is_empty() {
        return Err(proxy_error("no rules are configured"));
    }
    for rule in &config.rules {
        validate_rule(rule)?;
    }
    for domain in &config.allow_domains {
        if !is_valid_domain_pattern(domain) {
            return Err(proxy_error(format!(
                "allow_domains entry '{domain}' is not a valid domain"
            )));
        }
    }
    for entry in &config.allow_private {
        parse_network(entry)?;
    }
    Ok(())
}

impl ProxyPlan {
    pub fn new(config: &ProxyConfig, values: &IndexMap<String, String>) -> Result<Self> {
        validate_config(config)?;

        let mut placeholders = HashMap::<String, String>::new();
        let mut env_values = IndexMap::new();
        let mut prepared = Vec::new();
        let mut seen_placeholders = HashSet::new();

        for rule in &config.rules {
            let value = values
                .get(&rule.secret)
                .ok_or_else(|| proxy_error(format!("secret '{}' did not resolve", rule.secret)))?;
            if value.is_empty() {
                return Err(proxy_error(format!(
                    "secret '{}' resolved to an empty value",
                    rule.secret
                )));
            }
            let placeholder = match placeholders.get(&rule.secret) {
                Some(existing) => {
                    if let Some(configured) = &rule.placeholder
                        && configured != existing
                    {
                        return Err(proxy_error(format!(
                            "rules for '{}' use different placeholders",
                            rule.secret
                        )));
                    }
                    existing.clone()
                }
                None => {
                    let placeholder = rule
                        .placeholder
                        .clone()
                        .unwrap_or_else(|| generated_placeholder(&rule.secret));
                    if placeholder.is_empty() {
                        return Err(proxy_error(format!(
                            "placeholder for '{}' cannot be empty",
                            rule.secret
                        )));
                    }
                    if placeholder == *value {
                        return Err(proxy_error(format!(
                            "placeholder for '{}' must differ from the real value",
                            rule.secret
                        )));
                    }
                    if !seen_placeholders.insert(placeholder.clone()) {
                        return Err(proxy_error("placeholders must be unique across secrets"));
                    }
                    placeholders.insert(rule.secret.clone(), placeholder.clone());
                    placeholder
                }
            };

            let env_name = rule.env.as_deref().unwrap_or(&rule.secret);
            if let Some(existing) = env_values.get(env_name)
                && existing != &placeholder
            {
                return Err(proxy_error(format!(
                    "environment variable '{env_name}' maps to multiple secrets"
                )));
            }
            env_values.insert(env_name.to_string(), placeholder.clone());

            prepared.push(PreparedRule {
                secret: rule.secret.clone(),
                domain: rule.domain.to_ascii_lowercase(),
                target: Target::for_rule(rule),
                methods: rule
                    .methods
                    .iter()
                    .map(|method| method.to_ascii_uppercase())
                    .collect(),
                paths: compile_paths(&rule.paths)?,
                placeholder,
                value: value.clone(),
            });
        }

        let placeholder_values: Vec<_> = placeholders.values().collect();
        for (index, placeholder) in placeholder_values.iter().enumerate() {
            for other in placeholder_values.iter().skip(index + 1) {
                if placeholder.contains(other.as_str()) || other.contains(placeholder.as_str()) {
                    return Err(proxy_error(
                        "one secret placeholder cannot contain another placeholder",
                    ));
                }
            }
            if values
                .values()
                .any(|value| value.contains(placeholder.as_str()))
            {
                return Err(proxy_error(
                    "a real secret value cannot contain a configured placeholder",
                ));
            }
        }

        let mut redactions: Vec<Redaction> = Vec::new();
        for rule in &prepared {
            let lenient = matches!(rule.target, Target::Query(_));
            match redactions
                .iter_mut()
                .find(|redaction| redaction.value == rule.value.as_bytes())
            {
                Some(existing) => existing.lenient |= lenient,
                None => redactions.push(Redaction {
                    value: rule.value.as_bytes().to_vec(),
                    placeholder: rule.placeholder.as_bytes().to_vec(),
                    lenient,
                }),
            }
        }
        redactions.sort_by_key(|redaction| std::cmp::Reverse(redaction.value.len()));

        let destinations = Arc::new(DestinationPolicy {
            allowed: config
                .allow_private
                .iter()
                .map(|entry| parse_network(entry))
                .collect::<Result<_>>()?,
        });

        Ok(Self {
            policy: Arc::new(ProxyPolicy {
                egress: config.egress,
                audit: config.audit,
                rules: prepared,
                allow_domains: config
                    .allow_domains
                    .iter()
                    .map(|domain| domain.to_ascii_lowercase())
                    .collect(),
                destinations: destinations.clone(),
                token: data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>()),
                redactions,
                client: reqwest::Client::builder()
                    .http1_only()
                    .no_proxy()
                    .dns_resolver(Arc::new(DestinationResolver(destinations)))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|error| {
                        proxy_error(format!("failed to build upstream client: {error}"))
                    })?,
            }),
            child_env: env_values,
        })
    }
}

fn is_valid_domain_pattern(domain: &str) -> bool {
    if domain.trim().is_empty()
        || domain.contains('/')
        || domain.contains(':')
        || domain.ends_with('.')
        || domain.chars().any(char::is_whitespace)
    {
        return false;
    }
    // `*` is only valid as a leading `*.` label, and the rest must still name a
    // registrable-looking domain so that `*.com` cannot be written by accident.
    let host = domain.strip_prefix("*.").unwrap_or(domain);
    let wildcard = host.len() != domain.len();
    !(host.contains('*')
        || host.starts_with('.')
        || host.contains("..")
        || (wildcard && !host.contains('.')))
}

fn validate_rule(rule: &ProxyRule) -> Result<()> {
    if rule.secret.trim().is_empty() {
        return Err(proxy_error("rule secret cannot be empty"));
    }
    if !is_valid_domain_pattern(&rule.domain) {
        return Err(proxy_error(format!(
            "rule for '{}' has an invalid domain '{}'",
            rule.secret, rule.domain
        )));
    }
    if rule.header.is_some() && rule.query.is_some() {
        return Err(proxy_error(format!(
            "rule for '{}' sets both header and query; choose one",
            rule.secret
        )));
    }
    if let Some(header) = &rule.header
        && (header.trim().is_empty()
            || !header
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    {
        return Err(proxy_error(format!(
            "rule for '{}' has an invalid header name",
            rule.secret
        )));
    }
    if let Some(query) = &rule.query
        && query.is_empty()
    {
        return Err(proxy_error(format!(
            "rule for '{}' has an empty query parameter name",
            rule.secret
        )));
    }
    for method in &rule.methods {
        Method::from_bytes(method.as_bytes()).map_err(|_| {
            proxy_error(format!(
                "rule for '{}' has an invalid HTTP method '{method}'",
                rule.secret
            ))
        })?;
    }
    compile_paths(&rule.paths)?;
    Ok(())
}

fn compile_paths(paths: &[String]) -> Result<Option<GlobSet>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for path in paths {
        if !path.starts_with('/') {
            return Err(proxy_error(format!(
                "path pattern '{path}' must start with '/'"
            )));
        }
        builder.add(
            GlobBuilder::new(path)
                .literal_separator(true)
                .build()
                .map_err(|error| proxy_error(format!("invalid path pattern '{path}': {error}")))?,
        );
    }
    Ok(Some(builder.build().map_err(|error| {
        proxy_error(format!("invalid path patterns: {error}"))
    })?))
}

fn generated_placeholder(secret: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(secret.as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    format!("fnox_proxy_{}", &hasher.finalize().to_hex()[..24])
}

struct CertificateAuthority {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    fn new() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| proxy_error(format!("failed to configure CA: {error}")))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fnox proxy session");
        let key = KeyPair::generate()
            .map_err(|error| proxy_error(format!("failed to generate CA key: {error}")))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|error| proxy_error(format!("failed to generate CA certificate: {error}")))?;
        Ok(Self {
            certificate,
            issuer: Issuer::new(params, key),
        })
    }

    fn server_config(&self, domain: &str) -> Result<ServerConfig> {
        let params = CertificateParams::new(vec![domain.to_string()]).map_err(|error| {
            proxy_error(format!("failed to configure TLS certificate: {error}"))
        })?;
        let key = KeyPair::generate()
            .map_err(|error| proxy_error(format!("failed to generate TLS key: {error}")))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| proxy_error(format!("failed to sign TLS certificate: {error}")))?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .map_err(|error| proxy_error(format!("failed to configure TLS: {error}")))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Where the proxy accepts clients.
pub enum ProxyListener {
    /// A random port on `127.0.0.1`.
    Loopback,
    /// A Unix socket at this path, created with mode 0600. The path must not
    /// exist and should be in a directory only the user can enter. This lets
    /// a sandboxed process reach the proxy without sharing the host's network.
    #[cfg(unix)]
    #[cfg_attr(not(test), allow(dead_code))] // used by the upcoming agent sandbox
    Unix(std::path::PathBuf),
}

/// Accepts client connections for the proxy, dropping ones it must refuse.
trait ProxyAccept: Send + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept_client(
        &self,
    ) -> impl std::future::Future<Output = std::io::Result<Option<Self::Stream>>> + Send;
}

impl ProxyAccept for TcpListener {
    type Stream = TcpStream;

    async fn accept_client(&self) -> std::io::Result<Option<TcpStream>> {
        let (stream, peer) = self.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("rejected non-loopback proxy client: {peer}");
            return Ok(None);
        }
        Ok(Some(stream))
    }
}

#[cfg(unix)]
impl ProxyAccept for tokio::net::UnixListener {
    type Stream = tokio::net::UnixStream;

    async fn accept_client(&self) -> std::io::Result<Option<tokio::net::UnixStream>> {
        Ok(Some(self.accept().await?.0))
    }
}

fn serve<L: ProxyAccept>(
    listener: L,
    policy: Arc<ProxyPolicy>,
    authority: Arc<CertificateAuthority>,
    mut shutdown: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept_client() => {
                    let stream = match accepted {
                        Ok(Some(stream)) => stream,
                        Ok(None) => continue,
                        Err(error) => {
                            tracing::warn!("proxy accept failed: {error}");
                            // Errors such as EMFILE persist; back off instead of spinning.
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let policy = policy.clone();
                    let authority = authority.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, policy, authority).await {
                            tracing::debug!("proxy connection failed: {error}");
                        }
                    });
                }
            }
        }
    })
}

/// Removes the proxy's socket file when dropped, so a failed start or a
/// proxy dropped without `shutdown` does not leave it blocking the path.
#[cfg(unix)]
struct SocketFile(std::path::PathBuf);

#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub struct RunningProxy {
    address: Option<SocketAddr>,
    /// Held only so its `Drop` removes the socket file.
    #[cfg(unix)]
    _socket_file: Option<SocketFile>,
    token: String,
    ca_file: NamedTempFile,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningProxy {
    pub async fn start(plan: ProxyPlan, listen: ProxyListener) -> Result<Self> {
        let authority = Arc::new(CertificateAuthority::new()?);
        let mut ca_file = tempfile::Builder::new()
            .prefix("fnox-proxy-ca-")
            .suffix(".pem")
            .tempfile()
            .map_err(|error| proxy_error(format!("failed to create CA file: {error}")))?;
        write_trust_bundle(&mut ca_file, &authority.certificate)?;
        ca_file
            .flush()
            .map_err(|error| proxy_error(format!("failed to flush CA file: {error}")))?;

        let policy = plan.policy;
        let token = policy.token.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut address = None;
        #[cfg(unix)]
        let mut socket_file = None;
        let task = match listen {
            ProxyListener::Loopback => {
                let listener = TcpListener::bind(("127.0.0.1", 0))
                    .await
                    .map_err(|error| proxy_error(format!("failed to bind listener: {error}")))?;
                address = Some(listener.local_addr().map_err(|error| {
                    proxy_error(format!("failed to read listener address: {error}"))
                })?);
                serve(listener, policy, authority, shutdown_rx)
            }
            #[cfg(unix)]
            ProxyListener::Unix(path) => {
                use std::os::unix::fs::PermissionsExt;
                let listener = tokio::net::UnixListener::bind(&path).map_err(|error| {
                    proxy_error(format!("failed to bind socket {}: {error}", path.display()))
                })?;
                let guard = SocketFile(path);
                std::fs::set_permissions(&guard.0, std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| {
                        proxy_error(format!("failed to restrict proxy socket: {error}"))
                    })?;
                socket_file = Some(guard);
                serve(listener, policy, authority, shutdown_rx)
            }
        };

        Ok(Self {
            address,
            #[cfg(unix)]
            _socket_file: socket_file,
            token,
            ca_file,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    /// The `HTTPS_PROXY` URL for a loopback listener, carrying the session
    /// token as the proxy password.
    pub fn proxy_url(&self) -> Option<String> {
        self.address
            .map(|address| format!("http://fnox:{}@{address}", self.token))
    }

    pub fn ca_path(&self) -> &std::path::Path {
        self.ca_file.path()
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

fn write_trust_bundle(file: &mut impl Write, authority: &Certificate) -> Result<()> {
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(proxy_error(format!(
            "failed to load native TLS roots for proxy trust bundle{}",
            native
                .errors
                .first()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )));
    }
    for error in native.errors {
        tracing::warn!("failed to load a native TLS root: {error}");
    }
    for certificate in native.certs {
        write_pem_certificate(file, certificate.as_ref())
            .map_err(|error| proxy_error(format!("failed to write native CA: {error}")))?;
    }
    file.write_all(authority.pem().as_bytes())
        .map_err(|error| proxy_error(format!("failed to write proxy CA: {error}")))
}

fn write_pem_certificate(file: &mut impl Write, der: &[u8]) -> std::io::Result<()> {
    writeln!(file, "-----BEGIN CERTIFICATE-----")?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        file.write_all(line)?;
        file.write_all(b"\n")?;
    }
    writeln!(file, "-----END CERTIFICATE-----")
}

/// The request line and `Proxy-Authorization` header of a request sent to
/// the proxy itself, before any tunnel is established.
struct ProxyRequestHead {
    method: String,
    target: String,
    authorization: Option<String>,
}

async fn read_proxy_request_head<R>(reader: &mut R) -> Result<ProxyRequestHead>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let request_line = read_line_limited(reader, MAX_HEADER_BYTES).await?;
    let mut header_bytes = request_line.len();
    let mut authorization = None;
    loop {
        let line = read_line_limited(reader, MAX_HEADER_BYTES - header_bytes).await?;
        header_bytes += line.len();
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("proxy-authorization")
        {
            authorization = Some(value.trim().to_string());
        }
    }
    let mut parts = request_line.split_whitespace();
    Ok(ProxyRequestHead {
        method: parts.next().unwrap_or_default().to_string(),
        target: parts.next().unwrap_or_default().to_string(),
        authorization,
    })
}

async fn handle_connection<S>(
    stream: S,
    policy: Arc<ProxyPolicy>,
    authority: Arc<CertificateAuthority>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut reader = BufReader::new(stream);
    let mut challenged: Option<ProxyRequestHead> = None;
    let mut attempts = 0;
    let head = loop {
        let head = match read_proxy_request_head(&mut reader).await {
            Ok(head) => head,
            Err(error) => {
                // A client that never answers the challenge was refused.
                if let Some(head) = challenged {
                    policy.audit_refused(
                        &head.method,
                        &head.target,
                        None,
                        "missing proxy credentials",
                    );
                    return Ok(());
                }
                return Err(error);
            }
        };
        match head.authorization.as_deref() {
            Some(credentials) if policy.accepts_credentials(credentials) => break head,
            Some(_) => {
                let reason = "invalid proxy credentials";
                policy.audit_refused(&head.method, &head.target, None, reason);
                write_auth_required(reader.get_mut(), true).await?;
                return Ok(());
            }
            None => {}
        }
        attempts += 1;
        if attempts >= MAX_AUTH_ATTEMPTS {
            let reason = "missing proxy credentials";
            policy.audit_refused(&head.method, &head.target, None, reason);
            write_auth_required(reader.get_mut(), true).await?;
            return Ok(());
        }
        write_auth_required(reader.get_mut(), false).await?;
        challenged = Some(head);
    };

    let mut stream = reader.into_inner();
    if head.method != "CONNECT" {
        let reason = "HTTPS CONNECT is required";
        policy.audit_refused(&head.method, &head.target, None, reason);
        write_error(&mut stream, 400, reason).await?;
        return Ok(());
    }
    let (domain, port) = parse_connect_target(&head.target)?;
    let refuse = async |stream: &mut S, status: u16, reason: &str| {
        policy.audit_refused("CONNECT", &head.target, None, reason);
        write_error(stream, status, reason).await
    };

    if !policy.has_domain(&domain) {
        if !policy.allows_tunnel(&domain) {
            return refuse(&mut stream, 403, "destination is not allowed").await;
        }
        let addresses = match policy.destinations.resolve(&domain, port).await {
            Ok(addresses) => addresses,
            Err(error @ DestinationError::Refused) => {
                return refuse(&mut stream, 403, &error.to_string()).await;
            }
            Err(error) => {
                tracing::debug!("{domain}: {error}");
                return write_error(&mut stream, 502, "failed to resolve destination").await;
            }
        };
        let mut upstream = match TcpStream::connect(&addresses[..]).await {
            Ok(upstream) => upstream,
            Err(error) => {
                tracing::debug!("failed to connect to {domain}: {error}");
                return write_error(&mut stream, 502, "failed to connect to destination").await;
            }
        };
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| proxy_error(format!("failed to establish tunnel: {error}")))?;
        tokio::io::copy_bidirectional(&mut stream, &mut upstream)
            .await
            .map_err(|error| proxy_error(format!("tunnel failed: {error}")))?;
        return Ok(());
    }
    if port != 443 {
        return refuse(&mut stream, 403, "credential injection requires port 443").await;
    }
    // The upstream client re-checks every lookup it makes, but checking here
    // first refuses IP literals (which skip DNS) and gives a clear error.
    match policy.destinations.resolve(&domain, port).await {
        Ok(_) => {}
        Err(error @ DestinationError::Refused) => {
            return refuse(&mut stream, 403, &error.to_string()).await;
        }
        Err(error) => {
            tracing::debug!("{domain}: {error}");
            return write_error(&mut stream, 502, "failed to resolve destination").await;
        }
    }

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| proxy_error(format!("failed to establish TLS tunnel: {error}")))?;
    let acceptor = TlsAcceptor::from(Arc::new(authority.server_config(&domain)?));
    let mut tls = acceptor
        .accept(stream)
        .await
        .map_err(|error| proxy_error(format!("client TLS handshake failed: {error}")))?;
    let result = proxy_http_request(&mut tls, &domain, &policy).await;
    if let Err(error) = tls.shutdown().await {
        if result.is_ok() {
            return Err(proxy_error(format!(
                "failed to shut down client TLS connection: {error}"
            )));
        }
        tracing::debug!("failed to shut down client TLS connection: {error}");
    }
    result
}

fn parse_connect_target(target: &str) -> Result<(String, u16)> {
    let (domain, port) = target
        .rsplit_once(':')
        .ok_or_else(|| proxy_error("CONNECT target must include a port"))?;
    let domain = domain.trim_matches(['[', ']']).to_ascii_lowercase();
    if domain.is_empty() {
        return Err(proxy_error("CONNECT target has an empty domain"));
    }
    let port = port
        .parse()
        .map_err(|_| proxy_error("CONNECT target has an invalid port"))?;
    Ok((domain, port))
}

struct HttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn proxy_http_request<S>(stream: &mut S, domain: &str, policy: &ProxyPolicy) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match read_http_request(stream).await {
        Ok(request) => request,
        Err(error) => {
            write_error(stream, 400, &error.to_string()).await?;
            return Ok(());
        }
    };
    let refuse = async |stream: &mut S, path: &str, reason: &str| {
        policy.audit_refused(&request.method, domain, Some(path), reason);
        write_error(stream, 403, reason).await
    };
    if has_ambiguous_path_encoding(&request.target) {
        let path = request.target.split('?').next().unwrap_or_default();
        return refuse(stream, path, "request path contains an ambiguous encoding").await;
    }
    let mut url = match reqwest::Url::parse(&format!("https://{domain}{}", request.target)) {
        Ok(url) => url,
        Err(error) => {
            write_error(
                stream,
                400,
                &format!("request used an invalid URL: {error}"),
            )
            .await?;
            return Ok(());
        }
    };
    let path = url.path().to_string();
    if url.host_str() != Some(domain) {
        return refuse(
            stream,
            &path,
            "request URL changed the approved destination",
        )
        .await;
    }
    let mut headers = request.headers;
    let injected = match policy.authorize(domain, &request.method, &mut url, &mut headers) {
        Ok(injected) => injected,
        Err(error) => return refuse(stream, &path, &error.to_string()).await,
    };

    if policy.audit {
        tracing::info!(
            target: "fnox::proxy",
            method = %request.method,
            domain,
            path = %path,
            injected = ?injected,
            "proxied request"
        );
    }

    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            write_error(stream, 400, "request used an invalid HTTP method").await?;
            return Ok(());
        }
    };
    let mut outbound = policy
        .client
        .request(method, url)
        .header("accept-encoding", "identity")
        .body(request.body);
    for (name, value) in headers {
        if is_hop_by_hop_header(&name) || name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        outbound = outbound.header(&name, &value);
    }
    let mut response = match outbound.send().await {
        Ok(response) => response,
        Err(error) => {
            // reqwest errors embed the request URL, which can carry a query secret.
            tracing::debug!("upstream request failed: {}", error.without_url());
            write_error(stream, 502, "upstream request failed").await?;
            return Ok(());
        }
    };
    let status = response.status();
    let response_headers = response.headers().clone();
    if response_headers
        .get("content-encoding")
        .is_some_and(|value| value != "identity")
    {
        write_error(
            stream,
            502,
            "upstream returned an encoded response that cannot be safely redacted",
        )
        .await?;
        return Ok(());
    }
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                tracing::debug!("failed to read upstream response: {}", error.without_url());
                write_error(stream, 502, "failed to read upstream response").await?;
                return Ok(());
            }
        };
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(body.len()) {
            write_error(stream, 502, "upstream response exceeded proxy limit").await?;
            return Ok(());
        }
        body.extend_from_slice(&chunk);
    }
    redact_values(&mut body, &policy.redactions);

    let reason = status.canonical_reason().unwrap_or("");
    let mut head = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
    for (name, value) in &response_headers {
        if is_hop_by_hop_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            let value = redact_string(value, &policy.redactions);
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(&value);
            head.push_str("\r\n");
        }
    }
    head.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| proxy_error(format!("failed to write client response: {error}")))?;
    stream
        .write_all(&body)
        .await
        .map_err(|error| proxy_error(format!("failed to write client response: {error}")))?;
    Ok(())
}

fn has_ambiguous_path_encoding(target: &str) -> bool {
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

async fn read_http_request<S>(stream: &mut S) -> Result<HttpRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let request_line = read_line_limited(&mut reader, MAX_HEADER_BYTES).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || !target.starts_with('/') || !version.starts_with("HTTP/1.") {
        return Err(proxy_error("invalid HTTP request line"));
    }

    let mut headers = Vec::new();
    let mut header_bytes = request_line.len();
    let mut content_length = None;
    loop {
        let line = read_line_limited(&mut reader, MAX_HEADER_BYTES - header_bytes).await?;
        header_bytes += line.len();
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| proxy_error("invalid HTTP header"))?;
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .parse()
                .map_err(|_| proxy_error("invalid content-length"))?;
            if content_length.replace(length).is_some() {
                return Err(proxy_error("duplicate content-length"));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(proxy_error(
                "chunked request bodies are not supported in this first proxy version",
            ));
        }
        headers.push((name.trim().to_string(), value));
    }
    if content_length.is_none() && matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        return Err(proxy_error(format!(
            "{method} requests must include content-length"
        )));
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(proxy_error("request body exceeded proxy limit"));
    }
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| proxy_error(format!("failed to read request body: {error}")))?;
    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

async fn read_line_limited<R>(reader: &mut R, remaining: usize) -> Result<String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    if remaining == 0 {
        return Err(proxy_error("HTTP headers exceeded proxy limit"));
    }
    let mut line = Vec::with_capacity(remaining.min(1024));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| proxy_error(format!("failed to read HTTP request: {error}")))?;
        if available.is_empty() {
            return Err(proxy_error("connection closed while reading HTTP request"));
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if consumed > remaining.saturating_sub(line.len()) {
            return Err(proxy_error("HTTP headers exceeded proxy limit"));
        }
        let complete = available[consumed - 1] == b'\n';
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if complete {
            break;
        }
    }
    String::from_utf8(line).map_err(|_| proxy_error("HTTP request headers are not valid UTF-8"))
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn redact_values(body: &mut Vec<u8>, redactions: &[Redaction]) {
    *body = redact_bytes(body, redactions);
}

fn redact_string(value: &str, redactions: &[Redaction]) -> String {
    String::from_utf8(redact_bytes(value.as_bytes(), redactions))
        .expect("redacting UTF-8 values with UTF-8 placeholders preserves UTF-8")
}

fn redact_bytes(input: &[u8], redactions: &[Redaction]) -> Vec<u8> {
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

/// Challenges the client for proxy credentials. Unless `close` is set, the
/// connection stays open so the client can retry on it.
async fn write_auth_required<S>(stream: &mut S, close: bool) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = "proxy credentials are required\n";
    let connection = if close { "close" } else { "keep-alive" };
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm=\"fnox\"\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: {connection}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| proxy_error(format!("failed to write proxy error: {error}")))
}

async fn write_error<S>(stream: &mut S, status: u16, message: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| proxy_error(format!("failed to write proxy error: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyRule;

    fn config() -> ProxyConfig {
        ProxyConfig {
            egress: ProxyEgress::Strict,
            audit: false,
            rules: vec![ProxyRule {
                secret: "GITHUB_TOKEN".to_string(),
                domain: "api.github.com".to_string(),
                env: None,
                header: Some("authorization".to_string()),
                query: None,
                methods: vec!["GET".to_string()],
                paths: vec!["/repos/example/**".to_string()],
                placeholder: Some("ghp_placeholder".to_string()),
            }],
            ..ProxyConfig::default()
        }
    }

    fn authorize(
        plan: &ProxyPlan,
        domain: &str,
        method: &str,
        target: &str,
        headers: &mut [(String, String)],
    ) -> Result<(Vec<String>, String)> {
        let mut url = reqwest::Url::parse(&format!("https://{domain}{target}")).unwrap();
        let injected = plan.policy.authorize(domain, method, &mut url, headers)?;
        Ok((injected, url.to_string()))
    }

    fn policy() -> ProxyPlan {
        ProxyPlan::new(
            &config(),
            &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn proxy_trust_bundle_includes_native_roots_and_session_ca() {
        let running = RunningProxy::start(policy(), ProxyListener::Loopback)
            .await
            .unwrap();
        let bundle = std::fs::read_to_string(running.ca_path()).unwrap();

        assert!(
            bundle.matches("-----BEGIN CERTIFICATE-----").count() > 1,
            "trust bundle must preserve native roots and append the proxy CA"
        );

        running.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_tls_request_receives_http_error() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let policy = policy().policy;
        let task = tokio::spawn(async move {
            proxy_http_request(&mut server, "api.github.com", &policy).await
        });

        client
            .write_all(b"not an HTTP request\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        task.await.unwrap().unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "malformed requests should receive a usable HTTP error"
        );
    }

    #[test]
    fn substitutes_only_on_allowed_route_and_header() {
        let plan = policy();
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer ghp_placeholder".to_string(),
        )];
        let (injected, _) = authorize(
            &plan,
            "api.github.com",
            "GET",
            "/repos/example/fnox",
            &mut headers,
        )
        .unwrap();
        assert_eq!(injected, ["GITHUB_TOKEN"]);
        assert_eq!(headers[0].1, "Bearer real-token");
    }

    #[test]
    fn rejects_placeholder_on_wrong_method() {
        let plan = policy();
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer ghp_placeholder".to_string(),
        )];
        assert!(
            authorize(
                &plan,
                "api.github.com",
                "DELETE",
                "/repos/example/fnox",
                &mut headers,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_placeholder_in_another_header() {
        let plan = policy();
        let mut headers = vec![("X-Leak".to_string(), "ghp_placeholder".to_string())];
        assert!(
            authorize(
                &plan,
                "api.github.com",
                "GET",
                "/repos/example/fnox",
                &mut headers
            )
            .is_err()
        );
    }

    #[test]
    fn redacts_reflected_values() {
        let mut body = b"token=real-token".to_vec();
        redact_values(&mut body, &policy().policy.redactions);
        assert_eq!(body, b"token=ghp_placeholder");
    }

    #[test]
    fn redacts_overlapping_values_without_scanning_placeholders() {
        let mut config = config();
        config.rules[0].placeholder = Some("placeholder-with-token".to_string());
        config.rules.push(ProxyRule {
            secret: "SHORT_TOKEN".to_string(),
            domain: "api.github.com".to_string(),
            env: None,
            header: Some("x-api-key".to_string()),
            query: None,
            methods: vec![],
            paths: vec![],
            placeholder: Some("short-placeholder".to_string()),
        });
        let values = [
            ("GITHUB_TOKEN".to_string(), "real-token".to_string()),
            ("SHORT_TOKEN".to_string(), "token".to_string()),
        ]
        .into_iter()
        .collect();
        let plan = ProxyPlan::new(&config, &values).unwrap();
        let mut body = b"real-token token".to_vec();

        redact_values(&mut body, &plan.policy.redactions);

        assert_eq!(
            body, b"placeholder-with-token short-placeholder",
            "the longer value must match first and replacements must not be rescanned"
        );
    }

    #[test]
    fn rejects_ambiguous_paths() {
        assert!(has_ambiguous_path_encoding(
            "/repos/example/../another/private"
        ));
        assert!(has_ambiguous_path_encoding(
            "/repos/example/%2e%2e/another/private"
        ));
        assert!(has_ambiguous_path_encoding(
            "/repos/example/%252e%252e/another/private"
        ));
        assert!(!has_ambiguous_path_encoding("/repos/example/fnox?dot=.."));
    }

    #[test]
    fn sibling_rules_allow_any_matching_route() {
        let mut config = config();
        config.rules[0].paths = vec!["/repos/example/issues/**".to_string()];
        config.rules.push(ProxyRule {
            secret: "GITHUB_TOKEN".to_string(),
            domain: "api.github.com".to_string(),
            env: None,
            header: Some("authorization".to_string()),
            query: None,
            methods: vec!["GET".to_string()],
            paths: vec!["/repos/example/pulls/**".to_string()],
            placeholder: Some("ghp_placeholder".to_string()),
        });
        let plan = ProxyPlan::new(
            &config,
            &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer ghp_placeholder".to_string(),
        )];

        authorize(
            &plan,
            "api.github.com",
            "GET",
            "/repos/example/pulls/1",
            &mut headers,
        )
        .unwrap();

        assert_eq!(headers[0].1, "Bearer real-token");
    }

    #[test]
    fn single_star_path_does_not_cross_directory_boundaries() {
        let paths = compile_paths(&["/repos/example/*".to_string()])
            .unwrap()
            .unwrap();

        assert!(paths.is_match("/repos/example/fnox"));
        assert!(!paths.is_match("/repos/example/team/fnox"));
    }

    #[tokio::test]
    async fn body_bearing_methods_require_content_length() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client
            .write_all(b"POST /repos/example/fnox HTTP/1.1\r\nhost: api.github.com\r\n\r\nbody")
            .await
            .unwrap();
        drop(client);

        let error = read_http_request(&mut server).await.err().unwrap();

        assert!(error.to_string().contains("must include content-length"));
    }

    #[tokio::test]
    async fn explicit_empty_request_body_is_allowed() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client
            .write_all(
                b"POST /repos/example/fnox HTTP/1.1\r\nhost: api.github.com\r\ncontent-length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        drop(client);

        let request = read_http_request(&mut server).await.unwrap();

        assert!(request.body.is_empty());
    }

    #[test]
    fn rejects_overlapping_placeholders() {
        let mut config = config();
        config.rules.push(ProxyRule {
            secret: "OTHER_TOKEN".to_string(),
            domain: "api.github.com".to_string(),
            env: None,
            header: Some("x-api-key".to_string()),
            query: None,
            methods: vec![],
            paths: vec![],
            placeholder: Some("ghp_placeholder_suffix".to_string()),
        });
        let values = [
            ("GITHUB_TOKEN".to_string(), "real-token".to_string()),
            ("OTHER_TOKEN".to_string(), "other-token".to_string()),
        ]
        .into_iter()
        .collect();
        assert!(ProxyPlan::new(&config, &values).is_err());
    }

    fn plan_with(rules: Vec<ProxyRule>, value: &str) -> Result<ProxyPlan> {
        let config = ProxyConfig {
            egress: ProxyEgress::Strict,
            audit: false,
            rules,
            ..ProxyConfig::default()
        };
        ProxyPlan::new(
            &config,
            &[("API_KEY".to_string(), value.to_string())]
                .into_iter()
                .collect(),
        )
    }

    fn query_rule(domain: &str, query: &str) -> ProxyRule {
        ProxyRule {
            secret: "API_KEY".to_string(),
            domain: domain.to_string(),
            env: None,
            header: None,
            query: Some(query.to_string()),
            methods: vec![],
            paths: vec![],
            placeholder: Some("key_placeholder".to_string()),
        }
    }

    #[test]
    fn substitutes_in_named_query_parameter() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
        let (injected, url) = authorize(
            &plan,
            "maps.example.com",
            "GET",
            "/geocode?q=a%20b&key=key_placeholder&z=1",
            &mut [],
        )
        .unwrap();
        assert_eq!(injected, ["API_KEY"]);
        assert_eq!(
            url,
            "https://maps.example.com/geocode?q=a%20b&key=real-key&z=1"
        );
    }

    #[test]
    fn percent_encodes_substituted_query_value() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a+b/c=d&e").unwrap();
        let (_, url) = authorize(
            &plan,
            "maps.example.com",
            "GET",
            "/?key=key_placeholder",
            &mut [],
        )
        .unwrap();
        assert_eq!(url, "https://maps.example.com/?key=a%2Bb%2Fc%3Dd%26e");
    }

    #[test]
    fn rejects_query_placeholder_in_other_parameter_path_or_header() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
        for target in [
            "/?other=key_placeholder",
            "/?key_placeholder=1",
            "/key_placeholder?key=1",
        ] {
            assert!(
                authorize(&plan, "maps.example.com", "GET", target, &mut []).is_err(),
                "{target} must be refused"
            );
        }
        let mut headers = vec![("Authorization".to_string(), "key_placeholder".to_string())];
        assert!(authorize(&plan, "maps.example.com", "GET", "/", &mut headers).is_err());
    }

    #[test]
    fn rejects_query_placeholder_repeated_or_in_both_places() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
        assert!(
            authorize(
                &plan,
                "maps.example.com",
                "GET",
                "/?key=key_placeholder&key=key_placeholder",
                &mut [],
            )
            .is_err()
        );
        let mut headers = vec![("X-Key".to_string(), "key_placeholder".to_string())];
        assert!(
            authorize(
                &plan,
                "maps.example.com",
                "GET",
                "/?key=key_placeholder",
                &mut headers,
            )
            .is_err()
        );
    }

    #[test]
    fn header_rule_rejects_placeholder_in_query() {
        let plan = policy();
        assert!(
            authorize(
                &plan,
                "api.github.com",
                "GET",
                "/repos/example/fnox?token=ghp_placeholder",
                &mut [],
            )
            .is_err()
        );
    }

    #[test]
    fn query_rule_without_placeholder_leaves_url_untouched() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
        let (injected, url) =
            authorize(&plan, "maps.example.com", "GET", "/?a=1&&b", &mut []).unwrap();
        assert!(injected.is_empty());
        assert_eq!(url, "https://maps.example.com/?a=1&&b");
    }

    #[test]
    fn redacts_percent_encoded_query_secret() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a b&c").unwrap();
        let mut body = b"Location: /?key=a+b%26c and a b&c".to_vec();
        redact_values(&mut body, &plan.policy.redactions);
        assert_eq!(body, b"Location: /?key=key_placeholder and key_placeholder");
    }

    #[test]
    fn wildcard_domain_matches_exactly_one_label() {
        assert!(domain_matches("*.example.com", "a.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "a.b.example.com"));
        assert!(!domain_matches("*.example.com", "evilexample.com"));
        assert!(!domain_matches("*.example.com", ".example.com"));
        assert!(domain_matches("api.example.com", "api.example.com"));
        assert!(!domain_matches("api.example.com", "a.api.example.com"));
    }

    #[test]
    fn wildcard_rule_authorizes_matching_subdomain_only() {
        let plan = plan_with(vec![query_rule("*.example.com", "key")], "real-key").unwrap();
        assert!(plan.policy.has_domain("maps.example.com"));
        assert!(!plan.policy.has_domain("example.com"));
        assert!(!plan.policy.has_domain("a.b.example.com"));
        let (injected, _) = authorize(
            &plan,
            "maps.example.com",
            "GET",
            "/?key=key_placeholder",
            &mut [],
        )
        .unwrap();
        assert_eq!(injected, ["API_KEY"]);
        assert!(
            authorize(
                &plan,
                "example.com",
                "GET",
                "/?key=key_placeholder",
                &mut []
            )
            .is_err()
        );
    }

    #[test]
    fn validates_wildcard_domains() {
        for good in ["*.example.com", "*.s3.amazonaws.com"] {
            assert!(
                plan_with(vec![query_rule(good, "key")], "v").is_ok(),
                "{good} should be accepted"
            );
        }
        for bad in [
            "*",
            "*.",
            "*.com",
            "**.example.com",
            "a.*.example.com",
            "*example.com",
            "*..example.com",
            "api.*",
            "*.example.com.",
        ] {
            assert!(
                plan_with(vec![query_rule(bad, "key")], "v").is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_rule_with_both_header_and_query() {
        let mut rule = query_rule("api.example.com", "key");
        rule.header = Some("x-api-key".to_string());
        assert!(plan_with(vec![rule], "v").is_err());
        assert!(plan_with(vec![query_rule("api.example.com", "")], "v").is_err());
    }

    #[test]
    fn labels_rule_targets() {
        assert_eq!(target_label(&config().rules[0]), "header=authorization");
        assert_eq!(
            target_label(&query_rule("api.example.com", "key")),
            "query=key"
        );
    }

    #[test]
    fn redacts_any_percent_encoding_of_query_secret() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "a b&c/d").unwrap();
        let mut body =
            b"/?k=a%20b%26c%2Fd /?k=a%20b%26c/d /?k=a+b%26c%2fd /?k=%61%20b&c/d".to_vec();
        redact_values(&mut body, &plan.policy.redactions);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "/?k=key_placeholder /?k=key_placeholder /?k=key_placeholder /?k=key_placeholder"
        );
    }

    #[test]
    fn header_secret_redaction_stays_exact() {
        let mut body = b"token=real%2Dtoken real-token".to_vec();
        redact_values(&mut body, &policy().policy.redactions);
        assert_eq!(body, b"token=real%2Dtoken ghp_placeholder");
    }

    #[test]
    fn rejects_percent_encoded_placeholder_in_path() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "real-key").unwrap();
        for target in [
            "/key%5Fplaceholder?key=key_placeholder",
            "/key_placeholder?key=key_placeholder",
        ] {
            assert!(
                authorize(&plan, "maps.example.com", "GET", target, &mut []).is_err(),
                "{target} must be refused"
            );
        }
    }

    #[test]
    fn redacts_query_secret_containing_percent() {
        let plan = plan_with(vec![query_rule("maps.example.com", "key")], "50%off%41").unwrap();
        let mut body = b"a=50%25off%2541 b=50%off%41 c=50%25off%41 d=50%25off%2541x".to_vec();
        redact_values(&mut body, &plan.policy.redactions);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "a=key_placeholder b=key_placeholder c=key_placeholder d=key_placeholderx"
        );
    }

    #[test]
    fn classifies_non_public_addresses() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "2001:2::1",
            "3fff::1",
        ] {
            assert!(
                !is_public(address.parse().unwrap()),
                "{address} should not be public"
            );
        }
        for address in [
            "8.8.8.8",
            "140.82.112.6",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(
                is_public(address.parse().unwrap()),
                "{address} should be public"
            );
        }
    }

    #[test]
    fn allow_private_permits_listed_networks_only() {
        let destinations = DestinationPolicy {
            allowed: vec![
                parse_network("10.0.0.0/8").unwrap(),
                parse_network("127.0.0.1").unwrap(),
            ],
        };
        assert!(destinations.permits("10.9.8.7".parse().unwrap()));
        assert!(destinations.permits("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!destinations.permits("127.0.0.2".parse().unwrap()));
        assert!(!destinations.permits("169.254.169.254".parse().unwrap()));
        assert!(destinations.permits("8.8.8.8".parse().unwrap()));

        // Entries written in IPv4-mapped form match like their IPv4 form.
        let mapped = DestinationPolicy {
            allowed: vec![
                parse_network("::ffff:127.0.0.1").unwrap(),
                parse_network("::ffff:10.0.0.0/104").unwrap(),
            ],
        };
        assert!(mapped.permits("127.0.0.1".parse().unwrap()));
        assert!(mapped.permits("::ffff:127.0.0.1".parse().unwrap()));
        assert!(mapped.permits("10.200.0.1".parse().unwrap()));
        assert!(!mapped.permits("127.0.0.2".parse().unwrap()));
        assert_eq!(
            parse_network("::ffff:10.0.0.0/104").unwrap(),
            parse_network("10.0.0.0/8").unwrap()
        );
    }

    #[test]
    fn validates_allow_lists() {
        let mut config = config();
        config.allow_domains = vec!["*.com".to_string()];
        assert!(validate_config(&config).is_err());
        config.allow_domains = vec![
            "registry.npmjs.org".to_string(),
            "*.githubusercontent.com".to_string(),
        ];
        assert!(validate_config(&config).is_ok());
        config.allow_private = vec!["10.0.0.0/33".to_string()];
        assert!(validate_config(&config).is_err());
        config.allow_private = vec![
            "10.0.0.0/8".to_string(),
            "fd00::/8".to_string(),
            "192.168.1.5".to_string(),
        ];
        assert!(validate_config(&config).is_ok());
    }

    fn basic(credentials: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )
    }

    #[test]
    fn credentials_must_carry_the_session_token() {
        let plan = policy();
        let proxy = &plan.policy;
        let token = &proxy.token;
        assert_eq!(token.len(), 32);
        assert!(proxy.accepts_credentials(&basic(&format!("fnox:{token}"))));
        // The scheme is case-insensitive and the user name is ignored.
        let lowercase = basic(&format!("anyone:{token}")).replacen("Basic", "basic", 1);
        assert!(proxy.accepts_credentials(&lowercase));
        assert!(!proxy.accepts_credentials(&basic("fnox:wrong")));
        assert!(!proxy.accepts_credentials(&basic(token)));
        assert!(!proxy.accepts_credentials(&format!("Bearer {token}")));
        assert!(!proxy.accepts_credentials("Basic not-base64!"));
        assert_ne!(
            token,
            &policy().policy.token,
            "each session gets its own token"
        );
    }

    async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map_or(0, |length| length.trim().parse().unwrap());
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        head + &String::from_utf8(body).unwrap()
    }

    async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &str,
        credentials: Option<&str>,
    ) -> String {
        let authorization = credentials
            .map(|credentials| format!("Proxy-Authorization: {}\r\n", basic(credentials)))
            .unwrap_or_default();
        let head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        read_response(stream).await
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    async fn assert_echoes<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    fn tunnel_config(allow_private: &[&str]) -> ProxyConfig {
        let mut config = config();
        config.allow_domains = vec!["localhost".to_string()];
        config.allow_private = allow_private.iter().map(|s| s.to_string()).collect();
        config
    }

    fn plan_from(config: ProxyConfig) -> ProxyPlan {
        ProxyPlan::new(
            &config,
            &[("GITHUB_TOKEN".to_string(), "real-token".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn loopback_proxy_challenges_then_accepts_credentials_on_one_connection() {
        let echo = echo_server().await;
        let running = RunningProxy::start(
            plan_from(tunnel_config(&["127.0.0.1"])),
            ProxyListener::Loopback,
        )
        .await
        .unwrap();
        let url = running.proxy_url().unwrap();
        assert!(url.starts_with(&format!("http://fnox:{}@127.0.0.1:", running.token)));
        let mut stream = TcpStream::connect(running.address.unwrap()).await.unwrap();
        let target = format!("localhost:{}", echo.port());

        let challenge = connect(&mut stream, &target, None).await;
        assert!(challenge.starts_with("HTTP/1.1 407 "), "{challenge}");
        assert!(
            challenge.contains("proxy-authenticate: Basic"),
            "{challenge}"
        );
        assert!(challenge.contains("connection: keep-alive"), "{challenge}");

        let credentials = format!("fnox:{}", running.token);
        let established = connect(&mut stream, &target, Some(&credentials)).await;
        assert!(established.starts_with("HTTP/1.1 200 "), "{established}");
        assert_echoes(&mut stream).await;
        running.shutdown().await;
    }

    #[tokio::test]
    async fn proxy_refuses_bad_credentials_and_unlisted_or_private_destinations() {
        let echo = echo_server().await;
        let mut config = tunnel_config(&[]);
        config.rules[0].domain = "localhost".to_string();
        config.allow_domains = vec!["127.0.0.1".to_string()];
        let running = RunningProxy::start(plan_from(config), ProxyListener::Loopback)
            .await
            .unwrap();
        let address = running.address.unwrap();
        let credentials = format!("fnox:{}", running.token);
        let attempt = async |target: &str, credentials: Option<&str>| {
            let mut stream = TcpStream::connect(address).await.unwrap();
            connect(&mut stream, target, credentials).await
        };

        let wrong = attempt("example.com:443", Some("fnox:wrong")).await;
        assert!(wrong.starts_with("HTTP/1.1 407 "), "{wrong}");
        assert!(wrong.contains("connection: close"), "{wrong}");

        let unlisted = attempt("example.com:443", Some(&credentials)).await;
        assert!(unlisted.starts_with("HTTP/1.1 403 "), "{unlisted}");
        assert!(
            unlisted.contains("destination is not allowed"),
            "{unlisted}"
        );

        // An allowed tunnel to a loopback address is still refused.
        let tunnel = attempt(&format!("127.0.0.1:{}", echo.port()), Some(&credentials)).await;
        assert!(tunnel.starts_with("HTTP/1.1 403 "), "{tunnel}");
        assert!(tunnel.contains("non-public address"), "{tunnel}");

        // So is a rule's domain that resolves to loopback.
        let injected = attempt("localhost:443", Some(&credentials)).await;
        assert!(injected.starts_with("HTTP/1.1 403 "), "{injected}");
        assert!(injected.contains("non-public address"), "{injected}");
        running.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_listener_is_private_and_removed_on_shutdown() {
        use std::os::unix::fs::PermissionsExt;
        let echo = echo_server().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let running = RunningProxy::start(
            plan_from(tunnel_config(&["127.0.0.0/8"])),
            ProxyListener::Unix(path.clone()),
        )
        .await
        .unwrap();
        assert_eq!(running.proxy_url(), None);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let credentials = format!("fnox:{}", running.token);
        let established = connect(
            &mut stream,
            &format!("localhost:{}", echo.port()),
            Some(&credentials),
        )
        .await;
        assert!(established.starts_with("HTTP/1.1 200 "), "{established}");
        assert_echoes(&mut stream).await;

        running.shutdown().await;
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_is_removed_when_proxy_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let running = RunningProxy::start(policy(), ProxyListener::Unix(path.clone()))
            .await
            .unwrap();
        assert!(path.exists());
        drop(running);
        assert!(!path.exists());
        RunningProxy::start(policy(), ProxyListener::Unix(path.clone()))
            .await
            .expect("the path is free again")
            .shutdown()
            .await;
    }

    #[test]
    fn loggable_targets_drop_credentials_and_queries() {
        for (target, logged) in [
            (
                "http://user:pass@api.example.com/v1?token=SECRET#frag",
                "http://api.example.com/v1",
            ),
            (
                "http://api.example.com:8080/x?key=SECRET",
                "http://api.example.com:8080/x",
            ),
            ("api.example.com:443", "api.example.com:443"),
            ("user:pass@api.example.com:443", "api.example.com:443"),
            ("/path?token=SECRET", "/path"),
        ] {
            assert_eq!(loggable_target(target), logged, "{target}");
        }
    }
}
