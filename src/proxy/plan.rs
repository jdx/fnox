//! Validating `[proxy]` config and turning it into a running proxy's policy.

use super::*;

pub struct ProxyPlan {
    pub(super) policy: Arc<ProxyPolicy>,
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
        Self::with_pending(config, values, &HashSet::new())
    }

    /// Like `new`, but the secrets in `pending` may have no value yet. Their
    /// placeholders are refused until `ProxySecrets::set` gives them one.
    pub fn with_pending(
        config: &ProxyConfig,
        values: &IndexMap<String, String>,
        pending: &HashSet<String>,
    ) -> Result<Self> {
        validate_config(config)?;

        let mut placeholders = HashMap::<String, String>::new();
        let mut env_values = IndexMap::new();
        let mut prepared = Vec::new();
        let mut seen_placeholders = HashSet::new();
        let mut rule_values = HashMap::new();
        let mut in_query = HashSet::new();

        for rule in &config.rules {
            match values.get(&rule.secret) {
                Some(value) => {
                    rule_values.insert(rule.secret.clone(), value.clone());
                }
                None if pending.contains(&rule.secret) => {}
                None => {
                    return Err(proxy_error(format!(
                        "secret '{}' did not resolve",
                        rule.secret
                    )));
                }
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

            let target = Target::for_rule(rule);
            if matches!(target, Target::Query(_)) {
                in_query.insert(rule.secret.clone());
            }
            prepared.push(PreparedRule {
                secret: rule.secret.clone(),
                domain: rule.domain.to_ascii_lowercase(),
                target,
                methods: rule
                    .methods
                    .iter()
                    .map(|method| method.to_ascii_uppercase())
                    .collect(),
                paths: compile_paths(&rule.paths)?,
                placeholder,
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
        }
        let secrets = Arc::new(ProxySecrets::new(placeholders, in_query, rule_values)?);

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
                secrets,
                mcp: std::sync::OnceLock::new(),
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

    /// The values behind this plan's placeholders, which stay live while the
    /// proxy runs
    pub fn secrets(&self) -> Arc<ProxySecrets> {
        self.policy.secrets.clone()
    }

    /// Accept MCP sessions on the proxy's port: a client that sends
    /// `CONNECT` to [`MCP_TARGET`] with the proxy password is handed to
    /// `endpoint`. Without this, such requests are refused.
    pub fn serve_mcp(&self, endpoint: McpEndpoint) {
        let _ = self.policy.mcp.set(endpoint);
    }
}

pub(super) fn is_valid_domain_pattern(domain: &str) -> bool {
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

pub(super) fn validate_rule(rule: &ProxyRule) -> Result<()> {
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

pub(super) fn compile_paths(paths: &[String]) -> Result<Option<GlobSet>> {
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

pub(super) fn generated_placeholder(secret: &str) -> String {
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
