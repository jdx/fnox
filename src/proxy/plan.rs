//! Validating `[proxy]` config and turning it into a running proxy's policy.

use super::*;

pub struct ProxyPlan {
    pub(super) policy: Arc<ProxyPolicy>,
    pub child_env: IndexMap<String, String>,
    pub(super) rules: Arc<Vec<RuleInfo>>,
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
    /// Resolve pending secrets from `session` when a request needs them
    pub fn set_session(&self, session: Arc<crate::secret_session::SecretSession>) {
        self.policy.values.set_session(session);
    }

    /// Rule secrets that have no value yet
    pub fn pending(&self) -> Vec<String> {
        self.policy.values.pending()
    }

    /// Serve MCP to `fnox mcp` relays in the child with `service`
    pub fn set_mcp_service(&self, service: McpService) {
        let _ = self.policy.mcp.set(McpSlot(service));
    }

    /// What the MCP tools may know about this proxy's rules and values
    pub fn handle(&self) -> ProxyHandle {
        ProxyHandle {
            policy: self.policy.clone(),
            rules: self.rules.clone(),
        }
    }

    pub fn new(config: &ProxyConfig, values: &IndexMap<String, String>) -> Result<Self> {
        validate_config(config)?;

        let mut placeholders = HashMap::<String, String>::new();
        let mut env_values = IndexMap::new();
        let mut prepared = Vec::new();
        let mut seen_placeholders = HashSet::new();
        let mut rule_infos = Vec::new();

        for rule in &config.rules {
            // A secret without a value is pending: see `values.rs`
            let value = values.get(&rule.secret);
            if value.is_some_and(|value| value.is_empty()) {
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
                    if value.is_some_and(|value| *value == placeholder) {
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
            rule_infos.push(RuleInfo {
                secret: rule.secret.clone(),
                env: env_name.to_string(),
                domain: rule.domain.to_ascii_lowercase(),
                placeholder: placeholder.clone(),
            });

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

        let rule_redactions = prepared
            .iter()
            .map(|rule| RuleRedaction {
                secret: rule.secret.clone(),
                placeholder: rule.placeholder.clone(),
                lenient: matches!(rule.target, Target::Query(_)),
            })
            .collect();
        let known = values
            .iter()
            .filter(|(secret, _)| prepared.iter().any(|rule| rule.secret == **secret))
            .map(|(secret, value)| (secret.clone(), value.clone()))
            .collect();

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
                values: Arc::new(SecretValues::new(rule_redactions, known)),
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
            rules: Arc::new(rule_infos),
        })
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
