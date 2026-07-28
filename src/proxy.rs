use crate::config::{ProxyConfig, ProxyEgress};
use crate::error::{FnoxError, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indexmap::IndexMap;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, Issuer, KeyPair};
use reqwest::Method;
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

fn proxy_error(message: impl Into<String>) -> FnoxError {
    FnoxError::Config(format!("proxy: {}", message.into()))
}

#[derive(Debug)]
struct PreparedRule {
    secret: String,
    domain: String,
    header: String,
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
}

impl ProxyPolicy {
    fn has_domain(&self, domain: &str) -> bool {
        self.rules.iter().any(|rule| rule.domain == domain)
    }

    fn authorize(
        &self,
        domain: &str,
        method: &str,
        path: &str,
        headers: &mut [(String, String)],
    ) -> Result<Vec<String>> {
        let domain_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.domain == domain)
            .collect();
        if domain_rules.is_empty() {
            return Err(proxy_error(format!(
                "destination '{domain}' is not allowed"
            )));
        }

        if !domain_rules
            .iter()
            .any(|rule| rule.route_matches(method, path))
        {
            return Err(proxy_error(format!(
                "{method} {domain}{path} does not match an allowed route"
            )));
        }

        let mut injected = Vec::new();
        for (header_name, header_value) in headers.iter_mut() {
            for rule in &domain_rules {
                let occurrences = header_value.matches(&rule.placeholder).count();
                if occurrences == 0 {
                    continue;
                }
                if !rule.route_matches(method, path)
                    || !header_name.eq_ignore_ascii_case(&rule.header)
                {
                    return Err(proxy_error(format!(
                        "placeholder for '{}' appeared outside its allowed route or header",
                        rule.secret
                    )));
                }
                if occurrences > 1 {
                    return Err(proxy_error(format!(
                        "placeholder for '{}' appeared more than once",
                        rule.secret
                    )));
                }
                *header_value = header_value.replacen(&rule.placeholder, &rule.value, 1);
                injected.push(rule.secret.clone());
            }
        }
        Ok(injected)
    }
}

pub struct ProxyPlan {
    policy: Arc<ProxyPolicy>,
    pub child_env: IndexMap<String, String>,
}

pub fn validate_config(config: &ProxyConfig) -> Result<()> {
    if config.rules.is_empty() {
        return Err(proxy_error("no rules are configured"));
    }
    for rule in &config.rules {
        validate_rule(rule)?;
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
                header: rule.header.to_ascii_lowercase(),
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

        Ok(Self {
            policy: Arc::new(ProxyPolicy {
                egress: config.egress,
                audit: config.audit,
                rules: prepared,
            }),
            child_env: env_values,
        })
    }
}

fn validate_rule(rule: &crate::config::ProxyRule) -> Result<()> {
    if rule.secret.trim().is_empty() {
        return Err(proxy_error("rule secret cannot be empty"));
    }
    if rule.domain.trim().is_empty()
        || rule.domain.contains('/')
        || rule.domain.contains(':')
        || rule.domain.ends_with('.')
        || rule.domain.chars().any(char::is_whitespace)
    {
        return Err(proxy_error(format!(
            "rule for '{}' has an invalid domain",
            rule.secret
        )));
    }
    if rule.header.trim().is_empty()
        || !rule
            .header
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(proxy_error(format!(
            "rule for '{}' has an invalid header name",
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
            Glob::new(path)
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

pub struct RunningProxy {
    pub address: std::net::SocketAddr,
    ca_file: NamedTempFile,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningProxy {
    pub async fn start(plan: ProxyPlan) -> Result<Self> {
        let authority = Arc::new(CertificateAuthority::new()?);
        let mut ca_file = tempfile::Builder::new()
            .prefix("fnox-proxy-ca-")
            .suffix(".pem")
            .tempfile()
            .map_err(|error| proxy_error(format!("failed to create CA file: {error}")))?;
        ca_file
            .write_all(authority.certificate.pem().as_bytes())
            .map_err(|error| proxy_error(format!("failed to write CA file: {error}")))?;
        ca_file
            .flush()
            .map_err(|error| proxy_error(format!("failed to flush CA file: {error}")))?;

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| proxy_error(format!("failed to bind listener: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| proxy_error(format!("failed to read listener address: {error}")))?;
        let policy = plan.policy;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else {
                            break;
                        };
                        if !peer.ip().is_loopback() {
                            tracing::warn!("rejected non-loopback proxy client: {peer}");
                            continue;
                        }
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
        });

        Ok(Self {
            address,
            ca_file,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn ca_path(&self) -> &std::path::Path {
        self.ca_file.path()
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

async fn handle_connection(
    stream: TcpStream,
    policy: Arc<ProxyPolicy>,
    authority: Arc<CertificateAuthority>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let request_line = read_line_limited(&mut reader, MAX_HEADER_BYTES).await?;
    let mut header_bytes = request_line.len();
    loop {
        let line = read_line_limited(&mut reader, MAX_HEADER_BYTES - header_bytes).await?;
        header_bytes += line.len();
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "CONNECT" {
        let mut stream = reader.into_inner();
        write_error(&mut stream, 400, "HTTPS CONNECT is required").await?;
        return Ok(());
    }
    let (domain, port) = parse_connect_target(target)?;
    let mut stream = reader.into_inner();

    if !policy.has_domain(&domain) {
        if policy.egress == ProxyEgress::Strict {
            write_error(&mut stream, 403, "destination is not allowed").await?;
            return Ok(());
        }
        let mut upstream = TcpStream::connect((domain.as_str(), port))
            .await
            .map_err(|error| proxy_error(format!("failed to connect to {domain}: {error}")))?;
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
        write_error(&mut stream, 403, "credential injection requires port 443").await?;
        return Ok(());
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
    proxy_http_request(&mut tls, &domain, &policy).await
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
    let request = read_http_request(stream).await?;
    if has_ambiguous_path_encoding(&request.target) {
        write_error(stream, 403, "request path contains an ambiguous encoding").await?;
        return Ok(());
    }
    let url = reqwest::Url::parse(&format!("https://{domain}{}", request.target))
        .map_err(|error| proxy_error(format!("request used an invalid URL: {error}")))?;
    if url.host_str() != Some(domain) {
        write_error(stream, 403, "request URL changed the approved destination").await?;
        return Ok(());
    }
    let path = url.path();
    let mut headers = request.headers;
    let injected = match policy.authorize(domain, &request.method, path, &mut headers) {
        Ok(injected) => injected,
        Err(error) => {
            write_error(stream, 403, &error.to_string()).await?;
            return Ok(());
        }
    };

    if policy.audit {
        tracing::info!(
            target: "fnox::proxy",
            method = %request.method,
            domain,
            path,
            injected = ?injected,
            "proxied request"
        );
    }

    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| proxy_error("request used an invalid HTTP method"))?;
    let client = reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| proxy_error(format!("failed to build upstream client: {error}")))?;
    let mut outbound = client
        .request(method, url)
        .header("accept-encoding", "identity")
        .body(request.body);
    for (name, value) in headers {
        if is_hop_by_hop_header(&name) || name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        outbound = outbound.header(&name, &value);
    }
    let response = outbound
        .send()
        .await
        .map_err(|error| proxy_error(format!("upstream request failed: {error}")))?;
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
    let mut body = response
        .bytes()
        .await
        .map_err(|error| proxy_error(format!("failed to read upstream response: {error}")))?
        .to_vec();
    if body.len() > MAX_BODY_BYTES {
        write_error(stream, 502, "upstream response exceeded proxy limit").await?;
        return Ok(());
    }
    redact_values(&mut body, &policy.rules);

    let reason = status.canonical_reason().unwrap_or("");
    let mut head = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
    for (name, value) in &response_headers {
        if is_hop_by_hop_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            let value = redact_string(value, &policy.rules);
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
    let mut content_length = 0usize;
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
            content_length = value
                .parse()
                .map_err(|_| proxy_error("invalid content-length"))?;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(proxy_error(
                "chunked request bodies are not supported in this first proxy version",
            ));
        }
        headers.push((name.trim().to_string(), value));
    }
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
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|error| proxy_error(format!("failed to read HTTP request: {error}")))?;
    if read == 0 {
        return Err(proxy_error("connection closed while reading HTTP request"));
    }
    if read > remaining {
        return Err(proxy_error("HTTP headers exceeded proxy limit"));
    }
    Ok(line)
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

fn redact_values(body: &mut Vec<u8>, rules: &[PreparedRule]) {
    for rule in rules {
        if rule.value.is_empty() {
            continue;
        }
        *body = replace_bytes(body, rule.value.as_bytes(), rule.placeholder.as_bytes());
    }
}

fn redact_string(value: &str, rules: &[PreparedRule]) -> String {
    let mut value = value.to_string();
    for rule in rules {
        if !rule.value.is_empty() {
            value = value.replace(&rule.value, &rule.placeholder);
        }
    }
    value
}

fn replace_bytes(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return input.to_vec();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(position) = input[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let position = offset + position;
        output.extend_from_slice(&input[offset..position]);
        output.extend_from_slice(replacement);
        offset = position + needle.len();
    }
    output.extend_from_slice(&input[offset..]);
    output
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
                header: "authorization".to_string(),
                methods: vec!["GET".to_string()],
                paths: vec!["/repos/example/**".to_string()],
                placeholder: Some("ghp_placeholder".to_string()),
            }],
        }
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

    #[test]
    fn substitutes_only_on_allowed_route_and_header() {
        let plan = policy();
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer ghp_placeholder".to_string(),
        )];
        let injected = plan
            .policy
            .authorize("api.github.com", "GET", "/repos/example/fnox", &mut headers)
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
            plan.policy
                .authorize(
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
            plan.policy
                .authorize("api.github.com", "GET", "/repos/example/fnox", &mut headers,)
                .is_err()
        );
    }

    #[test]
    fn redacts_reflected_values() {
        let mut body = b"token=real-token".to_vec();
        redact_values(&mut body, &policy().policy.rules);
        assert_eq!(body, b"token=ghp_placeholder");
    }

    #[test]
    fn rejects_ambiguous_paths() {
        assert!(has_ambiguous_path_encoding(
            "/repos/example/../another/private"
        ));
        assert!(has_ambiguous_path_encoding(
            "/repos/example/%2e%2e/another/private"
        ));
        assert!(!has_ambiguous_path_encoding("/repos/example/fnox?dot=.."));
    }

    #[test]
    fn rejects_overlapping_placeholders() {
        let mut config = config();
        config.rules.push(ProxyRule {
            secret: "OTHER_TOKEN".to_string(),
            domain: "api.github.com".to_string(),
            env: None,
            header: "x-api-key".to_string(),
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
}
