//! Accepting client connections, CONNECT tunnels, and forwarding
//! intercepted HTTP requests.

use super::*;

/// Where the proxy accepts clients.
pub enum ProxyListener {
    /// A random port on `127.0.0.1`.
    Loopback,
    /// A Unix socket at this path, created with mode 0600. The path must not
    /// exist and should be in a directory only the user can enter. This lets
    /// a sandboxed process reach the proxy without sharing the host's network.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

/// Accepts client connections for the proxy, dropping ones it must refuse.
pub(super) trait ProxyAccept: Send + 'static {
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

pub(super) fn serve<L: ProxyAccept>(
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
pub(super) struct SocketFile(pub(super) std::path::PathBuf);

#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub struct RunningProxy {
    pub(super) address: Option<SocketAddr>,
    /// Held only so its `Drop` removes the socket file.
    #[cfg(unix)]
    pub(super) _socket_file: Option<SocketFile>,
    pub(super) token: String,
    pub(super) ca_file: NamedTempFile,
    pub(super) shutdown: Option<oneshot::Sender<()>>,
    pub(super) task: tokio::task::JoinHandle<()>,
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

    /// The address of a loopback listener.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.address
    }

    /// The `HTTPS_PROXY` URL for a client that reaches the proxy at `address`
    /// by some other route, such as a bridge in front of a Unix socket.
    pub fn session_url(&self, address: std::net::SocketAddr) -> String {
        format!("http://fnox:{}@{address}", self.token)
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

/// The request line and `Proxy-Authorization` header of a request sent to
/// the proxy itself, before any tunnel is established.
pub(super) struct ProxyRequestHead {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) authorization: Option<String>,
}

pub(super) async fn read_proxy_request_head<R>(reader: &mut R) -> Result<ProxyRequestHead>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let request_line = read_line_limited(reader, MAX_HEADER_BYTES)
        .await
        .map_err(proxy_error)?;
    let mut header_bytes = request_line.len();
    let mut authorization = None;
    loop {
        let line = read_line_limited(reader, MAX_HEADER_BYTES - header_bytes)
            .await
            .map_err(proxy_error)?;
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

pub(super) async fn handle_connection<S>(
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

pub(super) fn parse_connect_target(target: &str) -> Result<(String, u16)> {
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

pub(super) async fn proxy_http_request<S>(
    stream: &mut S,
    domain: &str,
    policy: &ProxyPolicy,
) -> Result<()>
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
    policy.refresh_pending(domain).await;
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
    let redactions = policy.redactions();
    redact_values(&mut body, &redactions);

    let reason = status.canonical_reason().unwrap_or("");
    let mut head = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
    for (name, value) in &response_headers {
        if is_hop_by_hop_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            let value = redact_string(value, &redactions);
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

pub(super) async fn read_http_request<S>(stream: &mut S) -> Result<HttpRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_http_request_limited(stream, MAX_BODY_BYTES)
        .await
        .map_err(proxy_error)
}

pub(super) fn is_hop_by_hop_header(name: &str) -> bool {
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

/// Challenges the client for proxy credentials. Unless `close` is set, the
/// connection stays open so the client can retry on it.
pub(super) async fn write_auth_required<S>(stream: &mut S, close: bool) -> Result<()>
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

pub(super) async fn write_error<S>(stream: &mut S, status: u16, message: &str) -> Result<()>
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
