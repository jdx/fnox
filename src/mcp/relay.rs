//! `fnox mcp` inside `fnox proxy run`: relays the client's stdio session to
//! the MCP endpoint that the proxy serves on its own port.
//!
//! The proxied command, and with `--sandbox` everything it starts, can't read
//! fnox's config or keys, and the proxy holds the values. So request_secret
//! has to run in the proxy process, outside the sandbox. Its page then listens
//! on the host's loopback, which a sandboxed agent can't reach.

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::{FnoxError, Result};
use crate::local_http::{MAX_HEADER_BYTES, read_line_limited};
use crate::proxy::MCP_TARGET;

/// Relay stdin and stdout to the proxy at `proxy_url`, which carries the
/// session password, until either side closes
pub async fn relay(proxy_url: &str) -> Result<()> {
    let relay_error = |message: String| FnoxError::Config(format!("fnox mcp relay: {message}"));
    let url = url::Url::parse(proxy_url)
        .map_err(|e| relay_error(format!("FNOX_PROXY_MCP is not a URL: {e}")))?;
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return Err(relay_error(
            "FNOX_PROXY_MCP has no host or port".to_string(),
        ));
    };
    let password = url.password().unwrap_or_default();
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{password}", url.username()));

    let stream = TcpStream::connect((host.trim_matches(['[', ']']), port))
        .await
        .map_err(|e| relay_error(format!("failed to reach the fnox proxy: {e}")))?;
    let mut stream = BufReader::new(stream);
    stream
        .get_mut()
        .write_all(
            format!(
                "CONNECT {MCP_TARGET} HTTP/1.1\r\nHost: {MCP_TARGET}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| relay_error(format!("failed to write to the fnox proxy: {e}")))?;

    let status = read_line_limited(&mut stream, MAX_HEADER_BYTES)
        .await
        .map_err(relay_error)?;
    let mut header_bytes = status.len();
    loop {
        let line = read_line_limited(&mut stream, MAX_HEADER_BYTES - header_bytes)
            .await
            .map_err(relay_error)?;
        header_bytes += line.len();
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    if status.split_whitespace().nth(1) != Some("200") {
        // The proxy's error responses are a short plain-text reason
        let mut body = Vec::new();
        let _ = (&mut stream).take(1024).read_to_end(&mut body).await;
        let reason = String::from_utf8_lossy(&body).trim().to_string();
        return Err(relay_error(format!(
            "the fnox proxy refused the session ({}): {reason}",
            status.trim()
        )));
    }

    let (mut from_proxy, mut to_proxy) = tokio::io::split(stream);
    let upload = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut to_proxy).await;
        // Tell the proxy the client is done, so it ends the session
        let _ = to_proxy.shutdown().await;
    });
    let mut stdout = tokio::io::stdout();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = from_proxy
            .read(&mut buffer)
            .await
            .map_err(|e| relay_error(format!("lost the fnox proxy: {e}")))?;
        if read == 0 {
            break;
        }
        // Flush every message: the client waits for each reply
        let written = match stdout.write_all(&buffer[..read]).await {
            Ok(()) => stdout.flush().await,
            Err(e) => Err(e),
        };
        written.map_err(|e| relay_error(format!("failed to write to the client: {e}")))?;
    }
    upload.abort();
    Ok(())
}
