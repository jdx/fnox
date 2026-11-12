//! Minimal HTTP/1.1 request reading for fnox's loopback listeners: the
//! credential proxy and the `request_secret` page.
//!
//! Errors are plain messages; each caller wraps them in its own error.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};

/// Largest request line plus headers that is read
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Why a request could not be read
#[derive(Debug)]
pub(crate) enum HttpReadError {
    /// The body is larger than the caller allows (413)
    BodyTooLarge { limit: usize },
    /// The request line and headers are larger than [`MAX_HEADER_BYTES`] (431)
    HeadersTooLarge,
    /// Anything else the client sent wrong, or a dropped connection (400)
    Invalid(String),
}

impl HttpReadError {
    /// The HTTP status that best describes this error
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::BodyTooLarge { .. } => 413,
            Self::HeadersTooLarge => 431,
            Self::Invalid(_) => 400,
        }
    }
}

impl std::fmt::Display for HttpReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { limit } if limit % (1024 * 1024) == 0 => write!(
                f,
                "request body is larger than the {} MiB limit",
                limit / (1024 * 1024)
            ),
            Self::BodyTooLarge { limit } => {
                write!(f, "request body is larger than the {limit} byte limit")
            }
            Self::HeadersTooLarge => write!(
                f,
                "request headers are larger than the {} KiB limit",
                MAX_HEADER_BYTES / 1024
            ),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl From<HttpReadError> for String {
    fn from(error: HttpReadError) -> Self {
        error.to_string()
    }
}

fn http_error(message: impl Into<String>) -> HttpReadError {
    HttpReadError::Invalid(message.into())
}

/// Compare two byte strings in time that depends only on their lengths
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// A request read by [`read_http_request_limited`]
pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// Read one HTTP/1.1 request whose body is at most `max_body` bytes
pub(crate) async fn read_http_request_limited<S>(
    stream: &mut S,
    max_body: usize,
) -> Result<HttpRequest, HttpReadError>
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
        return Err(http_error("invalid HTTP request line"));
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
            .ok_or_else(|| http_error("invalid HTTP header"))?;
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .parse()
                .map_err(|_| http_error("invalid content-length"))?;
            if content_length.replace(length).is_some() {
                return Err(http_error("duplicate content-length"));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(http_error(
                "chunked request bodies are not supported in this first proxy version",
            ));
        }
        headers.push((name.trim().to_string(), value));
    }
    if content_length.is_none() && matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        return Err(http_error(format!(
            "{method} requests must include content-length"
        )));
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > max_body {
        return Err(HttpReadError::BodyTooLarge { limit: max_body });
    }
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| http_error(format!("failed to read request body: {error}")))?;
    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

pub(crate) async fn read_line_limited<R>(
    reader: &mut R,
    remaining: usize,
) -> Result<String, HttpReadError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    if remaining == 0 {
        return Err(HttpReadError::HeadersTooLarge);
    }
    let mut line = Vec::with_capacity(remaining.min(1024));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| http_error(format!("failed to read HTTP request: {error}")))?;
        if available.is_empty() {
            return Err(http_error("connection closed while reading HTTP request"));
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if consumed > remaining.saturating_sub(line.len()) {
            return Err(HttpReadError::HeadersTooLarge);
        }
        let complete = available[consumed - 1] == b'\n';
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if complete {
            break;
        }
    }
    String::from_utf8(line).map_err(|_| http_error("HTTP request headers are not valid UTF-8"))
}
