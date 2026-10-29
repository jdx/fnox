//! `fnox mcp` inside `fnox proxy run`: relay MCP between stdin/stdout and the
//! proxy, which serves the tools from outside any sandbox. The relay needs no
//! config, so it works where the sandbox hides it.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{FnoxError, Result};
use crate::proxy::{MCP_HOST, MCP_RELAY_ENV as RELAY_ENV, MCP_RELAY_PROFILE_ENV};

/// Longest proxy response head the relay reads
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// Whether `fnox mcp` should relay to the proxy it runs under
pub fn requested() -> bool {
    crate::env::var(RELAY_ENV).is_ok_and(|value| value == "1")
}

/// The relay serves the proxy's config and profiles; refuse flags that ask
/// for others instead of silently ignoring them
pub fn check_flags(config_arg: &std::path::Path, profile_flag: &[String]) -> Result<()> {
    if config_arg != std::path::Path::new(crate::config::DEFAULT_CONFIG_FILENAME) {
        return Err(FnoxError::Config(
            "fnox mcp under fnox proxy run serves the proxy's config; pass -c to fnox proxy run instead"
                .into(),
        ));
    }
    if profile_flag.is_empty() {
        return Ok(());
    }
    let requested = crate::config::Config::normalize_profiles(profile_flag);
    let served = crate::env::var(MCP_RELAY_PROFILE_ENV)
        .map(|served| crate::config::Config::normalize_profiles(&[served]))
        .unwrap_or_default();
    if requested != served {
        return Err(FnoxError::Config(format!(
            "fnox mcp under fnox proxy run serves profile '{}', not '{}'; pass -P to fnox proxy run instead",
            served.join(","),
            requested.join(",")
        )));
    }
    Ok(())
}

/// The proxy's address and password, from `HTTPS_PROXY`
#[derive(Debug, PartialEq, Eq)]
struct ProxyAddress {
    host: String,
    port: u16,
    user: String,
    password: String,
}

impl ProxyAddress {
    fn parse(proxy_url: &str) -> Result<Self> {
        let invalid = || {
            FnoxError::Config(format!(
                "{RELAY_ENV} is set but HTTPS_PROXY is not a fnox proxy URL"
            ))
        };
        let url = url::Url::parse(proxy_url).map_err(|_| invalid())?;
        // fnox's credentials are `fnox` and a hex token, so nothing in them
        // is percent-encoded
        Ok(Self {
            host: url.host_str().ok_or_else(invalid)?.to_string(),
            port: url.port_or_known_default().ok_or_else(invalid)?,
            user: url.username().to_string(),
            password: url.password().ok_or_else(invalid)?.to_string(),
        })
    }
}

pub async fn run() -> Result<()> {
    let proxy_url = crate::env::var("HTTPS_PROXY")
        .or_else(|_| crate::env::var("https_proxy"))
        .map_err(|_| FnoxError::Config(format!("{RELAY_ENV} is set but HTTPS_PROXY is not")))?;
    let address = ProxyAddress::parse(&proxy_url)?;
    let failed = |error: std::io::Error| {
        FnoxError::Config(format!("fnox mcp could not reach fnox proxy run: {error}"))
    };
    let mut stream = TcpStream::connect((address.host.as_str(), address.port))
        .await
        .map_err(failed)?;
    use base64::Engine;
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", address.user, address.password));
    let request = format!(
        "CONNECT {MCP_HOST}:1 HTTP/1.1\r\nHost: {MCP_HOST}:1\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.map_err(failed)?;

    // Read the response head byte by byte so nothing after it is consumed
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(FnoxError::Config(
                "fnox proxy sent an oversized response".into(),
            ));
        }
        let byte = stream.read_u8().await.map_err(failed)?;
        head.push(byte);
    }
    let status = String::from_utf8_lossy(&head);
    let status = status.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(FnoxError::Config(format!(
            "fnox proxy run refused the MCP connection: {status}"
        )));
    }

    let (mut from_proxy, mut to_proxy) = stream.into_split();
    let upstream = async {
        tokio::io::copy(&mut tokio::io::stdin(), &mut to_proxy).await?;
        to_proxy.shutdown().await
    };
    let downstream = async {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut from_proxy, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::pin!(upstream, downstream);
    // The session ends when the proxy closes the connection, even if the
    // client keeps stdin open, so the client sees stdout close. When the
    // client closes stdin first, replies still drain until the proxy closes.
    tokio::select! {
        result = &mut downstream => {
            // tokio reads stdin on a blocking thread that can't be cancelled,
            // so returning would wait for the client to close stdin. Exit
            // instead, which closes stdout and tells the client.
            if let Err(error) = result {
                tracing::error!("fnox mcp lost its connection to fnox proxy run: {error}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        result = &mut upstream => {
            result.map_err(failed)?;
            downstream.await.map_err(failed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_proxy_url_fnox_sets() {
        let address = ProxyAddress::parse("http://fnox:0a1b2c@127.0.0.1:41234").unwrap();
        assert_eq!(
            address,
            ProxyAddress {
                host: "127.0.0.1".into(),
                port: 41234,
                user: "fnox".into(),
                password: "0a1b2c".into(),
            }
        );
    }

    #[test]
    fn refuses_a_proxy_url_without_a_password() {
        assert!(ProxyAddress::parse("http://127.0.0.1:41234").is_err());
        assert!(ProxyAddress::parse("not a url").is_err());
    }
}
