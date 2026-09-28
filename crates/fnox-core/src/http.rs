use std::time::Duration;

fn configured_timeout(value: &str) -> Option<Duration> {
    if value.trim() == "0" {
        None
    } else {
        Some(crate::lease::parse_duration(value).unwrap_or(Duration::from_secs(30)))
    }
}

/// Build an HTTP client with the configured timeout from settings.
pub fn http_client() -> reqwest::Client {
    let settings = crate::settings::Settings::get();
    let user_agent = format!("fnox/{}", env!("CARGO_PKG_VERSION"));
    let mut builder = reqwest::Client::builder().user_agent(user_agent);
    if let Some(timeout) = configured_timeout(&settings.http_timeout) {
        builder = builder.timeout(timeout);
    }
    builder.build().unwrap_or_else(|e| {
        tracing::warn!("Failed to build HTTP client with timeout: {e}; using default (no timeout)");
        reqwest::Client::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_disables_the_timeout() {
        assert_eq!(configured_timeout("0"), None);
        assert_eq!(configured_timeout(" 0 "), None);
    }

    #[test]
    fn invalid_timeout_uses_the_default() {
        assert_eq!(configured_timeout("invalid"), Some(Duration::from_secs(30)));
    }
}
