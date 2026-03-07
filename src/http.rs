use std::time::Duration;

/// Build an HTTP client with the configured timeout from settings.
pub fn http_client() -> reqwest::Client {
    let settings = crate::settings::Settings::get();
    let timeout =
        crate::lease::parse_duration(&settings.http_timeout).unwrap_or(Duration::from_secs(30));
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to build HTTP client with timeout: {e}; using default (no timeout)"
            );
            reqwest::Client::new()
        })
}
