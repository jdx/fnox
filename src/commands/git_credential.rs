use crate::commands::get::resolve_named_lease;
use crate::commands::{Cli, load_read_config};
use crate::config::{Config, uses_config_discovery};
use crate::error::{FnoxError, Result};
use crate::lease_backends::LeaseBackendConfig;
use std::io::{BufRead, Write};

/// Git credential helper that serves short-lived GitHub and GitLab tokens
///
/// Lets git (and tools that use git's credential protocol, such as cargo and
/// go) authenticate with a token from a `github-app`, `github-oauth`, or
/// `gitlab` lease backend, so no personal access token sits on disk. Configure
/// it with `git config --global credential.helper '!fnox git-credential'`;
/// git then runs `fnox git-credential get` and passes the request on stdin.
///
/// fnox picks the lease backend whose host matches the request: `github.com`
/// for GitHub backends (the host of `api_base` for GitHub Enterprise) and the
/// host of `url` for GitLab backends (`gitlab.com` by default). When no backend
/// matches, fnox prints nothing and exits 0, so git falls through to its next
/// helper. `store` and `erase` do nothing, because leases expire on their own.
/// Tokens are returned only for HTTPS requests, or plain HTTP to a loopback
/// address, so they never cross a network in cleartext.
///
/// Backends come from the global config (`~/.config/fnox/config.toml`) only,
/// because git runs the helper inside repositories you may not trust; a
/// `fnox.toml` in the repository is ignored. Pass `-c PATH` to read a specific
/// file instead. With no config, fnox prints nothing.
#[derive(Debug, usage_rs::Args)]
#[usage(
    name = "git-credential",
    example(
        "git config --global credential.helper '!fnox git-credential'",
        header = "Let git use fnox's lease tokens"
    ),
    example(
        "printf 'protocol=https\\nhost=github.com\\n\\n' | fnox git-credential get",
        header = "See what git would receive"
    ),
    after_long_help = "See also:\n- Git credential helper: https://fnox.jdx.dev/guide/git-credential\n- Credential leases: https://fnox.jdx.dev/guide/leases"
)]
pub struct GitCredentialCommand {
    /// Operation git requests: `get`, `store`, or `erase`
    ///
    /// Only `get` returns credentials; the others, and any operation git adds
    /// later, are accepted and ignored.
    pub operation: String,

    /// Use this lease backend instead of choosing one by host
    ///
    /// Needed when several backends serve the same host, for example two
    /// GitHub App installations. Without it, the last matching backend wins.
    #[usage(long)]
    pub backend: Option<String>,
}

/// The request git writes on stdin: `key=value` lines ended by a blank line.
#[derive(Debug, Default, PartialEq)]
struct Request {
    protocol: Option<String>,
    host: Option<String>,
}

/// Read git's request up to the blank line that ends it, or EOF. Fields are
/// read as bytes, so a value fnox ignores (a path, a password) need not be
/// UTF-8; only `protocol` and `host` are decoded.
fn read_request(mut input: impl BufRead) -> Request {
    let mut request = Request::default();
    let mut line = Vec::new();
    loop {
        line.clear();
        match input.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let record = line.strip_suffix(b"\n").unwrap_or(&line);
        let record = record.strip_suffix(b"\r").unwrap_or(record);
        if record.is_empty() {
            break;
        }
        let Some(eq) = record.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        let field = match key {
            b"protocol" => &mut request.protocol,
            b"host" => &mut request.host,
            _ => continue,
        };
        *field = String::from_utf8(value.to_vec()).ok();
    }
    request
}

/// The config whose lease backends may answer git. git runs the helper on its
/// own, from inside whatever repository it is working in, so a `fnox.toml`
/// checked into that repository must not decide where fnox sends a parent
/// token. Only the global config is read, unless `-c` names a file.
fn load_helper_config(cli: &Cli) -> Result<Config> {
    if !uses_config_discovery(&cli.config) {
        return load_read_config(cli);
    }
    let mut config = Config::load_global_only()?;
    // Share one lease ledger across repositories rather than one per repo.
    config.project_dir = Some(crate::env::FNOX_CONFIG_DIR.clone());
    config.validate_profiles(&Config::get_profiles(&cli.profile), None)?;
    Ok(config)
}

/// `host[:port]` of a URL, lowercased, with the scheme's default port dropped.
fn authority(url: &url::Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn url_authority(value: &str) -> Option<String> {
    authority(&url::Url::parse(value).ok()?)
}

/// The host git asks about, normalized like a backend URL, or `None` when the
/// request must not receive a token. Tokens go only over HTTPS, or over plain
/// HTTP to a loopback address, so they never cross a network in cleartext.
fn request_authority(request: &Request) -> Option<String> {
    let protocol = request.protocol.as_deref()?;
    if !matches!(protocol, "http" | "https") {
        return None;
    }
    let url = url::Url::parse(&format!("{protocol}://{}/", request.host.as_deref()?)).ok()?;
    if protocol == "http" {
        let loopback = match url.host()? {
            url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        };
        if !loopback {
            return None;
        }
    }
    authority(&url)
}

/// The git host a backend's tokens authenticate against, with the username git
/// should send. `None` for backends that don't issue git credentials.
fn git_endpoint(config: &LeaseBackendConfig) -> Option<(String, &'static str)> {
    match config {
        LeaseBackendConfig::GithubApp { api_base, .. } => Some((
            github_host(api_base.as_deref().unwrap_or("https://api.github.com")),
            "x-access-token",
        )),
        LeaseBackendConfig::GithubOauth { api_base, .. } => {
            Some((github_host(api_base), "x-access-token"))
        }
        LeaseBackendConfig::Gitlab { url, .. } => Some((
            url_authority(url.as_deref().unwrap_or("https://gitlab.com"))?,
            "oauth2",
        )),
        _ => None,
    }
}

/// The git host an API base serves: `api.github.com` serves `github.com`, a
/// GitHub Enterprise Cloud API such as `api.acme.ghe.com` serves `acme.ghe.com`,
/// and a GitHub Enterprise Server API such as `https://ghe.example.com/api/v3`
/// serves its own host.
fn github_host(api_base: &str) -> String {
    match url_authority(api_base) {
        Some(host) if host == "api.github.com" => "github.com".to_string(),
        Some(host) if host.ends_with(".ghe.com") && host.starts_with("api.") => {
            host["api.".len()..].to_string()
        }
        Some(host) => host,
        None => "github.com".to_string(),
    }
}

impl GitCredentialCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        // Git sends its request on stdin for every operation; read it so git
        // never sees a broken pipe.
        let request = read_request(std::io::stdin().lock());
        if self.operation != "get" {
            return Ok(());
        }
        let Some(host) = request_authority(&request) else {
            return Ok(());
        };

        // With no config there is no backend, so let git try its next helper.
        let config = match load_helper_config(cli) {
            Ok(config) => config,
            Err(FnoxError::ConfigNotFound { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        let profile = Config::get_profiles(cli.profile.as_slice());
        let leases = config.get_leases(&profile)?;
        let selected = leases.iter().rev().find_map(|(name, lease)| {
            if self.backend.as_deref().is_some_and(|wanted| wanted != name) {
                return None;
            }
            let (served, username) = git_endpoint(lease)?;
            (served == host).then_some((name, lease, username))
        });
        let Some((name, lease, username)) = selected else {
            tracing::debug!("no lease backend serves git host '{host}'");
            return Ok(());
        };
        let Some(key) = lease.produced_env_vars().first().map(|key| key.to_string()) else {
            return Ok(());
        };

        tracing::debug!("serving git host '{host}' from lease backend '{name}'");
        // A failure surfaces as a nonzero exit with the error on stderr, which
        // git shows to the user; stdout stays empty so git tries its next helper.
        if let Some((token, _)) =
            resolve_named_lease(cli, &config, &profile, name, lease, &key).await?
        {
            let mut out = std::io::stdout().lock();
            let _ = write!(out, "username={username}\npassword={token}\n");
            let _ = out.flush();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(protocol: &str, host: &str) -> Option<String> {
        request_authority(&Request {
            protocol: Some(protocol.into()),
            host: Some(host.into()),
        })
    }

    #[test]
    fn parses_the_request_until_the_blank_line() {
        let request = read_request(
            &b"protocol=https\r\nhost=GitHub.com\npath=a/\xff\npassword=\xfe\n\nhost=other\n"[..],
        );
        assert_eq!(request.protocol.as_deref(), Some("https"));
        assert_eq!(request.host.as_deref(), Some("GitHub.com"));

        let request = read_request(&b"protocol=https\nhost=github.com"[..]);
        assert_eq!(request.host.as_deref(), Some("github.com"));
    }

    #[test]
    fn request_hosts_are_normalized() {
        assert_eq!(request("https", "GitHub.com"), Some("github.com".into()));
        assert_eq!(
            request("https", "github.com:443"),
            Some("github.com".into())
        );
        assert_eq!(
            request("https", "gl.example.com:8443"),
            Some("gl.example.com:8443".into())
        );
    }

    #[test]
    fn cleartext_requests_get_tokens_only_on_loopback() {
        assert_eq!(request("http", "gitlab.com"), None);
        assert_eq!(
            request("http", "127.0.0.1:8080"),
            Some("127.0.0.1:8080".into())
        );
        assert_eq!(request("http", "localhost"), Some("localhost".into()));
        assert_eq!(request("http", "[::1]:8080"), Some("[::1]:8080".into()));
        assert_eq!(request("ssh", "github.com"), None);
    }

    #[test]
    fn backend_urls_drop_default_ports_and_userinfo() {
        assert_eq!(
            url_authority("https://GitLab.com/"),
            Some("gitlab.com".into())
        );
        assert_eq!(
            url_authority("https://gl.example.com:443"),
            Some("gl.example.com".into())
        );
        assert_eq!(
            url_authority("https://u:p@gl.example.com/x"),
            Some("gl.example.com".into())
        );
        assert_eq!(url_authority("not a url"), None);
    }

    #[test]
    fn github_api_bases_map_to_git_hosts() {
        assert_eq!(github_host("https://api.github.com"), "github.com");
        assert_eq!(github_host("https://api.acme.ghe.com"), "acme.ghe.com");
        assert_eq!(
            github_host("https://ghe.example.com/api/v3"),
            "ghe.example.com"
        );
    }
}
