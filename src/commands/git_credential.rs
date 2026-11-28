use crate::commands::Cli;
use crate::commands::get::GetCommand;
use crate::config::Config;
use crate::error::Result;
use crate::lease_backends::LeaseBackendConfig;
use std::io::{Read, Write};

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
///
/// git runs the helper from the repository's directory, so a project's
/// `fnox.toml` applies. Outside a project, define the backend in the global
/// config or pass `-c`.
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

fn parse_request(input: &str) -> Request {
    let mut request = Request::default();
    for line in input.lines() {
        if line.is_empty() {
            break;
        }
        match line.split_once('=') {
            Some(("protocol", value)) => request.protocol = Some(value.to_string()),
            Some(("host", value)) => request.host = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    request
}

/// `host[:port]` of a URL, lowercased, with the scheme's default port dropped.
fn authority(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?.to_ascii_lowercase();
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = authority
        .strip_suffix(default_port)
        .filter(|_| !default_port.is_empty())
        .map(str::to_string)
        .unwrap_or(authority);
    (!authority.is_empty()).then_some(authority)
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
            authority(url.as_deref().unwrap_or("https://gitlab.com"))?,
            "oauth2",
        )),
        _ => None,
    }
}

/// `https://api.github.com` serves `github.com`; a GitHub Enterprise API base
/// such as `https://ghe.example.com/api/v3` serves its own host.
fn github_host(api_base: &str) -> String {
    match authority(api_base) {
        Some(host) if host == "api.github.com" => "github.com".to_string(),
        Some(host) => host,
        None => "github.com".to_string(),
    }
}

impl GitCredentialCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        // Git sends its request on stdin for every operation; read it so git
        // never sees a broken pipe.
        let mut input = String::new();
        let _ = std::io::stdin().read_to_string(&mut input);
        if self.operation != "get" {
            return Ok(());
        }

        let request = parse_request(&input);
        if !matches!(request.protocol.as_deref(), Some("http" | "https")) {
            return Ok(());
        }
        let Some(host) = request.host else {
            return Ok(());
        };

        let profile = Config::get_profiles(cli.profile.as_slice());
        let leases = config.get_leases(&profile)?;
        let selected = leases.iter().rfind(|(name, lease)| {
            self.backend.as_deref().is_none_or(|wanted| wanted == *name)
                && git_endpoint(lease).is_some_and(|(served, _)| served == host)
        });
        let Some((name, lease)) = selected else {
            tracing::debug!("no lease backend serves git host '{host}'");
            return Ok(());
        };
        let Some((_, username)) = git_endpoint(lease) else {
            return Ok(());
        };
        let Some(key) = lease.produced_env_vars().first().map(|key| key.to_string()) else {
            return Ok(());
        };

        tracing::debug!("serving git host '{host}' from lease backend '{name}'");
        let getter = GetCommand {
            key: Some(key),
            base64_decode: false,
            file: None,
            refresh: false,
        };
        // A failure surfaces as a nonzero exit with the error on stderr, which
        // git shows to the user; stdout stays empty so git tries its next helper.
        if let Some((token, _)) = getter.resolve_from_lease(cli, &config, &profile).await? {
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

    #[test]
    fn parses_the_request_until_the_blank_line() {
        let request = parse_request("protocol=https\nhost=GitHub.com\npath=a/b\n\nhost=other\n");
        assert_eq!(request.protocol.as_deref(), Some("https"));
        assert_eq!(request.host.as_deref(), Some("github.com"));
    }

    #[test]
    fn authority_drops_default_ports_and_userinfo() {
        assert_eq!(authority("https://GitLab.com/"), Some("gitlab.com".into()));
        assert_eq!(
            authority("https://gl.example.com:443"),
            Some("gl.example.com".into())
        );
        assert_eq!(
            authority("http://127.0.0.1:8080/api"),
            Some("127.0.0.1:8080".into())
        );
        assert_eq!(
            authority("https://u:p@gl.example.com/x"),
            Some("gl.example.com".into())
        );
        assert_eq!(authority("not a url"), None);
    }

    #[test]
    fn github_api_bases_map_to_git_hosts() {
        assert_eq!(github_host("https://api.github.com"), "github.com");
        assert_eq!(
            github_host("https://ghe.example.com/api/v3"),
            "ghe.example.com"
        );
    }
}
