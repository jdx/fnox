use crate::commands::Cli;
use crate::config::{Config, ProxyConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::proxy::{ProxyPlan, RunningProxy};
use indexmap::IndexMap;
use std::process::Stdio;

const AMBIENT_CREDENTIAL_ENV_VARS: &[&str] = &[
    "FNOX_AGE_KEY",
    "FNOX_AGE_KEY_FILE",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
    "INFISICAL_TOKEN",
    "KEEPASS_PASSWORD",
    "PASSWORDSTATE_API_KEY",
    "DOPPLER_TOKEN",
    "FNOX_DOPPLER_TOKEN",
    "KSM_CONFIG",
    "FNOX_KEEPER_CONFIG",
    "KSM_TOKEN",
    "FNOX_KEEPER_TOKEN",
    "FOKS_BOT_TOKEN",
    "FNOX_FOKS_BOT_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    // AWS SDK credential-chain inputs, including selectors and alternate
    // credential sources that can bypass explicitly brokered placeholders.
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_SDK_LOAD_CONFIG",
    // Vault configuration can point a child at an authenticated local agent or
    // supply enough TLS context to use credentials outside the proxy policy.
    "VAULT_TOKEN",
    "VAULT_ADDR",
    "VAULT_AGENT_ADDR",
    "VAULT_NAMESPACE",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_TLS_SERVER_NAME",
    "VAULT_SKIP_VERIFY",
    "FNOX_VAULT_TOKEN",
    "FNOX_VAULT_ADDR",
    // Azure Identity treats these as credential-chain inputs rather than only
    // secret values, so remove the complete environment credential shape.
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_AUTHORITY_HOST",
    "AZURE_CONFIG_DIR",
    "AZURE_ACCESS_TOKEN",
    // pass-cli accepts both native and fnox-prefixed login/session controls.
    "PROTON_PASS_PASSWORD",
    "PROTON_PASS_TOTP",
    "PROTON_PASS_EXTRA_PASSWORD",
    "PROTON_PASS_PASSWORD_FILE",
    "PROTON_PASS_TOTP_FILE",
    "PROTON_PASS_EXTRA_PASSWORD_FILE",
    "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "PROTON_PASS_AGENT_REASON",
    "PROTON_PASS_SESSION_DIR",
    "PROTON_PASS_KEY_PROVIDER",
    "PROTON_PASS_ENCRYPTION_KEY",
    "PROTON_PASS_LINUX_KEYRING",
    "FNOX_PROTON_PASS_PASSWORD",
    "FNOX_PROTON_PASS_TOTP",
    "FNOX_PROTON_PASS_EXTRA_PASSWORD",
    "FNOX_PROTON_PASS_PASSWORD_FILE",
    "FNOX_PROTON_PASS_TOTP_FILE",
    "FNOX_PROTON_PASS_EXTRA_PASSWORD_FILE",
    "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "FNOX_PROTON_PASS_AGENT_REASON",
    "FNOX_PROTON_PASS_SESSION_DIR",
    "FNOX_PROTON_PASS_KEY_PROVIDER",
    "FNOX_PROTON_PASS_ENCRYPTION_KEY",
    "FNOX_PROTON_PASS_LINUX_KEYRING",
];

#[derive(Debug, usage_derive::Args)]
pub struct ProxyCommand {
    #[usage(subcommand)]
    command: ProxySubcommand,
}

#[derive(Debug, usage_derive::Subcommands)]
enum ProxySubcommand {
    /// Show the effective credential proxy rules
    Rules,

    /// Run a command with placeholder credentials through the local proxy
    Run(ProxyRunCommand),
}

#[derive(Debug, usage_derive::Args)]
struct ProxyRunCommand {
    /// Command to run
    #[usage(arg, double_dash = "automatic")]
    command: Vec<String>,
}

impl ProxyCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let proxy = config.proxy.as_ref().ok_or_else(|| {
            FnoxError::Config(
                "No [proxy] configuration found; add one or more [[proxy.rules]]".to_string(),
            )
        })?;
        match &self.command {
            ProxySubcommand::Rules => show_rules(proxy),
            ProxySubcommand::Run(command) => command.run(cli, config).await,
        }
    }
}

fn show_rules(proxy: &ProxyConfig) -> Result<()> {
    crate::proxy::validate_config(proxy)?;
    println!("egress: {:?}", proxy.egress);
    println!("audit: {}", proxy.audit);
    for rule in &proxy.rules {
        let methods = if rule.methods.is_empty() {
            "*".to_string()
        } else {
            rule.methods.join(",")
        };
        let paths = if rule.paths.is_empty() {
            "*".to_string()
        } else {
            rule.paths.join(",")
        };
        println!(
            "{} -> https://{} methods={} paths={} header={} env={}",
            rule.secret,
            rule.domain,
            methods,
            paths,
            rule.header,
            rule.env.as_deref().unwrap_or(&rule.secret)
        );
    }
    Ok(())
}

fn collect_requested_secrets(
    config: &Config,
    profile: &[String],
    proxy: &ProxyConfig,
    all_secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    let providers = config.get_providers(profile);
    let default_provider = config.get_default_provider(profile)?;
    let mut requested = IndexMap::new();

    for rule in &proxy.rules {
        let secret = all_secrets.get(&rule.secret).ok_or_else(|| {
            FnoxError::Config(format!(
                "Proxy rule references unknown secret '{}'",
                rule.secret
            ))
        })?;
        requested.insert(rule.secret.clone(), secret.clone());
    }

    loop {
        let mut added = false;
        let keys: Vec<_> = requested.keys().cloned().collect();
        for key in keys {
            let secret = &requested[&key];
            let provider_name = secret
                .sync
                .as_ref()
                .map(|sync| sync.provider.as_str())
                .or_else(|| secret.provider())
                .or_else(|| {
                    secret
                        .value()
                        .is_some()
                        .then_some(default_provider.as_deref())
                        .flatten()
                });
            let Some(provider) = provider_name.and_then(|name| providers.get(name)) else {
                continue;
            };
            for dependency in provider.env_dependencies() {
                if requested.contains_key(*dependency) {
                    continue;
                }
                if let Some(secret) = all_secrets.get(*dependency) {
                    requested.insert((*dependency).to_string(), secret.clone());
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }

    Ok(requested)
}

impl ProxyRunCommand {
    async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }
        let proxy_config = config
            .proxy
            .as_ref()
            .ok_or_else(|| FnoxError::Config("No [proxy] configuration found".to_string()))?;
        crate::proxy::validate_config(proxy_config)?;
        let profile = Config::get_profiles(&cli.profile);
        let all_secrets = config.get_secrets(&profile)?;
        let requested = collect_requested_secrets(&config, &profile, proxy_config, &all_secrets)?;
        let resolved = crate::daemon::resolve_batch(
            cli,
            &config,
            &profile,
            &requested,
            crate::daemon::Purpose::Proxy,
            true,
        )
        .await?;
        let mut values = IndexMap::new();
        for rule in &proxy_config.rules {
            let value = resolved
                .get(&rule.secret)
                .cloned()
                .flatten()
                .ok_or_else(|| {
                    FnoxError::Config(format!("Proxy secret '{}' did not resolve", rule.secret))
                })?;
            values.insert(rule.secret.clone(), value);
        }

        let plan = ProxyPlan::new(proxy_config, &values)?;
        let child_env = plan.child_env.clone();
        let running = RunningProxy::start(plan).await?;
        let proxy_url = format!("http://{}", running.address);
        let ca_path = running.ca_path().to_string_lossy().to_string();

        tracing::warn!(
            "fnox proxy does not sandbox the child process yet; same-user code may bypass the proxy"
        );

        let mut command = tokio::process::Command::new(&self.command[0]);
        command
            .args(&self.command[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        // Do not inherit secrets already loaded by shell integration. Proxy
        // rules add back placeholders for the explicitly brokered values.
        for key in all_secrets.keys() {
            command.env_remove(key);
        }
        for key in AMBIENT_CREDENTIAL_ENV_VARS {
            command.env_remove(key);
        }
        for provider in config.get_providers(&profile).values() {
            for dependency in provider.env_dependencies() {
                command.env_remove(dependency);
            }
        }
        command.env("FNOX_DAEMON", "off");
        command.env("FNOX_NON_INTERACTIVE", "1");
        for (key, placeholder) in child_env {
            command.env(key, placeholder);
        }
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(key, &proxy_url);
        }
        command.env("NO_PROXY", "localhost,127.0.0.1,::1");
        command.env("no_proxy", "localhost,127.0.0.1,::1");
        command.env("NODE_USE_ENV_PROXY", "1");
        for key in [
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "CARGO_HTTP_CAINFO",
            "DENO_CERT",
        ] {
            command.env(key, &ca_path);
        }

        let status = command.status().await;
        running.shutdown().await;
        let status = status.map_err(|source| FnoxError::CommandExecutionFailed {
            command: self.command.join(" "),
            source,
        })?;

        if !status.success() {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    std::process::exit(128 + signal);
                }
            }
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_secrets_include_provider_dependencies() {
        let config: Config = toml_edit::de::from_str(
            r#"
[providers.doppler]
type = "doppler"

[providers.plain]
type = "plain"

[secrets]
DOPPLER_TOKEN = { provider = "plain", value = "provider-token" }
API_TOKEN = { provider = "doppler", value = "api-token" }

[proxy]
[[proxy.rules]]
secret = "API_TOKEN"
domain = "api.example.com"
"#,
        )
        .unwrap();
        let profile = vec!["default".to_string()];
        let all_secrets = config.get_secrets(&profile).unwrap();

        let requested = collect_requested_secrets(
            &config,
            &profile,
            config.proxy.as_ref().unwrap(),
            &all_secrets,
        )
        .unwrap();

        assert!(requested.contains_key("API_TOKEN"));
        assert!(requested.contains_key("DOPPLER_TOKEN"));
    }

    #[test]
    fn ambient_credential_scrub_covers_provider_chains() {
        for key in [
            "KSM_CONFIG",
            "FNOX_KEEPER_CONFIG",
            "KSM_TOKEN",
            "FNOX_KEEPER_TOKEN",
            "AWS_PROFILE",
            "AWS_REGION",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "VAULT_ADDR",
            "VAULT_AGENT_ADDR",
            "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID",
            "AZURE_FEDERATED_TOKEN_FILE",
            "PROTON_PASS_PASSWORD",
            "PROTON_PASS_SESSION_DIR",
            "FNOX_PROTON_PASS_ENCRYPTION_KEY",
        ] {
            assert!(
                AMBIENT_CREDENTIAL_ENV_VARS.contains(&key),
                "{key} must be removed from proxy children"
            );
        }
    }
}
