use crate::commands::Cli;
use crate::config::{Config, ProxyConfig};
use crate::error::{FnoxError, Result};
use crate::proxy::{ProxyPlan, RunningProxy};
use clap::{Args, Subcommand, ValueHint};
use indexmap::IndexMap;
use std::process::Stdio;

#[derive(Debug, Args)]
pub struct ProxyCommand {
    #[command(subcommand)]
    command: ProxySubcommand,
}

#[derive(Debug, Subcommand)]
enum ProxySubcommand {
    /// Show the effective credential proxy rules
    Rules,

    /// Run a command with placeholder credentials through the local proxy
    Run(ProxyRunCommand),
}

#[derive(Debug, Args)]
struct ProxyRunCommand {
    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_hint = ValueHint::CommandWithArguments)]
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
        let mut requested = IndexMap::new();
        for rule in &proxy_config.rules {
            let secret = all_secrets.get(&rule.secret).ok_or_else(|| {
                FnoxError::Config(format!(
                    "Proxy rule references unknown secret '{}'",
                    rule.secret
                ))
            })?;
            requested.insert(rule.secret.clone(), secret.clone());
        }
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
        for (key, value) in resolved {
            let value = value.ok_or_else(|| {
                FnoxError::Config(format!("Proxy secret '{key}' did not resolve"))
            })?;
            values.insert(key, value);
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
        for key in [
            "FNOX_AGE_KEY",
            "FNOX_AGE_KEY_FILE",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "BW_SESSION",
            "BWS_ACCESS_TOKEN",
            "VAULT_TOKEN",
            "INFISICAL_TOKEN",
            "KEEPASS_PASSWORD",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ] {
            command.env_remove(key);
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

        let status =
            command
                .status()
                .await
                .map_err(|source| FnoxError::CommandExecutionFailed {
                    command: self.command.join(" "),
                    source,
                })?;
        running.shutdown().await;

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
