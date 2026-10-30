use crate::commands::Cli;
use crate::config::{Config, ProxyConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::lease::{LeaseLedger, LeaseRecord};
use crate::lease_backends::{Lease, LeaseBackendConfig};
use crate::proxy::{LeaseMinter, MintFuture, ProxyListener, ProxyPlan, RunningProxy};
use crate::sandbox::{Sandbox, SandboxPolicy};
use crate::secret_session::SecretSession;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::path::PathBuf;
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

/// Inject credentials into a command's HTTPS requests through a local proxy
///
/// `fnox proxy run` starts a local HTTPS proxy and runs a command that sees only
/// placeholder values. When the command sends a request that matches a
/// `[[proxy.rules]]` entry by domain, method, and path, the proxy swaps in the
/// real secret. The proxy controls where credentials are sent; it does not
/// sandbox the command unless you pass `--sandbox` to `run`. Both subcommands
/// require a `[proxy]` table.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example("fnox proxy rules", header = "Check the rules"),
    example(
        "fnox proxy run -- node agent.js",
        header = "Run a command behind the proxy"
    ),
    after_long_help = "See also:\n- Credential proxy: https://fnox.jdx.dev/guide/proxy"
)]
pub struct ProxyCommand {
    #[usage(subcommand)]
    command: ProxySubcommand,
}

#[derive(Debug, usage_rs::Subcommands)]
enum ProxySubcommand {
    /// Print the effective proxy rules
    ///
    /// Validates the `[proxy]` table and prints its egress mode, audit setting,
    /// and each rule's secret or lease, domain, methods, paths, header or query
    /// parameter, and placeholder variable. Secrets are not resolved and no lease
    /// is created.
    #[usage(
        example("fnox proxy rules", header = "Print the rules"),
        example(
            "fnox -P staging proxy rules",
            header = "Print another profile's rules"
        ),
        after_long_help = "See also:\n- Credential proxy: https://fnox.jdx.dev/guide/proxy"
    )]
    Rules,
    Run(ProxyRunCommand),
}

/// Run a command with placeholder credentials behind the proxy
///
/// Resolves the secrets that `[[proxy.rules]]` names, plus any secrets their
/// providers need and the parent credentials of the leases rules name, starts
/// the proxy on a local port, and runs COMMAND with:
///
///  - each rule's variable set to a placeholder instead of the real value
///  - `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` pointing at the proxy, with
///    a per-session password that other users' processes don't have
///  - CA variables such as `SSL_CERT_FILE` pointing at the proxy's certificate
///  - every configured secret and common cloud credential variables removed
///
/// With `--sandbox` (or `sandbox = true`), the command also runs in an OS
/// sandbox: its only network route is the proxy, the filesystem is read-only
/// except for the working directory and temporary files, and fnox's
/// configuration, keys and common credential directories are hidden.
///
/// A lease is created the first time a request needs it and revoked when
/// COMMAND exits. The command's HTTP client must honor those proxy and CA
/// settings. fnox exits with the command's exit status.
#[derive(Debug, usage_rs::Args)]
#[usage(
    example(
        "fnox proxy run -- node agent.js",
        header = "Run an agent behind the proxy"
    ),
    after_long_help = "See also:\n- Credential proxy: https://fnox.jdx.dev/guide/proxy"
)]
struct ProxyRunCommand {
    /// Run the command without the sandbox, even if `[proxy]` enables it
    #[usage(long)]
    no_sandbox: bool,

    /// Run the command in an OS sandbox whose only way out is the proxy
    ///
    /// Also enabled by `sandbox = true` in `[proxy]`. Needs `bwrap` on Linux or
    /// `sandbox-exec` on macOS, and fails instead of running unsandboxed.
    #[usage(long)]
    sandbox: bool,

    /// Command to run, with its arguments
    #[usage(
        arg,
        double_dash = "automatic",
        value_hint = usage_rs::ValueHint::CommandWithArguments
    )]
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
            ProxySubcommand::Rules => {
                let profile = Config::get_profiles(&cli.profile);
                let leases = config.get_leases(&profile)?;
                show_rules(proxy, &lease_credentials(proxy, &leases)?)
            }
            ProxySubcommand::Run(command) => command.run(cli, config).await,
        }
    }
}

fn show_rules(proxy: &ProxyConfig, lease_credentials: &HashMap<String, String>) -> Result<()> {
    crate::proxy::validate_config(proxy)?;
    println!("egress: {:?}", proxy.egress);
    println!("audit: {}", proxy.audit);
    if !proxy.allow_domains.is_empty() {
        println!("allow_domains: {}", proxy.allow_domains.join(","));
    }
    if !proxy.allow_private.is_empty() {
        println!("allow_private: {}", proxy.allow_private.join(","));
    }
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
        let name = rule.value_name();
        let credential = rule
            .lease
            .as_ref()
            .and_then(|lease| rule.credential.as_ref().or(lease_credentials.get(lease)));
        println!(
            "{} -> https://{} methods={} paths={} {} env={}",
            name,
            rule.domain,
            methods,
            paths,
            crate::proxy::target_label(rule),
            rule.env.as_ref().or(credential).unwrap_or(&name)
        );
    }
    Ok(())
}

/// Serves the MCP tools to each `fnox mcp` relay in the child, sharing this
/// run's secrets and handing values the user enters to the proxy
fn mcp_service(
    session: std::sync::Arc<SecretSession>,
    mcp_config: crate::config::McpConfig,
    proxy: crate::proxy::ProxyHandle,
) -> crate::proxy::McpService {
    std::sync::Arc::new(move |stream| {
        let server = crate::mcp::FnoxMcpServer::new(session.clone(), mcp_config.clone())
            .under_proxy(proxy.clone());
        Box::pin(async move {
            match rmcp::ServiceExt::serve(server, stream).await {
                Ok(running) => {
                    let _ = running.waiting().await;
                }
                Err(error) => tracing::debug!("MCP session over the proxy failed: {error}"),
            }
        })
    })
}

fn collect_requested_secrets(
    config: &Config,
    profile: &[String],
    proxy: &ProxyConfig,
    all_secrets: &IndexMap<String, SecretConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    let mut requested = IndexMap::new();
    for name in proxy.rules.iter().filter_map(|rule| rule.secret.as_ref()) {
        let secret = all_secrets.get(name).ok_or_else(|| {
            FnoxError::Config(format!("Proxy rule references unknown secret '{name}'"))
        })?;
        requested.insert(name.clone(), secret.clone());
    }

    crate::secret_session::with_provider_dependencies(config, profile, all_secrets, requested)
}

/// The variable each lease that rules name injects by default: the only one
/// it produces. Also checks that each lease exists and produces the
/// `credential` a rule picks.
fn lease_credentials(
    proxy: &ProxyConfig,
    leases: &IndexMap<String, LeaseBackendConfig>,
) -> Result<HashMap<String, String>> {
    let mut credentials = HashMap::new();
    for rule in &proxy.rules {
        let Some(name) = &rule.lease else {
            continue;
        };
        let lease = leases.get(name).ok_or_else(|| {
            FnoxError::Config(format!("Proxy rule references unknown lease '{name}'"))
        })?;
        let produced = lease.produced_env_vars();
        if let Some(credential) = &rule.credential {
            // A `command` lease's variables are known only once it runs
            if !produced.is_empty() && !produced.contains(&credential.as_str()) {
                return Err(FnoxError::Config(format!(
                    "Proxy rule picks credential '{credential}', which lease '{name}' doesn't produce (it produces {})",
                    produced.join(", ")
                )));
            }
        } else if let [only] = produced.as_slice() {
            credentials.insert(name.clone(), only.to_string());
        } else if produced.is_empty() {
            return Err(FnoxError::Config(format!(
                "Proxy rule for lease '{name}' needs `credential`: the lease's variables are known only once it runs"
            )));
        } else {
            return Err(FnoxError::Config(format!(
                "Proxy rule for lease '{name}' needs `credential` to pick one of {}",
                produced.join(", ")
            )));
        }
    }
    Ok(credentials)
}

/// Creates the leases rules name, and records each in the lease ledger so
/// `fnox lease list` and `fnox lease revoke` see it. No credentials are
/// cached: a later `fnox exec` must not reuse a token only the proxy holds.
struct LedgerMinter {
    leases: IndexMap<String, LeaseBackendConfig>,
    project_dir: PathBuf,
}

impl LeaseMinter for LedgerMinter {
    fn mint<'a>(&'a self, name: &'a str) -> MintFuture<'a, Lease> {
        Box::pin(async move {
            let config = self.lease(name)?;
            let backend = config.create_backend()?;
            let duration_str = config
                .duration()
                .unwrap_or(crate::lease::DEFAULT_LEASE_DURATION);
            let duration = crate::lease::parse_duration(duration_str)?;
            if duration > backend.max_lease_duration() {
                return Err(FnoxError::Config(format!(
                    "Lease duration '{duration_str}' for '{name}' exceeds maximum {:?}",
                    backend.max_lease_duration()
                )));
            }
            let label = format!("fnox-proxy-{name}");
            let lease = backend.create_lease(duration, &label).await?;
            let _lock = LeaseLedger::lock(&self.project_dir)?;
            let mut ledger = LeaseLedger::load(&self.project_dir)?;
            ledger.add(LeaseRecord {
                lease_id: lease.lease_id.clone(),
                backend_name: name.to_string(),
                label,
                created_at: chrono::Utc::now(),
                expires_at: lease.expires_at,
                revoked: false,
                cached_credentials: None,
                encryption_provider: None,
                config_hash: Some(config.config_hash()),
            });
            if let Err(error) = ledger.save(&self.project_dir) {
                tracing::warn!(
                    "Lease '{}' created for '{name}' but the ledger save failed: {error}",
                    lease.lease_id
                );
            }
            Ok(lease)
        })
    }

    fn revoke<'a>(&'a self, name: &'a str, minted: &'a Lease) -> MintFuture<'a, ()> {
        Box::pin(async move {
            self.lease(name)?
                .create_backend()?
                .revoke_lease(&minted.lease_id, Some(&minted.credentials))
                .await?;
            let _lock = LeaseLedger::lock(&self.project_dir)?;
            let mut ledger = LeaseLedger::load(&self.project_dir)?;
            if ledger.mark_revoked(&minted.lease_id) {
                ledger.save(&self.project_dir)?;
            }
            Ok(())
        })
    }
}

impl LedgerMinter {
    fn lease(&self, name: &str) -> Result<&LeaseBackendConfig> {
        self.leases
            .get(name)
            .ok_or_else(|| FnoxError::Config(format!("unknown lease '{name}'")))
    }
}

impl ProxyRunCommand {
    fn sandbox_enabled(&self, proxy: &ProxyConfig) -> bool {
        self.sandbox || (proxy.sandbox && !self.no_sandbox)
    }

    async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }
        let proxy_config = config
            .proxy
            .as_ref()
            .ok_or_else(|| FnoxError::Config("No [proxy] configuration found".to_string()))?;
        crate::proxy::validate_config(proxy_config)?;
        // Checked before any secret is resolved, so a machine that cannot
        // sandbox fails without having fetched anything.
        let sandbox = if self.sandbox_enabled(proxy_config) {
            let policy = SandboxPolicy::from_environment(cli, &config, proxy_config)?;
            Some(Sandbox::prepare(policy)?)
        } else {
            None
        };
        // Before any secret is resolved into this process's memory.
        crate::proxy::deny_inspection();
        let profile = Config::get_profiles(&cli.profile);
        let all_secrets = config.get_secrets(&profile)?;
        let requested = collect_requested_secrets(&config, &profile, proxy_config, &all_secrets)?;
        let session = SecretSession::new(
            config.clone(),
            profile.clone(),
            crate::daemon::ResolveContext::from_cli(cli),
            crate::daemon::Purpose::Proxy,
            all_secrets.clone(),
        )
        .with_write_target(cli.config.clone(), cli.write_profile.clone());
        let resolved = session.resolve_now(&requested).await?;
        // A rule secret without a value is pending: the child still gets its
        // placeholder, and the proxy resolves it again when a request needs it
        let values: IndexMap<String, String> = proxy_config
            .rules
            .iter()
            .filter_map(|rule| {
                let secret = rule.secret.as_ref()?;
                let value = resolved.get(secret).cloned().flatten()?;
                Some((secret.clone(), value))
            })
            .collect();

        let all_leases = config.get_leases(&profile)?;
        let lease_credentials = lease_credentials(proxy_config, &all_leases)?;
        let leases: IndexMap<String, LeaseBackendConfig> = all_leases
            .into_iter()
            .filter(|(name, _)| {
                proxy_config
                    .rules
                    .iter()
                    .any(|rule| rule.lease.as_ref() == Some(name))
            })
            .collect();
        // A backend reads its parent credential from this process's
        // environment when it creates a lease, so load it now and keep it
        // for the session. The child's environment drops it below.
        let mut lease_env = crate::lease::TempEnvGuard::default();
        let mut _lease_files = Vec::new();
        for (name, lease) in &leases {
            _lease_files.extend(
                crate::lease::load_backend_secrets(lease, &config, &profile, &mut lease_env)
                    .await?,
            );
            if let Some(missing) = lease.check_prerequisites() {
                return Err(FnoxError::Config(format!(
                    "Proxy rule for lease '{name}' can't create it: {missing}"
                )));
            }
        }

        let plan = ProxyPlan::with_leases(proxy_config, &values, &lease_credentials)?;
        if !leases.is_empty() {
            plan.set_lease_minter(std::sync::Arc::new(LedgerMinter {
                project_dir: crate::lease::project_dir_from_config(&config, &cli.config),
                leases: leases.clone(),
            }));
        }
        let proxy_leases = plan.leases();
        let session = std::sync::Arc::new(session);
        plan.set_session(session.clone());
        // Resolving later (a pending secret, or an MCP tool) must not prompt:
        // the child owns the terminal now
        crate::env::set_non_interactive(true);
        plan.set_mcp_service(mcp_service(
            session,
            config.mcp.clone().unwrap_or_default(),
            plan.handle(),
        ));
        for secret in plan.pending() {
            tracing::warn!(
                "fnox proxy: '{secret}' is not set; requests that need it are refused until it is (for example, run `fnox set {secret}`)"
            );
        }
        let child_env = plan.child_env.clone();
        let listener = sandbox
            .as_ref()
            .map_or(ProxyListener::Loopback, Sandbox::listener);
        let running = RunningProxy::start(plan, listener).await?;
        let mut mount_points = Vec::new();
        let (program, args, proxy_url, ca_path) = match &sandbox {
            Some(sandbox) => {
                let launch = sandbox.launch(&running, &self.command)?;
                mount_points = launch.mount_points;
                (
                    launch.program,
                    launch.args,
                    launch.proxy_url,
                    launch.ca_path.to_string_lossy().to_string(),
                )
            }
            None => {
                tracing::warn!(
                    "fnox proxy is not sandboxing the command; same-user code may bypass the proxy (see --sandbox)"
                );
                (
                    self.command[0].clone().into(),
                    self.command[1..].iter().map(Into::into).collect(),
                    running
                        .proxy_url()
                        .expect("a loopback proxy has a proxy URL"),
                    running.ca_path().to_string_lossy().to_string(),
                )
            }
        };

        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
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
        for provider in config.get_providers(&profile)?.values() {
            for dependency in provider.env_dependencies() {
                command.env_remove(dependency);
            }
        }
        for key in &lease_env.keys {
            command.env_remove(key);
        }
        for lease in leases.values() {
            for key in lease.consumed_env_vars() {
                command.env_remove(key);
            }
        }
        if sandbox.is_some() {
            for key in crate::sandbox::UNSET_ENV {
                command.env_remove(key);
            }
        }
        command.env("FNOX_DAEMON", "off");
        command.env("FNOX_NON_INTERACTIVE", "1");
        // `fnox mcp` in the child relays to the tools this process serves
        command.env(crate::proxy::MCP_RELAY_ENV, "1");
        command.env(crate::proxy::MCP_RELAY_PROFILE_ENV, profile.join(","));
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

        let outcome = if sandbox.is_some() {
            run_until_interrupted(command).await
        } else if !leases.is_empty() {
            // Ctrl-C would otherwise end fnox before it revokes the leases
            run_forwarding_signals(command).await
        } else {
            command.status().await.map(Outcome::Exited)
        };
        crate::sandbox::remove_mount_points(&mount_points);
        running.shutdown().await;
        proxy_leases.revoke_all().await;
        drop(lease_env);
        // `process::exit` below skips destructors, so this removes the
        // sandbox's socket directory.
        drop(sandbox);
        let status = match outcome {
            Ok(Outcome::Interrupted(signal)) => std::process::exit(128 + signal),
            Ok(Outcome::Exited(status)) => Ok(status),
            Err(error) => Err(error),
        };
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

/// How a command ended.
enum Outcome {
    Exited(std::process::ExitStatus),
    /// fnox was interrupted by this signal and stopped the command.
    Interrupted(i32),
}

/// Runs `command`, and if fnox is interrupted first, stops it so the caller
/// can remove the sandbox's placeholder files. The sandbox starts a session of
/// its own, so Ctrl-C reaches fnox and not the command.
async fn run_until_interrupted(mut command: tokio::process::Command) -> std::io::Result<Outcome> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        // Registered before the spawn, so no signal arrives unobserved.
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let mut child = command.spawn()?;
        let number = tokio::select! {
            status = child.wait() => return status.map(Outcome::Exited),
            _ = interrupt.recv() => libc::SIGINT,
            _ = terminate.recv() => libc::SIGTERM,
            _ = hangup.recv() => libc::SIGHUP,
        };
        let _ = child.kill().await;
        Ok(Outcome::Interrupted(number))
    }
    #[cfg(not(unix))]
    {
        command.status().await.map(Outcome::Exited)
    }
}

/// Runs `command` and passes SIGINT and SIGTERM on to it instead of letting
/// them end fnox, so fnox outlives the command and can clean up after it.
async fn run_forwarding_signals(mut command: tokio::process::Command) -> std::io::Result<Outcome> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut child = command.spawn()?;
        let pid = child.id();
        let forward = |signal| {
            if let Some(pid) = pid {
                // SAFETY: kill takes only integer arguments.
                unsafe { libc::kill(pid as i32, signal) };
            }
        };
        loop {
            tokio::select! {
                status = child.wait() => return status.map(Outcome::Exited),
                _ = interrupt.recv() => forward(libc::SIGINT),
                _ = terminate.recv() => forward(libc::SIGTERM),
            }
        }
    }
    #[cfg(not(unix))]
    {
        command.status().await.map(Outcome::Exited)
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
