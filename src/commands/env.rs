use crate::child_env::{
    self, DescribeDocument, ENV_SCHEMA, EnvDocument, EnvScope, ErrorDocument, ErrorKind, Roots,
};
use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};
use serde::Serialize;
use std::io::Write;
use strum::{Display, EnumString, VariantNames};

/// Where the environment is meant to be injected
#[derive(Debug, Clone, Copy, usage_rs::ValueEnum, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum EnvFor {
    /// A command started by `fnox exec`: `env = true` and `env = "exec"` secrets, plus leases
    Exec,
    /// An interactive shell: `env = true` secrets only, no leases
    Shell,
}

impl From<EnvFor> for EnvScope {
    fn from(value: EnvFor) -> Self {
        match value {
            EnvFor::Exec => EnvScope::Exec,
            EnvFor::Shell => EnvScope::Shell,
        }
    }
}

/// Print the environment fnox would give a command, as JSON for other tools
///
/// For tools that start processes themselves, such as mise. stdout carries one
/// line of JSON and contains secret values in plain text. Callers apply `remove`,
/// then `set`, then `files`.
#[derive(Debug, usage_rs::Args)]
pub struct EnvCommand {
    /// List keys and where each may be injected, without resolving anything
    #[usage(long)]
    pub describe: bool,

    /// Where the environment will be injected
    #[usage(long = "for", value_name = "SCOPE", default = "exec", value_enum)]
    pub scope: EnvFor,

    /// Print JSON (required)
    #[usage(long)]
    pub json: bool,

    /// Only these keys, plus the secrets they depend on. Repeat or comma-separate
    #[usage(long, value_name = "KEY", delimiter = ',')]
    pub keys: Vec<String>,
}

/// An error document for the phase that failed, paired with the error to return.
type Failure = Box<(ErrorDocument, FnoxError)>;

fn failure(kind: ErrorKind, err: FnoxError) -> Failure {
    Box::new((ErrorDocument::new(kind, err.to_string()), err))
}

fn print_document<T: Serialize>(doc: &T) -> Result<()> {
    let mut out = std::io::stdout().lock();
    let write = serde_json::to_writer(&mut out, doc)
        .map_err(std::io::Error::from)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    write.map_err(|e| FnoxError::Config(format!("Failed to write to stdout: {e}")))
}

impl EnvCommand {
    pub async fn run(&self, cli: &Cli) -> Result<()> {
        if !self.json {
            return Err(FnoxError::Config("fnox env requires --json".to_string()));
        }
        match self.run_phases(cli).await {
            Ok(()) => Ok(()),
            Err(failure) => {
                let (doc, err) = *failure;
                print_document(&doc)?;
                Err(err)
            }
        }
    }

    async fn run_phases(&self, cli: &Cli) -> std::result::Result<(), Failure> {
        let scope: EnvScope = self.scope.into();

        // Phase `config`
        let loaded = (|| -> Result<_> {
            let config = crate::commands::load_read_config(cli)?;
            let profile = Config::get_profiles(cli.profile.as_slice());
            let secrets = config.get_secrets(&profile)?;
            let leases = config.get_leases(&profile)?;
            Ok((config, profile, secrets, leases))
        })()
        .map_err(|e| failure(ErrorKind::Config, e))?;
        let (config, profile, secrets, leases) = loaded;

        // Phase `invalid_keys`
        let sel = match child_env::select(&secrets, &leases, scope, roots_for(&self.keys)) {
            Ok(sel) => sel,
            Err(rejection) => {
                let err = rejection.to_error();
                let doc = ErrorDocument::invalid_keys(rejection, err.to_string());
                return Err(Box::new((doc, err)));
            }
        };

        if self.describe {
            let doc = DescribeDocument {
                schema: ENV_SCHEMA,
                fnox_version: env!("CARGO_PKG_VERSION").to_string(),
                profile,
                keys: child_env::describe(&secrets, &leases, sel.requested.as_deref()),
                dynamic_leases: child_env::dynamic_leases(&leases),
            };
            return print_document(&doc).map_err(|e| failure(ErrorKind::Resolution, e));
        }

        // Phase `resolution`
        let result = async {
            let env = child_env::plan(cli, &config, &profile, scope, roots_for(&self.keys), "env")
                .await?;
            print_document(&EnvDocument::new(scope, profile.clone(), env))
        }
        .await;
        result.map_err(|e| failure(ErrorKind::Resolution, e))
    }
}

fn roots_for(keys: &[String]) -> Roots<'_> {
    if keys.is_empty() {
        Roots::Scope
    } else {
        Roots::Keys(keys)
    }
}
