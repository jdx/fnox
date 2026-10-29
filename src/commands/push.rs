use crate::commands::Cli;
use crate::config::{Config, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::push_targets::PushTargetConfig;
use crate::secret_resolver::{dependency_closure, resolve_secrets_batch};
use console;
use indexmap::IndexMap;
use std::io;

/// Copy secrets into write-only stores such as GitHub Actions or Vercel
///
/// Each secret's `push` field names targets from `[targets]`. fnox resolves
/// the value through the secret's provider, as `fnox get` would, and writes it
/// to every listed target. Targets that use a CLI receive the value on stdin.
///
/// Targets cannot be read back, so fnox stays the source of truth: run push
/// again after changing a value.
#[derive(usage_rs::Args)]
#[usage(
    example("fnox push --dry-run", header = "Preview which secrets go where"),
    example("fnox push", header = "Push every secret that lists targets"),
    example(
        "fnox push STRIPE_KEY --target gh",
        header = "Push one secret to one target"
    ),
    after_long_help = "See also:\n- Push targets: https://fnox.jdx.dev/guide/push\n- Target catalog: https://fnox.jdx.dev/targets/"
)]
pub struct PushCommand {
    /// Push only these keys
    keys: Vec<String>,

    /// Push without asking for confirmation
    #[usage(short, long)]
    force: bool,

    /// List what would be pushed without pushing anything
    #[usage(short = 'n', long)]
    dry_run: bool,

    /// Push only to this target; repeat for several
    #[usage(short = 't', long)]
    target: Vec<String>,
}

impl PushCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profiles = Config::get_profiles(cli.profile.as_slice());
        let secrets = config.get_secrets(&profiles)?;
        let targets = config.get_targets(&profiles)?;

        let plan = self.plan(&secrets, &targets)?;
        if plan.is_empty() {
            println!("No secrets to push");
            return Ok(());
        }
        // Check every target in use, so a config mistake stops the push (or
        // dry run) before anything is written
        for (name, target) in &targets {
            if plan.values().flatten().any(|t| t == name) {
                target.validate(name)?;
            }
        }

        let pushes: usize = plan.values().map(Vec::len).sum();
        if self.dry_run {
            println!(
                "{} Would push {} secrets ({pushes} writes):",
                console::style("[dry-run]").yellow().bold(),
                plan.len()
            );
            print_plan(&plan, &targets);
            return Ok(());
        }

        if !self.force {
            if cli.non_interactive {
                return Err(FnoxError::Config(
                    "fnox push needs confirmation; pass --force to push without it".to_string(),
                ));
            }
            println!("Ready to push {} secrets ({pushes} writes):", plan.len());
            print_plan(&plan, &targets);
            println!("\nContinue? [y/N]");
            let mut response = String::new();
            io::stdin()
                .read_line(&mut response)
                .map_err(|e| FnoxError::StdinReadFailed { source: e })?;
            if !response.trim().to_lowercase().starts_with('y') {
                println!("Push cancelled");
                return Ok(());
            }
        }

        // Resolve the secrets each pushed value depends on too (defaults that
        // reference other secrets, provider credentials), but push only the plan
        let roots: Vec<String> = plan.keys().cloned().collect();
        let to_resolve = dependency_closure(&config, &profiles, &secrets, &roots)?;
        let resolved = resolve_secrets_batch(&config, &profiles, &to_resolve).await?;

        let mut pushed = 0;
        let mut failed = Vec::new();
        for (key, target_names) in &plan {
            let Some(Some(value)) = resolved.get(key) else {
                tracing::warn!("Skipping '{key}': could not resolve value");
                failed.push(key.clone());
                continue;
            };
            for target_name in target_names {
                match targets[target_name].target().push(key, value).await {
                    Ok(()) => {
                        pushed += 1;
                        println!(
                            "{} {} → {}",
                            console::style("✓").green(),
                            console::style(key).cyan(),
                            target_name
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "{} {} → {}: {e}",
                            console::style("✗").red(),
                            console::style(key).cyan(),
                            target_name
                        );
                        failed.push(format!("{key} → {target_name}"));
                    }
                }
            }
        }

        if failed.is_empty() {
            println!("Pushed {pushed} of {pushes}");
            Ok(())
        } else {
            Err(FnoxError::Config(format!(
                "pushed {pushed} of {pushes}; failed: {}",
                failed.join(", ")
            )))
        }
    }

    /// Map each secret to push to the targets it goes to, checking that every
    /// target exists before anything is resolved
    fn plan(
        &self,
        secrets: &IndexMap<String, SecretConfig>,
        targets: &IndexMap<String, PushTargetConfig>,
    ) -> Result<IndexMap<String, Vec<String>>> {
        for key in &self.keys {
            match secrets.get(key) {
                None => {
                    return Err(FnoxError::Config(format!(
                        "secret '{key}' is not defined in the active profile"
                    )));
                }
                Some(secret) if secret.push.is_empty() => {
                    return Err(FnoxError::Config(format!(
                        "secret '{key}' has no push targets; add push = [\"<target>\"] to it"
                    )));
                }
                Some(_) => {}
            }
        }
        for name in &self.target {
            if !targets.contains_key(name) {
                return Err(unknown_target(name, None, targets));
            }
        }

        let mut plan = IndexMap::new();
        for (key, secret) in secrets {
            if !self.keys.is_empty() && !self.keys.contains(key) {
                continue;
            }
            let mut names = Vec::new();
            for name in &secret.push {
                if !targets.contains_key(name) {
                    return Err(unknown_target(name, Some(key), targets));
                }
                if (self.target.is_empty() || self.target.contains(name)) && !names.contains(name) {
                    names.push(name.clone());
                }
            }
            if !names.is_empty() {
                plan.insert(key.clone(), names);
            }
        }
        Ok(plan)
    }
}

fn unknown_target(
    name: &str,
    key: Option<&str>,
    targets: &IndexMap<String, PushTargetConfig>,
) -> FnoxError {
    let configured = if targets.is_empty() {
        "no targets are configured; add one under [targets]".to_string()
    } else {
        format!(
            "configured targets: {}",
            targets.keys().cloned().collect::<Vec<_>>().join(", ")
        )
    };
    let subject = match key {
        Some(key) => format!("secret '{key}' pushes to unknown target '{name}'"),
        None => format!("unknown target '{name}'"),
    };
    FnoxError::Config(format!("{subject}; {configured}"))
}

fn print_plan(plan: &IndexMap<String, Vec<String>>, targets: &IndexMap<String, PushTargetConfig>) {
    for (key, target_names) in plan {
        for name in target_names {
            println!(
                "  {} → {} ({})",
                console::style(key).cyan(),
                console::style(name).green(),
                console::style(targets[name].target().describe()).dim()
            );
        }
    }
}
