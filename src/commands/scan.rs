use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use strum::{Display, EnumString};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::{DirEntry, WalkBuilder};
use regex::Regex;
use serde::Serialize;

use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Resolved secrets shorter than this many characters (after trimming
/// surrounding whitespace) are not searched for. Values like `1`, `true`, or
/// `dev` would match almost any file and bury real findings.
const MIN_SECRET_LEN: usize = 8;

const HOOK_MARKER: &str = "# fnox-scan-hook";

/// Scan files for secrets committed in plaintext
///
/// Walks DIR and reports lines that look like cloud keys, API tokens, private
/// keys, or password assignments, with the matched value redacted. It skips
/// gitignored files, binary files, files over 5 MiB, and directories such as
/// `.git`, `node_modules`, `target`, and `vendor`.
///
/// fnox exits 1 when it finds anything. Findings are heuristic: review each one,
/// and do not treat a clean scan as proof that no secret is present.
///
/// With `--values`, fnox instead resolves the active profile's secrets and
/// reports every file that contains one of their actual values. This has far
/// fewer false positives than the pattern heuristics. Values are never printed,
/// only the name of the matching secret. Empty secrets and secrets shorter than
/// 8 characters are skipped. Add `--staged` to check the content staged in git
/// (the index) rather than the working tree, and `--install-hook` to install a
/// pre-commit hook that runs `fnox scan --values --staged`.
#[derive(usage_rs::Args)]
#[usage(
    example("fnox scan", header = "Scan the current directory"),
    example("fnox scan . --format json", header = "Print findings as JSON"),
    example("fnox scan . --ignore 'fixtures/**'", header = "Skip matching files"),
    example(
        "fnox scan --values",
        header = "Find files containing this profile's real secret values"
    ),
    example(
        "fnox scan --values --staged",
        header = "Check only what is staged for commit"
    ),
    example(
        "fnox scan --install-hook",
        header = "Install a pre-commit hook that scans staged secrets"
    ),
    after_long_help = "See also:\n- Import and export: https://fnox.jdx.dev/guide/import-export"
)]
pub struct ScanCommand {
    /// Directory to scan
    #[usage(arg, default = ".", value_hint = ValueHint::DirPath)]
    dir: PathBuf,

    /// Skip files whose path or name matches this glob; repeatable
    #[usage(short, long)]
    ignore: Vec<String>,

    /// Print only the paths of files with findings
    #[usage(short, long)]
    quiet: bool,

    /// With --install-hook, append to an existing pre-commit hook instead of refusing
    #[usage(long)]
    append: bool,

    /// Output format
    #[usage(long, value_enum, default_value_t = ScanFormat::Human, default = "human")]
    format: ScanFormat,

    /// Also scan files ignored by .gitignore (working tree scans only)
    #[usage(long)]
    include_ignored: bool,

    /// Install a git pre-commit hook that runs `fnox scan --values --staged`
    #[usage(long)]
    install_hook: bool,

    /// Scan content staged in git (the index) instead of the working tree
    #[usage(long)]
    staged: bool,

    /// Resolve the active profile's secrets and report files containing their values
    #[usage(long)]
    values: bool,
}

#[derive(Clone, Copy, Debug, usage_rs::ValueEnum, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
enum ScanFormat {
    /// Readable report grouped by file
    Human,
    /// JSON with `findings` and a `summary`
    Json,
}

#[derive(Clone, Copy)]
struct Detector {
    name: &'static str,
    severity: Severity,
    regex: &'static Regex,
    capture: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    High,
    Medium,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => f.write_str("high"),
            Self::Medium => f.write_str("medium"),
        }
    }
}

#[derive(Debug, Serialize)]
struct ScanFinding {
    path: String,
    line: usize,
    column: usize,
    detector: &'static str,
    severity: Severity,
    redacted: String,
    /// Name of the fnox secret whose value matched (`--values` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
}

/// A resolved secret value to search for. Never printed or serialized.
struct ResolvedSecret {
    name: String,
    value: String,
}

#[derive(Clone, Copy)]
enum Matcher<'a> {
    Patterns,
    Values(&'a [ResolvedSecret]),
}

#[derive(Debug, Serialize)]
struct ScanSummary {
    files_scanned: usize,
    files_with_findings: usize,
    findings: usize,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    findings: Vec<ScanFinding>,
    summary: ScanSummary,
}

static AWS_ACCESS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap());
static GITHUB_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").unwrap());
static SLACK_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap());
static STRIPE_SECRET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk_live_[A-Za-z0-9]{16,}\b").unwrap());
static GOOGLE_API_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap());
static PEM_PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});
static SECRET_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?im)(?:^|[^A-Za-z0-9_])(?P<key>password|passwd|pwd|api[_-]?key|secret|client[_-]?secret|token|auth[_-]?token)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9][A-Za-z0-9_./+=:@!#$%^&*?~-]{7,})["']?"#,
    )
    .unwrap()
});

static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    vec![
        Detector {
            name: "aws-access-key",
            severity: Severity::High,
            regex: &AWS_ACCESS_KEY_RE,
            capture: None,
        },
        Detector {
            name: "github-token",
            severity: Severity::High,
            regex: &GITHUB_TOKEN_RE,
            capture: None,
        },
        Detector {
            name: "slack-token",
            severity: Severity::High,
            regex: &SLACK_TOKEN_RE,
            capture: None,
        },
        Detector {
            name: "stripe-live-secret-key",
            severity: Severity::High,
            regex: &STRIPE_SECRET_RE,
            capture: None,
        },
        Detector {
            name: "google-api-key",
            severity: Severity::High,
            regex: &GOOGLE_API_KEY_RE,
            capture: None,
        },
        Detector {
            name: "pem-private-key",
            severity: Severity::High,
            regex: &PEM_PRIVATE_KEY_RE,
            capture: None,
        },
        Detector {
            name: "secret-assignment",
            severity: Severity::Medium,
            regex: &SECRET_ASSIGNMENT_RE,
            capture: Some("secret"),
        },
    ]
});

impl ScanCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.install_hook {
            let message = install_hook(&self.dir, self.append)?;
            println!("{message}");
            return Ok(());
        }
        if self.append {
            return Err(FnoxError::Config(
                "--append only applies to --install-hook".to_string(),
            ));
        }
        if self.include_ignored && self.staged {
            return Err(FnoxError::Config(
                "--include-ignored does not apply to --staged scans".to_string(),
            ));
        }

        let ignore_globs = build_ignore_globs(&self.ignore)?;

        let resolved = if self.values {
            Some(resolve_secret_values(cli, &config).await?)
        } else {
            None
        };
        let matcher = match &resolved {
            Some(secrets) => Matcher::Values(secrets),
            None => Matcher::Patterns,
        };

        let report = if self.staged {
            scan_staged(&self.dir, ignore_globs.as_ref(), matcher)?
        } else {
            scan_directory(
                &self.dir,
                ignore_globs.as_ref(),
                self.include_ignored,
                matcher,
            )?
        };

        match (self.quiet, self.format) {
            (true, ScanFormat::Human) => print_quiet_report(&report),
            (true, ScanFormat::Json) => print_quiet_json_report(&report)?,
            (false, ScanFormat::Human) => {
                print_human_report(&self.dir, &report, self.values, self.staged)
            }
            (false, ScanFormat::Json) => {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }

        if !report.findings.is_empty() {
            return Err(FnoxError::ScanSecretsFound);
        }

        Ok(())
    }
}

/// Resolve the active profile's secrets through the normal path (daemon,
/// providers, `if_missing`). A resolution failure is returned as an error so a
/// scan never passes because a secret could not be read.
async fn resolve_secret_values(cli: &Cli, config: &Config) -> Result<Vec<ResolvedSecret>> {
    let profile = Config::get_profiles(cli.profile.as_slice());
    let profile_secrets = config.get_secrets(&profile)?;
    if profile_secrets.is_empty() {
        eprintln!(
            "Warning: no secrets defined in profile '{}'; nothing to scan for",
            Config::display_profiles(&profile)
        );
        return Ok(Vec::new());
    }

    let values = crate::daemon::resolve_batch(
        cli,
        config,
        &profile,
        &profile_secrets,
        crate::daemon::Purpose::ListValues,
        true,
    )
    .await?;

    let mut secrets = Vec::new();
    let mut unresolved = Vec::new();
    let mut too_short = Vec::new();
    for (name, value) in values {
        match value {
            None => unresolved.push(name),
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.chars().count() < MIN_SECRET_LEN {
                    too_short.push(name);
                } else {
                    secrets.push(ResolvedSecret {
                        name,
                        value: trimmed.to_string(),
                    });
                }
            }
        }
    }

    if !unresolved.is_empty() {
        eprintln!(
            "Warning: {} secret(s) have no value and were not checked: {}",
            unresolved.len(),
            unresolved.join(", ")
        );
    }
    if !too_short.is_empty() {
        eprintln!(
            "Note: {} secret(s) are empty or shorter than {MIN_SECRET_LEN} characters and were skipped: {}",
            too_short.len(),
            too_short.join(", ")
        );
    }

    if secrets.is_empty() && !unresolved.is_empty() {
        return Err(FnoxError::Config(format!(
            "None of the profile's secrets could be resolved, so nothing was scanned: {}",
            unresolved.join(", ")
        )));
    }

    Ok(secrets)
}

fn git<S: AsRef<std::ffi::OsStr>>(dir: &Path, args: &[S]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|err| FnoxError::Config(format!("Failed to run git: {err}")))?;
    if !output.status.success() {
        return Err(FnoxError::Config(format!(
            "git {} failed: {}",
            args.iter()
                .map(|arg| arg.as_ref().to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

/// A file staged for commit. `path` keeps the raw bytes git reported so the
/// blob can be looked up even when the name is not valid UTF-8.
struct StagedFile {
    path: Vec<u8>,
    /// Blob id from the index; looked up by id so odd file names (such as
    /// `1:notes.txt`, which git would read as a stage selector) cannot misresolve.
    sha: String,
}

impl StagedFile {
    fn display(&self) -> String {
        String::from_utf8_lossy(&self.path).into_owned()
    }
}

/// List every added/copied/modified/renamed file in the git index, returning
/// the repository root and the files. Contents are read lazily by
/// [`read_staged_blob`] so skipped files are never loaded.
fn staged_files(dir: &Path) -> Result<(PathBuf, Vec<StagedFile>)> {
    let top = git(dir, &["rev-parse", "--show-toplevel"])?;
    let top = PathBuf::from(String::from_utf8_lossy(&top).trim_end_matches(['\n', '\r']));

    let raw = git(
        &top,
        &[
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--diff-filter=ACMR",
            "--no-renames",
        ],
    )?;
    // Records: ":<old mode> <new mode> <old sha> <new sha> <status>\0<path>\0"
    let mut fields = raw.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut files = Vec::new();
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let meta = String::from_utf8_lossy(meta);
        let new_mode = meta.split_whitespace().nth(1).unwrap_or("");
        // Skip symlinks (120000) and submodules (160000): not file content.
        if new_mode == "120000" || new_mode == "160000" {
            continue;
        }
        let Some(sha) = meta.split_whitespace().nth(3) else {
            continue;
        };
        files.push(StagedFile {
            path: path.to_vec(),
            sha: sha.to_string(),
        });
    }
    Ok((top, files))
}

/// Blob sizes for all staged files in a single `git cat-file --batch-check`.
fn staged_sizes(top: &Path, files: &[StagedFile]) -> Result<Vec<u64>> {
    use std::io::Write;
    use std::process::Stdio;

    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["cat-file", "--batch-check"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| FnoxError::Config(format!("Failed to run git: {err}")))?;
    let input: String = files.iter().map(|f| format!("{}\n", f.sha)).collect();
    let mut stdin = child.stdin.take().expect("piped stdin");
    // Write from a thread so a full stdout pipe cannot deadlock a large input.
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|err| FnoxError::Config(format!("Failed to run git: {err}")))?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(FnoxError::Config(format!(
            "git cat-file --batch-check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // Lines: "<sha> <type> <size>"
    let sizes: Vec<u64> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            line.split_whitespace()
                .nth(2)
                .and_then(|size| size.parse().ok())
                .unwrap_or(u64::MAX)
        })
        .collect();
    if sizes.len() != files.len() {
        return Err(FnoxError::Config(
            "git cat-file --batch-check returned an unexpected number of results".to_string(),
        ));
    }
    Ok(sizes)
}

fn read_staged_blob(top: &Path, file: &StagedFile) -> Result<Vec<u8>> {
    git(top, &["cat-file", "blob", file.sha.as_str()])
}

fn scan_staged(
    dir: &Path,
    ignore_globs: Option<&GlobSet>,
    matcher: Matcher<'_>,
) -> Result<ScanReport> {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let (top, files) = staged_files(dir)?;
    let sizes = staged_sizes(&top, &files)?;

    for (file, size) in files.into_iter().zip(sizes) {
        let path = file.display();
        if ignored_by_globs(ignore_globs, Path::new(&path), Path::new(&path)) {
            continue;
        }
        if size > MAX_FILE_SIZE {
            tracing::debug!("Skipping large staged file {path}");
            continue;
        }
        let bytes = read_staged_blob(&top, &file)?;
        if bytes.contains(&0) {
            tracing::debug!("Skipping binary staged file {path}");
            continue;
        }
        files_scanned += 1;
        findings.extend(scan_text(&path, &String::from_utf8_lossy(&bytes), matcher));
    }

    Ok(build_report(findings, files_scanned))
}

fn ignored_by_globs(globs: Option<&GlobSet>, rel: &Path, path: &Path) -> bool {
    globs.is_some_and(|globs| {
        globs.is_match(rel)
            || path
                .file_name()
                .is_some_and(|name| globs.is_match(Path::new(name)))
    })
}

fn build_report(findings: Vec<ScanFinding>, files_scanned: usize) -> ScanReport {
    let files_with_findings = findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let finding_count = findings.len();

    ScanReport {
        findings,
        summary: ScanSummary {
            files_scanned,
            files_with_findings,
            findings: finding_count,
        },
    }
}

fn scan_text(path: &str, content: &str, matcher: Matcher<'_>) -> Vec<ScanFinding> {
    match matcher {
        Matcher::Patterns => scan_content(path, content),
        Matcher::Values(secrets) => scan_values(path, content, secrets),
    }
}

/// Find occurrences of the resolved secret values. Findings carry the secret's
/// name and a fully masked placeholder: no part of the value is ever shown.
fn scan_values(path: &str, content: &str, secrets: &[ResolvedSecret]) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let mut line_starts: Option<Vec<usize>> = None;
    for secret in secrets {
        for (offset, _) in content.match_indices(secret.value.as_str()) {
            let starts = line_starts.get_or_insert_with(|| {
                std::iter::once(0)
                    .chain(content.match_indices('\n').map(|(idx, _)| idx + 1))
                    .collect()
            });
            let line_idx = starts.partition_point(|start| *start <= offset) - 1;
            let line = line_idx + 1;
            let column = content[starts[line_idx]..offset].chars().count() + 1;
            findings.push(ScanFinding {
                path: path.to_string(),
                line,
                column,
                detector: "resolved-secret",
                severity: Severity::High,
                redacted: "****".to_string(),
                secret: Some(secret.name.clone()),
            });
        }
    }
    findings.sort_by_key(|finding| (finding.line, finding.column));
    findings
}

/// Locate the hooks directory git will actually use (honours `core.hooksPath`
/// and linked worktrees) and install the pre-commit hook there.
fn install_hook(dir: &Path, append: bool) -> Result<String> {
    let hooks = git(dir, &["rev-parse", "--git-path", "hooks"])?;
    let hooks = PathBuf::from(String::from_utf8_lossy(&hooks).trim_end_matches(['\n', '\r']));
    let hooks = if hooks.is_absolute() {
        hooks
    } else {
        dir.join(hooks)
    };
    install_hook_in(&hooks, append)
}

fn hook_block(append: bool) -> String {
    // When appended, keep the exit status of the script above: a failure there
    // must not be masked by a passing scan.
    let (prelude, epilogue) = if append {
        ("fnox_prev_status=$?\n", "exit \"$fnox_prev_status\"\n")
    } else {
        ("", "")
    };
    format!(
        "{HOOK_MARKER}\n{prelude}if command -v fnox >/dev/null 2>&1; then\n  fnox scan --values --staged || exit 1\nelse\n  echo \"fnox not found; skipping secret scan\" >&2\nfi\n{epilogue}"
    )
}

/// Whether the script's shebang names a POSIX-style shell that can run the
/// generated block (`sh`, `bash`, `dash`, `ash`, `ksh`, `zsh`).
fn is_posix_shell_shebang(script: &str) -> bool {
    let Some(line) = script.lines().next().and_then(|l| l.strip_prefix("#!")) else {
        return false;
    };
    let mut words = line.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    let name = |word: &str| word.rsplit('/').next().unwrap_or(word).to_string();
    let interpreter = if name(first) == "env" {
        // `env [-S] [VAR=val ...] shell`: take the first non-option, non-assignment word.
        let mut found = None;
        while let Some(word) = words.next() {
            if matches!(word, "-u" | "--unset" | "-C" | "--chdir") {
                words.next(); // option argument
            } else if !word.starts_with('-') && !word.contains('=') {
                found = Some(name(word));
                break;
            }
        }
        match found {
            Some(word) => word,
            None => return false,
        }
    } else {
        name(first)
    };
    matches!(
        interpreter.as_str(),
        "sh" | "bash" | "dash" | "ash" | "ksh" | "zsh"
    )
}

fn install_hook_in(hooks_dir: &Path, append: bool) -> Result<String> {
    fs::create_dir_all(hooks_dir)?;
    let hook = hooks_dir.join("pre-commit");

    if hook.exists() {
        let existing = fs::read_to_string(&hook).map_err(|err| {
            FnoxError::Config(format!("Cannot read existing {}: {err}", hook.display()))
        })?;
        if existing.contains(HOOK_MARKER) {
            return Ok(format!("fnox hook already installed at {}", hook.display()));
        }
        if !append {
            return Err(FnoxError::Config(format!(
                "{} already exists. Re-run with --append to add the fnox check to it, or add `fnox scan --values --staged` to it yourself (or to your hk / pre-commit config).",
                hook.display()
            )));
        }
        if !is_posix_shell_shebang(&existing) {
            return Err(FnoxError::Config(format!(
                "Cannot append to {}: it is not a shell script. Add `fnox scan --values --staged` to it manually.",
                hook.display()
            )));
        }
        let mut updated = existing;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push('\n');
        updated.push_str(&hook_block(true));
        fs::write(&hook, updated)?;
        make_executable(&hook)?;
        return Ok(format!(
            "Appended fnox secret scan to {}. Note: an earlier `exit` in that script would skip it.",
            hook.display()
        ));
    }

    fs::write(&hook, format!("#!/bin/sh\n{}", hook_block(false)))?;
    make_executable(&hook)?;
    Ok(format!("Installed pre-commit hook at {}", hook.display()))
}

/// Ensure git will run the hook: it ignores hooks without the executable bit.
fn make_executable(_hook: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(_hook)?.permissions().mode();
        // Add execute only where read is already granted: never widen access.
        let exec = (mode & 0o444) >> 2;
        fs::set_permissions(_hook, fs::Permissions::from_mode(mode | exec))?;
    }
    Ok(())
}

fn scan_directory(
    dir: &Path,
    ignore_globs: Option<&GlobSet>,
    include_ignored: bool,
    matcher: Matcher<'_>,
) -> Result<ScanReport> {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let root = fs::canonicalize(dir)?;
    let cwd = std::env::current_dir()?;

    let mut walker = WalkBuilder::new(&root);
    walker.hidden(false);
    walker.git_ignore(!include_ignored);
    walker.git_exclude(!include_ignored);
    walker.git_global(!include_ignored);
    walker.filter_entry(should_visit_entry);

    for result in walker.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                tracing::debug!("Skipping unreadable path during scan: {err}");
                continue;
            }
        };

        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let path = entry.path();
        let rel_to_root = path.strip_prefix(&root).unwrap_or(path);
        if ignored_by_globs(ignore_globs, rel_to_root, path) {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                tracing::debug!("Skipping file without metadata {}: {err}", path.display());
                continue;
            }
        };
        if metadata.len() > MAX_FILE_SIZE {
            tracing::debug!("Skipping large file {}", path.display());
            continue;
        }

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::debug!("Skipping unreadable file {}: {err}", path.display());
                continue;
            }
        };
        if bytes.contains(&0) {
            tracing::debug!("Skipping binary file {}", path.display());
            continue;
        }

        let content = String::from_utf8_lossy(&bytes);
        files_scanned += 1;
        let display_path = display_path(path, &cwd);
        findings.extend(scan_text(&display_path, &content, matcher));
    }

    Ok(build_report(findings, files_scanned))
}

fn scan_content(path: &str, content: &str) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for detector in DETECTORS.iter() {
        for captures in detector.regex.captures_iter(content) {
            let Some(matched) = detector
                .capture
                .and_then(|name| captures.name(name))
                .or_else(|| captures.get(0))
            else {
                continue;
            };
            let secret = matched.as_str();

            if detector.name == "secret-assignment" && !looks_like_secret(secret) {
                continue;
            }

            let (line, column) = line_column(content, matched.start());
            findings.push(ScanFinding {
                path: path.to_string(),
                line,
                column,
                detector: detector.name,
                severity: detector.severity,
                redacted: redact(secret),
                secret: None,
            });
        }
    }

    findings
}

fn build_ignore_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|err| {
            FnoxError::Config(format!("Invalid --ignore glob '{pattern}': {err}"))
        })?;
        builder.add(glob);

        if !pattern.contains('/') {
            let nested = format!("**/{pattern}");
            let glob = Glob::new(&nested).map_err(|err| {
                FnoxError::Config(format!("Invalid --ignore glob '{pattern}': {err}"))
            })?;
            builder.add(glob);
        }
    }

    builder
        .build()
        .map(Some)
        .map_err(|err| FnoxError::Config(format!("Invalid --ignore glob set: {err}")))
}

fn should_visit_entry(entry: &DirEntry) -> bool {
    if !entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }

    let Some(name) = entry.file_name().to_str() else {
        return true;
    };

    !matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "target"
            | "node_modules"
            | "vendor"
            | "dist"
            | "build"
            | ".next"
            | ".cache"
            | "coverage"
    )
}

fn display_path(path: &Path, cwd: &Path) -> String {
    path.strip_prefix(cwd)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn print_human_report(dir: &Path, report: &ScanReport, values: bool, staged: bool) {
    let (noun, place) = match (values, staged) {
        (true, true) => ("resolved secret value", "the git index".to_string()),
        (true, false) => ("resolved secret value", format!("{}", dir.display())),
        (false, true) => ("potential secret", "the git index".to_string()),
        (false, false) => ("potential secret", format!("{}", dir.display())),
    };
    if report.findings.is_empty() {
        println!(
            "No {noun}s found in {} file(s) under {place}",
            report.summary.files_scanned
        );
        return;
    }

    println!(
        "Found {} {noun}(s) in {} file(s):",
        report.summary.findings, report.summary.files_with_findings
    );
    for finding in &report.findings {
        match &finding.secret {
            Some(name) => println!(
                "{}:{}:{} [{}] {} = {}",
                finding.path,
                finding.line,
                finding.column,
                finding.detector,
                name,
                finding.redacted
            ),
            None => println!(
                "{}:{}:{} [{} {}] {}",
                finding.path,
                finding.line,
                finding.column,
                finding.detector,
                finding.severity,
                finding.redacted
            ),
        }
    }
}

fn print_quiet_report(report: &ScanReport) {
    for path in report
        .findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect::<BTreeSet<_>>()
    {
        println!("{path}");
    }
}

fn print_quiet_json_report(report: &ScanReport) -> Result<()> {
    let paths = report
        .findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    println!("{}", serde_json::to_string_pretty(&paths)?);
    Ok(())
}

fn line_column(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut line_start = 0;

    for (idx, ch) in content.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            line_start = idx + ch.len_utf8();
        }
    }

    let column = content[line_start..offset].chars().count() + 1;
    (line, column)
}

fn looks_like_secret(secret: &str) -> bool {
    if secret.len() >= 20 && shannon_entropy(secret) >= 3.5 {
        return true;
    }

    secret.len() >= 8
        && secret.chars().any(|ch| ch.is_ascii_alphabetic())
        && secret
            .chars()
            .any(|ch| ch.is_ascii_digit() || !ch.is_ascii_alphanumeric())
        && !matches!(
            secret.to_ascii_lowercase().as_str(),
            "password" | "changeme" | "example" | "placeholder"
        )
}

fn shannon_entropy(value: &str) -> f64 {
    let len = value.chars().count() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }

    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn redact(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 8 {
        return "****".to_string();
    }

    let prefix = chars.iter().take(4).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();

    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_redacts_known_tokens() {
        let findings = scan_content("config.env", "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456\n");

        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|finding| finding.detector == "github-token")
        );
        assert!(
            findings
                .iter()
                .all(|finding| !finding.redacted.contains("abcdefghijklmnopqrstuvwxyz"))
        );
    }

    #[test]
    fn ignores_low_signal_assignments() {
        let findings = scan_content("config.env", "PASSWORD=example\nDEBUG_TOKEN=disabled\n");

        assert!(findings.is_empty());
    }

    #[test]
    fn reports_line_and_column_for_secret_value() {
        let findings = scan_content("config.env", "ok=true\npassword = abc12345!\n");

        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 12);
    }

    fn secret(name: &str, value: &str) -> ResolvedSecret {
        ResolvedSecret {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn value_scan_finds_secret_and_never_exposes_it() {
        let secrets = [secret("DB_PASSWORD", "s3cr3t-value-12345")];
        let findings = scan_values("a.env", "ok=1\nX=\"s3cr3t-value-12345\"\n", &secrets);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret.as_deref(), Some("DB_PASSWORD"));
        assert_eq!((findings[0].line, findings[0].column), (2, 4));
        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("s3cr3t"));
        assert_eq!(findings[0].redacted, "****");
    }

    #[test]
    fn value_scan_ignores_files_without_the_value() {
        let secrets = [secret("TOKEN", "abcdefghijkl")];
        assert!(scan_values("a.txt", "nothing to see", &secrets).is_empty());
    }

    #[test]
    fn value_scan_finds_multiline_values() {
        let pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----";
        let secrets = [secret("KEY", pem)];
        let findings = scan_values("k.pem", &format!("x\n{pem}\n"), &secrets);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.email=t@example.com", "-c", "user.name=t"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn staged_reader_uses_index_not_working_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git_ok(dir, &["init", "-q"]);
        fs::write(dir.join("staged.txt"), "token=staged-secret-value\n").unwrap();
        fs::write(dir.join("unstaged.txt"), "token=unstaged-secret\n").unwrap();
        fs::write(dir.join("bin.dat"), b"\0\x01binary").unwrap();
        git_ok(dir, &["add", "staged.txt", "bin.dat"]);
        // Edit after staging: the working tree no longer holds the staged content.
        fs::write(dir.join("staged.txt"), "clean now\n").unwrap();

        let (top, files) = staged_files(dir).unwrap();
        let staged = files.iter().find(|f| f.path == b"staged.txt").unwrap();
        assert_eq!(
            read_staged_blob(&top, staged).unwrap(),
            b"token=staged-secret-value\n"
        );
        assert!(files.iter().all(|f| f.path != b"unstaged.txt"));

        let secrets = [secret("T", "staged-secret-value")];
        let report = scan_staged(dir, None, Matcher::Values(&secrets)).unwrap();
        assert_eq!(report.summary.findings, 1);
        assert_eq!(report.summary.files_scanned, 1); // binary file skipped
        assert_eq!(report.findings[0].path, "staged.txt");
    }

    #[test]
    fn staged_reader_errors_outside_a_repository() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(staged_files(tmp.path()).is_err());
    }

    #[test]
    fn working_tree_scan_skips_gitignored_unless_included() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git_ok(dir, &["init", "-q"]);
        fs::write(dir.join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(dir.join("ignored.txt"), "value-abcdefgh-1234").unwrap();
        let secrets = [secret("S", "value-abcdefgh-1234")];

        let skipped = scan_directory(dir, None, false, Matcher::Values(&secrets)).unwrap();
        assert_eq!(skipped.summary.findings, 0);
        let included = scan_directory(dir, None, true, Matcher::Values(&secrets)).unwrap();
        assert_eq!(included.summary.findings, 1);
    }

    #[test]
    fn install_hook_creates_executable_hook_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let hooks = tmp.path().join("hooks");
        install_hook_in(&hooks, false).unwrap();
        let hook = hooks.join("pre-commit");
        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains("fnox scan --values --staged"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&hook).unwrap().permissions().mode() & 0o111,
                0o111
            );
        }
        let msg = install_hook_in(&hooks, false).unwrap();
        assert!(msg.contains("already installed"));
        assert_eq!(fs::read_to_string(&hook).unwrap(), content);
    }

    #[test]
    fn install_hook_never_overwrites_foreign_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let hook = tmp.path().join("pre-commit");
        fs::write(&hook, "#!/bin/sh\necho mine\n").unwrap();

        assert!(install_hook_in(tmp.path(), false).is_err());
        assert_eq!(fs::read_to_string(&hook).unwrap(), "#!/bin/sh\necho mine\n");

        install_hook_in(tmp.path(), true).unwrap();
        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.starts_with("#!/bin/sh\necho mine\n"));
        assert!(content.contains(HOOK_MARKER));
    }

    #[test]
    fn install_hook_refuses_to_append_to_non_shell_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let hook = tmp.path().join("pre-commit");
        fs::write(&hook, "#!/usr/bin/env python3\nprint(1)\n").unwrap();
        assert!(install_hook_in(tmp.path(), true).is_err());
        assert_eq!(
            fs::read_to_string(&hook).unwrap(),
            "#!/usr/bin/env python3\nprint(1)\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn staged_reader_handles_non_utf8_filenames() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git_ok(dir, &["init", "-q"]);
        let name = std::ffi::OsStr::from_bytes(b"caf\xe9.txt");
        // Some filesystems (APFS) reject non-UTF-8 names; nothing to test there.
        if fs::write(dir.join(name), "key=non-utf8-name-secret\n").is_err() {
            return;
        }
        git_ok(dir, &["add", "-A"]);

        let secrets = [secret("K", "non-utf8-name-secret")];
        let report = scan_staged(dir, None, Matcher::Values(&secrets)).unwrap();
        assert_eq!(report.summary.findings, 1);
    }

    #[test]
    fn value_scan_reports_many_repeated_matches_with_correct_positions() {
        let secrets = [secret("Z", "00000000")];
        let content = "00000000\nxx00000000\n".to_string() + &"00000000\n".repeat(1000);
        let findings = scan_values("z.txt", &content, &secrets);
        assert_eq!(findings.len(), 1002);
        assert_eq!((findings[1].line, findings[1].column), (2, 3));
    }

    #[test]
    fn append_requires_posix_shell_shebang() {
        assert!(is_posix_shell_shebang("#!/bin/sh\n"));
        assert!(is_posix_shell_shebang("#!/usr/bin/env bash\n"));
        assert!(is_posix_shell_shebang("#!/usr/bin/env -S zsh -e\n"));
        assert!(!is_posix_shell_shebang("#!/usr/bin/fish\n"));
        assert!(is_posix_shell_shebang(
            "#!/usr/bin/env -S -u BASH_ENV bash\n"
        ));
        assert!(!is_posix_shell_shebang("#!/bin/csh\n"));
        assert!(!is_posix_shell_shebang("#!/usr/bin/env tcsh\n"));
        assert!(!is_posix_shell_shebang("echo hi\n"));
    }

    #[test]
    #[cfg(unix)]
    fn append_makes_hook_executable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let hook = tmp.path().join("pre-commit");
        fs::write(&hook, "#!/bin/sh\ntrue\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o644)).unwrap();
        install_hook_in(tmp.path(), true).unwrap();
        assert_eq!(
            fs::metadata(&hook).unwrap().permissions().mode() & 0o111,
            0o111
        );
    }

    #[test]
    #[cfg(unix)]
    fn staged_reader_handles_stage_selector_lookalike_names() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git_ok(dir, &["init", "-q"]);
        fs::write(dir.join("1:notes.txt"), "k=selector-name-secret\n").unwrap();
        git_ok(dir, &["add", "-A"]);

        let secrets = [secret("K", "selector-name-secret")];
        let report = scan_staged(dir, None, Matcher::Values(&secrets)).unwrap();
        assert_eq!(report.summary.findings, 1);
    }
}
