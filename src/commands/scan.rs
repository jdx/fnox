use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use clap::{Args, ValueEnum, ValueHint};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::{DirEntry, WalkBuilder};
use regex::Regex;
use serde::Serialize;

use crate::commands::Cli;
use crate::config::Config;
use crate::error::{FnoxError, Result};

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Scan repository for potential secrets in plaintext
#[derive(Args)]
pub struct ScanCommand {
    /// Directory to scan (default: current directory)
    #[arg(default_value = ".", value_hint = ValueHint::DirPath)]
    dir: PathBuf,

    /// Skip files matching this glob pattern (can be used multiple times)
    #[arg(short, long)]
    ignore: Vec<String>,

    /// Output format
    #[arg(long, value_enum, default_value_t = ScanFormat::Human)]
    format: ScanFormat,

    /// Show only files with potential secrets
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanFormat {
    Human,
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
    pub async fn run(&self, _cli: &Cli, _config: Config) -> Result<()> {
        let ignore_globs = build_ignore_globs(&self.ignore)?;
        let report = scan_directory(&self.dir, ignore_globs.as_ref())?;

        match (self.quiet, self.format) {
            (true, ScanFormat::Human) => print_quiet_report(&report),
            (true, ScanFormat::Json) => print_quiet_json_report(&report)?,
            (false, ScanFormat::Human) => print_human_report(&self.dir, &report),
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

fn scan_directory(dir: &Path, ignore_globs: Option<&GlobSet>) -> Result<ScanReport> {
    let mut findings = Vec::new();
    let mut files_scanned = 0;
    let root = fs::canonicalize(dir)?;
    let cwd = std::env::current_dir()?;

    let mut walker = WalkBuilder::new(&root);
    walker.hidden(false);
    walker.git_ignore(true);
    walker.git_exclude(true);
    walker.git_global(true);
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
        if ignore_globs.is_some_and(|globs| {
            globs.is_match(rel_to_root)
                || path
                    .file_name()
                    .is_some_and(|name| globs.is_match(Path::new(name)))
        }) {
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
        findings.extend(scan_content(&display_path, &content));
    }

    let files_with_findings = findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let finding_count = findings.len();

    Ok(ScanReport {
        findings,
        summary: ScanSummary {
            files_scanned,
            files_with_findings,
            findings: finding_count,
        },
    })
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

fn print_human_report(dir: &Path, report: &ScanReport) {
    if report.findings.is_empty() {
        println!(
            "No potential secrets found in {} file(s) under {}",
            report.summary.files_scanned,
            dir.display()
        );
        return;
    }

    println!(
        "Found {} potential secret(s) in {} file(s):",
        report.summary.findings, report.summary.files_with_findings
    );
    for finding in &report.findings {
        println!(
            "{}:{}:{} [{} {}] {}",
            finding.path,
            finding.line,
            finding.column,
            finding.detector,
            finding.severity,
            finding.redacted
        );
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
}
