//! Parsing for the plaintext secret file formats written by `fnox export`.
//!
//! Shared by `fnox import` and the `plain` provider's `file` option.

use crate::error::{FnoxError, Result};
use miette::{NamedSource, SourceSpan};
use std::collections::HashMap;
use std::sync::Arc;
use strum::{Display, EnumString, VariantNames};

/// Plaintext secret file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString, VariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum SecretFileFormat {
    /// Environment variable format (KEY=value)
    Env,
    /// POSIX shell format (export KEY=value)
    Shell,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
}

impl SecretFileFormat {
    /// Parse `input` into a map of secret names to values.
    ///
    /// Structured formats accept either a flat mapping of names to values or the
    /// `{ secrets = {...}, metadata = {...} }` document written by `fnox export`.
    /// `source_name` labels parse errors.
    pub fn parse(self, input: &str, source_name: &str) -> Result<HashMap<String, String>> {
        match self {
            Self::Env => parse_env(input),
            Self::Shell => parse_shell(input),
            Self::Json => parse_json(input, source_name),
            Self::Yaml => parse_yaml(input, source_name),
            Self::Toml => parse_toml(input, source_name),
        }
    }
}

fn parse_env(input: &str) -> Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();
    let mut lines = input.lines();

    while let Some(line) = lines.next() {
        let mut line = line.trim_start().to_string();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Docker Compose permits literal newlines inside single-quoted
        // dotenv values. Reassemble them before parsing the assignment.
        while has_unclosed_single_quoted_value(&line) {
            let Some(next_line) = lines.next() else {
                return Err(FnoxError::Config(
                    "Unterminated single-quoted ENV value".to_string(),
                ));
            };
            line.push('\n');
            line.push_str(next_line);
        }

        // Parse export statements and simple KEY=VALUE
        if let Some(export_key_value) = line.strip_prefix("export ") {
            parse_key_value(export_key_value, &mut secrets);
        } else {
            parse_key_value(&line, &mut secrets);
        }
    }

    Ok(secrets)
}

fn parse_key_value(line: &str, secrets: &mut HashMap<String, String>) {
    if let Some((key, value)) = line.split_once('=') {
        let key = key.trim();
        if !key.is_empty() {
            secrets.insert(key.to_string(), parse_env_value(value.trim()));
        }
    }
}

/// Decode a dotenv value, dropping any inline comment.
///
/// Follows Docker Compose: a comment may follow a quoted value, while in an
/// unquoted value `#` only starts a comment when preceded by whitespace.
fn parse_env_value(value: &str) -> String {
    for (quote, unescape) in [
        ('"', unescape_double_quoted_env_value as fn(&str) -> String),
        ('\'', unescape_single_quoted_env_value),
    ] {
        if let Some(rest) = value.strip_prefix(quote) {
            return match closing_quote(rest, quote) {
                Some(end) if is_comment_or_empty(&rest[end + 1..]) => unescape(&rest[..end]),
                // Not a well-formed quoted value; keep it as written
                _ => value.to_string(),
            };
        }
    }

    match value
        .char_indices()
        .find(|&(i, c)| c == '#' && value[..i].ends_with(char::is_whitespace))
    {
        Some((i, _)) => value[..i].trim_end().to_string(),
        None => value.to_string(),
    }
}

/// Byte offset of the first `quote` not escaped by a backslash.
fn closing_quote(value: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if c == quote && !escaped {
            return Some(i);
        }
        escaped = c == '\\' && !escaped;
    }
    None
}

fn is_comment_or_empty(rest: &str) -> bool {
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

/// Parse `export KEY=value` statements using POSIX shell quoting rules.
///
/// Only assignments are supported; values are taken literally, without
/// parameter expansion or command substitution.
fn parse_shell(input: &str) -> Result<HashMap<String, String>> {
    let words = shlex::split(input).ok_or_else(|| {
        FnoxError::Config("Failed to parse shell input: unterminated quote or escape".to_string())
    })?;

    let mut secrets = HashMap::new();
    for word in words {
        if word == "export" {
            continue;
        }
        match word.split_once('=') {
            Some((key, value)) if !key.is_empty() => {
                secrets.insert(key.to_string(), value.to_string());
            }
            _ => {
                return Err(FnoxError::Config(format!(
                    "Failed to parse shell input: expected `export KEY=value`, found '{word}'"
                )));
            }
        }
    }

    Ok(secrets)
}

fn parse_json(input: &str, source_name: &str) -> Result<HashMap<String, String>> {
    let data: serde_json::Value = serde_json::from_str(input).map_err(|e| {
        let offset = json_error_offset(input, e.line(), e.column());
        FnoxError::ImportParseErrorWithSource {
            format: "JSON".to_string(),
            details: e.to_string(),
            src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
            span: SourceSpan::new(offset.into(), 1usize),
        }
    })?;
    extract_string_values(&data)
}

fn parse_yaml(input: &str, source_name: &str) -> Result<HashMap<String, String>> {
    let data: serde_yaml::Value = serde_yaml::from_str(input).map_err(|e| {
        if let Some(loc) = e.location() {
            // serde_yaml reports the byte index of the error
            let offset = loc.index().min(input.len());
            FnoxError::ImportParseErrorWithSource {
                format: "YAML".to_string(),
                details: e.to_string(),
                src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
                span: SourceSpan::new(offset.into(), 1usize),
            }
        } else {
            FnoxError::Config(format!("Failed to parse YAML: {}", e))
        }
    })?;
    extract_string_values(&data)
}

fn parse_toml(input: &str, source_name: &str) -> Result<HashMap<String, String>> {
    let data: serde_json::Value = toml_edit::de::from_str(input).map_err(|e| {
        // toml_edit provides span via e.span()
        if let Some(span) = e.span() {
            FnoxError::ImportParseErrorWithSource {
                format: "TOML".to_string(),
                details: e.to_string(),
                src: Arc::new(NamedSource::new(source_name, Arc::new(input.to_string()))),
                span: SourceSpan::new(span.start.into(), span.end - span.start),
            }
        } else {
            FnoxError::Config(format!("Failed to parse TOML: {}", e))
        }
    })?;
    extract_string_values(&data)
}

/// Convert a serde_json error position to a byte offset for miette source spans.
///
/// serde_json reports a 1-indexed line and a column counted in bytes, so the
/// offset is snapped back to a UTF-8 character boundary. Errors without a
/// position (type mismatches, custom errors) report line 0, column 0 and map
/// to offset 0.
fn json_error_offset(input: &str, line: usize, column: usize) -> usize {
    if line == 0 || column == 0 {
        return 0;
    }

    let line_start = match line {
        1 => 0,
        _ => match input.match_indices('\n').nth(line - 2) {
            Some((newline, _)) => newline + 1,
            // Requested line is beyond the input
            None => return input.len(),
        },
    };

    let mut offset = (line_start + column - 1).min(input.len());
    while !input.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn extract_string_values<V>(data: &V) -> Result<HashMap<String, String>>
where
    V: serde::Serialize,
{
    let json_value = serde_json::to_value(data)?;

    let mut secrets = HashMap::new();

    if let serde_json::Value::Object(mut map) = json_value {
        // Unwrap the document written by `fnox export`
        if matches!(map.get("secrets"), Some(serde_json::Value::Object(_)))
            && map.keys().all(|k| k == "secrets" || k == "metadata")
            && let Some(serde_json::Value::Object(inner)) = map.remove("secrets")
        {
            map = inner;
        }

        for (key, value) in map {
            match value {
                serde_json::Value::String(s) => {
                    secrets.insert(key, s);
                }
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => {
                    secrets.insert(key, value.to_string());
                }
                _ => {
                    tracing::warn!("Skipping non-string value for key '{}'", key);
                }
            }
        }
    }

    Ok(secrets)
}

fn has_unclosed_single_quoted_value(line: &str) -> bool {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((_, value)) = line.split_once('=') else {
        return false;
    };
    let Some(value) = value.trim_start().strip_prefix('\'') else {
        return false;
    };

    let mut escaped = false;
    for c in value.chars() {
        if c == '\'' && !escaped {
            return false;
        }
        escaped = c == '\\' && !escaped;
    }
    true
}

fn unescape_double_quoted_env_value(value: &str) -> String {
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(c) = chars.next() {
        if c != '\\' {
            unescaped.push(c);
            continue;
        }

        match chars.next() {
            Some('\\') => unescaped.push('\\'),
            Some('"') => unescaped.push('"'),
            Some('$') => unescaped.push('$'),
            Some('n') => unescaped.push('\n'),
            Some('r') => unescaped.push('\r'),
            Some('t') => unescaped.push('\t'),
            Some(other) => {
                unescaped.push('\\');
                unescaped.push(other);
            }
            None => unescaped.push('\\'),
        }
    }

    unescaped
}

fn unescape_single_quoted_env_value(value: &str) -> String {
    value.replace("\\'", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_multiline_single_quoted_values() {
        assert!(has_unclosed_single_quoted_value("VALUE='first"));
        assert!(has_unclosed_single_quoted_value("VALUE='it\\'s first"));
        assert!(!has_unclosed_single_quoted_value("VALUE='first'"));
        assert!(!has_unclosed_single_quoted_value("VALUE=first"));
    }

    #[test]
    fn parse_env_preserves_multiline_spaces_and_double_quoted_fallbacks() {
        let secrets =
            parse_env("SPACES='first  \nsecond'\nFALLBACK=\"prefix\\\\'\\$value\\ncontinuation\"")
                .unwrap();

        assert_eq!(secrets["SPACES"], "first  \nsecond");
        assert_eq!(secrets["FALLBACK"], "prefix\\'$value\ncontinuation");
    }

    #[test]
    fn parse_env_drops_inline_comments() {
        let secrets = parse_env(concat!(
            "SINGLE='abc$123' # service token\n",
            "DOUBLE=\"x y\" # comment\n",
            "ESCAPED='it\\'s' # comment\n",
            "MULTI='a\nb' # comment\n",
            "UNQUOTED=plain # comment\n",
            "NOT_A_COMMENT=val#ue\n",
            "HASH_IN_QUOTES=\"a # b\"\n",
            "TRAILING_TEXT=\"a\" b\n",
        ))
        .unwrap();

        assert_eq!(secrets["SINGLE"], "abc$123");
        assert_eq!(secrets["DOUBLE"], "x y");
        assert_eq!(secrets["ESCAPED"], "it's");
        assert_eq!(secrets["MULTI"], "a\nb");
        assert_eq!(secrets["UNQUOTED"], "plain");
        assert_eq!(secrets["NOT_A_COMMENT"], "val#ue");
        assert_eq!(secrets["HASH_IN_QUOTES"], "a # b");
        assert_eq!(secrets["TRAILING_TEXT"], "\"a\" b");
    }

    #[test]
    fn parse_env_rejects_unterminated_single_quoted_values() {
        let error = parse_env("KEY='secret").unwrap_err();

        assert_eq!(
            error.to_string(),
            "Configuration error: Unterminated single-quoted ENV value"
        );
    }

    #[test]
    fn unescape_double_quoted_env_value_handles_export_escapes() {
        assert_eq!(
            unescape_double_quoted_env_value(r#"line1\nline2\t\"quoted\"\\path"#),
            "line1\nline2\t\"quoted\"\\path"
        );
        assert_eq!(
            unescape_double_quoted_env_value(r"secret\$value\\"),
            "secret$value\\"
        );
        assert_eq!(
            unescape_double_quoted_env_value("secret$$value"),
            "secret$$value"
        );
    }

    #[test]
    fn unescape_double_quoted_env_value_preserves_unknown_escapes() {
        assert_eq!(
            unescape_double_quoted_env_value(r#"secret\$value\`tick"#),
            r#"secret$value\`tick"#
        );
    }

    #[test]
    fn unescape_single_quoted_env_value_handles_apostrophes() {
        assert_eq!(unescape_single_quoted_env_value(r"it\'s $5"), "it's $5");
    }

    #[test]
    fn parse_shell_handles_posix_quoting_and_comments() {
        let input = "# Exported from profile: default\n\nexport PLAIN=kek\nexport QUOTED='it'\\''s $HOME'\nexport MULTI='a\nb'\nBARE=\"x y\"\n";
        let secrets = SecretFileFormat::Shell.parse(input, "test.sh").unwrap();

        assert_eq!(secrets.len(), 4);
        assert_eq!(secrets["PLAIN"], "kek");
        assert_eq!(secrets["QUOTED"], "it's $HOME");
        assert_eq!(secrets["MULTI"], "a\nb");
        assert_eq!(secrets["BARE"], "x y");
    }

    #[test]
    fn parse_shell_rejects_non_assignments() {
        assert!(parse_shell("export A=1\nunset B\n").is_err());
        assert!(parse_shell("export A='unterminated\n").is_err());
    }

    #[test]
    fn structured_formats_accept_flat_and_export_documents() {
        let flat = SecretFileFormat::Json
            .parse(r#"{"A": "1", "B": 2}"#, "flat.json")
            .unwrap();
        assert_eq!(flat["A"], "1");
        assert_eq!(flat["B"], "2");

        let exported = SecretFileFormat::Json
            .parse(
                r#"{"secrets": {"A": "1"}, "metadata": {"profile": "default"}}"#,
                "export.json",
            )
            .unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported["A"], "1");

        let exported = SecretFileFormat::Yaml
            .parse("secrets:\n  A: '1'\nmetadata: null\n", "export.yaml")
            .unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported["A"], "1");

        let exported = SecretFileFormat::Toml
            .parse(
                "[secrets]\nA = \"1\"\n\n[metadata]\nprofile = \"default\"\n",
                "export.toml",
            )
            .unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported["A"], "1");
    }

    fn error_offset(format: SecretFileFormat, input: &str) -> usize {
        match format.parse(input, "test") {
            Err(FnoxError::ImportParseErrorWithSource { span, .. }) => span.offset(),
            other => panic!("expected a parse error with a source span, got {other:?}"),
        }
    }

    #[test]
    fn json_error_span_counts_columns_in_bytes() {
        let input = "{\n  \"A\": \"é\" x\n}";
        assert_eq!(
            error_offset(SecretFileFormat::Json, input),
            input.find('x').unwrap()
        );
    }

    #[test]
    fn yaml_error_span_points_at_the_error() {
        let input = "A: 1\nB: \"é\" x\n";
        assert_eq!(
            error_offset(SecretFileFormat::Yaml, input),
            input.find('x').unwrap()
        );
    }

    #[test]
    fn structured_formats_keep_secrets_key_alongside_other_keys() {
        let secrets = SecretFileFormat::Json
            .parse(r#"{"secrets": {"A": "1"}, "B": "2"}"#, "flat.json")
            .unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets["B"], "2");
    }
}
