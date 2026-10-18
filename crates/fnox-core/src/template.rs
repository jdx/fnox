//! Tera templating for config values.
//!
//! Config strings that contain a Tera delimiter (`{{`, `{%` or `{#`) are rendered with a
//! small, read-only context before use. Strings without a marker are returned
//! untouched, so existing values keep working. To write a literal marker, wrap it
//! in Tera's raw block:
//!
//! ```toml
//! [secrets]
//! TEMPLATE = { default = "{% raw %}{{ not rendered }}{% endraw %}" }
//! ```
//!
//! The context is built from the active profile selection and is never exported to
//! the process environment:
//!
//! - `fnox.profile`: the highest-priority selected profile (`default` when none)
//! - `fnox.profiles`: every selected profile, lowest priority first

use crate::error::{FnoxError, Result};
use std::borrow::Cow;
use tera::{Context, Tera};

/// Returns true if `input` contains a Tera expression, statement or comment
/// delimiter. Any of them makes the whole string a template, so a literal
/// delimiter always needs a `{% raw %}` block.
pub fn has_marker(input: &str) -> bool {
    input.contains("{{") || input.contains("{%") || input.contains("{#")
}

fn build_context(profiles: &[String]) -> Context {
    let profile = profiles.last().map(String::as_str).unwrap_or("default");
    let profiles = if profiles.is_empty() {
        vec!["default".to_string()]
    } else {
        profiles.to_vec()
    };
    let mut context = Context::new();
    context.insert(
        "fnox",
        &serde_json::json!({ "profile": profile, "profiles": profiles }),
    );
    context
}

/// Render `input` for the given profile selection.
///
/// `field` names the config value for error messages (for example
/// `"default of secret 'AWS_PROFILE'"`).
pub fn render<'a>(input: &'a str, profiles: &[String], field: &str) -> Result<Cow<'a, str>> {
    if !has_marker(input) {
        return Ok(Cow::Borrowed(input));
    }
    Tera::one_off(input, &build_context(profiles), false)
        .map(Cow::Owned)
        .map_err(|e| {
            FnoxError::Config(format!(
                "Failed to render template in {field}: {}",
                error_chain(&e)
            ))
        })
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plain_strings_are_untouched() {
        let out = render("postgres://${HOST}/db", &profiles(&["prod"]), "test").unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "postgres://${HOST}/db");
    }

    #[test]
    fn renders_active_profile() {
        let out = render("{{ fnox.profile }}", &profiles(&["aws", "staging"]), "test").unwrap();
        assert_eq!(out, "staging");
    }

    #[test]
    fn renders_profile_list() {
        let out = render(
            "{{ fnox.profiles | join(sep=\"+\") }}",
            &profiles(&["aws", "staging"]),
            "test",
        )
        .unwrap();
        assert_eq!(out, "aws+staging");
    }

    #[test]
    fn empty_selection_is_default() {
        let out = render("{{ fnox.profile }}", &[], "test").unwrap();
        assert_eq!(out, "default");
    }

    #[test]
    fn raw_block_escapes_markers() {
        let out = render(
            "{% raw %}{{ literal }}{% endraw %}",
            &profiles(&["prod"]),
            "test",
        )
        .unwrap();
        assert_eq!(out, "{{ literal }}");
    }

    #[test]
    fn comment_delimiter_makes_a_template() {
        assert!(has_marker("pa{#ss"));
        let out = render("a{# note #}b", &profiles(&["prod"]), "test").unwrap();
        assert_eq!(out, "ab");
        assert!(render("pa{#ss", &profiles(&["prod"]), "test").is_err());
    }

    #[test]
    fn raw_block_keeps_a_literal_comment_delimiter() {
        let out = render(
            "{{ fnox.profile }}-{% raw %}pa{#ss{% endraw %}",
            &profiles(&["prod"]),
            "test",
        )
        .unwrap();
        assert_eq!(out, "prod-pa{#ss");
    }

    #[test]
    fn coexists_with_secret_interpolation() {
        let out = render(
            "{{ fnox.profile }}-${DB_HOST}",
            &profiles(&["prod"]),
            "test",
        )
        .unwrap();
        assert_eq!(out, "prod-${DB_HOST}");
    }

    #[test]
    fn undefined_variable_is_an_error_naming_the_field() {
        let err = render("{{ nope }}", &profiles(&["prod"]), "default of secret 'X'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("default of secret 'X'"), "{err}");
    }

    #[test]
    fn output_is_not_html_escaped() {
        let out = render("{{ fnox.profile }}", &profiles(&["a&b"]), "test").unwrap();
        assert_eq!(out, "a&b");
    }
}
