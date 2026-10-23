//! Per-run secret filtering for `fnox exec --only` / `--except`.
//!
//! A [`SecretFilter`] narrows which secrets (and leases) a run resolves, so a
//! broken or unreachable secret the command does not need cannot fail it.
//! Patterns are exact names or globs (`*`, `?`, `[...]`), matched
//! case-sensitively against secret names and lease-produced variable names.

use crate::error::{FnoxError, Result};
use fnox_client::document::KeyRejection;
use globset::{Glob, GlobMatcher};

#[derive(Debug, Clone)]
struct Pattern {
    raw: String,
    /// `None` for an exact name.
    glob: Option<GlobMatcher>,
}

impl Pattern {
    fn parse(raw: &str) -> Result<Self> {
        let glob = if raw.contains(['*', '?', '[']) {
            let glob = Glob::new(raw).map_err(|e| {
                FnoxError::Config(format!("Invalid secret filter pattern '{raw}': {e}"))
            })?;
            Some(glob.compile_matcher())
        } else {
            None
        };
        Ok(Self {
            raw: raw.to_string(),
            glob,
        })
    }

    fn matches(&self, name: &str) -> bool {
        match &self.glob {
            Some(glob) => glob.is_match(name),
            None => self.raw == name,
        }
    }
}

/// The `--only` and `--except` patterns of one run.
#[derive(Debug, Clone, Default)]
pub struct SecretFilter {
    only: Vec<Pattern>,
    except: Vec<Pattern>,
}

impl SecretFilter {
    pub fn new(only: &[String], except: &[String]) -> Result<Self> {
        let parse = |patterns: &[String]| -> Result<Vec<Pattern>> {
            patterns.iter().map(|p| Pattern::parse(p)).collect()
        };
        Ok(Self {
            only: parse(only)?,
            except: parse(except)?,
        })
    }

    /// Whether neither `--only` nor `--except` was given.
    pub fn is_empty(&self) -> bool {
        self.only.is_empty() && self.except.is_empty()
    }

    /// Whether a name passes the filter: it matches `--only` (when given) and
    /// does not match `--except`.
    pub fn allows(&self, name: &str) -> bool {
        (self.only.is_empty() || self.only.iter().any(|p| p.matches(name)))
            && !self.except.iter().any(|p| p.matches(name))
    }

    /// Whether `--except` names `name`.
    pub fn excludes(&self, name: &str) -> bool {
        self.except.iter().any(|p| p.matches(name))
    }

    /// Whether `--only` names `name`. False when `--only` was not given.
    pub fn includes(&self, name: &str) -> bool {
        self.only.iter().any(|p| p.matches(name))
    }

    pub fn has_only(&self) -> bool {
        !self.only.is_empty()
    }

    /// Checks every pattern against the names a run can inject.
    ///
    /// `known` is every secret name and lease-produced variable; `injectable`
    /// is the subset that is in scope. An exact name that is not in `known` is
    /// unknown, as is an `--only` glob that matches nothing injectable.
    /// An exact `--only` name that exists but is not injectable (`env = false`)
    /// is reported as such. Typos in `--except` are errors too, because
    /// ignoring one would resolve the secret the user meant to skip.
    pub fn validate(
        &self,
        known: &[&str],
        injectable: &[&str],
        mode_of: impl Fn(&str) -> Option<crate::config::EnvMode>,
    ) -> std::result::Result<(), KeyRejection> {
        let mut rejection = KeyRejection::default();
        let patterns = self
            .only
            .iter()
            .map(|p| (p, true))
            .chain(self.except.iter().map(|p| (p, false)));
        for (pattern, is_only) in patterns {
            if pattern.glob.is_some() {
                if is_only && !injectable.iter().any(|name| pattern.matches(name)) {
                    rejection.unknown.push(pattern.raw.clone());
                }
                continue;
            }
            if !known.contains(&pattern.raw.as_str()) {
                let similar: Vec<String> = if pattern.raw.is_empty() {
                    Vec::new()
                } else {
                    crate::suggest::find_similar(
                        &pattern.raw,
                        known.iter().copied().filter(|k| *k != pattern.raw),
                    )
                    .into_iter()
                    .map(String::from)
                    .collect()
                };
                if !similar.is_empty() {
                    rejection.suggestions.insert(pattern.raw.clone(), similar);
                }
                rejection.unknown.push(pattern.raw.clone());
            } else if is_only
                && !injectable.contains(&pattern.raw.as_str())
                && let Some(env) = mode_of(&pattern.raw)
            {
                rejection
                    .not_injectable
                    .push(fnox_client::document::NotInjectable {
                        key: pattern.raw.clone(),
                        env: env.into(),
                    });
            }
        }
        if rejection.unknown.is_empty() && rejection.not_injectable.is_empty() {
            Ok(())
        } else {
            Err(rejection)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(only: &[&str], except: &[&str]) -> SecretFilter {
        let to_vec = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        SecretFilter::new(&to_vec(only), &to_vec(except)).unwrap()
    }

    #[test]
    fn empty_filter_allows_everything() {
        let f = filter(&[], &[]);
        assert!(f.is_empty());
        assert!(f.allows("ANYTHING"));
    }

    #[test]
    fn only_matches_names_and_globs() {
        let f = filter(&["DATABASE_URL", "AWS_*"], &[]);
        assert!(f.allows("DATABASE_URL"));
        assert!(f.allows("AWS_REGION"));
        assert!(!f.allows("STRIPE_KEY"));
        assert!(!f.allows("DATABASE_URL_2"));
    }

    #[test]
    fn except_wins_over_only() {
        let f = filter(&["AWS_*"], &["AWS_SECRET_ACCESS_KEY"]);
        assert!(f.allows("AWS_REGION"));
        assert!(!f.allows("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn except_alone_allows_the_rest() {
        let f = filter(&[], &["BROKEN_*"]);
        assert!(f.allows("OK"));
        assert!(!f.allows("BROKEN_ONE"));
    }

    #[test]
    fn matching_is_case_sensitive_and_question_mark_matches_one_char() {
        let f = filter(&["KEY_?"], &[]);
        assert!(f.allows("KEY_1"));
        assert!(!f.allows("KEY_12"));
        assert!(!f.allows("key_1"));
    }

    #[test]
    fn invalid_glob_is_an_error() {
        assert!(SecretFilter::new(&["[".to_string()], &[]).is_err());
    }

    #[test]
    fn validate_reports_unknown_names_with_suggestions() {
        let f = filter(&["DATABASE_UR", "NOPE_NOPE"], &[]);
        let known = ["DATABASE_URL", "STRIPE_KEY"];
        let rejection = f.validate(&known, &known, |_| None).unwrap_err();
        assert_eq!(rejection.unknown, ["DATABASE_UR", "NOPE_NOPE"]);
        assert_eq!(rejection.suggestions["DATABASE_UR"], ["DATABASE_URL"]);
        assert!(!rejection.suggestions.contains_key("NOPE_NOPE"));
    }

    #[test]
    fn validate_rejects_only_globs_that_match_nothing() {
        let known = ["A", "B"];
        assert!(
            filter(&["Z*"], &[])
                .validate(&known, &known, |_| None)
                .is_err()
        );
        assert!(
            filter(&[], &["Z*"])
                .validate(&known, &known, |_| None)
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_unknown_except_names() {
        let known = ["A", "B"];
        let rejection = filter(&[], &["C"])
            .validate(&known, &known, |_| None)
            .unwrap_err();
        assert_eq!(rejection.unknown, ["C"]);
    }

    #[test]
    fn validate_flags_only_names_that_are_not_injectable() {
        let known = ["A", "HIDDEN"];
        let rejection = filter(&["HIDDEN"], &[])
            .validate(&known, &["A"], |key| {
                (key == "HIDDEN").then_some(crate::config::EnvMode::Never)
            })
            .unwrap_err();
        assert_eq!(rejection.not_injectable.len(), 1);
        assert_eq!(rejection.not_injectable[0].key, "HIDDEN");
    }
}
