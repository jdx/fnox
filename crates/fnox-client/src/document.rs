//! The JSON documents of `fnox env --json`, schema 1.
//!
//! Consumers must ignore unknown fields: new optional fields may appear within
//! a schema. Any breaking change increments [`ENV_SCHEMA`].
//!
//! Every struct that fnox may grow a field on is `#[non_exhaustive]`, so build
//! one with its constructor rather than a struct literal.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Schema version of the documents below. Any breaking change increments it.
pub const ENV_SCHEMA: u32 = 1;

/// Which consumer the environment is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvScope {
    /// A command started by `fnox exec`: `env = true` and `env = "exec"` secrets, plus leases.
    Exec,
    /// An interactive shell: `env = true` secrets only, no leases.
    Shell,
}

/// Where a secret's `env` setting lets it be injected.
///
/// Serialized as `true` (`Shell`), `"exec"` (`Exec`) or `false` (`Never`), as
/// in fnox.toml.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvMode {
    /// Injected by shell integration and `fnox exec` (`true`).
    Shell,
    /// Injected only into `fnox exec` subprocesses (`"exec"`).
    Exec,
    /// Never injected as an environment variable (`false`).
    Never,
}

impl Serialize for EnvMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Shell => serializer.serialize_bool(true),
            Self::Exec => serializer.serialize_str("exec"),
            Self::Never => serializer.serialize_bool(false),
        }
    }
}

impl<'de> Deserialize<'de> for EnvMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvModeVisitor;

        impl serde::de::Visitor<'_> for EnvModeVisitor {
            type Value = EnvMode;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("true, false, or \"exec\"")
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<EnvMode, E> {
                Ok(if v { EnvMode::Shell } else { EnvMode::Never })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<EnvMode, E> {
                match v {
                    "exec" => Ok(EnvMode::Exec),
                    other => Err(E::invalid_value(
                        serde::de::Unexpected::Str(other),
                        &"true, false, or \"exec\"",
                    )),
                }
            }
        }

        deserializer.deserialize_any(EnvModeVisitor)
    }
}

/// A secret value. `Debug` never prints it and there is no `Display`, so a
/// value cannot reach a log through formatting by accident.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value, in plain text.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Success document of `fnox env --json`.
///
/// Callers apply it in this order: `remove`, then `set`, then `files` (write
/// each value to a file and set `KEY=<path>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EnvDocument {
    pub schema: u32,
    pub fnox_version: String,
    pub scope: EnvScope,
    pub profile: Vec<String>,
    /// Variables to set.
    pub set: IndexMap<String, SecretValue>,
    /// `as_file` secrets: raw contents, for the caller to write to a file.
    pub files: IndexMap<String, SecretValue>,
    /// Variables to remove from the inherited environment.
    pub remove: Vec<String>,
    /// Requested keys that resolved to nothing.
    pub missing: Vec<String>,
    /// Leases that ran.
    pub leases: Vec<String>,
}

impl EnvDocument {
    /// A schema-1 document. `fnox_version` is this crate's version, which
    /// equals fnox's because the crates are released in lockstep.
    pub fn new(
        scope: EnvScope,
        profile: Vec<String>,
        set: IndexMap<String, SecretValue>,
        files: IndexMap<String, SecretValue>,
        remove: Vec<String>,
        missing: Vec<String>,
        leases: Vec<String>,
    ) -> Self {
        Self {
            schema: ENV_SCHEMA,
            fnox_version: env!("CARGO_PKG_VERSION").to_string(),
            scope,
            profile,
            set,
            files,
            remove,
            missing,
            leases,
        }
    }
}

/// Whether a key comes from a secret or from a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Secret,
    Lease,
}

/// Where a key may be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Injectable {
    pub exec: bool,
    pub shell: bool,
}

/// One key in a [`DescribeDocument`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyInfo {
    pub key: String,
    pub kind: KeyKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_file: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub injectable: Injectable,
}

impl KeyInfo {
    pub fn new(
        key: String,
        kind: KeyKind,
        lease: Option<String>,
        env: Option<EnvMode>,
        as_file: Option<bool>,
        description: Option<String>,
        injectable: Injectable,
    ) -> Self {
        Self {
            key,
            kind,
            lease,
            env,
            as_file,
            description,
            injectable,
        }
    }
}

/// Success document of `fnox env --json --describe`: metadata only, no values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DescribeDocument {
    pub schema: u32,
    pub fnox_version: String,
    pub profile: Vec<String>,
    pub keys: Vec<KeyInfo>,
    pub dynamic_leases: Vec<String>,
}

impl DescribeDocument {
    pub fn new(profile: Vec<String>, keys: Vec<KeyInfo>, dynamic_leases: Vec<String>) -> Self {
        Self {
            schema: ENV_SCHEMA,
            fnox_version: env!("CARGO_PKG_VERSION").to_string(),
            profile,
            keys,
            dynamic_leases,
        }
    }
}

/// A requested key that is a secret, but not one this scope injects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotInjectable {
    pub key: String,
    pub env: EnvMode,
}

/// Why a set of requested keys was rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRejection {
    #[serde(default)]
    pub unknown: Vec<String>,
    #[serde(default)]
    pub suggestions: IndexMap<String, Vec<String>>,
    #[serde(default)]
    pub not_injectable: Vec<NotInjectable>,
}

/// The phase of `fnox env --json` that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Config,
    InvalidKeys,
    Resolution,
}

/// The `error` object of an [`ErrorDocument`].
///
/// New optional fields within schema 1 go here, not on [`ErrorDocument`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown: Vec<String>,
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub suggestions: IndexMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_injectable: Vec<NotInjectable>,
}

/// Failure document of `fnox env --json`, written to stdout with exit status 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorDocument {
    pub schema: u32,
    pub error: ErrorBody,
}

impl ErrorDocument {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self {
            schema: ENV_SCHEMA,
            error: ErrorBody {
                kind,
                message,
                unknown: Vec::new(),
                suggestions: IndexMap::new(),
                not_injectable: Vec::new(),
            },
        }
    }

    pub fn invalid_keys(rejection: KeyRejection, message: String) -> Self {
        let mut doc = Self::new(ErrorKind::InvalidKeys, message);
        doc.error.unknown = rejection.unknown;
        doc.error.suggestions = rejection.suggestions;
        doc.error.not_injectable = rejection.not_injectable;
        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    fn creds(entries: &[(&str, &str)]) -> IndexMap<String, SecretValue> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), SecretValue::new(v.to_string())))
            .collect()
    }

    // ---- golden documents: these pin schema 1 ----

    #[test]
    fn golden_env_document() {
        let doc = EnvDocument {
            schema: 1,
            fnox_version: "1.38.0".to_string(),
            scope: EnvScope::Exec,
            profile: keys(&["default"]),
            set: creds(&[("DATABASE_URL", "postgres://x")]),
            files: creds(&[("GCP_SA_JSON", "{}")]),
            remove: keys(&["FNOX_AGE_KEY", "SIGNING_KEY"]),
            missing: keys(&["OPTIONAL_TOKEN"]),
            leases: keys(&["aws"]),
        };
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"fnox_version":"1.38.0","scope":"exec","profile":["default"],"set":{"DATABASE_URL":"postgres://x"},"files":{"GCP_SA_JSON":"{}"},"remove":["FNOX_AGE_KEY","SIGNING_KEY"],"missing":["OPTIONAL_TOKEN"],"leases":["aws"]}"#
        );
    }

    #[test]
    fn golden_describe_document() {
        let doc = DescribeDocument {
            schema: 1,
            fnox_version: "1.38.0".to_string(),
            profile: keys(&["default"]),
            keys: vec![
                KeyInfo {
                    key: "DATABASE_URL".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Shell),
                    as_file: Some(false),
                    description: Some("Main DB".to_string()),
                    injectable: Injectable {
                        exec: true,
                        shell: true,
                    },
                },
                KeyInfo {
                    key: "STRIPE_KEY".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Exec),
                    as_file: Some(false),
                    description: None,
                    injectable: Injectable {
                        exec: true,
                        shell: false,
                    },
                },
                KeyInfo {
                    key: "SIGNING_KEY".to_string(),
                    kind: KeyKind::Secret,
                    lease: None,
                    env: Some(EnvMode::Never),
                    as_file: Some(false),
                    description: None,
                    injectable: Injectable {
                        exec: false,
                        shell: false,
                    },
                },
                KeyInfo {
                    key: "AWS_ACCESS_KEY_ID".to_string(),
                    kind: KeyKind::Lease,
                    lease: Some("aws".to_string()),
                    env: None,
                    as_file: None,
                    description: None,
                    injectable: Injectable {
                        exec: true,
                        shell: false,
                    },
                },
            ],
            dynamic_leases: keys(&["build_token"]),
        };
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"fnox_version":"1.38.0","profile":["default"],"keys":[{"key":"DATABASE_URL","kind":"secret","env":true,"as_file":false,"description":"Main DB","injectable":{"exec":true,"shell":true}},{"key":"STRIPE_KEY","kind":"secret","env":"exec","as_file":false,"injectable":{"exec":true,"shell":false}},{"key":"SIGNING_KEY","kind":"secret","env":false,"as_file":false,"injectable":{"exec":false,"shell":false}},{"key":"AWS_ACCESS_KEY_ID","kind":"lease","lease":"aws","injectable":{"exec":true,"shell":false}}],"dynamic_leases":["build_token"]}"#
        );
    }

    #[test]
    fn golden_error_document() {
        let rejection = KeyRejection {
            unknown: keys(&["DEPLOY_KYE"]),
            suggestions: IndexMap::from([("DEPLOY_KYE".to_string(), keys(&["DEPLOY_KEY"]))]),
            not_injectable: vec![NotInjectable {
                key: "SIGNING_KEY".to_string(),
                env: EnvMode::Never,
            }],
        };
        let doc = ErrorDocument::invalid_keys(rejection, "bad keys".to_string());
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            r#"{"schema":1,"error":{"kind":"invalid_keys","message":"bad keys","unknown":["DEPLOY_KYE"],"suggestions":{"DEPLOY_KYE":["DEPLOY_KEY"]},"not_injectable":[{"key":"SIGNING_KEY","env":false}]}}"#
        );
        let plain = ErrorDocument::new(ErrorKind::Config, "boom".to_string());
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"schema":1,"error":{"kind":"config","message":"boom"}}"#
        );
    }

    #[test]
    fn documents_round_trip_and_ignore_unknown_fields() {
        let doc = EnvDocument::new(
            EnvScope::Shell,
            keys(&["default"]),
            creds(&[("B", "2"), ("A", "1")]),
            IndexMap::new(),
            keys(&["X"]),
            Vec::new(),
            Vec::new(),
        );
        let json = serde_json::to_string(&doc).unwrap();
        let back: EnvDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
        assert_eq!(back.fnox_version, env!("CARGO_PKG_VERSION"));

        let with_extra = json.replacen("{\"schema\":1", "{\"future\":[1],\"schema\":1", 1);
        assert_eq!(
            serde_json::from_str::<EnvDocument>(&with_extra).unwrap(),
            doc
        );
    }

    #[test]
    fn debug_never_prints_values() {
        let doc = EnvDocument::new(
            EnvScope::Exec,
            keys(&["default"]),
            creds(&[("TOKEN", "s3cr3t")]),
            creds(&[("FILE", "s3cr3t-file")]),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let debug = format!("{doc:?}");
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(debug.contains("TOKEN"));
        assert_eq!(SecretValue::new("x".into()).expose(), "x");
        assert_eq!(SecretValue::from("y".to_string()).into_inner(), "y");
    }
}
