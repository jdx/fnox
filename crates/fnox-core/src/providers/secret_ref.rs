//! Types for provider configuration fields that can reference secrets.
//!
//! This module provides types that allow provider configuration properties to be either
//! literal values or references to secrets defined elsewhere in the configuration.
//!
//! # Example
//!
//! ```toml
//! [providers]
//! age = { type = "age", recipients = ["age1..."] }
//! vault = { type = "vault", address = "https://vault.example.com", token = { secret = "VAULT_TOKEN" } }
//!
//! [secrets]
//! VAULT_TOKEN = { provider = "age", value = "encrypted-token..." }
//! ```

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;

/// A value that can be either a literal string or a reference to a secret.
///
/// In TOML, this deserializes from either:
/// - `field = "literal-value"`
/// - `field = { secret = "SECRET_NAME" }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringOrSecretRef {
    /// A literal string value
    Literal(String),
    /// A reference to a secret by name
    SecretRef { secret: String },
}

impl JsonSchema for StringOrSecretRef {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("StringOrSecretRef")
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        // Get the string schema
        let string_schema = generator.subschema_for::<String>();

        // Create the oneOf schema: string or { secret: string }
        json_schema!({
            "description": "Either a literal string or a reference to a secret",
            "oneOf": [
                string_schema,
                {
                    "type": "object",
                    "properties": {
                        "secret": { "type": "string" }
                    },
                    "required": ["secret"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

impl StringOrSecretRef {
    /// Returns true if this is a secret reference
    #[cfg(test)]
    pub fn is_secret_ref(&self) -> bool {
        matches!(self, Self::SecretRef { .. })
    }

    /// Returns the secret name if this is a secret reference
    #[cfg(test)]
    pub fn secret_name(&self) -> Option<&str> {
        match self {
            Self::SecretRef { secret } => Some(secret),
            Self::Literal(_) => None,
        }
    }

    /// Returns the literal value if this is a literal
    pub fn as_literal(&self) -> Option<&str> {
        match self {
            Self::Literal(s) => Some(s),
            Self::SecretRef { .. } => None,
        }
    }
}

impl<'de> Deserialize<'de> for StringOrSecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Literal(String),
            SecretRef { secret: String },
        }

        match Helper::deserialize(deserializer)? {
            Helper::Literal(s) => Ok(StringOrSecretRef::Literal(s)),
            Helper::SecretRef { secret } => Ok(StringOrSecretRef::SecretRef { secret }),
        }
    }
}

impl Serialize for StringOrSecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Literal(s) => s.serialize(serializer),
            Self::SecretRef { secret } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("secret", secret)?;
                map.end()
            }
        }
    }
}

impl From<String> for StringOrSecretRef {
    fn from(s: String) -> Self {
        Self::Literal(s)
    }
}

impl From<&str> for StringOrSecretRef {
    fn from(s: &str) -> Self {
        Self::Literal(s.to_string())
    }
}

/// An optional value that can be a literal string, a secret reference, or absent.
///
/// In TOML, this deserializes from:
/// - Field absent: `None`
/// - `field = "literal-value"`: `Some(Literal("literal-value"))`
/// - `field = { secret = "SECRET_NAME" }`: `Some(SecretRef { secret: "SECRET_NAME" })`
#[derive(Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(transparent)]
pub struct OptionStringOrSecretRef(pub Option<StringOrSecretRef>);

impl OptionStringOrSecretRef {
    /// Creates a new empty optional value
    pub fn none() -> Self {
        Self(None)
    }

    /// Creates a new optional value with a literal string
    pub fn literal(s: impl Into<String>) -> Self {
        Self(Some(StringOrSecretRef::Literal(s.into())))
    }

    /// Returns true if this is None
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    /// Returns true if this is Some
    #[cfg(test)]
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    /// Returns the inner Option
    pub fn as_ref(&self) -> Option<&StringOrSecretRef> {
        self.0.as_ref()
    }

    /// Returns true if this contains a secret reference
    #[cfg(test)]
    pub fn has_secret_ref(&self) -> bool {
        matches!(self.0, Some(StringOrSecretRef::SecretRef { .. }))
    }

    /// Returns the secret name if this is a secret reference
    #[cfg(test)]
    pub fn secret_name(&self) -> Option<&str> {
        match &self.0 {
            Some(StringOrSecretRef::SecretRef { secret }) => Some(secret),
            _ => None,
        }
    }

    /// Returns the literal value if this is a literal
    #[cfg(test)]
    pub fn as_literal(&self) -> Option<&str> {
        self.0.as_ref().and_then(|v| v.as_literal())
    }
}

impl<'de> Deserialize<'de> for OptionStringOrSecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<StringOrSecretRef> = Option::deserialize(deserializer)?;
        Ok(OptionStringOrSecretRef(opt))
    }
}

impl Serialize for OptionStringOrSecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            Some(v) => v.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

impl From<Option<String>> for OptionStringOrSecretRef {
    fn from(opt: Option<String>) -> Self {
        Self(opt.map(StringOrSecretRef::Literal))
    }
}

impl From<String> for OptionStringOrSecretRef {
    fn from(s: String) -> Self {
        Self(Some(StringOrSecretRef::Literal(s)))
    }
}

impl From<&str> for OptionStringOrSecretRef {
    fn from(s: &str) -> Self {
        Self(Some(StringOrSecretRef::Literal(s.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_or_secret_ref_literal_deser() {
        let toml_str = r#"field = "literal-value""#;
        #[derive(Deserialize)]
        struct Test {
            field: StringOrSecretRef,
        }
        let parsed: Test = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(
            parsed.field,
            StringOrSecretRef::Literal("literal-value".to_string())
        );
    }

    #[test]
    fn test_string_or_secret_ref_secret_ref_deser() {
        let toml_str = r#"field = { secret = "MY_SECRET" }"#;
        #[derive(Deserialize)]
        struct Test {
            field: StringOrSecretRef,
        }
        let parsed: Test = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(
            parsed.field,
            StringOrSecretRef::SecretRef {
                secret: "MY_SECRET".to_string()
            }
        );
    }

    #[test]
    fn test_string_or_secret_ref_literal_ser() {
        #[derive(Serialize)]
        struct Test {
            field: StringOrSecretRef,
        }
        let value = Test {
            field: StringOrSecretRef::Literal("test".to_string()),
        };
        let serialized = toml_edit::ser::to_string(&value).unwrap();
        assert_eq!(serialized.trim(), r#"field = "test""#);
    }

    #[test]
    fn test_string_or_secret_ref_secret_ref_ser() {
        #[derive(Serialize)]
        struct Test {
            field: StringOrSecretRef,
        }
        let value = Test {
            field: StringOrSecretRef::SecretRef {
                secret: "MY_SECRET".to_string(),
            },
        };
        let serialized = toml_edit::ser::to_string(&value).unwrap();
        assert!(serialized.contains("secret"));
        assert!(serialized.contains("MY_SECRET"));
    }

    #[test]
    fn test_option_string_or_secret_ref_none() {
        let toml_str = r#""#;
        #[derive(Deserialize)]
        struct Test {
            #[serde(default)]
            field: OptionStringOrSecretRef,
        }
        let parsed: Test = toml_edit::de::from_str(toml_str).unwrap();
        assert!(parsed.field.is_none());
    }

    #[test]
    fn test_option_string_or_secret_ref_literal() {
        let toml_str = r#"field = "value""#;
        #[derive(Deserialize)]
        struct Test {
            #[serde(default)]
            field: OptionStringOrSecretRef,
        }
        let parsed: Test = toml_edit::de::from_str(toml_str).unwrap();
        assert!(parsed.field.is_some());
        assert_eq!(parsed.field.as_literal(), Some("value"));
    }

    #[test]
    fn test_option_string_or_secret_ref_secret() {
        let toml_str = r#"field = { secret = "SECRET_NAME" }"#;
        #[derive(Deserialize)]
        struct Test {
            #[serde(default)]
            field: OptionStringOrSecretRef,
        }
        let parsed: Test = toml_edit::de::from_str(toml_str).unwrap();
        assert!(parsed.field.is_some());
        assert!(parsed.field.has_secret_ref());
        assert_eq!(parsed.field.secret_name(), Some("SECRET_NAME"));
    }

    #[test]
    fn test_helpers() {
        let literal = StringOrSecretRef::Literal("test".to_string());
        assert!(!literal.is_secret_ref());
        assert_eq!(literal.as_literal(), Some("test"));
        assert_eq!(literal.secret_name(), None);

        let secret = StringOrSecretRef::SecretRef {
            secret: "SECRET".to_string(),
        };
        assert!(secret.is_secret_ref());
        assert_eq!(secret.as_literal(), None);
        assert_eq!(secret.secret_name(), Some("SECRET"));
    }
}
