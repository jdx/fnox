//! Span-tracking wrapper for config values.
//!
//! This module provides `SpannedValue<T>`, a wrapper that captures the byte span
//! of a value during TOML deserialization, enabling precise error reporting with miette.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Range;

/// A value that optionally tracks its source location (byte span) in a config file.
///
/// When deserializing from TOML, this uses `serde_spanned` to capture the byte range
/// where the value appeared. When serializing, only the value is written.
///
/// # Example
/// ```ignore
/// #[derive(Deserialize)]
/// struct Config {
///     provider: Option<SpannedValue<String>>,
/// }
///
/// // After deserializing, you can get both value and span:
/// if let Some(ref provider) = config.provider {
///     println!("Provider: {}", provider.value());
///     if let Some(span) = provider.span() {
///         println!("Located at bytes {}..{}", span.start, span.end);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SpannedValue<T> {
    value: T,
    span: Option<Range<usize>>,
}

impl<T> SpannedValue<T> {
    /// Create a new spanned value with a known span.
    #[cfg(test)]
    pub fn new(value: T, span: Range<usize>) -> Self {
        Self {
            value,
            span: Some(span),
        }
    }

    /// Create a spanned value without span information.
    /// Useful when programmatically creating values (not from deserialization).
    pub fn without_span(value: T) -> Self {
        Self { value, span: None }
    }

    /// Get a reference to the inner value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Get the byte span where this value was found in the source.
    /// Returns `None` if the value was created programmatically.
    pub fn span(&self) -> Option<Range<usize>> {
        self.span.clone()
    }
}

// Implement AsRef for convenient access
impl<T> AsRef<T> for SpannedValue<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

// Allow creating from just a value (no span)
impl<T> From<T> for SpannedValue<T> {
    fn from(value: T) -> Self {
        Self::without_span(value)
    }
}

// Serialize just the inner value (no span info in output)
impl<T: Serialize> Serialize for SpannedValue<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

// Deserialize using serde_spanned to capture the span
impl<'de, T: Deserialize<'de>> Deserialize<'de> for SpannedValue<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Use serde_spanned::Spanned to capture the span during deserialization
        let spanned = serde_spanned::Spanned::<T>::deserialize(deserializer)?;
        let span = spanned.span();
        let value = spanned.into_inner();
        Ok(Self {
            value,
            span: Some(span),
        })
    }
}

// PartialEq compares only values, not spans
impl<T: PartialEq> PartialEq for SpannedValue<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for SpannedValue<T> {}

// Display delegates to inner value
impl<T: std::fmt::Display> std::fmt::Display for SpannedValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

// Implement JsonSchema by delegating to inner type
impl<T: schemars::JsonSchema> schemars::JsonSchema for SpannedValue<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        T::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spanned_value_creation() {
        let sv = SpannedValue::new("hello".to_string(), 0..5);
        assert_eq!(sv.value(), "hello");
        assert_eq!(sv.span(), Some(0..5));
    }

    #[test]
    fn test_spanned_value_without_span() {
        let sv = SpannedValue::without_span("hello".to_string());
        assert_eq!(sv.value(), "hello");
        assert_eq!(sv.span(), None);
    }

    #[test]
    fn test_spanned_value_from() {
        let sv: SpannedValue<String> = "hello".to_string().into();
        assert_eq!(sv.value(), "hello");
        assert_eq!(sv.span(), None);
    }

    #[test]
    fn test_spanned_value_serialize() {
        let sv = SpannedValue::new("test".to_string(), 10..14);
        let json = serde_json::to_string(&sv).unwrap();
        assert_eq!(json, r#""test""#);
    }

    #[test]
    fn test_spanned_value_deserialize_toml() {
        #[derive(Deserialize)]
        struct TestConfig {
            name: SpannedValue<String>,
        }

        let toml = r#"name = "hello""#;
        let config: TestConfig = toml_edit::de::from_str(toml).unwrap();
        assert_eq!(config.name.value(), "hello");
        // toml_edit should capture the span
        assert!(config.name.span().is_some());
    }

    #[test]
    fn test_spanned_value_equality() {
        let sv1 = SpannedValue::new("hello".to_string(), 0..5);
        let sv2 = SpannedValue::new("hello".to_string(), 10..15);
        let sv3 = SpannedValue::new("world".to_string(), 0..5);

        // Same value, different spans - should be equal
        assert_eq!(sv1, sv2);
        // Different values - should not be equal
        assert_ne!(sv1, sv3);
    }
}
