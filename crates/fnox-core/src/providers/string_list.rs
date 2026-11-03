//! A config field that takes either a plain list of strings or a table of named strings.

use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// A list of strings, written either as an array or as a table whose keys only name the values.
///
/// In TOML, this deserializes from either:
/// - `field = ["value1", "value2"]`
/// - `[provider.field]` with `name = "value"` entries
///
/// The names only document the values; the values are used in the order they were written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum StringListOrMap {
    /// A plain list of values
    List(Vec<String>),
    /// Values keyed by a descriptive name
    Map(IndexMap<String, String>),
}

impl Default for StringListOrMap {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

impl StringListOrMap {
    /// The values in the order they were written, without their names.
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::List(values) => values.clone(),
            Self::Map(values) => values.values().cloned().collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::List(values) => values.is_empty(),
            Self::Map(values) => values.is_empty(),
        }
    }
}

impl From<Vec<String>> for StringListOrMap {
    fn from(values: Vec<String>) -> Self {
        Self::List(values)
    }
}

// Hand-written so a wrong shape reports what is accepted instead of serde's generic
// "did not match any variant of untagged enum".
impl<'de> Deserialize<'de> for StringListOrMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StringListOrMap;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an array of strings or a table of named strings")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> Result<Self::Value, A::Error> {
                Vec::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(StringListOrMap::List)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                IndexMap::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(StringListOrMap::Map)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Serialize)]
    struct Wrapper {
        recipients: StringListOrMap,
    }

    #[test]
    fn deserializes_array() {
        let w: Wrapper = toml_edit::de::from_str(r#"recipients = ["a", "b"]"#).unwrap();
        assert_eq!(w.recipients.to_vec(), vec!["a", "b"]);
    }

    #[test]
    fn deserializes_table_in_written_order() {
        let w: Wrapper =
            toml_edit::de::from_str("[recipients]\nlaptop = \"b\"\ndesktop = \"a\"\n").unwrap();
        assert_eq!(w.recipients.to_vec(), vec!["b", "a"]);
        assert!(matches!(w.recipients, StringListOrMap::Map(_)));
    }

    #[test]
    fn round_trips_table() {
        let w: Wrapper = toml_edit::de::from_str("[recipients]\nlaptop = \"b\"\n").unwrap();
        let out = toml_edit::ser::to_string(&w).unwrap();
        let back: Wrapper = toml_edit::de::from_str(&out).unwrap();
        assert_eq!(back.recipients, w.recipients, "{out}");
    }

    #[test]
    fn rejects_other_shapes_with_clear_error() {
        let err = toml_edit::de::from_str::<Wrapper>(r#"recipients = "a""#)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("an array of strings or a table of named strings"),
            "{err}"
        );
    }
}
