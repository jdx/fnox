use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use serde_json::Value;

#[derive(clap::Args)]
#[command(hide = true)]
pub struct SchemaCommand {}

impl SchemaCommand {
    pub async fn run(&self, _cli: &Cli) -> Result<()> {
        let schema = schemars::schema_for!(Config);
        let value = serde_json::to_value(&schema)?;
        let sorted = sort_json_keys(value);
        let json = serde_json::to_string_pretty(&sorted)?;
        println!("{json}");
        Ok(())
    }
}

/// Recursively sort all object keys in a JSON value
fn sort_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json_keys).collect()),
        other => other,
    }
}
