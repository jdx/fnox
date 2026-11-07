use super::OnePasswordProvider;
use crate::error::{FnoxError, Result};
use crate::providers::discovery::DiscoveredItem;

impl OnePasswordProvider {
    /// Discover metadata only; delegate tag matching (including nested tags) to op.
    pub async fn discover_items(&self, tags: &[String]) -> Result<Vec<DiscoveredItem>> {
        if tags.iter().any(|tag| tag.trim().is_empty()) {
            return Err(FnoxError::Config("Discovery tags must not be empty".into()));
        }
        let mut args = vec![
            "item".to_string(),
            "list".to_string(),
            "--format=json".to_string(),
            "--include-archive=false".to_string(),
        ];
        if let Some(vault) = &self.vault {
            args.push(format!("--vault={vault}"));
        }
        if !tags.is_empty() {
            args.push(format!("--tags={}", tags.join(",")));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.execute_op_command(&args).await?;
        parse_items(&output)
    }
}

pub fn parse_items(output: &str) -> Result<Vec<DiscoveredItem>> {
    // Deserialize into a whitelist rather than passing op's JSON through. New
    // upstream fields (including any values) cannot silently enter our output.
    let mut items: Vec<DiscoveredItem> =
        serde_json::from_str(output).map_err(|_| FnoxError::ProviderInvalidResponse {
            provider: "1Password".into(),
            details: "Could not parse item metadata from 'op item list'".into(),
            hint: "Expected a JSON array of item IDs, titles, tags, and vault metadata".into(),
            url: "https://fnox.jdx.dev/providers/1password".into(),
        })?;
    items.sort_by(|left, right| {
        left.title
            .cmp(&right.title)
            .then_with(|| {
                left.vault
                    .as_ref()
                    .map(|vault| &vault.id)
                    .cmp(&right.vault.as_ref().map(|vault| &vault.id))
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(items)
}

#[cfg(test)]
#[path = "../../../tests/providers/onepassword/discovery.rs"]
mod tests;
