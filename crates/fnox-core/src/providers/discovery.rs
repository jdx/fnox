use serde::{Deserialize, Serialize};

/// Metadata returned by provider discovery. Never includes secret fields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiscoveredItem {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<DiscoveredVault>,
}

/// Optional vault metadata for providers that organize items into vaults.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiscoveredVault {
    pub id: String,
    pub name: String,
}
