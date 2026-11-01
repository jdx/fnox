//! Azure Container Apps environment variables, set through the ARM REST API.
//!
//! fnox reads the container app, sets or replaces the pushed variables in one
//! container's `env`, and writes the containers back with a single PATCH, so a
//! push creates at most one new revision however many variables it carries.
//! Variables fnox does not push are left alone. Authentication is the same
//! credential chain as the `azure-sm` and `azure-ac` providers.

use super::PushTarget;
use crate::error::{FnoxError, Result};
use crate::providers::azure_shared::AzureAuth;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TARGET_TYPE: &str = "azure-container-apps";
const ARM: &str = "https://management.azure.com";
const SCOPE: &str = "https://management.azure.com/.default";
const API_VERSION: &str = "2024-03-01";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AzureContainerApps {
    /// Subscription ID that holds the container app
    pub subscription: String,
    /// Resource group that holds the container app
    pub resource_group: String,
    /// Container app name
    pub app: String,
    /// Container to set the variables in (default: the app's only container)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Authentication: `"default"` or `"managed-identity"`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Client ID of a user-assigned managed identity (with `auth = "managed-identity"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_identity_client_id: Option<String>,
}

impl AzureContainerApps {
    fn app_url(&self) -> String {
        format!(
            "{ARM}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.App/containerApps/{}?api-version={API_VERSION}",
            urlencoding::encode(&self.subscription),
            urlencoding::encode(&self.resource_group),
            urlencoding::encode(&self.app),
        )
    }

    fn auth(&self) -> Result<AzureAuth> {
        AzureAuth::from_config(
            self.auth.as_deref(),
            self.managed_identity_client_id.clone(),
        )
    }

    fn error(details: String) -> FnoxError {
        FnoxError::ProviderApiError {
            provider: TARGET_TYPE.to_string(),
            details,
            hint: "Check that the identity can read and update the container app (for example the Contributor role)".to_string(),
            url: super::docs_url(TARGET_TYPE),
        }
    }

    async fn token(&self) -> Result<String> {
        let auth = self.auth()?;
        let url = super::docs_url(TARGET_TYPE);
        let credential = auth.build_credential(TARGET_TYPE, &url)?;
        let token = credential.get_token(&[SCOPE], None).await.map_err(|e| {
            FnoxError::ProviderAuthFailed {
                provider: TARGET_TYPE.to_string(),
                details: e.to_string(),
                hint: auth.hint().to_string(),
                url,
            }
        })?;
        Ok(token.token.secret().to_string())
    }

    async fn request(
        &self,
        token: &str,
        method: reqwest::Method,
        body: Option<Value>,
        if_match: Option<&str>,
    ) -> Result<(Value, Option<String>)> {
        let mut request = crate::http::credential_client()
            .request(method.clone(), self.app_url())
            .bearer_auth(token);
        if let Some(etag) = if_match {
            request = request.header("If-Match", etag);
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        let response = request
            .send()
            .await
            .map_err(|e| Self::error(format!("{method} container app: request failed: {e}")))?;
        let status = response.status();
        let header_etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let text = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::PRECONDITION_FAILED {
            return Err(Self::error(format!(
                "{}: the app changed since fnox read it, so nothing was written; run fnox push again",
                self.app
            )));
        }
        if !status.is_success() {
            return Err(Self::error(format!(
                "{method} container app: HTTP {status}: {}",
                text.trim()
            )));
        }
        if text.trim().is_empty() {
            return Ok((Value::Null, header_etag));
        }
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| Self::error(format!("{method} container app: invalid JSON: {e}")))?;
        let etag =
            header_etag.or_else(|| value.get("etag").and_then(Value::as_str).map(String::from));
        Ok((value, etag))
    }

    /// Set every pair in one read and at most one write
    async fn write(&self, values: &[(&str, &str)]) -> Result<()> {
        let token = self.token().await?;
        let (app, etag) = self
            .request(&token, reqwest::Method::GET, None, None)
            .await?;
        let containers = merge_env(&app, self.container.as_deref(), values)
            .map_err(|why| Self::error(format!("{}: {why}", self.app)))?;
        let Some(containers) = containers else {
            tracing::debug!("{}: every variable already has its value", self.app);
            return Ok(());
        };
        // A merge patch replaces arrays whole, so this sends every container
        // as read; it leaves the app's `secrets` and the rest of the template alone
        let body = json!({ "properties": { "template": { "containers": containers } } });
        // The patch sends back every container as read, so it must fail if
        // another deployment changed the app since: If-Match turns that into a 412
        if etag.is_none() {
            tracing::warn!(
                "{}: Azure returned no etag, so a concurrent change to the app cannot be detected",
                self.app
            );
        }
        self.request(&token, reqwest::Method::PATCH, Some(body), etag.as_deref())
            .await?;
        Ok(())
    }
}

/// The app's containers with `values` set in the selected container's `env`,
/// or None when every variable already has its value (so no revision is made)
fn merge_env(
    app: &Value,
    container: Option<&str>,
    values: &[(&str, &str)],
) -> std::result::Result<Option<Value>, String> {
    let containers = app
        .pointer("/properties/template/containers")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty())
        .ok_or("the app has no containers")?;
    let names: Vec<&str> = containers
        .iter()
        .filter_map(|c| c.get("name").and_then(Value::as_str))
        .collect();
    let index = match container {
        Some(name) => names
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| format!("no container named '{name}'; it has: {}", names.join(", ")))?,
        None if containers.len() == 1 => 0,
        None => {
            return Err(format!(
                "it has {} containers ({}); set `container` to choose one",
                containers.len(),
                names.join(", ")
            ));
        }
    };

    let mut containers = containers.clone();
    let object = containers[index]
        .as_object_mut()
        .ok_or("the container is not an object")?;
    let env = object.entry("env").or_insert(Value::Null);
    if env.is_null() {
        *env = json!([]);
    }
    let env = env
        .as_array_mut()
        .ok_or("the container's env is not a list")?;

    let mut changed = false;
    for &(name, value) in values {
        let wanted = json!({ "name": name, "value": value });
        // Replaces every entry with this name, `secretRef` ones too, because
        // Azure applies the last duplicate
        let mut found = false;
        for var in env.iter_mut().filter(|var| var["name"] == name) {
            found = true;
            if *var != wanted {
                *var = wanted.clone();
                changed = true;
            }
        }
        if !found {
            env.push(wanted);
            changed = true;
        }
    }
    Ok(changed.then_some(Value::Array(containers)))
}

#[async_trait]
impl PushTarget for AzureContainerApps {
    fn describe(&self) -> String {
        let container = match &self.container {
            Some(c) => format!(", container {c}"),
            None => String::new(),
        };
        format!(
            "Azure Container Apps env var in {}/{}{container}",
            self.resource_group, self.app
        )
    }

    fn validate(&self) -> std::result::Result<(), String> {
        for (field, value) in [
            ("subscription", &self.subscription),
            ("resource_group", &self.resource_group),
            ("app", &self.app),
        ] {
            if value.is_empty() {
                return Err(format!("`{field}` must not be empty"));
            }
        }
        if self.container.as_deref() == Some("") {
            return Err("`container` must not be empty".to_string());
        }
        self.auth().map(|_| ()).map_err(|e| e.to_string())
    }

    fn validate_name(&self, name: &str) -> std::result::Result<(), String> {
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            Ok(())
        } else {
            Err(
                "Container Apps env var names may only use letters, digits, `_`, `-` and `.`"
                    .to_string(),
            )
        }
    }

    async fn push(&self, name: &str, value: &str) -> Result<()> {
        self.write(&[(name, value)]).await
    }

    async fn push_all(&self, values: &[(&str, &str)]) -> Vec<Result<()>> {
        match self.write(values).await {
            Ok(()) => values.iter().map(|_| Ok(())).collect(),
            Err(e) => {
                let message = e.to_string();
                values
                    .iter()
                    .map(|_| Err(FnoxError::Config(message.clone())))
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(extra: &str) -> AzureContainerApps {
        toml_edit::de::from_str(&format!(
            "subscription = \"sub\"\nresource_group = \"rg dev\"\napp = \"ca-api\"\n{extra}"
        ))
        .unwrap()
    }

    fn app(containers: Value) -> Value {
        json!({ "properties": { "template": { "containers": containers } } })
    }

    #[test]
    fn url_and_description() {
        let t = target("container = \"api\"");
        assert_eq!(
            t.app_url(),
            "https://management.azure.com/subscriptions/sub/resourceGroups/rg%20dev/providers/Microsoft.App/containerApps/ca-api?api-version=2024-03-01"
        );
        assert_eq!(
            t.describe(),
            "Azure Container Apps env var in rg dev/ca-api, container api"
        );
    }

    #[test]
    fn adds_and_replaces_in_one_pass() {
        let app = app(json!([{
            "name": "api",
            "image": "x",
            "env": [
                { "name": "KEEP", "value": "1" },
                { "name": "DB", "secretRef": "db" },
                { "name": "LOG_LEVEL", "value": "debug" }
            ]
        }]));
        let out = merge_env(
            &app,
            None,
            &[("DB", "url"), ("LOG_LEVEL", "info"), ("NEW", "n")],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            out,
            json!([{
                "name": "api",
                "image": "x",
                "env": [
                    { "name": "KEEP", "value": "1" },
                    { "name": "DB", "value": "url" },
                    { "name": "LOG_LEVEL", "value": "info" },
                    { "name": "NEW", "value": "n" }
                ]
            }])
        );
    }

    #[test]
    fn replaces_every_duplicate() {
        let app = app(json!([{ "name": "api", "env": [
            { "name": "A", "value": "new" },
            { "name": "A", "value": "old" }
        ] }]));
        let out = merge_env(&app, None, &[("A", "new")]).unwrap().unwrap();
        assert_eq!(
            out[0]["env"],
            json!([{ "name": "A", "value": "new" }, { "name": "A", "value": "new" }])
        );
    }

    #[test]
    fn creates_missing_env() {
        for container in [
            json!({ "name": "api" }),
            json!({ "name": "api", "env": null }),
        ] {
            let out = merge_env(&app(json!([container])), None, &[("A", "1")])
                .unwrap()
                .unwrap();
            assert_eq!(out[0]["env"], json!([{ "name": "A", "value": "1" }]));
        }
    }

    #[test]
    fn unchanged_values_make_no_write() {
        let app = app(json!([{ "name": "api", "env": [{ "name": "A", "value": "1" }] }]));
        assert_eq!(merge_env(&app, None, &[("A", "1")]).unwrap(), None);
    }

    #[test]
    fn picks_the_named_container() {
        let app = app(json!([{ "name": "api" }, { "name": "sidecar" }]));
        let err = merge_env(&app, None, &[("A", "1")]).unwrap_err();
        assert!(
            err.contains("api, sidecar") && err.contains("`container`"),
            "{err}"
        );
        let err = merge_env(&app, Some("web"), &[("A", "1")]).unwrap_err();
        assert!(err.contains("no container named 'web'"), "{err}");
        let out = merge_env(&app, Some("sidecar"), &[("A", "1")])
            .unwrap()
            .unwrap();
        assert!(out[0].get("env").is_none());
        assert_eq!(out[1]["env"], json!([{ "name": "A", "value": "1" }]));
    }

    #[test]
    fn rejects_an_app_without_containers() {
        assert!(merge_env(&json!({}), None, &[("A", "1")]).is_err());
        assert!(merge_env(&app(json!([])), None, &[("A", "1")]).is_err());
    }

    #[test]
    fn validates_config_and_names() {
        assert!(target("").validate().is_ok());
        assert!(target("").validate_name("DATABASE_URL").is_ok());
        assert!(target("").validate_name("a b").is_err());
        assert!(target("").validate_name("").is_err());
        assert!(target("container = \"\"").validate().is_err());
        assert!(
            target("managed_identity_client_id = \"x\"")
                .validate()
                .is_err()
        );
        let mut t = target("");
        t.app.clear();
        assert!(t.validate().is_err());
    }
}
