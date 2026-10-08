use crate::error::{FnoxError, Result};
use crate::secret_file::SecretFileFormat;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use strum::VariantNames;
use tokio::sync::OnceCell;

const PROVIDER_NAME: &str = "Plain";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/plain";

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

/// Plain provider that stores and returns values as-is without encryption.
///
/// This provider is useful for:
/// - Development and testing
/// - Non-sensitive configuration values
/// - Simple string storage
///
/// When configured with a `file`, values are instead looked up by key in that
/// plaintext file, which is read once per provider instance.
///
/// WARNING: Values are stored in plain text in the configuration file.
/// Do not use this provider for sensitive secrets in production.
#[derive(Default)]
pub struct PlainProvider {
    file: Option<SecretFile>,
}

struct SecretFile {
    path: PathBuf,
    format: SecretFileFormat,
    /// Parsed contents (or the read/parse failure), read on first use and
    /// shared by every lookup made through this instance, so a batch reads the
    /// file once.
    secrets: OnceCell<Result<HashMap<String, String>>>,
}

impl PlainProvider {
    pub fn new(file: Option<String>, format: Option<String>) -> Result<Self> {
        let file = match (file, format) {
            (None, None) => None,
            (None, Some(_)) => {
                return Err(FnoxError::Config(
                    "plain provider: `format` requires `file` to be set".to_string(),
                ));
            }
            (Some(_), None) => {
                return Err(FnoxError::Config(format!(
                    "plain provider: `file` requires `format` to be set (one of: {})",
                    SecretFileFormat::VARIANTS.join(", ")
                )));
            }
            (Some(path), Some(format)) => {
                let format = SecretFileFormat::from_str(&format).map_err(|_| {
                    FnoxError::Config(format!(
                        "plain provider: unknown format '{format}' (expected one of: {})",
                        SecretFileFormat::VARIANTS.join(", ")
                    ))
                })?;
                Some(SecretFile {
                    path: PathBuf::from(path),
                    format,
                    secrets: OnceCell::new(),
                })
            }
        };
        Ok(Self { file })
    }
}

impl SecretFile {
    async fn secrets(&self) -> Result<&HashMap<String, String>> {
        self.secrets
            .get_or_init(|| async {
                let input = tokio::fs::read_to_string(&self.path).await.map_err(|e| {
                    FnoxError::Provider(format!(
                        "plain provider: failed to read '{}': {e}",
                        self.path.display()
                    ))
                })?;
                self.format.parse(&input, &self.path.display().to_string())
            })
            .await
            .as_ref()
            .map_err(shared_error)
    }

    async fn get(&self, key: &str) -> Result<String> {
        self.secrets()
            .await?
            .get(key)
            .cloned()
            .ok_or_else(|| FnoxError::ProviderSecretNotFound {
                provider: PROVIDER_NAME.to_string(),
                secret: key.to_string(),
                hint: format!("Check that '{key}' is defined in {}", self.path.display()),
                url: PROVIDER_URL.to_string(),
            })
    }
}

/// Rebuild a cached read or parse failure for each lookup that shares it.
fn shared_error(error: &FnoxError) -> FnoxError {
    match error {
        FnoxError::ImportParseErrorWithSource {
            format,
            details,
            src,
            span,
        } => FnoxError::ImportParseErrorWithSource {
            format: format.clone(),
            details: details.clone(),
            src: src.clone(),
            span: *span,
        },
        FnoxError::Config(message) => FnoxError::Config(message.clone()),
        FnoxError::Provider(message) => FnoxError::Provider(message.clone()),
        other => FnoxError::Provider(other.to_string()),
    }
}

#[async_trait]
impl crate::providers::Provider for PlainProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        if self.file.is_some() {
            // Values come from a file fnox does not write to
            return vec![crate::providers::ProviderCapability::RemoteRead];
        }
        // Plain provider stores values as-is (no actual encryption)
        // We return Encryption to indicate it handles the value directly
        vec![crate::providers::ProviderCapability::Encryption]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        match &self.file {
            Some(file) => file.get(value).await,
            // Simply return the value as-is
            None => Ok(value.to_string()),
        }
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        let mut results = HashMap::with_capacity(secrets.len());
        for (key, value) in secrets {
            results.insert(key.clone(), self.get_secret(value).await);
        }
        results
    }

    async fn encrypt(&self, value: &str) -> Result<String> {
        if self.file.is_some() {
            return Err(FnoxError::Provider(
                "plain provider with `file` is read-only".to_string(),
            ));
        }
        // Plain provider stores values as-is without encryption
        Ok(value.to_string())
    }

    async fn test_connection(&self) -> Result<()> {
        if let Some(file) = &self.file {
            file.secrets().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    #[tokio::test]
    async fn returns_values_as_is_without_file() {
        let provider = PlainProvider::new(None, None).unwrap();
        assert_eq!(provider.get_secret("value").await.unwrap(), "value");
    }

    #[test]
    fn requires_file_and_format_together() {
        assert!(PlainProvider::new(Some("a.env".to_string()), None).is_err());
        assert!(PlainProvider::new(None, Some("env".to_string())).is_err());
        assert!(PlainProvider::new(Some("a.env".to_string()), Some("ini".to_string())).is_err());
    }

    #[tokio::test]
    async fn looks_up_values_in_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets");
        std::fs::write(&path, "export A='one'\nexport B=two\n").unwrap();

        let provider =
            PlainProvider::new(Some(path.display().to_string()), Some("shell".to_string()))
                .unwrap();
        let results = provider
            .get_secrets_batch(&[
                ("X".to_string(), "A".to_string()),
                ("Y".to_string(), "B".to_string()),
                ("Z".to_string(), "MISSING".to_string()),
            ])
            .await;

        assert_eq!(results["X"].as_ref().unwrap(), "one");
        assert_eq!(results["Y"].as_ref().unwrap(), "two");
        assert!(matches!(
            results["Z"],
            Err(FnoxError::ProviderSecretNotFound { .. })
        ));
        assert!(provider.encrypt("value").await.is_err());
    }

    #[tokio::test]
    async fn shares_read_failures_without_rereading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        std::fs::write(&path, "{ not json").unwrap();

        let provider =
            PlainProvider::new(Some(path.display().to_string()), Some("json".to_string())).unwrap();
        assert!(matches!(
            provider.get_secret("A").await,
            Err(FnoxError::ImportParseErrorWithSource { .. })
        ));

        // A fixed file is not picked up by the same instance
        std::fs::write(&path, r#"{"A": "1"}"#).unwrap();
        let results = provider
            .get_secrets_batch(&[
                ("X".to_string(), "A".to_string()),
                ("Y".to_string(), "A".to_string()),
            ])
            .await;
        assert!(matches!(
            results["X"],
            Err(FnoxError::ImportParseErrorWithSource { .. })
        ));
        assert!(matches!(
            results["Y"],
            Err(FnoxError::ImportParseErrorWithSource { .. })
        ));
    }
}
