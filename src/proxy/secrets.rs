//! The real values behind a running proxy's placeholders. `request_secret`
//! can fill in a secret that had no value when the proxy started, or replace
//! one, without restarting the proxied command.

use super::*;

pub struct ProxySecrets {
    /// Each rule secret's placeholder
    placeholders: HashMap<String, String>,
    /// Secrets that some rule substitutes into a query parameter, whose
    /// echoes are redacted in percent-encoded form too
    in_query: HashSet<String>,
    current: std::sync::RwLock<Arc<SecretValues>>,
}

/// One consistent set of values and the redactions derived from them
#[derive(Default)]
pub(super) struct SecretValues {
    values: HashMap<String, String>,
    pub(super) redactions: Vec<Redaction>,
}

impl SecretValues {
    pub(super) fn get(&self, secret: &str) -> Option<&str> {
        self.values.get(secret).map(String::as_str)
    }
}

impl ProxySecrets {
    pub(super) fn new(
        placeholders: HashMap<String, String>,
        in_query: HashSet<String>,
        values: HashMap<String, String>,
    ) -> Result<Self> {
        let secrets = Self {
            placeholders,
            in_query,
            current: std::sync::RwLock::new(Arc::default()),
        };
        let current = secrets.prepare(values)?;
        *secrets.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(current);
        Ok(secrets)
    }

    /// The values in use now. A request keeps the snapshot it started with.
    pub(super) fn current(&self) -> Arc<SecretValues> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether a `[[proxy.rules]]` entry names `secret`
    pub fn has_rule(&self, secret: &str) -> bool {
        self.placeholders.contains_key(secret)
    }

    /// Whether `secret` has a value the proxy can inject
    pub fn has_value(&self, secret: &str) -> bool {
        self.current().get(secret).is_some()
    }

    /// Use `value` for `secret` from the next request on
    pub fn set(&self, secret: &str, value: String) -> Result<()> {
        if !self.has_rule(secret) {
            return Err(proxy_error(format!("no rule names secret '{secret}'")));
        }
        let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
        let mut values = current.values.clone();
        values.insert(secret.to_string(), value);
        *current = Arc::new(self.prepare(values)?);
        Ok(())
    }

    fn prepare(&self, values: HashMap<String, String>) -> Result<SecretValues> {
        for (secret, value) in &values {
            if value.is_empty() {
                return Err(proxy_error(format!(
                    "secret '{secret}' resolved to an empty value"
                )));
            }
            if self.placeholders.get(secret) == Some(value) {
                return Err(proxy_error(format!(
                    "placeholder for '{secret}' must differ from the real value"
                )));
            }
            if self
                .placeholders
                .values()
                .any(|placeholder| value.contains(placeholder.as_str()))
            {
                return Err(proxy_error(
                    "a real secret value cannot contain a configured placeholder",
                ));
            }
        }

        let mut redactions: Vec<Redaction> = Vec::new();
        // Sorted so that two secrets sharing a value always redact to the
        // same placeholder
        let mut secrets: Vec<_> = values.keys().collect();
        secrets.sort();
        for secret in secrets {
            let value = values[secret].as_bytes();
            let Some(placeholder) = self.placeholders.get(secret) else {
                continue;
            };
            let lenient = self.in_query.contains(secret);
            match redactions
                .iter_mut()
                .find(|redaction| redaction.value == value)
            {
                Some(existing) => existing.lenient |= lenient,
                None => redactions.push(Redaction {
                    value: value.to_vec(),
                    placeholder: placeholder.as_bytes().to_vec(),
                    lenient,
                }),
            }
        }
        redactions.sort_by_key(|redaction| std::cmp::Reverse(redaction.value.len()));
        Ok(SecretValues { values, redactions })
    }
}
