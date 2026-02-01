// Code generator for providers from providers/*.toml
// Generates ProviderConfig, ResolvedProviderConfig, and all related methods

use indexmap::IndexMap;
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct ProviderTomlRaw {
    display_name: String,
    serde_rename: String,
    rust_variant: String,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    struct_name: Option<String>,
    category: String,
    description: String,
    default_name: String,
    setup_instructions: String,
    #[serde(default)]
    auth_command: Option<String>,
    #[serde(default)]
    fields: IndexMap<String, FieldDef>,
    #[serde(default)]
    wizard_fields: IndexMap<String, WizardFieldDef>,
}

/// Provider config with derived fields filled in
#[derive(Debug)]
struct ProviderToml {
    display_name: String,
    serde_rename: String,
    rust_variant: String,
    module: String,
    struct_name: String,
    category: String,
    description: String,
    default_name: String,
    setup_instructions: String,
    auth_command: Option<String>,
    fields: IndexMap<String, FieldDef>,
    wizard_fields: IndexMap<String, WizardFieldDef>,
}

impl ProviderTomlRaw {
    /// Convert to ProviderToml, deriving module and struct_name if not specified
    fn into_provider(self) -> ProviderToml {
        // Derive module from serde_rename: replace `-` with `_`, handle leading digit
        let module = self.module.unwrap_or_else(|| {
            let m = self.serde_rename.replace('-', "_");
            // Handle "1password" -> "onepassword"
            if let Some(rest) = m.strip_prefix('1') {
                format!("one{rest}")
            } else {
                m
            }
        });

        // Derive struct_name from rust_variant + "Provider"
        let struct_name = self
            .struct_name
            .unwrap_or_else(|| format!("{}Provider", self.rust_variant));

        ProviderToml {
            display_name: self.display_name,
            serde_rename: self.serde_rename,
            rust_variant: self.rust_variant,
            module,
            struct_name,
            category: self.category,
            description: self.description,
            default_name: self.default_name,
            setup_instructions: self.setup_instructions,
            auth_command: self.auth_command,
            fields: self.fields,
            wizard_fields: self.wizard_fields,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FieldDef {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    placeholder: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    wizard: bool,
}

#[derive(Debug, Deserialize)]
struct WizardFieldDef {
    #[serde(rename = "type")]
    typ: String,
    placeholder: String,
    label: String,
}

pub fn generate() -> Result<(), Box<dyn std::error::Error>> {
    let providers = load_providers()?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let generated_dir = out_dir.join("generated");
    fs::create_dir_all(&generated_dir)?;

    // Generate providers_config.rs - ProviderConfig and ResolvedProviderConfig enums
    let providers_config_rs = generate_provider_config(&providers)?;
    fs::write(
        generated_dir.join("providers_config.rs"),
        providers_config_rs,
    )?;

    // Generate providers_methods.rs - has_secret_refs, try_to_resolved, from_wizard_fields
    let providers_methods_rs = generate_provider_methods(&providers)?;
    fs::write(
        generated_dir.join("providers_methods.rs"),
        providers_methods_rs,
    )?;

    // Generate providers_instantiate.rs - get_provider_from_resolved
    let providers_instantiate_rs = generate_provider_instantiate(&providers)?;
    fs::write(
        generated_dir.join("providers_instantiate.rs"),
        providers_instantiate_rs,
    )?;

    // Generate providers_resolver.rs - resolve_provider_config match
    let providers_resolver_rs = generate_provider_resolver(&providers)?;
    fs::write(
        generated_dir.join("providers_resolver.rs"),
        providers_resolver_rs,
    )?;

    // Generate providers_wizard.rs - ALL_WIZARD_INFO and WizardInfo
    let providers_wizard_rs = generate_provider_wizard(&providers)?;
    fs::write(
        generated_dir.join("providers_wizard.rs"),
        providers_wizard_rs,
    )?;

    Ok(())
}

fn load_providers() -> Result<Vec<(String, ProviderToml)>, Box<dyn std::error::Error>> {
    let providers_dir = PathBuf::from("providers");
    let mut providers = Vec::new();

    for entry in fs::read_dir(&providers_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let content = fs::read_to_string(&path)?;
            let raw: ProviderTomlRaw = toml_edit::de::from_str(&content)
                .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
            let provider = raw.into_provider();
            let name = path.file_stem().unwrap().to_string_lossy().to_string();
            providers.push((name, provider));
        }
    }

    // Sort by category for consistent ordering
    providers.sort_by(|a, b| {
        let cat_order = |cat: &str| -> usize {
            match cat {
                "Local" => 0,
                "PasswordManager" => 1,
                "CloudKms" => 2,
                "CloudSecretsManager" => 3,
                "OsKeychain" => 4,
                _ => 5,
            }
        };
        cat_order(&a.1.category).cmp(&cat_order(&b.1.category))
    });

    Ok(providers)
}

fn generate_provider_config(
    providers: &[(String, ProviderToml)],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut config_variants = Vec::new();
    let mut resolved_variants = Vec::new();

    for (_name, provider) in providers {
        let variant = Ident::new(&provider.rust_variant, Span::call_site());
        let serde_rename = &provider.serde_rename;

        // Generate ProviderConfig variant
        let config_fields = generate_config_variant_fields(provider);
        let resolved_fields = generate_resolved_variant_fields(provider);

        if config_fields.is_empty() {
            // Unit variant (like Plain)
            config_variants.push(quote! {
                #[serde(rename = #serde_rename)]
                #[strum(serialize = #serde_rename)]
                #variant
            });
            resolved_variants.push(quote! {
                #variant
            });
        } else {
            config_variants.push(quote! {
                #[serde(rename = #serde_rename)]
                #[strum(serialize = #serde_rename)]
                #variant { #(#config_fields),* }
            });
            resolved_variants.push(quote! {
                #variant { #(#resolved_fields),* }
            });
        }
    }

    // Note: Use super::super:: because this is included inside mod generated { mod providers_config { ... } }
    let output = quote! {
        use schemars::JsonSchema;
        use serde::{Deserialize, Serialize};
        use strum::AsRefStr;
        use super::super::secret_ref::{OptionStringOrSecretRef, StringOrSecretRef};
        use super::super::BitwardenBackend;

        fn default_bitwarden_backend() -> Option<BitwardenBackend> {
            Some(BitwardenBackend::Bw)
        }

        fn is_default_backend(backend: &Option<BitwardenBackend>) -> bool {
            backend.as_ref().is_none_or(|b| *b == BitwardenBackend::Bw)
        }

        #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, AsRefStr)]
        #[serde(tag = "type")]
        #[serde(deny_unknown_fields)]
        pub enum ProviderConfig {
            #(#config_variants),*
        }

        /// Provider configuration with all secret references resolved to actual values.
        #[derive(Debug, Clone)]
        pub enum ResolvedProviderConfig {
            #(#resolved_variants),*
        }
    };

    Ok(output.to_string())
}

fn generate_config_variant_fields(provider: &ProviderToml) -> Vec<TokenStream> {
    let mut fields = Vec::new();

    for (name, field) in &provider.fields {
        let field_name = Ident::new(name, Span::call_site());

        match field.typ.as_str() {
            "required" => {
                fields.push(quote! {
                    #field_name: StringOrSecretRef
                });
            }
            "optional" => {
                fields.push(quote! {
                    #[serde(default, skip_serializing_if = "OptionStringOrSecretRef::is_none")]
                    #field_name: OptionStringOrSecretRef
                });
            }
            "vec_string" => {
                fields.push(quote! {
                    #field_name: Vec<String>
                });
            }
            "backend_enum" => {
                fields.push(quote! {
                    #[serde(
                        default = "default_bitwarden_backend",
                        skip_serializing_if = "is_default_backend"
                    )]
                    backend: Option<BitwardenBackend>
                });
            }
            _ => {}
        }
    }

    fields
}

fn generate_resolved_variant_fields(provider: &ProviderToml) -> Vec<TokenStream> {
    let mut fields = Vec::new();

    for (name, field) in &provider.fields {
        let field_name = Ident::new(name, Span::call_site());

        match field.typ.as_str() {
            "required" => {
                fields.push(quote! { #field_name: String });
            }
            "optional" => {
                fields.push(quote! { #field_name: Option<String> });
            }
            "vec_string" => {
                fields.push(quote! { #field_name: Vec<String> });
            }
            "backend_enum" => {
                fields.push(quote! { backend: Option<BitwardenBackend> });
            }
            _ => {}
        }
    }

    fields
}

fn generate_provider_methods(
    providers: &[(String, ProviderToml)],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut try_to_resolved_arms = Vec::new();
    let mut from_wizard_fields_arms = Vec::new();
    let mut auth_command_arms = Vec::new();
    let mut env_deps_arms = Vec::new();

    for (_name, provider) in providers {
        let variant = Ident::new(&provider.rust_variant, Span::call_site());
        let serde_rename = &provider.serde_rename;
        let module = Ident::new(&provider.module, Span::call_site());

        // try_to_resolved arm
        let try_resolved_body = generate_try_to_resolved_body(provider);
        if provider.fields.is_empty() {
            try_to_resolved_arms.push(quote! {
                Self::#variant => Ok(ResolvedProviderConfig::#variant)
            });
        } else {
            let field_patterns = generate_field_patterns(provider);
            try_to_resolved_arms.push(quote! {
                Self::#variant { #(#field_patterns),* } => {
                    #try_resolved_body
                }
            });
        }

        // from_wizard_fields arm
        let from_wizard_body = generate_from_wizard_fields_body(provider);
        from_wizard_fields_arms.push(quote! {
            #serde_rename => { #from_wizard_body }
        });

        // auth_command arm
        let auth_cmd = if let Some(ref cmd) = provider.auth_command {
            quote! { Some(#cmd) }
        } else {
            quote! { None }
        };
        if provider.fields.is_empty() {
            auth_command_arms.push(quote! {
                Self::#variant => #auth_cmd
            });
            env_deps_arms.push(quote! {
                Self::#variant => #module::env_dependencies()
            });
        } else {
            auth_command_arms.push(quote! {
                Self::#variant { .. } => #auth_cmd
            });
            env_deps_arms.push(quote! {
                Self::#variant { .. } => #module::env_dependencies()
            });
        }
    }

    // Note: Use super::super:: because this is included inside mod generated { mod providers_methods { ... } }
    // Also reference providers_config module for ProviderConfig and ResolvedProviderConfig
    // Build use statements for provider modules
    let module_uses: Vec<TokenStream> = providers
        .iter()
        .map(|(_name, provider)| {
            let module = Ident::new(&provider.module, Span::call_site());
            quote! { use super::super::#module; }
        })
        .collect();

    let output = quote! {
        use crate::error::{FnoxError, Result};
        use super::providers_config::{ProviderConfig, ResolvedProviderConfig};
        use super::super::secret_ref::{OptionStringOrSecretRef, StringOrSecretRef};
        use std::collections::HashMap;
        #(#module_uses)*

        impl ProviderConfig {
            /// Get the provider type name (e.g., "age", "1password", "plain")
            pub fn provider_type(&self) -> &str {
                self.as_ref()
            }

            /// Get the environment variable names this provider depends on.
            /// Used by the dependency-ordered secret resolver (Kahn's algorithm).
            pub fn env_dependencies(&self) -> &'static [&'static str] {
                match self {
                    #(#env_deps_arms),*
                }
            }

            /// Convert to ResolvedProviderConfig if all values are literals.
            pub fn try_to_resolved(&self) -> Result<ResolvedProviderConfig> {
                // Helper to extract literal from required field
                let req = |v: &StringOrSecretRef| -> Result<String> {
                    v.as_literal().map(String::from).ok_or_else(|| {
                        FnoxError::Config(
                            "Cannot resolve secret reference without config context".to_string(),
                        )
                    })
                };

                // Helper to extract literal from optional field
                let opt = |v: &OptionStringOrSecretRef| -> Result<Option<String>> {
                    match v.as_ref() {
                        None => Ok(None),
                        Some(inner) => inner
                            .as_literal()
                            .map(|s| Some(s.to_string()))
                            .ok_or_else(|| {
                                FnoxError::Config(
                                    "Cannot resolve secret reference without config context".to_string(),
                                )
                            }),
                    }
                };

                // Suppress warnings for unused helpers when no provider uses them
                let _ = &req;
                let _ = &opt;

                match self {
                    #(#try_to_resolved_arms),*
                }
            }

            /// Build a ProviderConfig from wizard field values
            pub fn from_wizard_fields(
                provider_type: &str,
                fields: &HashMap<String, String>,
            ) -> Result<Self> {
                // Helper to get a required field as StringOrSecretRef
                let get_required = |name: &str| -> Result<StringOrSecretRef> {
                    fields
                        .get(name)
                        .filter(|s| !s.is_empty())
                        .map(|s| StringOrSecretRef::Literal(s.clone()))
                        .ok_or_else(|| FnoxError::Config(format!("{} is required", name)))
                };

                // Helper to get an optional field as OptionStringOrSecretRef
                let get_optional = |name: &str| -> OptionStringOrSecretRef {
                    fields
                        .get(name)
                        .filter(|s| !s.is_empty())
                        .map(|s| OptionStringOrSecretRef::literal(s.clone()))
                        .unwrap_or_default()
                };

                // Suppress warnings for unused helpers
                let _ = &get_required;
                let _ = &get_optional;

                match provider_type {
                    #(#from_wizard_fields_arms),*
                    _ => Err(FnoxError::Config(format!(
                        "Unknown provider type: {}",
                        provider_type
                    ))),
                }
            }

            /// Get the default auth command for this provider type.
            /// Returns None if no auth command is configured for this provider.
            pub fn default_auth_command(&self) -> Option<&'static str> {
                match self {
                    #(#auth_command_arms),*
                }
            }
        }
    };

    Ok(output.to_string())
}

/// Reserved names that conflict with function parameters in generated code
const RESERVED_NAMES: &[&str] = &["config", "profile", "provider_name", "ctx"];

/// Get local variable name for a field, prefixing with `field_` if it conflicts with reserved names
fn local_var_name(name: &str) -> String {
    if RESERVED_NAMES.contains(&name) {
        format!("field_{}", name)
    } else {
        name.to_string()
    }
}

fn generate_field_patterns(provider: &ProviderToml) -> Vec<TokenStream> {
    provider
        .fields
        .keys()
        .map(|name| {
            let field_name = Ident::new(name, Span::call_site());
            let local_name = local_var_name(name);
            if local_name != *name {
                let local_ident = Ident::new(&local_name, Span::call_site());
                quote! { #field_name: #local_ident }
            } else {
                quote! { #field_name }
            }
        })
        .collect()
}

fn generate_try_to_resolved_body(provider: &ProviderToml) -> TokenStream {
    let variant = Ident::new(&provider.rust_variant, Span::call_site());
    let mut field_conversions = Vec::new();

    for (name, field) in &provider.fields {
        let field_name = Ident::new(name, Span::call_site());
        let local_name = local_var_name(name);
        let local_ident = Ident::new(&local_name, Span::call_site());
        match field.typ.as_str() {
            "required" => {
                field_conversions.push(quote! { #field_name: req(#local_ident)? });
            }
            "optional" => {
                field_conversions.push(quote! { #field_name: opt(#local_ident)? });
            }
            "vec_string" => {
                field_conversions.push(quote! { #field_name: #local_ident.clone() });
            }
            "backend_enum" => {
                field_conversions.push(quote! { backend: *backend });
            }
            _ => {}
        }
    }

    quote! {
        Ok(ResolvedProviderConfig::#variant {
            #(#field_conversions),*
        })
    }
}

fn generate_from_wizard_fields_body(provider: &ProviderToml) -> TokenStream {
    let variant = Ident::new(&provider.rust_variant, Span::call_site());

    if provider.fields.is_empty() {
        return quote! { Ok(ProviderConfig::#variant) };
    }

    // Special handling for age provider
    if provider.serde_rename == "age" {
        return quote! {
            Ok(ProviderConfig::AgeEncryption {
                recipients: vec![
                    fields
                        .get("recipient")
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .ok_or_else(|| FnoxError::Config("recipient is required".to_string()))?,
                ],
                key_file: OptionStringOrSecretRef::none(),
            })
        };
    }

    // Special handling for keepass provider
    if provider.serde_rename == "keepass" {
        return quote! {
            Ok(ProviderConfig::KeePass {
                database: get_required("database")?,
                keyfile: get_optional("keyfile"),
                password: OptionStringOrSecretRef::none(),
            })
        };
    }

    // Special handling for password-store provider
    if provider.serde_rename == "password-store" {
        return quote! {
            Ok(ProviderConfig::PasswordStore {
                prefix: get_optional("prefix"),
                store_dir: get_optional("store_dir"),
                gpg_opts: OptionStringOrSecretRef::none(),
            })
        };
    }

    // Special handling for bitwarden provider
    if provider.serde_rename == "bitwarden" {
        return quote! {
            Ok(ProviderConfig::Bitwarden {
                collection: get_optional("collection"),
                organization_id: get_optional("organization_id"),
                profile: get_optional("profile"),
                backend: None,
            })
        };
    }

    let mut field_inits = Vec::new();
    for (name, field) in &provider.fields {
        let field_name = Ident::new(name, Span::call_site());
        let name_str = name.as_str();

        match field.typ.as_str() {
            "required" => {
                field_inits.push(quote! { #field_name: get_required(#name_str)? });
            }
            "optional" => {
                field_inits.push(quote! { #field_name: get_optional(#name_str) });
            }
            "vec_string" | "backend_enum" => {
                // Skip - handled specially
            }
            _ => {}
        }
    }

    quote! {
        Ok(ProviderConfig::#variant {
            #(#field_inits),*
        })
    }
}

fn generate_provider_instantiate(
    providers: &[(String, ProviderToml)],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut arms = Vec::new();

    for (_name, provider) in providers {
        let variant = Ident::new(&provider.rust_variant, Span::call_site());
        let module = Ident::new(&provider.module, Span::call_site());
        let struct_name = Ident::new(&provider.struct_name, Span::call_site());

        if provider.fields.is_empty() {
            arms.push(quote! {
                ResolvedProviderConfig::#variant => {
                    Ok(Box::new(#module::#struct_name::new()))
                }
            });
        } else {
            let field_patterns = generate_field_patterns(provider);
            let new_args = generate_new_args(provider);
            arms.push(quote! {
                ResolvedProviderConfig::#variant { #(#field_patterns),* } => {
                    Ok(Box::new(#module::#struct_name::new(#(#new_args),*)))
                }
            });
        }
    }

    // Note: Use super::super:: because this is included inside mod generated { mod providers_instantiate { ... } }
    let output = quote! {
        use crate::error::Result;
        use super::super::Provider;
        use super::providers_config::ResolvedProviderConfig;

        /// Create a provider from a resolved provider configuration.
        pub fn get_provider_from_resolved(config: &ResolvedProviderConfig) -> Result<Box<dyn Provider>> {
            match config {
                #(#arms),*
            }
        }
    };

    Ok(output.to_string())
}

fn generate_new_args(provider: &ProviderToml) -> Vec<TokenStream> {
    provider
        .fields
        .iter()
        .map(|(name, field)| {
            let local_name = local_var_name(name);
            let local_ident = Ident::new(&local_name, Span::call_site());
            match field.typ.as_str() {
                "backend_enum" => quote! { *backend },
                _ => quote! { #local_ident.clone() },
            }
        })
        .collect()
}

fn generate_provider_resolver(
    providers: &[(String, ProviderToml)],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut arms = Vec::new();

    for (_name, provider) in providers {
        let variant = Ident::new(&provider.rust_variant, Span::call_site());

        if provider.fields.is_empty() {
            arms.push(quote! {
                ProviderConfig::#variant => Ok(ResolvedProviderConfig::#variant)
            });
        } else {
            let field_patterns = generate_field_patterns(provider);
            let resolved_fields = generate_resolver_fields(provider);
            arms.push(quote! {
                ProviderConfig::#variant { #(#field_patterns),* } => {
                    Ok(ResolvedProviderConfig::#variant {
                        #(#resolved_fields),*
                    })
                }
            });
        }
    }

    // Note: Use super::super:: because this is included inside mod generated { mod providers_resolver { ... } }
    let output = quote! {
        use super::providers_config::{ProviderConfig, ResolvedProviderConfig};
        use crate::config::Config;
        use crate::error::Result;

        /// Resolve a provider config within a resolution context.
        ///
        /// This is the generated match statement for resolving provider configs.
        pub async fn resolve_provider_config_match(
            config: &Config,
            profile: &str,
            provider_name: &str,
            provider_config: &ProviderConfig,
            ctx: &mut super::super::resolver::ResolutionContext,
        ) -> Result<ResolvedProviderConfig> {
            match provider_config {
                #(#arms),*
            }
        }
    };

    Ok(output.to_string())
}

fn generate_resolver_fields(provider: &ProviderToml) -> Vec<TokenStream> {
    provider
        .fields
        .iter()
        .map(|(name, field)| {
            let field_name = Ident::new(name, Span::call_site());
            let local_name = local_var_name(name);
            let local_ident = Ident::new(&local_name, Span::call_site());
            let name_str = name.as_str();
            match field.typ.as_str() {
                "required" => {
                    quote! {
                        #field_name: super::super::resolver::resolve_required(config, profile, provider_name, #name_str, #local_ident, ctx).await?
                    }
                }
                "optional" => {
                    quote! {
                        #field_name: super::super::resolver::resolve_option(config, profile, provider_name, #local_ident, ctx).await?
                    }
                }
                "vec_string" => {
                    quote! { #field_name: #local_ident.clone() }
                }
                "backend_enum" => {
                    quote! { backend: *backend }
                }
                _ => quote! {},
            }
        })
        .collect()
}

fn generate_provider_wizard(
    providers: &[(String, ProviderToml)],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut wizard_info_entries = Vec::new();

    for (_name, provider) in providers {
        let provider_type = &provider.serde_rename;
        let display_name = &provider.display_name;
        let description = &provider.description;
        let default_name = &provider.default_name;
        let setup_instructions = &provider.setup_instructions;
        let category = match provider.category.as_str() {
            "Local" => quote! { WizardCategory::Local },
            "PasswordManager" => quote! { WizardCategory::PasswordManager },
            "CloudKms" => quote! { WizardCategory::CloudKms },
            "CloudSecretsManager" => quote! { WizardCategory::CloudSecretsManager },
            "OsKeychain" => quote! { WizardCategory::OsKeychain },
            _ => quote! { WizardCategory::Local },
        };

        // Build wizard fields
        let mut wizard_fields = Vec::new();

        // Check for wizard_fields first (for age provider's special "recipient" field)
        for (name, wf) in &provider.wizard_fields {
            let name_str = name.as_str();
            let label = &wf.label;
            let placeholder = &wf.placeholder;
            let required = wf.typ == "required";
            wizard_fields.push(quote! {
                WizardField {
                    name: #name_str,
                    label: #label,
                    placeholder: #placeholder,
                    required: #required,
                }
            });
        }

        // Then add regular fields that have wizard = true
        for (name, field) in &provider.fields {
            if field.wizard {
                let name_str = name.as_str();
                let label = &field.label;
                let placeholder = &field.placeholder;
                let required = field.typ == "required";
                wizard_fields.push(quote! {
                    WizardField {
                        name: #name_str,
                        label: #label,
                        placeholder: #placeholder,
                        required: #required,
                    }
                });
            }
        }

        wizard_info_entries.push(quote! {
            WizardInfo {
                provider_type: #provider_type,
                display_name: #display_name,
                description: #description,
                category: #category,
                setup_instructions: #setup_instructions,
                default_name: #default_name,
                fields: &[#(#wizard_fields),*],
            }
        });
    }

    // Note: Use super::super:: because this is included inside mod generated { mod providers_wizard { ... } }
    let output = quote! {
        use super::super::{WizardCategory, WizardField, WizardInfo};

        /// All wizard info for providers, generated from providers/*.toml
        pub static ALL_WIZARD_INFO: &[WizardInfo] = &[
            #(#wizard_info_entries),*
        ];
    };

    Ok(output.to_string())
}
