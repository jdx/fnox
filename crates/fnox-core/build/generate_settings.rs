// Code generator for settings from settings.toml
// Based on the pattern from hk (https://github.com/jdx/hk)

use indexmap::IndexMap;
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct SettingsToml {
    #[serde(flatten)]
    settings: IndexMap<String, SettingDef>,
}

#[derive(Debug, Deserialize)]
struct SettingDef {
    #[serde(rename = "type")]
    typ: String,
    default: String,
    #[serde(default)]
    sources: SettingSources,
    #[serde(default)]
    #[allow(dead_code)]
    docs: String,
}

#[derive(Debug, Default, Deserialize)]
struct SettingSources {
    #[serde(default)]
    cli: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    config: Vec<String>,
}

pub fn generate() -> Result<(), Box<dyn std::error::Error>> {
    let settings_toml = fs::read_to_string("settings.toml")?;
    let settings: SettingsToml = toml_edit::de::from_str(&settings_toml)?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let generated_dir = out_dir.join("generated");
    fs::create_dir_all(&generated_dir)?;

    // Generate settings.rs - the main Settings struct
    let settings_rs = generate_settings_struct(&settings)?;
    fs::write(generated_dir.join("settings.rs"), settings_rs)?;

    // Generate settings_merge.rs - merge types and enums
    let settings_merge_rs = generate_merge_types(&settings)?;
    fs::write(generated_dir.join("settings_merge.rs"), settings_merge_rs)?;

    // Generate settings_meta.rs - metadata for introspection
    let settings_meta_rs = generate_metadata(&settings)?;
    fs::write(generated_dir.join("settings_meta.rs"), settings_meta_rs)?;

    Ok(())
}

fn generate_settings_struct(settings: &SettingsToml) -> Result<String, Box<dyn std::error::Error>> {
    let mut fields = Vec::new();
    let mut defaults = Vec::new();

    for (name, def) in &settings.settings {
        let field_name = Ident::new(name, Span::call_site());
        let field_type = parse_type(&def.typ)?;
        let default_value = parse_default(&def.default, &def.typ)?;

        fields.push(quote! {
            pub #field_name: #field_type
        });

        defaults.push(quote! {
            #field_name: #default_value
        });
    }

    let output = quote! {
        use std::path::PathBuf;
        use std::sync::LazyLock;

        #[allow(dead_code)]
        static HOME_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
            dirs::home_dir().unwrap_or_default()
        });

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct Settings {
            #(#fields),*
        }

        impl Default for Settings {
            fn default() -> Self {
                Self {
                    #(#defaults),*
                }
            }
        }
    };

    Ok(output.to_string())
}

fn generate_merge_types(_settings: &SettingsToml) -> Result<String, Box<dyn std::error::Error>> {
    let output = quote! {
        use std::path::PathBuf;
        use indexmap::IndexMap;

        #[derive(Clone, Debug)]
        pub enum SettingValue {
            String(String),
            OptionString(Option<String>),
            Path(PathBuf),
            OptionPath(Option<PathBuf>),
            Bool(bool),
        }

        pub type SourceMap = IndexMap<&'static str, SettingValue>;

        #[allow(dead_code)]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum SettingSource {
            Defaults,
            Config,
            Env,
            Cli,
        }

        #[allow(dead_code)]
        pub type SourceInfoMap = IndexMap<&'static str, SourceInfoEntry>;

        #[allow(dead_code)]
        #[derive(Clone, Debug)]
        pub struct SourceInfoEntry {
            pub source: SettingSource,
            pub value: String,
        }
    };

    Ok(output.to_string())
}

fn generate_metadata(settings: &SettingsToml) -> Result<String, Box<dyn std::error::Error>> {
    let mut meta_entries = Vec::new();

    for (name, def) in &settings.settings {
        let name_lit = name.as_str();
        let typ_lit = def.typ.as_str();
        let default_lit = def.default.as_str();

        let cli_flags: Vec<_> = def.sources.cli.iter().map(|s| s.as_str()).collect();
        let env_vars: Vec<_> = def.sources.env.iter().map(|s| s.as_str()).collect();
        let config_keys: Vec<_> = def.sources.config.iter().map(|s| s.as_str()).collect();

        meta_entries.push(quote! {
            map.insert(
                #name_lit,
                SettingMeta {
                    typ: #typ_lit,
                    default_value: Some(#default_lit),
                    sources: SettingSourcesMeta {
                        cli: &[#(#cli_flags),*],
                        env: &[#(#env_vars),*],
                        config: &[#(#config_keys),*],
                    },
                },
            );
        });
    }

    let output = quote! {
        use indexmap::IndexMap;
        use std::sync::LazyLock;

        #[allow(dead_code)]
        pub struct SettingMeta {
            pub typ: &'static str,
            #[allow(dead_code)]
            pub default_value: Option<&'static str>,
            pub sources: SettingSourcesMeta,
        }

        #[allow(dead_code)]
        pub struct SettingSourcesMeta {
            #[allow(dead_code)]
            pub cli: &'static [&'static str],
            pub env: &'static [&'static str],
            #[allow(dead_code)]
            pub config: &'static [&'static str],
        }

        fn build_settings_meta() -> IndexMap<&'static str, SettingMeta> {
            let mut map = IndexMap::new();
            #(#meta_entries)*
            map
        }

        pub static SETTINGS_META: LazyLock<IndexMap<&'static str, SettingMeta>> =
            LazyLock::new(build_settings_meta);
    };

    Ok(output.to_string())
}

fn parse_type(typ: &str) -> Result<TokenStream, Box<dyn std::error::Error>> {
    Ok(match typ {
        "string" => quote! { String },
        "option<string>" => quote! { Option<String> },
        "path" => quote! { PathBuf },
        "option<path>" => quote! { Option<PathBuf> },
        "bool" => quote! { bool },
        _ => return Err(format!("Unsupported type: {}", typ).into()),
    })
}

fn parse_default(default: &str, typ: &str) -> Result<TokenStream, Box<dyn std::error::Error>> {
    Ok(match typ {
        "string" => {
            let default_str = default.trim_matches('"');
            quote! { #default_str.to_string() }
        }
        "option<string>" => {
            if default == "None" {
                quote! { None }
            } else {
                let default_str = default.trim_matches('"');
                quote! { Some(#default_str.to_string()) }
            }
        }
        "path" => {
            // Parse complex default expressions like: dirs::config_dir()...
            if default.starts_with("dirs::") {
                // Parse as raw tokens
                let tokens: TokenStream = default.parse()?;
                quote! { #tokens }
            } else {
                let default_str = default.trim_matches('"');
                quote! { PathBuf::from(#default_str) }
            }
        }
        "option<path>" => {
            if default == "None" {
                quote! { None }
            } else {
                let default_str = default.trim_matches('"');
                quote! { Some(PathBuf::from(#default_str)) }
            }
        }
        "bool" => match default {
            "true" => quote! { true },
            "false" => quote! { false },
            _ => return Err(format!("Invalid bool default: {}", default).into()),
        },
        _ => return Err(format!("Unsupported type for default: {}", typ).into()),
    })
}
