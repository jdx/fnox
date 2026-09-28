// Build script for fnox
// Generates provider code from providers/*.toml
//
// Settings are not generated any more: they are declared once, on `SettingsData` in
// src/settings.rs, and `#[derive(usage::Config)]` generates the registry and reader.

#[path = "build/generate_providers.rs"]
mod generate_providers;

fn main() {
    // Tell Cargo to rerun this build script if any provider toml changes
    println!("cargo:rerun-if-changed=providers");
    for entry in std::fs::read_dir("providers").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    // Generate provider code
    generate_providers::generate().expect("Failed to generate provider code");
}
