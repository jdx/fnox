// Build script for fnox
// Generates settings code from settings.toml
// Generates provider code from providers/*.toml

#[path = "build/generate_settings.rs"]
mod generate_settings;

#[path = "build/generate_providers.rs"]
mod generate_providers;

fn main() {
    // Tell Cargo to rerun this build script if settings.toml changes
    println!("cargo:rerun-if-changed=settings.toml");

    // Tell Cargo to rerun this build script if any provider toml changes
    println!("cargo:rerun-if-changed=providers");
    for entry in std::fs::read_dir("providers").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    // Generate settings code
    generate_settings::generate().expect("Failed to generate settings code");

    // Generate provider code
    generate_providers::generate().expect("Failed to generate provider code");
}
