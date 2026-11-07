// Build script for fnox
// Generates provider code from providers/*.toml
//
// Settings are not generated any more: they are declared once, on `SettingsData` in
// src/settings.rs, and `#[derive(usage::Config)]` generates the registry and reader.

#[path = "build/generate_providers.rs"]
mod generate_providers;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
        let preview = manifest.join("native/touch-id-preview");
        let generated = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
            .join("touch-id-generated");
        std::fs::create_dir_all(&generated).expect("create Touch ID generated header directory");
        let node = std::env::var_os("NODE").unwrap_or_else(|| std::ffi::OsString::from("node"));
        let output = std::process::Command::new(node)
            .arg(preview.join("build-header.mts"))
            .arg(&generated)
            .output()
            .expect("Node.js 26 LTS is required to build the macOS Touch ID approval UI");
        if !output.status.success() {
            panic!(
                "Touch ID UI header generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let mut native = cc::Build::new();
        native
            .cpp(true)
            .file("src/providers/keychain_touch_id.mm")
            .file(preview.join("preview/authorization.mm"))
            .file(preview.join("src/approval-prompt.mm"))
            .file(preview.join("src/fingerprint-view.mm"))
            .include(preview.join("src"))
            .include(&generated)
            .flag("-fobjc-arc")
            .flag("-std=c++23");
        native.compile("fnox_keychain_touch_id");
        println!("cargo:rerun-if-changed={}", preview.display());
        println!("cargo:rerun-if-changed=src/providers/keychain_touch_id.mm");
        for framework in [
            "AppKit",
            "QuartzCore",
            "Security",
            "LocalAuthentication",
            "Foundation",
        ] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
    // Tell Cargo to rerun this build script if any provider toml changes
    println!("cargo:rerun-if-changed=providers");
    for entry in std::fs::read_dir("providers").unwrap().flatten() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    // Generate provider code
    generate_providers::generate().expect("Failed to generate provider code");
}
