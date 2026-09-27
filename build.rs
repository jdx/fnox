//! Release builds for Linux GNU set `FNOX_NO_PIE=1` (see
//! .github/workflows/release.yml) to link the `fnox` executable at a fixed
//! address. As a position-independent executable, fnox makes the dynamic loader
//! patch about 120k pointers on every launch, which copies hundreds of pages
//! and is a large share of the run time of short commands such as the shell
//! hook. Linked non-PIE, those pointers are final in the file. Dependencies are
//! still compiled position-independent; the flag reaches only bin targets, so
//! no shared library is linked with it. musl is left out on purpose: its
//! static-PIE start code crashes when linked with `-no-pie`, and the
//! alternative, `-C relocation-model=static`, is not something a build script
//! can set.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FNOX_NO_PIE");
    let linux_gnu = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    if linux_gnu && std::env::var("FNOX_NO_PIE").as_deref() == Ok("1") {
        println!("cargo:rustc-link-arg-bins=-no-pie");
    }
}
