//! Build script: records the compiler and target that built this crate so the
//! evidence records (DESIGN.md §9.2 "Validation") name the exact toolchain
//! whose code was compared against the hardware.
//!
//! It also makes the committed evidence records (`evidence/<arch>.json`)
//! inputs of the build. The front end reads them at run time through
//! `evidence::validation` (`std::fs`, not its tracked file system) for the
//! `target-model:` lock items, so without this a crate whose build script
//! runs the verified pipeline could keep a result computed against an older
//! record. With the directory listed, changing any file in it re-runs this
//! script, which rebuilds this crate and everything that depends on it,
//! including those build scripts.

use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(&rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo::rustc-env=SANDBLASTER_TARGETS_RUSTC_VERSION={version}");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo::rustc-env=SANDBLASTER_TARGETS_TARGET={target}");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo::rustc-env=SANDBLASTER_TARGETS_PROFILE={profile}");
    println!("cargo::rerun-if-changed=build.rs");
    // A directory is scanned recursively: an edited, replaced (`cp`), added or
    // removed evidence file re-runs this script.
    println!("cargo::rerun-if-changed=evidence");
}
