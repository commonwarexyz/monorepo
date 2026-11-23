//! Warns when a release build sets no stability cfg, or more than one stability level.
//!
//! It reads the cfgs this crate is built with, which match those of the crates it gates.

use std::env;

/// Stability levels in order of increasing stability.
const LEVELS: [&str; 6] = ["WIP", "ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON"];

/// `WIP` is additive (it is compiled only when its cfg is set) and the monorepo enables it by
/// default, so it may be set alongside one other level (which takes precedence).
const WIP_LEVEL: &str = "WIP";

/// `RESERVED` is a special level that excludes ALL stability-marked items, used for finding unmarked public API.
const RESERVED_LEVEL: &str = "RESERVED";

/// Returns all levels to check, including RESERVED.
fn all_levels() -> impl Iterator<Item = &'static str> {
    LEVELS
        .iter()
        .copied()
        .chain(std::iter::once(RESERVED_LEVEL))
}

/// Returns the stability levels whose cfgs are set in the environment.
fn stability_cfgs() -> Vec<&'static str> {
    // Check CARGO_CFG_* env vars (set by cargo for --cfg flags)
    let found: Vec<_> = all_levels()
        .filter(|level| {
            let var = format!("CARGO_CFG_COMMONWARE_STABILITY_{}", level);
            env::var_os(var).is_some()
        })
        .collect();
    if !found.is_empty() {
        return found;
    }

    // Check CARGO_ENCODED_RUSTFLAGS
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    all_levels()
        .filter(|level| {
            let cfg = format!("commonware_stability_{}", level);
            encoded.split('\u{1f}').any(|flag| flag.contains(&cfg))
        })
        .collect()
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=PROFILE");

    // Skip stability warnings for development profiles (debug, test)
    let profile = env::var("PROFILE").unwrap_or_default();
    let is_dev_profile = matches!(profile.as_str(), "debug" | "test");

    // Print a warning if no stability cfg is set or if multiple stability cfgs are set.
    let cfgs = stability_cfgs();
    let explicit = cfgs.iter().filter(|level| **level != WIP_LEVEL).count();
    if cfgs.is_empty() && !is_dev_profile {
        println!(
            "cargo:warning=stability cfg not set (defaulting to ALPHA); set RUSTFLAGS=\"--cfg commonware_stability_X\" (ALPHA/BETA/GAMMA/DELTA/EPSILON) to enforce stability gating"
        );
    } else if explicit > 1 {
        println!(
            "cargo:warning=multiple stability cfgs detected; only one stability level (ALPHA/BETA/GAMMA/DELTA/EPSILON) should be set at a time"
        );
    }
}
