use std::env;

const LEVELS: [&str; 5] = ["ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON"];
/// RESERVED is a special level that excludes ALL stability-marked items, used for finding unmarked public API.
const RESERVED_LEVEL: &str = "RESERVED";

/// Returns all levels to check, including RESERVED.
fn all_levels() -> impl Iterator<Item = &'static str> {
    LEVELS
        .iter()
        .copied()
        .chain(std::iter::once(RESERVED_LEVEL))
}

fn count_stability_cfgs() -> usize {
    let mut count = 0;

    // Check CARGO_CFG_* env vars (set by cargo for --cfg flags)
    for level in all_levels() {
        let var = format!("CARGO_CFG_COMMONWARE_STABILITY_{}", level);
        if env::var_os(var).is_some() {
            count += 1;
        }
    }

    // If we found any via CARGO_CFG_*, return that count
    if count > 0 {
        return count;
    }

    // Check RUSTFLAGS directly
    let rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    for level in all_levels() {
        let cfg = format!("commonware_stability_{}", level);
        if rustflags.contains(&cfg) {
            count += 1;
        }
    }

    if count > 0 {
        return count;
    }

    // Check CARGO_ENCODED_RUSTFLAGS
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for level in all_levels() {
        let cfg = format!("commonware_stability_{}", level);
        if encoded.split('\u{1f}').any(|flag| flag.contains(&cfg)) {
            count += 1;
        }
    }

    count
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    println!("cargo:rustc-check-cfg=cfg(commonware_stability_ALPHA)");
    println!("cargo:rustc-check-cfg=cfg(commonware_stability_BETA)");
    println!("cargo:rustc-check-cfg=cfg(commonware_stability_GAMMA)");
    println!("cargo:rustc-check-cfg=cfg(commonware_stability_DELTA)");
    println!("cargo:rustc-check-cfg=cfg(commonware_stability_EPSILON)");

    let count = count_stability_cfgs();
    if count == 0 {
        println!(
            "cargo:warning=stability cfg not set; set RUSTFLAGS=\"--cfg commonware_stability_X\" (ALPHA/BETA/GAMMA/DELTA/EPSILON) to enforce stability gating"
        );
    } else if count > 1 {
        println!(
            "cargo:warning=multiple stability cfgs detected; only one stability level (ALPHA/BETA/GAMMA/DELTA/EPSILON) should be set at a time"
        );
    }
}
