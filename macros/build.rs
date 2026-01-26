use std::env;

const LEVELS: [&str; 5] = ["ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON"];

fn has_readiness_cfg() -> bool {
    // Check CARGO_CFG_* env vars (set by cargo for --cfg flags)
    for level in LEVELS {
        let var = format!("CARGO_CFG_MIN_READINESS_{}", level);
        if env::var_os(var).is_some() {
            return true;
        }
    }

    // Check RUSTFLAGS directly
    let rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    if rustflags.contains("min_readiness_") {
        return true;
    }

    // Check CARGO_ENCODED_RUSTFLAGS
    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    encoded
        .split('\u{1f}')
        .any(|flag| flag.contains("min_readiness_"))
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    if !has_readiness_cfg() {
        println!(
            "cargo:warning=readiness cfg not set; set RUSTFLAGS=\"--cfg min_readiness_X\" (ALPHA/BETA/GAMMA/DELTA/EPSILON) to enforce readiness gating"
        );
    }
}
