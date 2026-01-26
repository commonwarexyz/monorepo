use std::env;

fn has_readiness_cfg() -> bool {
    for level in ["BETA", "GAMMA", "DELTA", "EPSILON"] {
        let var = format!("CARGO_CFG_MIN_READINESS_{}", level);
        if env::var_os(var).is_some() {
            return true;
        }
    }
    let rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    if rustflags.contains("min_readiness_") {
        return true;
    }
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
            "cargo:warning=readiness cfg not set; set RUSTFLAGS=\"--cfg min_readiness_X\" (BETA/GAMMA/DELTA/EPSILON) to enforce readiness gating"
        );
    }
}
