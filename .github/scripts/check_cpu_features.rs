//! Check that the CPU reports each feature named on the command line, or lacks it when the name
//! starts with `!`.
//!
//! CI runs this under the job's CPU emulator before the emulated tests, so a runner or model change
//! that drops a feature, or adds one the entry expects absent, fails the job instead of silently
//! changing which kernels the tests reach.

#[cfg(target_arch = "x86_64")]
fn detected(feature: &str) -> bool {
    match feature {
        "ssse3" => std::arch::is_x86_feature_detected!("ssse3"),
        "sse4.1" => std::arch::is_x86_feature_detected!("sse4.1"),
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        "bmi2" => std::arch::is_x86_feature_detected!("bmi2"),
        "adx" => std::arch::is_x86_feature_detected!("adx"),
        "sha" => std::arch::is_x86_feature_detected!("sha"),
        "avx512f" => std::arch::is_x86_feature_detected!("avx512f"),
        "avx512bw" => std::arch::is_x86_feature_detected!("avx512bw"),
        "avx512vl" => std::arch::is_x86_feature_detected!("avx512vl"),
        "avx512ifma" => std::arch::is_x86_feature_detected!("avx512ifma"),
        "gfni" => std::arch::is_x86_feature_detected!("gfni"),
        "vpclmulqdq" => std::arch::is_x86_feature_detected!("vpclmulqdq"),
        _ => panic!("unknown feature `{feature}`"),
    }
}

#[cfg(target_arch = "aarch64")]
fn detected(feature: &str) -> bool {
    match feature {
        "neon" => std::arch::is_aarch64_feature_detected!("neon"),
        "sha2" => std::arch::is_aarch64_feature_detected!("sha2"),
        "sha3" => std::arch::is_aarch64_feature_detected!("sha3"),
        "sve" => std::arch::is_aarch64_feature_detected!("sve"),
        "sve2" => std::arch::is_aarch64_feature_detected!("sve2"),
        _ => panic!("unknown feature `{feature}`"),
    }
}

fn main() {
    assert!(std::env::args().len() > 1, "no CPU features named");
    let mut unexpected = Vec::new();
    for arg in std::env::args().skip(1) {
        let (feature, expected) = match arg.strip_prefix('!') {
            Some(feature) => (feature, false),
            None => (arg.as_str(), true),
        };
        let found = detected(feature);
        println!("{feature}: {found}");
        if found != expected {
            unexpected.push(arg.clone());
        }
    }
    assert!(
        unexpected.is_empty(),
        "unexpected CPU features: {unexpected:?}"
    );
}
