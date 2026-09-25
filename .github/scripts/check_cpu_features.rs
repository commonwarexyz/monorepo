//! Check that the CPU reports each x86 feature named on the command line, or lacks it when the
//! name starts with `!`.
//!
//! CI runs this under Intel SDE before the emulated tests, so a runner or model change that drops
//! a feature fails the job instead of letting the tests fall back to narrower kernels.

fn detected(feature: &str) -> bool {
    match feature {
        "avx512f" => std::arch::is_x86_feature_detected!("avx512f"),
        "avx512bw" => std::arch::is_x86_feature_detected!("avx512bw"),
        "avx512vl" => std::arch::is_x86_feature_detected!("avx512vl"),
        "avx512ifma" => std::arch::is_x86_feature_detected!("avx512ifma"),
        "gfni" => std::arch::is_x86_feature_detected!("gfni"),
        "vpclmulqdq" => std::arch::is_x86_feature_detected!("vpclmulqdq"),
        _ => panic!("unknown feature `{feature}`"),
    }
}

fn main() {
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
