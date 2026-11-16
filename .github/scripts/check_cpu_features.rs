//! Check that the CPU has exactly the named features among those this program knows. Every name on
//! the command line must be a known feature the CPU has, and the CPU must lack every other known
//! feature.
//!
//! CI runs this twice for a row that names an emulated CPU. The first run, on the runner itself,
//! decides whether the row can skip the emulator. The second run, on the CPU the tests use, fails
//! the job when that CPU differs from the row's list in any known feature, since the difference
//! would change which kernels the tests reach. A row that always runs natively uses one run to
//! check the runner the same way.

/// The features this program knows, each with its detector.
#[cfg(target_arch = "x86_64")]
const FEATURES: &[(&str, fn() -> bool)] = &[
    ("avx2", || std::arch::is_x86_feature_detected!("avx2")),
    ("bmi2", || std::arch::is_x86_feature_detected!("bmi2")),
    ("adx", || std::arch::is_x86_feature_detected!("adx")),
    ("sha", || std::arch::is_x86_feature_detected!("sha")),
    ("avx512f", || std::arch::is_x86_feature_detected!("avx512f")),
    ("avx512bw", || {
        std::arch::is_x86_feature_detected!("avx512bw")
    }),
    ("avx512vl", || {
        std::arch::is_x86_feature_detected!("avx512vl")
    }),
    ("avx512ifma", || {
        std::arch::is_x86_feature_detected!("avx512ifma")
    }),
    ("avx512vnni", || {
        std::arch::is_x86_feature_detected!("avx512vnni")
    }),
    ("gfni", || std::arch::is_x86_feature_detected!("gfni")),
    ("vaes", || std::arch::is_x86_feature_detected!("vaes")),
    ("vpclmulqdq", || {
        std::arch::is_x86_feature_detected!("vpclmulqdq")
    }),
];

/// The features this program knows, each with its detector.
#[cfg(target_arch = "aarch64")]
const FEATURES: &[(&str, fn() -> bool)] = &[
    ("neon", || std::arch::is_aarch64_feature_detected!("neon")),
    ("sha2", || std::arch::is_aarch64_feature_detected!("sha2")),
    ("sha3", || std::arch::is_aarch64_feature_detected!("sha3")),
    ("sve", || std::arch::is_aarch64_feature_detected!("sve")),
    ("sve2", || std::arch::is_aarch64_feature_detected!("sve2")),
];

fn main() {
    let named: Vec<String> = std::env::args().skip(1).collect();
    assert!(!named.is_empty(), "at least one CPU feature must be named");
    for name in &named {
        assert!(
            FEATURES.iter().any(|(known, _)| known == name),
            "feature `{name}` must be one this program knows"
        );
    }
    let mut unexpected = Vec::new();
    for (name, detected) in FEATURES {
        let found = detected();
        let expected = named.iter().any(|named| named == name);
        println!("{name}: {found}");
        if found != expected {
            unexpected.push(format!(
                "{name} {}",
                if found { "present" } else { "missing" }
            ));
        }
    }
    assert!(
        unexpected.is_empty(),
        "unexpected CPU features: {unexpected:?}"
    );
}
