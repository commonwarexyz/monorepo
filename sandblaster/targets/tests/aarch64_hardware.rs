//! Differential tests: aarch64 NEON/SHA2 models against the real intrinsics
//! on this CPU (DESIGN.md §9.2 "Validation").
//!
//! One fast test per model (random + corner cases, every immediate
//! exhaustively), the whole-compression checks, must-detect checks proving the
//! harness is not vacuous, and an `#[ignore]`d §9.2-size campaign (≥ 10^7
//! random cases per model), best run with `--release`:
//!
//! ```text
//! CARGO_TARGET_DIR=target/targets cargo test --release -p sandblaster-targets \
//!     --test aarch64_hardware -- --ignored
//! ```
#![cfg(target_arch = "aarch64")]

use sandblaster_targets::aarch64 as model;
use sandblaster_targets::diff::{self, Config, assert_all_passed};
use sandblaster_targets::evidence::REQUIRED_RANDOM_CASES;
use sandblaster_targets::fips;
use sandblaster_targets::hw::aarch64 as hw;
use sandblaster_targets::registry;

fn check(name: &str) {
    let o =
        hw::run_model(name, &Config::fast()).unwrap_or_else(|| panic!("{name} has no campaign"));
    if let Some(imms) =
        registry::find(registry::Arch::Aarch64, name).and_then(|m| m.immediates.as_ref())
    {
        assert_eq!(
            o.immediates.as_ref(),
            Some(imms),
            "{name}: every immediate must be covered"
        );
    }
    assert_all_passed(&[o]);
}

macro_rules! model_tests {
    ($($name:ident)*) => {
        $( #[test] fn $name() { check(stringify!($name)); } )*
        /// The per-model tests above cover exactly the registry.
        #[test]
        fn tests_cover_the_registry() {
            let tested = [$(stringify!($name)),*];
            let registered: Vec<&str> = registry::AARCH64.iter().map(|m| m.name).collect();
            assert_eq!(tested.to_vec(), registered);
        }
    };
}

model_tests! {
    vld1q_u8 vld1q_u32 vld1_u8 vst1q_u8 vst1q_u32 vrev32q_u8 vreinterpretq_u32_u8 vreinterpretq_u8_u32
    vaddq_u32 veorq_u32 vandq_u32 vorrq_u32 vshlq_n_u32 vshrq_n_u32 vextq_u32 vdupq_n_u32
    vgetq_lane_u32 vsetq_lane_u32 vsetq_lane_u8
    vsha256hq_u32 vsha256h2q_u32 vsha256su0q_u32 vsha256su1q_u32
    vld1q_u64 vst1q_u64 veorq_u8 vandq_u8 vorrq_u8 vdupq_n_u8 vshrq_n_u8 vcltq_u8 vcgeq_u8 vceqq_u8
    vqtbl1q_u8 vcntq_u8 vaddvq_u8 vmaxvq_u8 vreinterpretq_u16_u8 vreinterpretq_u64_u8 vcombine_u8
    vgetq_lane_u64 vshrn_n_u16 vshrn_n_u64 vmovn_u64 vaddq_u64 vsraq_n_u64 vbslq_u64 vbslq_u32
    vmull_u32 vmlal_u32
    veor3q_u8 vbcaxq_u8 vrax1q_u64 vxarq_u64 vsha512hq_u64 vsha512h2q_u64 vsha512su0q_u64 vsha512su1q_u64
}

#[test]
fn compress_from_intrinsics_equals_fips_and_models() {
    assert_all_passed(&hw::run_compositions(&Config::fast()));
}

#[test]
fn intrinsic_compression_known_answer() {
    // SHA-256("abc") through the real SHA2 instructions.
    assert!(std::arch::is_aarch64_feature_detected!("sha2"));
    let mut block = [0u8; 64];
    block[..3].copy_from_slice(b"abc");
    block[3] = 0x80;
    block[63] = 24;
    // SAFETY: sha2 detected above.
    let s = unsafe { hw::compress_sha2(fips::H0, &block) };
    let mut digest = [0u8; 32];
    for (i, w) in s.iter().enumerate() {
        digest[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    assert_eq!(
        fips::hex(&digest),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// The harness must catch the classic transcription bugs: SHA256H2 with the
/// pseudocode's argument order, SU1 without the dependence on its own lower
/// half, and a USHR model that mishandles `#32`.
#[test]
fn harness_detects_plausible_wrong_models() {
    let cfg = Config {
        random_per_model: 2_000,
        seed: 7,
    };
    // SAFETY: sha2/neon present on every aarch64-apple-darwin CPU; checked.
    assert!(std::arch::is_aarch64_feature_detected!("sha2"));
    let swapped = diff::diff3(
        "h2 swapped",
        cfg.random_per_model,
        cfg.seed,
        |efgh, abcd, wk| model::vsha256h2q_u32(abcd, efgh, wk),
        |a, b, c| unsafe { hw::vsha256h2q_u32(a, b, c) },
    );
    assert!(
        swapped.mismatches > 0,
        "swapped H2 arguments went unnoticed"
    );
    let naive_su1 = diff::diff3(
        "su1 without T1 = result<63:0>",
        cfg.random_per_model,
        cfg.seed,
        |x: [u32; 4], n: [u32; 4], m: [u32; 4]| {
            let t0 = [n[1], n[2], n[3], m[0]];
            let t1 = [m[2], m[3], m[0], m[1]];
            core::array::from_fn(|e| {
                fips::small_sigma1(t1[e])
                    .wrapping_add(x[e])
                    .wrapping_add(t0[e])
            })
        },
        |a, b, c| unsafe { hw::vsha256su1q_u32(a, b, c) },
    );
    assert!(naive_su1.mismatches > 0);
    let bad_shr = diff::diff_imm1(
        "ushr #32 as identity",
        1..=32,
        320,
        cfg.seed,
        |a: [u32; 4], n| a.map(|x| x.wrapping_shr(n as u32)),
        |a, n| unsafe { hw::vshrq_n_u32(a, n) },
    );
    assert!(bad_shr.mismatches > 0);
}

#[test]
#[ignore = "§9.2-size campaign (>= 10^7 random cases per model); run with --release -- --ignored"]
fn large_campaign_1e7_per_model() {
    let cfg = Config::large();
    let outcomes = hw::run_all(&cfg);
    for o in &outcomes {
        assert!(
            o.random >= REQUIRED_RANDOM_CASES,
            "{}: only {} random cases",
            o.name,
            o.random
        );
    }
    assert_all_passed(&outcomes);
    assert_all_passed(&hw::run_compositions(&cfg));
}
