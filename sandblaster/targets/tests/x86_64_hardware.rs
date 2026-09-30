//! Differential tests: x86_64 SSE2/SSSE3/SSE4.1 and SHA-NI models against the
//! real intrinsics (DESIGN.md §9.2 "Validation").
//!
//! Run on this Apple silicon machine under Rosetta 2:
//!
//! ```text
//! CARGO_TARGET_DIR=target/targets cargo test -p sandblaster-targets \
//!     --target x86_64-apple-darwin --test x86_64_hardware
//! ```
//!
//! Features are detected at run time and absent ones are skipped with the
//! reason printed. **SHA-NI is absent under Rosetta 2**: the SHA-NI tests then
//! check the models against FIPS 180-4 instead (RNDS2 = two FIPS rounds on the
//! ABEF/CDGH packing with `k[0]`, `k[1]`; MSG1/MSG2 = schedule steps; the
//! `sha2` crate's sequence = FIPS compression) and hardware validation of the
//! SHA-NI models remains **pending** (x86 CI with SHA-NI).
#![cfg(target_arch = "x86_64")]

use sandblaster_targets::consistency;
use sandblaster_targets::diff::{self, Config, assert_all_passed};
use sandblaster_targets::evidence::REQUIRED_RANDOM_CASES;
use sandblaster_targets::hw::x86_64 as hw;
use sandblaster_targets::registry;
use sandblaster_targets::x86_64 as model;

fn check(name: &str) {
    let cfg = Config::fast();
    let o = hw::run_model(name, &cfg).unwrap_or_else(|| panic!("{name} has no campaign"));
    if let Some(reason) = &o.skipped {
        eprintln!("SKIP {name}: {reason}");
        // Without the hardware, a SHA-NI model must at least agree with FIPS 180-4.
        let cons: Vec<_> = consistency::x86_models(&cfg)
            .into_iter()
            .filter(|c| c.name == name)
            .collect();
        if !cons.is_empty() {
            eprintln!(
                "{name}: hardware validation PENDING; checking FIPS 180-4 consistency instead"
            );
            assert_all_passed(&cons);
        }
        // A 256/512-bit model must agree with its independent reference.
        if let Some(c) = consistency::x86_wide_model(name, &Config { random_per_model: 2_000, ..cfg }) {
            eprintln!("{name}: hardware validation PENDING; checking the reference implementation instead");
            assert_all_passed(&[c]);
        }
        return;
    }
    let m = registry::find(registry::Arch::X86_64, name).expect("registered");
    if let Some(imms) = &m.immediates {
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
            let registered: Vec<&str> = registry::X86_64.iter().map(|m| m.name).collect();
            assert_eq!(tested.to_vec(), registered);
        }
    };
}

model_tests! {
    _mm_loadu_si128 _mm_storeu_si128 _mm_shuffle_epi8 _mm_shuffle_epi32 _mm_alignr_epi8 _mm_blend_epi16
    _mm_add_epi32 _mm_set_epi32 _mm_set_epi64x _mm_xor_si128 _mm_and_si128 _mm_or_si128
    _mm_sha256rnds2_epu32 _mm_sha256msg1_epu32 _mm_sha256msg2_epu32
    _mm512_loadu_si512 _mm512_storeu_si512 _mm512_add_epi32 _mm512_add_epi64 _mm512_sub_epi32 _mm512_sub_epi64
    _mm512_xor_si512 _mm512_and_si512 _mm512_or_si512 _mm512_andnot_si512 _mm512_ternarylogic_epi32
    _mm512_ternarylogic_epi64 _mm512_rol_epi32 _mm512_ror_epi32 _mm512_rol_epi64 _mm512_ror_epi64
    _mm512_rolv_epi32 _mm512_rorv_epi32 _mm512_rolv_epi64 _mm512_rorv_epi64 _mm512_slli_epi32
    _mm512_srli_epi32 _mm512_slli_epi64 _mm512_srli_epi64 _mm512_sllv_epi64 _mm512_srlv_epi64
    _mm512_shuffle_epi8 _mm512_permutexvar_epi32 _mm512_permutexvar_epi64 _mm512_permutex2var_epi64
    _mm512_shuffle_i32x4 _mm512_shuffle_i64x2 _mm512_unpacklo_epi32 _mm512_unpackhi_epi32
    _mm512_unpacklo_epi64 _mm512_unpackhi_epi64 _mm512_set1_epi32 _mm512_set1_epi64 _mm512_mask_blend_epi32
    _mm512_mask_blend_epi64 _mm512_cmplt_epu64_mask _mm512_cmpeq_epi64_mask _mm512_cmpeq_epi32_mask
    _mm512_maskz_mov_epi32 _mm512_mask_mov_epi32 _mm512_maskz_mov_epi64 _mm512_mask_mov_epi64
    _mm512_mullo_epi64 _mm512_mul_epu32 _mm256_ternarylogic_epi32 _mm256_ternarylogic_epi64 _mm256_rol_epi32
    _mm256_ror_epi32 _mm256_rol_epi64 _mm256_ror_epi64 _mm512_madd52lo_epu64 _mm512_madd52hi_epu64
    _mm256_madd52lo_epu64 _mm256_madd52hi_epu64 _mm512_gf2p8mul_epi8 _mm256_gf2p8mul_epi8 _mm_gf2p8mul_epi8
    _mm512_gf2p8affine_epi64_epi8 _mm256_gf2p8affine_epi64_epi8 _mm_gf2p8affine_epi64_epi8
    _mm512_gf2p8affineinv_epi64_epi8 _mm256_gf2p8affineinv_epi64_epi8 _mm_gf2p8affineinv_epi64_epi8
    _mm512_permutexvar_epi8 _mm512_permutex2var_epi8 _mm512_multishift_epi64_epi8 _mm512_shldv_epi64
    _mm512_shrdv_epi64 _mm512_shldv_epi32 _mm512_shrdv_epi32 _mm512_shldi_epi64 _mm512_shldi_epi32
    _mm512_popcnt_epi64 _mm512_popcnt_epi32 _mm512_popcnt_epi8 _mm512_popcnt_epi16 _mm256_loadu_si256
    _mm256_storeu_si256 _mm256_add_epi32 _mm256_add_epi64 _mm256_xor_si256 _mm256_and_si256 _mm256_or_si256
    _mm256_shuffle_epi8 _mm256_permutevar8x32_epi32 _mm256_slli_epi32 _mm256_srli_epi32 _mm256_slli_epi64
    _mm256_srli_epi64 _mm256_blend_epi32 _mm256_alignr_epi8 _mm256_set1_epi32 _mm256_set1_epi64x
}

#[test]
fn features_as_expected_under_rosetta() {
    let translated = std::process::Command::new("sysctl")
        .args(["-n", "sysctl.proc_translated"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
        .unwrap_or(false);
    for (f, present) in hw::detected_features() {
        eprintln!("{f}: {present}");
    }
    if translated {
        // Rosetta 2: SSE up to 4.2, no SHA-NI, no AVX (so no AVX2, AVX-512 or
        // VEX/EVEX GFNI: every 256/512-bit model is pending hardware here).
        assert!(hw::feature_detected("sse4.1") && hw::feature_detected("ssse3"));
        assert!(
            !hw::feature_detected("sha"),
            "Rosetta 2 unexpectedly reports SHA-NI; update the evidence notes"
        );
        assert!(!hw::feature_detected("avx") && !hw::feature_detected("avx512f"));
    }
}

#[test]
fn compress_from_intrinsics_equals_fips_or_skips() {
    let outcomes = hw::run_compositions(&Config::fast());
    for o in &outcomes {
        if let Some(r) = &o.skipped {
            eprintln!("SKIP {}: {r}", o.name);
        }
    }
    assert_all_passed(&outcomes);
}

/// The harness must catch plausible transcription bugs in the SSE models:
/// PALIGNR with swapped operands, PSHUFB honouring bits 6..4, PBLENDW on
/// dwords.
#[test]
fn harness_detects_plausible_wrong_models() {
    assert!(hw::feature_detected("sse4.1") && hw::feature_detected("ssse3"));
    let n = 500;
    // SAFETY: ssse3/sse4.1 detected above.
    let swapped = diff::diff_imm2(
        "alignr swapped",
        0..=255,
        n,
        1,
        |a, b, i| model::_mm_alignr_epi8(b, a, i),
        |a, b, i| unsafe { hw::_mm_alignr_epi8(a, b, i) },
    );
    assert!(swapped.mismatches > 0);
    let wide_index = diff::diff2(
        "pshufb zeroing on bit 4",
        n,
        2,
        |a: [u8; 16], m: [u8; 16]| {
            core::array::from_fn(|i| {
                if m[i] & 0x90 != 0 {
                    0
                } else {
                    a[(m[i] & 0x0f) as usize]
                }
            })
        },
        |a, m| unsafe { hw::_mm_shuffle_epi8(a, m) },
    );
    assert!(wide_index.mismatches > 0);
    let dword_blend = diff::diff_imm2(
        "blend on dwords",
        0..=255,
        n,
        3,
        |a: [u8; 16], b: [u8; 16], imm| {
            core::array::from_fn(|i| {
                if (imm >> (i / 4)) & 1 == 1 {
                    b[i]
                } else {
                    a[i]
                }
            })
        },
        |a, b, i| unsafe { hw::_mm_blend_epi16(a, b, i) },
    );
    assert!(dword_blend.mismatches > 0);
}

#[test]
#[ignore = "§9.2-size campaign (>= 10^7 random cases per model); run with --release -- --ignored"]
fn large_campaign_1e7_per_model() {
    let cfg = Config::large();
    let outcomes = hw::run_all(&cfg);
    for o in outcomes.iter().filter(|o| o.skipped.is_none()) {
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
