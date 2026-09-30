//! Portable consistency checks: the SHA instruction models against FIPS 180-4.
//!
//! The differential campaigns of [`crate::hw`] compare a model with the
//! hardware. This module compares the SHA models with the *specification*
//! they implement, [`crate::fips`], which is what the phase-3 `VariantEquiv`
//! proofs (DESIGN.md §9.3) establish symbolically. These checks run on any
//! host. For SHA-NI they are the **only** validation available on this
//! machine (Rosetta 2 has no SHA-NI; §9.2), so SHA-NI models carry
//! `pending-hardware` evidence: consistent with FIPS 180-4, not yet compared
//! with an Intel/AMD CPU.
//!
//! Properties, each a campaign of the [`crate::diff`] harness with the FIPS
//! formulation as the reference:
//!
//! * `vsha256hq_u32(abcd, efgh, wk)` = the `abcd` half of four FIPS rounds
//!   with `K + W = wk[0..4]`; `vsha256h2q_u32(efgh, abcd, wk)` (efgh first,
//!   pre-update abcd) = the `efgh` half of the same four rounds.
//! * `vsha256su0q_u32` / `vsha256su1q_u32`: the partial schedule sums of the
//!   Arm pseudocode, and their composition `su1(su0(s0, s1), s2, s3)` =
//!   `W16..W19` of the FIPS schedule.
//! * `_mm_sha256rnds2_epu32(cdgh, abef, wk)` = two FIPS rounds on the
//!   ABEF/CDGH packing using only `wk[0]`, `wk[1]`; the `sha2` crate's
//!   four-round group (second RNDS2 on `shuffle_epi32(wk, 0x0E)` with the
//!   registers swapped) = four FIPS rounds.
//! * `_mm_sha256msg1_epu32` / `_mm_sha256msg2_epu32`: the SDM partial sums,
//!   and the `sha2` crate's `schedule` = `W16..W19`.
//! * Big-endian loads: `vreinterpretq_u32_u8(vrev32q_u8(b))` and
//!   `_mm_shuffle_epi8(b, MASK)` equal `from_be_bytes` per lane.
//! * Whole compressions: [`crate::compress`]'s aarch64 and x86 assemblies
//!   equal [`crate::fips::compress`].
//!
//! The 256/512-bit x86 models (MODELS.md §10) have no FIPS formulation;
//! [`x86_wide_models`] compares each with its independent reference
//! implementation ([`crate::reference`]) instead: the local check of the
//! transcriptions, and their recorded consistency evidence on a CPU without
//! the feature (`pending-hardware`, like SHA-NI under Rosetta 2).
#![forbid(unsafe_code)]

use crate::aarch64 as a64;
use crate::compress;
use crate::diff::{Config, Outcome, diff_imm1, diff_imm2, diff_imm3, diff1, diff2, diff3};
use crate::fips;
use crate::x86_64 as x86;

/// FIPS rounds on `[a, b, c, d, e, f, g, h]` with the given `K + W` words.
pub fn fips_rounds(mut s: [u32; 8], kw: &[u32]) -> [u32; 8] {
    for &w in kw {
        s = fips::round(s, w);
    }
    s
}

fn join(abcd: [u32; 4], efgh: [u32; 4]) -> [u32; 8] {
    [
        abcd[0], abcd[1], abcd[2], abcd[3], efgh[0], efgh[1], efgh[2], efgh[3],
    ]
}

/// Reference for SHA256H: the `abcd` half after four FIPS rounds.
pub fn fips_rounds4_abcd(abcd: [u32; 4], efgh: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    let s = fips_rounds(join(abcd, efgh), &wk);
    [s[0], s[1], s[2], s[3]]
}

/// Reference for SHA256H2: the `efgh` half after four FIPS rounds.
pub fn fips_rounds4_efgh(abcd: [u32; 4], efgh: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    let s = fips_rounds(join(abcd, efgh), &wk);
    [s[4], s[5], s[6], s[7]]
}

/// `[a..h]` from the SHA-NI packing `abef = [f, e, b, a]`, `cdgh = [h, g, d, c]`.
pub fn unpack_abef_cdgh(abef: [u32; 4], cdgh: [u32; 4]) -> [u32; 8] {
    [
        abef[3], abef[2], cdgh[3], cdgh[2], abef[1], abef[0], cdgh[1], cdgh[0],
    ]
}

/// The SHA-NI packing of `[a..h]`: `(abef, cdgh) = ([f, e, b, a], [h, g, d, c])`.
pub fn pack_abef_cdgh(s: [u32; 8]) -> ([u32; 4], [u32; 4]) {
    ([s[5], s[4], s[1], s[0]], [s[7], s[6], s[3], s[2]])
}

/// Reference for SHA256RNDS2: two FIPS rounds with `wk[0]`, `wk[1]`, result
/// in the ABEF packing.
pub fn fips_rnds2(cdgh: [u32; 4], abef: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    let s = fips_rounds(unpack_abef_cdgh(abef, cdgh), &wk[..2]);
    pack_abef_cdgh(s).0
}

/// `W16..W19` from `W0..W15` by the FIPS schedule recurrence.
pub fn fips_schedule4(w: [u32; 16]) -> [u32; 4] {
    let mut x = [0u32; 20];
    x[..16].copy_from_slice(&w);
    for t in 16..20 {
        x[t] = fips::schedule_step(x[t - 2], x[t - 7], x[t - 15], x[t - 16]);
    }
    [x[16], x[17], x[18], x[19]]
}

fn be_words(b: [u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| {
        u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
    })
}

/// The per-model consistency properties for the aarch64 SHA2 models (names
/// equal the model names so the evidence writer can attach them).
pub fn aarch64_models(cfg: &Config) -> Vec<Outcome> {
    let n = cfg.random_per_model;
    vec![
        diff3(
            "vsha256hq_u32",
            n,
            cfg.seed_for("c/vsha256hq_u32"),
            a64::vsha256hq_u32,
            fips_rounds4_abcd,
        ),
        // H2 takes efgh first and the pre-update abcd second.
        diff3(
            "vsha256h2q_u32",
            n,
            cfg.seed_for("c/vsha256h2q_u32"),
            a64::vsha256h2q_u32,
            |efgh, abcd, wk| fips_rounds4_efgh(abcd, efgh, wk),
        ),
        diff2(
            "vsha256su0q_u32",
            n,
            cfg.seed_for("c/vsha256su0q_u32"),
            a64::vsha256su0q_u32,
            |a: [u32; 4], b: [u32; 4]| {
                let w = [a[0], a[1], a[2], a[3], b[0]];
                core::array::from_fn(|i| w[i].wrapping_add(fips::small_sigma0(w[i + 1])))
            },
        ),
        diff3(
            "vsha256su1q_u32",
            n,
            cfg.seed_for("c/vsha256su1q_u32"),
            a64::vsha256su1q_u32,
            |x: [u32; 4], w8: [u32; 4], w12: [u32; 4]| {
                // W9..W12 and W14, W15; the upper lanes use the freshly computed W16, W17.
                let w16 = x[0]
                    .wrapping_add(w8[1])
                    .wrapping_add(fips::small_sigma1(w12[2]));
                let w17 = x[1]
                    .wrapping_add(w8[2])
                    .wrapping_add(fips::small_sigma1(w12[3]));
                let w18 = x[2]
                    .wrapping_add(w8[3])
                    .wrapping_add(fips::small_sigma1(w16));
                let w19 = x[3]
                    .wrapping_add(w12[0])
                    .wrapping_add(fips::small_sigma1(w17));
                [w16, w17, w18, w19]
            },
        ),
    ]
}

/// The per-model consistency properties for the x86 SHA-NI models.
pub fn x86_models(cfg: &Config) -> Vec<Outcome> {
    let n = cfg.random_per_model;
    let v = x86::view_u32;
    let m = x86::from_u32x4;
    vec![
        diff3(
            "_mm_sha256rnds2_epu32",
            n,
            cfg.seed_for("c/_mm_sha256rnds2_epu32"),
            |a: [u32; 4], b: [u32; 4], k: [u32; 4]| v(x86::_mm_sha256rnds2_epu32(m(a), m(b), m(k))),
            fips_rnds2,
        ),
        diff2(
            "_mm_sha256msg1_epu32",
            n,
            cfg.seed_for("c/_mm_sha256msg1_epu32"),
            |a: [u32; 4], b: [u32; 4]| v(x86::_mm_sha256msg1_epu32(m(a), m(b))),
            |a: [u32; 4], b: [u32; 4]| {
                let w = [a[0], a[1], a[2], a[3], b[0]];
                core::array::from_fn(|i| w[i].wrapping_add(fips::small_sigma0(w[i + 1])))
            },
        ),
        diff2(
            "_mm_sha256msg2_epu32",
            n,
            cfg.seed_for("c/_mm_sha256msg2_epu32"),
            |a: [u32; 4], b: [u32; 4]| v(x86::_mm_sha256msg2_epu32(m(a), m(b))),
            |x: [u32; 4], w12: [u32; 4]| {
                let w16 = x[0].wrapping_add(fips::small_sigma1(w12[2]));
                let w17 = x[1].wrapping_add(fips::small_sigma1(w12[3]));
                let w18 = x[2].wrapping_add(fips::small_sigma1(w16));
                let w19 = x[3].wrapping_add(fips::small_sigma1(w17));
                [w16, w17, w18, w19]
            },
        ),
    ]
}

/// Compositions: schedule groups, round groups, byte-order loads, state
/// packing and whole compressions, for both architectures. `cfg.random_per_model`
/// is the budget of the cheap properties; whole compressions get a tenth.
pub fn compositions(cfg: &Config) -> Vec<Outcome> {
    let n = cfg.random_per_model;
    let n_compress = (n / 10).max(1);
    let v = x86::view_u32;
    let m = x86::from_u32x4;
    vec![
        diff2(
            "sha2_schedule4_vs_fips",
            n,
            cfg.seed_for("sha2_schedule4_vs_fips"),
            |lo: [u32; 8], hi: [u32; 8]| {
                let s = |x: [u32; 8], i: usize| [x[i], x[i + 1], x[i + 2], x[i + 3]];
                let (s0, s1, s2, s3) = (s(lo, 0), s(lo, 4), s(hi, 0), s(hi, 4));
                a64::vsha256su1q_u32(a64::vsha256su0q_u32(s0, s1), s2, s3)
            },
            |lo: [u32; 8], hi: [u32; 8]| {
                let mut w = [0u32; 16];
                w[..8].copy_from_slice(&lo);
                w[8..].copy_from_slice(&hi);
                fips_schedule4(w)
            },
        ),
        diff3(
            "sha2_rounds4_vs_fips",
            n,
            cfg.seed_for("sha2_rounds4_vs_fips"),
            |abcd: [u32; 4], efgh: [u32; 4], wk: [u32; 4]| {
                let abcd_prev = abcd;
                join(
                    a64::vsha256hq_u32(abcd_prev, efgh, wk),
                    a64::vsha256h2q_u32(efgh, abcd_prev, wk),
                )
            },
            |abcd: [u32; 4], efgh: [u32; 4], wk: [u32; 4]| fips_rounds(join(abcd, efgh), &wk),
        ),
        diff1(
            "sha2_be_load_vs_from_be_bytes",
            n,
            cfg.seed_for("sha2_be_load_vs_from_be_bytes"),
            |b: [u8; 16]| a64::vreinterpretq_u32_u8(a64::vrev32q_u8(a64::vld1q_u8(&b))),
            be_words,
        ),
        diff2(
            "shani_schedule4_vs_fips",
            n,
            cfg.seed_for("shani_schedule4_vs_fips"),
            |lo: [u32; 8], hi: [u32; 8]| {
                let s = |x: [u32; 8], i: usize| m([x[i], x[i + 1], x[i + 2], x[i + 3]]);
                v(compress::shani_schedule(
                    s(lo, 0),
                    s(lo, 4),
                    s(hi, 0),
                    s(hi, 4),
                ))
            },
            |lo: [u32; 8], hi: [u32; 8]| {
                let mut w = [0u32; 16];
                w[..8].copy_from_slice(&lo);
                w[8..].copy_from_slice(&hi);
                fips_schedule4(w)
            },
        ),
        diff2(
            "shani_rounds4_vs_fips",
            n,
            cfg.seed_for("shani_rounds4_vs_fips"),
            |s: [u32; 8], w: [u32; 4]| {
                // Group i = 0 of the sha2 crate: t1 = W + K[0..4].
                let (abef, cdgh) = pack_abef_cdgh(s);
                let (abef, cdgh) = compress::shani_rounds4(m(abef), m(cdgh), m(w), 0);
                unpack_abef_cdgh(v(abef), v(cdgh))
            },
            |s: [u32; 8], w: [u32; 4]| {
                let kw: [u32; 4] = core::array::from_fn(|i| w[i].wrapping_add(fips::K[i]));
                fips_rounds(s, &kw)
            },
        ),
        diff1(
            "shani_be_load_vs_from_be_bytes",
            n,
            cfg.seed_for("shani_be_load_vs_from_be_bytes"),
            |b: [u8; 16]| {
                v(x86::_mm_shuffle_epi8(
                    x86::_mm_loadu_si128(&b),
                    compress::shani_bswap_mask(),
                ))
            },
            be_words,
        ),
        diff1(
            "shani_state_packing",
            n,
            cfg.seed_for("shani_state_packing"),
            |s: [u32; 8]| {
                let (abef, cdgh) = compress::shani_pack_state(s);
                (v(abef), v(cdgh), compress::shani_unpack_state(abef, cdgh))
            },
            |s: [u32; 8]| {
                let (abef, cdgh) = pack_abef_cdgh(s);
                (abef, cdgh, s)
            },
        ),
        diff2(
            "compress_sha2_models_vs_fips",
            n_compress,
            cfg.seed_for("compress_sha2_models_vs_fips"),
            |s: [u32; 8], b: [u8; 64]| compress::compress_aarch64_models(s, &b),
            |s: [u32; 8], b: [u8; 64]| fips::compress(s, &b),
        ),
        diff2(
            "compress_shani_models_vs_fips",
            n_compress,
            cfg.seed_for("compress_shani_models_vs_fips"),
            |s: [u32; 8], b: [u8; 64]| compress::compress_x86_models(s, &b),
            |s: [u32; 8], b: [u8; 64]| fips::compress(s, &b),
        ),
    ]
}

/// The reference-consistency campaign of one 256/512-bit x86 model: the
/// executable model against [`crate::reference`] on the diff harness
/// (corner phase, `cfg.random_per_model` random cases, every immediate), or
/// `None` if `name` is not such a model. The outcome is named after the
/// model.
pub fn x86_wide_model(name: &str, cfg: &Config) -> Option<Outcome> {
    use crate::reference as r;
    let n = cfg.random_per_model;
    let s = cfg.seed_for(&format!("ref/{name}"));
    Some(match name {
        "_mm512_loadu_si512" => diff1(name, n, s, |a: [u8; 64]| x86::_mm512_loadu_si512(&a), |a: [u8; 64]| r::_mm512_loadu_si512(&a)),
        "_mm512_storeu_si512" => diff1(name, n, s, x86::_mm512_storeu_si512, r::_mm512_storeu_si512),
        "_mm512_add_epi32" => diff2(name, n, s, x86::_mm512_add_epi32, r::_mm512_add_epi32),
        "_mm512_add_epi64" => diff2(name, n, s, x86::_mm512_add_epi64, r::_mm512_add_epi64),
        "_mm512_sub_epi32" => diff2(name, n, s, x86::_mm512_sub_epi32, r::_mm512_sub_epi32),
        "_mm512_sub_epi64" => diff2(name, n, s, x86::_mm512_sub_epi64, r::_mm512_sub_epi64),
        "_mm512_xor_si512" => diff2(name, n, s, x86::_mm512_xor_si512, r::_mm512_xor_si512),
        "_mm512_and_si512" => diff2(name, n, s, x86::_mm512_and_si512, r::_mm512_and_si512),
        "_mm512_or_si512" => diff2(name, n, s, x86::_mm512_or_si512, r::_mm512_or_si512),
        "_mm512_andnot_si512" => diff2(name, n, s, x86::_mm512_andnot_si512, r::_mm512_andnot_si512),
        "_mm512_ternarylogic_epi32" => diff_imm3(name, 0..=255, n, s, x86::_mm512_ternarylogic_epi32, r::_mm512_ternarylogic_epi32),
        "_mm512_ternarylogic_epi64" => diff_imm3(name, 0..=255, n, s, x86::_mm512_ternarylogic_epi64, r::_mm512_ternarylogic_epi64),
        "_mm512_rol_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm512_rol_epi32, r::_mm512_rol_epi32),
        "_mm512_ror_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm512_ror_epi32, r::_mm512_ror_epi32),
        "_mm512_rol_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm512_rol_epi64, r::_mm512_rol_epi64),
        "_mm512_ror_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm512_ror_epi64, r::_mm512_ror_epi64),
        "_mm512_rolv_epi32" => diff2(name, n, s, x86::_mm512_rolv_epi32, r::_mm512_rolv_epi32),
        "_mm512_rorv_epi32" => diff2(name, n, s, x86::_mm512_rorv_epi32, r::_mm512_rorv_epi32),
        "_mm512_rolv_epi64" => diff2(name, n, s, x86::_mm512_rolv_epi64, r::_mm512_rolv_epi64),
        "_mm512_rorv_epi64" => diff2(name, n, s, x86::_mm512_rorv_epi64, r::_mm512_rorv_epi64),
        "_mm512_slli_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm512_slli_epi32, r::_mm512_slli_epi32),
        "_mm512_srli_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm512_srli_epi32, r::_mm512_srli_epi32),
        "_mm512_slli_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm512_slli_epi64, r::_mm512_slli_epi64),
        "_mm512_srli_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm512_srli_epi64, r::_mm512_srli_epi64),
        "_mm512_sllv_epi64" => diff2(name, n, s, x86::_mm512_sllv_epi64, r::_mm512_sllv_epi64),
        "_mm512_srlv_epi64" => diff2(name, n, s, x86::_mm512_srlv_epi64, r::_mm512_srlv_epi64),
        "_mm512_shuffle_epi8" => diff2(name, n, s, x86::_mm512_shuffle_epi8, r::_mm512_shuffle_epi8),
        "_mm512_permutexvar_epi32" => diff2(name, n, s, x86::_mm512_permutexvar_epi32, r::_mm512_permutexvar_epi32),
        "_mm512_permutexvar_epi64" => diff2(name, n, s, x86::_mm512_permutexvar_epi64, r::_mm512_permutexvar_epi64),
        "_mm512_permutex2var_epi64" => diff3(name, n, s, x86::_mm512_permutex2var_epi64, r::_mm512_permutex2var_epi64),
        "_mm512_shuffle_i32x4" => diff_imm2(name, 0..=255, n, s, x86::_mm512_shuffle_i32x4, r::_mm512_shuffle_i32x4),
        "_mm512_shuffle_i64x2" => diff_imm2(name, 0..=255, n, s, x86::_mm512_shuffle_i64x2, r::_mm512_shuffle_i64x2),
        "_mm512_unpacklo_epi32" => diff2(name, n, s, x86::_mm512_unpacklo_epi32, r::_mm512_unpacklo_epi32),
        "_mm512_unpackhi_epi32" => diff2(name, n, s, x86::_mm512_unpackhi_epi32, r::_mm512_unpackhi_epi32),
        "_mm512_unpacklo_epi64" => diff2(name, n, s, x86::_mm512_unpacklo_epi64, r::_mm512_unpacklo_epi64),
        "_mm512_unpackhi_epi64" => diff2(name, n, s, x86::_mm512_unpackhi_epi64, r::_mm512_unpackhi_epi64),
        "_mm512_set1_epi32" => diff1(name, n, s, x86::_mm512_set1_epi32, r::_mm512_set1_epi32),
        "_mm512_set1_epi64" => diff1(name, n, s, x86::_mm512_set1_epi64, r::_mm512_set1_epi64),
        "_mm512_mask_blend_epi32" => diff3(name, n, s, x86::_mm512_mask_blend_epi32, r::_mm512_mask_blend_epi32),
        "_mm512_mask_blend_epi64" => diff3(name, n, s, x86::_mm512_mask_blend_epi64, r::_mm512_mask_blend_epi64),
        "_mm512_cmplt_epu64_mask" => diff2(name, n, s, x86::_mm512_cmplt_epu64_mask, r::_mm512_cmplt_epu64_mask),
        "_mm512_cmpeq_epi64_mask" => diff2(name, n, s, x86::_mm512_cmpeq_epi64_mask, r::_mm512_cmpeq_epi64_mask),
        "_mm512_cmpeq_epi32_mask" => diff2(name, n, s, x86::_mm512_cmpeq_epi32_mask, r::_mm512_cmpeq_epi32_mask),
        "_mm512_maskz_mov_epi32" => diff2(name, n, s, x86::_mm512_maskz_mov_epi32, r::_mm512_maskz_mov_epi32),
        "_mm512_mask_mov_epi32" => diff3(name, n, s, x86::_mm512_mask_mov_epi32, r::_mm512_mask_mov_epi32),
        "_mm512_maskz_mov_epi64" => diff2(name, n, s, x86::_mm512_maskz_mov_epi64, r::_mm512_maskz_mov_epi64),
        "_mm512_mask_mov_epi64" => diff3(name, n, s, x86::_mm512_mask_mov_epi64, r::_mm512_mask_mov_epi64),
        "_mm512_mullo_epi64" => diff2(name, n, s, x86::_mm512_mullo_epi64, r::_mm512_mullo_epi64),
        "_mm512_mul_epu32" => diff2(name, n, s, x86::_mm512_mul_epu32, r::_mm512_mul_epu32),
        "_mm256_ternarylogic_epi32" => diff_imm3(name, 0..=255, n, s, x86::_mm256_ternarylogic_epi32, r::_mm256_ternarylogic_epi32),
        "_mm256_ternarylogic_epi64" => diff_imm3(name, 0..=255, n, s, x86::_mm256_ternarylogic_epi64, r::_mm256_ternarylogic_epi64),
        "_mm256_rol_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm256_rol_epi32, r::_mm256_rol_epi32),
        "_mm256_ror_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm256_ror_epi32, r::_mm256_ror_epi32),
        "_mm256_rol_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm256_rol_epi64, r::_mm256_rol_epi64),
        "_mm256_ror_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm256_ror_epi64, r::_mm256_ror_epi64),
        "_mm512_madd52lo_epu64" => diff3(name, n, s, x86::_mm512_madd52lo_epu64, r::_mm512_madd52lo_epu64),
        "_mm512_madd52hi_epu64" => diff3(name, n, s, x86::_mm512_madd52hi_epu64, r::_mm512_madd52hi_epu64),
        "_mm256_madd52lo_epu64" => diff3(name, n, s, x86::_mm256_madd52lo_epu64, r::_mm256_madd52lo_epu64),
        "_mm256_madd52hi_epu64" => diff3(name, n, s, x86::_mm256_madd52hi_epu64, r::_mm256_madd52hi_epu64),
        "_mm512_gf2p8mul_epi8" => diff2(name, n, s, x86::_mm512_gf2p8mul_epi8, r::_mm512_gf2p8mul_epi8),
        "_mm256_gf2p8mul_epi8" => diff2(name, n, s, x86::_mm256_gf2p8mul_epi8, r::_mm256_gf2p8mul_epi8),
        "_mm_gf2p8mul_epi8" => diff2(name, n, s, x86::_mm_gf2p8mul_epi8, r::_mm_gf2p8mul_epi8),
        "_mm512_gf2p8affine_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm512_gf2p8affine_epi64_epi8, r::_mm512_gf2p8affine_epi64_epi8),
        "_mm256_gf2p8affine_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm256_gf2p8affine_epi64_epi8, r::_mm256_gf2p8affine_epi64_epi8),
        "_mm_gf2p8affine_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm_gf2p8affine_epi64_epi8, r::_mm_gf2p8affine_epi64_epi8),
        "_mm512_gf2p8affineinv_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm512_gf2p8affineinv_epi64_epi8, r::_mm512_gf2p8affineinv_epi64_epi8),
        "_mm256_gf2p8affineinv_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm256_gf2p8affineinv_epi64_epi8, r::_mm256_gf2p8affineinv_epi64_epi8),
        "_mm_gf2p8affineinv_epi64_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm_gf2p8affineinv_epi64_epi8, r::_mm_gf2p8affineinv_epi64_epi8),
        "_mm512_permutexvar_epi8" => diff2(name, n, s, x86::_mm512_permutexvar_epi8, r::_mm512_permutexvar_epi8),
        "_mm512_permutex2var_epi8" => diff3(name, n, s, x86::_mm512_permutex2var_epi8, r::_mm512_permutex2var_epi8),
        "_mm512_multishift_epi64_epi8" => diff2(name, n, s, x86::_mm512_multishift_epi64_epi8, r::_mm512_multishift_epi64_epi8),
        "_mm512_shldv_epi64" => diff3(name, n, s, x86::_mm512_shldv_epi64, r::_mm512_shldv_epi64),
        "_mm512_shrdv_epi64" => diff3(name, n, s, x86::_mm512_shrdv_epi64, r::_mm512_shrdv_epi64),
        "_mm512_shldv_epi32" => diff3(name, n, s, x86::_mm512_shldv_epi32, r::_mm512_shldv_epi32),
        "_mm512_shrdv_epi32" => diff3(name, n, s, x86::_mm512_shrdv_epi32, r::_mm512_shrdv_epi32),
        "_mm512_shldi_epi64" => diff_imm2(name, 0..=255, n, s, x86::_mm512_shldi_epi64, r::_mm512_shldi_epi64),
        "_mm512_shldi_epi32" => diff_imm2(name, 0..=255, n, s, x86::_mm512_shldi_epi32, r::_mm512_shldi_epi32),
        "_mm512_popcnt_epi64" => diff1(name, n, s, x86::_mm512_popcnt_epi64, r::_mm512_popcnt_epi64),
        "_mm512_popcnt_epi32" => diff1(name, n, s, x86::_mm512_popcnt_epi32, r::_mm512_popcnt_epi32),
        "_mm512_popcnt_epi8" => diff1(name, n, s, x86::_mm512_popcnt_epi8, r::_mm512_popcnt_epi8),
        "_mm512_popcnt_epi16" => diff1(name, n, s, x86::_mm512_popcnt_epi16, r::_mm512_popcnt_epi16),
        "_mm256_loadu_si256" => diff1(name, n, s, |a: [u8; 32]| x86::_mm256_loadu_si256(&a), |a: [u8; 32]| r::_mm256_loadu_si256(&a)),
        "_mm256_storeu_si256" => diff1(name, n, s, x86::_mm256_storeu_si256, r::_mm256_storeu_si256),
        "_mm256_add_epi32" => diff2(name, n, s, x86::_mm256_add_epi32, r::_mm256_add_epi32),
        "_mm256_add_epi64" => diff2(name, n, s, x86::_mm256_add_epi64, r::_mm256_add_epi64),
        "_mm256_xor_si256" => diff2(name, n, s, x86::_mm256_xor_si256, r::_mm256_xor_si256),
        "_mm256_and_si256" => diff2(name, n, s, x86::_mm256_and_si256, r::_mm256_and_si256),
        "_mm256_or_si256" => diff2(name, n, s, x86::_mm256_or_si256, r::_mm256_or_si256),
        "_mm256_shuffle_epi8" => diff2(name, n, s, x86::_mm256_shuffle_epi8, r::_mm256_shuffle_epi8),
        "_mm256_permutevar8x32_epi32" => diff2(name, n, s, x86::_mm256_permutevar8x32_epi32, r::_mm256_permutevar8x32_epi32),
        "_mm256_slli_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm256_slli_epi32, r::_mm256_slli_epi32),
        "_mm256_srli_epi32" => diff_imm1(name, 0..=255, n, s, x86::_mm256_srli_epi32, r::_mm256_srli_epi32),
        "_mm256_slli_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm256_slli_epi64, r::_mm256_slli_epi64),
        "_mm256_srli_epi64" => diff_imm1(name, 0..=255, n, s, x86::_mm256_srli_epi64, r::_mm256_srli_epi64),
        "_mm256_blend_epi32" => diff_imm2(name, 0..=255, n, s, x86::_mm256_blend_epi32, r::_mm256_blend_epi32),
        "_mm256_alignr_epi8" => diff_imm2(name, 0..=255, n, s, x86::_mm256_alignr_epi8, r::_mm256_alignr_epi8),
        "_mm256_set1_epi32" => diff1(name, n, s, x86::_mm256_set1_epi32, r::_mm256_set1_epi32),
        "_mm256_set1_epi64x" => diff1(name, n, s, x86::_mm256_set1_epi64x, r::_mm256_set1_epi64x),

        _ => return None,
    })
}

/// [`x86_wide_model`] for every 256/512-bit x86 model, in registry order, in
/// parallel.
pub fn x86_wide_models(cfg: &Config) -> Vec<Outcome> {
    crate::hw::run_parallel(crate::reference::NAMES, |name| {
        x86_wide_model(name, cfg).unwrap_or_else(|| panic!("no reference campaign for {name}"))
    })
}

/// Every consistency property (per-model and compositions).
pub fn run_all(cfg: &Config) -> Vec<Outcome> {
    let mut v = aarch64_models(cfg);
    v.extend(x86_models(cfg));
    v.extend(x86_wide_models(cfg));
    v.extend(compositions(cfg));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packing_is_a_bijection() {
        let s = [10, 11, 12, 13, 14, 15, 16, 17];
        let (abef, cdgh) = pack_abef_cdgh(s);
        assert_eq!(abef, [15, 14, 11, 10]);
        assert_eq!(cdgh, [17, 16, 13, 12]);
        assert_eq!(unpack_abef_cdgh(abef, cdgh), s);
    }

    #[test]
    fn fips_schedule4_matches_full_schedule() {
        let block: [u8; 64] = core::array::from_fn(|i| (i * 31 + 7) as u8);
        let w = fips::schedule(&block);
        let mut first = [0u32; 16];
        first.copy_from_slice(&w[..16]);
        assert_eq!(fips_schedule4(first), [w[16], w[17], w[18], w[19]]);
    }
}
