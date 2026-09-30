//! Real x86_64 SSE2/SSSE3/SSE4.1 and SHA-NI intrinsics on the model
//! representation, the SHA-NI compression built from them, and the
//! differential campaigns (DESIGN.md §9.2 "Validation").
//!
//! On this machine x86_64 code runs under Rosetta 2 (`sysctl.proc_translated`
//! = 1), which provides SSE up to 4.2, AES and PCLMUL but **no SHA-NI** and no
//! AVX. Features are detected at run time; campaigns whose features are
//! absent are skipped with the reason. SHA-NI models therefore get only the
//! portable FIPS 180-4 consistency checks of [`crate::consistency`] here, and
//! their evidence is `pending-hardware` until the evidence binary runs on a
//! CPU with SHA-NI (x86 CI: Ice Lake / Zen or later).
//!
//! Every wrapper has the signature of the model of the same name in
//! [`crate::x86_64`] (`__m128i` as `[u8; 16]`, byte 0 = bits 7:0).

//!
//! # Safety
//!
//! The wrappers are safe `#[target_feature]` functions: calling one from code
//! without the feature enabled is `unsafe`, and the caller must ensure the
//! running CPU has the feature (`run_model` checks with run-time detection
//! before every call). Clippy's `missing_safety_doc` is allowed for that
//! reason: this section is the safety documentation of every wrapper.
#![allow(clippy::missing_safety_doc)]

use crate::diff::{self, Config, Outcome};
use crate::registry::{self, Arch};
use crate::x86_64 as model;
use core::arch::x86_64 as arch;
use core::arch::x86_64::__m128i;
use core::mem::transmute;

use super::imm8_table;

// SAFETY (both conversions): `__m128i` and `[u8; 16]` have the same size,
// every bit pattern is valid for both, and byte i of the memory image is bits
// 8i+7:8i (little-endian), the §9.2 representation.
#[inline(always)]
fn m(a: [u8; 16]) -> __m128i {
    unsafe { transmute(a) }
}
#[inline(always)]
fn b(v: __m128i) -> [u8; 16] {
    unsafe { transmute(v) }
}

/// Byte written around stores to detect writes outside the stored bytes.
const SENTINEL: u8 = 0xa5;

/// `_mm_loadu_si128` reading the 16 bytes of `mem`.
#[target_feature(enable = "sse2")]
pub fn _mm_loadu_si128(mem: &[u8; 16]) -> [u8; 16] {
    // SAFETY: `mem` is valid for reading 16 bytes; MOVDQU has no alignment requirement.
    b(unsafe { arch::_mm_loadu_si128(mem.as_ptr().cast()) })
}

/// `_mm_storeu_si128` into an unaligned slot of a sentinel-filled buffer;
/// returns the 16 bytes written and panics if any byte outside them changed.
#[target_feature(enable = "sse2")]
pub fn _mm_storeu_si128(a: [u8; 16]) -> [u8; 16] {
    let mut buf = [SENTINEL; 48];
    // SAFETY: `buf[17..33]` is in bounds and writable; MOVDQU has no alignment requirement.
    unsafe { arch::_mm_storeu_si128(buf.as_mut_ptr().add(17).cast(), m(a)) };
    assert!(
        buf[..17].iter().chain(&buf[33..]).all(|&x| x == SENTINEL),
        "_mm_storeu_si128 wrote outside its 16 bytes"
    );
    buf[17..33].try_into().expect("16 bytes")
}

/// `_mm_shuffle_epi8` (SSSE3).
#[target_feature(enable = "ssse3")]
pub fn _mm_shuffle_epi8(a: [u8; 16], mask: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_shuffle_epi8(m(a), m(mask)))
}

/// `_mm_add_epi32`.
#[target_feature(enable = "sse2")]
pub fn _mm_add_epi32(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_add_epi32(m(x), m(y)))
}

/// `_mm_set_epi32(e3, e2, e1, e0)`.
#[target_feature(enable = "sse2")]
pub fn _mm_set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> [u8; 16] {
    b(arch::_mm_set_epi32(e3, e2, e1, e0))
}

/// `_mm_set_epi64x(e1, e0)`.
#[target_feature(enable = "sse2")]
pub fn _mm_set_epi64x(e1: i64, e0: i64) -> [u8; 16] {
    b(arch::_mm_set_epi64x(e1, e0))
}

/// `_mm_xor_si128`.
#[target_feature(enable = "sse2")]
pub fn _mm_xor_si128(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_xor_si128(m(x), m(y)))
}

/// `_mm_and_si128`.
#[target_feature(enable = "sse2")]
pub fn _mm_and_si128(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_and_si128(m(x), m(y)))
}

/// `_mm_or_si128`.
#[target_feature(enable = "sse2")]
pub fn _mm_or_si128(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_or_si128(m(x), m(y)))
}

// ---------------------------------------------------------------------------
// imm8 forms: 256 monomorphizations each, dispatched by table.

type Unary = unsafe fn([u8; 16]) -> [u8; 16];
type Binary = unsafe fn([u8; 16], [u8; 16]) -> [u8; 16];

#[target_feature(enable = "sse2")]
fn shuffle_epi32<const IMM: i32>(a: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_shuffle_epi32::<IMM>(m(a)))
}
#[target_feature(enable = "ssse3")]
fn alignr_epi8<const IMM: i32>(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_alignr_epi8::<IMM>(m(x), m(y)))
}
#[target_feature(enable = "sse4.1")]
fn blend_epi16<const IMM: i32>(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_blend_epi16::<IMM>(m(x), m(y)))
}

fn shuffle_epi32_table() -> &'static [Unary; 256] {
    static T: std::sync::OnceLock<[Unary; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| imm8_table!(shuffle_epi32, Unary))
}
fn alignr_epi8_table() -> &'static [Binary; 256] {
    static T: std::sync::OnceLock<[Binary; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| imm8_table!(alignr_epi8, Binary))
}
fn blend_epi16_table() -> &'static [Binary; 256] {
    static T: std::sync::OnceLock<[Binary; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| imm8_table!(blend_epi16, Binary))
}

fn imm8(imm: i32, what: &str) -> usize {
    usize::try_from(imm)
        .ok()
        .filter(|&i| i < 256)
        .unwrap_or_else(|| panic!("{what}: immediate {imm} out of range"))
}

/// `_mm_shuffle_epi32::<IMM8>` with `IMM8` as an argument.
#[target_feature(enable = "sse2")]
pub fn _mm_shuffle_epi32(a: [u8; 16], imm8_: i32) -> [u8; 16] {
    // SAFETY: the table entries require `sse2`, which this function has.
    unsafe { shuffle_epi32_table()[imm8(imm8_, "_mm_shuffle_epi32")](a) }
}

/// `_mm_alignr_epi8::<IMM8>` with `IMM8` as an argument.
#[target_feature(enable = "ssse3")]
pub fn _mm_alignr_epi8(x: [u8; 16], y: [u8; 16], imm8_: i32) -> [u8; 16] {
    // SAFETY: the table entries require `ssse3`, which this function has.
    unsafe { alignr_epi8_table()[imm8(imm8_, "_mm_alignr_epi8")](x, y) }
}

/// `_mm_blend_epi16::<IMM8>` with `IMM8` as an argument.
#[target_feature(enable = "sse4.1")]
pub fn _mm_blend_epi16(x: [u8; 16], y: [u8; 16], imm8_: i32) -> [u8; 16] {
    // SAFETY: the table entries require `sse4.1`, which this function has.
    unsafe { blend_epi16_table()[imm8(imm8_, "_mm_blend_epi16")](x, y) }
}

// ---------------------------------------------------------------------------
// SHA-NI

/// `_mm_sha256rnds2_epu32(a, b, k)`.
#[target_feature(enable = "sha")]
pub fn _mm_sha256rnds2_epu32(x: [u8; 16], y: [u8; 16], k: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_sha256rnds2_epu32(m(x), m(y), m(k)))
}

/// `_mm_sha256msg1_epu32(a, b)`.
#[target_feature(enable = "sha")]
pub fn _mm_sha256msg1_epu32(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_sha256msg1_epu32(m(x), m(y)))
}

/// `_mm_sha256msg2_epu32(a, b)`.
#[target_feature(enable = "sha")]
pub fn _mm_sha256msg2_epu32(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    b(arch::_mm_sha256msg2_epu32(m(x), m(y)))
}

/// SHA-256 compression of one block with the real SHA-NI intrinsics,
/// statement for statement the `sha2` crate's `x86_sha::compress` (one block).
/// Compiled everywhere, executed only where `sha` is detected.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub fn compress_shani(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    use crate::compress::K32X4;
    let mask = arch::_mm_set_epi64x(
        0x0C0D_0E0F_0809_0A0Bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );
    // SAFETY (loads/stores below): every pointer is to 16 in-bounds bytes of
    // `state`, `block` or `out`; MOVDQU has no alignment requirement.
    let state_ptr: *const __m128i = state.as_ptr().cast();
    let dcba = unsafe { arch::_mm_loadu_si128(state_ptr) };
    let hgfe = unsafe { arch::_mm_loadu_si128(state_ptr.add(1)) };
    let cdab = arch::_mm_shuffle_epi32(dcba, 0xB1);
    let efgh = arch::_mm_shuffle_epi32(hgfe, 0x1B);
    let mut abef = arch::_mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = arch::_mm_blend_epi16(efgh, cdab, 0xF0);
    let abef_save = abef;
    let cdgh_save = cdgh;

    let block_ptr: *const __m128i = block.as_ptr().cast();
    let load =
        |i: usize| arch::_mm_shuffle_epi8(unsafe { arch::_mm_loadu_si128(block_ptr.add(i)) }, mask);
    let mut w0 = load(0);
    let mut w1 = load(1);
    let mut w2 = load(2);
    let mut w3 = load(3);
    let mut w4;

    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
            let t1 = arch::_mm_sha256msg1_epu32($v0, $v1);
            let t2 = arch::_mm_alignr_epi8($v3, $v2, 4);
            let t3 = arch::_mm_add_epi32(t1, t2);
            arch::_mm_sha256msg2_epu32(t3, $v3)
        }};
    }
    macro_rules! rounds4 {
        ($rest:expr, $i:expr) => {{
            let k = K32X4[$i];
            let kv = arch::_mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
            let t1 = arch::_mm_add_epi32($rest, kv);
            cdgh = arch::_mm_sha256rnds2_epu32(cdgh, abef, t1);
            let t2 = arch::_mm_shuffle_epi32(t1, 0x0E);
            abef = arch::_mm_sha256rnds2_epu32(abef, cdgh, t2);
        }};
    }
    macro_rules! schedule_rounds4 {
        ($w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr, $i:expr) => {{
            $w4 = schedule!($w0, $w1, $w2, $w3);
            rounds4!($w4, $i);
        }};
    }

    rounds4!(w0, 0);
    rounds4!(w1, 1);
    rounds4!(w2, 2);
    rounds4!(w3, 3);
    schedule_rounds4!(w0, w1, w2, w3, w4, 4);
    schedule_rounds4!(w1, w2, w3, w4, w0, 5);
    schedule_rounds4!(w2, w3, w4, w0, w1, 6);
    schedule_rounds4!(w3, w4, w0, w1, w2, 7);
    schedule_rounds4!(w4, w0, w1, w2, w3, 8);
    schedule_rounds4!(w0, w1, w2, w3, w4, 9);
    schedule_rounds4!(w1, w2, w3, w4, w0, 10);
    schedule_rounds4!(w2, w3, w4, w0, w1, 11);
    schedule_rounds4!(w3, w4, w0, w1, w2, 12);
    schedule_rounds4!(w4, w0, w1, w2, w3, 13);
    schedule_rounds4!(w0, w1, w2, w3, w4, 14);
    schedule_rounds4!(w1, w2, w3, w4, w0, 15);

    abef = arch::_mm_add_epi32(abef, abef_save);
    cdgh = arch::_mm_add_epi32(cdgh, cdgh_save);

    let feba = arch::_mm_shuffle_epi32(abef, 0x1B);
    let dchg = arch::_mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = arch::_mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = arch::_mm_alignr_epi8(dchg, feba, 8);
    let mut out = [0u32; 8];
    let out_ptr: *mut __m128i = out.as_mut_ptr().cast();
    unsafe {
        arch::_mm_storeu_si128(out_ptr, dcba);
        arch::_mm_storeu_si128(out_ptr.add(1), hgef);
    }
    out
}

// ---------------------------------------------------------------------------
// Campaigns

/// Whether the running CPU has target feature `f` (the names used in the
/// registry, including every feature of the 256/512-bit models; an unknown
/// name is `false`, so its models are skipped, fail closed).
pub fn feature_detected(f: &str) -> bool {
    match f {
        "sse2" => std::arch::is_x86_feature_detected!("sse2"),
        "ssse3" => std::arch::is_x86_feature_detected!("ssse3"),
        "sse4.1" => std::arch::is_x86_feature_detected!("sse4.1"),
        "sse4.2" => std::arch::is_x86_feature_detected!("sse4.2"),
        "sha" => std::arch::is_x86_feature_detected!("sha"),
        "aes" => std::arch::is_x86_feature_detected!("aes"),
        "pclmulqdq" => std::arch::is_x86_feature_detected!("pclmulqdq"),
        "avx" => std::arch::is_x86_feature_detected!("avx"),
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        "avx512f" => std::arch::is_x86_feature_detected!("avx512f"),
        "avx512bw" => std::arch::is_x86_feature_detected!("avx512bw"),
        "avx512vl" => std::arch::is_x86_feature_detected!("avx512vl"),
        "avx512dq" => std::arch::is_x86_feature_detected!("avx512dq"),
        "avx512cd" => std::arch::is_x86_feature_detected!("avx512cd"),
        "avx512ifma" => std::arch::is_x86_feature_detected!("avx512ifma"),
        "avx512vbmi" => std::arch::is_x86_feature_detected!("avx512vbmi"),
        "avx512vbmi2" => std::arch::is_x86_feature_detected!("avx512vbmi2"),
        "avx512vpopcntdq" => std::arch::is_x86_feature_detected!("avx512vpopcntdq"),
        "avx512bitalg" => std::arch::is_x86_feature_detected!("avx512bitalg"),
        "gfni" => std::arch::is_x86_feature_detected!("gfni"),
        "vaes" => std::arch::is_x86_feature_detected!("vaes"),
        "vpclmulqdq" => std::arch::is_x86_feature_detected!("vpclmulqdq"),
        "bmi1" => std::arch::is_x86_feature_detected!("bmi1"),
        "bmi2" => std::arch::is_x86_feature_detected!("bmi2"),
        "lzcnt" => std::arch::is_x86_feature_detected!("lzcnt"),
        "popcnt" => std::arch::is_x86_feature_detected!("popcnt"),
        _ => false,
    }
}

/// Run-time feature detection results recorded in the evidence.
pub fn detected_features() -> Vec<(String, bool)> {
    [
        "sse2",
        "ssse3",
        "sse4.1",
        "sse4.2",
        "aes",
        "pclmulqdq",
        "sha",
        "avx",
        "avx2",
        "avx512f",
        "avx512bw",
        "avx512vl",
        "avx512dq",
        "avx512cd",
        "avx512ifma",
        "avx512vbmi",
        "avx512vbmi2",
        "avx512vpopcntdq",
        "avx512bitalg",
        "gfni",
        "vaes",
        "vpclmulqdq",
    ]
    .iter()
    .map(|f| (f.to_string(), feature_detected(f)))
    .collect()
}

/// The explanation recorded when SHA-NI is absent.
pub const SHA_NI_ABSENT: &str = "CPU lacks `sha` (SHA-NI; Rosetta 2 does not provide it): hardware validation pending, \
     FIPS 180-4 consistency checked instead (consistency::x86_models)";

/// The differential campaign of one model against its intrinsic, or `None`
/// if `name` is not an x86_64 model. Skipped (with the reason) if the CPU
/// lacks a required feature.
pub fn run_model(name: &str, cfg: &Config) -> Option<Outcome> {
    let md = registry::find(Arch::X86_64, name)?;
    if let Some(f) = md.features.iter().find(|f| !feature_detected(f)) {
        let reason = if *f == "sha" {
            SHA_NI_ABSENT.to_string()
        } else {
            format!("CPU lacks `{f}`")
        };
        return Some(Outcome::skipped(name, reason));
    }
    let n = cfg.random_per_model;
    let s = cfg.seed_for(name);
    let imms = || md.immediates.clone().expect("immediate model");
    // SAFETY (every `unsafe` block below): it calls a `#[target_feature]`
    // wrapper whose features were detected on this CPU just above.
    let o = match name {
        "_mm_loadu_si128" => diff::diff1(
            name,
            n,
            s,
            |a: [u8; 16]| model::_mm_loadu_si128(&a),
            |a: [u8; 16]| unsafe { _mm_loadu_si128(&a) },
        ),
        "_mm_storeu_si128" => diff::diff1(name, n, s, model::_mm_storeu_si128, |a| unsafe {
            _mm_storeu_si128(a)
        }),
        "_mm_shuffle_epi8" => diff::diff2(name, n, s, model::_mm_shuffle_epi8, |a, c| unsafe {
            _mm_shuffle_epi8(a, c)
        }),
        "_mm_shuffle_epi32" => diff::diff_imm1(
            name,
            imms(),
            n,
            s,
            model::_mm_shuffle_epi32,
            |a, i| unsafe { _mm_shuffle_epi32(a, i) },
        ),
        "_mm_alignr_epi8" => diff::diff_imm2(
            name,
            imms(),
            n,
            s,
            model::_mm_alignr_epi8,
            |x, y, i| unsafe { _mm_alignr_epi8(x, y, i) },
        ),
        "_mm_blend_epi16" => diff::diff_imm2(
            name,
            imms(),
            n,
            s,
            model::_mm_blend_epi16,
            |x, y, i| unsafe { _mm_blend_epi16(x, y, i) },
        ),
        "_mm_add_epi32" => diff::diff2(name, n, s, model::_mm_add_epi32, |x, y| unsafe {
            _mm_add_epi32(x, y)
        }),
        "_mm_set_epi32" => diff::diff4(name, n, s, model::_mm_set_epi32, |e3, e2, e1, e0| unsafe {
            _mm_set_epi32(e3, e2, e1, e0)
        }),
        "_mm_set_epi64x" => diff::diff2(name, n, s, model::_mm_set_epi64x, |e1, e0| unsafe {
            _mm_set_epi64x(e1, e0)
        }),
        "_mm_xor_si128" => diff::diff2(name, n, s, model::_mm_xor_si128, |x, y| unsafe {
            _mm_xor_si128(x, y)
        }),
        "_mm_and_si128" => diff::diff2(name, n, s, model::_mm_and_si128, |x, y| unsafe {
            _mm_and_si128(x, y)
        }),
        "_mm_or_si128" => diff::diff2(name, n, s, model::_mm_or_si128, |x, y| unsafe {
            _mm_or_si128(x, y)
        }),
        "_mm_sha256rnds2_epu32" => {
            diff::diff3(name, n, s, model::_mm_sha256rnds2_epu32, |x, y, k| unsafe {
                _mm_sha256rnds2_epu32(x, y, k)
            })
        }
        "_mm_sha256msg1_epu32" => {
            diff::diff2(name, n, s, model::_mm_sha256msg1_epu32, |x, y| unsafe {
                _mm_sha256msg1_epu32(x, y)
            })
        }
        "_mm_sha256msg2_epu32" => {
            diff::diff2(name, n, s, model::_mm_sha256msg2_epu32, |x, y| unsafe {
                _mm_sha256msg2_epu32(x, y)
            })
        }
        // The 256/512-bit families (features detected above).
        _ => return super::x86_64_wide::campaign(name, n, s, md.immediates.clone()),
    };
    Some(o)
}

/// Every model's campaign, in registry order, run in parallel.
pub fn run_all(cfg: &Config) -> Vec<Outcome> {
    let names: Vec<&str> = registry::X86_64.iter().map(|md| md.name).collect();
    super::run_parallel(&names, |name| {
        run_model(name, cfg).unwrap_or_else(|| panic!("no campaign for model {name}"))
    })
}

/// Whole-kernel hardware checks: the SHA-NI compression from the real
/// intrinsics against FIPS 180-4 and the model compression (skipped without
/// SHA-NI).
pub fn run_compositions(cfg: &Config) -> Vec<Outcome> {
    let n = (cfg.random_per_model / 10).max(1);
    if !["sha", "sse2", "ssse3", "sse4.1"]
        .iter()
        .all(|f| feature_detected(f))
    {
        return vec![
            Outcome::skipped("compress_shani_intrinsics_vs_fips", SHA_NI_ABSENT),
            Outcome::skipped("compress_shani_intrinsics_vs_models", SHA_NI_ABSENT),
        ];
    }
    // SAFETY: `sha,sse2,ssse3,sse4.1` were detected just above.
    vec![
        diff::diff2(
            "compress_shani_intrinsics_vs_fips",
            n,
            cfg.seed_for("compress_shani_intrinsics_vs_fips"),
            |st: [u32; 8], blk: [u8; 64]| unsafe { compress_shani(st, &blk) },
            |st: [u32; 8], blk: [u8; 64]| crate::fips::compress(st, &blk),
        ),
        diff::diff2(
            "compress_shani_intrinsics_vs_models",
            n,
            cfg.seed_for("compress_shani_intrinsics_vs_models"),
            |st: [u32; 8], blk: [u8; 64]| unsafe { compress_shani(st, &blk) },
            |st: [u32; 8], blk: [u8; 64]| crate::compress::compress_x86_models(st, &blk),
        ),
    ]
}
