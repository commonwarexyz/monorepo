//! SIMD code verified as written (capability C8, first slice;
//! `docs/mir-lift.md` §20.9, DESIGN.md §16.4): the verifier reads safe
//! `core::arch` code from rustc's MIR onto the retained, validated target
//! models, in both readings — the structured reading S (the subset's
//! `core::arch` calls, which the front end elaborates to the models) and
//! the literal reading L (each intrinsic call a leaf: its model's global,
//! pinned to a model with native validation evidence).
//!
//! * `mir_fixtures/sd_neon`: sixteen bytes through nibble tables with NEON,
//!   the shape of Reed–Solomon's NEON `mul_128` on one vector, built only
//!   from value intrinsics (`vdupq_n_u8`, `vandq_u8`, `vqtbl1q_u8`,
//!   `vshrq_n_u8::<4>`, `veorq_u8`) in `#[target_feature(enable = "neon")]`
//!   functions, one of them calling another, and a feature detection that
//!   the target enables statically. Verified in place against scalar
//!   reference laws (`tbl`, `mul_byte`: what a scalar engine computes per
//!   byte), with every MIR theorem kernel-checked, the models pinned in the
//!   lock (`target-model:` items: source, core and evidence hashes, the
//!   fail-closed verdict), and the lift conformance check running the NEON
//!   code natively against the kernel's evaluation of both readings.
//! * negative twins: a wrong shift (`vshrq_n_u8::<3>`) and the wrong lanes
//!   (TBL's table and indices swapped) are refused by the laws, with the
//!   same laws and proofs; a load through a raw pointer (`vld1q_u8`) is
//!   refused with the load named; an intrinsic without a validated model
//!   (`vaddq_u8`) is refused by both readings; a runtime feature detection
//!   (`sm4`, not enabled statically) is refused; MIR of another
//!   architecture is refused at its load.
//! * fault injection: an intrinsic call's immediate, its path or the order
//!   of its arguments changed in the MIR the literal reading reads (the
//!   structured reading unchanged) breaks exactly the theorem of the
//!   function that makes the call.
//! * `mir_fixtures/sd_x86`: the SSSE3 counterpart (PSHUFB,
//!   `_mm_shuffle_epi8`, with `_mm_and_si128` and `_mm_xor_si128`),
//!   extracted for `x86_64-apple-darwin` and read onto the x86 models; its
//!   gates and MIR theorems pass for an x86_64 build (the lift conformance
//!   check, which runs the code natively, runs on x86 hosts only). Its laws
//!   are proven by the lane closer (`auto::lanes`, C8's second slice): each
//!   lane split on bit 7 of its index byte, with no lemma of 256 cases.
//! * `mir_fixtures/sd_neon_mul128`: Reed–Solomon's NEON `mul_128` and
//!   `muladd_128` as the engine writes them (an `#[inline(always)]` helper
//!   whose value intrinsics need `unsafe`; the eight table rows loaded
//!   through raw pointers formed from shared references), their rows byte
//!   arrays where the engine's are `u128`: verified in place, lane by lane,
//!   against the scalar reference (each element's product bytes through the
//!   split nibble tables) by the lane closer, with native conformance; its
//!   twins (a shift by 3, two rows swapped) refused by the same laws.

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sandblaster_front::driver::{self, BuildOutcome, Checked, LockUse};
use sandblaster_front::lift::LiftFacts;
use sandblaster_front::loader::MemFs;
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir::{self, Callee, Term};
use sandblaster_front::target::TargetInfo;

/// A host file and rustc's MIR of it (`mir_fixtures/extract.py`).
type Code = (&'static str, &'static str);
const NEON: Code = (include_str!("mir_fixtures/sd_neon/src/a.rs"), include_str!("mir_fixtures/sd_neon/a.sbmir"));
const WRONG_SHIFT: Code = (include_str!("mir_fixtures/sd_neon_shift/src/a.rs"), include_str!("mir_fixtures/sd_neon_shift/a.sbmir"));
const WRONG_LANES: Code = (include_str!("mir_fixtures/sd_neon_lane/src/a.rs"), include_str!("mir_fixtures/sd_neon_lane/a.sbmir"));
const POINTER: Code = (include_str!("mir_fixtures/sd_neon_ptr/src/a.rs"), include_str!("mir_fixtures/sd_neon_ptr/a.sbmir"));
const NO_MODEL: Code = (include_str!("mir_fixtures/sd_neon_nomodel/src/a.rs"), include_str!("mir_fixtures/sd_neon_nomodel/a.sbmir"));
const DETECT: Code = (include_str!("mir_fixtures/sd_neon_detect/src/a.rs"), include_str!("mir_fixtures/sd_neon_detect/a.sbmir"));
const X86: Code = (include_str!("mir_fixtures/sd_x86/src/a.rs"), include_str!("mir_fixtures/sd_x86/a.sbmir"));

/// The NEON functions (the twins have the same).
const NEON_FNS: &str = "mul_nibbles, lookup, mul_twice, has_neon";

const NEON_LAWS: &str = r#"//! What the NEON nibble functions compute: lane by lane, the scalar
//! references below (what a scalar engine computes per byte).
use sandblaster::prelude::*;
use core::arch::aarch64::*;
use crate::a::{mul_nibbles, lookup, mul_twice, has_neon};

/// A table lookup of one byte: `t[k]`, or 0 past the table (the scalar
/// meaning of TBL, and of a bounds-checked lookup).
#[spec]
#[example(tbl([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 3u8) == 13u8)]
#[example(tbl([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 16u8) == 0u8)]
pub fn tbl(t: [u8; 16], k: u8) -> u8 {
    if k < 16u8 { t[k as usize] } else { 0u8 }
}

/// Each byte of `idx` looked up in `t`, lane 0 first.
#[spec]
#[example(tbl_lanes([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]) == [10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 0])]
pub fn tbl_lanes(t: [u8; 16], idx: [u8; 16]) -> [u8; 16] {
    [tbl(t, idx[0]), tbl(t, idx[1]), tbl(t, idx[2]), tbl(t, idx[3]),
     tbl(t, idx[4]), tbl(t, idx[5]), tbl(t, idx[6]), tbl(t, idx[7]),
     tbl(t, idx[8]), tbl(t, idx[9]), tbl(t, idx[10]), tbl(t, idx[11]),
     tbl(t, idx[12]), tbl(t, idx[13]), tbl(t, idx[14]), tbl(t, idx[15])]
}

/// One byte through the nibble tables: its low nibble looked up in `lo`,
/// its high nibble in `hi`, the two combined by xor.
#[spec]
#[example(mul_byte(0x21u8, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == 0x21u8)]
#[example(mul_byte(0xffu8, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 7], [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]) == 4u8)]
pub fn mul_byte(b: u8, lo: [u8; 16], hi: [u8; 16]) -> u8 {
    tbl(lo, b & 15u8) ^ tbl(hi, b >> 4u32)
}

/// `mul_byte` in every lane, lane 0 first.
#[spec]
#[example(mul_lanes([0x21u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == [0x21u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff])]
pub fn mul_lanes(x: [u8; 16], lo: [u8; 16], hi: [u8; 16]) -> [u8; 16] {
    [mul_byte(x[0], lo, hi), mul_byte(x[1], lo, hi), mul_byte(x[2], lo, hi), mul_byte(x[3], lo, hi),
     mul_byte(x[4], lo, hi), mul_byte(x[5], lo, hi), mul_byte(x[6], lo, hi), mul_byte(x[7], lo, hi),
     mul_byte(x[8], lo, hi), mul_byte(x[9], lo, hi), mul_byte(x[10], lo, hi), mul_byte(x[11], lo, hi),
     mul_byte(x[12], lo, hi), mul_byte(x[13], lo, hi), mul_byte(x[14], lo, hi), mul_byte(x[15], lo, hi)]
}

/// `mul_nibbles` is the scalar reference in every lane (a vector is the
/// array of its lanes, lane 0 first).
#[law]
fn mul_nibbles_is_the_scalar_reference(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    ensures(mul_nibbles(x, lo, hi) == mul_lanes(x, lo, hi));
}

/// `lookup` looks every byte up in the table, 0 past it.
#[law]
fn lookup_is_the_scalar_reference(t: uint8x16_t, idx: uint8x16_t) {
    ensures(lookup(t, idx) == tbl_lanes(t, idx));
}

/// `mul_twice` is the scalar reference applied twice.
#[law]
fn mul_twice_is_the_reference_twice(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    ensures(mul_twice(x, lo, hi) == mul_lanes(mul_lanes(x, lo, hi), lo, hi));
}

/// `has_neon` is `true`: every aarch64 target enables NEON statically, so
/// its detection is the constant.
#[lift_attach(crate::a::has_neon)]
fn has_neon_contract() {
    ensures(|ret: bool| ret == true);
}
"#;

const NEON_PROOF: &str = r#"use sandblaster::prelude::*;
use core::arch::aarch64::*;
#[allow(unused_imports)]
use crate::a::{mul_nibbles, lookup, mul_twice, has_neon};
#[allow(unused_imports)]
use crate::laws::{tbl, tbl_lanes, mul_byte, mul_lanes};

/// Lane for lane, by word algebra: the models unfold on symbolic lanes.
#[proof]
fn mul_nibbles_is_the_scalar_reference(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    unfold(mul_nibbles);
    bv();
}

#[proof]
fn lookup_is_the_scalar_reference(t: uint8x16_t, idx: uint8x16_t) {
    unfold(lookup);
    bv();
}

/// `mul_nibbles`'s law, twice.
#[proof]
fn mul_twice_is_the_reference_twice(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    mul_nibbles_is_the_scalar_reference(x, lo, hi);
    mul_nibbles_is_the_scalar_reference(mul_nibbles(x, lo, hi), lo, hi);
    unfold(mul_twice);
    follows();
}

#[proof(complete = crate::a::mul_nibbles)]
fn mul_nibbles_determined(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    use_hyp(0, x, lo, hi);
    use_real(0, x, lo, hi);
    by_arithmetic();
}

#[proof(complete = crate::a::lookup)]
fn lookup_determined(table: uint8x16_t, idx: uint8x16_t) {
    use_hyp(0, table, idx);
    use_real(0, table, idx);
    follows();
}

#[proof(complete = crate::a::mul_twice)]
fn mul_twice_determined(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    use_hyp(0, x, lo, hi);
    use_real(0, x, lo, hi);
    follows();
}
"#;

const X86_FNS: &str = "lookup, mul_split, lookup_masked";

const X86_LAWS: &str = r#"//! What the SSSE3 lookups compute: lane by lane, PSHUFB's scalar meaning.
use sandblaster::prelude::*;
use core::arch::x86_64::*;
use crate::a::{lookup, mul_split, lookup_masked};

/// PSHUFB on one byte: 0 when bit 7 of `k` is set, else `t[k & 15]`.
#[spec]
#[example(pshufb([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 0x03u8) == 13u8 && pshufb([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 0x13u8) == 13u8)]
#[example(pshufb([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 0x83u8) == 0u8)]
pub fn pshufb(t: [u8; 16], k: u8) -> u8 {
    if k & 128u8 != 0u8 { 0u8 } else { t[(k & 15u8) as usize] }
}

/// Each byte of `idx` through PSHUFB, lane 0 first.
#[spec]
#[example(pshufb_lanes([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x1e, 0xff]) == [10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 0])]
pub fn pshufb_lanes(t: [u8; 16], idx: [u8; 16]) -> [u8; 16] {
    [pshufb(t, idx[0]), pshufb(t, idx[1]), pshufb(t, idx[2]), pshufb(t, idx[3]),
     pshufb(t, idx[4]), pshufb(t, idx[5]), pshufb(t, idx[6]), pshufb(t, idx[7]),
     pshufb(t, idx[8]), pshufb(t, idx[9]), pshufb(t, idx[10]), pshufb(t, idx[11]),
     pshufb(t, idx[12]), pshufb(t, idx[13]), pshufb(t, idx[14]), pshufb(t, idx[15])]
}

/// One byte through the nibble tables, its nibbles split beforehand.
#[spec]
#[example(split_byte(1u8, 2u8, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == 0x21u8)]
pub fn split_byte(ln: u8, hn: u8, lo: [u8; 16], hi: [u8; 16]) -> u8 {
    pshufb(lo, ln) ^ pshufb(hi, hn)
}

/// `split_byte` in every lane.
#[spec]
#[example(split_lanes([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == [0x21u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]
pub fn split_lanes(ln: [u8; 16], hn: [u8; 16], lo: [u8; 16], hi: [u8; 16]) -> [u8; 16] {
    [split_byte(ln[0], hn[0], lo, hi), split_byte(ln[1], hn[1], lo, hi), split_byte(ln[2], hn[2], lo, hi), split_byte(ln[3], hn[3], lo, hi),
     split_byte(ln[4], hn[4], lo, hi), split_byte(ln[5], hn[5], lo, hi), split_byte(ln[6], hn[6], lo, hi), split_byte(ln[7], hn[7], lo, hi),
     split_byte(ln[8], hn[8], lo, hi), split_byte(ln[9], hn[9], lo, hi), split_byte(ln[10], hn[10], lo, hi), split_byte(ln[11], hn[11], lo, hi),
     split_byte(ln[12], hn[12], lo, hi), split_byte(ln[13], hn[13], lo, hi), split_byte(ln[14], hn[14], lo, hi), split_byte(ln[15], hn[15], lo, hi)]
}

/// Each byte of `idx` masked with `m`, then through PSHUFB.
#[spec]
#[example(masked_lanes([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], [0x83u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0x0fu8, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]) == [13u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25])]
pub fn masked_lanes(t: [u8; 16], idx: [u8; 16], m: [u8; 16]) -> [u8; 16] {
    [pshufb(t, idx[0] & m[0]), pshufb(t, idx[1] & m[1]), pshufb(t, idx[2] & m[2]), pshufb(t, idx[3] & m[3]),
     pshufb(t, idx[4] & m[4]), pshufb(t, idx[5] & m[5]), pshufb(t, idx[6] & m[6]), pshufb(t, idx[7] & m[7]),
     pshufb(t, idx[8] & m[8]), pshufb(t, idx[9] & m[9]), pshufb(t, idx[10] & m[10]), pshufb(t, idx[11] & m[11]),
     pshufb(t, idx[12] & m[12]), pshufb(t, idx[13] & m[13]), pshufb(t, idx[14] & m[14]), pshufb(t, idx[15] & m[15])]
}

/// `lookup` is PSHUFB in every lane.
#[law]
fn lookup_is_pshufb(t: __m128i, idx: __m128i) {
    ensures(lookup(t, idx) == pshufb_lanes(t, idx));
}

/// `mul_split` is the split-nibble reference in every lane.
#[law]
fn mul_split_is_the_scalar_reference(lo_n: __m128i, hi_n: __m128i, lo: __m128i, hi: __m128i) {
    ensures(mul_split(lo_n, hi_n, lo, hi) == split_lanes(lo_n, hi_n, lo, hi));
}

/// `lookup_masked` masks each index, then looks it up.
#[law]
fn lookup_masked_is_the_scalar_reference(t: __m128i, idx: __m128i, m: __m128i) {
    ensures(lookup_masked(t, idx, m) == masked_lanes(t, idx, m));
}
"#;

const X86_PROOF: &str = r#"use sandblaster::prelude::*;
use core::arch::x86_64::*;
#[allow(unused_imports)]
use crate::a::{lookup, mul_split, lookup_masked};
#[allow(unused_imports)]
use crate::laws::{pshufb, pshufb_lanes, split_byte, split_lanes, masked_lanes};

/// Lane for lane (the lane closer, `auto::lanes`): each lane's condition,
/// bit 7 of its index byte, is split; in either case the model's `if` and
/// the reference's compute the same byte.
#[proof]
fn lookup_is_pshufb(t: __m128i, idx: __m128i) {
    unfold(lookup);
    follows();
}

#[proof]
fn mul_split_is_the_scalar_reference(lo_n: __m128i, hi_n: __m128i, lo: __m128i, hi: __m128i) {
    unfold(mul_split);
    follows();
}

#[proof]
fn lookup_masked_is_the_scalar_reference(t: __m128i, idx: __m128i, m: __m128i) {
    unfold(lookup_masked);
    follows();
}

#[proof(complete = crate::a::lookup)]
fn lookup_determined(table: __m128i, idx: __m128i) {
    use_hyp(0, table, idx);
    use_real(0, table, idx);
    by_arithmetic();
}

#[proof(complete = crate::a::mul_split)]
fn mul_split_determined(lo_n: __m128i, hi_n: __m128i, lo: __m128i, hi: __m128i) {
    use_hyp(0, lo_n, hi_n, lo, hi);
    use_real(0, lo_n, hi_n, lo, hi);
    by_arithmetic();
}

#[proof(complete = crate::a::lookup_masked)]
fn lookup_masked_determined(table: __m128i, idx: __m128i, mask: __m128i) {
    use_hyp(0, table, idx, mask);
    use_real(0, table, idx, mask);
    by_arithmetic();
}
"#;

/// A host file, rustc's MIR of it, and its window extraction (the
/// unoptimized MIR the narrow reading's window rule reads, for code with raw
/// pointers; `docs/mir-lift.md` §20.10).
type CodeW = (&'static str, &'static str, &'static str);
const MUL128: CodeW =
    (include_str!("mir_fixtures/sd_neon_mul128/src/a.rs"), include_str!("mir_fixtures/sd_neon_mul128/a.sbmir"), include_str!("mir_fixtures/sd_neon_mul128/a.window.sbmir"));
const MUL128_SHIFT: CodeW = (
    include_str!("mir_fixtures/sd_neon_mul128_shift/src/a.rs"),
    include_str!("mir_fixtures/sd_neon_mul128_shift/a.sbmir"),
    include_str!("mir_fixtures/sd_neon_mul128_shift/a.window.sbmir"),
);
const MUL128_ROW: CodeW = (
    include_str!("mir_fixtures/sd_neon_mul128_row/src/a.rs"),
    include_str!("mir_fixtures/sd_neon_mul128_row/a.sbmir"),
    include_str!("mir_fixtures/sd_neon_mul128_row/a.window.sbmir"),
);

/// The split-table multiply's items (the twins have the same).
const MUL128_FNS: &str = "Lut, mul_128, muladd_128";

/// The elements `f(i)` for `i` in `0..n`, comma separated.
fn elems(n: usize, f: impl Fn(usize) -> String) -> String {
    (0..n).map(f).collect::<Vec<_>>().join(", ")
}

/// A literal `Lut` whose row `i` holds `lo(i, x)` and `hi(i, x)` at `x`.
fn lut_lit(lo: impl Fn(usize, usize) -> u8, hi: impl Fn(usize, usize) -> u8) -> String {
    let rows = |f: &dyn Fn(usize, usize) -> u8| format!("[{}]", elems(4, |i| format!("[{}]", elems(16, |x| format!("{}u8", f(i, x))))));
    format!("Lut {{ lo: {}, hi: {} }}", rows(&lo), rows(&hi))
}

/// What the split-table multiply computes: element by element, the scalar
/// reference (Reed–Solomon's `Scalar::mul` on one element, its 16-bit table
/// rows split into the rows of the product's low and high bytes).
fn mul128_laws() -> String {
    // the multiplier 1 (the rows of `log_m = 0`): every element unchanged
    let one = lut_lit(|i, x| match i { 0 => x as u8, 1 => ((x << 4) & 0xff) as u8, _ => 0 }, |i, x| match i { 2 => x as u8, 3 => ((x << 4) & 0xff) as u8, _ => 0 });
    // rows with every entry distinct
    let some = lut_lit(|i, x| (x + 16 * i) as u8, |i, x| (3 * x + 7 * i) as u8);
    format!(
        r#"//! What the split-table multiply computes: element by element, the product's
//! low and high bytes through the split nibble tables, which is what
//! Reed–Solomon's scalar engine computes per element (`Scalar::mul`, its
//! 16-bit rows split into the rows of the product's low and high bytes).
use sandblaster::prelude::*;
use core::arch::aarch64::*;
use crate::a::{{Lut, mul_128, muladd_128}};

/// The low byte of the product of one element (low byte `lo`, high byte
/// `hi`) by the multiplier of `lut`: its four nibbles looked up in the rows of
/// the product's low bytes, combined by xor.
#[spec]
#[example(mul_lo_byte({one}, 0x21u8, 0x43u8) == 0x21u8)]
#[example(mul_lo_byte({some}, 0x21u8, 0x43u8) == 4u8)]
pub fn mul_lo_byte(lut: Lut, lo: u8, hi: u8) -> u8 {{
    lut.lo[0][(lo & 15u8) as usize] ^ lut.lo[1][(lo >> 4u32) as usize] ^ lut.lo[2][(hi & 15u8) as usize] ^ lut.lo[3][(hi >> 4u32) as usize]
}}

/// The high byte of the same product.
#[spec]
#[example(mul_hi_byte({one}, 0x21u8, 0x43u8) == 0x43u8)]
#[example(mul_hi_byte({some}, 0x21u8, 0x43u8) == 56u8)]
pub fn mul_hi_byte(lut: Lut, lo: u8, hi: u8) -> u8 {{
    lut.hi[0][(lo & 15u8) as usize] ^ lut.hi[1][(lo >> 4u32) as usize] ^ lut.hi[2][(hi & 15u8) as usize] ^ lut.hi[3][(hi >> 4u32) as usize]
}}

/// The low product bytes of sixteen elements, lane 0 first.
#[spec]
#[example(mul_lo_lanes({one}, {vlo}, {vhi}) == {vlo})]
pub fn mul_lo_lanes(lut: Lut, vlo: [u8; 16], vhi: [u8; 16]) -> [u8; 16] {{
    [{lo_lanes}]
}}

/// Their high product bytes.
#[spec]
#[example(mul_hi_lanes({one}, {vlo}, {vhi}) == {vhi})]
pub fn mul_hi_lanes(lut: Lut, vlo: [u8; 16], vhi: [u8; 16]) -> [u8; 16] {{
    [{hi_lanes}]
}}

/// `mul_128` multiplies every element by the multiplier of `lut`: the low and
/// high product bytes, lane by lane (a vector is the array of its lanes, lane 0
/// first).
#[law]
fn mul_128_is_the_scalar_reference(value_lo: uint8x16_t, value_hi: uint8x16_t, lut: Lut) {{
    ensures(mul_128(value_lo, value_hi, &lut) == (mul_lo_lanes(lut, value_lo, value_hi), mul_hi_lanes(lut, value_lo, value_hi)));
}}

/// `muladd_128` adds (xor) the product of `y` to `x`, lane by lane.
#[law]
fn muladd_128_adds_the_product(x_lo: uint8x16_t, x_hi: uint8x16_t, y_lo: uint8x16_t, y_hi: uint8x16_t, lut: Lut) {{
    ensures(muladd_128(x_lo, x_hi, y_lo, y_hi, &lut) == ([{xor_lo}], [{xor_hi}]));
}}
"#,
        vlo = format!("[{}]", elems(16, |i| format!("{}u8", (17 * i + 3) & 0xff))),
        vhi = format!("[{}]", elems(16, |i| format!("{}u8", 255 - 13 * i))),
        lo_lanes = elems(16, |i| format!("mul_lo_byte(lut, vlo[{i}], vhi[{i}])")),
        hi_lanes = elems(16, |i| format!("mul_hi_byte(lut, vlo[{i}], vhi[{i}])")),
        xor_lo = elems(16, |i| format!("x_lo[{i}] ^ mul_lo_byte(lut, y_lo[{i}], y_hi[{i}])")),
        xor_hi = elems(16, |i| format!("x_hi[{i}] ^ mul_hi_byte(lut, y_lo[{i}], y_hi[{i}])")),
    )
}

/// The proofs of [`mul128_laws`]: the lane closer (`auto::lanes`), which
/// decides each lane's table lookups (an index `x & 15` or `x >> 4` is below
/// 16) and closes the lane.
const MUL128_PROOF: &str = r#"use sandblaster::prelude::*;
use core::arch::aarch64::*;
#[allow(unused_imports)]
use crate::a::{Lut, mul_128, muladd_128};
#[allow(unused_imports)]
use crate::laws::{mul_lo_byte, mul_hi_byte, mul_lo_lanes, mul_hi_lanes};

/// Lane for lane: every lookup's index is a nibble.
#[proof]
fn mul_128_is_the_scalar_reference(value_lo: uint8x16_t, value_hi: uint8x16_t, lut: Lut) {
    unfold(mul_128);
    follows();
}

/// The same lanes, each xored into `x`.
#[proof]
fn muladd_128_adds_the_product(x_lo: uint8x16_t, x_hi: uint8x16_t, y_lo: uint8x16_t, y_hi: uint8x16_t, lut: Lut) {
    unfold(muladd_128);
    unfold(mul_128);
    follows();
}

#[proof(complete = crate::a::mul_128)]
fn mul_128_determined(value_lo: uint8x16_t, value_hi: uint8x16_t, lut: &Lut) {
    use_hyp(0, value_lo, value_hi, *lut);
    use_real(0, value_lo, value_hi, lut);
    by_arithmetic();
}

#[proof(complete = crate::a::muladd_128)]
fn muladd_128_determined(x_lo: uint8x16_t, x_hi: uint8x16_t, y_lo: uint8x16_t, y_hi: uint8x16_t, lut: &Lut) {
    use_hyp(0, x_lo, x_hi, y_lo, y_hi, *lut);
    use_real(0, x_lo, x_hi, y_lo, y_hi, lut);
    by_arithmetic();
}
"#;

const LOCK: &str = "host/sandblaster/m/SPEC.lock";
const ROOT_PATH: &str = "host/sandblaster/m/mod.rs";

/// The DSL root exporting `fns` (with a proof file when `proof` is set).
fn root(fns: &str, proof: bool) -> String {
    let proof = if proof { "\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n" } else { "" };
    format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n{proof}\npub use a::{{{fns}}};\n")
}

/// The host crate of `code` exporting `fns`, with the laws and proofs given
/// (none: an empty laws file), without a lock.
fn files(code: Code, fns: &str, laws: Option<&str>, proof: Option<&str>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![
        ("host/Cargo.toml".into(), "[package]\nname = \"sd-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n".into()),
        ("host/src/lib.rs".into(), format!("//! The host crate.\nmod a;\npub use a::{{{fns}}};\n")),
        ("host/src/a.rs".into(), code.0.into()),
        (ROOT_PATH.into(), root(fns, proof.is_some())),
        ("host/sandblaster/m/a.sbmir".into(), code.1.into()),
        ("host/sandblaster/m/LAWS.rs".into(), laws.unwrap_or("//! No laws.\nuse sandblaster::prelude::*;\n").into()),
    ];
    if let Some(p) = proof {
        v.push(("host/sandblaster/m/PROOF.rs".into(), p.into()));
    }
    v
}

/// [`files`] for code with raw pointers: its window extraction beside it,
/// declared by the lift (`window_mir`).
fn files_w(code: CodeW, fns: &str, laws: Option<&str>, proof: Option<&str>) -> Vec<(String, String)> {
    let mut v = files((code.0, code.1), fns, laws, proof);
    for (p, t) in v.iter_mut() {
        if p == ROOT_PATH {
            *t = t.replace("mir = \"a.sbmir\")]", "mir = \"a.sbmir\", window_mir = \"a.window.sbmir\")]");
        }
    }
    v.push(("host/sandblaster/m/a.window.sbmir".into(), code.2.into()));
    v
}

fn with_lock(mut files: Vec<(String, String)>, lock: &str) -> Vec<(String, String)> {
    files.retain(|(p, _)| p != LOCK);
    files.push((LOCK.into(), lock.into()));
    files
}

/// A scratch directory: the crate, its target directories and its cache.
struct Scratch {
    dir: PathBuf,
    builds: usize,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sandblaster-simd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir, builds: 0 }
    }

    fn abs(&self, files: &[(String, String)]) -> (Vec<(String, String)>, String) {
        let abs: Vec<(String, String)> = files.iter().map(|(p, t)| (self.dir.join(p).display().to_string(), t.clone())).collect();
        (abs, self.dir.join(ROOT_PATH).display().to_string())
    }

    /// The lock `sandblaster spec --accept` writes for `files` (every gate
    /// but the lock must pass, the theorem gate included), or why there is
    /// none.
    fn accept(&self, files: &[(String, String)], target: &TargetInfo) -> Result<String, String> {
        let (abs, root) = self.abs(files);
        gated::accept_lock(&abs, &root, target)
    }

    /// The front end's reading of `files` (no proofs, no gates).
    fn check(&self, files: &[(String, String)], target: &TargetInfo) -> Checked {
        let (abs, root) = self.abs(files);
        let fs = MemFs::from_files(abs.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        driver::check(Path::new(&root), &fs, target)
    }

    /// Every proof and gate of `files` but the lock (the crate path that
    /// `spec --accept` runs): whether all passed, and every diagnostic
    /// rendered.
    fn gates(&self, files: &[(String, String)], target: &TargetInfo) -> (bool, String) {
        let c = self.check(files, target);
        if !c.ok() {
            return (false, c.render());
        }
        let (_, root) = self.abs(files);
        let b = driver::build_crate(&c, LockUse::Accepting, &root);
        (b.permit.is_some(), format!("{}\n{}", b.render_failure(&c, &root), b.gates.diags.render(&c.sm)))
    }

    /// An enforcing in-place build of `files` (written to disk, in a new
    /// target directory), as the facade's `compile_lifted` runs it: the
    /// proofs, every gate, the theorem gate and the lift conformance check
    /// (which compiles the host and runs it natively).
    fn build(&mut self, files: &[(String, String)]) -> BuildOutcome {
        let _ = std::fs::remove_dir_all(self.dir.join("host"));
        for (p, t) in files {
            let f = self.dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, t).unwrap();
        }
        self.builds += 1;
        let out = self.dir.join(format!("target{}/out", self.builds));
        std::fs::create_dir_all(&out).unwrap();
        let mut e: HashMap<String, String> = [
            ("CARGO_MANIFEST_DIR", self.dir.join("host").display().to_string()),
            ("OUT_DIR", out.display().to_string()),
            ("CARGO_CFG_TARGET_ARCH", "aarch64".into()),
            // the static features stable rustc gives `aarch64-apple-darwin`
            // (an extraction records its own, which must be the build's)
            ("CARGO_CFG_TARGET_FEATURE", TargetInfo::aarch64_apple_darwin().features.iter().cloned().collect::<Vec<_>>().join(",")),
            ("CARGO_CFG_TARGET_ENDIAN", "little".into()),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", "64".into()),
            ("SANDBLASTER_CACHE_DIR", self.dir.join("cache").display().to_string()),
            ("SANDBLASTER_CACHE_KEY", "test secret".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for k in ["RUSTC", "CARGO"] {
            if let Ok(v) = std::env::var(k) {
                e.insert(k.into(), v);
            }
        }
        driver::build_lifted("sandblaster/m/mod.rs", "m", Some("simd-test-toolchain"), &|k| e.get(k).cloned(), &sandblaster_front::loader::RealFs)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

/// A gate's entry in a build's report (for assertions and the test's log).
fn gate_entry(report: &str, gate: &str) -> String {
    let Some(at) = report.find(&format!("\"gate\": \"{gate}\"")) else { return String::new() };
    report[at..report[at..].find('}').map_or(report.len(), |e| at + e)].to_string()
}

/// The models the NEON fixture calls (each is a `target-model:` item).
const NEON_MODELS: [&str; 5] = ["vandq_u8", "vdupq_n_u8", "veorq_u8", "vqtbl1q_u8", "vshrq_n_u8"];

#[test]
fn a_neon_function_is_verified_in_place_against_its_scalar_reference_and_run_natively() {
    let mut s = Scratch::new("neon");
    let neon = files(NEON, NEON_FNS, Some(NEON_LAWS), Some(NEON_PROOF));
    let lock = s.accept(&neon, &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the NEON fixture's gates:\n{e}"));
    for law in ["mul_nibbles_is_the_scalar_reference", "lookup_is_the_scalar_reference", "mul_twice_is_the_reference_twice"] {
        assert!(lock.contains(&format!("law:crate::laws::{law}")), "{law}: {lock}");
    }
    // the models pinned in the lock: each validated natively on aarch64
    for m in NEON_MODELS {
        let key = format!("item target-model:aarch64:{m}\n");
        let at = lock.find(&key).unwrap_or_else(|| panic!("no `target-model:aarch64:{m}` in the lock"));
        let entry = &lock[at..lock[at + 1..].find("\nitem ").map_or(lock.len(), |e| at + 1 + e)];
        assert!(entry.contains("verdict Validated { executor: \"native\" }"), "{m}: {entry}");
    }
    let o = s.build(&with_lock(neon, &lock));
    assert!(o.ok, "no verdict:\n{}\n{:?}", o.stderr, o.cargo);
    let record = output(&o, "m-verified.txt").unwrap_or_else(|| panic!("no record: {:?}", o.cargo));
    assert!(record.contains("VERIFIED + LIFTED IN PLACE") && record.contains("src/a.rs"), "{record}");
    let report = output(&o, "m-report.json").expect("a report");
    for gate in ["boundary", "examples", "sections", "law-rules", "lock", "mir-theorems", "lift-conformance"] {
        let entry = gate_entry(report, gate);
        assert!(entry.contains("\"ran\": true") && entry.contains("\"errors\": 0"), "gate {gate}: {entry}");
    }
    // every function read from MIR has its theorem; the conformance check ran
    // the NEON code natively (L and S against rustc's build), none skipped
    assert!(gate_entry(report, "mir-theorems").contains("4 of 4"), "{}", gate_entry(report, "mir-theorems"));
    let conformance = gate_entry(report, "lift-conformance");
    assert!(conformance.contains("on 4 function(s) (0 skipped)") && conformance.contains(", 0 mismatch(es)"), "{conformance}");
    eprintln!("{}\n{conformance}", gate_entry(report, "mir-theorems"));
}

/// The refusal of a wrong variant by the NEON laws and proofs, rendered.
fn refused(s: &Scratch, code: Code) -> String {
    let (ok, why) = s.gates(&files(code, NEON_FNS, Some(NEON_LAWS), Some(NEON_PROOF)), &TargetInfo::aarch64_apple_darwin());
    assert!(!ok, "a wrong variant passed every gate:\n{why}");
    why
}

#[test]
fn a_wrong_shift_and_the_wrong_lanes_are_refused_by_the_same_laws() {
    let s = Scratch::new("twins");
    for (what, code) in [("a shift by 3", WRONG_SHIFT), ("TBL's table and indices swapped", WRONG_LANES)] {
        let why = refused(&s, code);
        assert!(why.contains("mul_nibbles_is_the_scalar_reference"), "{what}: the refusal names the law:\n{why}");
        // (the reading is right: the wrong code is read as what it is)
        let c = s.check(&files(code, NEON_FNS, Some(NEON_LAWS), Some(NEON_PROOF)), &TargetInfo::aarch64_apple_darwin());
        let m = theorems(&c, &c.lift_facts);
        assert_eq!(outcome(&m, "crate::a::mul_nibbles"), Ok(()), "{what}: the MIR theorem of the wrong code");
        eprintln!("{what}: refused by the law");
    }
}

/// Reed–Solomon's NEON `mul_128` as written (`mir_fixtures/sd_neon_mul128`:
/// its rows loaded through raw pointers formed from shared references, its
/// value intrinsics in `unsafe`, its rows as byte arrays) is verified in place
/// against the scalar reference, lane by lane, by the lane closer: each lane's
/// eight lookups have nibble indices (decided below 16), so each product byte
/// is the reference's xor of four row entries. `muladd_128` likewise. The
/// lock pins the laws and the models; every function has its MIR theorem; the
/// lift conformance check runs the NEON code natively.
#[test]
fn a_split_table_multiply_is_verified_lane_by_lane_against_its_scalar_reference() {
    let mut s = Scratch::new("mul128");
    let laws = mul128_laws();
    let f = files_w(MUL128, MUL128_FNS, Some(&laws), Some(MUL128_PROOF));
    let lock = s.accept(&f, &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the split-table multiply's gates:\n{e}"));
    for law in ["mul_128_is_the_scalar_reference", "muladd_128_adds_the_product"] {
        assert!(lock.contains(&format!("law:crate::laws::{law}")), "{law}: {lock}");
    }
    for m in ["vandq_u8", "vdupq_n_u8", "veorq_u8", "vld1q_u8", "vqtbl1q_u8", "vshrq_n_u8"] {
        assert!(lock.contains(&format!("item target-model:aarch64:{m}\n")), "{m}");
    }
    let o = s.build(&with_lock(f, &lock));
    assert!(o.ok, "no verdict:\n{}\n{:?}", o.stderr, o.cargo);
    let record = output(&o, "m-verified.txt").unwrap_or_else(|| panic!("no record: {:?}", o.cargo));
    assert!(record.contains("VERIFIED + LIFTED IN PLACE") && record.contains("src/a.rs"), "{record}");
    let report = output(&o, "m-report.json").expect("a report");
    for gate in ["boundary", "examples", "sections", "law-rules", "lock", "mir-theorems", "lift-conformance"] {
        let entry = gate_entry(report, gate);
        assert!(entry.contains("\"ran\": true") && entry.contains("\"errors\": 0"), "gate {gate}: {entry}");
    }
    // both functions read from MIR have their theorems; the conformance check
    // ran them natively (their table rows loaded through the pointers)
    assert!(gate_entry(report, "mir-theorems").contains("2 of 2"), "{}", gate_entry(report, "mir-theorems"));
    let conformance = gate_entry(report, "lift-conformance");
    assert!(conformance.contains("on 2 function(s) (0 skipped)") && conformance.contains(", 0 mismatch(es)"), "{conformance}");
    eprintln!("{}\n{conformance}", gate_entry(report, "mir-theorems"));
}

/// The negative twins (`sd_neon_mul128_shift`: the low bytes' high nibble
/// taken with a shift by 3; `sd_neon_mul128_row`: the third and fourth rows of
/// the low product bytes swapped) are refused by the same laws and proofs: a
/// lane the closer cannot decide (its lookups read other entries than the
/// reference's), no kernel rejection. Their MIR theorems hold (the wrong code
/// is read as what it is).
#[test]
fn a_wrong_nibble_and_a_wrong_row_are_refused_by_the_same_laws() {
    let s = Scratch::new("mul128-twins");
    let laws = mul128_laws();
    for (what, code) in [("a shift by 3", MUL128_SHIFT), ("two rows swapped", MUL128_ROW)] {
        let f = files_w(code, MUL128_FNS, Some(&laws), Some(MUL128_PROOF));
        let (ok, why) = s.gates(&f, &TargetInfo::aarch64_apple_darwin());
        assert!(!ok, "{what}: a wrong variant passed every gate:\n{why}");
        assert!(why.contains("mul_128_is_the_scalar_reference"), "{what}: the refusal names the law:\n{why}");
        assert!(!why.contains("rejected by the kernel") && !why.contains("the kernel rejected"), "{what}: {why}");
        let c = s.check(&f, &TargetInfo::aarch64_apple_darwin());
        let m = theorems(&c, &c.lift_facts);
        assert_eq!(outcome(&m, "crate::a::mul_128"), Ok(()), "{what}: the MIR theorem of the wrong code");
        eprintln!("{what}: refused by the law");
    }
}

#[test]
fn a_load_through_a_raw_pointer_is_refused_and_named() {
    let s = Scratch::new("pointer");
    let c = s.check(&files(POINTER, "load", None, None), &TargetInfo::aarch64_apple_darwin());
    let r = c.render();
    assert!(!c.ok(), "a pointer load was read:\n{r}");
    // (an extraction from before the narrow reading of existing `unsafe`:
    // refused with the load named, and the remedy, extracting it again)
    assert!(r.contains("`unsafe` in a lifted function whose MIR was extracted before the narrow reading") && r.contains("`vld1q_u8`") && r.contains("extract it again"), "{r}");
    // the literal reading refuses the load itself (whatever the source says)
    let m = ir::parse(POINTER.1).expect("parse");
    let f = m.fns.get("fx_sd_neon_ptr::a::load").expect("load's MIR");
    let a = f.blocks.iter().find_map(|b| match &b.term {
        Term::Call(Callee::Arch(a), ..) => Some(a.clone()),
        _ => None,
    });
    let a = a.expect("an arch call");
    assert!(!a.safe && a.pointer, "{a:?}");
    let why = sandblaster_front::mir::arch::model(&m, &a, &f.target_features).expect_err("refused");
    assert!(why.contains("raw pointer") && why.contains("vld1q_u8"), "{why}");
}

#[test]
fn an_intrinsic_without_a_validated_model_is_refused_by_both_readings() {
    let s = Scratch::new("nomodel");
    let laws = "//! `add_bytes` adds lane by lane.\nuse sandblaster::prelude::*;\nuse core::arch::aarch64::*;\nuse crate::a::add_bytes;\n";
    let (ok, why) = s.gates(&files(NO_MODEL, "add_bytes", Some(laws), None), &TargetInfo::aarch64_apple_darwin());
    assert!(!ok);
    assert!(why.contains("core model is deferred") && why.contains("intrinsic `vaddq_u8` has no core model"), "the structured reading: {why}");
    assert!(why.contains("`crate::a::add_bytes` has no kernel-checked theorem"), "{why}");
    // the literal reading: no model has the call's path
    let m = ir::parse(NO_MODEL.1).expect("parse");
    let f = m.fns.get("fx_sd_neon_nomodel::a::add_bytes").expect("MIR");
    let Some(Term::Call(Callee::Arch(a), ..)) = f.blocks.first().map(|b| &b.term) else { panic!("an arch call") };
    let e = sandblaster_front::mir::arch::model(&m, a, &f.target_features).expect_err("refused");
    assert!(e.contains("has no model in the target library"), "{e}");
}

#[test]
fn a_runtime_feature_detection_is_refused() {
    let s = Scratch::new("detect");
    let laws = "//! `has_sm4`.\nuse sandblaster::prelude::*;\nuse crate::a::has_sm4;\n";
    let (ok, why) = s.gates(&files(DETECT, "has_sm4", Some(laws), None), &TargetInfo::aarch64_apple_darwin());
    assert!(!ok);
    assert!(why.contains("runtime feature detection"), "{why}");
}

#[test]
fn mir_of_another_architecture_is_refused_at_its_load() {
    let s = Scratch::new("arch");
    let c = s.check(&files(X86, X86_FNS, None, None), &TargetInfo::aarch64_apple_darwin());
    let r = c.render();
    assert!(!c.ok());
    assert!(r.contains("extracted for `x86_64-apple-macosx` (x86_64), but this build is for aarch64"), "{r}");
}

#[test]
fn an_ssse3_function_is_read_onto_the_x86_models() {
    let s = Scratch::new("x86");
    let x86 = files(X86, X86_FNS, Some(X86_LAWS), Some(X86_PROOF));
    let lock = s.accept(&x86, &TargetInfo::x86_64_apple_darwin()).unwrap_or_else(|e| panic!("the SSSE3 fixture's gates:\n{e}"));
    for m in ["_mm_and_si128", "_mm_shuffle_epi8", "_mm_xor_si128"] {
        assert!(lock.contains(&format!("item target-model:x86_64:{m}\n")), "{m}");
    }
    assert!(lock.contains("\ntarget x86_64 "), "{}", lock.lines().take(12).collect::<Vec<_>>().join("\n"));
    let c = s.check(&x86, &TargetInfo::x86_64_apple_darwin());
    let m = theorems(&c, &c.lift_facts);
    assert_eq!((m.functions(), m.proven()), (3, 3), "{:?}", m.missing);
}

// ---------------------------------------------------------------------------
// fault injection: the literal reading's arch leaves
// ---------------------------------------------------------------------------

/// The gate's theorems on the structured reading of `c`'s lifted functions,
/// with the MIR the literal reading reads taken from `facts`.
fn theorems(c: &Checked, facts: &LiftFacts) -> ModuleTheorems {
    let mut reps = sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        let mut out = checked::elaborate_names(k, &items);
        checked::prove_and_check(&mut out, k, facts, &GateOptions::default())
    });
    assert_eq!(reps.len(), 1, "one lifted MIR module");
    reps.remove(0)
}

/// The outcome of `global`'s theorem: `Ok` proven, `Err` why not.
fn outcome<'m>(m: &'m ModuleTheorems, global: &str) -> Result<(), &'m str> {
    if let Some(o) = m.outcomes.iter().find(|o| o.is_fn && o.global == global) {
        return o.result.as_ref().map(|_| ()).map_err(|e| e.as_str());
    }
    m.missing.iter().find(|(g, _)| g == global).map(|(_, why)| Err(why.as_str())).unwrap_or_else(|| panic!("no theorem planned for `{global}`"))
}

/// The arch call ending block `b`.
fn arch_call(f: &mut ir::Fn, b: usize) -> (&mut ir::ArchCall, &mut Vec<ir::Operand>) {
    match &mut f.blocks[b].term {
        Term::Call(Callee::Arch(a), args, ..) => (a, args),
        other => panic!("bb{b} is no arch call: {other:?}"),
    }
}

#[test]
fn a_changed_intrinsic_call_breaks_the_theorem_of_its_function_only() {
    let s = Scratch::new("faults");
    let c = s.check(&files(NEON, NEON_FNS, Some(NEON_LAWS), Some(NEON_PROOF)), &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let changes: [(&str, fn(&mut ir::Fn)); 3] = [
        // `vshrq_n_u8::<4>` reads `::<3>`
        ("an immediate", |f| {
            let (a, _) = arch_call(f, 3);
            assert_eq!((a.path.as_str(), a.imms.as_slice()), ("core::arch::aarch64::vshrq_n_u8", &[4][..]));
            a.imms = vec![3];
        }),
        // `veorq_u8` reads `vandq_u8`
        ("the intrinsic", |f| {
            let (a, _) = arch_call(f, 5);
            assert_eq!(a.path, "core::arch::aarch64::veorq_u8");
            a.path = "core::arch::aarch64::vandq_u8".into();
        }),
        // TBL's table and indices swapped
        ("the arguments' order", |f| {
            let (a, args) = arch_call(f, 2);
            assert_eq!(a.path, "core::arch::aarch64::vqtbl1q_u8");
            args.swap(0, 1);
        }),
    ];
    for (what, change) in changes {
        let mut facts = c.lift_facts.clone();
        let mut loaded = (*facts.mir_loaded[0].loaded).clone();
        change(loaded.m.fns.get_mut("fx_sd_neon::a::mul_nibbles").expect("mul_nibbles' MIR"));
        facts.mir_loaded[0].loaded = Arc::new(loaded);
        let m = theorems(&c, &facts);
        let why = outcome(&m, "crate::a::mul_nibbles").expect_err(what);
        assert!(!why.starts_with("not attempted"), "{what}: {why}");
        // the module's other theorems are untouched (`mul_twice` runs it)
        assert_eq!(outcome(&m, "crate::a::lookup"), Ok(()), "{what}");
        assert_eq!(outcome(&m, "crate::a::has_neon"), Ok(()), "{what}");
        eprintln!("{what} changed: `mul_nibbles` has no theorem");
    }
}
