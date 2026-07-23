//! AVX-512 backend for [`Reduced`]/[`Unreduced`] arithmetic (multiplication, addition,
//! subtraction, reduction).
//!
//! Real-hardware testing (on an actual AVX-512 server) previously found multiple correctness
//! issues here. First: chaining enough operations on the same accumulator (e.g. the MSM's
//! transposed-Pippenger window-doubling loop, and batch point decompression's sqrt kernel with
//! varied per-lane values) silently produced wrong results, traced to `vpmadd52lo`/`vpmadd52hi`
//! requiring inputs of *exactly* 52 bits (they silently discard anything above bit 51) combined
//! with a single carry ripple leaving one limb only "nominal 52 bits, occasionally exactly 52"
//! rather than strictly below it -- a bound the portable backend's `u128` arithmetic tolerates
//! fine but these specific instructions do not. This module (and [`super::Reduced`]/
//! [`super::Unreduced`], and the `PointVec`/transposed MSM machinery built on top of them) is
//! restructured around that distinction -- see the [`super`] module docs -- with [`mul`]/
//! [`square`] only ever accepting/returning [`Reduced`] (every limb strictly `< 2^52`, proven by
//! [`reduce`]'s three-pass ripple; see [`super::reduce_limbs`]'s doc comment for the exact bound
//! analysis) and [`add`]/[`sub`] working on [`Unreduced`].
//!
//! Second, and separately: even with strictly `< 2^52`-bounded *inputs*, [`mul`]/[`square`] could
//! still produce a wrong result for specific operands, isolated to a single exact value found by
//! bit-for-bit hardware/portable comparison (see
//! `tests::mul_matches_portable_for_known_bad_value_on_real_hardware`) and confirmed symbolically:
//! a raw schoolbook column (before folding, see [`mul`]'s doc comment) can reach ~`2^55.17`, and
//! `vpmullq`'s plain 64-bit lane multiply by [`super::FOLD_608`] (`~2^9.25`) can then exceed
//! `u64::MAX` and silently wrap, with no carry-out. This is a bound on an internal, never-typed
//! intermediate (`col: [__m512i; 10]`, built and consumed entirely inside one function body) that
//! the [`Reduced`]/[`Unreduced`] split cannot express or enforce -- that split only guards values
//! crossing a function boundary. [`carry_cols`] fixes this by narrowing every column *before* the
//! `*608` fold, the same way [`reduce`]'s [`carry`] narrows the final 5 limbs after it.
//!
//! If this backend is ever disabled again for a similar reason, re-validate it against this
//! module's own `matches_portable_*_on_real_hardware` tests (which cover [`reduce`] against the
//! exact adversarial boundary cases in `super::tests` too, and [`mul`] against the known-bad value
//! above) plus `signing::msm::tests::transposed_matches_scalar`, on real AVX-512 hardware, before
//! re-enabling.
//!
//! # Design
//!
//! `vpmadd52luq`/`vpmadd52huq` each compute, per 64-bit lane, `acc += low52(a*b)` /
//! `acc += high52(a*b)` for 52-bit `a`, `b` -- an accumulating multiply, not a plain one. The
//! schoolbook product of two 5-limb, radix-`2^52` numbers has 25 `a[i]*b[j]` terms, each spanning
//! two of 10 raw output columns (column `i+j` gets the low 52 bits, column `i+j+1` gets the high
//! 52 bits, since a term's value is `low52(a_i*b_j) * 2^(52*(i+j)) + high52(a_i*b_j) * 2^(52*(i+j+1))`).
//! So: 25 `vpmadd52luq` + 25 `vpmadd52huq` accumulate directly into 10 column registers (`col[0]`
//! through `col[9]`), matching the design notes' field layer section. Column 4 (the worst case, 5
//! low-half terms with `i+j==4` plus 4 high-half terms with `i+j==3`) can reach 9 accumulated
//! `< 2^52` terms, i.e. up to `~2^55.17` -- [`carry_cols`] ripple-carries all 10 columns first so
//! every one of columns 5-9 (the ones about to be scaled by 608) is small enough that the scaling
//! multiply cannot overflow a `u64` lane (see [`carry_cols`]'s doc comment for the exact bound).
//! Only then are columns 5-9 (weight `>= 2^260`) folded back into columns 0-4 via
//! `2^260 ≡ 608 (mod p)` (see [`super::FOLD_608`]), and [`reduce`]'s three-pass vectorized [`carry`]
//! ripple brings every limb strictly under `2^52`. [`add`]/[`sub`] are simpler: an elementwise
//! `vpaddq`/`vpsubq` per limb followed by a *single* [`carry`] pass (an [`Unreduced`] result, not
//! [`Reduced`]).

use super::{Reduced, Unreduced};
use core::arch::x86_64::*;

/// Feature set this backend requires: IFMA for the 52x52-bit multiply-accumulates, VL to use
/// `__m512i` ops introduced alongside AVX-512VL, DQ for the plain 64-bit lane multiply used to
/// scale by the small constant `608`.
pub(crate) fn available() -> bool {
    is_x86_feature_detected!("avx512f")
        && is_x86_feature_detected!("avx512ifma")
        && is_x86_feature_detected!("avx512vl")
        && is_x86_feature_detected!("avx512dq")
}

/// Loads 5 rows of 8 packed `u64` limbs into zmm registers.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn load(limbs: &[[u64; super::LANES]; 5]) -> [__m512i; 5] {
    // SAFETY: each row is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
    // `loadu` places no alignment requirement on the source.
    unsafe { core::array::from_fn(|i| _mm512_loadu_si512(limbs[i].as_ptr().cast())) }
}

/// Stores 5 zmm registers into 5 rows of 8 packed `u64` limbs.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn store(regs: [__m512i; 5]) -> [[u64; super::LANES]; 5] {
    let mut limbs = [[0u64; super::LANES]; 5];
    for (row, reg) in limbs.iter_mut().zip(regs) {
        // SAFETY: `row` is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
        // `storeu` places no alignment requirement on the destination.
        unsafe { _mm512_storeu_si512(row.as_mut_ptr().cast(), reg) };
    }
    limbs
}

/// Vectorized counterpart to `super::carry`: the carry chain propagates between *limbs* (rows),
/// not between lanes, so every step here is a uniform shift/mask/add applied to all 8 lanes in a
/// row at once -- no cross-lane shuffling needed, unlike [`mul`]'s schoolbook columns. A single
/// pass leaves every limb but one strictly `< 2^52`; see [`reduce`] for the full three-pass
/// reduction and `super::reduce_limbs`'s doc comment for why three passes.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (for the 64-bit lane multiply used
/// to scale by the small constant `608`).
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn carry(mut l: [__m512i; 5]) -> [__m512i; 5] {
    let mask = _mm512_set1_epi64(super::MASK_52 as i64);
    l[1] = _mm512_add_epi64(l[1], _mm512_srli_epi64(l[0], 52));
    l[0] = _mm512_and_si512(l[0], mask);
    l[2] = _mm512_add_epi64(l[2], _mm512_srli_epi64(l[1], 52));
    l[1] = _mm512_and_si512(l[1], mask);
    l[3] = _mm512_add_epi64(l[3], _mm512_srli_epi64(l[2], 52));
    l[2] = _mm512_and_si512(l[2], mask);
    l[4] = _mm512_add_epi64(l[4], _mm512_srli_epi64(l[3], 52));
    l[3] = _mm512_and_si512(l[3], mask);
    let fold_608 = _mm512_set1_epi64(super::FOLD_608 as i64);
    let wrap = _mm512_mullo_epi64(_mm512_srli_epi64(l[4], 52), fold_608);
    l[4] = _mm512_and_si512(l[4], mask);
    l[0] = _mm512_add_epi64(l[0], wrap);
    l[1] = _mm512_add_epi64(l[1], _mm512_srli_epi64(l[0], 52));
    l[0] = _mm512_and_si512(l[0], mask);
    l
}

/// Vectorized counterpart to `super::reduce_limbs`: three [`carry`] passes, guaranteeing every
/// limb strictly `< 2^52` (see that function's doc comment for the bound analysis this relies on).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn reduce_regs(l: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic `carry` uses.
    unsafe { carry(carry(carry(l))) }
}

/// Ripple-carries the 10 raw schoolbook-product columns ([`mul`]/[`square`]'s intermediate,
/// before the `*608` fold) so every one of columns 5-8 is strictly `< 2^52` -- the only columns
/// that actually feed the `*608` fold-multiply below (column `5+k` scales into column `k`, for `k`
/// in `0..5`). Columns 0-4 are only ever *added* into the fold result, never scaled, so a fold
/// value of `col[k] + 608 * col[k+5]` is exactly as correct (and no more overflow-prone: at most
/// `~2^55.17 + 608 * 2^52 ~= 2^61.3`, comfortably under `2^64`) whether `col[k]` for `k < 5` is
/// masked here or left raw -- [`reduce_regs`]'s three carry passes normalize that looseness away
/// regardless, the same as it does for any other loose input. So this only ripples `k` in `5..9`,
/// leaving columns 0-4 untouched. Column 9 is left unmasked too (there is no column 10 to carry its
/// overflow into), and is provably safe as a fold-multiply input regardless: it only ever
/// accumulates the single `i==j==4` high-half term in both [`mul`] and [`square`] (every other
/// `i + j + 1 == 9` pair needs `i + j == 8`, impossible for `i, j < 5`), so it is `< 2^52` before
/// even receiving column 8's carry-out (itself `< 9`, from at most 9 accumulated `< 2^52` terms per
/// raw column -- column 4 or 5, the worst case: 5 low-half terms with `i+j==4` plus 4 high-half
/// terms with `i+j==3`, or the mirror for column 5), i.e. column 9 stays `< 2^52 + 9`. Either bound,
/// multiplied by [`super::FOLD_608`] (`608 < 2^10`), stays comfortably under `2^63`, which is what
/// makes the `vpmullq`-based fold safe -- unlike folding the *raw* columns directly, which can
/// reach `~2^55.17 * 608 ~= 2^64.4`, overflowing a `u64` lane with no carry-out (found on real
/// AVX-512 hardware; see the module docs).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn carry_cols(mut col: [__m512i; 10]) -> [__m512i; 10] {
    let mask = _mm512_set1_epi64(super::MASK_52 as i64);
    for k in 5..9 {
        col[k + 1] = _mm512_add_epi64(col[k + 1], _mm512_srli_epi64(col[k], 52));
        col[k] = _mm512_and_si512(col[k], mask);
    }
    col
}

/// Register-level counterpart to [`mul`], but skipping the final [`reduce_regs`]: the schoolbook
/// accumulate, [`carry_cols`] narrowing, and `*608` fold all still happen (so the result is a
/// correct value, congruent to the true product mod `p`), but it is left "loose" -- each limb up
/// to `~2^61.3` (one raw, unmasked column, `< 9 * 2^52`, plus a masked column scaled by
/// [`super::FOLD_608`], `< 608 * 2^52`) -- rather than brought under `2^52`.
///
/// Callers must not feed this into [`mul_regs`]/[`square_regs`] (which require [`Reduced`]-quality,
/// strictly `< 2^52` input) or use it as [`sub_regs`]'s *right-hand* operand (`b` in `a - b`):
/// [`super::SUB_BIAS`] is sized with a `16x` margin over a `< 2^52` right-hand operand specifically,
/// and this value can be `~2^61.3`, `2^9.3`-ish times looser than that margin covers, which would
/// underflow the biased subtraction (wrap to a huge, wrong result) instead of merely losing
/// precision. It *is* safe as [`add_regs`]'s operand (either side) or [`sub_regs`]'s left-hand
/// operand (`a` in `a - b`): both just need the raw sum/difference to fit in a `u64` lane before
/// their own single [`carry`] pass, and `2 * 2^61.3 ~= 2^62.3` is nowhere near overflowing that.
/// Use this whenever the result only ever reaches such a position before its own consumer's
/// `reduce_regs` call -- see [`point_add`]/[`point_double`] for where this actually applies (audited
/// per call site, not blanket) and why it's safe there.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
unsafe fn mul_regs_loose(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        // 10 raw columns: column `k` accumulates every `low52(a[i]*b[j])` with `i+j == k` and every
        // `high52(a[i]*b[j])` with `i+j+1 == k`, i.e. the full, un-folded schoolbook product.
        //
        // Splitting lo-terms and hi-terms into separate accumulator sets (combined via one final
        // add) shortens each busy column's dependency chain -- a real technique (see
        // curve25519-dalek-ng's `docs/ifma-notes.md`, ipp-crypto's IFMA RSA Montgomery kernel, and
        // OpenSSL's `rsaz-avx512.pl`) -- but measured here, inside this already register-pressured
        // fused caller (`point_add`/`point_double` juggle up to 8 coordinates' worth of limbs at
        // once), it roughly tripled this function's stack-spill traffic and the net effect on real
        // hardware was a wash-to-regression, not a win. Kept as plain shared-column accumulation;
        // the split is worth revisiting for a truly standalone `mul`/`square` call with registers
        // to spare, not for the fused point ops.
        let mut col = [_mm512_setzero_si512(); 10];
        for i in 0..5 {
            for j in 0..5 {
                col[i + j] = _mm512_madd52lo_epu64(col[i + j], a[i], b[j]);
                col[i + j + 1] = _mm512_madd52hi_epu64(col[i + j + 1], a[i], b[j]);
            }
        }

        // Narrow every column first -- see `carry_cols`'s doc comment for why the raw columns are
        // not already safe to scale by 608 directly.
        let col = carry_cols(col);

        // Fold columns 5-9 (weight >= 2^260) back into columns 0-4 via 2^260 ≡ 608 (mod p): column
        // `5+k` has exactly `608` times column `k`'s weight, for k in 0..5.
        let fold_608 = _mm512_set1_epi64(super::FOLD_608 as i64);
        let mut folded = [_mm512_setzero_si512(); 5];
        for k in 0..5 {
            let scaled = _mm512_mullo_epi64(col[k + 5], fold_608);
            folded[k] = _mm512_add_epi64(col[k], scaled);
        }

        folded
    }
}

/// Register-level counterpart to [`mul`]: identical computation, but every intermediate (the raw
/// columns, the folded, un-reduced product) stays in registers -- no `Reduced`/`Unreduced` struct
/// is materialized to/from memory anywhere in between. [`mul`] and callers chaining multiple
/// primitive operations without ever needing the intermediate as a `Reduced` value (e.g.
/// [`point_add`]) should call this directly instead of `mul`, since `mul`'s own [`load`]/[`store`]
/// round trip is exactly the memory traffic profiling found dominating the transposed MSM's inner
/// loop (see the module docs) -- a `#[target_feature]` function cannot be inlined into a caller
/// that does not share its exact feature set, so every `Reduced`/`Unreduced` method call is a real
/// function boundary, and each one paid for its own load-from-memory/store-to-memory even when the
/// very next line just fed that value into another such call. Callers only needing an
/// [`Unreduced`]-quality (loose) result should call [`mul_regs_loose`] instead and skip this
/// function's [`reduce_regs`] pass -- see that function's doc comment for exactly when that's safe.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
unsafe fn mul_regs(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { reduce_regs(mul_regs_loose(a, b)) }
}

/// Register-level counterpart to [`square`], but skipping the final [`reduce_regs`] -- see
/// [`mul_regs_loose`]'s doc comment for exactly what "loose" means here and when it's safe to
/// consume: the same bound (each limb `< ~2^61.3`) and the same restrictions apply (never feed
/// this into another `mul_regs`/`square_regs`/`mul_regs_loose`/`square_regs_loose` call, or use it
/// as [`sub_regs`]'s right-hand operand).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
unsafe fn square_regs_loose(a: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let mut diag = [_mm512_setzero_si512(); 10];
        for (i, ai) in a.iter().enumerate() {
            diag[2 * i] = _mm512_madd52lo_epu64(diag[2 * i], *ai, *ai);
            diag[2 * i + 1] = _mm512_madd52hi_epu64(diag[2 * i + 1], *ai, *ai);
        }

        let mut cross = [_mm512_setzero_si512(); 10];
        for i in 0..5 {
            for j in (i + 1)..5 {
                cross[i + j] = _mm512_madd52lo_epu64(cross[i + j], a[i], a[j]);
                cross[i + j + 1] = _mm512_madd52hi_epu64(cross[i + j + 1], a[i], a[j]);
            }
        }

        let col: [_; 10] = core::array::from_fn(|k| {
            _mm512_add_epi64(diag[k], _mm512_add_epi64(cross[k], cross[k]))
        });

        // Narrow every column first, same as `mul_regs` -- see `carry_cols`'s doc comment.
        let col = carry_cols(col);

        let fold_608 = _mm512_set1_epi64(super::FOLD_608 as i64);
        let mut folded = [_mm512_setzero_si512(); 5];
        for k in 0..5 {
            let scaled = _mm512_mullo_epi64(col[k + 5], fold_608);
            folded[k] = _mm512_add_epi64(col[k], scaled);
        }

        folded
    }
}

/// Register-level counterpart to [`square`]; see [`mul_regs`] for why callers chaining several
/// primitive operations should prefer this over [`square`] directly, and [`mul_regs_loose`] for
/// when to call [`square_regs_loose`] instead and skip this function's [`reduce_regs`] pass.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
unsafe fn square_regs(a: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { reduce_regs(square_regs_loose(a)) }
}

/// Register-level counterpart to [`add`]: an [`Unreduced`]-equivalent (not fully reduced) result,
/// same as `add` -- see [`mul_regs`] for why callers chaining several primitive operations should
/// prefer this over `add` directly.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn add_regs(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { carry(add_raw(a, b)) }
}

/// Elementwise add with no [`carry`] pass -- callers immediately chaining this into another
/// `add_raw`/`sub_raw` or straight into [`reduce_regs`] should use this instead of [`add_regs`] to
/// skip a wasted intermediate carry pass. See [`sub_raw`]'s doc comment for the bound argument
/// covering both.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn add_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| _mm512_add_epi64(a[i], b[i]))
}

/// Register-level counterpart to [`sub`]; see [`mul_regs`] for why callers chaining several
/// primitive operations should prefer this over `sub` directly.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn sub_regs(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { carry(sub_raw(a, b)) }
}

/// Elementwise biased-subtract with no [`carry`] pass -- callers immediately chaining this into
/// another `add_raw`/`sub_raw` or straight into [`reduce_regs`] should use this instead of
/// [`sub_regs`] to skip a wasted intermediate carry pass: every current call site either feeds the
/// result straight to [`reduce_regs`] (which runs three carry passes regardless of how loose its
/// input is -- see [`mul_regs_loose`]'s doc comment for that bound argument) or chains one more
/// raw op first. Chaining raw ops before finally reducing keeps every intermediate a valid, if
/// loose, redundant-radix-52 value (each limb independently `<= a[i] + SUB_BIAS[i]`, comfortably
/// under `2^57` even after two chained raw subtracts starting from a loose
/// [`mul_regs_loose`]-quality operand, `~2^61.3` from `2^61.3 + SUB_BIAS ~2^56`) -- nowhere near a
/// `u64` lane overflow, and no less resolvable by three [`carry`] passes than the already-tested
/// `~2^61.3` fold-output bound.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (for [`super::SUB_BIAS`]'s 64-bit
/// per-limb constant).
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn sub_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| {
        let biased = _mm512_add_epi64(a[i], _mm512_set1_epi64(super::SUB_BIAS[i] as i64));
        _mm512_sub_epi64(biased, b[i])
    })
}

/// Reduces an [`Unreduced`] value so every limb is strictly `< 2^52`. Callers must check
/// [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
pub(crate) unsafe fn reduce(a: &Unreduced) -> Reduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(reduce_regs(load(&a.limbs)));
        Reduced { limbs }
    }
}

/// Multiplies two [`Reduced`] values via AVX-512 IFMA, returning a [`Reduced`] result. Callers
/// must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
pub(crate) unsafe fn mul(a: &Reduced, b: &Reduced) -> Reduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(mul_regs(load(&a.limbs), load(&b.limbs)));
        Reduced { limbs }
    }
}

/// Squares a [`Reduced`] value via AVX-512 IFMA, returning a [`Reduced`] result. Callers must
/// check [`available`] first.
///
/// Dedicated formula rather than `mul(a, a)`, mirroring [`super::square_lane`]: every cross term
/// `a[i]*a[j]` (`i != j`) is accumulated into a separate `cross` column once, then folded into the
/// diagonal (`i == j`) column via a single doubling add (`vpaddq`) instead of a second
/// `vpmadd52lo`/`vpmadd52hi` pair -- 15 multiply-accumulates here versus 25 in [`mul`].
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
pub(crate) unsafe fn square(a: &Reduced) -> Reduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(square_regs(load(&a.limbs)));
        Reduced { limbs }
    }
}

/// Adds two [`Unreduced`] values via AVX-512. Callers must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
pub(crate) unsafe fn add(a: &Unreduced, b: &Unreduced) -> Unreduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(add_regs(load(&a.limbs), load(&b.limbs)));
        Unreduced { limbs }
    }
}

/// Subtracts two [`Unreduced`] values via AVX-512. Callers must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512DQ (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512dq")]
pub(crate) unsafe fn sub(a: &Unreduced, b: &Unreduced) -> Unreduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(sub_regs(load(&a.limbs), load(&b.limbs)));
        Unreduced { limbs }
    }
}

/// Fused point addition: the entire Hisil-Wong-Carter-Dawson unified addition formula (see
/// [`crate::signing::point::PointVec::add`]) computed with every intermediate (`a`, `b`, `t1t2`,
/// `td`, `c`, `zz`, `dd`, `e`, `f`, `g`, `h`) held in registers via [`mul_regs`]/[`add_regs`]/
/// [`sub_regs`]/[`reduce_regs`], rather than chaining the separate `Reduced`/`Unreduced` methods
/// (each of which pays for its own [`load`]/[`store`] round trip -- see [`mul_regs`]'s doc
/// comment). Only the 8 operand coordinates and the `2*d` constant are loaded, and only the 4
/// output coordinates are stored, no matter how many field operations the formula chains in
/// between. Callers must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn point_add(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
    at: &Reduced,
    bx: &Reduced,
    by: &Reduced,
    bz: &Reduced,
    bt: &Reduced,
    two_d: &Reduced,
) -> (Reduced, Reduced, Reduced, Reduced) {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let (x1, y1, z1, t1) = (
            load(&ax.limbs),
            load(&ay.limbs),
            load(&az.limbs),
            load(&at.limbs),
        );
        let (x2, y2, z2, t2) = (
            load(&bx.limbs),
            load(&by.limbs),
            load(&bz.limbs),
            load(&bt.limbs),
        );
        let two_d = load(&two_d.limbs);

        // Every `sub_regs`/`add_regs` call below was immediately wrapped in an explicit
        // `reduce_regs` (or feeds one after one more raw combine), which already runs three carry
        // passes over whatever comes in regardless of looseness -- so `sub_regs`/`add_regs`'s own
        // single internal carry pass was wasted work, immediately superseded. `sub_raw`/`add_raw`
        // skip it; see `sub_raw`'s doc comment for the bound argument.
        let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
        // `b` is only ever consumed as `sub_regs`'s *left*-hand operand (`e` below) or as an
        // `add_regs` operand (`h` below) -- never the right-hand side of a subtraction, so
        // `mul_regs_loose`'s bound is safe here (see that function's doc comment).
        let b = mul_regs_loose(
            reduce_regs(add_raw(y1, x1)),
            reduce_regs(add_raw(y2, x2)),
        );
        let t1t2 = mul_regs(t1, t2);
        // `two_d` is `2*d`, folding in the doubling `c = td.add(&td)` the non-fused formula does
        // separately -- one multiply-by-a-reduced-constant instead of a multiply plus an add.
        // `c` feeds `sub_raw(dd, c)` (`f` below) as the right-hand operand, so it must stay fully
        // reduced.
        let c = mul_regs(t1t2, two_d);
        // `zz` (and thus `dd`) is only ever an `add_raw`/`sub_raw`-left-hand-side operand below
        // (never a subtraction's right-hand side), same reasoning as `b`; left raw since it only
        // ever feeds another raw op before `reduce_regs`.
        let zz = mul_regs_loose(z1, z2);
        let dd = add_raw(zz, zz);
        let e = reduce_regs(sub_raw(b, a));
        let f = reduce_regs(sub_raw(dd, c));
        let g = reduce_regs(add_raw(dd, c));
        let h = reduce_regs(add_raw(b, a));

        (
            Reduced {
                limbs: store(mul_regs(e, f)),
            },
            Reduced {
                limbs: store(mul_regs(g, h)),
            },
            Reduced {
                limbs: store(mul_regs(f, g)),
            },
            Reduced {
                limbs: store(mul_regs(e, h)),
            },
        )
    }
}

/// Fused point doubling: the dedicated `dbl-2008-hwcd` formula (see
/// [`crate::signing::point::PointVec::double`]), with every intermediate held in registers, same
/// [`point_add`] pattern and for the same reason (see that function's doc comment). Only the 3
/// input coordinates (doubling never reads `t`) and the 4 output coordinates touch memory.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F, AVX-512IFMA, AVX-512VL, and AVX-512DQ (checked
/// by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma,avx512vl,avx512dq")]
pub(crate) unsafe fn point_double(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
) -> (Reduced, Reduced, Reduced, Reduced) {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let (x, y, z) = (load(&ax.limbs), load(&ay.limbs), load(&az.limbs));

        // `a`/`b` are each used as `sub_regs`'s *right*-hand operand below (in `e`'s and `h`'s
        // inner subtractions, and directly in `g`), so both must stay fully reduced.
        let a = square_regs(x);
        let b = square_regs(y);
        // `c0` is only ever consumed by `add_regs` (`c` below) -- never a subtraction's right-hand
        // side -- so `square_regs_loose` is safe here (see that function's doc comment). `c`
        // itself does become `sub_regs(g, c)`'s right-hand operand, so it keeps its explicit
        // `reduce_regs` rather than relying on `add_regs`'s own single pass.
        let c0 = square_regs_loose(z);
        // Every `sub_regs`/`add_regs` below (including this one) was immediately wrapped in
        // `reduce_regs`, or feeds one after one more raw combine -- `sub_raw`/`add_raw` skip the
        // wasted intermediate carry pass that would just get superseded; see that function's doc
        // comment for the bound argument.
        let c = reduce_regs(add_raw(c0, c0));
        // `xy2` is only ever `sub_regs(xy2, a)`'s *left*-hand operand (`e` below), never a
        // right-hand side, so it's safe loose too.
        let xy2 = square_regs_loose(reduce_regs(add_raw(x, y)));
        let e = reduce_regs(sub_raw(sub_raw(xy2, a), b));
        let g = reduce_regs(sub_raw(b, a));
        let f = reduce_regs(sub_raw(g, c));
        // `h = -a - b`: no zero-constant load needed, `_mm512_setzero_si512` is free.
        let zero = [_mm512_setzero_si512(); 5];
        let h = reduce_regs(sub_raw(sub_raw(zero, a), b));

        (
            Reduced {
                limbs: store(mul_regs(e, f)),
            },
            Reduced {
                limbs: store(mul_regs(g, h)),
            },
            Reduced {
                limbs: store(mul_regs(f, g)),
            },
            Reduced {
                limbs: store(mul_regs(e, h)),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::test_support::rand_field_element;
    use commonware_utils::test_rng;

    fn rand_pair(rng: &mut impl rand_core::Rng) -> (Reduced, Reduced) {
        let a: [_; super::super::LANES] = core::array::from_fn(|_| rand_field_element(rng));
        let b: [_; super::super::LANES] = core::array::from_fn(|_| rand_field_element(rng));
        (
            Unreduced::from_lanes(&a).reduce(),
            Unreduced::from_lanes(&b).reduce(),
        )
    }

    /// A no-op everywhere except on genuine AVX-512 hardware: this repository's own development
    /// machine cannot execute this backend at all (see the module docs), so these tests exist to
    /// validate the backend wherever it *can* run (e.g. contributor hardware or future CI runners
    /// with AVX-512), not to provide coverage on this platform.
    macro_rules! skip_unless_available {
        () => {
            if !available() {
                return;
            }
        };
    }

    #[test]
    fn matches_portable_mul_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        for _ in 0..64 {
            let (a, b) = rand_pair(&mut rng);
            // SAFETY: `available()` returned true above.
            let actual = unsafe { mul(&a, &b) }.to_lanes();
            // Compare against `mul_portable` specifically, not the dispatching `mul`: on hardware
            // where `available()` is true, `mul` itself would take this same AVX-512 path.
            let expected = a.mul_portable(&b).to_lanes();
            for i in 0..super::super::LANES {
                assert!(actual[i].eq(&expected[i]));
            }
        }
    }

    #[test]
    fn matches_portable_square_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        for _ in 0..64 {
            let (a, _) = rand_pair(&mut rng);
            // SAFETY: `available()` returned true above.
            let actual = unsafe { square(&a) }.to_lanes();
            let expected = a.square_portable().to_lanes();
            for i in 0..super::super::LANES {
                assert!(actual[i].eq(&expected[i]));
            }
        }
    }

    #[test]
    fn matches_portable_add_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        for _ in 0..64 {
            let (a, b) = rand_pair(&mut rng);
            let (a, b) = (Unreduced::from(a), Unreduced::from(b));
            // SAFETY: `available()` returned true above.
            let actual = unsafe { add(&a, &b) }.to_lanes();
            let expected = a.add_portable(&b).to_lanes();
            for i in 0..super::super::LANES {
                assert!(actual[i].eq(&expected[i]));
            }
        }
    }

    #[test]
    fn matches_portable_sub_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        for _ in 0..64 {
            let (a, b) = rand_pair(&mut rng);
            let (a, b) = (Unreduced::from(a), Unreduced::from(b));
            // SAFETY: `available()` returned true above.
            let actual = unsafe { sub(&a, &b) }.to_lanes();
            let expected = a.sub_portable(&b).to_lanes();
            for i in 0..super::super::LANES {
                assert!(actual[i].eq(&expected[i]));
            }
        }
    }

    /// Regression test for a specific value found, via careful isolation on real AVX-512
    /// hardware, to break [`mul`] when squared: every limb of this value is already strictly
    /// `< 2^52` (a valid [`Reduced`] per [`super::reduce_limbs`]'s bound, confirmed identical
    /// between the AVX-512 and portable `reduce` outputs immediately before the failing multiply),
    /// yet `mul(&r, &r)` disagrees with [`Reduced::mul_portable`] on every lane when this value is
    /// splatted uniformly -- so the divergence is in the multiply's column accumulation itself, not
    /// in boundedness or cross-lane contamination (isolated by comparing lane-by-lane; only ever
    /// this exact bit pattern has been found to trigger it). Constructed via
    /// [`Reduced::from_raw_limbs_for_test`] rather than `Unreduced::from_lanes(..).reduce()`
    /// because that round trip is not guaranteed to reproduce the exact bit pattern that triggers
    /// this (multiple "loose" limb representations can encode the same field value, and only some
    /// of them trigger the bug).
    #[test]
    fn mul_matches_portable_for_known_bad_value_on_real_hardware() {
        skip_unless_available!();
        const BAD_LIMBS: [u64; 5] = [
            3861911732996160,
            3597670383495455,
            2658354966848412,
            4433374780423169,
            3956073920996080,
        ];
        for limb in BAD_LIMBS {
            assert!(limb < (1u64 << 52));
        }
        let limbs: [[u64; super::super::LANES]; 5] =
            core::array::from_fn(|i| [BAD_LIMBS[i]; super::super::LANES]);
        let r = Reduced::from_raw_limbs_for_test(limbs);
        // SAFETY: `available()` returned true above.
        let actual = unsafe { mul(&r, &r) }.to_lanes();
        let expected = r.mul_portable(&r).to_lanes();
        for i in 0..super::super::LANES {
            assert!(
                actual[i].eq(&expected[i]),
                "lane {i}: actual={actual:?} expected={expected:?}"
            );
        }
    }

    #[test]
    fn matches_portable_reduce_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        for _ in 0..64 {
            let lanes: [_; super::super::LANES] =
                core::array::from_fn(|_| rand_field_element(&mut rng));
            let unreduced = Unreduced::from_lanes(&lanes);
            // SAFETY: `available()` returned true above.
            let actual = unsafe { reduce(&unreduced) }.to_lanes();
            let expected = unreduced.reduce_portable().to_lanes();
            for i in 0..super::super::LANES {
                assert!(actual[i].eq(&expected[i]));
            }
        }
    }

    /// [`point_add`] against the same Hisil-Wong-Carter-Dawson formula written out against the
    /// `_portable` methods specifically (not the dispatching ones, which would also take this
    /// same AVX-512 path on hardware where `available()` is true) -- this is the fused function's
    /// correctness check, independent of [`crate::signing::point::PointVec::add`]'s own tests
    /// (which exercise it too, but only via the dispatching path).
    #[test]
    fn point_add_matches_portable_formula_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        let rand_reduced = |rng: &mut _| {
            let lanes: [_; super::super::LANES] = core::array::from_fn(|_| rand_field_element(rng));
            Unreduced::from_lanes(&lanes).reduce()
        };
        for _ in 0..64 {
            let (ax, ay, az, at) = (
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
            );
            let (bx, by, bz, bt) = (
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
            );
            let two_d = super::super::EDWARDS_D_TIMES_2;

            // SAFETY: `available()` returned true above.
            let actual = unsafe { point_add(&ax, &ay, &az, &at, &bx, &by, &bz, &bt, &two_d) };

            let y1mx1 = Unreduced::from(ay)
                .sub_portable(&Unreduced::from(ax))
                .reduce_portable();
            let y2mx2 = Unreduced::from(by)
                .sub_portable(&Unreduced::from(bx))
                .reduce_portable();
            let a_val = y1mx1.mul_portable(&y2mx2);
            let y1px1 = Unreduced::from(ay)
                .add_portable(&Unreduced::from(ax))
                .reduce_portable();
            let y2px2 = Unreduced::from(by)
                .add_portable(&Unreduced::from(bx))
                .reduce_portable();
            let b_val = y1px1.mul_portable(&y2px2);
            let t1t2 = at.mul_portable(&bt);
            let c = t1t2.mul_portable(&two_d);
            let zz = az.mul_portable(&bz);
            let dd = Unreduced::from(zz).add_portable(&Unreduced::from(zz));
            let e = Unreduced::from(b_val)
                .sub_portable(&Unreduced::from(a_val))
                .reduce_portable();
            let f = dd.sub_portable(&Unreduced::from(c)).reduce_portable();
            let g = dd.add_portable(&Unreduced::from(c)).reduce_portable();
            let h = Unreduced::from(b_val)
                .add_portable(&Unreduced::from(a_val))
                .reduce_portable();
            let expected = (
                e.mul_portable(&f),
                g.mul_portable(&h),
                f.mul_portable(&g),
                e.mul_portable(&h),
            );

            let actual_lanes = (
                actual.0.to_lanes(),
                actual.1.to_lanes(),
                actual.2.to_lanes(),
                actual.3.to_lanes(),
            );
            let expected_lanes = (
                expected.0.to_lanes(),
                expected.1.to_lanes(),
                expected.2.to_lanes(),
                expected.3.to_lanes(),
            );
            for i in 0..super::super::LANES {
                assert!(actual_lanes.0[i].eq(&expected_lanes.0[i]), "x lane {i}");
                assert!(actual_lanes.1[i].eq(&expected_lanes.1[i]), "y lane {i}");
                assert!(actual_lanes.2[i].eq(&expected_lanes.2[i]), "z lane {i}");
                assert!(actual_lanes.3[i].eq(&expected_lanes.3[i]), "t lane {i}");
            }
        }
    }

    /// Same structure as [`point_add_matches_portable_formula_on_real_hardware`], but for
    /// [`point_double`] against the `dbl-2008-hwcd` formula written out with the portable
    /// kernels directly.
    #[test]
    fn point_double_matches_portable_formula_on_real_hardware() {
        skip_unless_available!();
        let mut rng = test_rng();
        let rand_reduced = |rng: &mut _| {
            let lanes: [_; super::super::LANES] = core::array::from_fn(|_| rand_field_element(rng));
            Unreduced::from_lanes(&lanes).reduce()
        };
        for _ in 0..64 {
            let (ax, ay, az) = (
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
            );

            // SAFETY: `available()` returned true above.
            let actual = unsafe { point_double(&ax, &ay, &az) };

            let a_val = ax.mul_portable(&ax);
            let b_val = ay.mul_portable(&ay);
            let c0 = az.mul_portable(&az);
            let c = Unreduced::from(c0)
                .add_portable(&Unreduced::from(c0))
                .reduce_portable();
            let xy = Unreduced::from(ax)
                .add_portable(&Unreduced::from(ay))
                .reduce_portable();
            let xy2 = xy.mul_portable(&xy);
            let e_step1 = Unreduced::from(xy2)
                .sub_portable(&Unreduced::from(a_val))
                .reduce_portable();
            let e = Unreduced::from(e_step1)
                .sub_portable(&Unreduced::from(b_val))
                .reduce_portable();
            let g = Unreduced::from(b_val)
                .sub_portable(&Unreduced::from(a_val))
                .reduce_portable();
            let f = Unreduced::from(g)
                .sub_portable(&Unreduced::from(c))
                .reduce_portable();
            let zero = Reduced::from_raw_limbs_for_test([[0; super::super::LANES]; 5]);
            let h_step1 = Unreduced::from(zero)
                .sub_portable(&Unreduced::from(a_val))
                .reduce_portable();
            let h = Unreduced::from(h_step1)
                .sub_portable(&Unreduced::from(b_val))
                .reduce_portable();

            let expected = (
                e.mul_portable(&f),
                g.mul_portable(&h),
                f.mul_portable(&g),
                e.mul_portable(&h),
            );

            let actual_lanes = (
                actual.0.to_lanes(),
                actual.1.to_lanes(),
                actual.2.to_lanes(),
                actual.3.to_lanes(),
            );
            let expected_lanes = (
                expected.0.to_lanes(),
                expected.1.to_lanes(),
                expected.2.to_lanes(),
                expected.3.to_lanes(),
            );
            for i in 0..super::super::LANES {
                assert!(actual_lanes.0[i].eq(&expected_lanes.0[i]), "x lane {i}");
                assert!(actual_lanes.1[i].eq(&expected_lanes.1[i]), "y lane {i}");
                assert!(actual_lanes.2[i].eq(&expected_lanes.2[i]), "z lane {i}");
                assert!(actual_lanes.3[i].eq(&expected_lanes.3[i]), "t lane {i}");
            }
        }
    }
}
