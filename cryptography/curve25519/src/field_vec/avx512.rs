//! AVX-512 IFMA backend for [`Reduced`]/[`Unreduced`] arithmetic (multiplication, addition,
//! subtraction, reduction), at radix `2^51` -- see the [`super`] module docs for why 51 and not
//! the instructions' native split point of 52.
//!
//! # Hardware history, and the bound discipline
//!
//! Real-hardware testing of this module's radix-52 predecessor found multiple silent-corruption
//! bugs, all of one family: `vpmadd52lo`/`vpmadd52hi` read *exactly* the low 52 bits of each
//! input lane and silently discard anything above bit 51, and at radix 52 a fully reduced limb
//! sat one ULP below that cliff -- so any value that dodged its (three-pass, sequential-ripple)
//! reduction, or any internal column that crossed `2^64` before its fold-multiply, corrupted
//! results with no error signal. The [`Reduced`]/[`Unreduced`] type split was introduced to make
//! "operand skipped reduction before a multiply" a compile error, and remains load-bearing here.
//!
//! At radix 51 the same discipline holds but with margin instead of a cliff: a [`Reduced`] limb
//! is at most [`super::REDUCED_BOUND`] (`~2^51`), a factor of two below the instructions' `2^52`
//! ceiling, and every internal bound in this module (documented per call site) tops out around
//! `2^60`, a factor of eight below `u64` overflow. Reduction is a single parallel carry pass
//! ([`reduce_regs`]) rather than the old three sequential ripple passes -- the central win of the
//! radix change (measured ~9 versus ~50 cycles of dependent latency on the EPYC 9354P).
//!
//! If this backend is ever suspected of a similar failure again, re-validate it against this
//! module's own `matches_portable_*_on_real_hardware` tests (which include operands at exactly
//! [`super::REDUCED_BOUND`], the documented worst case) plus
//! `signing::msm::tests::transposed_matches_scalar`, on real AVX-512 hardware, before trusting it.
//!
//! # Design
//!
//! `vpmadd52luq`/`vpmadd52huq` each compute, per 64-bit lane, `acc += low52(a*b)` /
//! `acc += high52(a*b)` for inputs strictly below `2^52` -- an accumulating multiply. The
//! schoolbook product of two 5-limb radix-51 numbers has 25 `a[i]*b[j]` terms; each term's low
//! half lands on column `i+j` with coefficient 1, and because the instructions split at bit 52
//! (not 51), its high half lands on column `i+j+1` with coefficient **2** (`2^52 = 2 * 2^51`). So
//! low-half and high-half terms accumulate into two separate register chains (`lo[k]`, `hi[k]`),
//! combined at the end as `z[k] = lo[k] + 2*hi[k]` -- one doubling add per column, no shifts. The
//! multiply-accumulate count (25 + 25) is identical to the radix-52 version's; only the combine
//! differs. Columns 5-9 (weight `>= 2^255`) fold back onto columns 0-4 via `2^255 = 19 (mod p)`,
//! with `19*z` computed as `(z << 4) + (z << 1) + z` ([`mul19`]) -- plain shifts and adds, chosen
//! over `vpmullq` (slow on Intel) and over extra IFMA operations (expensive on double-pumped
//! Zen 4, whose single 512-bit IFMA slot per cycle is the scarce resource) so one code path is
//! sound on every AVX-512 core. [`add`]/[`sub`] are an elementwise `vpaddq`/biased `vpsubq`
//! followed by a single [`reduce_regs`] pass.

use super::{Reduced, Unreduced};
use core::arch::x86_64::*;

/// Feature set this backend requires: AVX-512F for the 512-bit integer add/shift/mask operations,
/// and AVX-512 IFMA for the 52x52-bit multiply-accumulates.
pub(crate) fn available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
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

/// `19*z` via `(z << 4) + (z << 1) + z`: 2 shifts + 2 adds per call, all on ports the IFMA
/// operations don't use. Callers must guarantee `z < 2^59` per lane so `z << 4` cannot overflow
/// (every call site here is bounded well under that; see [`mul_regs_loose`]/[`reduce_regs`]).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn mul19(z: __m512i) -> __m512i {
    _mm512_add_epi64(
        _mm512_add_epi64(_mm512_slli_epi64(z, 4), _mm512_slli_epi64(z, 1)),
        z,
    )
}

/// Vectorized counterpart to [`super::reduce_limbs`]: the *entire* reduction, as one parallel
/// pass. All five carry-outs are computed from the original limbs at once (no ripple -- the spare
/// bit below the multiplier's 52-bit ceiling is what makes one pass sufficient; see the [`super`]
/// module docs), all five limbs masked at once, and all five carry-ins added at once, with limb
/// 4's carry folded onto limb 0 via `2^255 = 19`. Dependency depth ~4 operations, versus the
/// radix-52 predecessor's three sequential ripple passes.
///
/// Accepts any input with limbs `<= 2^63` (every caller in this module is bounded `< 2^61`; see
/// the per-site comments) and produces limbs `<= super::REDUCED_BOUND` -- see that constant's
/// derivation. The carried value `c4 <= 2^12` keeps [`mul19`]'s shift trivially safe.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn reduce_regs(l: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let mask = _mm512_set1_epi64(super::MASK_51 as i64);
        let c: [__m512i; 5] = core::array::from_fn(|i| _mm512_srli_epi64(l[i], 51));
        [
            _mm512_add_epi64(_mm512_and_si512(l[0], mask), mul19(c[4])),
            _mm512_add_epi64(_mm512_and_si512(l[1], mask), c[0]),
            _mm512_add_epi64(_mm512_and_si512(l[2], mask), c[1]),
            _mm512_add_epi64(_mm512_and_si512(l[3], mask), c[2]),
            _mm512_add_epi64(_mm512_and_si512(l[4], mask), c[3]),
        ]
    }
}

/// Register-level schoolbook multiply, left "loose": the full radix-51 product, folded onto 5
/// limbs, but with no reduction -- each output limb is bounded by `~2^59.3` (see below). Callers
/// chain raw adds/subtractions on the result and run one [`reduce_regs`] pass before the next
/// multiply; see the [`super`] module docs for the discipline and [`point_add`] for it in action.
///
/// Bound derivation, for inputs bounded by [`super::REDUCED_BOUND`] (`< 2^51.001`): each product
/// term is `< 2^102.002`, so its low half is `< 2^52` and its high half `< 2^50.002`. A column
/// accumulates at most 5 of each: `lo[k] < 2^54.33`, `hi[k] < 2^52.33`, so `z[k] = lo[k] +
/// 2*hi[k] < 2^54.92`. The fold adds `19 * z[k+5] < 2^59.17` (within [`mul19`]'s `< 2^59` shift
/// requirement for its input, since `z[k+5] < 2^54.92`), for a final bound of `2^54.92 + 2^59.17
/// < 2^59.3` -- far from `u64` overflow even after several raw add/sub chains, and within
/// [`reduce_regs`]'s `2^63` input contract with room for those chains on top.
///
/// Callers must not feed this into another multiply without reducing first (IFMA's `2^52` input
/// ceiling), and must not use it as [`sub_raw`]'s *right-hand* operand ([`super::SUB_BIAS`]'s
/// `~2^55` limbs only dominate [`Reduced`]-quality values). It *is* safe as [`add_raw`]'s operand
/// (either side) or [`sub_raw`]'s left-hand operand.
///
/// The two accumulator chains (`lo`, `hi`) total ~18 live registers plus the 10 input limbs --
/// close to the 32 zmm registers available. An earlier radix-52 experiment with split
/// accumulators regressed the fused point ops on spill traffic; the difference here is that the
/// split buys the single-pass reduction (structural), not just instruction scheduling, but watch
/// benchmark results for spill regressions all the same.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn mul_regs_loose(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        // Low-half terms (coefficient 1) on columns 0-8; high-half terms (coefficient 2, since
        // the instructions split at bit 52 = 2 * 2^51) on columns 1-9. `lo[9]`/`hi[0]` stay zero.
        let mut lo = [_mm512_setzero_si512(); 10];
        let mut hi = [_mm512_setzero_si512(); 10];
        for i in 0..5 {
            for j in 0..5 {
                lo[i + j] = _mm512_madd52lo_epu64(lo[i + j], a[i], b[j]);
                hi[i + j + 1] = _mm512_madd52hi_epu64(hi[i + j + 1], a[i], b[j]);
            }
        }

        // Combine the coefficient-2 chain with one doubling add per column.
        let z: [__m512i; 10] =
            core::array::from_fn(|k| _mm512_add_epi64(lo[k], _mm512_add_epi64(hi[k], hi[k])));

        // Fold columns 5-9 (weight >= 2^255) back onto columns 0-4 via 2^255 = 19 (mod p):
        // column `5+k` has exactly `19 * 2^(51k)`'s weight relative to column `k`.
        core::array::from_fn(|k| _mm512_add_epi64(z[k], mul19(z[k + 5])))
    }
}

/// Register-level counterpart to [`mul`]: [`mul_regs_loose`] plus the single [`reduce_regs`]
/// pass, returning [`Reduced`]-quality limbs. Callers chaining multiple primitive operations
/// without needing the intermediate in memory (e.g. [`point_add`]) should call this (or the
/// loose variant) directly instead of `mul`, since `mul`'s own [`load`]/[`store`] round trip is
/// exactly the memory traffic profiling found dominating the transposed MSM's inner loop -- a
/// `#[target_feature]` function cannot be inlined into a caller that does not share its feature
/// set, so every `Reduced`/`Unreduced` method call is a real function boundary paying its own
/// loads and stores.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn mul_regs(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { reduce_regs(mul_regs_loose(a, b)) }
}

/// Register-level squaring, left "loose" -- same output bound and consumption rules as
/// [`mul_regs_loose`] (the column values are identical to `mul_regs_loose(a, a)`'s; only the
/// instruction count differs).
///
/// Each unique product `a[i]*a[j]` (`i < j`) appears twice in the square, so it is computed once
/// and its coefficient doubled: with the high-half split's own factor of 2, terms carry
/// coefficients 1 (diagonal low halves), 2 (diagonal high halves and cross low halves), or 4
/// (cross high halves), accumulated in three chains and combined per column as `c1 + 2*c2 +
/// 4*c4`. 15 unique products = 30 multiply-accumulates, versus [`mul_regs_loose`]'s 50. The
/// `c4[k] << 2` is safe: `c4[k]` accumulates at most 4 high-half terms, `< 2^52`.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn square_regs_loose(a: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let mut c1 = [_mm512_setzero_si512(); 10];
        let mut c2 = [_mm512_setzero_si512(); 10];
        let mut c4 = [_mm512_setzero_si512(); 10];
        for i in 0..5 {
            c1[2 * i] = _mm512_madd52lo_epu64(c1[2 * i], a[i], a[i]);
            c2[2 * i + 1] = _mm512_madd52hi_epu64(c2[2 * i + 1], a[i], a[i]);
            for j in (i + 1)..5 {
                c2[i + j] = _mm512_madd52lo_epu64(c2[i + j], a[i], a[j]);
                c4[i + j + 1] = _mm512_madd52hi_epu64(c4[i + j + 1], a[i], a[j]);
            }
        }

        let z: [__m512i; 10] = core::array::from_fn(|k| {
            _mm512_add_epi64(
                c1[k],
                _mm512_add_epi64(_mm512_add_epi64(c2[k], c2[k]), _mm512_slli_epi64(c4[k], 2)),
            )
        });

        core::array::from_fn(|k| _mm512_add_epi64(z[k], mul19(z[k + 5])))
    }
}

/// Register-level counterpart to [`square`]; see [`mul_regs`] for when to call this rather than
/// the memory-round-tripping method, and [`square_regs_loose`] to skip the reduction pass.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn square_regs(a: [__m512i; 5]) -> [__m512i; 5] {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe { reduce_regs(square_regs_loose(a)) }
}

/// Elementwise add with no reduction pass -- the natural operation between multiplies at this
/// radix (looseness accumulates a bit per chained add and the consumer's single [`reduce_regs`]
/// pass absorbs all of it; see the [`super`] module docs). Both operands may be loose (bounded
/// per call site; every site here keeps the raw sum under [`reduce_regs`]'s `2^63` contract with
/// a wide margin).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn add_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| _mm512_add_epi64(a[i], b[i]))
}

/// Elementwise biased subtract with no reduction pass, computing `a + 16p - b` limb-wise (see
/// [`super::SUB_BIAS`]). The *right-hand* operand must be [`Reduced`]-quality (`<= REDUCED_BOUND`,
/// which the `~2^55` bias limbs dominate); the left-hand operand may be loose (up to `~2^60` at
/// the sites here -- adding the `~2^55` bias stays far below [`reduce_regs`]'s `2^63` contract,
/// even chained twice as in [`point_double`]'s `e`/`h`).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F.
#[target_feature(enable = "avx512f")]
unsafe fn sub_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| {
        let biased = _mm512_add_epi64(a[i], _mm512_set1_epi64(super::SUB_BIAS[i] as i64));
        _mm512_sub_epi64(biased, b[i])
    })
}

/// Reduces an [`Unreduced`] value to [`Reduced`]'s bound via the single parallel pass. Callers
/// must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F (checked by [`available`]).
#[target_feature(enable = "avx512f")]
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
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn mul(a: &Reduced, b: &Reduced) -> Reduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(mul_regs(load(&a.limbs), load(&b.limbs)));
        Reduced { limbs }
    }
}

/// Squares a [`Reduced`] value via AVX-512 IFMA, returning a [`Reduced`] result. Callers must
/// check [`available`] first. See [`square_regs_loose`] for why this is cheaper than `mul(a, a)`
/// (30 multiply-accumulates versus 50).
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn square(a: &Reduced) -> Reduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(square_regs(load(&a.limbs)));
        Reduced { limbs }
    }
}

/// Adds two [`Unreduced`] values via AVX-512. The result carries a fresh [`reduce_regs`] pass so
/// it satisfies the public [`Unreduced`] looseness bound regardless of the operands'. Callers
/// must check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F (checked by [`available`]).
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn add(a: &Unreduced, b: &Unreduced) -> Unreduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(reduce_regs(add_raw(load(&a.limbs), load(&b.limbs))));
        Unreduced { limbs }
    }
}

/// Subtracts two [`Unreduced`] values via AVX-512; see [`add`]. Callers must check [`available`]
/// first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F (checked by [`available`]).
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn sub(a: &Unreduced, b: &Unreduced) -> Unreduced {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let limbs = store(reduce_regs(sub_raw(load(&a.limbs), load(&b.limbs))));
        Unreduced { limbs }
    }
}

/// Fused point addition: the entire Hisil-Wong-Carter-Dawson unified addition formula (see
/// [`crate::signing::point::PointVec::add`]) computed with every intermediate held in registers,
/// rather than chaining the separate `Reduced`/`Unreduced` methods (each of which pays for its
/// own [`load`]/[`store`] round trip -- see [`mul_regs`]'s doc comment). Only the 8 operand
/// coordinates and the `2*d` constant are loaded, and only the 4 output coordinates are stored,
/// no matter how many field operations the formula chains in between. Callers must check
/// [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
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

        // Bound audit (inputs are `Reduced`, `< 2^51.001`): each `sub_raw` below has a `Reduced`
        // right-hand operand as `sub_raw` requires; raw sums/differences top out at `~2^60.4`
        // (`dd + bias` in `f`), inside `reduce_regs`'s `2^63` contract.
        //
        // `a` must be fully reduced: it is `sub_raw(b, a)`'s *right-hand* operand in `e`.
        let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
        // `b` is only ever consumed as `sub_raw`'s left-hand operand (`e`) or as an `add_raw`
        // operand (`h`) -- never a subtraction's right-hand side -- so it stays loose (`< 2^59.3`).
        let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
        let t1t2 = mul_regs(t1, t2);
        // `two_d` is `2*d`, folding in the doubling `c = td + td` the non-fused formula does
        // separately. `c` feeds `sub_raw(dd, c)` (`f`) as the right-hand operand, so it must stay
        // fully reduced.
        let c = mul_regs(t1t2, two_d);
        // `zz` (and thus `dd`, `< 2^60.3`) is only ever a left-hand/add operand below.
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

/// Fused mixed-addition point add: the entire mixed-addition formula (see
/// [`crate::signing::point::PointVec::add_mixed`]) computed with every intermediate held in
/// registers, same [`point_add`] pattern and for the same reason. One fewer operand than
/// [`point_add`]'s 9 (`bz` is never loaded -- `rhs`'s `Z` is implicitly `1` -- and `bt2d` is a
/// single already-precomputed input rather than `point_add`'s separate `bt`/`two_d`). Callers must
/// check [`available`] first.
///
/// # Safety
///
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn point_add_mixed(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
    at: &Reduced,
    bx: &Reduced,
    by: &Reduced,
    bt2d: &Reduced,
) -> (Reduced, Reduced, Reduced, Reduced) {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let (x1, y1, z1, t1) = (
            load(&ax.limbs),
            load(&ay.limbs),
            load(&az.limbs),
            load(&at.limbs),
        );
        let (x2, y2) = (load(&bx.limbs), load(&by.limbs));
        let bt2d = load(&bt2d.limbs);

        // Same bound audit as `point_add`: every `sub_raw` right-hand operand below is `Reduced`,
        // and the loosest raw value (`sub_raw(b, a)` in `e`, `< 2^59.4`) is far inside
        // `reduce_regs`'s contract.
        let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
        let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
        // `c = t1 * bt2d`: `bt2d` already folds in the `2d` factor (precomputed once per point;
        // see [`crate::signing::point::MixedPoint::new`]), so this is a single multiply where
        // `point_add` needs two. Fully reduced: it is `sub_raw(dd, c)`'s right-hand operand.
        let c = mul_regs(t1, bt2d);
        // `dd = z1 + z1`: `rhs`'s `Z` is implicitly `1`, so this needs no multiply at all, and
        // `z1` is `Reduced`, so `dd < 2^52.1` -- the tightest intermediate in the formula.
        let dd = add_raw(z1, z1);
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
/// The CPU executing this must support AVX-512F and AVX-512 IFMA (checked by [`available`]).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) unsafe fn point_double(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
) -> (Reduced, Reduced, Reduced, Reduced) {
    // SAFETY: function-level requirement covers every intrinsic used here.
    unsafe {
        let (x, y, z) = (load(&ax.limbs), load(&ay.limbs), load(&az.limbs));

        // `a`/`b` are each used as `sub_raw`'s *right*-hand operand below (in `e`'s and `h`'s
        // inner subtractions, and directly in `g`), so both must stay fully reduced.
        let a = square_regs(x);
        let b = square_regs(y);
        // `c0` is only ever consumed by `add_raw` (`c` below), so it stays loose (`< 2^59.3`).
        // `c` itself becomes `sub_raw(g, c)`'s right-hand operand, so it gets an explicit
        // `reduce_regs` (its input `c0 + c0 < 2^60.3`).
        let c0 = square_regs_loose(z);
        let c = reduce_regs(add_raw(c0, c0));
        // `xy2` is only ever `sub_raw(xy2, a)`'s *left*-hand operand (`e` below), so loose too.
        let xy2 = square_regs_loose(reduce_regs(add_raw(x, y)));
        // Chained raw subtractions: `xy2 + bias - a + bias - b < 2^59.5`, inside `reduce_regs`'s
        // contract (see `sub_raw`'s doc comment).
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

    /// [`mul`]/[`square`] at the documented adversarial worst case: every limb of both operands
    /// at exactly [`super::super::REDUCED_BOUND`], the loosest value the [`Reduced`] type may
    /// carry -- the input that maximizes every internal column bound at once. The radix-52
    /// predecessor of this module was broken by exactly this kind of bound-edge operand (a raw
    /// column crossing what its fold-multiply could take; found on real hardware, not by review),
    /// so the replacement bound analysis gets pinned at its extreme here. Constructed via
    /// [`Reduced::from_raw_limbs_for_test`] because no organic `reduce()` output reaches this
    /// exact pattern.
    #[test]
    fn mul_matches_portable_at_reduced_bound_on_real_hardware() {
        skip_unless_available!();
        let limbs: [[u64; super::super::LANES]; 5] =
            [[super::super::REDUCED_BOUND; super::super::LANES]; 5];
        let r = Reduced::from_raw_limbs_for_test(limbs);
        // SAFETY: `available()` returned true above.
        let mul_actual = unsafe { mul(&r, &r) }.to_lanes();
        let mul_expected = r.mul_portable(&r).to_lanes();
        // SAFETY: `available()` returned true above.
        let square_actual = unsafe { square(&r) }.to_lanes();
        for i in 0..super::super::LANES {
            assert!(
                mul_actual[i].eq(&mul_expected[i]),
                "mul lane {i}: actual={mul_actual:?} expected={mul_expected:?}"
            );
            assert!(
                square_actual[i].eq(&mul_expected[i]),
                "square lane {i}: actual={square_actual:?} expected={mul_expected:?}"
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
    /// [`point_add_mixed`] against the mixed-addition formula (`bz` implicit `1`, `bt2d` already
    /// folding in `2d`) written out with the portable kernels directly.
    #[test]
    fn point_add_mixed_matches_portable_formula_on_real_hardware() {
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
            let (bx, by, bt2d) = (
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
                rand_reduced(&mut rng),
            );

            // SAFETY: `available()` returned true above.
            let actual = unsafe { point_add_mixed(&ax, &ay, &az, &at, &bx, &by, &bt2d) };

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
            let c = at.mul_portable(&bt2d);
            let dd = Unreduced::from(az).add_portable(&Unreduced::from(az));
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
