//! Eight field elements packed side by side in radix `2^51` -- the same radix as
//! [`FieldElement`], so packing/unpacking is a pure lane transpose with no bit realignment -- the
//! layout batch signature verification's SIMD kernels operate on.
//!
//! # Why radix 51 (and not 52)
//!
//! AVX-512 IFMA's `vpmadd52lo`/`vpmadd52hi` split a limb product at bit 52, which makes radix
//! `2^52` look natural (each product half lands exactly on a column boundary). An earlier version
//! of this module used it. But 52-bit limbs are *saturated* from the multiplier's point of view:
//! the instructions read exactly the low 52 bits of each input lane and silently discard anything
//! above bit 51, so every multiply input had to be brought *strictly* below `2^52` first -- and
//! because a carry into a limb could push it back over that exact boundary, reduction had to
//! ripple *sequentially* through the limbs, three full passes' worth (~50 cycles of dependent
//! latency per reduction site, measured on the EPYC 9354P this crate is tuned on; see
//! `zen4_timing` results). That exact-boundary cliff was also the source of real silent-corruption
//! bugs found on hardware.
//!
//! At radix `2^51` every limb keeps one spare bit below the multiplier's 52-bit ceiling. That
//! turns reduction into a *single parallel pass* (all five carry-outs computed at once from the
//! original limbs, all five masks applied at once, all five carry-ins added at once -- ~9 cycles
//! measured, no ripple), and it means a freshly reduced value sits at `~2^51`, a factor of two
//! below the IFMA cliff instead of one ULP below it. Additions and subtractions then never need
//! their own carry: raw limb-wise sums accumulate a few bits of looseness, and the single parallel
//! pass before the next multiply absorbs all of it at once. The price is that a product half split
//! at bit 52 no longer lands on a column boundary (weight `2^(51(i+j)) * 2^52 = 2 *
//! 2^(51(i+j+1))`), so high halves carry a coefficient of 2 -- handled by accumulating low-half
//! and high-half terms in separate register chains and combining with one shift-free doubling add
//! at the end (see `avx512::mul_regs_loose`). The multiply-accumulate count is unchanged (25
//! `vpmadd52lo` + 25 `vpmadd52hi`, exactly as at radix 52).
//!
//! The `2^255 = 19` wraparound fold is computed as `19*z = (z << 4) + (z << 1) + z` -- plain
//! shifts and adds -- rather than `vpmullq` (fast on Zen 4/5, slow on Intel) or extra IFMA
//! operations (cheap on Intel's two 512-bit FMA ports, expensive on double-pumped Zen 4's one):
//! shift/add is cheap on every AVX-512 core, so one code path serves all of them.
//!
//! This module holds the *portable* (no target-feature-specific intrinsics) implementation, which
//! simply delegates to [`FieldElement`]'s scalar arithmetic lane by lane -- possible precisely
//! because the radix now matches. It exists for three reasons: it is the correctness reference the
//! accelerated backend is checked against, it is usable on every platform (including this
//! development machine, which has no AVX-512), and it is the actual fallback path wherever no
//! faster backend applies.
//!
//! # `Reduced` vs. `Unreduced`
//!
//! Two types represent the same physical layout (five rows of eight `u64` limbs) but carry
//! different guarantees:
//!
//! - [`Reduced`]: every limb is at most [`REDUCED_BOUND`] (`2^51 + 2^17`, comfortably below the
//!   IFMA instructions' hard `2^52` input ceiling). The only type [`Reduced::mul`]/
//!   [`Reduced::square`] accept, so multiplying/squaring is safe to chain indefinitely (e.g.
//!   [`Reduced::pow_p58`]'s 251 chained squarings). Obtained from an [`Unreduced`] only via
//!   [`Unreduced::reduce`], a single parallel carry pass.
//! - [`Unreduced`]: limbs may run a few bits over 51 (every public constructor keeps them below
//!   `~2^53`; the fused AVX-512 kernels privately track looser intermediates up to `~2^60`, per-
//!   call-site -- see `avx512`). The natural result of [`Unreduced::add`]/[`Unreduced::sub`] and
//!   of packing raw field elements via [`Unreduced::from_lanes`]. A [`Reduced`] value casts to
//!   [`Unreduced`] for free (`From`); going the other way costs the one-pass [`Unreduced::reduce`].
//!   Operations that consume two `Reduced` operands but don't preserve the reduced bound (`add`,
//!   `sub`) are implemented on [`Reduced`] too, by casting both sides to `Unreduced` first.

use crate::field::FieldElement;

#[cfg(target_arch = "x86_64")]
mod avx512;

/// Lane count: eight field elements per [`Unreduced`]/[`Reduced`].
pub(crate) const LANES: usize = 8;

/// Returns `true` if this CPU actually has an accelerated backend for this module's arithmetic
/// (currently: AVX-512 IFMA on `x86_64`).
///
/// Algorithms with both a "SIMD-shaped" variant (packing values into these lanes) and a plain
/// scalar one -- like the MSM's transposed Pippenger vs. its classic ancestor -- should check this
/// before picking the SIMD-shaped one: packing/unpacking lanes costs the same either way, so that
/// variant only pays for itself when the packed arithmetic is actually accelerated in hardware.
/// Without that, it is strictly *more* work than the scalar equivalent for no benefit.
// Not `const`: on `x86_64` this calls `is_x86_feature_detected!`, a runtime CPU check.
#[allow(clippy::missing_const_for_fn)]
pub(crate) fn simd_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        avx512::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

const MASK_51: u64 = (1 << 51) - 1;

/// Upper bound (inclusive) on every limb of a [`Reduced`] value: `2^51 + 2^17`.
///
/// Derivation: [`reduce_limbs`] (and its vectorized counterpart) accepts any input with limbs
/// `<= 2^63`, computes carry-outs `c_i = l_i >> 51 <= 2^12`, and produces `(l_i & MASK_51) +
/// c_{i-1} <= 2^51 - 1 + 2^12` for limbs 1-4 and `(l_0 & MASK_51) + 19*c_4 <= 2^51 - 1 + 19*2^12
/// < 2^51 + 2^17` for limb 0. Every limb is therefore strictly below `2^52`, the IFMA multiply
/// instructions' hard input ceiling, with roughly a factor-of-two margin -- unlike the radix-52
/// predecessor of this module, which lived exactly one ULP below that cliff (see the module docs).
pub(crate) const REDUCED_BOUND: u64 = (1 << 51) + (1 << 17);

/// `16*p` decomposed limb-wise at radix 51 (the same constant [`FieldElement::sub`] uses):
/// added before a limb-wise subtraction so every limb stays non-negative without changing the
/// value mod `p`. Every limb is `~2^55`, comfortably above any operand this module's subtractions
/// ever see on the right-hand side (public [`Unreduced`] values are `< 2^53`; the fused kernels
/// only ever subtract [`Reduced`]-quality right-hand operands -- see [`avx512`]) and small enough
/// that even a loose (`~2^60`) left-hand operand plus this bias stays far from `u64` overflow.
/// Only the AVX-512 backend subtracts limb-wise; the portable path delegates to
/// [`FieldElement::sub`], which carries its own copy of this constant.
#[cfg(target_arch = "x86_64")]
const SUB_BIAS: [u64; 5] = [
    16 * ((1u64 << 51) - 19),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
];

/// Radix-`2^51` limbs with no bound guarantee beyond every public constructor's documented
/// looseness (`< ~2^53` per limb; see the type-level docs in this module's header). See the module
/// docs for why this is split from [`Reduced`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unreduced {
    limbs: [[u64; LANES]; 5],
}

/// Radix-`2^51` limbs, every one at most [`REDUCED_BOUND`] -- safe as an IFMA multiply input. See
/// the module docs for why this is split from [`Unreduced`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reduced {
    limbs: [[u64; LANES]; 5],
}

impl From<Reduced> for Unreduced {
    fn from(value: Reduced) -> Self {
        Self { limbs: value.limbs }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
impl Reduced {
    /// Constructs a `Reduced` from exact limbs, bit for bit, with no repacking -- for driving the
    /// AVX-512 backend's adversarial worst-case tests (limbs at exactly [`REDUCED_BOUND`], a bit
    /// pattern [`Unreduced::reduce`] rarely produces organically).
    pub(crate) fn from_raw_limbs_for_test(limbs: [[u64; LANES]; 5]) -> Self {
        Self { limbs }
    }
}

/// One parallel carry pass, the entire reduction at radix 51: all five carry-outs are computed
/// from the *original* limbs (no ripple -- the spare bit below the multiplier's 52-bit ceiling is
/// what makes one pass sufficient; see the module docs), all five limbs masked, and all five
/// carry-ins added, with limb 4's carry folded onto limb 0 via `2^255 = 19 (mod p)`. Accepts any
/// input with limbs `<= 2^63` and produces limbs `<= REDUCED_BOUND` (see that constant's
/// derivation).
const fn reduce_limbs(l: [u64; 5]) -> [u64; 5] {
    [
        (l[0] & MASK_51) + 19 * (l[4] >> 51),
        (l[1] & MASK_51) + (l[0] >> 51),
        (l[2] & MASK_51) + (l[1] >> 51),
        (l[3] & MASK_51) + (l[2] >> 51),
        (l[4] & MASK_51) + (l[3] >> 51),
    ]
}

/// `2 * EDWARDS_D` splatted across all lanes, fully reduced at compile time. Used by
/// [`avx512::point_add`] so the fused point-addition formula never has to compute this per call.
/// [`FieldElement::EDWARDS_D2`]'s limbs are already carry-propagated (`const` addition ends in a
/// carry), well under [`REDUCED_BOUND`]; with the radices now matching, splatting is a plain copy.
#[cfg(target_arch = "x86_64")]
pub(crate) const EDWARDS_D_TIMES_2: Reduced = {
    let d2 = FieldElement::EDWARDS_D2.0;
    Reduced {
        limbs: [
            [d2[0]; LANES],
            [d2[1]; LANES],
            [d2[2]; LANES],
            [d2[3]; LANES],
            [d2[4]; LANES],
        ],
    }
};

impl Unreduced {
    /// Packs eight copies of the same field element into one `Unreduced`.
    pub(crate) fn splat(value: FieldElement) -> Self {
        Self::from_lanes(&[value; LANES])
    }

    /// Packs eight field elements into one `Unreduced`. With the radix matching
    /// [`FieldElement`]'s, this is a pure transpose -- no bit realignment, no reduction -- so any
    /// "loose" limbs a `FieldElement` carries (a few bits over 51, the normal state between scalar
    /// operations) transfer verbatim, comfortably inside this type's invariant.
    pub(crate) fn from_lanes(lanes: &[FieldElement; LANES]) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for (i, lane) in lanes.iter().enumerate() {
            for (row, value) in limbs.iter_mut().zip(lane.0) {
                row[i] = value;
            }
        }
        Self { limbs }
    }

    /// Unpacks this value back into eight field elements: the inverse transpose of
    /// [`Unreduced::from_lanes`]. The results are "loose" the same way any [`FieldElement`]
    /// arithmetic result is (not necessarily canonical in `[0, p)`), which is fine: callers that
    /// need a canonical answer already call [`FieldElement::to_bytes`] or [`FieldElement::eq`].
    pub(crate) fn to_lanes(self) -> [FieldElement; LANES] {
        core::array::from_fn(|i| FieldElement(core::array::from_fn(|limb| self.limbs[limb][i])))
    }

    /// Adds two values, dispatching to the AVX-512 backend when the running CPU supports it and
    /// falling back to the portable kernel everywhere else, same as [`Reduced::mul`].
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        #[cfg(target_arch = "x86_64")]
        if avx512::available() {
            // SAFETY: `available()` just confirmed the CPU supports every feature `avx512::add`
            // requires.
            return unsafe { avx512::add(self, rhs) };
        }
        self.add_portable(rhs)
    }

    fn add_portable(&self, rhs: &Self) -> Self {
        self.zip_lanes(rhs, |a, b| a.add(&b))
    }

    /// Subtracts two values, dispatching to the AVX-512 backend when the running CPU supports it
    /// and falling back to the portable kernel everywhere else, same as [`Reduced::mul`].
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        #[cfg(target_arch = "x86_64")]
        if avx512::available() {
            // SAFETY: `available()` just confirmed the CPU supports every feature `avx512::sub`
            // requires.
            return unsafe { avx512::sub(self, rhs) };
        }
        self.sub_portable(rhs)
    }

    fn sub_portable(&self, rhs: &Self) -> Self {
        self.zip_lanes(rhs, |a, b| a.sub(&b))
    }

    /// Applies a scalar [`FieldElement`] binary operation lane by lane -- the entire portable
    /// backend for `add`/`sub`/`mul`/`square`, made possible by the radices matching (see the
    /// module docs). Perf is a non-goal here: this path only runs where no vector backend exists,
    /// and correctness-by-obviousness (one shared scalar implementation) is worth more than a
    /// hand-unrolled second copy of the arithmetic.
    fn zip_lanes(
        &self,
        rhs: &Self,
        op: impl Fn(FieldElement, FieldElement) -> FieldElement,
    ) -> Self {
        let a = self.to_lanes();
        let b = rhs.to_lanes();
        Self::from_lanes(&core::array::from_fn(|i| op(a[i], b[i])))
    }

    /// Reduces every lane to [`Reduced`]'s bound via one parallel carry pass (see
    /// [`reduce_limbs`]) -- the only way to obtain a [`Reduced`] value, and what makes it safe to
    /// feed into [`Reduced::mul`]/[`Reduced::square`]'s AVX-512 backend.
    pub(crate) fn reduce(&self) -> Reduced {
        #[cfg(target_arch = "x86_64")]
        if avx512::available() {
            // SAFETY: `available()` just confirmed the CPU supports every feature
            // `avx512::reduce` requires.
            return unsafe { avx512::reduce(self) };
        }
        self.reduce_portable()
    }

    fn reduce_portable(&self) -> Reduced {
        let mut limbs = [[0u64; LANES]; 5];
        for i in 0..LANES {
            let l = core::array::from_fn(|limb| self.limbs[limb][i]);
            let c = reduce_limbs(l);
            for (row, value) in limbs.iter_mut().zip(c) {
                row[i] = value;
            }
        }
        Reduced { limbs }
    }
}

impl Reduced {
    /// `LANES` copies of zero, every limb trivially within bound.
    pub(crate) const ZERO: Self = Self {
        limbs: [[0; LANES]; 5],
    };

    /// Adds two `Reduced` values. The sum is not itself guaranteed to stay within [`Reduced`]'s
    /// bound, so the result is [`Unreduced`]; callers needing to multiply/square it call
    /// [`Unreduced::reduce`] first.
    pub(crate) fn add(&self, rhs: &Self) -> Unreduced {
        Unreduced::from(*self).add(&Unreduced::from(*rhs))
    }

    /// Subtracts two `Reduced` values; see [`Reduced::add`] for why the result is [`Unreduced`].
    pub(crate) fn sub(&self, rhs: &Self) -> Unreduced {
        Unreduced::from(*self).sub(&Unreduced::from(*rhs))
    }

    /// Negates a `Reduced` value, mirroring [`FieldElement::neg`]'s `ZERO.sub(self)`.
    pub(crate) fn neg(&self) -> Unreduced {
        Self::ZERO.sub(self)
    }

    /// Unpacks this value back into eight field elements; see [`Unreduced::to_lanes`].
    pub(crate) fn to_lanes(self) -> [FieldElement; LANES] {
        Unreduced::from(self).to_lanes()
    }

    /// Multiplies two `Reduced` values, dispatching to the AVX-512 IFMA backend when the running
    /// CPU supports it and falling back to the portable kernel everywhere else (including every
    /// non-`x86_64` target, where the AVX-512 backend does not even exist in the compiled binary).
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        #[cfg(target_arch = "x86_64")]
        if avx512::available() {
            // SAFETY: `available()` just confirmed the CPU supports every feature `avx512::mul`
            // requires.
            return unsafe { avx512::mul(self, rhs) };
        }
        self.mul_portable(rhs)
    }

    pub(crate) fn mul_portable(&self, rhs: &Self) -> Self {
        // `FieldElement::mul` tolerates limbs a few bits over 51 (its `19*b` prefolds and `u128`
        // column sums have ample headroom for anything within `REDUCED_BOUND`) and its output is
        // carry-propagated, i.e. within `REDUCED_BOUND` again.
        Unreduced::from(*self)
            .zip_lanes(&Unreduced::from(*rhs), |a, b| a.mul(&b))
            .assume_reduced()
    }

    /// Squares a `Reduced` value, dispatching to the AVX-512 IFMA backend when the running CPU
    /// supports it and falling back to the portable kernel everywhere else, same as
    /// [`Reduced::mul`].
    pub(crate) fn square(&self) -> Self {
        #[cfg(target_arch = "x86_64")]
        if avx512::available() {
            // SAFETY: `available()` just confirmed the CPU supports every feature
            // `avx512::square` requires.
            return unsafe { avx512::square(self) };
        }
        self.square_portable()
    }

    pub(crate) fn square_portable(&self) -> Self {
        // Same bound reasoning as `mul_portable`.
        Unreduced::from(*self)
            .zip_lanes(&Unreduced::from(*self), |a, _| a.square())
            .assume_reduced()
    }

    /// Squares every lane `k` times in a row.
    fn pow2k(&self, k: u32) -> Self {
        let mut result = *self;
        for _ in 0..k {
            result = result.square();
        }
        result
    }

    /// 8-wide counterpart to [`FieldElement::pow_2_250_minus_1`]: the exact same `2^k - 1`-chain,
    /// just built from `Reduced` operations. See that function for the chain's derivation.
    fn pow_2_250_minus_1(&self) -> Self {
        let a = self.square();
        let a2 = a.square().square();
        let b = self.mul(&a2);
        let c = a.mul(&b);
        let d = c.square();
        let e = b.mul(&d);
        let f = e.pow2k(5).mul(&e);
        let g = f.pow2k(10).mul(&f);
        let h = g.pow2k(20).mul(&g);
        let i = h.pow2k(10).mul(&f);
        let j = i.pow2k(50).mul(&i);
        let k = j.pow2k(100).mul(&j);
        k.pow2k(50).mul(&i)
    }

    /// Raises every lane to the power `(p - 5) / 8 = 2^252 - 3`, 8-wide counterpart to
    /// [`FieldElement::pow_p58`] used by the batch decompression sqrt kernel: the standard
    /// `2^k - 1`-chain (251 squarings + 11 multiplications) rather than a naive square-and-
    /// multiply loop over this exponent's mostly-`1` bits (~252 squarings + ~251 multiplications).
    pub(crate) fn pow_p58(&self) -> Self {
        self.mul(&self.pow_2_250_minus_1().pow2k(2))
    }
}

impl Unreduced {
    /// Reinterprets this value as [`Reduced`] without running a reduction. Only for use by
    /// operations whose per-lane arithmetic already guarantees the [`REDUCED_BOUND`] limb bound
    /// (the portable `mul`/`square`, whose [`FieldElement`] kernels end in a carry propagation)
    /// -- never a substitute for [`Unreduced::reduce`].
    fn assume_reduced(self) -> Reduced {
        debug_assert!(
            self.limbs
                .iter()
                .all(|row| row.iter().all(|&limb| limb <= REDUCED_BOUND)),
            "assume_reduced on a value outside REDUCED_BOUND"
        );
        Reduced { limbs: self.limbs }
    }
}

/// Computes one step of the Hisil-Wong-Carter-Dawson unified point-addition formula 8-wide (see
/// `PointVec::add`) via a single fused AVX-512 function when available,
/// with every intermediate held in registers rather than round-tripping through memory once per
/// field operation (see `avx512::point_add`'s doc comment) -- returns `None` on any CPU without
/// this backend, in which case callers fall back to chaining the ordinary `Reduced`/`Unreduced`
/// methods (which cost the same on such CPUs either way, since there is no faster fused path to
/// miss out on).
// Not `const`: on `x86_64` this calls `avx512::available()`, a runtime CPU check (see
// `simd_available`'s own `#[allow]` for the same reason).
#[allow(clippy::missing_const_for_fn, clippy::too_many_arguments)]
pub(crate) fn fused_point_add(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
    at: &Reduced,
    bx: &Reduced,
    by: &Reduced,
    bz: &Reduced,
    bt: &Reduced,
) -> Option<(Reduced, Reduced, Reduced, Reduced)> {
    #[cfg(target_arch = "x86_64")]
    if avx512::available() {
        // SAFETY: `available()` just confirmed the CPU supports every feature `avx512::point_add`
        // requires.
        return Some(unsafe {
            avx512::point_add(ax, ay, az, at, bx, by, bz, bt, &EDWARDS_D_TIMES_2)
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (ax, ay, az, at, bx, by, bz, bt);
    None
}

/// Computes one step of the mixed-addition formula 8-wide (see
/// `PointVec::add_mixed`) via a single fused AVX-512 function when
/// available, same [`fused_point_add`] pattern and for the same reason (see
/// `avx512::point_add_mixed`'s doc comment) -- returns `None` on any CPU without this backend.
// Not `const`: on `x86_64` this calls `avx512::available()`, a runtime CPU check (see
// `simd_available`'s own `#[allow]` for the same reason).
#[allow(clippy::missing_const_for_fn, clippy::too_many_arguments)]
pub(crate) fn fused_point_add_mixed(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
    at: &Reduced,
    bx: &Reduced,
    by: &Reduced,
    bt2d: &Reduced,
) -> Option<(Reduced, Reduced, Reduced, Reduced)> {
    #[cfg(target_arch = "x86_64")]
    if avx512::available() {
        // SAFETY: `available()` just confirmed the CPU supports every feature
        // `avx512::point_add_mixed` requires.
        return Some(unsafe { avx512::point_add_mixed(ax, ay, az, at, bx, by, bt2d) });
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (ax, ay, az, at, bx, by, bt2d);
    None
}

/// Computes the dedicated `dbl-2008-hwcd` doubling formula 8-wide (see
/// `PointVec::double`) via a single fused AVX-512 function when
/// available, same [`fused_point_add`] pattern and for the same reason (see
/// `avx512::point_double`'s doc comment) -- returns `None` on any CPU without this backend.
// Not `const`: on `x86_64` this calls `avx512::available()`, a runtime CPU check (see
// `simd_available`'s own `#[allow]` for the same reason).
#[allow(clippy::missing_const_for_fn)]
pub(crate) fn fused_point_double(
    ax: &Reduced,
    ay: &Reduced,
    az: &Reduced,
) -> Option<(Reduced, Reduced, Reduced, Reduced)> {
    #[cfg(target_arch = "x86_64")]
    if avx512::available() {
        // SAFETY: `available()` just confirmed the CPU supports every feature
        // `avx512::point_double` requires.
        return Some(unsafe { avx512::point_double(ax, ay, az) });
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (ax, ay, az);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::test_support::rand_field_element;
    use commonware_utils::test_rng;

    fn rand_lanes(rng: &mut impl rand_core::Rng) -> [FieldElement; LANES] {
        core::array::from_fn(|_| rand_field_element(rng))
    }

    #[test]
    fn round_trips_through_lanes() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let lanes = rand_lanes(&mut rng);
            let round_tripped = Unreduced::from_lanes(&lanes).to_lanes();
            for (a, b) in lanes.iter().zip(round_tripped.iter()) {
                assert!(a.eq(b));
            }
        }
    }

    #[test]
    fn add_matches_scalar_per_lane() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a = rand_lanes(&mut rng);
            let b = rand_lanes(&mut rng);
            let actual = Unreduced::from_lanes(&a)
                .add(&Unreduced::from_lanes(&b))
                .to_lanes();
            for i in 0..LANES {
                assert!(actual[i].eq(&a[i].add(&b[i])));
            }
        }
    }

    #[test]
    fn sub_matches_scalar_per_lane() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a = rand_lanes(&mut rng);
            let b = rand_lanes(&mut rng);
            let actual = Unreduced::from_lanes(&a)
                .sub(&Unreduced::from_lanes(&b))
                .to_lanes();
            for i in 0..LANES {
                assert!(actual[i].eq(&a[i].sub(&b[i])));
            }
        }
    }

    #[test]
    fn mul_matches_scalar_per_lane() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a = rand_lanes(&mut rng);
            let b = rand_lanes(&mut rng);
            let actual = Unreduced::from_lanes(&a)
                .reduce()
                .mul(&Unreduced::from_lanes(&b).reduce())
                .to_lanes();
            for i in 0..LANES {
                assert!(actual[i].eq(&a[i].mul(&b[i])));
            }
        }
    }

    #[test]
    fn square_matches_scalar_per_lane() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a = rand_lanes(&mut rng);
            let actual = Unreduced::from_lanes(&a).reduce().square().to_lanes();
            for i in 0..LANES {
                assert!(actual[i].eq(&a[i].square()));
            }
        }
    }

    #[test]
    fn pow_p58_matches_scalar_per_lane() {
        let mut rng = test_rng();
        let a = rand_lanes(&mut rng);
        let actual = Unreduced::from_lanes(&a).reduce().pow_p58().to_lanes();
        for i in 0..LANES {
            assert!(actual[i].eq(&a[i].pow_p58()));
        }
    }

    /// Every limb of a [`Reduced`] value must be at most [`REDUCED_BOUND`] -- the whole point of
    /// the type. `Unreduced::reduce` (backed by [`reduce_limbs`]) is the only way to produce one,
    /// so this is the type's core safety property, checked here over many random inputs.
    #[test]
    fn reduce_produces_bounded_limbs() {
        let mut rng = test_rng();
        for _ in 0..256 {
            let a = rand_lanes(&mut rng);
            let reduced = Unreduced::from_lanes(&a).reduce();
            for row in reduced.limbs {
                for limb in row {
                    assert!(limb <= REDUCED_BOUND);
                }
            }
        }
    }

    /// [`reduce_limbs`] at its documented worst case: every limb at the maximum the function
    /// accepts (`2^63`), checking both the output bound ([`REDUCED_BOUND`]) and value congruence
    /// mod `p`. At radix 51 there is no exact-boundary cliff to hunt for adversarially (the
    /// radix-52 predecessor needed hand-constructed inputs that landed a limb at exactly `2^52`
    /// after one ripple pass); the single parallel pass's bound follows directly from the carry
    /// arithmetic, checked here at its extreme.
    #[test]
    fn reduce_handles_maximum_looseness() {
        let cases: &[[u64; 5]] = &[
            [1u64 << 63; 5],
            [(1u64 << 63) - 1; 5],
            [
                u64::MAX >> 1,
                MASK_51,
                u64::MAX >> 1,
                MASK_51,
                u64::MAX >> 1,
            ],
            [0, 0, 0, 0, 1u64 << 63],
        ];
        for &case in cases {
            let reduced = reduce_limbs(case);
            for &limb in &reduced {
                assert!(limb <= REDUCED_BOUND, "limb {limb} above REDUCED_BOUND");
            }
            // Value congruence mod p: both are radix-2^51 representations, so compare canonical
            // encodings directly.
            let to_bytes = |l: [u64; 5]| FieldElement(l).to_bytes();
            assert_eq!(to_bytes(case), to_bytes(reduced));
        }
    }
}
