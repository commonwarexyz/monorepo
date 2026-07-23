//! Eight field elements packed side by side, radix `2^52` (5 limbs spanning 260 bits, versus
//! [`FieldElement`]'s radix `2^51`/255 bits): the layout batch signature verification's SIMD
//! kernels operate on -- see the design notes' field layer section for why 52 rather than 51 (it
//! matches the split point of the AVX-512 IFMA multiply-accumulate instructions, with no
//! shift fixups needed between the low and high halves of a limb product).
//!
//! This module holds the *portable* (no target-feature-specific intrinsics) implementation: a
//! straight loop over the 8 lanes, each doing the same radix-52 schoolbook multiply a vectorized
//! backend would do 8-wide. It exists for three reasons: it is the correctness reference the
//! accelerated backends are checked against, it is usable on every platform (including this
//! development machine, which has no AVX-512), and it is the actual fallback path wherever no
//! faster backend applies.
//!
//! # `Reduced` vs. `Unreduced`
//!
//! Two types represent the same physical layout (five rows of eight `u64` limbs) but carry
//! different guarantees, because AVX-512's `vpmadd52lo`/`vpmadd52hi` instructions are far less
//! forgiving than they look: they operate on *exactly* the low 52 bits of each 64-bit input lane,
//! silently discarding anything above bit 51, whereas the portable backend's `u128` arithmetic
//! tolerates a "loose" (not perfectly bounded) input of any reasonable width. A value with even
//! one limb at bit 52 or higher, fed into [`avx512::mul`]/[`avx512::square`], produces a silently
//! wrong result on real hardware -- confirmed by running this crate's test suite on an actual
//! AVX-512 machine, not just cross-compiling and reasoning about the assembly.
//!
//! - [`Reduced`]: every limb is *strictly* less than `2^52`. The only type [`Reduced::mul`]/
//!   [`Reduced::square`] accept, and the only type they produce, so multiplying/squaring is safe
//!   to chain indefinitely (e.g. [`Reduced::pow_p58`]'s 251 chained squarings) without an
//!   intermediate reduction. Obtained from an [`Unreduced`] only via [`Unreduced::reduce`].
//! - [`Unreduced`]: no bound beyond fitting in a `u64` limb without overflowing during `add`/`sub`.
//!   The natural result of [`Unreduced::add`]/[`Unreduced::sub`] (`vpaddq`/`vpsubq` tolerate any
//!   reasonable input width, unlike the IFMA instructions), and of packing raw field elements via
//!   [`Unreduced::from_lanes`]. A [`Reduced`] value casts to [`Unreduced`] for free (`From`) since
//!   its bound is strictly tighter than `Unreduced` requires; going the other way needs an actual
//!   reduction. Operations that consume two `Reduced` operands but don't themselves preserve the
//!   `<2^52` bound (`add`, `sub`) are implemented directly on [`Reduced`] too, for convenience,
//!   simply by casting both sides to `Unreduced` first -- see [`Reduced::add`]/[`Reduced::sub`].

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

const MASK_52: u64 = (1 << 52) - 1;

/// `2^260 mod p`, used to fold a radix-52 schoolbook multiply's overflow (5 limbs span 260 bits,
/// 5 more than `p`'s 255) back in: `2^260 = 2^5 * 2^255 = 32*(p + 19) = 32p + 608`, so
/// `2^260 ≡ 608 (mod p)`.
const FOLD_608: u64 = 608;

/// Radix-`2^52` limbs with no bound guarantee beyond fitting in a `u64` per limb without
/// overflowing across a single `add`/`sub`. See the module docs for why this is split from
/// [`Reduced`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unreduced {
    limbs: [[u64; LANES]; 5],
}

/// Radix-`2^52` limbs, every one strictly less than `2^52`. See the module docs for why this is
/// split from [`Unreduced`].
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
    /// Constructs a `Reduced` from exact limbs, bit for bit, with no repacking -- for
    /// reproducing a specific known bit pattern in a regression test (see
    /// [`avx512::tests::mul_matches_portable_for_known_bad_value_on_real_hardware`]), which a
    /// round trip through [`Unreduced::from_lanes`]/[`Unreduced::reduce`] cannot guarantee, since
    /// multiple loose representations can encode the same value.
    pub(crate) fn from_raw_limbs_for_test(limbs: [[u64; LANES]; 5]) -> Self {
        Self { limbs }
    }
}

/// One ripple-carry pass: propagates each limb's overflow past bit 52 into the next, folding the
/// final overflow (past bit 260) back in via `2^260 = 608`. Leaves every limb `< 2^52` *except*
/// limb 1, which may be exactly `2^52` (the final `l[1] += l[0] >> 52` has no subsequent mask) --
/// this is why a single pass is an [`Unreduced`]-to-`Unreduced` operation, not a path to
/// [`Reduced`]; see [`reduce`] for the latter.
const fn carry(mut l: [u64; 5]) -> [u64; 5] {
    l[1] += l[0] >> 52;
    l[0] &= MASK_52;
    l[2] += l[1] >> 52;
    l[1] &= MASK_52;
    l[3] += l[2] >> 52;
    l[2] &= MASK_52;
    l[4] += l[3] >> 52;
    l[3] &= MASK_52;
    l[0] += (l[4] >> 52) * FOLD_608;
    l[4] &= MASK_52;
    l[1] += l[0] >> 52;
    l[0] &= MASK_52;
    l
}

/// Fully reduces radix-`2^52` limbs so every one is *strictly* `< 2^52` -- safe to feed into
/// AVX-512's `vpmadd52lo`/`vpmadd52hi`, which [`carry`] alone is not (see the module docs and
/// [`carry`]'s own doc comment for why). Three [`carry`] passes: exact worst-case bound propagation
/// shows a single pass reaches a fixed point where every limb but one is already strictly bounded,
/// leaving only limb 1 possibly exactly at `2^52`; concrete (non-interval) adversarial search found
/// many inputs hitting that exact boundary after one pass, and a second pass resolved every one of
/// them (see `reduce_settles_adversarial_boundary_cases` below, built from those exact search
/// results); the third pass is margin, not load-bearing by that evidence. This is not a closed-form
/// proof that a third occurrence is impossible, but the same test exercises this function directly
/// against the concrete cases that motivated it.
const fn reduce_limbs(l: [u64; 5]) -> [u64; 5] {
    carry(carry(carry(l)))
}

/// Re-expresses a radix-`2^52` value as radix-`2^51` limbs (the inverse bit realignment of
/// [`from_radix_51`]), landing any bits past position 255 (i.e. `f[4] >> 47`) back in via
/// `2^255 ≡ 19`. Every term is combined with addition rather than OR, so this tolerates "loose"
/// (not perfectly bounded, e.g. a limb running a couple of bits over its nominal width) input the
/// same way [`FieldElement`]'s own arithmetic does -- a carry that OR would silently drop instead
/// lands correctly. The result is itself loose in exactly that same sense; that is fine, since
/// downstream [`FieldElement`] arithmetic (and [`FieldElement::to_bytes`]/[`FieldElement::eq`] for
/// final output) already normalizes loose values, same as any other `FieldElement` this crate
/// produces.
const fn to_radix_51(f: [u64; 5]) -> [u64; 5] {
    const MASK_51: u64 = (1 << 51) - 1;
    [
        (f[0] & MASK_51) + (f[4] >> 47) * 19,
        (f[0] >> 51) + ((f[1] & ((1u64 << 50) - 1)) << 1),
        (f[1] >> 50) + ((f[2] & ((1u64 << 49) - 1)) << 2),
        (f[2] >> 49) + ((f[3] & ((1u64 << 48) - 1)) << 3),
        (f[3] >> 48) + ((f[4] & ((1u64 << 47) - 1)) << 4),
    ]
}

/// The inverse of [`to_radix_51`]: re-expresses a radix-`2^51` value as radix-`2^52` limbs. Like
/// `to_radix_51`, this combines every term with addition (not OR) so it tolerates the same "loose"
/// limbs [`FieldElement`]'s own arithmetic produces -- unlike a round trip through
/// [`FieldElement::to_bytes`]/[`FieldElement::from_bytes`], neither this nor `to_radix_51` does any
/// modular reduction, which is what makes them cheap enough to use in a hot loop (e.g. once per
/// MSM bucket update; see [`Unreduced::from_lanes`]/[`Unreduced::to_lanes`]).
const fn from_radix_51(e: [u64; 5]) -> [u64; 5] {
    [
        e[0] + ((e[1] & 1) << 51),
        (e[1] >> 1) + ((e[2] & 0b11) << 50),
        (e[2] >> 2) + ((e[3] & 0b111) << 49),
        (e[3] >> 3) + ((e[4] & 0b1111) << 48),
        e[4] >> 4,
    ]
}

/// `16*p` decomposed the same way any redundant radix-`2^52` value would be, analogous to
/// [`FieldElement`]'s own `SUB_BIAS`: `2^260 - 608 = 32p` (see [`FOLD_608`]), so
/// `16*(2^52 - 608) + 16*(2^52-1)*(2^52+2^104+2^156+2^208) = 16*(2^260 - 608) = 512p`, an exact
/// multiple of `p`, with every limb comfortably above any legal rhs limb (`< 2^52`).
const SUB_BIAS: [u64; 5] = [
    16 * ((1u64 << 52) - 608),
    16 * ((1u64 << 52) - 1),
    16 * ((1u64 << 52) - 1),
    16 * ((1u64 << 52) - 1),
    16 * ((1u64 << 52) - 1),
];

/// `2 * EDWARDS_D`, radix-`2^52`, fully [`reduce_limbs`]-reduced, computed once at compile time --
/// doubling each radix-`2^51` limb directly (rather than via `FieldElement::add`) is a "loose" but
/// value-preserving radix-51 representation of `2*d`, which [`from_radix_51`] tolerates the same
/// way it tolerates any other loose input (see its doc comment); `reduce_limbs` then brings it
/// under the strict `< 2^52` bound [`Reduced::mul`] requires. Used by [`avx512::point_add`] so the
/// fused point-addition formula never has to compute this per call -- `PointVec::add`'s own
/// (non-fused, portable-only) formula used to via `Unreduced::splat(FieldElement::EDWARDS_D).
/// reduce()` on every call.
#[cfg(target_arch = "x86_64")]
pub(crate) const EDWARDS_D_TIMES_2: Reduced = {
    let d = FieldElement::EDWARDS_D.0;
    let doubled = [d[0] * 2, d[1] * 2, d[2] * 2, d[3] * 2, d[4] * 2];
    let limbs52 = reduce_limbs(from_radix_51(doubled));
    Reduced {
        limbs: [
            [limbs52[0]; LANES],
            [limbs52[1]; LANES],
            [limbs52[2]; LANES],
            [limbs52[3]; LANES],
            [limbs52[4]; LANES],
        ],
    }
};

/// Multiplies two single lanes' worth of radix-`2^52` limbs via schoolbook multiplication, folding
/// overflow past 260 bits back in via [`FOLD_608`] using the same "pre-fold `b`'s upper limbs"
/// technique as [`FieldElement::mul`] (there, folding via 19 at the 255-bit wraparound; here via
/// 608 at the 260-bit one). Returns fully [`reduce_limbs`]-reduced output: every limb `< 2^52`.
fn mul_lane(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    let b1_f = b[1] * FOLD_608;
    let b2_f = b[2] * FOLD_608;
    let b3_f = b[3] * FOLD_608;
    let b4_f = b[4] * FOLD_608;

    let m = |x: u64, y: u64| (x as u128) * (y as u128);

    let c0 = m(a[0], b[0]) + m(a[1], b4_f) + m(a[2], b3_f) + m(a[3], b2_f) + m(a[4], b1_f);
    let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_f) + m(a[3], b3_f) + m(a[4], b2_f);
    let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_f) + m(a[4], b3_f);
    let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_f);
    let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

    let mask = MASK_52 as u128;
    let c1 = c1 + (c0 >> 52);
    let c0 = (c0 & mask) as u64;
    let c2 = c2 + (c1 >> 52);
    let c1 = (c1 & mask) as u64;
    let c3 = c3 + (c2 >> 52);
    let c2 = (c2 & mask) as u64;
    let c4 = c4 + (c3 >> 52);
    let c3 = (c3 & mask) as u64;
    let carry4 = (c4 >> 52) as u64;
    let c4 = (c4 & mask) as u64;

    reduce_limbs([c0 + carry4 * FOLD_608, c1, c2, c3, c4])
}

/// Squares a single lane's worth of radix-`2^52` limbs. Dedicated formula rather than
/// `mul_lane(a, a)`, mirroring [`FieldElement::square`] at radix 52 instead of 51: every cross
/// term `a[i]*a[j]` (`i != j`) is computed once and doubled instead of computed twice, 15 limb
/// multiplies here versus 25 in [`mul_lane`]. Returns fully [`reduce_limbs`]-reduced output: every
/// limb `< 2^52`.
fn square_lane(a: [u64; 5]) -> [u64; 5] {
    let a3_f = a[3] * FOLD_608;
    let a4_f = a[4] * FOLD_608;

    let m = |x: u64, y: u64| (x as u128) * (y as u128);

    let c0 = m(a[0], a[0]) + 2 * (m(a[1], a4_f) + m(a[2], a3_f));
    let c1 = m(a[3], a3_f) + 2 * (m(a[0], a[1]) + m(a[2], a4_f));
    let c2 = m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_f));
    let c3 = m(a[4], a4_f) + 2 * (m(a[0], a[3]) + m(a[1], a[2]));
    let c4 = m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3]));

    let mask = MASK_52 as u128;
    let c1 = c1 + (c0 >> 52);
    let c0 = (c0 & mask) as u64;
    let c2 = c2 + (c1 >> 52);
    let c1 = (c1 & mask) as u64;
    let c3 = c3 + (c2 >> 52);
    let c2 = (c2 & mask) as u64;
    let c4 = c4 + (c3 >> 52);
    let c3 = (c3 & mask) as u64;
    let carry4 = (c4 >> 52) as u64;
    let c4 = (c4 & mask) as u64;

    reduce_limbs([c0 + carry4 * FOLD_608, c1, c2, c3, c4])
}

impl Unreduced {
    /// Packs eight copies of the same field element into one `Unreduced`.
    pub(crate) fn splat(value: FieldElement) -> Self {
        Self::from_lanes(&[value; LANES])
    }

    /// Packs eight field elements into one `Unreduced`, via the cheap [`from_radix_51`] bit
    /// realignment -- no modular reduction, so this is fast enough to call in a hot loop (e.g.
    /// once per MSM bucket update), unlike a round trip through [`FieldElement::to_bytes`]. Not
    /// `Reduced` directly: a source limb sitting at [`FieldElement`]'s own loose upper bound can,
    /// after this bit realignment, land at exactly `2^52`, one past `Reduced`'s bound; callers
    /// that need `Reduced` call [`Unreduced::reduce`] on the result.
    pub(crate) fn from_lanes(lanes: &[FieldElement; LANES]) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for (i, lane) in lanes.iter().enumerate() {
            let f = from_radix_51(lane.0);
            for (row, value) in limbs.iter_mut().zip(f) {
                row[i] = value;
            }
        }
        Self { limbs }
    }

    /// Unpacks this value back into eight field elements, via the cheap [`to_radix_51`] bit
    /// realignment -- the result is "loose" the same way any [`FieldElement`] arithmetic result
    /// is loose (not necessarily the canonical representative in `[0, p)`), which is fine: callers
    /// that need a canonical answer already call [`FieldElement::to_bytes`] or
    /// [`FieldElement::eq`], same as with any other loose `FieldElement`.
    pub(crate) fn to_lanes(self) -> [FieldElement; LANES] {
        core::array::from_fn(|i| {
            let f = core::array::from_fn(|limb| self.limbs[limb][i]);
            FieldElement(to_radix_51(f))
        })
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
        let mut limbs = [[0u64; LANES]; 5];
        for ((out_row, a_row), b_row) in limbs.iter_mut().zip(&self.limbs).zip(&rhs.limbs) {
            for ((out, a), b) in out_row.iter_mut().zip(a_row).zip(b_row) {
                *out = a + b;
            }
        }
        let mut out = Self { limbs };
        out.carry_in_place();
        out
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
        let mut limbs = [[0u64; LANES]; 5];
        for (((out_row, a_row), b_row), bias) in limbs
            .iter_mut()
            .zip(&self.limbs)
            .zip(&rhs.limbs)
            .zip(SUB_BIAS)
        {
            for ((out, a), b) in out_row.iter_mut().zip(a_row).zip(b_row) {
                *out = a + bias - b;
            }
        }
        let mut out = Self { limbs };
        out.carry_in_place();
        out
    }

    fn carry_in_place(&mut self) {
        for i in 0..LANES {
            let l = core::array::from_fn(|limb| self.limbs[limb][i]);
            let c = carry(l);
            for (row, value) in self.limbs.iter_mut().zip(c) {
                row[i] = value;
            }
        }
    }

    /// Fully reduces every lane so each of its 5 limbs is strictly `< 2^52` -- the only way to
    /// obtain a [`Reduced`] value, and the only thing that makes it safe to feed into
    /// [`Reduced::mul`]/[`Reduced::square`]'s AVX-512 backend. See [`reduce_limbs`] for why three
    /// passes.
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
    /// `LANES` copies of zero, every limb trivially `< 2^52`.
    pub(crate) const ZERO: Self = Self {
        limbs: [[0; LANES]; 5],
    };

    /// Adds two `Reduced` values. The sum is not itself guaranteed `< 2^52` per limb, so the
    /// result is [`Unreduced`]; callers needing to multiply/square it call [`Unreduced::reduce`]
    /// first.
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

    fn mul_portable(&self, rhs: &Self) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for i in 0..LANES {
            let a = core::array::from_fn(|limb| self.limbs[limb][i]);
            let b = core::array::from_fn(|limb| rhs.limbs[limb][i]);
            let c = mul_lane(a, b);
            for (row, value) in limbs.iter_mut().zip(c) {
                row[i] = value;
            }
        }
        Self { limbs }
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

    fn square_portable(&self) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for i in 0..LANES {
            let a = core::array::from_fn(|limb| self.limbs[limb][i]);
            let c = square_lane(a);
            for (row, value) in limbs.iter_mut().zip(c) {
                row[i] = value;
            }
        }
        Self { limbs }
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

/// Computes one step of the Hisil-Wong-Carter-Dawson unified point-addition formula 8-wide (see
/// [`crate::signing::point::PointVec::add`]) via a single fused AVX-512 function when available,
/// with every intermediate held in registers rather than round-tripping through memory once per
/// field operation (see [`avx512::point_add`]'s doc comment) -- returns `None` on any CPU without
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

/// Computes the dedicated `dbl-2008-hwcd` doubling formula 8-wide (see
/// [`crate::signing::point::PointVec::double`]) via a single fused AVX-512 function when
/// available, same [`fused_point_add`] pattern and for the same reason (see
/// [`avx512::point_double`]'s doc comment) -- returns `None` on any CPU without this backend.
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

    /// Every limb of a [`Reduced`] value must be strictly `< 2^52` -- the whole point of the
    /// type. `Unreduced::reduce` (backed by [`reduce_limbs`]) is the only way to produce one, so
    /// this is the type's core safety property, checked here over many random inputs.
    #[test]
    fn reduce_produces_strictly_bounded_limbs() {
        let mut rng = test_rng();
        for _ in 0..256 {
            let a = rand_lanes(&mut rng);
            let reduced = Unreduced::from_lanes(&a).reduce();
            for row in reduced.limbs {
                for limb in row {
                    assert!(limb < (1u64 << 52));
                }
            }
        }
    }

    /// [`reduce_limbs`] against the exact adversarial cases found by deliberately constructing
    /// 5-limb inputs designed to leave limb 1 at exactly `2^52` after one [`carry`] pass (the one
    /// limb [`carry`]'s own doc comment says is not necessarily masked) -- see the design
    /// analysis this crate's AVX-512 correctness fix was based on. A single [`carry`] pass landing
    /// exactly on this boundary is the exact failure mode that silently corrupted AVX-512 results
    /// (`vpmadd52lo`/`vpmadd52hi` truncate a `2^52` limb to zero); this checks `reduce_limbs`
    /// (three passes) resolves every one of them to a strictly bounded value congruent to the
    /// original mod `p`.
    #[test]
    fn reduce_settles_adversarial_boundary_cases() {
        const MASK: u64 = (1u64 << 52) - 1;
        const B: u64 = 1u64 << 52;

        // Each case: (l0, l1, l2, l3, l4) engineered so that, after one `carry()` pass, limb 1
        // lands at exactly `2^52` (found via the exact/concrete search described in the design
        // analysis, not sampled randomly; verified against a Python model of `carry()` before
        // being hardcoded here).
        let cases: &[[u64; 5]] = &[
            [B - 608, B - 1, B - 1, B - 1, B],
            [B - 1, B - 1, B - 1, B - 1, 1u64 << 60],
            [B - 1000, B - 1, B - 1, B - 1, (1u64 << 60) + 12345],
        ];

        for &case in cases {
            // Confirm the premise: one `carry()` pass really does land limb 1 at exactly 2^52 for
            // this input (otherwise the case doesn't exercise what it claims to).
            assert_eq!(
                carry(case)[1],
                B,
                "test case no longer lands limb 1 at exactly 2^52 after one carry() pass"
            );

            let reduced = reduce_limbs(case);
            for &limb in &reduced {
                assert!(limb <= MASK, "limb {limb} not strictly < 2^52");
            }

            // Value congruence mod p is preserved through reduce_limbs (the same property the
            // Python analysis checked): both are radix-2^52 representations of values congruent
            // mod p, so re-expressing each as radix-2^51 (via `to_radix_51`, itself value-
            // preserving) and comparing the canonical `FieldElement` encoding confirms it.
            let to_bytes = |l: [u64; 5]| FieldElement(to_radix_51(l)).to_bytes();
            assert_eq!(to_bytes(case), to_bytes(reduced));
        }
    }
}
