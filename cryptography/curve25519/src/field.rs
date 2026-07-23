//! Arithmetic in the base field GF(2^255 - 19) underlying curve25519 point coordinates.
//!
//! Elements are held as five 51-bit unsigned limbs (little-endian by weight). Limbs are kept
//! "loose" between operations (each may run a few bits over 51) and are only fully canonicalized
//! in [`FieldElement::to_bytes`]. Signature verification only ever operates on public data, so
//! every operation here is variable-time; there is no need to pay for constant-time arithmetic.

const MASK_51: u64 = (1 << 51) - 1;

/// An element of the field GF(2^255 - 19).
#[derive(Copy, Clone, Debug)]
pub(crate) struct FieldElement(pub(crate) [u64; 5]);

impl FieldElement {
    pub(crate) const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// The curve25519 twisted-Edwards curve constant `d = -121665/121666 mod p`.
    pub(crate) const EDWARDS_D: Self = Self([
        0x0034dca135978a3,
        0x001a8283b156ebd,
        0x005e7a26001c029,
        0x00739c663a03cbb,
        0x0052036cee2b6ff,
    ]);

    /// A fixed square root of `-1` in the field, used to recover `x` from `y` when decompressing
    /// a point whose candidate `x` has the wrong sign of square.
    pub(crate) const SQRT_M1: Self = Self([
        0x0061b274a0ea0b0,
        0x000d5a5fc8f189d,
        0x007ef5e9cbd0c60,
        0x0078595a6804c9e,
        0x002b8324804fc1d,
    ]);

    /// Parses a little-endian 255-bit value (the top bit of `bytes[31]`, i.e. bit 255, is
    /// dropped). Values in `[p, 2^255)` are accepted and represented redundantly rather than
    /// rejected; use [`FieldElement::to_bytes`] to obtain the canonical representative.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(chunk)
        };

        Self([
            load8(0) & MASK_51,
            (load8(6) >> 3) & MASK_51,
            (load8(12) >> 6) & MASK_51,
            (load8(19) >> 1) & MASK_51,
            (load8(24) >> 12) & MASK_51,
        ])
    }

    /// Fully carry-propagates the limbs, folding any overflow past bit 255 back in via the
    /// `2^255 = 19` identity. The result is bounded (each limb `< 2^51 + O(1)`) but not
    /// necessarily the canonical representative in `[0, p)`.
    const fn carry(&self) -> Self {
        let mut l = self.0;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        l[2] += l[1] >> 51;
        l[1] &= MASK_51;
        l[3] += l[2] >> 51;
        l[2] &= MASK_51;
        l[4] += l[3] >> 51;
        l[3] &= MASK_51;
        l[0] += (l[4] >> 51) * 19;
        l[4] &= MASK_51;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        Self(l)
    }

    /// Serializes the canonical representative of this element (fully reduced mod `p`) as
    /// 255 bits in little-endian order; bit 255 (the top bit of the last byte) is always 0.
    pub(crate) const fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().0;

        // q = 1 if l >= p, else 0: adding 19 and folding the carry through all five limbs
        // overflows bit 255 exactly when l + 19 >= 2^255, i.e. when l >= p.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;

        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        l[2] += l[1] >> 51;
        l[1] &= MASK_51;
        l[3] += l[2] >> 51;
        l[2] &= MASK_51;
        l[4] += l[3] >> 51;
        l[3] &= MASK_51;
        l[4] &= MASK_51;

        let mut out = [0u8; 32];
        out[0] = l[0] as u8;
        out[1] = (l[0] >> 8) as u8;
        out[2] = (l[0] >> 16) as u8;
        out[3] = (l[0] >> 24) as u8;
        out[4] = (l[0] >> 32) as u8;
        out[5] = (l[0] >> 40) as u8;
        out[6] = ((l[0] >> 48) | (l[1] << 3)) as u8;
        out[7] = (l[1] >> 5) as u8;
        out[8] = (l[1] >> 13) as u8;
        out[9] = (l[1] >> 21) as u8;
        out[10] = (l[1] >> 29) as u8;
        out[11] = (l[1] >> 37) as u8;
        out[12] = ((l[1] >> 45) | (l[2] << 6)) as u8;
        out[13] = (l[2] >> 2) as u8;
        out[14] = (l[2] >> 10) as u8;
        out[15] = (l[2] >> 18) as u8;
        out[16] = (l[2] >> 26) as u8;
        out[17] = (l[2] >> 34) as u8;
        out[18] = (l[2] >> 42) as u8;
        out[19] = ((l[2] >> 50) | (l[3] << 1)) as u8;
        out[20] = (l[3] >> 7) as u8;
        out[21] = (l[3] >> 15) as u8;
        out[22] = (l[3] >> 23) as u8;
        out[23] = (l[3] >> 31) as u8;
        out[24] = (l[3] >> 39) as u8;
        out[25] = ((l[3] >> 47) | (l[4] << 4)) as u8;
        out[26] = (l[4] >> 4) as u8;
        out[27] = (l[4] >> 12) as u8;
        out[28] = (l[4] >> 20) as u8;
        out[29] = (l[4] >> 28) as u8;
        out[30] = (l[4] >> 36) as u8;
        out[31] = (l[4] >> 44) as u8;
        out
    }

    /// Returns `true` if the canonical representatives of `self` and `other` are equal.
    pub(crate) fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Returns `true` if this element's canonical representative is 0.
    pub(crate) fn is_zero(&self) -> bool {
        self.eq(&Self::ZERO)
    }

    /// Returns `true` if the canonical representative of this element is odd.
    pub(crate) const fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub(crate) const fn add(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        Self([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
        .carry()
    }

    pub(crate) const fn sub(&self, rhs: &Self) -> Self {
        // `SUB_BIAS` is 16*p, decomposed the same way any redundant field value would be, so
        // adding it changes nothing mod p; it just keeps every limb-wise subtraction below
        // non-negative (`rhs`'s limbs are always well under 2^51 here).
        const SUB_BIAS: [u64; 5] = [
            16 * ((1u64 << 51) - 19),
            16 * ((1u64 << 51) - 1),
            16 * ((1u64 << 51) - 1),
            16 * ((1u64 << 51) - 1),
            16 * ((1u64 << 51) - 1),
        ];
        let a = self.0;
        let b = rhs.0;
        Self([
            a[0] + SUB_BIAS[0] - b[0],
            a[1] + SUB_BIAS[1] - b[1],
            a[2] + SUB_BIAS[2] - b[2],
            a[3] + SUB_BIAS[3] - b[3],
            a[4] + SUB_BIAS[4] - b[4],
        ])
        .carry()
    }

    pub(crate) const fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        // Products with a weight of 2^255 or more (i.e. b[j] for a column beyond limb 4) are
        // folded back in early via 2^255 = 19 (mod p).
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let m = |x: u64, y: u64| (x as u128) * (y as u128);

        let c0 = m(a[0], b[0]) + m(a[1], b4_19) + m(a[2], b3_19) + m(a[3], b2_19) + m(a[4], b1_19);
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_19) + m(a[3], b3_19) + m(a[4], b2_19);
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_19) + m(a[4], b3_19);
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

        // Carry propagate the wide (u128) accumulators down to 51-bit limbs, folding the final
        // overflow back in via 2^255 = 19, then run the same short limb-wise carry as `carry()`.
        let mask = MASK_51 as u128;
        let c1 = c1 + (c0 >> 51);
        let c0 = (c0 & mask) as u64;
        let c2 = c2 + (c1 >> 51);
        let c1 = (c1 & mask) as u64;
        let c3 = c3 + (c2 >> 51);
        let c2 = (c2 & mask) as u64;
        let c4 = c4 + (c3 >> 51);
        let c3 = (c3 & mask) as u64;
        let carry4 = (c4 >> 51) as u64;
        let c4 = (c4 & mask) as u64;

        Self([c0 + carry4 * 19, c1, c2, c3, c4]).carry()
    }

    /// Squares `self`. A dedicated formula rather than `self.mul(self)`: since `a[i]*a[j]` and
    /// `a[j]*a[i]` are the same product, every cross term is computed once and doubled (a cheap
    /// add) instead of computed twice (an extra multiply) -- 15 limb multiplies here versus 25 in
    /// the general schoolbook `mul`, the standard ~30-40% squaring speedup essentially every
    /// Curve25519 implementation uses (see e.g. curve25519-dalek's `square`/`pow2k`). This matters
    /// a lot for [`FieldElement::pow_p58`], which is 251 squarings and only 11 multiplies.
    pub(crate) fn square(&self) -> Self {
        let a = self.0;

        // Only the top two limbs' folds are needed: squaring's pairing structure (see below)
        // never needs a1/a2 pre-folded the way the general `mul` does.
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;

        let m = |x: u64, y: u64| (x as u128) * (y as u128);

        let c0 = m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19));
        let c1 = m(a[3], a3_19) + 2 * (m(a[0], a[1]) + m(a[2], a4_19));
        let c2 = m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_19));
        let c3 = m(a[4], a4_19) + 2 * (m(a[0], a[3]) + m(a[1], a[2]));
        let c4 = m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3]));

        // Same carry propagation as `mul`.
        let mask = MASK_51 as u128;
        let c1 = c1 + (c0 >> 51);
        let c0 = (c0 & mask) as u64;
        let c2 = c2 + (c1 >> 51);
        let c1 = (c1 & mask) as u64;
        let c3 = c3 + (c2 >> 51);
        let c2 = (c2 & mask) as u64;
        let c4 = c4 + (c3 >> 51);
        let c3 = (c3 & mask) as u64;
        let carry4 = (c4 >> 51) as u64;
        let c4 = (c4 & mask) as u64;

        Self([c0 + carry4 * 19, c1, c2, c3, c4]).carry()
    }

    /// Squares `self` `k` times in a row.
    pub(crate) fn pow2k(&self, k: u32) -> Self {
        let mut result = *self;
        for _ in 0..k {
            result = result.square();
        }
        result
    }

    /// Raises `self` to the power `2^250 - 1`, via the standard chain of `2^k - 1`-exponent
    /// building blocks (each doubling the previous block's bit-length via `pow2k`, then filling in
    /// the low half with one multiply): the same chain used by essentially every Curve25519
    /// implementation for combined inversion/sqrt exponentiations, needing only 251 squarings and
    /// 11 multiplications total (with [`FieldElement::pow_p58`]'s own 2 extra squarings and 1
    /// extra multiply) versus the `~252 squarings + ~251 multiplications` a naive square-and-
    /// multiply loop over this exponent's mostly-`1` bits would cost.
    fn pow_2_250_minus_1(&self) -> Self {
        let a = self.square(); // self^2
        let a2 = a.square().square(); // self^8
        let b = self.mul(&a2); // self^9 = self^(2^3 + 2^0)
        let c = a.mul(&b); // self^11 = self^(2^3 + 2^1 + 2^0)
        let d = c.square(); // self^22
        let e = b.mul(&d); // self^31 = self^(2^5 - 1)
        let f = e.pow2k(5).mul(&e); // self^(2^10 - 1)
        let g = f.pow2k(10).mul(&f); // self^(2^20 - 1)
        let h = g.pow2k(20).mul(&g); // self^(2^40 - 1)
        let i = h.pow2k(10).mul(&f); // self^(2^50 - 1)
        let j = i.pow2k(50).mul(&i); // self^(2^100 - 1)
        let k = j.pow2k(100).mul(&j); // self^(2^200 - 1)
        k.pow2k(50).mul(&i) // self^(2^250 - 1)
    }

    /// Raises `self` to the power `(p - 5) / 8 = 2^252 - 3`. Used, together with case analysis
    /// on the result, to compute a modular square root as part of point decompression.
    pub(crate) fn pow_p58(&self) -> Self {
        // self^(2^250 - 1), shifted up by 2 bits (2 more squarings) to self^(2^252 - 4), then one
        // more multiply by `self` fills in the bottom bit: self^(2^252 - 3).
        self.mul(&self.pow_2_250_minus_1().pow2k(2))
    }
}

/// Test-only helpers shared across this crate's test modules.
#[cfg(test)]
pub(crate) mod test_support {
    use super::FieldElement;
    use rand_core::Rng;

    /// Returns a valid (possibly non-canonically-encoded) field element, by parsing 32 random
    /// bytes the same way [`FieldElement::from_bytes`] parses any point's `y` coordinate.
    pub(crate) fn rand_field_element(rng: &mut impl Rng) -> FieldElement {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        FieldElement::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, test_support::rand_field_element};
    use commonware_utils::test_rng;

    /// Exponent bits of `(p - 5) / 8 = 2^252 - 3`, most-significant limb first, most-significant
    /// bit first: used only by [`pow_p58_naive`] below.
    const POW_P58_EXP: [u64; 4] = [
        0x0fff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_fffd,
    ];

    /// The original, naive square-and-multiply reference this crate used before switching to the
    /// standard `2^k - 1`-chain [`FieldElement::pow_p58`]: kept here only to differentially test
    /// the optimized version against, since both compute the same well-defined power.
    fn pow_p58_naive(x: &FieldElement) -> FieldElement {
        let mut result = FieldElement::ONE;
        for limb in POW_P58_EXP {
            for bit in (0..64).rev() {
                result = result.square();
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(x);
                }
            }
        }
        result
    }

    #[test]
    fn pow_p58_matches_naive_reference() {
        let mut rng = test_rng();
        for _ in 0..256 {
            let x = rand_field_element(&mut rng);
            assert!(x.pow_p58().eq(&pow_p58_naive(&x)));
        }
    }

    #[test]
    fn square_matches_mul_self() {
        let mut rng = test_rng();
        for _ in 0..256 {
            let x = rand_field_element(&mut rng);
            assert!(x.square().eq(&x.mul(&x)));
        }
    }
}
