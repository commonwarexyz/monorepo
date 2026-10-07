use self::msm::Backend as MBackend;
use core::array;
use subtle::{Choice, ConditionallySelectable};

/// Number of independent field or group elements carried by a vector for SIMD operations.
///
/// This targets AVX-512's eight 64-bit lanes, the widest native vector used by these backends.
/// Backends with narrower registers emulate this lane count by processing smaller native tiles,
/// such as NEON's two-lane tiles.
///
/// A larger logical lane count can increase memory pressure, so operations that do not need
/// all lanes can use smaller tiles directly.
pub const LANES: usize = 8;

/// The number of limbs in a field element.
const LIMBS: usize = 5;

/// The radix exponent: each limb holds `LIMB_BITS` bits once carries have been propagated out of
/// it, so a field element is `sum(limb[i] * 2^(LIMB_BITS * i))`.
const LIMB_BITS: usize = 51;

/// The low [`LIMB_BITS`] bits: what a limb holds once carries have been propagated out of it.
const MASK_51: u64 = (1 << LIMB_BITS) - 1;

/// `16*p`, decomposed limb-wise at radix `2^LIMB_BITS`, used to make subtraction underflow-free.
const BIAS_16P: [u64; LIMBS] = [
    16 * ((1u64 << LIMB_BITS) - 19),
    16 * ((1u64 << LIMB_BITS) - 1),
    16 * ((1u64 << LIMB_BITS) - 1),
    16 * ((1u64 << LIMB_BITS) - 1),
    16 * ((1u64 << LIMB_BITS) - 1),
];

/// A base field element in the field of order `p = 2^255 - 19`.
///
/// The five limbs use radix `2^51`. The representation is redundant: values need not be
/// canonical, but every arithmetic operation accepts and returns limbs less than `2^52`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct F(pub [u64; LIMBS]);

// Secret-dependent selection goes through `subtle`, whose `Choice` sits behind an optimization
// barrier so the compiler cannot prove the mask is 0/-1 and lower the select to a branch.
impl ConditionallySelectable for F {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(array::from_fn(|i| {
            u64::conditional_select(&a.0[i], &b.0[i], choice)
        }))
    }
}

impl F {
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// The curve25519 twisted-Edwards curve constant `d = -121665/121666 mod p`.
    pub const EDWARDS_D: Self = Self([
        0x0034dca135978a3,
        0x001a8283b156ebd,
        0x005e7a26001c029,
        0x00739c663a03cbb,
        0x0052036cee2b6ff,
    ]);

    /// `2 * EDWARDS_D`.
    pub const EDWARDS_D2: Self = Self([
        2 * Self::EDWARDS_D.0[0],
        2 * Self::EDWARDS_D.0[1],
        2 * Self::EDWARDS_D.0[2],
        2 * Self::EDWARDS_D.0[3],
        2 * Self::EDWARDS_D.0[4],
    ]);

    /// A fixed square root of `-1` in the field.
    pub const SQRT_M1: Self = Self([
        0x0061b274a0ea0b0,
        0x000d5a5fc8f189d,
        0x007ef5e9cbd0c60,
        0x0078595a6804c9e,
        0x002b8324804fc1d,
    ]);

    /// Parses a little-endian 255-bit value, ignoring bit 255.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(chunk)
        };

        let mut limbs = [0; LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let bit = i * LIMB_BITS;
            let offset = (bit / 8).min(bytes.len() - 8);
            *limb = (load8(offset) >> (bit - 8 * offset)) & MASK_51;
        }
        Self(limbs)
    }

    /// Restores the `< 2^52` limb bound without canonicalizing the field element.
    ///
    /// Inputs must have limbs below `2^63`.
    #[inline(always)]
    const fn reduce(mut l: [u64; LIMBS]) -> Self {
        let mut i = 0;
        while i < LIMBS - 1 {
            l[i + 1] += l[i] >> LIMB_BITS;
            l[i] &= MASK_51;
            i += 1;
        }

        // The carry out of limb 4 has at most 13 bits, so the fold stays below the `2^52` limb
        // bound for every input and the compiler drops the multiply's overflow check.
        const _: () = assert!(MASK_51 + (u64::MAX >> LIMB_BITS) * 19 < 1 << (LIMB_BITS + 1));
        l[0] += (l[LIMBS - 1] >> LIMB_BITS) * 19;
        l[LIMBS - 1] &= MASK_51;
        Self(l)
    }

    /// Carry-propagates the limbs for canonical serialization.
    ///
    /// The returned limbs are below `2^51`, except limb 1, which may equal `2^51`.
    const fn carry(&self) -> Self {
        let mut l = Self::reduce(self.0).0;
        l[1] += l[0] >> LIMB_BITS;
        l[0] &= MASK_51;
        Self(l)
    }

    /// Serializes the canonical representative as 255 little-endian bits.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().0;

        // Adding 19 overflows bit 255 exactly when l >= p.
        let mut q = 19;
        for &limb in &l {
            q = (limb + q) >> LIMB_BITS;
        }

        l[0] += 19 * q;
        for i in 0..LIMBS - 1 {
            l[i + 1] += l[i] >> LIMB_BITS;
            l[i] &= MASK_51;
        }
        l[LIMBS - 1] &= MASK_51;

        let mut words = [0u64; 4];
        for (i, limb) in l.into_iter().enumerate() {
            let bit = i * LIMB_BITS;
            let word = bit / 64;
            let shift = bit % 64;
            words[word] |= limb << shift;
            if shift > 64 - LIMB_BITS {
                words[word + 1] |= limb >> (64 - shift);
            }
        }

        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        out
    }

    /// Returns whether two canonical representatives are equal.
    ///
    /// Variable-time, so use only with public field elements.
    pub fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Returns whether the canonical representative is zero.
    ///
    /// Variable-time, so use only with public field elements.
    pub fn is_zero(&self) -> bool {
        self.eq(&Self::ZERO)
    }

    /// Returns whether the canonical representative is odd.
    pub fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Returns `self + rhs`.
    #[inline(always)]
    pub const fn add(self, rhs: Self) -> Self {
        let mut l = self.0;
        let mut i = 0;
        while i < l.len() {
            l[i] += rhs.0[i];
            i += 1;
        }
        Self::reduce(l)
    }

    /// Returns `self - rhs`.
    #[inline(always)]
    pub const fn sub(self, rhs: Self) -> Self {
        let mut l = self.0;
        let mut i = 0;
        while i < l.len() {
            l[i] = l[i] + BIAS_16P[i] - rhs.0[i];
            i += 1;
        }
        Self::reduce(l)
    }

    /// Returns `-self`.
    #[inline(always)]
    pub const fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Reduces [`LIMBS`] wide radix-`2^LIMB_BITS` columns to the scalar limb bound.
    #[inline(always)]
    const fn from_wide(mut c: [u128; LIMBS]) -> Self {
        const MASK: u128 = MASK_51 as u128;
        let mut i = 0;
        while i < LIMBS - 1 {
            c[i + 1] += c[i] >> LIMB_BITS;
            c[i] &= MASK;
            i += 1;
        }

        // The carry out of column 4 has at most 77 bits, so the fold stays below `2^102` for
        // every input, the final carry keeps limb 1 below the `2^52` limb bound, and the compiler
        // drops the multiply's overflow check.
        const _: () = assert!(MASK + (u128::MAX >> LIMB_BITS) * 19 < 1 << (2 * LIMB_BITS));
        c[0] += 19 * (c[LIMBS - 1] >> LIMB_BITS);
        c[LIMBS - 1] &= MASK;
        c[1] += c[0] >> LIMB_BITS;
        c[0] &= MASK;

        Self([
            c[0] as u64,
            c[1] as u64,
            c[2] as u64,
            c[3] as u64,
            c[4] as u64,
        ])
    }

    /// Returns `self * rhs`.
    #[inline(always)]
    pub const fn mul(self, rhs: Self) -> Self {
        // Accumulate the nine schoolbook columns, then fold columns 5 through 8 down using
        // `2^255 = 19 (mod p)`. At the input bound, every folded column remains below `2^112`.
        let mut c = [0u128; 2 * LIMBS - 1];
        let mut i = 0;
        while i < LIMBS {
            let mut j = 0;
            while j < LIMBS {
                c[i + j] += self.0[i] as u128 * rhs.0[j] as u128;
                j += 1;
            }
            i += 1;
        }
        let mut i = 0;
        while i < LIMBS - 1 {
            // On AArch64, a checked u128 multiply lowers to a branch on the operand's magnitude.
            // Every column stays below `2^107` at the input bound, so assert that bound and
            // multiply without a check.
            assert!(c[i + LIMBS] < 1 << 107);
            c[i] += c[i + LIMBS].wrapping_mul(19);
            i += 1;
        }
        Self::from_wide([c[0], c[1], c[2], c[3], c[4]])
    }

    /// Returns `self * self` using one product for each pair of distinct limbs.
    #[inline(always)]
    pub const fn square(self) -> Self {
        let limbs = self.0;
        let mut limbs_19 = limbs;
        let mut k = 3;
        while k < LIMBS {
            limbs_19[k] *= 19;
            k += 1;
        }

        // Each product of distinct limbs occurs twice, so it takes its left factor from `limbs_2`.
        let mut limbs_2 = limbs;
        let mut k = 0;
        while k < LIMBS - 1 {
            limbs_2[k] *= 2;
            k += 1;
        }

        let mut c = [0u128; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            let mut j = i;
            while j < LIMBS {
                let column = i + j;
                let (column, rhs) = if column < LIMBS {
                    (column, limbs[j])
                } else {
                    (column - LIMBS, limbs_19[j])
                };
                let lhs = if i == j { limbs[i] } else { limbs_2[i] };
                c[column] += lhs as u128 * rhs as u128;
                j += 1;
            }
            i += 1;
        }
        Self::from_wide(c)
    }

    /// Squares `self` `k` times.
    const fn pow2k(mut self, k: u32) -> Self {
        let mut n = 0;
        while n < k {
            self = self.square();
            n += 1;
        }
        self
    }

    /// Raises `self` to `2^250 - 1` using the standard addition chain.
    const fn pow_2_250_minus_1(self) -> Self {
        let a = self.square();
        let a2 = a.square().square();
        let b = self.mul(a2);
        let c = a.mul(b);
        let d = c.square();
        let e = b.mul(d);
        let f = e.pow2k(5).mul(e);
        let g = f.pow2k(10).mul(f);
        let h = g.pow2k(20).mul(g);
        let i = h.pow2k(10).mul(f);
        let j = i.pow2k(50).mul(i);
        let k = j.pow2k(100).mul(j);
        k.pow2k(50).mul(i)
    }

    /// Raises `self` to `(p - 5) / 8 = 2^252 - 3`.
    const fn pow_p58(self) -> Self {
        self.mul(self.pow_2_250_minus_1().pow2k(2))
    }

    /// Returns the multiplicative inverse of `self`.
    const fn invert(self) -> Self {
        self.pow_p58().pow2k(3).mul(self.square().mul(self))
    }
}

/// A vector of base field elements in the field of order `p = 2^255 - 19`.
///
/// Each lane is represented by five 64-bit limbs in radix `2^51`:
///
/// ```text
/// x = l0 + l1*2^51 + l2*2^102 + l3*2^153 + l4*2^204
/// ```
///
/// This representation is redundant: a limb may exceed 51 bits, and the value may exceed `p`.
/// This allows addition to be performed limb-wise, with carrying deferred until the end of an
/// operation. Overflow past bit 255 re-enters limb 0 multiplied by 19 because
/// `2^255 = 19 (mod p)`.
///
/// Every field operation accepts and produces values whose limbs are less than `2^52`. Keeping
/// one shared bound rather than separate loose and tight representations makes each operation's
/// correctness independent of the operation that produced its inputs.
///
/// Operations over this type apply to each lane in parallel, using SIMD instructions when the
/// selected backend supports them.
#[derive(Clone, Copy)]
#[repr(align(64))]
pub struct FVec {
    // We could have a dynamic number of lanes here, depending on the backend,
    // but it's easier to just have a fixed number, perhaps dispatching several
    // instructions for backends with fewer lanes.
    limbs: [[u64; LANES]; LIMBS],
}

impl FVec {
    /// Returns every lane set to `element`.
    pub const fn splat(element: F) -> Self {
        Self {
            limbs: [
                [element.0[0]; LANES],
                [element.0[1]; LANES],
                [element.0[2]; LANES],
                [element.0[3]; LANES],
                [element.0[4]; LANES],
            ],
        }
    }

    /// Transposes scalar field elements into limb rows.
    pub fn transpose(lanes: [F; LANES]) -> Self {
        let mut limbs = [[0u64; LANES]; LIMBS];
        for (i, lane) in lanes.iter().enumerate() {
            for (row, value) in limbs.iter_mut().zip(lane.0) {
                row[i] = value;
            }
        }
        Self { limbs }
    }

    /// Untransposes limb rows into scalar field elements.
    pub fn untranspose(self) -> [F; LANES] {
        array::from_fn(|i| F(array::from_fn(|limb| self.limbs[limb][i])))
    }
}

/// Abstracts over base field operations.
pub trait FBackend: Copy {
    /// a + b.
    fn add(self, a: FVec, b: FVec) -> FVec;

    /// -a.
    fn neg(self, a: FVec) -> FVec;

    /// a * b.
    fn mul(self, a: FVec, b: FVec) -> FVec;

    /// a * a.
    fn square(self, a: FVec) -> FVec {
        self.mul(a, a)
    }

    /// Squares every lane `k` times, returning `a` unchanged when `k` is zero.
    #[inline(always)]
    fn pow2k(self, mut a: FVec, k: u32) -> FVec {
        for _ in 0..k {
            a = self.square(a);
        }
        a
    }

    /// a - b.
    fn sub(self, a: FVec, b: FVec) -> FVec {
        self.add(a, self.neg(b))
    }
}

/// A compact point on the twisted Edwards curve in extended homogeneous coordinates.
///
/// This is the scalar representation used directly for individual point operations and as the
/// array-of-structures representation between vector operations. Its coordinates are laid out
/// as 20 consecutive limbs, so backends can load several points straight into lanes.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct G {
    x: F,
    y: F,
    t: F,
    z: F,
}

impl G {
    /// The neutral element, `(0, 1)` in affine coordinates.
    pub const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t: F::ZERO,
        z: F::ONE,
    };

    /// Compresses this point to its canonical Ed25519 encoding.
    pub fn compress(self) -> [u8; 32] {
        let z_inverse = self.z.invert();
        let x = self.x.mul(z_inverse);
        let mut bytes = self.y.mul(z_inverse).to_bytes();
        bytes[31] |= u8::from(x.is_odd()) << 7;
        bytes
    }

    /// Converts this point to affine representation.
    pub const fn to_affine(self) -> GAffine {
        let z_inverse = self.z.invert();
        let x = self.x.mul(z_inverse);
        let y = self.y.mul(z_inverse);
        GAffine {
            x,
            y,
            t2d: x.mul(y).mul(F::EDWARDS_D2),
        }
    }

    /// Negates this point.
    pub const fn negate(self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }

    /// Adds two points using the complete unified formula for `a = -1`.
    #[inline(always)]
    pub const fn add(self, rhs: Self) -> Self {
        // Hisil-Wong-Carter-Dawson, "Twisted Edwards Curves Revisited",
        // add-2008-hwcd-3 specialized to a = -1:
        //
        //   A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
        //   B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
        //   C = 2d * T1 * T2                 G = D + C        Z3 = F*G
        //   D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
        //
        // The formula is complete because a = -1 is a square and d is non-square. The
        // extended-coordinate invariant holds identically: (E*H)*(F*G) = (E*F)*(G*H).
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(rhs.t).mul(F::EDWARDS_D2);
        let zz = self.z.mul(rhs.z);
        let d = zz.add(zz);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// Adds an affine point using its precomputed `2d*x*y` coordinate.
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    #[inline(always)]
    pub const fn add_mixed(self, rhs: GAffine) -> Self {
        self.add_niels(Niels {
            sum: rhs.y.add(rhs.x),
            diff: rhs.y.sub(rhs.x),
            t2d: rhs.t2d,
        })
    }

    /// Adds a point in [`Niels`] form: [`G::add`] specialized to an operand whose `Z` is one.
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    #[inline(always)]
    const fn add_niels(self, rhs: Niels) -> Self {
        // The steps of `G::add` with `Z2 = 1`. The Niels form supplies `Y2 - X2`, `Y2 + X2`, and
        // `2d*T2`, so `C` takes one multiplication and `D = 2*Z1` takes none.
        let a = self.y.sub(self.x).mul(rhs.diff);
        let b = self.y.add(self.x).mul(rhs.sum);
        let c = self.t.mul(rhs.t2d);
        let d = self.z.add(self.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// Doubles this point using the dedicated `dbl-2008-hwcd` formula.
    #[inline(always)]
    pub const fn double(self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(c);
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = b.sub(a);
        let f = g.sub(c);
        let h = a.neg().sub(b);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// Multiplies this point by a public scalar bit sequence using variable-time double-and-add.
    #[cfg(test)]
    pub fn scalar_mul(self, bits: impl IntoIterator<Item = bool>) -> Self {
        let mut result = Self::IDENTITY;
        for bit in bits {
            result = result.double();
            if bit {
                result = result.add(self);
            }
        }
        result
    }

    /// Multiplies this point by the curve's cofactor (8).
    pub fn mul_by_cofactor(mut self) -> Self {
        for _ in 0..3 {
            self = self.double();
        }
        self
    }

    /// Returns whether this point represents the identity.
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }

    /// Drops the `T` coordinate, which doubling does not read.
    #[inline(always)]
    const fn to_projective(self) -> GProjective {
        GProjective {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    /// Prepares this point for repeated additions with [`Backend::add_cached`].
    #[inline(always)]
    const fn to_projective_niels(self) -> ProjectiveNiels {
        ProjectiveNiels {
            sum: self.y.add(self.x),
            diff: self.y.sub(self.x),
            z: self.z,
            t2d: self.t.mul(F::EDWARDS_D2),
        }
    }

    /// Adds a point in [`Niels`] form, deferring the final multiplications to the conversion of
    /// the returned completed point.
    #[inline(always)]
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    const fn add_niels_completed(self, rhs: Niels) -> GCompleted {
        // The steps of `G::add_niels` up to its final products.
        let a = self.y.sub(self.x).mul(rhs.diff);
        let b = self.y.add(self.x).mul(rhs.sum);
        let c = self.t.mul(rhs.t2d);
        let d = self.z.add(self.z);
        GCompleted::from_products(a, b, c, d)
    }

    /// Adds a point in [`ProjectiveNiels`] form, deferring the final multiplications to the
    /// conversion of the returned completed point.
    #[inline(always)]
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    const fn add_projective_niels(self, rhs: ProjectiveNiels) -> GCompleted {
        // The steps of `G::add` up to its final products, with `2d*T2` precomputed.
        let a = self.y.sub(self.x).mul(rhs.diff);
        let b = self.y.add(self.x).mul(rhs.sum);
        let c = self.t.mul(rhs.t2d);
        let zz = self.z.mul(rhs.z);
        GCompleted::from_products(a, b, c, zz.add(zz))
    }
}

/// A point in projective coordinates `(X:Y:Z)`, the affine point `(X/Z, Y/Z)`.
///
/// Doubling reads only these coordinates, so a chain of doublings can skip computing `T`.
#[derive(Clone, Copy, Debug)]
pub struct GProjective {
    x: F,
    y: F,
    z: F,
}

impl GProjective {
    /// Doubles this point with the steps of [`G::double`] up to its final products.
    #[inline(always)]
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    const fn double(self) -> GCompleted {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(c);
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = b.sub(a);
        let f = g.sub(c);
        let h = a.neg().sub(b);
        GCompleted {
            x: e,
            y: h,
            z: g,
            t: f,
        }
    }

    /// Multiplies this point by the curve's cofactor (8).
    #[cfg(test)]
    fn mul_by_cofactor(mut self) -> Self {
        for _ in 0..3 {
            self = self.double().to_projective();
        }
        self
    }

    /// Returns whether this point represents the identity.
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }

    /// Converts this point to extended coordinates.
    #[cfg(test)]
    pub const fn to_extended(self) -> G {
        G {
            x: self.x.mul(self.z),
            y: self.y.mul(self.z),
            t: self.x.mul(self.y),
            z: self.z.square(),
        }
    }
}

/// A point `((X:Z), (Y:T))`, the affine point `(X/Z, Y/T)`, as an addition or doubling leaves it
/// before its final multiplications.
///
/// Converting to [`GProjective`] takes three multiplications and to [`G`] four, so each
/// operation can compute only the coordinates the next one reads.
#[derive(Clone, Copy, Debug)]
pub struct GCompleted {
    x: F,
    y: F,
    z: F,
    t: F,
}

impl GCompleted {
    /// Finishes the complete addition formula of [`G::add`] from its products `A`, `B`, and `C`
    /// and `D = 2*Z1*Z2`.
    #[inline(always)]
    const fn from_products(a: F, b: F, c: F, d: F) -> Self {
        // In `G::add`'s notation, `X3/Z3 = E/G` and `Y3/Z3 = H/F`.
        Self {
            x: b.sub(a),
            y: b.add(a),
            z: d.add(c),
            t: d.sub(c),
        }
    }

    /// Converts this point to projective coordinates.
    #[inline(always)]
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    const fn to_projective(self) -> GProjective {
        GProjective {
            x: self.x.mul(self.t),
            y: self.z.mul(self.y),
            z: self.t.mul(self.z),
        }
    }

    /// Converts this point to extended coordinates.
    #[inline(always)]
    #[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
    const fn to_extended(self) -> G {
        G {
            x: self.x.mul(self.t),
            y: self.z.mul(self.y),
            t: self.x.mul(self.y),
            z: self.t.mul(self.z),
        }
    }
}

/// An affine point `(x, y)` stored as `(y + x, y - x, 2d*x*y)`.
///
/// The coordinates are laid out as 15 consecutive limbs, so backends can load them straight into
/// registers.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Niels {
    sum: F,
    diff: F,
    t2d: F,
}

impl Niels {
    /// The neutral element, `(0, 1)`.
    const IDENTITY: Self = Self {
        sum: F::ONE,
        diff: F::ONE,
        t2d: F::ZERO,
    };

    /// Negates this point, which swaps `y + x` with `y - x` and negates `2d*x*y`.
    #[inline(always)]
    const fn negate(self) -> Self {
        Self {
            sum: self.diff,
            diff: self.sum,
            t2d: self.t2d.neg(),
        }
    }
}

/// A point `(X:Y:Z:T)` in extended coordinates stored as `(Y + X, Y - X, Z, 2d*T)`, so adding it
/// with [`Backend::add_cached`] skips the multiplication by `2d`.
#[derive(Clone, Copy)]
pub struct ProjectiveNiels {
    sum: F,
    diff: F,
    z: F,
    t2d: F,
}

impl ProjectiveNiels {
    /// Negates this point, which swaps `Y + X` with `Y - X` and negates `2d*T`.
    #[inline(always)]
    const fn negate(self) -> Self {
        Self {
            sum: self.diff,
            diff: self.sum,
            z: self.z,
            t2d: self.t2d.neg(),
        }
    }
}

/// A compact affine point prepared for mixed addition.
///
/// This stores individual affine points and their precomputed `2d*x*y` coordinate. Its
/// coordinates are laid out as 15 consecutive limbs, so backends can load several points straight
/// into lanes.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GAffine {
    x: F,
    y: F,
    t2d: F,
}

impl GAffine {
    /// The neutral element, `(0, 1)`.
    pub const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t2d: F::ZERO,
    };

    /// The standard Ed25519 base point, prepared for mixed addition.
    pub const BASEPOINT: Self = Self {
        x: F([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: F([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        t2d: F([
            301289933810280,
            1259582250014073,
            1422107436869536,
            796239922652654,
            1953934009299142,
        ]),
    };

    /// Decompresses a point encoding, accepting non-canonical `y` values and negative zero
    /// (`x = 0` with the sign bit set) per ZIP215.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let sign = bytes[31] >> 7;
        let y = F::from_bytes(bytes);

        // Recover x from x^2 = u/v, where u = y^2 - 1 and v = d*y^2 + 1.
        let y2 = y.square();
        let u = y2.sub(F::ONE);
        let v = F::EDWARDS_D.mul(y2).add(F::ONE);
        let uv = u.mul(v);
        let mut x = u.mul(uv.pow_p58());
        let vxx = v.mul(x.square());

        if vxx.eq(&u) {
            // The candidate is already a square root.
        } else if vxx.eq(&u.neg()) {
            x = x.mul(F::SQRT_M1);
        } else {
            return None;
        }

        if x.is_odd() != (sign == 1) {
            x = x.neg();
        }

        Some(Self {
            x,
            y,
            t2d: x.mul(y).mul(F::EDWARDS_D2),
        })
    }

    /// Compresses this point to its canonical Ed25519 encoding.
    pub fn compress(self) -> [u8; 32] {
        let mut bytes = self.y.to_bytes();
        bytes[31] |= u8::from(self.x.is_odd()) << 7;
        bytes
    }

    /// Converts this affine point to extended homogeneous representation.
    pub const fn to_extended(self) -> G {
        G {
            x: self.x,
            y: self.y,
            t: self.x.mul(self.y),
            z: F::ONE,
        }
    }

    /// Decompresses eight point encodings with the square-root calculation performed lane-wise by
    /// the selected backend.
    pub fn decompress_batch<B: FBackend>(
        backend: B,
        bytes: &[[u8; 32]; LANES],
    ) -> [Option<Self>; LANES] {
        let signs = bytes.map(|encoding| encoding[31] >> 7);
        let ys = bytes.map(|encoding| F::from_bytes(&encoding));
        let y = FVec::transpose(ys);
        let one = FVec::splat(F::ONE);

        // Recover x from x^2 = u/v, where u = y^2 - 1 and v = d*y^2 + 1.
        let y2 = backend.square(y);
        let u = backend.sub(y2, one);
        let v = backend.add(backend.mul(FVec::splat(F::EDWARDS_D), y2), one);
        let uv = backend.mul(u, v);
        let candidate = backend.mul(u, pow_p58(backend, uv));
        let vxx = backend.mul(v, backend.square(candidate));

        let u_lanes = u.untranspose();
        let negative_u_lanes = backend.neg(u).untranspose();
        let vxx_lanes = vxx.untranspose();
        let factors = array::from_fn(|i| {
            if vxx_lanes[i].eq(&u_lanes[i]) {
                Some(F::ONE)
            } else if vxx_lanes[i].eq(&negative_u_lanes[i]) {
                Some(F::SQRT_M1)
            } else {
                None
            }
        });
        let factor_lanes = factors.map(|factor| factor.unwrap_or(F::ONE));
        let x = backend.mul(candidate, FVec::transpose(factor_lanes));
        let x_lanes = x.untranspose();
        let negative_x_lanes = backend.neg(x).untranspose();

        let final_x = array::from_fn(|i| {
            if x_lanes[i].is_odd() == (signs[i] == 1) {
                x_lanes[i]
            } else {
                negative_x_lanes[i]
            }
        });
        let t2d_lanes = backend
            .mul(
                backend.mul(FVec::transpose(final_x), y),
                FVec::splat(F::EDWARDS_D2),
            )
            .untranspose();

        array::from_fn(|i| {
            factors[i]?;
            Some(Self {
                x: final_x[i],
                y: ys[i],
                t2d: t2d_lanes[i],
            })
        })
    }
}

/// Raises every lane to `2^250 - 1` using the standard addition chain.
fn pow_2_250_minus_1<B: FBackend>(backend: B, value: FVec) -> FVec {
    let a = backend.square(value);
    let a2 = backend.square(backend.square(a));
    let b = backend.mul(value, a2);
    let c = backend.mul(a, b);
    let d = backend.square(c);
    let e = backend.mul(b, d);
    let f = backend.mul(backend.pow2k(e, 5), e);
    let g = backend.mul(backend.pow2k(f, 10), f);
    let h = backend.mul(backend.pow2k(g, 20), g);
    let i = backend.mul(backend.pow2k(h, 10), f);
    let j = backend.mul(backend.pow2k(i, 50), i);
    let k = backend.mul(backend.pow2k(j, 100), j);
    backend.mul(backend.pow2k(k, 50), i)
}

/// Raises every lane to `(p - 5) / 8 = 2^252 - 3` for point decompression.
fn pow_p58<B: FBackend>(backend: B, value: FVec) -> FVec {
    backend.mul(value, backend.pow2k(pow_2_250_minus_1(backend, value), 2))
}

/// Abstracts over field, group, and multi-scalar operations.
///
/// Every point operation must produce the same projective coordinates, modulo `p`, as the scalar
/// formulas of the portable backend for every input point, including the identity, equal points,
/// a point plus its negation, and points with a torsion component. Every input point, operand, and
/// table entry may have any limbs below `2^52`.
///
/// The point types follow a point through a chain: an addition or doubling returns a
/// [`Backend::Completed`] point, which converts to [`Backend::Projective`] coordinates for a
/// doubling or to [`Backend::Extended`] coordinates for an addition. A backend may skip work for
/// coordinates the next operation does not read.
pub trait Backend: MBackend + 'static {
    /// A point in extended coordinates, the input of an addition.
    type Extended: Copy;

    /// A point in projective coordinates, the input of a doubling.
    type Projective: Copy;

    /// A point as an addition or doubling leaves it, before its final multiplications.
    type Completed: Copy;

    /// A point prepared as the right operand of repeated additions.
    type Cached: Copy;

    /// Converts a point to the native extended representation.
    fn load(self, point: &G) -> Self::Extended;

    /// Converts a native extended point back to a [`G`] with limbs below `2^52`.
    fn store(self, point: Self::Extended) -> G;

    /// Converts a native projective point back to a [`GProjective`] with limbs below `2^52`.
    fn store_projective(self, point: Self::Projective) -> GProjective;

    /// Returns the identity in extended coordinates.
    fn identity(self) -> Self::Extended;

    /// Drops the `T` coordinate, which doubling does not read.
    fn project(self, point: Self::Extended) -> Self::Projective;

    /// Doubles a point, deferring its final coordinate multiplications.
    fn double(self, point: Self::Projective) -> Self::Completed;

    /// Finishes a completed point in projective coordinates.
    fn to_projective(self, point: Self::Completed) -> Self::Projective;

    /// Finishes a completed point in extended coordinates.
    fn to_extended(self, point: Self::Completed) -> Self::Extended;

    /// Prepares a point for repeated additions.
    fn cache(self, point: Self::Extended) -> Self::Cached;

    /// Adds `cached`, or its negation when `negate` is set, deferring the final coordinate
    /// multiplications.
    ///
    /// Variable-time in `negate`, which must be public.
    fn add_cached(
        self,
        point: Self::Extended,
        cached: Self::Cached,
        negate: bool,
    ) -> Self::Completed;

    /// Adds an affine point, or its negation when `negate` is set, deferring the final coordinate
    /// multiplications.
    ///
    /// Variable-time in `negate`, which must be public.
    fn add_niels(self, point: Self::Extended, niels: &Niels, negate: bool) -> Self::Completed;

    /// Adds `digit * P` for `row[k] = (k + 1) * P` and `digit` in `[-8, 8]`.
    ///
    /// Constant time: every entry of `row` is read, and the selection and negation use masks,
    /// so no branch, memory index, or early exit depends on `digit` or on the points.
    fn add_selected(self, point: Self::Extended, row: &[Niels; 8], digit: i8) -> Self::Completed;

    /// Decompresses a point encoding as [`GAffine::decompress`] does.
    #[inline(always)]
    fn decompress(self, encoding: &[u8; 32]) -> Option<GAffine> {
        GAffine::decompress(encoding)
    }

    /// Decompresses two point encodings as [`GAffine::decompress`] does, or returns `None` when
    /// either is invalid.
    #[inline(always)]
    fn decompress_pair(self, [first, second]: [&[u8; 32]; 2]) -> Option<[GAffine; 2]> {
        Some([GAffine::decompress(first)?, GAffine::decompress(second)?])
    }
}

/// A computation which can run over an arbitrary [`Backend`].
///
/// [`with_backend`] selects a concrete backend at runtime, so the computation must provide a
/// generic call method. Implement this trait on a type that captures the computation's inputs;
/// ordinary closures cannot have generic call methods.
pub trait WithBackend {
    /// The result of the computation.
    type Output;

    /// Run the computation with a concrete backend.
    fn call<B: Backend>(self, backend: B) -> Self::Output;
}

// Precomputed multiples of the Ed25519 basepoint: constant-time multiplication for key
// generation and signing, and odd-multiple tables for verification.
mod basepoint;
pub use basepoint::{ODD_MULTIPLES, ODD_MULTIPLES_NAF_WIDTH};

// Scalar multiplication on the Montgomery form of the curve, for X25519.
pub mod montgomery;

// Backend kernels for MSM. Signing owns digit recoding and scheduling.
pub mod msm;

// Now, a module for each backend.
#[cfg(all(target_arch = "x86_64", any(feature = "std", test)))]
mod avx512;
#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(any(test, feature = "fuzz", not(target_arch = "aarch64")))]
mod portable;
#[cfg(any(test, feature = "fuzz"))]
pub mod test;

/// Returns the portable backend for deterministic tests.
#[cfg(test)]
pub fn test_backend() -> impl Backend {
    portable::Backend::new()
}

/// Run a computation with the best [`Backend`] this CPU supports.
///
/// AVX-512 dispatch checks the required CPU features before constructing its backend and entering
/// the computation's target-feature scope.
#[cfg_attr(target_arch = "aarch64", inline(always))]
pub fn with_backend<F: WithBackend>(f: F) -> F::Output {
    #[cfg(all(target_arch = "x86_64", any(feature = "std", test)))]
    {
        if let Some(backend) = avx512::Backend::new() {
            // SAFETY: constructing `backend` confirmed that the CPU supports every target
            // feature enabled by `Backend::call`.
            return unsafe { backend.call(f) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        f.call(neon::Backend::new())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // Portable fallback, available everywhere.
        portable::Backend::new().call(f)
    }
}
