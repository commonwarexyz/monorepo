use core::array;

/// How many parallel operations we try and do via SIMD.
///
/// This is set to the highest realistic number, targetting AVX-512.
/// On other backends, this is larger than necessary.
///
/// This should not be harmful to performance, because a larger lane count
/// can be emulated with a smaller lane count.
/// An exception to this would be if the memory pressure were particularly bad,
/// but given how small this value is, this shouldn't be an issue.
pub(crate) const LANES: usize = 8;

const MASK_51: u64 = (1 << 51) - 1;

/// `16*p`, decomposed limb-wise at radix 51, used to make subtraction underflow-free.
const BIAS_16P: [u64; 5] = [
    16 * ((1u64 << 51) - 19),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
    16 * ((1u64 << 51) - 1),
];

/// A base field element in the field of order `p = 2^255 - 19`.
///
/// The five limbs use radix `2^51`. The representation is redundant: values need not be
/// canonical, but every arithmetic operation accepts and returns limbs less than `2^52`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct F(pub(crate) [u64; 5]);

impl F {
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

    /// `2 * EDWARDS_D`.
    pub(crate) const EDWARDS_D2: Self = Self([
        2 * Self::EDWARDS_D.0[0],
        2 * Self::EDWARDS_D.0[1],
        2 * Self::EDWARDS_D.0[2],
        2 * Self::EDWARDS_D.0[3],
        2 * Self::EDWARDS_D.0[4],
    ]);

    /// A fixed square root of `-1` in the field.
    pub(crate) const SQRT_M1: Self = Self([
        0x0061b274a0ea0b0,
        0x000d5a5fc8f189d,
        0x007ef5e9cbd0c60,
        0x0078595a6804c9e,
        0x002b8324804fc1d,
    ]);

    /// Parses a little-endian 255-bit value, ignoring bit 255.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(chunk)
        };

        let mut limbs = [0; 5];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let bit = i * 51;
            let offset = (bit / 8).min(bytes.len() - 8);
            *limb = (load8(offset) >> (bit - 8 * offset)) & MASK_51;
        }
        Self(limbs)
    }

    /// Restores the `< 2^52` limb bound without canonicalizing the field element.
    ///
    /// Inputs must have limbs below `2^63`.
    #[inline]
    fn reduce(mut l: [u64; 5]) -> Self {
        for i in 0..l.len() - 1 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK_51;
        }
        l[0] += (l[4] >> 51) * 19;
        l[4] &= MASK_51;
        Self(l)
    }

    /// Carry-propagates the limbs for canonical serialization.
    fn carry(&self) -> Self {
        let mut l = Self::reduce(self.0).0;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        Self(l)
    }

    /// Serializes the canonical representative as 255 little-endian bits.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().0;

        // Adding 19 overflows bit 255 exactly when l >= p.
        let mut q = 19;
        for &limb in &l {
            q = (limb + q) >> 51;
        }

        l[0] += 19 * q;
        for i in 0..l.len() - 1 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK_51;
        }
        l[4] &= MASK_51;

        let mut words = [0u64; 4];
        for (i, limb) in l.into_iter().enumerate() {
            let bit = i * 51;
            let word = bit / 64;
            let shift = bit % 64;
            words[word] |= limb << shift;
            if shift > 64 - 51 {
                words[word + 1] |= limb >> (64 - shift);
            }
        }

        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Returns whether two canonical representatives are equal.
    pub(crate) fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Returns whether the canonical representative is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.eq(&Self::ZERO)
    }

    /// Returns whether the canonical representative is odd.
    pub(crate) fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Returns `self + rhs`.
    #[inline]
    pub(crate) fn add(self, rhs: Self) -> Self {
        Self::reduce(array::from_fn(|i| self.0[i] + rhs.0[i]))
    }

    /// Returns `self - rhs`.
    #[inline]
    pub(crate) fn sub(self, rhs: Self) -> Self {
        Self::reduce(array::from_fn(|i| self.0[i] + BIAS_16P[i] - rhs.0[i]))
    }

    /// Returns `-self`.
    #[inline]
    pub(crate) fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Reduces five wide radix-`2^51` columns to the scalar limb bound.
    #[inline]
    fn from_wide(mut c: [u128; 5]) -> Self {
        const MASK: u128 = MASK_51 as u128;
        for i in 0..4 {
            c[i + 1] += c[i] >> 51;
            c[i] &= MASK;
        }
        c[0] += 19 * (c[4] >> 51);
        c[4] &= MASK;
        c[1] += c[0] >> 51;
        c[0] &= MASK;

        Self(array::from_fn(|i| c[i] as u64))
    }

    /// Returns `self * rhs`.
    #[inline]
    pub(crate) fn mul(self, rhs: Self) -> Self {
        // Accumulate the nine schoolbook columns, then fold columns 5 through 8 down using
        // `2^255 = 19 (mod p)`. At the input bound, every folded column remains below `2^112`.
        let mut c = [0u128; 9];
        for (i, a) in self.0.into_iter().enumerate() {
            for (c, b) in c[i..].iter_mut().zip(rhs.0) {
                *c += u128::from(a) * u128::from(b);
            }
        }
        let (low, high) = c.split_at_mut(5);
        for (low, high) in low.iter_mut().zip(high) {
            *low += 19 * *high;
        }
        Self::from_wide([c[0], c[1], c[2], c[3], c[4]])
    }

    /// Returns `self * self` using one product for each pair of distinct limbs.
    #[inline]
    pub(crate) fn square(self) -> Self {
        let limbs = self.0;
        let mut limbs_19 = limbs;
        for limb in &mut limbs_19[3..] {
            *limb *= 19;
        }

        let mut c = [0u128; 5];
        for i in 0..limbs.len() {
            for j in i..limbs.len() {
                let column = i + j;
                let (column, rhs) = if column < limbs.len() {
                    (column, limbs[j])
                } else {
                    (column - limbs.len(), limbs_19[j])
                };
                let product = u128::from(limbs[i]) * u128::from(rhs);
                c[column] += if i == j { product } else { 2 * product };
            }
        }
        Self::from_wide(c)
    }

    /// Squares `self` `k` times.
    fn pow2k(mut self, k: u32) -> Self {
        for _ in 0..k {
            self = self.square();
        }
        self
    }

    /// Raises `self` to `2^250 - 1` using the standard addition chain.
    fn pow_2_250_minus_1(self) -> Self {
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
    fn pow_p58(self) -> Self {
        self.mul(self.pow_2_250_minus_1().pow2k(2))
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
pub(crate) struct FVec {
    // We could have a dynamic number of lanes here, depending on the backend,
    // but it's easier to just have a fixed number, perhaps dispatching several
    // instructions for backends with fewer lanes.
    limbs: [[u64; LANES]; 5],
}

impl FVec {
    /// Returns every lane set to `element`.
    pub(crate) const fn splat(element: F) -> Self {
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
    pub(crate) fn transpose(lanes: [F; LANES]) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for (i, lane) in lanes.iter().enumerate() {
            for (row, value) in limbs.iter_mut().zip(lane.0) {
                row[i] = value;
            }
        }
        Self { limbs }
    }

    /// Untransposes limb rows into scalar field elements.
    pub(crate) fn untranspose(self) -> [F; LANES] {
        array::from_fn(|i| F(array::from_fn(|limb| self.limbs[limb][i])))
    }

    /// Selects `other` in lanes whose corresponding mask is true.
    fn select_lanes(self, other: Self, select_other: &[bool; LANES]) -> Self {
        let masks = select_other.map(|select| 0u64.wrapping_sub(select as u64));
        Self {
            limbs: array::from_fn(|limb| {
                array::from_fn(|lane| {
                    (self.limbs[limb][lane] & !masks[lane])
                        | (other.limbs[limb][lane] & masks[lane])
                })
            }),
        }
    }
}

/// Abstracts over base field operations.
pub(crate) trait FBackend: Copy {
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

    /// a - b.
    fn sub(self, a: FVec, b: FVec) -> FVec {
        self.add(a, self.neg(b))
    }
}

/// A compact point on the twisted Edwards curve in extended homogeneous coordinates.
///
/// This is the scalar representation used directly for individual point operations and as the
/// array-of-structures representation between vector operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct G {
    x: F,
    y: F,
    t: F,
    z: F,
}

impl G {
    /// The neutral element, `(0, 1)` in affine coordinates.
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t: F::ZERO,
        z: F::ONE,
    };

    /// Negates this point.
    pub(crate) fn negate(self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }

    /// Adds two points using the complete unified formula for `a = -1`.
    #[inline]
    pub(crate) fn add(self, rhs: Self) -> Self {
        // Hisil-Wong-Carter-Dawson, "Twisted Edwards Curves Revisited",
        // add-2008-hwcd-3 specialized to a = -1:
        //
        //   A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
        //   B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
        //   C = 2d * T1 * T2                 G = D + C        Z3 = F*G
        //   D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
        //
        // The formula is complete because d is non-square. The extended-coordinate invariant
        // holds identically: (E*H)*(F*G) = (E*F)*(G*H).
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
    #[inline]
    pub(crate) fn add_mixed(self, rhs: GAffine) -> Self {
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
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
    #[inline]
    pub(crate) fn double(self) -> Self {
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
    pub(crate) fn scalar_mul(self, bits: impl IntoIterator<Item = bool>) -> Self {
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
    pub(crate) fn mul_by_cofactor(mut self) -> Self {
        for _ in 0..3 {
            self = self.double();
        }
        self
    }

    /// Returns whether this point represents the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }
}

/// A compact affine point prepared for mixed addition.
///
/// This stores individual affine points and their precomputed `2d*x*y` coordinate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GAffine {
    x: F,
    y: F,
    t2d: F,
}

impl GAffine {
    /// The neutral element, `(0, 1)`.
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t2d: F::ZERO,
    };

    /// The standard Ed25519 base point, prepared for mixed addition.
    pub(crate) const BASEPOINT: Self = Self {
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

    /// Decompresses a point encoding, accepting non-canonical `y` values per ZIP215.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
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

        if x.is_zero() && sign == 1 {
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

    /// Converts this affine point to extended homogeneous representation.
    pub(crate) fn to_extended(self) -> G {
        G {
            x: self.x,
            y: self.y,
            t: self.x.mul(self.y),
            z: F::ONE,
        }
    }

    /// Decompresses eight point encodings with the square-root calculation performed lane-wise by
    /// the selected backend.
    pub(crate) fn decompress_batch<B: FBackend>(
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
            if x_lanes[i].is_zero() && signs[i] == 1 {
                return None;
            }
            Some(Self {
                x: final_x[i],
                y: ys[i],
                t2d: t2d_lanes[i],
            })
        })
    }
}

/// Points on the twisted Edwards curve `-x^2 + y^2 = 1 + d*x^2*y^2` in extended homogeneous
/// coordinates `(X : Y : Z : T)`.
///
/// The affine point is `(X/Z, Y/Z)`, and `T` carries the product `X*Y/Z`, giving the invariant
/// `X*Y = T*Z`. Scaling all four coordinates by any nonzero factor represents the same point.
/// The affine curve equation, scaled by `Z^2`, is `-X^2 + Y^2 = Z^2 + d*T^2`.
#[derive(Clone, Copy)]
pub(crate) struct GVec {
    /// The extended homogeneous X coordinate.
    pub(crate) x: FVec,
    /// The extended homogeneous Y coordinate.
    pub(crate) y: FVec,
    /// The extended homogeneous T coordinate.
    pub(crate) t: FVec,
    /// The extended homogeneous Z coordinate.
    pub(crate) z: FVec,
}

impl GVec {
    /// Transposes scalar points into backend lanes.
    pub(crate) fn transpose(lanes: [G; LANES]) -> Self {
        Self {
            x: FVec::transpose(lanes.map(|point| point.x)),
            y: FVec::transpose(lanes.map(|point| point.y)),
            t: FVec::transpose(lanes.map(|point| point.t)),
            z: FVec::transpose(lanes.map(|point| point.z)),
        }
    }

    /// Untransposes backend lanes into scalar points.
    pub(crate) fn untranspose(self) -> [G; LANES] {
        let x = self.x.untranspose();
        let y = self.y.untranspose();
        let t = self.t.untranspose();
        let z = self.z.untranspose();
        array::from_fn(|i| G {
            x: x[i],
            y: y[i],
            t: t[i],
            z: z[i],
        })
    }

    /// Returns every lane set to `point`.
    pub(crate) const fn splat(point: G) -> Self {
        Self {
            x: FVec::splat(point.x),
            y: FVec::splat(point.y),
            t: FVec::splat(point.t),
            z: FVec::splat(point.z),
        }
    }

    /// Returns the identity in every lane.
    pub(crate) const fn identity() -> Self {
        Self::splat(G::IDENTITY)
    }

    #[inline(always)]
    fn add_pairs<const COUNT: usize>(sums: [G; LANES], backend: impl GBackend) -> [G; LANES] {
        let mut left = [G::IDENTITY; LANES];
        let mut right = [G::IDENTITY; LANES];
        for i in 0..COUNT / 2 {
            left[i] = sums[2 * i];
            right[i] = sums[2 * i + 1];
        }
        backend
            .g_add(Self::transpose(left), Self::transpose(right))
            .untranspose()
    }

    /// Sums all eight lanes with a vector addition tree.
    pub(crate) fn sum_lanes<B: GBackend>(self, backend: B) -> G {
        let sums = Self::add_pairs::<LANES>(self.untranspose(), backend);
        let sums = Self::add_pairs::<{ LANES / 2 }>(sums, backend);
        Self::add_pairs::<{ LANES / 4 }>(sums, backend)[0]
    }
}

/// Like `GVec`, but assuming that the point is in affine representation.
///
/// When we deserialize a point from bytes, this is what we naturally get.
/// Operations are faster taking this into account, so we want to make sure to
/// exploit that when we can, by using [`GBackend::g_add_mixed`] and cousins.
#[derive(Clone, Copy)]
pub(crate) struct GAffineVec {
    pub(crate) x: FVec,
    pub(crate) y: FVec,
    pub(crate) t2d: FVec,
}

impl GAffineVec {
    /// Transposes scalar affine points into backend lanes.
    pub(crate) fn transpose(lanes: [GAffine; LANES]) -> Self {
        Self {
            x: FVec::transpose(lanes.map(|point| point.x)),
            y: FVec::transpose(lanes.map(|point| point.y)),
            t2d: FVec::transpose(lanes.map(|point| point.t2d)),
        }
    }

    /// Untransposes backend lanes into scalar affine points.
    pub(crate) fn untranspose(self) -> [GAffine; LANES] {
        let x = self.x.untranspose();
        let y = self.y.untranspose();
        let t2d = self.t2d.untranspose();
        array::from_fn(|i| GAffine {
            x: x[i],
            y: y[i],
            t2d: t2d[i],
        })
    }

    /// Packs affine points, negating the selected lanes.
    pub(crate) fn from_signed_lanes<B: FBackend>(
        backend: B,
        lanes: &[GAffine; LANES],
        negative: &[bool; LANES],
    ) -> Self {
        let packed = Self::transpose(*lanes);
        if !negative.iter().any(|&value| value) {
            return packed;
        }

        Self {
            x: packed.x.select_lanes(backend.neg(packed.x), negative),
            y: packed.y,
            t2d: packed.t2d.select_lanes(backend.neg(packed.t2d), negative),
        }
    }
}

/// Squares `value` `k` times.
fn pow2k<B: FBackend>(backend: B, mut value: FVec, k: u32) -> FVec {
    for _ in 0..k {
        value = backend.square(value);
    }
    value
}

/// Raises every lane to `2^250 - 1` using the standard addition chain.
fn pow_2_250_minus_1<B: FBackend>(backend: B, value: FVec) -> FVec {
    let a = backend.square(value);
    let a2 = backend.square(backend.square(a));
    let b = backend.mul(value, a2);
    let c = backend.mul(a, b);
    let d = backend.square(c);
    let e = backend.mul(b, d);
    let f = backend.mul(pow2k(backend, e, 5), e);
    let g = backend.mul(pow2k(backend, f, 10), f);
    let h = backend.mul(pow2k(backend, g, 20), g);
    let i = backend.mul(pow2k(backend, h, 10), f);
    let j = backend.mul(pow2k(backend, i, 50), i);
    let k = backend.mul(pow2k(backend, j, 100), j);
    backend.mul(pow2k(backend, k, 50), i)
}

/// Raises every lane to `(p - 5) / 8 = 2^252 - 3` for point decompression.
fn pow_p58<B: FBackend>(backend: B, value: FVec) -> FVec {
    backend.mul(value, pow2k(backend, pow_2_250_minus_1(backend, value), 2))
}

/// Abstracts over group operations.
pub(crate) trait GBackend: FBackend {
    /// Add two points together.
    ///
    /// This method must work for all points, including the identity point, equal points, and a
    /// point plus its negation. The Ed25519 curve admits complete addition formulas because
    /// `a = -1` and `d` is non-square.
    fn g_add(self, a: GVec, b: GVec) -> GVec;

    /// Add two points together, assuming one is in its affine representation.
    ///
    /// This can be faster than [`Self::g_add`].
    fn g_add_mixed(self, a: GVec, b: GAffineVec) -> GVec;

    /// Add a point to itself.
    fn g_double(self, a: GVec) -> GVec {
        self.g_add(a, a)
    }
}

/// Abstracts over field and group operations.
pub(crate) trait Backend: FBackend + GBackend + Send + Sync + 'static {}

/// A computation which can run over an arbitrary [`Backend`].
///
/// [`with_backend`] hands its caller a backend whose concrete type is only
/// known at runtime, so the computation must be generic over backends. Plain
/// closures can't have generic call methods, so we use a trait instead:
/// implement it on a struct capturing the computation's inputs, and return
/// its results from [`Self::call`].
pub(crate) trait WithBackend {
    /// The result of the computation.
    type Output;

    /// Run the computation with a concrete backend.
    ///
    /// The AVX-512 dispatcher enables its target features around this entire method, allowing the
    /// backend operations it invokes to inline without crossing a target-feature boundary for
    /// every operation.
    fn call<B: Backend>(self, backend: B) -> Self::Output;
}

// Now, a module for each backend.
#[cfg(target_arch = "x86_64")]
mod avx512;
mod portable;
#[cfg(test)]
mod test;

/// Returns the portable backend for deterministic tests.
#[cfg(test)]
pub(crate) fn test_backend() -> impl Backend {
    portable::Backend::new()
}

#[cfg(test)]
#[test]
fn test_portable() {
    commonware_invariants::minifuzz::test(|u| test::fuzz_backend(u, portable::Backend::new()));
}

#[cfg(all(test, target_arch = "x86_64"))]
#[test]
fn test_avx512() {
    let Some(backend) = avx512::Backend::new() else {
        return;
    };
    commonware_invariants::minifuzz::test(|u| test::fuzz_backend(u, backend));
}

#[cfg(all(test, target_arch = "x86_64"))]
#[test]
fn test_avx512_against_portable() {
    let Some(backend) = avx512::Backend::new() else {
        return;
    };
    test::check_backend_at_bounds(portable::Backend::new(), backend);
    commonware_invariants::minifuzz::test(|u| {
        test::fuzz_backend_against(u, portable::Backend::new(), backend)
    });
}

/// Run a computation with the best [`Backend`] this CPU supports.
///
/// This is the only way to gain access to a backend: the runtime feature
/// detection here is what justifies constructing the accelerated backends,
/// so every use is forced through this single gate.
pub(crate) fn with_backend<F: WithBackend>(f: F) -> F::Output {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(backend) = avx512::Backend::new() {
            // SAFETY: constructing `backend` confirmed that the CPU supports every target
            // feature enabled by `Backend::call`.
            return unsafe { backend.call(f) };
        }
    }
    // Portable fallback, available everywhere.
    f.call(portable::Backend::new())
}
