use crate::{
    bls12381::primitives::group::Scalar,
    zk::circuit::{BoolVar, Context, Var},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blst::blst_fr;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::{
    msm_naive, Additive, CryptoGroup, Field, HashToGroup, Multiplicative, Object, Random, Ring,
    Space,
};
use commonware_parallel::Strategy;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::array;

/// A scalar exponent for the Banderwagon group [`G`]: an element of the scalar
/// field `Z/r`, where `r` is the prime group order.
///
/// Stored as a canonical little-endian integer in `[0, r)`. The in-circuit
/// secret is witnessed directly as its [`bits`](F::bits) (`F::BITS` of them,
/// enough to cover all of `[0, r)`), with no recomposition or canonicity
/// constraint (see `G::scalar_mul_bits`): the bits simply *are* the exponent.
/// A witnessed bit pattern is not itself constrained to `[0, r)` and so may
/// exceed `r`, but that is harmless: every use feeds the bits into a group
/// scalar multiplication, which is well-defined modulo `r`, so any alias of the
/// same residue yields the same result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct F {
    limbs: [u64; 4],
}

impl F {
    /// The bit-width of the modulus `r`; enough bits to represent any element of
    /// `[0, r)`. See [`F`].
    const BITS: usize = 253;

    /// The field modulus `r`, the prime order of the Banderwagon group, as
    /// little-endian 64-bit limbs. Every [`F`] value is kept canonical in
    /// `[0, r)`, so `PartialEq` (derived limb equality) is correct.
    const R: [u64; 4] = [
        0x74fd_06b5_2876_e7e1,
        0xff8f_8700_7419_0471,
        0x0cce_7602_0268_7600,
        0x1cfb_69d4_ca67_5f52,
    ];

    /// The little-endian bits of the integer, `F::BITS` of them (enough to
    /// represent any element of `[0, r)`).
    pub fn bits(&self) -> Vec<bool> {
        (0..Self::BITS)
            .map(|i| (self.limbs[i / 64] >> (i % 64)) & 1 == 1)
            .collect()
    }
}

impl Random for F {
    fn random(mut rng: impl rand_core::CryptoRngCore) -> Self {
        // Rejection-sample a uniform element of `[0, r)`. Each candidate is
        // `F::BITS` random bits (the width of `r`), so it lands in `[0, 2^BITS)`
        // and is accepted with probability `r / 2^BITS > 0.9`: ~1.1 draws on
        // average.
        loop {
            let mut limbs: [u64; 4] = array::from_fn(|_| rng.next_u64());
            limbs[3] &= (1u64 << (Self::BITS - 192)) - 1;
            // Accept iff `limbs < r`, i.e. computing `limbs - r` borrows.
            let mut borrow = false;
            for (&x, &r) in limbs.iter().zip(Self::R.iter()) {
                let (d, b) = x.overflowing_sub(r);
                let (_, c) = d.overflowing_sub(borrow as u64);
                borrow = b | c;
            }
            if borrow {
                return Self { limbs };
            }
        }
    }
}

impl<'a> AddAssign<&'a Self> for F {
    fn add_assign(&mut self, rhs: &'a Self) {
        // Add the two canonical `< r` integers limb by limb with carry. The sum
        // is `< 2r < 2^254`, so it never overflows the 256-bit `limbs`.
        let mut sum = [0u64; 4];
        let mut carry = false;
        for (s, (&x, &y)) in sum.iter_mut().zip(self.limbs.iter().zip(rhs.limbs.iter())) {
            let (a, b) = x.overflowing_add(y);
            let (a, c) = a.overflowing_add(carry as u64);
            *s = a;
            carry = b | c;
        }
        // Reduce: since `sum < 2r`, subtracting `r` at most once is enough.
        // Compute `sum - r`; a final borrow means `sum < r`, so we keep `sum`.
        let mut diff = [0u64; 4];
        let mut borrow = false;
        for (d, (&s, &r)) in diff.iter_mut().zip(sum.iter().zip(Self::R.iter())) {
            let (x, b) = s.overflowing_sub(r);
            let (x, c) = x.overflowing_sub(borrow as u64);
            *d = x;
            borrow = b | c;
        }
        self.limbs = if borrow { sum } else { diff };
    }
}

impl<'a> Add<&'a Self> for F {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // `-0 = 0`; otherwise `r - self`, which lies in `[1, r)` and is canonical.
        if self.limbs == [0u64; 4] {
            return self;
        }
        let mut diff = [0u64; 4];
        let mut borrow = false;
        for (d, (&r, &x)) in diff.iter_mut().zip(Self::R.iter().zip(self.limbs.iter())) {
            let (v, b) = r.overflowing_sub(x);
            let (v, c) = v.overflowing_sub(borrow as u64);
            *d = v;
            borrow = b | c;
        }
        Self { limbs: diff }
    }
}

impl<'a> SubAssign<&'a Self> for F {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let rhs = -rhs.clone();
        *self += &rhs;
    }
}

impl<'a> Sub<&'a Self> for F {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<'a> MulAssign<&'a Self> for F {
    fn mul_assign(&mut self, rhs: &'a Self) {
        // `a * b mod r` is `a` added to itself `b` times in the additive group,
        // which `Additive::scale` computes by double-and-add. Each step reduces
        // mod `r`, so the result is canonical.
        //
        // This is deliberately slow (~380 modular additions per multiply, ~100x
        // a schoolbook mul) and not constant-time (the loop branches on the bits
        // of `rhs`). That is fine for our use: the only production caller is the
        // eVRF signing response `s = e * x + k`, whose cost is dwarfed by the
        // accompanying `G` scalar multiplication, and whose surrounding native
        // code is variable-time regardless. To improve when needed: replace with
        // schoolbook 4x4-limb multiplication into a 512-bit product followed by a
        // Montgomery (or Barrett) reduction, and make it constant-time if a
        // caller ever multiplies secret material on a timing-sensitive path.
        *self = self.scale(&rhs.limbs);
    }
}

impl<'a> Mul<&'a Self> for F {
    type Output = Self;

    fn mul(mut self, rhs: &'a Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Object for F {}

impl Additive for F {
    fn zero() -> Self {
        Self { limbs: [0u64; 4] }
    }
}

impl Multiplicative for F {}

impl Ring for F {
    fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0],
        }
    }
}

impl Field for F {
    fn inv(&self) -> Self {
        // Fermat: for prime `r`, `a^(r-2) = a^-1` for nonzero `a`, and the
        // square-and-multiply leaves `0^(r-2) = 0`, matching the trait contract.
        // `r - 2` only borrows from the lowest limb (`R[0]` ends in `...e1`).
        self.exp(&[Self::R[0] - 2, Self::R[1], Self::R[2], Self::R[3]])
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Reduce an arbitrary 256-bit integer mod `r` via the additive
        // double-and-add (`1` scaled by the integer), keeping it canonical.
        let limbs: [u64; 4] = [
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
        ];
        Ok(Self::one().scale(&limbs))
    }
}

/// The Bandersnatch twisted Edwards `a` coefficient, `-5`, in Montgomery form.
#[allow(dead_code)]
const A: Scalar = Scalar(blst_fr {
    l: [
        0xffff_fff4_0000_000c,
        0xece3_b023_ffec_4ff3,
        0x66b6_2060_7396_203f,
        0x6f23_d7e5_f361_df62,
    ],
});

/// The Bandersnatch twisted Edwards `d` coefficient in Montgomery form.
#[allow(dead_code)]
const D: Scalar = Scalar(blst_fr {
    l: [
        0xa8dc_ed1b_47a2_c730,
        0x381c_065a_ad3c_ccc7,
        0x53ff_52e1_1883_51f8,
        0x362e_8d63_990f_e940,
    ],
});

// Banderwagon group structure:
//
// `G` holds a point on the Bandersnatch twisted Edwards curve
// (`a*x^2 + y^2 = 1 + d*x^2*y^2`, with `a = -5`). The full curve group is not
// prime order; it is isomorphic to `Z/2 x Z/2 x Z/r` (cofactor 4, `r` the large
// prime). The cofactor part is the "2-torsion" subgroup `{O, (0,-1), S, S'}`,
// where `(0,-1)` has order 2 and `S`, `S'` are the two other order-2 points.
//
// Banderwagon turns this into a clean prime-order group of size `r` in two steps:
//
//   1. Restrict to the subgroup of order `2r`, i.e. the prime-order subgroup
//      together with its coset by `(0,-1)`. The order-2 points `S`, `S'` (and
//      anything built from them) are *not* in this subgroup. Membership is
//      enforced by a "subgroup check": `1 - a*x^2` must be a square in the base
//      field (equivalently, in projective form, `z^2 - a*x^2`, avoiding an
//      inversion). This is only needed when decoding an untrusted point; values
//      produced internally (the generator plus the group law) never leave this
//      subgroup, so we don't perform it here yet.
//   2. Quotient that `2r` subgroup by the order-2 subgroup `{O, (0,-1)}`, which
//      collapses it to size `r`. Concretely this identifies each point `P` with
//      `P + (0,-1)`; since adding `(0,-1)` maps `(x, y)` to `(-x, -y)`, the two
//      representatives of every group element are `(x, y)` and `(-x, -y)`.
//
// So a single group element has many in-memory representations (any projective
// scaling of either of its two affine representatives), and equality (below)
// must see through all of them.

/// Represents a point in the Banderwagon group.
///
/// This group is defined over the BLS12-381 [`Scalar`] field.
/// Because of that, we can efficiently use it in ZK proofs using BLS.
#[derive(Clone, Debug)]
pub struct G {
    // We use a projective representation where xy = tz.
    x: Scalar,
    y: Scalar,
    t: Scalar,
    z: Scalar,
}

impl PartialEq for G {
    fn eq(&self, other: &Self) -> bool {
        // See the group-structure notes above `struct G`. Two representations are
        // the same group element iff their affine `x:y` ratios match, i.e.
        // `x1/z1 * y2/z2 == x2/z2 * y1/z1`. Clearing the `z` factors (they cancel)
        // gives `x1 * y2 == x2 * y1`. This single check absorbs both sources of
        // redundancy:
        //
        //   - projective scaling `(x,y,t,z)` vs `(λx,λy,λt,λz)`: the `λ`s cancel;
        //   - the `(0,-1)` quotient `(x,y)` vs `(-x,-y)`: the signs cancel
        //     (`x * -y == -x * y`).
        //
        // (Soundness relies on both points being valid subgroup elements; for
        // points off the curve or outside the `2r` subgroup this is meaningless.)
        self.x.clone() * &other.y == other.x.clone() * &self.y
    }
}

impl Eq for G {}

impl CryptoGroup for G {
    type Scalar = F;

    /// Returns the prime-order Bandersnatch generator in extended coordinates.
    fn generator() -> Self {
        Self {
            // x = 0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18
            x: Scalar(blst_fr {
                l: [
                    0xec26_27e1_e7ab_47f5,
                    0x3e63_de48_4f01_aa9c,
                    0xfe0f_5c3b_5394_6dc4,
                    0x2d71_920b_aeb2_cfcd,
                ],
            }),
            // y = 0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166
            y: Scalar(blst_fr {
                l: [
                    0x4e30_593e_1895_bd34,
                    0x156d_738f_32af_be4b,
                    0x45ef_0b1c_cdeb_75f4,
                    0x6a7c_ca00_37d2_e71f,
                ],
            }),
            // t = x * y = 0x5e61c8a110562844571f0fdc470ac5ea53e51c121b538d00e2594f7a0d4781ab
            t: Scalar(blst_fr {
                l: [
                    0x5a92_e8f6_97ad_b6b9,
                    0xf138_8d46_06b1_4609,
                    0x101c_7836_40a6_4516,
                    0x1e9a_e707_3cc7_a9fc,
                ],
            }),
            // z = 0x1
            z: Scalar(blst_fr {
                l: [
                    0x0000_0001_ffff_fffe,
                    0x5884_b7fa_0003_4802,
                    0x998c_4fef_ecbc_4ff5,
                    0x1824_b159_acc5_056f,
                ],
            }),
        }
    }
}

impl Object for G {}

impl<'a> AddAssign<&'a Self> for G {
    fn add_assign(&mut self, rhs: &'a Self) {
        // A bit of a trick to take ownership of the fields.
        let Self {
            x: x1,
            y: y1,
            t: t1,
            z: z1,
        } = core::mem::replace(self, Self::zero());
        // These are by reference.
        let Self {
            x: x2,
            y: y2,
            t: t2,
            z: z2,
        } = rhs;

        let x1_y2 = x1.clone() * y2;
        let y1_x2 = y1.clone() * x2;
        let y1_y2 = y1 * y2;
        let x1_x2 = x1 * x2;
        let z1_z2 = z1 * z2;
        let t1_t2 = t1 * t2;

        let x1_y2_plus_y1_x2 = x1_y2 + &y1_x2;
        let y1_y2_minus_a_x1_x2 = y1_y2 - &(x1_x2 * &A);
        let d_t1_t2 = t1_t2 * &D;
        let z_minus_d_t = z1_z2.clone() - &d_t1_t2;
        let z_plus_d_t = z1_z2 + &d_t1_t2;

        *self = Self {
            x: x1_y2_plus_y1_x2.clone() * &z_minus_d_t,
            y: y1_y2_minus_a_x1_x2.clone() * &z_plus_d_t,
            t: x1_y2_plus_y1_x2 * &y1_y2_minus_a_x1_x2,
            z: z_minus_d_t * &z_plus_d_t,
        }
    }
}

impl<'a> Add<&'a Self> for G {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for G {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let rhs = -rhs.clone();
        *self += &rhs;
    }
}

impl<'a> Sub<&'a Self> for G {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for G {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: -self.x,
            y: self.y,
            t: -self.t,
            z: self.z,
        }
    }
}

impl Additive for G {
    fn zero() -> Self {
        Self {
            x: Scalar::zero(),
            y: Scalar::one(),
            t: Scalar::zero(),
            z: Scalar::one(),
        }
    }

    fn double(&mut self) {
        let x_sq = {
            let mut out = self.x.clone();
            out.square();
            out
        };

        let y_sq = {
            let mut out = self.y.clone();
            out.square();
            out
        };

        let z_sq_twice = {
            let mut out = self.z.clone();
            out.square();
            out.double();
            out
        };

        let a_x_sq = x_sq.clone() * &A;

        let x_plus_y_sq = {
            let mut out = self.x.clone() + &self.y;
            out.square();
            out -= &x_sq;
            out -= &y_sq;
            out
        };

        let g = a_x_sq.clone() + &y_sq;
        let f = g.clone() - &z_sq_twice;
        let h = a_x_sq - &y_sq;

        self.x = x_plus_y_sq.clone() * &f;
        self.y = g.clone() * &h;
        self.t = x_plus_y_sq * &h;
        self.z = f * &g;
    }
}

impl<'a> MulAssign<&'a F> for G {
    fn mul_assign(&mut self, rhs: &'a F) {
        *self = self.scale(&rhs.limbs);
    }
}

impl<'a> Mul<&'a F> for G {
    type Output = Self;

    fn mul(mut self, rhs: &'a F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<F> for G {
    fn msm(points: &[Self], scalars: &[F], _strategy: &impl Strategy) -> Self {
        msm_naive(points, scalars)
    }
}

// Banderwagon (de)serialization. See the spec for full details:
// <https://hackmd.io/@6iQDuIePQjyYBqDChYw_jg/BJBNcv9fq> and the implementation
// notes <https://hackmd.io/wliPP_RMT4emsucVuCqfHA>.
//
// A group element is encoded as the single base-field element
// `u = (X/Z) * Sign(Y/Z)`, written big-endian. Multiplying by `Sign(Y/Z)` makes
// `P` and its quotient twin `P + (0,-1) = (-X,-Y)` (see notes above `struct G`)
// serialize to the same bytes, since negating the point negates both `X` and
// `Y`, leaving `u` unchanged. The sign, subgroup, and square-root helpers used
// here live on [`Scalar`].

impl Write for G {
    fn write(&self, buf: &mut impl BufMut) {
        // Convert to affine `(x, y) = (X/Z, Y/Z)`; `Z != 0` for all elements of
        // the subgroup we represent.
        let z_inv = self.z.inv();
        let x = self.x.clone() * &z_inv;
        let y = self.y.clone() * &z_inv;
        // `u = x * Sign(y)`: keep `x` when `y` is the positive (largest)
        // representative, otherwise negate it.
        let u = if y.is_positive() { x } else { -x };
        u.write(buf);
    }
}

impl FixedSize for G {
    const SIZE: usize = Scalar::SIZE;
}

impl G {
    /// The affine coordinates `(x/z, y/z)` of this representative.
    fn affine(&self) -> (Scalar, Scalar) {
        let z_inv = self.z.inv();
        (self.x.clone() * &z_inv, self.y.clone() * &z_inv)
    }

    /// Out-of-circuit squared affine x-coordinate of `[scalar] * self`.
    ///
    /// We expose the *squared* abscissa rather than the bare one because the
    /// quotient identifies `(x, y)` with `(-x, -y)`: a plain x-coordinate flips
    /// sign between the two representatives, whereas its square is a well-defined
    /// function of the group element (no representative to agree on, no
    /// `canonicalize` needed). The native counterpart of
    /// the in-circuit [`scalar_mul_x_squared`](Self::scalar_mul_x_squared).
    pub fn scalar_mul_x_squared_base(&self, scalar: &Scalar) -> Scalar {
        let (mut x, _) = self.scale(&scalar_limbs(scalar)).affine();
        x.square();
        x
    }

    /// Out-of-circuit squared affine x-coordinate of `[x] * self` for an [`F`]
    /// exponent — the native counterpart of
    /// [`scalar_mul_x_squared_bits`](Self::scalar_mul_x_squared_bits). Like
    /// [`scalar_mul_x_squared_base`](Self::scalar_mul_x_squared_base), the
    /// square is representative-independent.
    pub fn scalar_mul_x_squared_f(&self, x: &F) -> Scalar {
        let (mut a, _) = (self.clone() * x).affine();
        a.square();
        a
    }

    /// Return the canonical representative of this group element.
    ///
    /// A Banderwagon element has two affine representatives `(x, y)` and
    /// `(-x, -y)`; this picks the one with positive `y` (the same choice
    /// [`G::from_x`] makes when decoding), so that two in-memory values for the
    /// same element become bit-identical. Used by [`GVar::constant`] so that a
    /// point folded into a circuit yields representative-independent constants.
    fn canonicalize(&self) -> Self {
        let (x, y) = self.affine();
        let u = if y.is_positive() { x } else { -x };
        Self::from_x(u).expect("a valid subgroup element re-derives from its abscissa")
    }

    /// Recovers the group element whose serialization has abscissa `x`.
    ///
    /// Returns `None` if `x` is not the serialization of an element of the
    /// subgroup we represent (i.e. it fails the subgroup check or lies off the
    /// curve). This is the shared core of both [`Read`] and
    /// [`hash_to_group`](HashToGroup::hash_to_group).
    fn from_x(x: Scalar) -> Option<Self> {
        let one = Scalar::one();
        let x_sq = {
            let mut out = x.clone();
            out.square();
            out
        };

        // `num = 1 - a*x^2`, `den = 1 - d*x^2`, and `y^2 = num / den`.
        let num = one.clone() - &(x_sq.clone() * &A);
        let den = one.clone() - &(x_sq * &D);

        // Subgroup check: `1 - a*x^2` must be a square (see notes above `struct G`).
        if !num.is_square() {
            return None;
        }

        // Recover `y` and pick the positive (largest) representative. `sqrt`
        // returning `None` means `x` is not a valid abscissa (point off-curve).
        let ratio = num * &den.inv();
        let mut y = ratio.sqrt()?;
        if !y.is_positive() {
            y = -y;
        }

        let t = x.clone() * &y;
        Some(Self { x, y, t, z: one })
    }
}

impl HashToGroup for G {
    /// Hashes `(domain_separator, message)` to a Banderwagon point.
    ///
    /// Uses try-and-increment: for `counter = 0, 1, 2, ...` we derive a candidate
    /// abscissa `x = H(domain_separator, message || counter)` and return the
    /// first one that is a valid subgroup serialization. Because the
    /// serialization is a bijection between group elements and valid abscissae,
    /// and each candidate is an independent uniform field element, the result is
    /// a uniformly random group element whose discrete log w.r.t. the generator
    /// is unknown.
    ///
    /// We deliberately choose this over a constant-time map (e.g. Elligator-2 on
    /// the Montgomery model of bandersnatch). Try-and-increment is *simpler* — it
    /// reuses `from_x` and adds no new trusted constants or rational maps — at
    /// the cost of *not being constant-time*: the number of attempts (~4 on
    /// average, since roughly 1/4 of field elements are valid abscissae) depends
    /// on the input.
    ///
    /// That tradeoff fits our use case. The intended caller is the Golden DKG
    /// eVRF, where the hash inputs (public keys and messages) and outputs are
    /// public and the secret scalar is only applied *afterwards* — so the
    /// data-dependent timing reveals nothing secret. A future caller that hashes
    /// secret material would instead need a constant-time map.
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        // `message || counter`, with an 8-byte big-endian counter we overwrite
        // in place each attempt.
        let mut data = Vec::with_capacity(message.len() + 8);
        data.extend_from_slice(message);
        data.extend_from_slice(&[0u8; 8]);
        let counter_at = message.len();

        // The loop is unbounded for totality, but is expected to terminate
        // quickly: each attempt succeeds with probability ~1/4, so the number of
        // iterations is geometric with mean ~4 and an exponentially small tail.
        let mut counter: u64 = 0;
        loop {
            data[counter_at..].copy_from_slice(&counter.to_be_bytes());
            // `Scalar::map` is RFC 9380 hash-to-field, giving a uniform abscissa.
            if let Some(p) = Self::from_x(Scalar::map(domain_separator, &data)) {
                return p;
            }
            counter += 1;
        }
    }
}

impl Read for G {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; 32]>::read(buf)?;
        let x = Scalar::from_canonical_bytes(&bytes).ok_or(CodecError::Invalid(
            "Banderwagon",
            "x not a canonical field element",
        ))?;
        Self::from_x(x).ok_or(CodecError::Invalid("Banderwagon", "point not in subgroup"))
    }
}

/// An in circuit representation of a banderwagon point.
#[derive(Clone)]
pub struct GVar<'ctx> {
    // We use an affine representation in circuit. Inversions are cheap in circuit,
    // but expensive out of circuit. This makes the projecive representation less
    // interesting for us.
    x: Var<'ctx, Scalar>,
    y: Var<'ctx, Scalar>,
}

impl<'ctx> AddAssign<&Self> for GVar<'ctx> {
    fn add_assign(&mut self, rhs: &Self) {
        // Complete affine addition law for the twisted Edwards curve
        // `a*x^2 + y^2 = 1 + d*x^2*y^2` (the same formula as the projective
        // `AddAssign` for `G`, specialized to `z = 1`):
        //
        //   x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
        //   y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        //
        // We use the standard circuit-optimal arrangement, which costs six
        // multiplications (the rest are additions and scalings by the fixed
        // constants `a`, `d`, all linear and free in an R1CS-style backend):
        //
        //   1. `A = x1*x2`
        //   2. `B = y1*y2`
        //   3. `U = (x1 + y1)*(x2 + y2)`, so `x1*y2 + y1*x2 = U - A - B`
        //   4. `AB = A*B`, so the shared term `d*x1*x2*y1*y2 = d*AB`
        //   5,6. the two `/` operations, each a single constraint `q*den == num`
        //        (see [`Var`]'s `Div`).
        //
        // The curve is complete (`a` is a square and `d` is not), so both
        // denominators are nonzero for every pair of subgroup points and the
        // divisions never add an unsatisfiable or underconstrained quotient.
        let Self { x: x1, y: y1 } = core::mem::replace(self, Self::identity());
        let Self { x: x2, y: y2 } = rhs;

        // Curve constants as native vars; they fold into the circuit as
        // constants when combined with the (circuit-backed) coordinates.
        let a = Var::native(A);
        let d = Var::native(D);

        let x1_x2 = x1.clone() * x2; // A
        let y1_y2 = y1.clone() * y2; // B
        let u = (x1 + &y1) * &(x2.clone() + y2); // U
        let ab = x1_x2.clone() * &y1_y2; // A*B
        let c = d * &ab; // d*x1*x2*y1*y2

        let x_num = u - &x1_x2 - &y1_y2; // x1*y2 + y1*x2
        let y_num = y1_y2 - &(a * &x1_x2); // y1*y2 - a*x1*x2
        let one = Var::one();
        let x_den = one.clone() + &c; // 1 + d*x1*x2*y1*y2
        let y_den = one - &c; // 1 - d*x1*x2*y1*y2

        *self = Self {
            x: x_num / &x_den,
            y: y_num / &y_den,
        };
    }
}

impl<'ctx> Add<&Self> for GVar<'ctx> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

/// Bit-length of the circuit field modulus `p` (`ceil(log2 p) = 255`).
const SCALAR_BITS: usize = 255;

impl<'ctx> GVar<'ctx> {
    /// The circuit representation of the group identity, the twisted Edwards
    /// neutral element `(0, 1)`. The complete addition law treats it as the
    /// identity, so it is a valid starting accumulator.
    fn identity() -> Self {
        Self {
            x: Var::zero(),
            y: Var::one(),
        }
    }

    /// The in-circuit representation of an out-of-circuit point, as native
    /// constants (its canonical affine coordinates `(X/Z, Y/Z)`). Folding the
    /// point in as a constant pins its representative, which is what makes
    /// reading a coordinate of a derived point well-defined.
    ///
    /// The point is `canonicalize`d first, so the embedded
    /// constants are a function of the *group element*, not of whichever of its
    /// two affine representatives the caller happens to hold. Two parties folding
    /// in the same element therefore build byte-identical circuits without having
    /// to canonicalize their public inputs themselves.
    pub fn constant(point: &G) -> Self {
        let (x, y) = point.canonicalize().affine();
        Self {
            x: Var::native(x),
            y: Var::native(y),
        }
    }

    /// Select between two points based on `bit`: `on_true` when the bit is `1`,
    /// `on_false` when it is `0`. Selecting each coordinate independently is
    /// sound because `bit` is boolean, so the result is exactly one of the two
    /// (already valid) input points.
    fn select(bit: &BoolVar<'ctx, Scalar>, on_true: &Self, on_false: &Self) -> Self {
        Self {
            x: bit.select(&on_true.x, &on_false.x),
            y: bit.select(&on_true.y, &on_false.y),
        }
    }

    /// Assert (in circuit) that `self` and `other` are the same group element.
    ///
    /// Mirrors the out-of-circuit [`PartialEq`] for [`G`]: two representatives
    /// denote the same quotient element iff `x1 * y2 == x2 * y1`. Constraining
    /// the affine coordinates directly would be unsound here, because it would
    /// reject the equally-valid twin representative `(-x, -y)`.
    pub fn assert_eq(&self, other: &Self) {
        (self.x.clone() * &other.y).assert_eq(&(other.x.clone() * &self.y));
    }

    /// Multiply by a scalar given as its little-endian bits, via double-and-add.
    ///
    /// `cur` holds `[2^i] * self` and `acc` accumulates the conditionally-added
    /// terms. The complete addition law makes the identity start and the
    /// doublings (including over leading zero bits) need no special casing.
    fn mul_bits(self, bits: &[BoolVar<'ctx, Scalar>]) -> Self {
        let mut acc = Self::identity();
        let mut cur = self;
        for bit in bits {
            let added = acc.clone() + &cur;
            acc = Self::select(bit, &added, &acc);
            cur = cur.clone() + &cur;
        }
        acc
    }
}

/// The canonical little-endian 64-bit limbs of `x`'s integer value in `[0, r)`.
///
/// This is the integer [`Additive::scale`] multiplies a point by, and matches
/// the canonical bit decomposition `to_canonical_bits_le` performs in circuit,
/// so the out-of-circuit and in-circuit scalar muls agree.
fn scalar_limbs(x: &Scalar) -> [u64; 4] {
    let bytes = x.as_blst_scalar().b;
    array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}

/// Decompose `x` into its canonical little-endian bits (`SCALAR_BITS` of them).
///
/// The bits are fresh witnesses bound to `x` by two constraints:
///
///   1. *recomposition*, `sum_i b_i * 2^i == x`, computed in the field;
///   2. *canonicity*, the integer `sum_i b_i * 2^i < p`.
///
/// Both are required. Recomposition alone holds only modulo the field modulus
/// `p`, so without the range check a prover could supply the non-canonical
/// alias `x + p`; because the Banderwagon group order does not divide `p`, that
/// alias scales a point to a *different* result. The canonicity check pins the
/// decomposition to the unique integer in `[0, p)`.
fn scalar_bits_le<'ctx>(
    ctx: Context<'ctx, Scalar>,
    x: &Var<'ctx, Scalar>,
) -> Vec<BoolVar<'ctx, Scalar>> {
    // `as_blst_scalar` yields the canonical integer in `[0, p)` as little-endian
    // bytes, so bit `i` is `(bytes[i / 8] >> (i % 8)) & 1`.
    let bits: Vec<BoolVar<'ctx, Scalar>> = (0..SCALAR_BITS)
        .map(|i| {
            let x = x.clone();
            BoolVar::witness(ctx, move |v| {
                (x.value(v).as_blst_scalar().b[i / 8] >> (i % 8)) & 1 == 1
            })
        })
        .collect();

    // Constraint 1: recomposition `sum_i b_i * 2^i == x`. Each `b_i * 2^i` is a
    // scaling by a constant, so this whole sum is linear (free in the backend).
    let mut acc = Var::zero();
    let mut pow = Scalar::one();
    for bit in &bits {
        acc += &(bit.var().clone() * &Var::native(pow.clone()));
        pow.double();
    }
    acc.assert_eq(x);

    // Constraint 2: canonicity, `value <= p - 1` (equivalently `value < p`).
    //
    // We walk the bits from most to least significant alongside the bits of the
    // largest canonical value `c = p - 1` (its little-endian bytes, just like
    // the witness bits above), maintaining `run = "every 1-bit of c so far was
    // matched by a 1 in value"`. At a 1-bit of `c` the value bit is free, but it
    // is folded into `run`; at a 0-bit of `c`, if `run` still holds the value
    // bit must be 0 (otherwise value would exceed `c`). This is the standard
    // run-folding field-membership check.
    let c = (-Scalar::one()).as_blst_scalar().b;
    let mut run = BoolVar::constant(true);
    for i in (0..SCALAR_BITS).rev() {
        if (c[i / 8] >> (i % 8)) & 1 == 1 {
            run = run & bits[i].clone();
        } else {
            (run.clone() & bits[i].clone()).assert_eq(&BoolVar::constant(false));
        }
    }

    bits
}

impl G {
    /// In-circuit scalar multiplication, returning the point `[scalar] * self`.
    ///
    /// `self` is an out-of-circuit (public) point. Taking it by value here, and
    /// folding its canonical affine coordinates in as constants, pins its
    /// representative; that is what makes a coordinate of the result well-defined
    /// (a Banderwagon element has two affine representatives `(x, y)` and
    /// `(-x, -y)`, so a coordinate of a *witnessed* point would be ambiguous).
    ///
    /// `scalar` may be a witness; it is canonically decomposed (see
    /// `to_canonical_bits_le`) and the bits drive a double-and-add. Soundness
    /// additionally assumes `self` is a valid prime-order subgroup element, as
    /// produced by this module's constructors.
    ///
    /// Use [`GVar::assert_eq`] to bind the result against a known point (e.g. a
    /// public key); use [`scalar_mul_x_squared`](Self::scalar_mul_x_squared) when
    /// only a (representative-independent) abscissa is needed.
    pub(crate) fn scalar_mul<'ctx>(
        &self,
        ctx: Context<'ctx, Scalar>,
        scalar: &Var<'ctx, Scalar>,
    ) -> GVar<'ctx> {
        let bits = scalar_bits_le(ctx, scalar);
        GVar::constant(self).mul_bits(&bits)
    }

    /// In-circuit squared affine x-coordinate of `[scalar] * self`.
    ///
    /// We expose the *squared* abscissa rather than the bare one because the
    /// quotient identifies `(x, y)` with `(-x, -y)`: a plain x-coordinate flips
    /// sign between the two representatives, whereas its square is a well-defined
    /// function of the group element, so the read agrees regardless of which
    /// representative a point happens to hold. The in-circuit counterpart of
    /// [`scalar_mul_x_squared_base`](Self::scalar_mul_x_squared_base).
    pub fn scalar_mul_x_squared<'ctx>(
        &self,
        ctx: Context<'ctx, Scalar>,
        scalar: &Var<'ctx, Scalar>,
    ) -> Var<'ctx, Scalar> {
        let x = self.scalar_mul(ctx, scalar).x;
        x.clone() * &x
    }

    /// In-circuit `[scalar] * self` where the scalar is given *directly* as its
    /// little-endian bits, rather than as a [`Var`] to be decomposed.
    ///
    /// This is the path for an [`F`] exponent (e.g. the eVRF secret): the bits
    /// are the witness, so unlike `scalar_mul` there is no
    /// recomposition or canonicity constraint — see [`F`] for why that is sound
    /// at `F::BITS` width. The caller must allocate the bits once and reuse the
    /// same slice across operations, so a single exponent is bound everywhere.
    pub fn scalar_mul_bits<'ctx>(&self, bits: &[BoolVar<'ctx, Scalar>]) -> GVar<'ctx> {
        GVar::constant(self).mul_bits(bits)
    }

    /// In-circuit squared affine x-coordinate of `[scalar] * self` for a
    /// bit-given scalar; combines [`scalar_mul_bits`](Self::scalar_mul_bits) with
    /// the representative-independent squaring of
    /// [`scalar_mul_x_squared`](Self::scalar_mul_x_squared).
    pub fn scalar_mul_x_squared_bits<'ctx>(
        &self,
        bits: &[BoolVar<'ctx, Scalar>],
    ) -> Var<'ctx, Scalar> {
        let x = self.scalar_mul_bits(bits).x;
        x.clone() * &x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_codec::{DecodeExt, Encode, EncodeFixed};
    use commonware_invariants::minifuzz;

    fn arbitrary_point(u: &mut Unstructured<'_>) -> arbitrary::Result<G> {
        Ok(G::generator()
            * &F {
                limbs: [u.arbitrary()?, 0, 0, 0],
            })
    }

    #[test]
    fn test_field_laws() {
        // Exercise the full algebraic suite (additive, multiplicative, ring, and
        // field/inverse laws) on `F`.
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<F>);
    }

    #[test]
    fn test_random_canonical_and_full_range() {
        // `random()` must stay canonical (`< r`) and, unlike the old 252-bit
        // cap, cover the whole field: values in `[2^252, r)` (top bit set) must
        // occur.
        let mut rng = commonware_utils::test_rng();
        let mut saw_top_bit = false;
        for _ in 0..1000 {
            let f = F::random(&mut rng);
            // Canonical iff `f - r` borrows.
            let mut borrow = false;
            for (&x, &r) in f.limbs.iter().zip(F::R.iter()) {
                let (d, b) = x.overflowing_sub(r);
                let (_, c) = d.overflowing_sub(borrow as u64);
                borrow = b | c;
            }
            assert!(borrow, "random() produced a non-canonical value: {f:?}");
            saw_top_bit |= f.bits()[F::BITS - 1];
        }
        assert!(
            saw_top_bit,
            "random() never set the top bit; range is capped"
        );
    }

    #[test]
    fn test_field_modulus_matches_group_order() {
        // The field modulus `r` must be the order of the group `G`: scaling the
        // generator by the integer product `a * b` must agree with scaling it by
        // the field product `a * b mod r`. This ties `F::R` to the independently
        // verified group law (see the codec test vectors), and would fail for any
        // other modulus.
        minifuzz::test(|u| {
            let a: F = u.arbitrary()?;
            let b: F = u.arbitrary()?;
            let g = G::generator();
            assert_eq!((g.clone() * &a) * &b, g * &(a * &b));
            Ok(())
        });
    }

    #[test]
    fn test_eq_identity() {
        assert_eq!(G::zero(), G::zero());
    }

    #[test]
    fn test_eq_reflexive() {
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            assert_eq!(p, p.clone());
            Ok(())
        });
    }

    #[test]
    fn test_eq_invariant_under_projective_scaling() {
        // Scaling every coordinate by a common nonzero factor yields the same point.
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            let mut lambda: Scalar = u.arbitrary()?;
            if lambda == Scalar::zero() {
                lambda = Scalar::one();
            }
            let scaled = G {
                x: p.x.clone() * &lambda,
                y: p.y.clone() * &lambda,
                t: p.t.clone() * &lambda,
                z: p.z.clone() * &lambda,
            };
            assert_eq!(p, scaled);
            Ok(())
        });
    }

    #[test]
    fn test_eq_invariant_under_two_torsion() {
        // Adding the order-2 point (0, -1) maps (x, y) to (-x, -y); `t = xy` is
        // unchanged. Banderwagon must treat this as the same group element.
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            let twin = G {
                x: -p.x.clone(),
                y: -p.y.clone(),
                t: p.t.clone(),
                z: p.z.clone(),
            };
            assert_eq!(p, twin);
            Ok(())
        });
    }

    #[test]
    fn test_neq_distinct_points() {
        // `P` and `P + generator` differ by a prime-order element, so they are
        // always distinct group elements.
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            assert_ne!(p, p.clone() + &G::generator());
            Ok(())
        });
    }

    #[test]
    fn test_codec_fixed_size() {
        assert_eq!(G::SIZE, 32);
    }

    #[test]
    fn test_codec_round_trip_identity() {
        // The identity serializes to all-zero bytes and decodes back to itself.
        let encoded = G::zero().encode();
        assert_eq!(encoded.as_ref(), &[0u8; 32]);
        let decoded = G::decode(encoded).unwrap();
        assert_eq!(decoded, G::zero());
    }

    #[test]
    fn test_codec_round_trip_generator() {
        let g = G::generator();
        let decoded = G::decode(g.encode()).unwrap();
        assert_eq!(decoded, g);
    }

    const TEST_DST: &[u8] = b"COMMONWARE_BANDERWAGON_HASH_TO_CURVE_TEST";

    #[test]
    fn test_hash_to_group_deterministic() {
        // Same inputs always produce the same point; it round-trips through the
        // codec (so it really is a valid subgroup element).
        let p = G::hash_to_group(TEST_DST, b"hello");
        let q = G::hash_to_group(TEST_DST, b"hello");
        assert_eq!(p, q);
        assert_eq!(G::decode(p.encode()).unwrap(), p);
    }

    #[test]
    fn test_hash_to_group_distinct_messages() {
        // Different messages map to different points.
        let p = G::hash_to_group(TEST_DST, b"message-a");
        let q = G::hash_to_group(TEST_DST, b"message-b");
        assert_ne!(p, q);
    }

    #[test]
    fn test_hash_to_group_in_subgroup() {
        // Every output must pass the subgroup check, i.e. re-encode/decode.
        minifuzz::test(|u| {
            let msg: Vec<u8> = u.arbitrary()?;
            let p = G::hash_to_group(TEST_DST, &msg);
            assert_eq!(G::decode(p.encode()).unwrap(), p);
            Ok(())
        });
    }

    #[test]
    fn test_hash_to_group_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_hash_to_group::<G>);
    }

    #[test]
    fn test_codec_fixed_vectors() {
        // Official Banderwagon test vectors: the serialization of `G, 2G, 4G,
        // 8G, ...` (successive doublings of the generator). Matching these
        // confirms interoperability with go-ipa / Ethereum Verkle.
        //
        // Source: crate-crypto/rust-verkle `banderwagon::element::fixed_test_vectors`.
        let expected = [
            "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",
            "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",
            "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",
            "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",
            "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",
            "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
            "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
            "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
            "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
            "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
            "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
            "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
            "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
            "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
            "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
            "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
        ];

        let mut point = G::generator();
        for (i, want) in expected.into_iter().enumerate() {
            let encoded = point.encode();
            assert_eq!(
                commonware_formatting::hex(encoded.as_ref()),
                want,
                "encoding mismatch at index {i}"
            );
            // The vectors must also decode back to the same point.
            let decoded = G::decode(encoded).unwrap();
            assert_eq!(decoded, point, "decode mismatch at index {i}");
            point.double();
        }
    }

    #[test]
    fn test_codec_round_trip() {
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            let decoded = G::decode(p.encode()).unwrap();
            assert_eq!(decoded, p);
            Ok(())
        });
    }

    #[test]
    fn test_codec_canonical_for_twin() {
        // `P` and its quotient twin `(-x, -y)` are the same group element, so
        // they must serialize to identical bytes.
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            let twin = G {
                x: -p.x.clone(),
                y: -p.y.clone(),
                t: p.t.clone(),
                z: p.z.clone(),
            };
            assert_eq!(p.encode(), twin.encode());
            Ok(())
        });
    }

    #[test]
    fn test_codec_canonical_under_projective_scaling() {
        // Projective scaling does not change the group element, so the encoding
        // must be invariant under it.
        minifuzz::test(|u| {
            let p = arbitrary_point(u)?;
            let mut lambda: Scalar = u.arbitrary()?;
            if lambda == Scalar::zero() {
                lambda = Scalar::one();
            }
            let scaled = G {
                x: p.x.clone() * &lambda,
                y: p.y.clone() * &lambda,
                t: p.t.clone() * &lambda,
                z: p.z.clone() * &lambda,
            };
            assert_eq!(p.encode(), scaled.encode());
            Ok(())
        });
    }

    #[test]
    fn test_decode_rejects_non_canonical_field_element() {
        // `r - 1` is the largest valid field element; `r` (and above) must be
        // rejected as non-canonical. These are the big-endian bytes of `r`.
        let r_bytes: [u8; 32] = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert!(G::decode(&r_bytes[..]).is_err());
        assert!(G::decode(&[0xffu8; 32][..]).is_err());
    }

    #[test]
    fn test_decode_rejects_off_subgroup() {
        // Search for an `x` whose `1 - a*x^2` is a non-square: decoding must fail
        // the subgroup check. We expect to find one quickly (~half of all `x`).
        minifuzz::test(|u| {
            let x: Scalar = u.arbitrary()?;
            let x_sq = {
                let mut out = x.clone();
                out.square();
                out
            };
            let num = Scalar::one() - &(x_sq * &A);
            if num != Scalar::zero() && !num.is_square() {
                let bytes = x.encode_fixed::<32>();
                assert!(G::decode(&bytes[..]).is_err());
            }
            Ok(())
        });
    }

    /// Build the circuit `[scalar] * base` and assert (in circuit) that it equals
    /// `expected`, returning whether the circuit is satisfied. `witness` chooses
    /// whether the scalar is a circuit witness (exercising `to_canonical_bits_le`)
    /// or a public constant.
    ///
    /// The check uses the quotient-aware [`GVar::assert_eq`], so `base` and
    /// `expected` need not be canonical: either affine representative is accepted.
    fn run_scalar_mul(base: &G, scalar: &Scalar, expected: &G, witness: bool) -> bool {
        use crate::zk::circuit::build_with_values;

        let base = base.clone();
        let expected = expected.clone();
        let scalar = scalar.clone();
        let valued = build_with_values(move |ctx| {
            let s = if witness {
                Var::witness(ctx, move |_| scalar)
            } else {
                Var::constant(ctx, scalar)
            };
            base.scalar_mul(ctx, &s)
                .assert_eq(&GVar::constant(&expected));
        });
        valued.is_satisfied()
    }

    #[test]
    fn test_scalar_mul_small() {
        let base = G::generator();
        for k in [0u64, 1, 2, 3, 4, 7, 8, 15, 16, 1_000_000, u64::MAX] {
            let scalar = Scalar::from_u64(k);
            let expected = base.scale(&[k, 0, 0, 0]);
            assert!(
                run_scalar_mul(&base, &scalar, &expected, false),
                "constant scalar k={k}"
            );
            assert!(
                run_scalar_mul(&base, &scalar, &expected, true),
                "witness scalar k={k}"
            );
        }
    }

    #[test]
    fn test_scalar_mul_rejects_wrong_result() {
        // Sanity: the in-circuit equality must actually constrain the result.
        let base = G::generator();
        let scalar = Scalar::from_u64(5);
        let correct = base.scale(&[5, 0, 0, 0]);
        let wrong = correct.clone() + &G::generator();
        assert!(run_scalar_mul(&base, &scalar, &correct, true));
        assert!(!run_scalar_mul(&base, &scalar, &wrong, true));
    }

    #[test]
    fn test_scalar_mul_random() {
        // Random base point and full-width random scalar, exercising the witness
        // decomposition (recomposition + canonicity) over the whole bit range.
        minifuzz::test(|u| {
            let base = arbitrary_point(u)?;
            let scalar: Scalar = u.arbitrary()?;
            // Scale `base` by the scalar's canonical integer (little-endian
            // limbs), matching the integer `scalar_mul` decomposes in circuit.
            let bytes = scalar.as_blst_scalar().b;
            let limbs: [u64; 4] =
                array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
            let expected = base.scale(&limbs);
            assert!(run_scalar_mul(&base, &scalar, &expected, true));
            Ok(())
        });
    }
}
