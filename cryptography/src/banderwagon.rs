use crate::bls12381::primitives::group::{Scalar, DST};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blst::blst_fr;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::{
    msm_naive, Additive, Field, Multiplicative, Object, Random, Ring, Space,
};
use commonware_parallel::Strategy;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::array;

/// Represents the scalar field for the Banderwagon group [`G`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F {
    limbs: [u64; 4],
}

impl Random for F {
    fn random(mut rng: impl rand_core::CryptoRngCore) -> Self {
        Self {
            limbs: array::from_fn(|_| rng.next_u64()),
        }
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

impl G {
    /// Returns the prime-order Bandersnatch generator in extended coordinates.
    pub const fn generator() -> Self {
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
    /// Recovers the group element whose serialization has abscissa `x`.
    ///
    /// Returns `None` if `x` is not the serialization of an element of the
    /// subgroup we represent (i.e. it fails the subgroup check or lies off the
    /// curve). This is the shared core of both [`Read`] and [`G::hash_to_curve`].
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
    pub fn hash_to_curve(domain_separator: DST, message: &[u8]) -> Self {
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

    const TEST_DST: DST = b"COMMONWARE_BANDERWAGON_HASH_TO_CURVE_TEST";

    #[test]
    fn test_hash_to_curve_deterministic() {
        // Same inputs always produce the same point; it round-trips through the
        // codec (so it really is a valid subgroup element).
        let p = G::hash_to_curve(TEST_DST, b"hello");
        let q = G::hash_to_curve(TEST_DST, b"hello");
        assert_eq!(p, q);
        assert_eq!(G::decode(p.encode()).unwrap(), p);
    }

    #[test]
    fn test_hash_to_curve_distinct_messages() {
        // Different messages map to different points.
        let p = G::hash_to_curve(TEST_DST, b"message-a");
        let q = G::hash_to_curve(TEST_DST, b"message-b");
        assert_ne!(p, q);
    }

    #[test]
    fn test_hash_to_curve_in_subgroup() {
        // Every output must pass the subgroup check, i.e. re-encode/decode.
        minifuzz::test(|u| {
            let msg: Vec<u8> = u.arbitrary()?;
            let p = G::hash_to_curve(TEST_DST, &msg);
            assert_eq!(G::decode(p.encode()).unwrap(), p);
            Ok(())
        });
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
}
