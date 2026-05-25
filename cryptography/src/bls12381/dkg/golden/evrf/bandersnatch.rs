//! Bandersnatch curve types for use in the Golden DKG EVRF.
//!
//! Bandersnatch is a twisted Edwards curve defined over the BLS12-381 scalar
//! field. This module wraps the arkworks implementation to conform to the
//! codebase's algebra trait hierarchy.

use crate::{
    bls12381::primitives::group::Scalar,
    zk::bulletproofs::circuit::{Circuit, SparseMatrix, Witness},
};
use ark_ec::{
    hashing::{
        curve_maps::elligator2::Elligator2Map, map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    twisted_edwards::MontCurveConfig,
    twisted_edwards::Projective,
    AdditiveGroup, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ed_on_bls12_381_bandersnatch::{
    BandersnatchConfig, EdwardsAffine, Fq, Fr, SWAffine, SWProjective,
};
use ark_ff::{
    field_hashers::DefaultFieldHasher, BigInteger, Field as ArkField, PrimeField, UniformRand,
    Zero as ArkZero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::{
    Additive, CryptoGroup, Field, HashToGroup, Multiplicative, Object, Random, Ring, Space,
};
use commonware_parallel::Strategy;
use core::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use std::sync::LazyLock;

/// A scalar in the Bandersnatch scalar field.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct F(Fr);

impl F {
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        self.0
            .serialize_compressed(&mut bytes[..])
            .expect("serialization into fixed buffer succeeds");
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, CodecError> {
        let fr = Fr::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map_err(|_| CodecError::Invalid("bandersnatch::F", "invalid"))?;
        Ok(Self(fr))
    }

    fn bits_le(&self) -> Vec<bool> {
        self.0.into_bigint().to_bits_le()
    }
}

impl Debug for F {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "bandersnatch::F([REDACTED])")
    }
}

impl Object for F {}

impl<'a> AddAssign<&'a Self> for F {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
    }
}

impl<'a> Add<&'a Self> for F {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for F {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= rhs.0;
    }
}

impl<'a> Sub<&'a Self> for F {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Additive for F {
    fn zero() -> Self {
        Self(Fr::from(0u64))
    }
}

impl<'a> MulAssign<&'a Self> for F {
    fn mul_assign(&mut self, rhs: &'a Self) {
        self.0 *= rhs.0;
    }
}

impl<'a> Mul<&'a Self> for F {
    type Output = Self;

    fn mul(mut self, rhs: &'a Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Multiplicative for F {}

impl Ring for F {
    fn one() -> Self {
        Self(Fr::from(1u64))
    }
}

impl Field for F {
    fn inv(&self) -> Self {
        if self.0.is_zero() {
            return Self::zero();
        }
        Self(self.0.inverse().expect("nonzero element has inverse"))
    }
}

impl Random for F {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        Self(Fr::rand(&mut rng))
    }
}

impl Write for F {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.to_bytes());
    }
}

impl Read for F {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        Self::from_bytes(&bytes)
    }
}

impl FixedSize for F {
    const SIZE: usize = 32;
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = u.arbitrary::<[u8; 32]>()?;
        Ok(Self(Fr::from_le_bytes_mod_order(&bytes)))
    }
}

fn fq_to_scalar(x: &Fq) -> Scalar {
    Scalar::from_limbs(x.into_bigint().0)
}

fn scalar_to_fq(x: &Scalar) -> Fq {
    Fq::from_be_bytes_mod_order(&x.encode())
}

fn montgomery_a() -> Fq {
    <BandersnatchConfig as MontCurveConfig>::COEFF_A
}

fn montgomery_b() -> Fq {
    <BandersnatchConfig as MontCurveConfig>::COEFF_B
}

fn montgomery_a_over_3() -> Fq {
    montgomery_a() * Fq::from(3u64).inverse().expect("3 is nonzero")
}

fn te_to_sw_affine(point: &EdwardsAffine) -> Option<SWAffine> {
    if point.is_zero() {
        return None;
    }

    // TE -> Montgomery:
    //   u = (1 + y) / (1 - y)
    //   v = u / x
    //
    // Montgomery -> SW:
    //   X = (u + A / 3) / B
    //   Y = v / B
    let one = Fq::ONE;
    let u = (one + point.y) * (one - point.y).inverse()?;
    let v = u * point.x.inverse()?;
    let b_inv = montgomery_b().inverse().expect("Montgomery B is nonzero");
    Some(SWAffine::new_unchecked(
        (u + montgomery_a_over_3()) * b_inv,
        v * b_inv,
    ))
}

/// A point on the Bandersnatch curve (twisted Edwards form).
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct G(Projective<BandersnatchConfig>);

impl G {
    fn sw_affine(&self) -> SWAffine {
        te_to_sw_affine(&self.0.into_affine())
            .expect("prime-subgroup Bandersnatch points used in eVRF are finite in SW form")
    }

    fn sw_projective(&self) -> SWProjective {
        self.sw_affine().into()
    }

    /// Returns the affine x-coordinate as the shared BLS12-381 scalar type.
    pub fn x_as_scalar(&self) -> Scalar {
        fq_to_scalar(&self.0.into_affine().x)
    }

    /// Returns the affine x-coordinate as a Bandersnatch scalar.
    pub fn x_as_f(&self) -> F {
        let bytes = self.0.into_affine().x.into_bigint().to_bytes_le();
        F(Fr::from_le_bytes_mod_order(&bytes))
    }

    /// Map this point into the prime-order subgroup by multiplying by the cofactor (4).
    pub fn clear_cofactor(&self) -> Self {
        let mut out = self.clone();
        out.double();
        out.double();
        out
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let affine = self.0.into_affine();
        let mut bytes = [0u8; Self::SIZE];
        affine
            .serialize_compressed(&mut bytes[..])
            .expect("serialization into fixed buffer succeeds");
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, CodecError> {
        let affine = EdwardsAffine::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map_err(|_| CodecError::Invalid("bandersnatch::G", "invalid"))?;
        Ok(Self(affine.into()))
    }
}

impl Debug for G {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "bandersnatch::G({})",
            commonware_formatting::hex(&self.to_bytes())
        )
    }
}

impl Object for G {}

impl<'a> AddAssign<&'a Self> for G {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += rhs.0;
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
        self.0 -= rhs.0;
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
        Self(-self.0)
    }
}

impl Additive for G {
    fn zero() -> Self {
        Self(Projective::<BandersnatchConfig>::zero())
    }

    fn double(&mut self) {
        self.0.double_in_place();
    }
}

impl<'a> MulAssign<&'a F> for G {
    fn mul_assign(&mut self, rhs: &'a F) {
        self.0 *= rhs.0;
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
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        if points.is_empty() {
            return Self::zero();
        }
        let affines: Vec<EdwardsAffine> = points.iter().map(|p| p.0.into_affine()).collect();
        let frs: Vec<Fr> = scalars.iter().map(|s| s.0).collect();
        Self(Projective::<BandersnatchConfig>::msm(&affines, &frs).expect("lengths are equal"))
    }
}

impl CryptoGroup for G {
    type Scalar = F;

    fn generator() -> Self {
        Self(Projective::<BandersnatchConfig>::generator())
    }
}

impl HashToGroup for G {
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        let hasher = MapToCurveBasedHasher::<
            Projective<BandersnatchConfig>,
            DefaultFieldHasher<Sha256, 128>,
            Elligator2Map<BandersnatchConfig>,
        >::new(domain_separator)
        // In non-test builds, new() unconditionally returns Ok. In test builds
        // it validates the Elligator2 constants, which are hardcoded correctly.
        .expect("valid DST");
        // Elligator2 is a total map (defined for every field element), so hash()
        // cannot fail. The Result comes from the generic MapToCurve trait which
        // also covers partial maps like try-and-increment.
        let affine = hasher.hash(message).expect("Elligator2 is a total map");
        // Clear the cofactor so the result is in the prime-order subgroup.
        // Elligator2 maps onto the full Bandersnatch curve (cofactor 4); a
        // hash-to-group primitive must land in the prime subgroup.
        Self(affine.into()).clear_cofactor()
    }
}

impl Write for G {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.to_bytes());
    }
}

impl Read for G {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        Self::from_bytes(&bytes)
    }
}

impl FixedSize for G {
    const SIZE: usize = 32;
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for G {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::generator() * &u.arbitrary::<F>()?)
    }
}

static GOLDEN_BETA: LazyLock<Scalar> =
    LazyLock::new(|| Scalar::map(b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_DKG_BETA", b""));

const POINT_DST: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_POINT_HASH";
const SW_CORRECTION_DST: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_DKG_SW_CORRECTION";
const SW_WINDOW_BITS: usize = 2;

fn point_hash(pk1: &G, pk2: &G, msg: &[u8]) -> (G, G) {
    let msg0 = [&pk1.to_bytes(), &pk2.to_bytes(), msg, &[0]].concat();
    let t0 = G::hash_to_group(POINT_DST, &msg0);
    let msg1 = {
        let mut out = msg0;
        out.pop();
        out.push(1);
        out
    };
    let t1 = G::hash_to_group(POINT_DST, &msg1);
    // `hash_to_group` returns prime-order-subgroup points. This is required so
    // that the gadget (which computes `t0 * k_int` via `scalar_mul_le` over
    // full bit-strings of the x-coordinate) and `vrf_recv` (which computes
    // `t0 * (k_int mod r)` via Fr scalar multiplication) agree.
    (t0, t1)
}

#[derive(Clone, Copy)]
enum Slot {
    Committed(usize),
    Left(usize),
    Right(usize),
    Out(usize),
}

#[derive(Clone)]
struct Var {
    value: Scalar,
    slot: Option<Slot>,
}

#[derive(Clone)]
struct Lin {
    value: Scalar,
    constant: Scalar,
    terms: Vec<(Scalar, Slot)>,
}

impl Lin {
    fn zero() -> Self {
        Self {
            value: Scalar::zero(),
            constant: Scalar::zero(),
            terms: Vec::new(),
        }
    }

    fn one() -> Self {
        Self::constant(Scalar::one())
    }

    fn constant(value: Scalar) -> Self {
        Self {
            value: value.clone(),
            constant: value,
            terms: Vec::new(),
        }
    }

    fn var(var: Var) -> Self {
        let mut out = Self::zero();
        out.add_scaled_var(Scalar::one(), &var);
        out
    }

    fn add_scaled_var(&mut self, coeff: Scalar, var: &Var) {
        let delta = coeff.clone() * &var.value;
        self.value += &delta;
        if let Some(slot) = var.slot {
            self.terms.push((coeff, slot));
        } else {
            self.constant += &delta;
        }
    }

    fn add_scaled_lin(&mut self, coeff: Scalar, rhs: &Self) {
        let delta = coeff.clone() * &rhs.value;
        self.value += &delta;
        let constant_delta = coeff.clone() * &rhs.constant;
        self.constant += &constant_delta;
        for (rhs_coeff, slot) in &rhs.terms {
            self.terms.push((coeff.clone() * rhs_coeff, *slot));
        }
    }

    fn scaled(mut self, coeff: Scalar) -> Self {
        self.value *= &coeff;
        self.constant *= &coeff;
        for (term_coeff, _) in &mut self.terms {
            *term_coeff *= &coeff;
        }
        self
    }

    fn plus(mut self, rhs: &Self) -> Self {
        self.add_scaled_lin(Scalar::one(), rhs);
        self
    }
}

#[derive(Clone)]
struct SwPoint {
    x: Scalar,
    y: Scalar,
}

impl SwPoint {
    fn from_affine(point: SWAffine) -> Self {
        assert!(
            !point.infinity,
            "paper-style eVRF exponentiation requires finite SW points"
        );
        Self {
            x: fq_to_scalar(&point.x),
            y: fq_to_scalar(&point.y),
        }
    }
}

#[derive(Clone)]
struct SwPointLin {
    x: Lin,
    y: Lin,
}

impl SwPointLin {
    fn constant(point: &G) -> Self {
        let point = SwPoint::from_affine(point.sw_affine());
        Self {
            x: Lin::constant(point.x),
            y: Lin::constant(point.y),
        }
    }
}

struct NativeCircuitBuilder {
    committed: Vec<Scalar>,
    left: Vec<Scalar>,
    right: Vec<Scalar>,
    out: Vec<Scalar>,
    constraints: Vec<Lin>,
}

impl NativeCircuitBuilder {
    fn new(committed: usize) -> Self {
        Self {
            committed: vec![Scalar::zero(); committed],
            left: Vec::new(),
            right: Vec::new(),
            out: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn committed(&self, index: usize) -> Var {
        Var {
            value: self.committed[index].clone(),
            slot: Some(Slot::Committed(index)),
        }
    }

    fn set_committed(&mut self, index: usize, value: Scalar) {
        self.committed[index] = value;
    }

    fn push_gate(&mut self, left: Scalar, right: Scalar, out: Scalar) -> usize {
        let index = self.left.len();
        self.left.push(left);
        self.right.push(right);
        self.out.push(out);
        index
    }

    fn left_var(&self, index: usize) -> Var {
        Var {
            value: self.left[index].clone(),
            slot: Some(Slot::Left(index)),
        }
    }

    fn right_var(&self, index: usize) -> Var {
        Var {
            value: self.right[index].clone(),
            slot: Some(Slot::Right(index)),
        }
    }

    fn out_var(&self, index: usize) -> Var {
        Var {
            value: self.out[index].clone(),
            slot: Some(Slot::Out(index)),
        }
    }

    fn assert_zero(&mut self, expr: Lin) {
        self.constraints.push(expr);
    }

    fn assert_equal(&mut self, lhs: Lin, rhs: Lin) {
        let mut expr = lhs;
        expr.add_scaled_lin(-Scalar::one(), &rhs);
        self.assert_zero(expr);
    }

    fn mul(&mut self, lhs: Lin, rhs: Lin) -> Var {
        let product = lhs.value.clone() * &rhs.value;
        let index = self.push_gate(lhs.value.clone(), rhs.value.clone(), product);
        self.assert_equal(Lin::var(self.left_var(index)), lhs);
        self.assert_equal(Lin::var(self.right_var(index)), rhs);
        self.out_var(index)
    }

    fn mul_lin(&mut self, lhs: Lin, rhs: Lin) -> Lin {
        if lhs.terms.is_empty() {
            if lhs.constant == Scalar::zero() {
                return Lin::zero();
            }
            if lhs.constant == Scalar::one() {
                return rhs;
            }
            return rhs.scaled(lhs.constant);
        }
        if rhs.terms.is_empty() {
            if rhs.constant == Scalar::zero() {
                return Lin::zero();
            }
            if rhs.constant == Scalar::one() {
                return lhs;
            }
            return lhs.scaled(rhs.constant);
        }
        Lin::var(self.mul(lhs, rhs))
    }

    fn mul_left_witness(&mut self, left: Scalar, right: Lin, product: Lin) -> Var {
        let index = self.push_gate(left, right.value.clone(), product.value.clone());
        self.assert_equal(Lin::var(self.right_var(index)), right);
        self.assert_equal(Lin::var(self.out_var(index)), product);
        self.left_var(index)
    }

    fn boolean(&mut self, value: bool) -> Var {
        let bit = if value { Scalar::one() } else { Scalar::zero() };
        let right = bit.clone() - &Scalar::one();
        let index = self.push_gate(bit, right, Scalar::zero());
        let mut right_minus_left = Lin::var(self.right_var(index));
        right_minus_left.add_scaled_var(-Scalar::one(), &self.left_var(index));
        right_minus_left.add_scaled_lin(Scalar::one(), &Lin::one());
        self.assert_zero(right_minus_left);
        self.assert_equal(Lin::var(self.out_var(index)), Lin::zero());
        self.left_var(index)
    }

    fn bit_decompose(&mut self, value: Lin, bits: &[bool], enforce_field: bool) -> Vec<Var> {
        let bit_vars = bits
            .iter()
            .map(|&bit| self.boolean(bit))
            .collect::<Vec<_>>();
        let mut reconstructed = Lin::zero();
        let mut coeff = Scalar::one();
        let two = Scalar::from_u64(2);
        for bit in &bit_vars {
            reconstructed.add_scaled_var(coeff.clone(), bit);
            coeff *= &two;
        }
        self.assert_equal(reconstructed, value);
        if enforce_field {
            self.enforce_field_bits(&bit_vars);
        }
        bit_vars
    }

    fn enforce_field_bits(&mut self, bits: &[Var]) {
        let modulus = fq_modulus_bits_le();
        assert_eq!(bits.len(), modulus.len(), "field bit check length mismatch");

        // Subtract the field modulus from the reconstructed integer. Because
        // `bits` has exactly the modulus bit length, the final borrow is one
        // iff the represented integer is strictly less than the modulus.
        let mut borrow = Lin::zero();
        for (bit, &modulus_bit) in bits.iter().zip(modulus.iter()) {
            let mut not_bit = Lin::one();
            not_bit.add_scaled_var(-Scalar::one(), bit);
            if modulus_bit {
                let mut not_borrow = Lin::one();
                not_borrow.add_scaled_lin(-Scalar::one(), &borrow);
                let bit_and_not_borrow = self.mul_lin(Lin::var(bit.clone()), not_borrow);
                let mut next = Lin::one();
                next.add_scaled_lin(-Scalar::one(), &bit_and_not_borrow);
                borrow = next;
            } else {
                borrow = self.mul_lin(borrow, not_bit);
            }
        }
        self.assert_equal(borrow, Lin::one());
    }

    fn sw_delta_coordinate(bit: &Var, zero: &Scalar, one: &Scalar) -> Lin {
        let mut out = Lin::constant(zero.clone());
        let mut coeff = one.clone();
        coeff -= zero;
        out.add_scaled_var(coeff, bit);
        out
    }

    fn sw_select_delta(bit: &Var, zero: &SwPoint, one: &SwPoint) -> SwPointLin {
        SwPointLin {
            x: Self::sw_delta_coordinate(bit, &zero.x, &one.x),
            y: Self::sw_delta_coordinate(bit, &zero.y, &one.y),
        }
    }

    fn sw_select_delta_window(&mut self, bits: &[Var], points: &[SwPoint]) -> SwPointLin {
        match bits.len() {
            1 => {
                debug_assert_eq!(points.len(), 2);
                Self::sw_select_delta(&bits[0], &points[0], &points[1])
            }
            2 => {
                debug_assert_eq!(points.len(), 4);
                let both = self.mul(Lin::var(bits[0].clone()), Lin::var(bits[1].clone()));
                let coordinate =
                    |zero: &Scalar, one: &Scalar, two: &Scalar, three: &Scalar, both: &Var| {
                        let mut out = Lin::constant(zero.clone());
                        let mut b0_coeff = one.clone();
                        b0_coeff -= zero;
                        out.add_scaled_var(b0_coeff, &bits[0]);
                        let mut b1_coeff = two.clone();
                        b1_coeff -= zero;
                        out.add_scaled_var(b1_coeff, &bits[1]);
                        let mut both_coeff = three.clone();
                        both_coeff -= two;
                        both_coeff -= one;
                        both_coeff += zero;
                        out.add_scaled_var(both_coeff, both);
                        out
                    };
                SwPointLin {
                    x: coordinate(
                        &points[0].x,
                        &points[1].x,
                        &points[2].x,
                        &points[3].x,
                        &both,
                    ),
                    y: coordinate(
                        &points[0].y,
                        &points[1].y,
                        &points[2].y,
                        &points[3].y,
                        &both,
                    ),
                }
            }
            _ => panic!("unsupported SW fixed-base window size"),
        }
    }

    fn sw_correction_base(base: &G) -> SWProjective {
        G::hash_to_group(SW_CORRECTION_DST, &base.to_bytes()).sw_projective()
    }

    fn sw_correction_point(
        correction_base: &SWProjective,
        index: usize,
        windows: usize,
    ) -> SWProjective {
        debug_assert!(index < windows);
        let coeff = if index == 0 {
            Fr::from(1u64)
        } else if index + 1 == windows {
            // The correction points must sum to the identity. With c_0 = 1
            // and c_i = 2 for the middle windows, the final correction is
            // -(1 + 2 * (windows - 2)).
            -Fr::from((2 * windows - 3) as u64)
        } else {
            Fr::from(2u64)
        };
        *correction_base * coeff
    }

    fn sw_add_chord(&mut self, p: &SwPointLin, q: &SwPointLin) -> SwPointLin {
        let mut x_diff = p.x.clone();
        x_diff.add_scaled_lin(-Scalar::one(), &q.x);
        let mut y_diff = p.y.clone();
        y_diff.add_scaled_lin(-Scalar::one(), &q.y);

        let slope_value = y_diff.value.clone() * &x_diff.value.inv();
        let slope = self.mul_left_witness(slope_value, x_diff, y_diff);
        let slope = Lin::var(slope);

        let slope_squared = self.mul(slope.clone(), slope.clone());
        let mut x = Lin::var(slope_squared);
        x.add_scaled_lin(-Scalar::one(), &p.x);
        x.add_scaled_lin(-Scalar::one(), &q.x);

        let mut x_prev_minus_x = p.x.clone();
        x_prev_minus_x.add_scaled_lin(-Scalar::one(), &x);
        let y_sum = self.mul(slope, x_prev_minus_x);
        let mut y = Lin::var(y_sum);
        y.add_scaled_lin(-Scalar::one(), &p.y);

        SwPointLin { x, y }
    }

    fn sw_fixed_base_mul(&mut self, base: &G, bits: &[Var]) -> SwPointLin {
        assert!(
            !bits.is_empty(),
            "fixed-base scalar multiplication needs at least one bit"
        );
        let windows = bits.len().div_ceil(SW_WINDOW_BITS);
        assert!(
            windows > 1,
            "correction-based fixed-base multiplication needs at least two windows"
        );
        let correction_base = Self::sw_correction_base(base);
        let mut base_power = base.sw_projective();
        let mut acc = None;
        for (i, window_bits) in bits.chunks(SW_WINDOW_BITS).enumerate() {
            let correction = Self::sw_correction_point(&correction_base, i, windows);
            let points = (0..(1usize << window_bits.len()))
                .map(|j| {
                    let multiple = base_power * Fr::from(j as u64);
                    SwPoint::from_affine((correction + multiple).into_affine())
                })
                .collect::<Vec<_>>();
            let delta = self.sw_select_delta_window(window_bits, &points);
            acc = Some(match acc {
                None => delta,
                Some(ref current) => self.sw_add_chord(current, &delta),
            });
            for _ in 0..SW_WINDOW_BITS {
                base_power.double_in_place();
            }
        }
        acc.expect("bits is not empty")
    }

    fn sw_fixed_base_muls_same_scalar(&mut self, bases: &[G], bits: &[Var]) -> Vec<SwPointLin> {
        bases
            .iter()
            .map(|base| self.sw_fixed_base_mul(base, bits))
            .collect()
    }

    fn sw_to_te_x(&mut self, point: &SwPointLin) -> Lin {
        let b = fq_to_scalar(&montgomery_b());
        let a_over_3 = fq_to_scalar(&montgomery_a_over_3());

        let mut u = point.x.clone().scaled(b.clone());
        u.add_scaled_lin(Scalar::one(), &Lin::constant(-a_over_3));
        let v = point.y.clone().scaled(b);

        let x = u.value.clone() * &v.value.inv();
        Lin::var(self.mul_left_witness(x, v, u))
    }

    fn finish(self) -> (Circuit<Scalar>, Witness<Scalar>) {
        let committed_vars = self.committed.len();
        let internal_vars = self.left.len();
        let mut weights = SparseMatrix::default();
        weights.pad(
            1 + committed_vars + 3 * internal_vars,
            self.constraints.len(),
        );
        for (row, constraint) in self.constraints.into_iter().enumerate() {
            if constraint.constant != Scalar::zero() {
                weights[(row, 0)] += &constraint.constant;
            }
            for (coeff, slot) in constraint.terms {
                let col = match slot {
                    Slot::Committed(i) => 1 + i,
                    Slot::Left(i) => 1 + committed_vars + i,
                    Slot::Right(i) => 1 + committed_vars + internal_vars + i,
                    Slot::Out(i) => 1 + committed_vars + 2 * internal_vars + i,
                };
                weights[(row, col)] += &coeff;
            }
        }
        let circuit = Circuit::new(committed_vars, weights).expect("native circuit shape is valid");
        let witness = Witness::new(
            self.committed,
            vec![Scalar::zero(); committed_vars],
            self.left,
            self.right,
            self.out,
        )
        .expect("native witness shape is valid");
        (circuit, witness)
    }
}

fn scalar_bits_le(value: &Scalar, bits: usize) -> Vec<bool> {
    let mut out = scalar_to_fq(value).into_bigint().to_bits_le();
    out.resize(bits, false);
    out.truncate(bits);
    out
}

fn fq_modulus_bits_le() -> Vec<bool> {
    let limbs = Fq::characteristic().to_vec();
    let mut bits = Vec::with_capacity(limbs.len() * 64);
    for limb in limbs {
        for i in 0..64 {
            bits.push(((limb >> i) & 1) == 1);
        }
    }
    bits.truncate(Fq::MODULUS_BIT_SIZE as usize);
    bits
}

fn vrf_batch_checked_inner(
    msg: &[u8],
    x: Option<&F>,
    sender: G,
    receivers: &[G],
) -> (Circuit<Scalar>, Option<Witness<Scalar>>) {
    let x_bits = x.map(F::bits_le).unwrap_or_else(|| F::zero().bits_le());
    let mut builder = NativeCircuitBuilder::new(receivers.len());
    let x_bits = x_bits
        .into_iter()
        .map(|bit| builder.boolean(bit))
        .collect::<Vec<_>>();

    let x_bases = core::iter::once(G::generator())
        .chain(receivers.iter().map(G::clear_cofactor))
        .collect::<Vec<_>>();
    let mut x_muls = builder.sw_fixed_base_muls_same_scalar(&x_bases, &x_bits);
    let sender_check = x_muls.remove(0);
    let sender_const = SwPointLin::constant(&sender);
    builder.assert_equal(sender_check.x, sender_const.x);
    builder.assert_equal(sender_check.y, sender_const.y);

    for (i, (receiver, shared)) in receivers.iter().zip(x_muls).enumerate() {
        let shared_x = builder.sw_to_te_x(&shared);
        let k_bits = {
            let bits = scalar_bits_le(&shared_x.value, Fq::MODULUS_BIT_SIZE as usize);
            builder.bit_decompose(shared_x, &bits, true)
        };
        let (t0, t1) = point_hash(&sender, receiver, msg);
        let mut evals = builder.sw_fixed_base_muls_same_scalar(&[t0, t1], &k_bits);
        let t0_eval = evals.remove(0);
        let t1_eval = evals.remove(0);
        let t0_x = builder.sw_to_te_x(&t0_eval);
        let t1_x = builder.sw_to_te_x(&t1_eval);
        let output = t0_x.scaled(GOLDEN_BETA.clone()).plus(&t1_x);
        builder.set_committed(i, output.value.clone());
        builder.assert_equal(Lin::var(builder.committed(i)), output);
    }

    let (circuit, witness) = builder.finish();
    if x.is_some() {
        debug_assert!(
            witness.is_satisfied(&circuit),
            "native eVRF witness does not satisfy circuit"
        );
        (circuit, Some(witness))
    } else {
        (circuit, None)
    }
}

pub fn vrf_batch_checked_circuit(msg: &[u8], sender: G, receivers: &[G]) -> Circuit<Scalar> {
    vrf_batch_checked_inner(msg, None, sender, receivers).0
}

pub fn vrf_batch_checked(msg: &[u8], x: &F, receivers: &[G]) -> (Circuit<Scalar>, Witness<Scalar>) {
    let (c, w) = vrf_batch_checked_inner(msg, Some(x), G::generator() * x, receivers);
    (c, w.expect("witness should not be None"))
}

pub fn vrf_recv(msg: &[u8], sender: G, receiver: &F) -> Scalar {
    let (t0, t1) = point_hash(&sender, &(G::generator() * receiver), msg);
    let s = (sender * receiver).clear_cofactor();
    let k = s.x_as_f();
    GOLDEN_BETA.clone() * &(t0 * &k).x_as_scalar() + &(t1 * &k).x_as_scalar()
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::test_suites;

    #[test]
    fn test_scalar_as_field() {
        minifuzz::test(test_suites::fuzz_field::<F>);
    }

    #[test]
    fn test_point_as_space() {
        minifuzz::test(test_suites::fuzz_space_ring::<F, G>);
    }

    #[test]
    fn test_hash_to_group() {
        minifuzz::test(test_suites::fuzz_hash_to_group::<G>);
    }

    #[test]
    fn test_small_scalar_vrf_witness_satisfies() {
        let x = F(Fr::from(1u64));
        let (circuit, witness) = vrf_batch_checked(b"small-scalar", &x, &[G::generator()]);
        assert!(witness.is_satisfied(&circuit));
    }

    /// Diagnostic: print circuit `internal_vars` (and `padded = next_pow2`) as
    /// a function of the number of receivers, so we can size
    /// `BULLETPROOFS_LG_LEN` appropriately.
    #[test]
    #[ignore = "diagnostic; run with `--ignored` to print circuit sizes"]
    fn measure_circuit_size_per_receiver() {
        for n in [1usize, 2, 3, 5, 7, 10, 16] {
            let receivers: Vec<G> = (0..n).map(|_| G::generator()).collect();
            let circuit = vrf_batch_checked_circuit(b"measure", G::generator(), &receivers);
            let internal = circuit.internal_vars();
            let padded = internal.next_power_of_two();
            eprintln!(
                "receivers={n:2} internal_vars={internal} padded={padded} (per_receiver={})",
                internal.checked_div(n).unwrap_or_default()
            );
        }
    }

    #[test]
    fn test_point_x_as_bls_scalar() {
        assert_eq!(G::zero().x_as_scalar(), Scalar::from_u64(0));

        let point = G::generator() * &F(Fr::from(7u64));
        assert_ne!(point.x_as_scalar(), Scalar::from_u64(0));
    }
}
