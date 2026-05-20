//! Bandersnatch curve types for use in the Golden DKG EVRF.
//!
//! Bandersnatch is a twisted Edwards curve defined over the BLS12-381 scalar
//! field. This module wraps the arkworks implementation to conform to the
//! codebase's algebra trait hierarchy.

use crate::{
    bls12381::primitives::group::Scalar,
    zk::bulletproofs::circuit::{
        r1cs_to_circuit, r1cs_to_circuit_and_witness, Circuit, R1cs, SparseMatrix, Witness,
    },
};
use ark_ec::{
    hashing::{
        curve_maps::elligator2::Elligator2Map, map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    twisted_edwards::Projective,
    AdditiveGroup, CurveGroup, PrimeGroup, VariableBaseMSM,
};
use ark_ed_on_bls12_381_bandersnatch::{
    constraints::EdwardsVar, BandersnatchConfig, EdwardsAffine, Fq, Fr,
};
use ark_ff::{
    field_hashers::DefaultFieldHasher, BigInteger, Field as ArkField, PrimeField, UniformRand,
    Zero as ArkZero,
};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::{AllocatedFp, FpVar},
    groups::CurveVar,
    prelude::{Boolean, ToBitsGadget},
    R1CSVar,
};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode,
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
use rand::rngs::StdRng;
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

/// A point on the Bandersnatch curve (twisted Edwards form).
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct G(Projective<BandersnatchConfig>);

impl G {
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

type GVar = EdwardsVar;

fn vrf_gadget(
    x_bits_le: &[Boolean<Fq>],
    receiver: &GVar,
    t0: &GVar,
    t1: &GVar,
    beta: &FpVar<Fq>,
) -> Result<FpVar<Fq>, SynthesisError> {
    let s = {
        let mut out = receiver.scalar_mul_le(x_bits_le.iter())?;
        out.double_in_place()?;
        out.double_in_place()?;
        out
    };
    // Use only the x-coordinate bits as the scalar. `AffineVar::to_bits_le`
    // returns `x_bits ++ y_bits`, which would not match `vrf_recv` (which
    // scalar-multiplies by `s.x_as_f()`).
    let k = s.x.to_bits_le()?;
    Ok(t0.scalar_mul_le(k.iter())?.x * beta + t1.scalar_mul_le(k.iter())?.x)
}

fn vrf_batch_circuit(
    msg: &[u8],
    cs: ConstraintSystemRef<Fq>,
    beta: &Fq,
    sender: &G,
    receivers: &[G],
    x: Option<&F>,
) -> Result<Vec<usize>, SynthesisError> {
    let beta = FpVar::new_constant(cs.clone(), beta)?;
    // The witness shape (the number of scalar bits) must be the same for
    // setup-mode synthesis (no `x`) as it is for proving. When `x` is missing,
    // we fall back to a fixed-length all-zero bit vector matching `F`'s bigint
    // representation.
    let x_bits_le = Vec::<Boolean<_>>::new_witness(cs.clone(), || {
        Ok::<_, SynthesisError>(x.map(F::bits_le).unwrap_or_else(|| F::zero().bits_le()))
    })?;
    let sender_var = GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || Ok(sender.0),
        AllocationMode::Constant,
    )?;
    let generator = GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || Ok(G::generator().0),
        AllocationMode::Constant,
    )?;
    sender_var.enforce_equal(&generator.scalar_mul_le(x_bits_le.iter())?)?;
    let mut out = Vec::new();
    for receiver in receivers {
        let (t0, t1) = point_hash(sender, receiver, msg);
        let t0 = GVar::new_variable_omit_on_curve_check(
            cs.clone(),
            || Ok(t0.0),
            AllocationMode::Constant,
        )?;
        let t1 = GVar::new_variable_omit_on_curve_check(
            cs.clone(),
            || Ok(t1.0),
            AllocationMode::Constant,
        )?;
        let receiver = GVar::new_variable_omit_on_curve_check(
            cs.clone(),
            || Ok(receiver.0),
            AllocationMode::Constant,
        )?;
        let out_i = vrf_gadget(&x_bits_le, &receiver, &t0, &t1, &beta)?;
        // In setup mode, `out_i.value()` is unavailable; fall back to zero so
        // synthesis can still produce the correct constraint matrices.
        let out_i_witness = AllocatedFp::new_witness(cs.clone(), || {
            Ok::<_, SynthesisError>(out_i.value().unwrap_or(Fq::ZERO))
        })?;
        out_i.enforce_equal(&out_i_witness.clone().into())?;
        // The R1CS matrix lays out columns as
        // `[instance_assignment | witness_assignment]`, so witness variables
        // start at column `num_instance_variables`. Use that offset so the
        // returned indices match the matrix column space.
        out.push(
            out_i_witness
                .variable
                .get_index_unchecked(cs.num_instance_variables())
                .expect("new_witness returns witness"),
        );
    }
    Ok(out)
}

fn constraint_matrices_to_r1cs(matrices: ConstraintMatrices<Fq>) -> R1cs<Scalar> {
    fn convert_matrix(m: Vec<Vec<(Fq, usize)>>) -> SparseMatrix<Scalar> {
        let mut out = SparseMatrix::default();
        for (i, m_i) in m.into_iter().enumerate() {
            for (m_ij, j) in m_i {
                out[(i, j)] = fq_to_scalar(&m_ij);
            }
        }
        out
    }
    R1cs {
        a: convert_matrix(matrices.a),
        b: convert_matrix(matrices.b),
        c: convert_matrix(matrices.c),
    }
}

fn vrf_batch_checked_inner(
    msg: &[u8],
    x: Option<&F>,
    sender: G,
    receivers: &[G],
) -> (Circuit<Scalar>, Option<Witness<Scalar>>) {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    if x.is_some() {
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
    } else {
        cs.set_mode(SynthesisMode::Setup);
    }
    let output_indices = vrf_batch_circuit(
        msg,
        cs.clone(),
        &scalar_to_fq(&GOLDEN_BETA),
        &sender,
        receivers,
        x,
    )
    .expect("constraint synthesization should not fail");
    cs.finalize();
    if x.is_some() {
        debug_assert!(
            cs.is_satisfied().unwrap_or(false),
            "arkworks constraint system unsatisfied"
        );
    }
    let cs = cs
        .into_inner()
        .expect("constraint system should have only one ref");
    let matrices = cs
        .to_matrices()
        .expect("constraint system should have generated matrices");
    let r1cs = constraint_matrices_to_r1cs(matrices);
    if x.is_some() {
        // Concatenate instance and witness assignments so the resulting vector
        // is column-aligned with the R1CS matrix
        // (`[instance_assignment | witness_assignment]`). The first instance
        // entry is the constant `1`.
        let witness = cs
            .instance_assignment
            .into_iter()
            .chain(cs.witness_assignment)
            .map(|x| fq_to_scalar(&x))
            .collect::<Vec<_>>();
        let (c, w) =
            r1cs_to_circuit_and_witness(None::<&mut StdRng>, r1cs, witness, &output_indices);
        (c, Some(w))
    } else {
        let c = r1cs_to_circuit(r1cs, &output_indices);
        (c, None)
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
