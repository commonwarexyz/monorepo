use super::{Error, circuit::Assignment, sample_scalar};
use crate::bls12381::primitives::group::{G1, G2, Scalar, ScalarReadCfg};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_math::algebra::{Additive, Space};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;
use std::collections::BTreeMap;

const COMMITMENT_KEY_DIGEST_NAMESPACE: &[u8] =
    b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_COMMITMENT_KEY_DIGEST";
const VERIFYING_KEY_DIGEST_NAMESPACE: &[u8] =
    b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_VERIFYING_KEY_DIGEST";

/// Randomness opening a native Pari committed-input commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening(Scalar);

impl Opening {
    /// Sample fresh commitment randomness.
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        Self(sample_scalar(rng))
    }

    /// Construct an opening from a scalar.
    pub const fn new(value: Scalar) -> Self {
        Self(value)
    }

    /// The opening randomness, e.g. for persisting alongside its commitment.
    pub const fn scalar(&self) -> &Scalar {
        &self.0
    }
}

impl Write for Opening {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Opening {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Opening {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self(Scalar::read_cfg(buf, &ScalarReadCfg::AllowZero)?))
    }
}

/// The circuit-specific key for committing to the relation's committed inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentKey {
    pub(crate) relation_digest: [u8; 32],
    pub(crate) basis: Vec<G1>,
    pub(crate) blinding: G1,
}

impl CommitmentKey {
    /// The relation this commitment key was generated for.
    pub const fn relation_digest(&self) -> &[u8; 32] {
        &self.relation_digest
    }

    /// Number of committed field elements expected by this key.
    pub const fn len(&self) -> usize {
        self.basis.len()
    }

    /// Returns whether the key commits to an empty vector.
    pub const fn is_empty(&self) -> bool {
        self.basis.is_empty()
    }

    /// Commit to an ordered vector of field elements.
    pub fn commit(
        &self,
        values: &[Scalar],
        opening: &Opening,
        strategy: &impl Strategy,
    ) -> Result<G1, Error> {
        if values.len() != self.basis.len() {
            return Err(Error::CommittedInputCount {
                expected: self.basis.len(),
                actual: values.len(),
            });
        }
        let commitment =
            G1::msm(&self.basis, values, strategy) + &(self.blinding * opening.scalar());
        if commitment == G1::zero() {
            return Err(Error::IdentityPoint { kind: "commitment" });
        }
        Ok(commitment)
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMMITMENT_KEY_DIGEST_NAMESPACE);
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }
}

impl Write for CommitmentKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.relation_digest.write(buf);
        self.basis.write(buf);
        self.blinding.write(buf);
    }
}

impl EncodeSize for CommitmentKey {
    fn encode_size(&self) -> usize {
        self.relation_digest.encode_size() + self.basis.encode_size() + self.blinding.encode_size()
    }
}

impl Read for CommitmentKey {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            relation_digest: <[u8; 32]>::read(buf)?,
            basis: Vec::<G1>::read_cfg(buf, &(*cfg, ()))?,
            blinding: G1::read(buf)?,
        })
    }
}

/// Public inputs and the expected native committed-input commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// Public inputs in the relation's declared order.
    pub public_inputs: Vec<Scalar>,
    /// Commitment to the relation's ordered committed inputs.
    pub commitment: G1,
}

/// Prover-only assignment and commitment opening for a compiled relation.
#[derive(Clone)]
pub struct Witness {
    pub(super) assignment: Assignment,
    pub(super) opening: Opening,
}

impl Witness {
    /// Construct the public claim corresponding to this witness.
    pub fn claim(
        &self,
        commitment_key: &CommitmentKey,
        strategy: &impl Strategy,
    ) -> Result<Claim, Error> {
        if self.assignment.relation_digest() != commitment_key.relation_digest() {
            return Err(Error::RelationMismatch);
        }
        Ok(Claim {
            public_inputs: self.assignment.public_inputs().to_vec(),
            commitment: commitment_key.commit(
                self.assignment.committed_inputs(),
                &self.opening,
                strategy,
            )?,
        })
    }

    pub(super) const fn assignment(&self) -> &Assignment {
        &self.assignment
    }

    pub(crate) const fn opening(&self) -> &Opening {
        &self.opening
    }
}

impl Claim {
    /// Construct a public Pari claim.
    pub const fn new(public_inputs: Vec<Scalar>, commitment: G1) -> Self {
        Self {
            public_inputs,
            commitment,
        }
    }
}

impl Write for Claim {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_inputs.write(buf);
        self.commitment.write(buf);
    }
}

impl EncodeSize for Claim {
    fn encode_size(&self) -> usize {
        self.public_inputs.encode_size() + self.commitment.encode_size()
    }
}

impl Read for Claim {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            public_inputs: Vec::<Scalar>::read_cfg(buf, &(*cfg, ScalarReadCfg::AllowZero))?,
            commitment: G1::read(buf)?,
        })
    }
}

/// A Pari proof consisting of two G1 elements and one scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub(crate) t: G1,
    pub(crate) u: G1,
    pub(crate) v_a: Scalar,
}

impl Write for Proof {
    fn write(&self, buf: &mut impl BufMut) {
        self.t.write(buf);
        self.u.write(buf);
        self.v_a.write(buf);
    }
}

impl EncodeSize for Proof {
    fn encode_size(&self) -> usize {
        self.t.encode_size() + self.u.encode_size() + self.v_a.encode_size()
    }
}

impl Read for Proof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            t: G1::read(buf)?,
            u: G1::read(buf)?,
            v_a: Scalar::read_cfg(buf, &ScalarReadCfg::AllowZero)?,
        })
    }
}

/// One public column of the constraint matrices, stored sparsely.
///
/// Maps a constraint-row index to that row's coefficient in this column of
/// `A` and of `B`. Row keys ascend and coefficients are nonzero, so every
/// column has exactly one encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublicColumn {
    pub(crate) a: BTreeMap<u32, Scalar>,
    pub(crate) b: BTreeMap<u32, Scalar>,
}

impl PublicColumn {
    fn max_row(&self) -> Option<u32> {
        let a = self.a.last_key_value().map(|(&row, _)| row);
        let b = self.b.last_key_value().map(|(&row, _)| row);
        a.max(b)
    }
}

impl Write for PublicColumn {
    fn write(&self, buf: &mut impl BufMut) {
        self.a.write(buf);
        self.b.write(buf);
    }
}

impl EncodeSize for PublicColumn {
    fn encode_size(&self) -> usize {
        self.a.encode_size() + self.b.encode_size()
    }
}

impl Read for PublicColumn {
    /// The relation's domain size, bounding row indices and entry counts.
    type Cfg = u32;

    fn read_cfg(
        buf: &mut impl Buf,
        domain_size: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let entries = RangeCfg::new(0..=*domain_size as usize);
        let cfg = (entries, ((), ScalarReadCfg::RejectZero));
        let column = Self {
            a: BTreeMap::read_cfg(buf, &cfg)?,
            b: BTreeMap::read_cfg(buf, &cfg)?,
        };
        if column.max_row().is_some_and(|row| row >= *domain_size) {
            return Err(commonware_codec::Error::Invalid(
                "PublicColumn",
                "row index exceeds the domain",
            ));
        }
        Ok(column)
    }
}

/// The succinct key used to verify proofs for one relation.
///
/// Embeds the sparse public columns of the constraint matrices, so
/// verification needs no access to the compiled relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub(crate) relation_digest: [u8; 32],
    pub(crate) commitment_key_digest: [u8; 32],
    pub(crate) domain_size: u32,
    pub(crate) public_inputs: u32,
    pub(crate) committed_inputs: u32,
    pub(crate) public_columns: Vec<PublicColumn>,
    pub(crate) alpha_g: G1,
    pub(crate) beta_g: G1,
    pub(crate) delta_committed_h: G2,
    pub(crate) delta_witness_h: G2,
    pub(crate) tau_h: G2,
    // Derived from the encoded fields; never encoded itself.
    pub(crate) digest: [u8; 32],
}

impl VerifyingKey {
    /// The relation this key verifies.
    pub const fn relation_digest(&self) -> &[u8; 32] {
        &self.relation_digest
    }

    /// Number of ordinary public inputs, excluding the implicit constant one.
    pub const fn public_input_count(&self) -> usize {
        self.public_inputs as usize
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Populate the cached digest from the other fields.
    pub(crate) fn finalize(mut self) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(VERIFYING_KEY_DIGEST_NAMESPACE);
        hasher.update(&self.encode());
        self.digest = *hasher.finalize().as_bytes();
        self
    }
}

impl Write for VerifyingKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.relation_digest.write(buf);
        self.commitment_key_digest.write(buf);
        self.domain_size.write(buf);
        self.public_inputs.write(buf);
        self.committed_inputs.write(buf);
        self.public_columns.write(buf);
        self.alpha_g.write(buf);
        self.beta_g.write(buf);
        self.delta_committed_h.write(buf);
        self.delta_witness_h.write(buf);
        self.tau_h.write(buf);
    }
}

impl EncodeSize for VerifyingKey {
    fn encode_size(&self) -> usize {
        self.relation_digest.encode_size()
            + self.commitment_key_digest.encode_size()
            + self.domain_size.encode_size()
            + self.public_inputs.encode_size()
            + self.committed_inputs.encode_size()
            + self.public_columns.encode_size()
            + self.alpha_g.encode_size()
            + self.beta_g.encode_size()
            + self.delta_committed_h.encode_size()
            + self.delta_witness_h.encode_size()
            + self.tau_h.encode_size()
    }
}

impl Read for VerifyingKey {
    /// Bound on the number of ordinary public inputs.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let relation_digest = <[u8; 32]>::read(buf)?;
        let commitment_key_digest = <[u8; 32]>::read(buf)?;
        let domain_size = u32::read(buf)?;
        if !domain_size.is_power_of_two() {
            return Err(commonware_codec::Error::Invalid(
                "VerifyingKey",
                "domain size must be a power of two",
            ));
        }
        let public_inputs = u32::read(buf)?;
        if !cfg.contains(&(public_inputs as usize)) {
            return Err(commonware_codec::Error::Invalid(
                "VerifyingKey",
                "public input count out of range",
            ));
        }
        let committed_inputs = u32::read(buf)?;
        let columns = public_inputs as usize + 1;
        if (committed_inputs as usize)
            .checked_add(columns)
            .is_none_or(|inputs| inputs > domain_size as usize)
        {
            return Err(commonware_codec::Error::Invalid(
                "VerifyingKey",
                "inputs exceed the domain",
            ));
        }
        let public_columns =
            Vec::<PublicColumn>::read_cfg(buf, &(RangeCfg::exact(columns), domain_size))?;
        Ok(Self {
            relation_digest,
            commitment_key_digest,
            domain_size,
            public_inputs,
            committed_inputs,
            public_columns,
            alpha_g: G1::read(buf)?,
            beta_g: G1::read(buf)?,
            delta_committed_h: G2::read(buf)?,
            delta_witness_h: G2::read(buf)?,
            tau_h: G2::read(buf)?,
            digest: [0u8; 32],
        }
        .finalize())
    }
}

/// The relation-specific key used to create proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKey {
    pub(crate) commitment_key: CommitmentKey,
    pub(crate) sigma_witness: Vec<G1>,
    pub(crate) sigma_mask_constant: G1,
    pub(crate) sigma_mask_linear: G1,
    pub(crate) sigma_quotient: Vec<G1>,
    pub(crate) sigma_a: Vec<G1>,
    pub(crate) sigma_r: Vec<G1>,
    pub(crate) verifying_key: VerifyingKey,
}

impl ProvingKey {
    /// Return the key for creating claims that this proving key can prove.
    pub const fn commitment_key(&self) -> &CommitmentKey {
        &self.commitment_key
    }

    /// Return the corresponding verification key.
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Witness basis entries that survive encoding.
    ///
    /// Zero witness columns (padding and unused variables) have identity basis
    /// points, which the point codec rejects, so they stay implicit.
    fn witness_entries(&self) -> impl Iterator<Item = (u32, &G1)> {
        self.sigma_witness
            .iter()
            .enumerate()
            .filter(|(_, point)| **point != G1::zero())
            .map(|(index, point)| (index as u32, point))
    }
}

impl Write for ProvingKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.verifying_key.write(buf);
        self.commitment_key.write(buf);
        self.witness_entries().count().write(buf);
        for (index, point) in self.witness_entries() {
            index.write(buf);
            point.write(buf);
        }
        self.sigma_mask_constant.write(buf);
        self.sigma_mask_linear.write(buf);
        self.sigma_quotient.write(buf);
        self.sigma_a.write(buf);
        self.sigma_r.write(buf);
    }
}

impl EncodeSize for ProvingKey {
    fn encode_size(&self) -> usize {
        let mut size = self.verifying_key.encode_size()
            + self.commitment_key.encode_size()
            + self.witness_entries().count().encode_size()
            + self.sigma_mask_constant.encode_size()
            + self.sigma_mask_linear.encode_size()
            + self.sigma_quotient.encode_size()
            + self.sigma_a.encode_size()
            + self.sigma_r.encode_size();
        for (index, point) in self.witness_entries() {
            size += index.encode_size() + point.encode_size();
        }
        size
    }
}

impl Read for ProvingKey {
    /// Bound on the number of ordinary public inputs of the embedded key.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let invalid =
            |message: &'static str| commonware_codec::Error::Invalid("ProvingKey", message);

        let verifying_key = VerifyingKey::read_cfg(buf, cfg)?;
        let commitment_key = CommitmentKey::read_cfg(
            buf,
            &RangeCfg::exact(verifying_key.committed_inputs as usize),
        )?;
        if commitment_key.relation_digest != verifying_key.relation_digest
            || verifying_key.commitment_key_digest != commitment_key.digest()
        {
            return Err(invalid("commitment key does not match the verifying key"));
        }

        // The verifying key bounds every remaining length: the assignment
        // holds the constant one, the inputs, and then the witness columns.
        let domain_size = verifying_key.domain_size as usize;
        let inputs = (verifying_key.public_inputs as usize)
            .checked_add(verifying_key.committed_inputs as usize)
            .and_then(|inputs| inputs.checked_add(1))
            .ok_or_else(|| invalid("inputs overflow"))?;
        let witness_len = domain_size
            .checked_sub(inputs)
            .ok_or_else(|| invalid("inputs exceed the domain"))?;
        let quotient_len = domain_size
            .checked_add(3)
            .ok_or_else(|| invalid("domain size overflow"))?;
        let opening_len = domain_size
            .checked_mul(2)
            .and_then(|len| len.checked_add(2))
            .ok_or_else(|| invalid("domain size overflow"))?;

        let entries = Vec::<(u32, G1)>::read_cfg(buf, &(RangeCfg::new(0..=witness_len), ((), ())))?;
        let sigma_mask_constant = G1::read(buf)?;
        let sigma_mask_linear = G1::read(buf)?;
        let sigma_quotient = Vec::<G1>::read_cfg(buf, &(RangeCfg::exact(quotient_len), ()))?;
        let sigma_a = Vec::<G1>::read_cfg(buf, &(RangeCfg::exact(domain_size + 1), ()))?;
        let sigma_r = Vec::<G1>::read_cfg(buf, &(RangeCfg::exact(opening_len), ()))?;

        // Materialize the witness basis only after every buffer-backed field
        // has been read, so a short input cannot force a large allocation.
        let mut sigma_witness = Vec::new();
        sigma_witness
            .try_reserve_exact(witness_len)
            .map_err(|_| invalid("witness basis too large"))?;
        sigma_witness.resize(witness_len, G1::zero());
        let mut last = None;
        for (index, point) in entries {
            if last.is_some_and(|last| index <= last) {
                return Err(invalid("witness indices must ascend"));
            }
            last = Some(index);
            *sigma_witness
                .get_mut(index as usize)
                .ok_or_else(|| invalid("witness index exceeds the domain"))? = point;
        }

        Ok(Self {
            commitment_key,
            sigma_witness,
            sigma_mask_constant,
            sigma_mask_linear,
            sigma_quotient,
            sigma_a,
            sigma_r,
            verifying_key,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary_impls {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    impl<'a> Arbitrary<'a> for Opening {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self(u.arbitrary()?))
        }
    }

    impl<'a> Arbitrary<'a> for ProvingKey {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                commitment_key: u.arbitrary()?,
                sigma_witness: u.arbitrary()?,
                sigma_mask_constant: u.arbitrary()?,
                sigma_mask_linear: u.arbitrary()?,
                sigma_quotient: u.arbitrary()?,
                sigma_a: u.arbitrary()?,
                sigma_r: u.arbitrary()?,
                verifying_key: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for CommitmentKey {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                relation_digest: u.arbitrary()?,
                basis: u.arbitrary()?,
                blinding: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for Claim {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                public_inputs: u.arbitrary()?,
                commitment: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for Proof {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                t: u.arbitrary()?,
                u: u.arbitrary()?,
                v_a: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for PublicColumn {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                a: u.arbitrary()?,
                b: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for VerifyingKey {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            // The digest is derived, never sampled.
            Ok(Self {
                relation_digest: u.arbitrary()?,
                commitment_key_digest: u.arbitrary()?,
                domain_size: u.arbitrary()?,
                public_inputs: u.arbitrary()?,
                committed_inputs: u.arbitrary()?,
                public_columns: u.arbitrary()?,
                alpha_g: u.arbitrary()?,
                beta_g: u.arbitrary()?,
                delta_committed_h: u.arbitrary()?,
                delta_witness_h: u.arbitrary()?,
                tau_h: u.arbitrary()?,
                digest: [0u8; 32],
            }
            .finalize())
        }
    }
}
