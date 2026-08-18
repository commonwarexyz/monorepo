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

    /// The generator committing each value slot, in slot order.
    ///
    /// Exposed so protocols can maintain commitments homomorphically outside
    /// the proof system (e.g. ledger balances in this key's basis).
    pub fn generators(&self) -> &[G1] {
        &self.basis
    }

    /// The generator committing the opening randomness.
    pub const fn blinding(&self) -> &G1 {
        &self.blinding
    }

    /// Commit to an ordered vector of field elements.
    ///
    /// The identity is a valid commitment (e.g. to all-zero values with zero
    /// randomness) and homomorphic arithmetic may produce it.
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
        Ok(G1::msm(&self.basis, values, strategy) + &(self.blinding * opening.scalar()))
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMMITMENT_KEY_DIGEST_NAMESPACE);
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }
}

/// Digest binding the ordered set of per-block commitment keys.
pub(crate) fn commitment_keys_digest(keys: &[CommitmentKey]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_KEY_DIGEST_NAMESPACE);
    hasher.update(&(keys.len() as u64).to_be_bytes());
    for key in keys {
        hasher.update(&key.digest());
    }
    *hasher.finalize().as_bytes()
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

/// Public inputs and the expected per-block committed-input commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// Public inputs in the relation's declared order.
    pub public_inputs: Vec<Scalar>,
    /// One commitment per committed-input block, in declared order.
    pub commitments: Vec<G1>,
}

/// Prover-only assignment and per-block commitment openings for a compiled
/// relation.
#[derive(Clone)]
pub struct Witness {
    pub(super) assignment: Assignment,
    pub(super) openings: Vec<Opening>,
}

impl Witness {
    /// Construct the public claim corresponding to this witness.
    pub fn claim(
        &self,
        commitment_keys: &[CommitmentKey],
        strategy: &impl Strategy,
    ) -> Result<Claim, Error> {
        if commitment_keys.len() != self.openings.len()
            || commitment_keys
                .iter()
                .any(|key| self.assignment.relation_digest() != key.relation_digest())
        {
            return Err(Error::RelationMismatch);
        }
        let mut commitments = Vec::with_capacity(commitment_keys.len());
        for ((key, values), opening) in commitment_keys
            .iter()
            .zip(self.assignment.block_values())
            .zip(&self.openings)
        {
            commitments.push(key.commit(values, opening, strategy)?);
        }
        Ok(Claim {
            public_inputs: self.assignment.public_inputs().to_vec(),
            commitments,
        })
    }

    pub(super) const fn assignment(&self) -> &Assignment {
        &self.assignment
    }

    pub(crate) fn openings(&self) -> &[Opening] {
        &self.openings
    }
}

impl Claim {
    /// Construct a public Pari claim.
    pub const fn new(public_inputs: Vec<Scalar>, commitments: Vec<G1>) -> Self {
        Self {
            public_inputs,
            commitments,
        }
    }
}

impl Write for Claim {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_inputs.write(buf);
        self.commitments.write(buf);
    }
}

impl EncodeSize for Claim {
    fn encode_size(&self) -> usize {
        self.public_inputs.encode_size() + self.commitments.encode_size()
    }
}

impl Read for Claim {
    /// Bounds on the number of public inputs and committed-input blocks.
    type Cfg = (RangeCfg<usize>, RangeCfg<usize>);

    fn read_cfg(
        buf: &mut impl Buf,
        (publics, blocks): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let public_inputs = Vec::<Scalar>::read_cfg(buf, &(*publics, ScalarReadCfg::AllowZero))?;
        // Block commitments may legitimately be the identity (e.g. homomorphic
        // commitments to zero), so bypass the identity-rejecting point codec.
        let count = usize::read_cfg(buf, blocks)?;
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count {
            commitments.push(G1::read_maybe_identity(buf)?);
        }
        Ok(Self {
            public_inputs,
            commitments,
        })
    }
}

/// A Pari proof consisting of two G1 elements and one scalar.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    pub(crate) blocks: Vec<u32>,
    pub(crate) public_columns: Vec<PublicColumn>,
    pub(crate) alpha_g: G1,
    pub(crate) beta_g: G1,
    pub(crate) delta_committed_h: Vec<G2>,
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
        self.blocks.write(buf);
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
            + self.blocks.encode_size()
            + self.public_columns.encode_size()
            + self.alpha_g.encode_size()
            + self.beta_g.encode_size()
            + self.delta_committed_h.encode_size()
            + self.delta_witness_h.encode_size()
            + self.tau_h.encode_size()
    }
}

impl Read for VerifyingKey {
    /// Bounds on the number of ordinary public inputs and committed-input
    /// blocks.
    type Cfg = (RangeCfg<usize>, RangeCfg<usize>);

    fn read_cfg(
        buf: &mut impl Buf,
        (publics_cfg, blocks_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let invalid =
            |message: &'static str| commonware_codec::Error::Invalid("VerifyingKey", message);

        let relation_digest = <[u8; 32]>::read(buf)?;
        let commitment_key_digest = <[u8; 32]>::read(buf)?;
        let domain_size = u32::read(buf)?;
        if !domain_size.is_power_of_two() {
            return Err(invalid("domain size must be a power of two"));
        }
        let public_inputs = u32::read(buf)?;
        if !publics_cfg.contains(&(public_inputs as usize)) {
            return Err(invalid("public input count out of range"));
        }
        let blocks = Vec::<u32>::read_cfg(buf, &(*blocks_cfg, ()))?;
        if blocks.is_empty() || blocks.contains(&0) {
            return Err(invalid("committed-input blocks must be non-empty"));
        }
        let columns = public_inputs as usize + 1;
        let committed = blocks.iter().map(|&size| u64::from(size)).sum::<u64>();
        if committed + columns as u64 > u64::from(domain_size) {
            return Err(invalid("inputs exceed the domain"));
        }
        let public_columns =
            Vec::<PublicColumn>::read_cfg(buf, &(RangeCfg::exact(columns), domain_size))?;
        let alpha_g = G1::read(buf)?;
        let beta_g = G1::read(buf)?;
        let delta_committed_h = Vec::<G2>::read_cfg(buf, &(RangeCfg::exact(blocks.len()), ()))?;
        Ok(Self {
            relation_digest,
            commitment_key_digest,
            domain_size,
            public_inputs,
            blocks,
            public_columns,
            alpha_g,
            beta_g,
            delta_committed_h,
            delta_witness_h: G2::read(buf)?,
            tau_h: G2::read(buf)?,
            digest: [0u8; 32],
        }
        .finalize())
    }
}

/// Toxic waste retained from a Pari setup.
///
/// Possession permits forging accepting proofs for arbitrary claims via
/// [`super::simulate`], defeating soundness entirely. It exists for
/// zero-knowledge testing and for load generation with simulated proofs;
/// production setups must use [`super::setup`], which never exposes it.
/// The scalars zeroize on drop.
#[derive(Clone)]
pub struct Trapdoor {
    pub(crate) alpha: Scalar,
    pub(crate) beta: Scalar,
    pub(crate) deltas: Vec<Scalar>,
    pub(crate) delta_witness: Scalar,
    pub(crate) tau: Scalar,
}

/// The relation-specific key used to create proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingKey {
    pub(crate) commitment_keys: Vec<CommitmentKey>,
    pub(crate) sigma_witness: Vec<G1>,
    pub(crate) sigma_mask_constant: G1,
    pub(crate) sigma_mask_linear: G1,
    pub(crate) sigma_quotient: Vec<G1>,
    pub(crate) sigma_a: Vec<G1>,
    pub(crate) sigma_r: Vec<G1>,
    pub(crate) verifying_key: VerifyingKey,
}

impl ProvingKey {
    /// Return the per-block keys for creating claims that this proving key
    /// can prove.
    pub fn commitment_keys(&self) -> &[CommitmentKey] {
        &self.commitment_keys
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
        self.commitment_keys.write(buf);
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
            + self.commitment_keys.encode_size()
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
    /// Bounds on the number of ordinary public inputs and committed-input
    /// blocks of the embedded key.
    type Cfg = (RangeCfg<usize>, RangeCfg<usize>);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let invalid =
            |message: &'static str| commonware_codec::Error::Invalid("ProvingKey", message);

        let verifying_key = VerifyingKey::read_cfg(buf, cfg)?;
        let mut commitment_keys = Vec::with_capacity(verifying_key.blocks.len());
        let keys_len = usize::read_cfg(buf, &RangeCfg::exact(verifying_key.blocks.len()))?;
        for &block in verifying_key.blocks.iter().take(keys_len) {
            commitment_keys.push(CommitmentKey::read_cfg(
                buf,
                &RangeCfg::exact(block as usize),
            )?);
        }
        if commitment_keys
            .iter()
            .any(|key| key.relation_digest != verifying_key.relation_digest)
            || verifying_key.commitment_key_digest != commitment_keys_digest(&commitment_keys)
        {
            return Err(invalid("commitment keys do not match the verifying key"));
        }

        // The verifying key bounds every remaining length: the assignment
        // holds the constant one, the inputs, and then the witness columns.
        let domain_size = verifying_key.domain_size as usize;
        let committed = verifying_key
            .blocks
            .iter()
            .map(|&size| size as usize)
            .try_fold(0usize, |sum, size| sum.checked_add(size))
            .ok_or_else(|| invalid("inputs overflow"))?;
        let inputs = (verifying_key.public_inputs as usize)
            .checked_add(committed)
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
            commitment_keys,
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
                commitment_keys: u.arbitrary()?,
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
                commitments: u.arbitrary()?,
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
                blocks: u.arbitrary()?,
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
