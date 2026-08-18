//! The [`crate::payments::Backend`] implementation over native Pari.
//!
//! Balances are committed in the transfer relation's payment basis (committed
//! block 1). A transfer proves that the amount and the sender's remaining
//! balance are each in `[0, 2^64)` and that their `theta`-aggregate opens the
//! ledger's aggregate commitment, where the aggregate is the verifier-derived
//! `ledger[0] + theta * ledger[1]`. Fund is proof-free (a deterministic
//! zero-blinding commitment) and burn reuses the transfer relation with a
//! public amount.

use super::range::{self, TRANSFER_BATCH};
use crate::payments::{Backend, Commitment, Opening};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::group::{G1, Scalar},
    transcript::{Transcript, Version},
    zk::pari::{self, BatchEntry, CommitmentTerm, InputLayout, ProvingKey, Relation, VerifyingKey},
};
use commonware_math::algebra::{Additive, Random};
use commonware_parallel::{Sequential, Strategy};
use core::convert::Infallible;
use rand_core::CryptoRng;

/// Transcript namespace for deriving the aggregation challenge `theta`.
const THETA_NAMESPACE: &[u8] = b"_COMMONWARE_PRIVACY_ZKPARI_THETA";
/// Transcript namespace for the transfer proof's statement binding.
pub(super) const PROOF_NAMESPACE: &[u8] = b"_COMMONWARE_PRIVACY_ZKPARI_PROOF";

/// A homomorphic commitment to a balance in the payment basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaymentCommitment(pub G1);

impl core::ops::Add<&Self> for PaymentCommitment {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl core::ops::Sub<&Self> for PaymentCommitment {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - &rhs.0)
    }
}

impl Commitment for PaymentCommitment {
    fn zero() -> Self {
        Self(G1::zero())
    }
}

/// The opening of a [`PaymentCommitment`]: a value and its blinding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentOpening {
    pub value: u64,
    pub blind: Scalar,
}

impl core::ops::Add<&Self> for PaymentOpening {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_add(rhs.value),
            blind: self.blind + &rhs.blind,
        }
    }
}

impl core::ops::Sub<&Self> for PaymentOpening {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            value: self
                .value
                .checked_sub(rhs.value)
                .expect("payment debit must not underflow"),
            blind: self.blind - &rhs.blind,
        }
    }
}

impl Opening for PaymentOpening {
    fn zero() -> Self {
        Self {
            value: 0,
            blind: Scalar::zero(),
        }
    }

    fn value(&self) -> u64 {
        self.value
    }
}

/// A transfer or burn proof: the fresh block-0 commitment plus the Pari proof.
///
/// The block-1 (aggregate) commitment is recomputed by the verifier from the
/// ledger, so it is not carried on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RangeProof {
    pub c_hat: G1,
    pub proof: pari::Proof,
}

/// A transfer proof.
pub type TransferProof = RangeProof;
/// A burn proof.
pub type BurnProof = RangeProof;

/// Public parameters: the transfer relation and its keys.
pub struct PaymentsParams {
    relation: Relation,
    layout: InputLayout,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
}

impl PaymentsParams {
    /// The value generator of the payment basis (committed block 1).
    fn value_base(&self) -> G1 {
        self.proving_key.commitment_keys()[range::PAYMENT_BLOCK].generators()[0]
    }

    /// The blinding generator of the payment basis.
    fn blind_base(&self) -> G1 {
        *self.proving_key.commitment_keys()[range::PAYMENT_BLOCK].blinding()
    }

    /// Commit a value with the given blinding in the payment basis.
    fn commit(&self, value: u64, blind: &Scalar) -> G1 {
        self.value_base() * &Scalar::from(value) + &(self.blind_base() * blind)
    }
}

/// The native-Pari private-payments backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkPariBackend;

impl ZkPariBackend {
    /// Derive parameters and the setup trapdoor from a seed.
    ///
    /// # Security
    ///
    /// The trapdoor is toxic waste; anyone holding it can forge accepting
    /// transfer proofs. It exists only for load generation and testing.
    #[cfg(feature = "simulator")]
    pub fn setup_with_trapdoor(seed: &[u8; 32]) -> (PaymentsParams, pari::Trapdoor) {
        setup_with_trapdoor(seed)
    }
}

/// Derive the aggregation challenge from the verifying key and the ledger.
pub(super) fn derive_theta(verifying_key: &VerifyingKey, ledger: &[G1; TRANSFER_BATCH]) -> Scalar {
    let mut transcript = Transcript::new(THETA_NAMESPACE, Version::V1);
    transcript.commit(verifying_key.encode());
    for point in ledger {
        transcript.commit(point.encode());
    }
    Scalar::random(transcript.noise(b"theta"))
}

/// Bind the transfer statement into a proof transcript, matching prover and
/// verifier.
pub(super) fn bind_statement(
    namespace: &'static [u8],
    theta: &Scalar,
    c_hat: &G1,
    ledger: &[G1; TRANSFER_BATCH],
) -> Transcript {
    let mut transcript = Transcript::new(namespace, Version::V1);
    transcript.commit(theta.encode());
    transcript.commit(c_hat.encode());
    for point in ledger {
        transcript.commit(point.encode());
    }
    transcript
}

/// Prove a range statement over `[v1, v2]` with the given ledger points.
fn prove_range(
    params: &PaymentsParams,
    values: [u64; TRANSFER_BATCH],
    ledger: [G1; TRANSFER_BATCH],
    amount_blind: &Scalar,
    remaining_blind: &Scalar,
    rng: &mut impl CryptoRng,
) -> RangeProof {
    let theta = derive_theta(&params.verifying_key, &ledger);
    let block0_blind = pari::Opening::random(rng);
    // com_theta = ledger[0] + theta * ledger[1] commits v1 + theta * v2 with
    // opening blind0 + theta * blind1.
    let aggregate_blind = amount_blind.clone() + &(theta.clone() * remaining_blind);
    let openings = vec![block0_blind, pari::Opening::new(aggregate_blind)];

    let witness = range::assignment(&params.relation, &params.layout, values, &theta, openings);
    let claim = witness
        .claim(params.proving_key.commitment_keys(), &Sequential)
        .expect("transfer claim is well-formed");
    let c_hat = claim.commitments[0];

    let mut transcript = bind_statement(PROOF_NAMESPACE, &theta, &c_hat, &ledger);
    let proof = pari::prove_prebound(
        rng,
        &mut transcript,
        &params.proving_key,
        &params.relation,
        &claim,
        &witness,
        &Sequential,
    )
    .expect("valid transfer witness proves");
    RangeProof { c_hat, proof }
}

/// A prepared claim for batched verification of one range proof.
fn range_entry(
    verifying_key: &VerifyingKey,
    ledger: [G1; TRANSFER_BATCH],
    proof: &RangeProof,
) -> (Transcript, BatchEntry) {
    let theta = derive_theta(verifying_key, &ledger);
    let transcript = bind_statement(PROOF_NAMESPACE, &theta, &proof.c_hat, &ledger);
    let entry = BatchEntry {
        public_inputs: vec![theta.clone()],
        commitments: vec![
            vec![CommitmentTerm::Point(proof.c_hat)],
            vec![
                CommitmentTerm::Point(ledger[0]),
                CommitmentTerm::Weighted(ledger[1], theta),
            ],
        ],
        proof: proof.proof.clone(),
    };
    (transcript, entry)
}

impl Backend for ZkPariBackend {
    type Params = PaymentsParams;
    type Commitment = PaymentCommitment;
    type Opening = PaymentOpening;
    type FundProof = ();
    type TransferProof = TransferProof;
    type BurnProof = BurnProof;
    #[cfg(feature = "simulator")]
    type Trapdoor = pari::Trapdoor;
    type SetupInput = [u8; 32];
    type SetupError = Infallible;

    fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError> {
        Ok(setup_params(input))
    }

    fn commit_public(params: &Self::Params, value: u64) -> (Self::Commitment, Self::Opening) {
        (
            PaymentCommitment(params.commit(value, &Scalar::zero())),
            PaymentOpening {
                value,
                blind: Scalar::zero(),
            },
        )
    }

    fn fund(
        params: &Self::Params,
        value: u64,
        _rng: &mut impl CryptoRng,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
        let (commitment, opening) = Self::commit_public(params, value);
        (commitment, opening, ())
    }

    fn transfer(
        params: &Self::Params,
        input_commitment: &Self::Commitment,
        input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRng,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
        let amount_blind = Scalar::random(&mut *rng);
        let amount_commitment = PaymentCommitment(params.commit(amount, &amount_blind));
        let amount_opening = PaymentOpening {
            value: amount,
            blind: amount_blind.clone(),
        };
        // The remaining balance opens `input - amount`; the subtraction panics
        // on overspend before any proving happens.
        let remaining = input_opening.clone() - &amount_opening;
        let ledger = [
            amount_commitment.0,
            (*input_commitment - &amount_commitment).0,
        ];
        let proof = prove_range(
            params,
            [amount, remaining.value],
            ledger,
            &amount_blind,
            &remaining.blind,
            rng,
        );
        (amount_commitment, amount_opening, proof)
    }

    #[cfg(feature = "simulator")]
    fn simulated_transfer_proof(
        params: &Self::Params,
        trapdoor: &Self::Trapdoor,
        input_commitment: &Self::Commitment,
        amount_commitment: &Self::Commitment,
        rng: &mut impl CryptoRng,
    ) -> Self::TransferProof {
        super::simulator::simulate_transfer(
            params,
            trapdoor,
            input_commitment,
            amount_commitment,
            rng,
        )
    }

    fn burn(
        params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRng,
    ) -> Self::BurnProof {
        // The burned amount is public: prove only that the remainder is in
        // range and opens `sender - commit_public(amount)`. Block 1 is the
        // identity (a commitment to zero), so theta drops out of the aggregate.
        let public = params.commit(amount, &Scalar::zero());
        let remaining_commitment = PaymentCommitment(commitment.0 - &public);
        let remaining = opening
            .value
            .checked_sub(amount)
            .expect("burn amount must not exceed the committed balance");
        let ledger = [remaining_commitment.0, G1::zero()];
        prove_range(
            params,
            [remaining, 0],
            ledger,
            &opening.blind,
            &Scalar::zero(),
            rng,
        )
    }

    fn batch_verify(
        params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        rng: &mut impl CryptoRng,
    ) -> bool {
        Self::batch_verify_with_strategy(&Sequential, params, funds, transfers, burns, rng)
    }

    fn batch_verify_with_strategy(
        strategy: &impl Strategy,
        params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        rng: &mut impl CryptoRng,
    ) -> bool {
        // Funds carry no proof; each commitment must be the deterministic
        // public commitment to its value.
        for (value, commitment, ()) in funds {
            if commitment.0 != params.commit(*value, &Scalar::zero()) {
                return false;
            }
        }

        let mut transcripts = Vec::with_capacity(transfers.len() + burns.len());
        let mut entries = Vec::with_capacity(transfers.len() + burns.len());
        for (sender, amount_commitment, proof) in transfers {
            let ledger = [amount_commitment.0, (*sender - amount_commitment).0];
            let (transcript, entry) = range_entry(&params.verifying_key, ledger, proof);
            transcripts.push(transcript);
            entries.push(entry);
        }
        for (sender, amount, proof) in burns {
            let public = params.commit(*amount, &Scalar::zero());
            let ledger = [(*sender - &PaymentCommitment(public)).0, G1::zero()];
            let (transcript, entry) = range_entry(&params.verifying_key, ledger, proof);
            transcripts.push(transcript);
            entries.push(entry);
        }

        pari::batch_verify_prebound(
            rng,
            &mut transcripts,
            &params.verifying_key,
            &entries,
            strategy,
        )
    }
}

/// Derive parameters from a seed (transparent setup).
fn setup_params(seed: &[u8; 32]) -> PaymentsParams {
    setup_with_trapdoor(seed).0
}

/// Derive parameters and the setup trapdoor from a seed.
fn setup_with_trapdoor(seed: &[u8; 32]) -> (PaymentsParams, pari::Trapdoor) {
    let (relation, layout) = range::relation();
    let mut transcript = Transcript::new(b"_COMMONWARE_PRIVACY_ZKPARI_SETUP", Version::V1);
    transcript.commit(seed.as_slice());
    let mut rng = transcript.noise(b"setup");
    let (proving_key, verifying_key, trapdoor) =
        pari::setup_with_trapdoor(&relation, &mut rng, &Sequential).expect("setup succeeds");
    (
        PaymentsParams {
            relation,
            layout,
            proving_key,
            verifying_key,
        },
        trapdoor,
    )
}

impl PaymentsParams {
    /// The verifying key, for constructing verification inputs.
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[cfg(feature = "codec")]
mod codec {
    use super::{PaymentCommitment, PaymentOpening, RangeProof};
    use bytes::{Buf, BufMut};
    use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
    use commonware_cryptography::bls12381::primitives::group::{G1, Scalar, ScalarReadCfg};

    impl FixedSize for PaymentCommitment {
        const SIZE: usize = G1::SIZE;
    }

    impl Write for PaymentCommitment {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for PaymentCommitment {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            // Payment commitments may legitimately be the group identity.
            Ok(Self(G1::read_maybe_identity(buf)?))
        }
    }

    impl FixedSize for PaymentOpening {
        const SIZE: usize = u64::SIZE + Scalar::SIZE;
    }

    impl Write for PaymentOpening {
        fn write(&self, buf: &mut impl BufMut) {
            self.value.write(buf);
            self.blind.write(buf);
        }
    }

    impl Read for PaymentOpening {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                value: u64::read(buf)?,
                blind: Scalar::read_cfg(buf, &ScalarReadCfg::AllowZero)?,
            })
        }
    }

    impl FixedSize for RangeProof {
        // c_hat plus the Pari proof (two G1 and one scalar).
        const SIZE: usize = G1::SIZE + 2 * G1::SIZE + Scalar::SIZE;
    }

    impl Write for RangeProof {
        fn write(&self, buf: &mut impl BufMut) {
            self.c_hat.write(buf);
            self.proof.write(buf);
        }
    }

    impl Read for RangeProof {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                c_hat: G1::read_maybe_identity(buf)?,
                proof: commonware_cryptography::zk::pari::Proof::read_cfg(buf, &())?,
            })
        }
    }
}
