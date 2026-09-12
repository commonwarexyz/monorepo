//! Complete-dealing validation and exact-quorum header certification.

mod certificate;
use crate::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    posted,
    qmdb::State,
    transition::{self, CloseContext, OperatorKey, PreparedClose},
};
use bytes::Bytes;
pub use certificate::{
    COMMITTEE_HASH_NAMESPACE, Committee, Error as AdmissionError, HEADER_NAMESPACE,
    MAX_COMMITTEE_SIZE, bls12381,
};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::Context;
use rand_core::CryptoRng;

/// One validator attestation over a full-close header.
pub type Vote = bls12381::Vote;

/// Decodes and authenticates a full proposal before signing its header.
///
/// The returned candidate owns the complete claim evidence and incremental state batch.
/// Applications must durably retain both before publishing the vote. Signing does not
/// install the candidate or admit it to settlement.
#[allow(clippy::too_many_arguments)]
pub async fn seal<H, P, D, E, S, B, R>(
    scheme: &bls12381::Scheme,
    state: &State<E, H, S>,
    context: &CloseContext<P, D>,
    operator: &OperatorKey,
    deposits: &DepositBatch<P>,
    withdrawals: &WithdrawalBatch<P, D>,
    encoded: Bytes,
    rng: &mut R,
    strategy: &S,
) -> Result<(Vote, PreparedClose<P, D, S>), AdmissionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
    E: Context + Spawner,
    S: Strategy,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
{
    if scheme.me().is_none() {
        return Err(AdmissionError::SigningUnavailable);
    }
    if scheme.committee().commitment::<H>() != *context.committee() {
        return Err(AdmissionError::CommitteeMismatch);
    }
    let dealing = posted::decode(encoded, context).map_err(|_| AdmissionError::InvalidDealing)?;
    let prepared = transition::validate_close_with_strategy::<H, P, D, E, S, B, R>(
        state,
        context,
        operator,
        deposits,
        withdrawals,
        dealing,
        rng,
        strategy,
    )
    .await
    .map_err(|_| AdmissionError::InvalidDealing)?;
    let vote = scheme.sign(&prepared.close().header)?;
    Ok((vote, prepared))
}
