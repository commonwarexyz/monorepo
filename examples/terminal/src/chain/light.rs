//! Client-side verification of certified reads.
//!
//! The chain of checks mirrors the dkg probe's finalization discovery: the
//! finalization certificate is verified against the committee scheme, the
//! certified commitment must equal the digest of the served block bytes, the
//! block is decoded from exactly those bytes, and the presence or absence
//! proof is verified against the block's canonical state root. A monotonic
//! height gate ([`Latest`]) detects stale-certificate replays, and [`recent`]
//! turns the certified block timestamp into a recency verdict: a verified
//! read whose timestamp lags the local clock beyond a threshold is rejected
//! as stale, so one certified read from a single validator suffices.

use crate::chain::{
    query::{CertifiedRead, ReadProof, ReadRequest},
    state::Record,
    types::{Block, Qmdb},
};
use commonware_codec::Decode as _;
use commonware_consensus::{
    marshal::{core::Variant as _, standard::Standard},
    simplex::{scheme::CertificateVerifier, types::Finalization},
};
use commonware_cryptography::{Hasher as _, Sha256, certificate::Scheme, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;
use rand_core::CryptoRng;
use thiserror::Error;

/// A certified read that failed verification.
#[derive(Debug, Error)]
pub(crate) enum Error {
    /// A component of the response does not decode.
    #[error("response component does not decode: {0}")]
    Codec(#[from] commonware_codec::Error),
    /// The finalization certificate does not verify against the committee.
    #[error("finalization certificate is invalid")]
    Certificate,
    /// The certified commitment does not match the served block bytes.
    #[error("finalized commitment does not match the block bytes")]
    Commitment,
    /// The proof does not verify against the block's canonical state root.
    #[error("proof does not verify against the certified state root")]
    Proof,
    /// The verified height is below one this client already accepted.
    #[error("response height {height} is below the accepted height {accepted}")]
    Stale { height: u64, accepted: u64 },
    /// The verified timestamp lags the local clock beyond the recency bound.
    #[error("certified read is {lag} ms behind the local clock (recency bound {bound} ms)")]
    Lagging { lag: u64, bound: u64 },
}

/// One verified certified read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Verified {
    /// Height of the finalized block the response was proven against.
    pub(crate) height: u64,
    /// Certified timestamp of that block (milliseconds since the Unix
    /// epoch), covered by the block digest and so by the certificate.
    pub(crate) timestamp: u64,
    /// The verified value, or `None` for a verified absence.
    pub(crate) record: Option<Record>,
}

/// Verifies one certified read against the committee `scheme`.
///
/// `E` names the caller's runtime context type. It only selects the storage
/// generics of the proof verifier and no context value is needed.
pub(crate) fn verify_read<E, S>(
    rng: &mut impl CryptoRng,
    scheme: &S,
    request: &ReadRequest,
    response: &CertifiedRead,
) -> Result<Verified, Error>
where
    E: StorageContext + Spawner,
    S: Scheme + CertificateVerifier<Digest>,
{
    // The certificate authenticates the commitment at the certified height.
    let finalization = Finalization::<S, Digest>::decode_cfg(
        response.finalization.clone(),
        &scheme.certificate_codec_config(),
    )?;
    if !finalization.verify(rng, scheme, &Sequential) {
        return Err(Error::Certificate);
    }

    // The commitment must be the digest of exactly the served block bytes,
    // so re-hashing the bytes before decoding pins the block to the
    // certificate.
    let digest = Sha256::hash(&[&response.block]);
    if Standard::<Block>::commitment_to_inner(finalization.proposal.payload) != digest {
        return Err(Error::Commitment);
    }
    let block = Block::decode_cfg(response.block.clone(), &())?;

    // The proof verifies against the block's committed canonical root.
    let key = request.key();
    let record = match &response.proof {
        ReadProof::Present { record, proof } => {
            if !Qmdb::<E>::verify_key_value_proof(key, record.clone(), proof, &block.state_root) {
                return Err(Error::Proof);
            }
            Some(record.clone())
        }
        ReadProof::Absent { proof } => {
            if !Qmdb::<E>::verify_exclusion_proof(&key, proof, &block.state_root) {
                return Err(Error::Proof);
            }
            None
        }
    };
    Ok(Verified {
        height: block.height.get(),
        timestamp: block.timestamp,
        record,
    })
}

/// Client-side monotonic height gate.
///
/// A certified response is authentic for its height even when it is old, so
/// a replayed stale certificate verifies. Tracking the highest accepted
/// height turns such replays into typed errors.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Latest {
    accepted: Option<u64>,
}

impl Latest {
    /// Accepts `height` if it does not regress below an accepted height.
    pub(crate) fn observe(&mut self, height: u64) -> Result<(), Error> {
        if let Some(accepted) = self.accepted
            && height < accepted
        {
            return Err(Error::Stale { height, accepted });
        }
        self.accepted = Some(
            self.accepted
                .map_or(height, |accepted| accepted.max(height)),
        );
        Ok(())
    }
}

/// Recency gate over one verified read.
///
/// Verification proved the timestamp is exactly what a finalized block
/// committed, so comparing it to `now` (the local clock in milliseconds
/// since the Unix epoch) bounds how old the served tip is: a lag over
/// `bound` milliseconds rejects the read as stale, a lag exactly at the
/// bound passes, and a timestamp ahead of the local clock (bounded drift)
/// never reads as stale.
pub(crate) const fn recent(verified: &Verified, now: u64, bound: u64) -> Result<(), Error> {
    let lag = now.saturating_sub(verified.timestamp);
    if lag > bound {
        return Err(Error::Lagging { lag, bound });
    }
    Ok(())
}
