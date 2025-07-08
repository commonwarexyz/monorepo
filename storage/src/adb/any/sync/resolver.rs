use crate::{
    adb::{
        any::{sync::Error, Any},
        operation::Operation,
    },
    index::Translator,
    mmr::verification::Proof,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64};

/// Result of a call to [Resolver::get_proof].
pub struct GetProofResult<H: Hasher, K: Array, V: Array> {
    /// Proof that the operations are valid.
    pub proof: Proof<H::Digest>,
    /// The operations in the requested range.
    pub operations: Vec<Operation<K, V>>,
    /// A channel to send the result of the proof verification.
    /// Caller should send `true` if the proof is valid, `false` otherwise.
    /// Caller should ignore error if the channel is closed.
    pub success_tx: oneshot::Sender<bool>,
}

/// Trait for network communication with the sync server
pub trait Resolver<H: Hasher, K: Array, V: Array> {
    /// Request proof and operations starting from the given index into an [Any] database's
    /// operation log. Returns at most `max_ops` operations.
    // TODO allow for fetching historical proofs; https://github.com/commonwarexyz/monorepo/issues/1216
    fn get_proof(
        &self,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<GetProofResult<H, K, V>, Error>>;
}

impl<E, K, V, H, T> Resolver<H, K, V> for &Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_proof(
        &self,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetProofResult<H, K, V>, Error> {
        self.proof(start_index, max_ops.get())
            .await
            .map_err(Error::GetProofFailed)
            .map(|(proof, operations)| GetProofResult {
                proof,
                operations,
                // Result of proof verification isn't used by this implementation.
                success_tx: oneshot::channel().0,
            })
    }
}
