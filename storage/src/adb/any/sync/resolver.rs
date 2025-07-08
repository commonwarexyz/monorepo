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
    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `db_size` operations.
    fn get_operations(
        &mut self,
        db_size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<GetProofResult<H, K, V>, Error>>;
}

impl<E, K, V, H, T> Resolver<H, K, V> for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_operations(
        &mut self,
        db_size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetProofResult<H, K, V>, Error> {
        self.historical_proof(db_size, start_loc, max_ops.get())
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

impl<E, K, V, H, T> Resolver<H, K, V> for &mut Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_operations(
        &mut self,
        db_size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetProofResult<H, K, V>, Error> {
        self.historical_proof(db_size, start_loc, max_ops.get())
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
