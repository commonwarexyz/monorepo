use crate::{
    adb::{
        any::{sync::Error, Any},
        operation::Operation,
    },
    mmr::verification::Proof,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64};

/// Result of a call to [Resolver::get_operations].
pub struct GetOperationsResult<H: Hasher, K: Array, V: Array> {
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
    /// `size` operations.
    fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<GetOperationsResult<H, K, V>, Error>>;
}

impl<E, K, V, H, T> Resolver<H, K, V> for &Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<H, K, V>, Error> {
        self.historical_proof(size, start_loc, max_ops.get())
            .await
            .map_err(Error::Adb)
            .map(|(proof, operations)| GetOperationsResult {
                proof,
                operations,
                // Result of proof verification isn't used by this implementation.
                success_tx: oneshot::channel().0,
            })
    }
}
