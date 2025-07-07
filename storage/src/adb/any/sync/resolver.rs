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
use std::{future::Future, num::NonZeroU64};

/// Trait for network communication with the sync server
pub trait Resolver<H: Hasher, K: Array, V: Array> {
    /// Request a proof for a range of operations at a specific historical database size.
    ///
    /// # Arguments
    /// * `db_size`: The total number of operations in the historical database state
    ///   for which the proof should be generated. i.e. The number of operations in the
    ///   database at the state we are trying to sync to.
    /// * `start_index`: The starting operation index for the proof.
    /// * `max_ops`: The maximum number of operations to include in the proof.
    #[allow(clippy::type_complexity)]
    fn get_proof(
        &mut self,
        db_size: u64,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error>>;

    /// Notify the resolver that the proof verification failed.
    /// A server implementation could decide to connect to a different server
    /// in response to several failed attempts, for example.
    fn notify_failure(&mut self);
}

impl<E, K, V, H, T> Resolver<H, K, V> for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_proof(
        &mut self,
        db_size: u64,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(db_size, start_index, max_ops.get())
            .await
            .map_err(Error::GetProofFailed)
    }

    fn notify_failure(&mut self) {}
}

impl<E, K, V, H, T> Resolver<H, K, V> for &mut Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    async fn get_proof(
        &mut self,
        db_size: u64,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(db_size, start_index, max_ops.get())
            .await
            .map_err(Error::GetProofFailed)
    }

    fn notify_failure(&mut self) {}
}
