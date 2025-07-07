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
    /// Request proof and operations starting from the given index
    #[allow(clippy::type_complexity)]
    fn get_proof(
        &mut self,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error>>;
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
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.proof(start_index, max_ops.get())
            .await
            .map_err(Error::GetProofFailed)
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
    async fn get_proof(
        &mut self,
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.proof(start_index, max_ops.get())
            .await
            .map_err(Error::GetProofFailed)
    }
}
