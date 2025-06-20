use crate::Error;
use commonware_cryptography::Hasher;
use commonware_storage::{adb::operation::Operation, mmr::verification::Proof};
use commonware_utils::Array;

/// Trait for network communication with the sync server
pub trait Resolver<H: Hasher, K: Array, V: Array> {
    /// Request the current tip (latest index and root hash) from the server
    #[allow(async_fn_in_trait)]
    async fn get_tip(&mut self) -> Result<(u64, H::Digest), Error>;

    /// Request proof and operations starting from the given index
    #[allow(async_fn_in_trait)]
    async fn get_proof(
        &mut self,
        start_index: u64,
        max_ops: u64,
    ) -> Result<(Proof<H>, Vec<Operation<K, V>>), Error>;
}
