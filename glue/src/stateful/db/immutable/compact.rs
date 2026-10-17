//! Compact [`ManagedDb`](crate::stateful::db::ManagedDb) support for QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! Compact databases retain only the current Merkle peaks. Batches support `set` and
//! merkleization but no historical reads. The shared implementation lives in
//! [`crate::stateful::db::compact`].

use crate::stateful::db::compact::CompactUnmerkleized;
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    merkle::Family,
    qmdb::{any::value::ValueEncoding, immutable::Operation, operation::Key},
};

impl<F, E, K, V, H, S> CompactUnmerkleized<F, E, Operation<F, K, V>, H, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: CodecShared,
{
    /// Sets `key` to `value` in the batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}
