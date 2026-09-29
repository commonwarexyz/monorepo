//! Compact [`ManagedDb`](crate::stateful::db::ManagedDb) support for QMDB
//! [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! Compact databases retain only the current Merkle peaks. Batches support `append` and
//! merkleization but no historical reads. The shared implementation lives in
//! [`crate::stateful::db::compact`].

use crate::stateful::db::compact::CompactUnmerkleized;
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    merkle::Family,
    qmdb::{any::value::ValueEncoding, keyless::Operation},
};

impl<F, E, V, H, S> CompactUnmerkleized<F, E, Operation<F, V>, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: CodecShared,
{
    /// Appends `value` to the batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}
