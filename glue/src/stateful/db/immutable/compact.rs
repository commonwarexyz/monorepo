//! Compact [`Qmdb`] support for QMDB [`immutable`] databases.
//!
//! Compact databases retain only the current Merkle peaks. Batches support `set` and
//! merkleization but no historical reads. The shared implementation lives in
//! [`crate::stateful::db::compact`].

use crate::stateful::db::qmdb::{Qmdb, Unmerkleized};
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    merkle::Family,
    qmdb::{
        compact::{Db, UnmerkleizedBatch},
        immutable,
        operation::Key,
        value::ValueEncoding,
    },
};

impl<F, E, K, V, H, S> Unmerkleized<Db<F, E, immutable::Operation<F, K, V>, H, S>>
where
    Db<F, E, immutable::Operation<F, K, V>, H, S>:
        Qmdb<Batch = UnmerkleizedBatch<F, H, immutable::Operation<F, K, V>, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    immutable::Operation<F, K, V>: CodecShared,
{
    /// Sets `key` to `value` in the batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}
