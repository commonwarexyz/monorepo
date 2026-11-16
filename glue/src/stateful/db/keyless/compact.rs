//! Compact [`Qmdb`] support for QMDB [`keyless`] databases.
//!
//! Compact databases retain only the current Merkle peaks. Batches support `append` and
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
        keyless,
        value::ValueEncoding,
    },
};

impl<F, E, V, H, S> Unmerkleized<Db<F, E, keyless::Operation<F, V>, H, S>>
where
    Db<F, E, keyless::Operation<F, V>, H, S>:
        Qmdb<Batch = UnmerkleizedBatch<F, H, keyless::Operation<F, V>, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    keyless::Operation<F, V>: CodecShared,
{
    /// Appends `value` to the batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}
