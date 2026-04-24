#[cfg(any(test, feature = "test-traits"))]
use crate::qmdb::any::traits::PersistableMutableLog;
use crate::{
    index::Unordered as Index,
    journal::contiguous::{Contiguous, Reader},
    merkle::{Family, Location},
    qmdb::{
        any::{db::Db, ValueEncoding},
        operation::Key,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Unordered as Update, Unordered as Operation};

impl<
        F: Family,
        E: Context,
        K: Key,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<F, K, V>>,
        I: Index<Value = Location<F>>,
        H: Hasher,
    > Db<F, E, C, I, H, Update<K, V>>
where
    Operation<F, K, V>: Codec,
{
    /// Returns the value for `key` and its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(V::Value, Location<F>)>, crate::qmdb::Error<F>> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = self.snapshot.get(key).copied().collect();

        let reader = self.log.reader().await;
        for loc in locs {
            let op = reader.read(*loc).await?;
            match &op {
                Operation::Update(Update(k, value)) => {
                    if k == key {
                        return Ok(Some((value.clone(), loc)));
                    }
                }
                _ => unreachable!("location {loc} does not reference update operation"),
            }
        }

        Ok(None)
    }
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [E, K, V, C, I, H] Db<crate::merkle::mmr::Family, E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<crate::merkle::mmr::Family, K, V>>,
        I: Index<Value = crate::mmr::Location> + Send + Sync + 'static,
        H: Hasher,
        Operation<crate::merkle::mmr::Family, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = crate::merkle::mmr::Family, Key = K, Value = V::Value, Digest = H::Digest
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_provable! {
    [E, K, V, C, I, H] Db<crate::merkle::mmr::Family, E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<crate::merkle::mmr::Family, K, V>>,
        I: Index<Value = crate::mmr::Location> + Send + Sync + 'static,
        H: Hasher,
        Operation<crate::merkle::mmr::Family, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = crate::merkle::mmr::Family, Operation = Operation<crate::merkle::mmr::Family, K, V>
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [E, K, V, C, I, H] Db<crate::merkle::mmb::Family, E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<crate::merkle::mmb::Family, K, V>>,
        I: Index<Value = crate::merkle::Location<crate::merkle::mmb::Family>> + Send + Sync + 'static,
        H: Hasher,
        Operation<crate::merkle::mmb::Family, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = crate::merkle::mmb::Family, Key = K, Value = V::Value, Digest = H::Digest
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_provable! {
    [E, K, V, C, I, H] Db<crate::merkle::mmb::Family, E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<crate::merkle::mmb::Family, K, V>>,
        I: Index<Value = crate::merkle::Location<crate::merkle::mmb::Family>> + Send + Sync + 'static,
        H: Hasher,
        Operation<crate::merkle::mmb::Family, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = crate::merkle::mmb::Family, Operation = Operation<crate::merkle::mmb::Family, K, V>
}
