#[cfg(any(test, feature = "test-traits"))]
use crate::qmdb::any::traits::PersistableMutableLog;
use crate::{
    index::Unordered as Index,
    journal::contiguous::{Contiguous, Mutable, Reader},
    mmr::Location,
    qmdb::{
        any::{
            db::{AuthenticatedLog, Db},
            ValueEncoding,
        },
        build_snapshot_from_log,
        operation::{Committable, Key, Operation as OperationTrait},
        Error,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Unordered as Update, Unordered as Operation};

impl<
        E: Context,
        K: Key,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > Db<E, C, I, H, Update<K, V>>
where
    Operation<K, V>: Codec,
{
    /// Returns the value for `key` and its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(V::Value, Location)>, Error> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location> = self.snapshot.get(key).copied().collect();

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

impl<
        E: Context,
        C: Mutable<Item = O>,
        O: OperationTrait + Codec + Committable + Send + Sync,
        I: Index<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Db<E, C, I, H, U>
{
    /// Returns an [Db] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last operation is assumed to be a commit.
    pub(crate) async fn from_components(
        inactivity_floor_loc: Location,
        log: AuthenticatedLog<E, C, H>,
        mut snapshot: I,
    ) -> Result<Self, Error> {
        let (active_keys, last_commit_loc) = {
            let reader = log.reader().await;
            let active_keys =
                build_snapshot_from_log(inactivity_floor_loc, &reader, &mut snapshot, |_, _| {})
                    .await?;
            let last_commit_loc = Location::new(
                reader
                    .bounds()
                    .end
                    .checked_sub(1)
                    .expect("commit should exist"),
            );
            assert!(reader.read(*last_commit_loc).await?.is_commit());
            (active_keys, last_commit_loc)
        };

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit_loc,
            active_keys,
            _update: core::marker::PhantomData,
        })
    }
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [E, K, V, C, I, H] Db<E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
        Operation<K, V>: Codec,
        V::Value: Send + Sync,
    }
    Key = K, Value = V::Value, Digest = H::Digest
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_provable! {
    [E, K, V, C, I, H] Db<E, C, I, H, Update<K, V>>
    where {
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
        Operation<K, V>: Codec,
        V::Value: Send + Sync,
    }
    Operation = Operation<K, V>
}
