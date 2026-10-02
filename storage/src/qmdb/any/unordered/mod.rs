use crate::{
    Context,
    index::Unordered as Index,
    journal::contiguous::Contiguous,
    merkle::{Family, Location},
    qmdb::{
        any::{ValueEncoding, db::Db},
        operation::Key,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use core::future::Future;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{Unordered as Operation, update::Unordered as Update};

impl<
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<F, K, V>>,
    I: Index<Value = Location<F>>,
    H: Hasher,
    const N: usize,
    S: Strategy,
> Db<F, E, C, I, H, Update<K, V>, N, S>
where
    Operation<F, K, V>: Codec,
{
    /// Returns the value for `key` and its location, or None if the key is not active.
    // Explicit Send avoids the borrowed-iterator inference limitation (rust-lang/rust#100013).
    #[allow(clippy::manual_async_fn, clippy::type_complexity)]
    pub(crate) fn get_with_loc(
        &self,
        key: &K,
    ) -> impl Future<Output = Result<Option<(V::Value, Location<F>)>, crate::qmdb::Error<F>>> + Send
    {
        async move {
            // Resolve translated-key collisions before returning a value and its location.
            for loc in self.snapshot.get(key).copied() {
                let op = self.log.read(*loc).await?;
                match op {
                    Operation::Update(Update(k, value)) => {
                        if k == *key {
                            return Ok(Some((value, loc)));
                        }
                    }
                    _ => unreachable!("location {loc} does not reference update operation"),
                }
            }

            Ok(None)
        }
    }
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, C, I, H, const N: usize, S] Db<F, E, C, I, H, Update<K, V>, N, S>
    where {
        F: crate::merkle::Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: crate::journal::authenticated::Prunable<Item = Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + Send + Sync + 'static,
        H: Hasher,
        S: Strategy,
        Operation<F, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = F, Key = K, Value = V::Value, Digest = H::Digest
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_provable! {
    [F, E, K, V, C, I, H, const N: usize, S] Db<F, E, C, I, H, Update<K, V>, N, S>
    where {
        F: crate::merkle::Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: crate::journal::authenticated::Prunable<Item = Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + Send + Sync + 'static,
        H: Hasher,
        S: Strategy,
        Operation<F, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = F, Operation = Operation<F, K, V>
}
