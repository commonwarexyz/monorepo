#[cfg(any(test, feature = "test-traits"))]
use crate::qmdb::any::traits::PersistableMutableLog;
use crate::{
    index::Ordered as Index,
    journal::contiguous::{Contiguous, Reader},
    merkle::{Family, Location},
    qmdb::{
        any::{db::Db, ValueEncoding},
        operation::{Key, Operation as OperationTrait},
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use futures::{
    future::try_join_all,
    stream::{self, Stream},
};

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Ordered as Update, Ordered as Operation};

/// Type alias for a location and its associated key data.
type LocatedKey<F, K, V> = Option<(Location<F>, Update<K, V>)>;

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
    async fn get_update_op(
        reader: &impl Reader<Item = Operation<F, K, V>>,
        loc: Location<F>,
    ) -> Result<Update<K, V>, crate::qmdb::Error<F>> {
        match reader.read(*loc).await? {
            Operation::Update(key_data) => Ok(key_data),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }

    /// Whether the span defined by `span_start` and `span_end` contains `key`.
    pub fn span_contains(span_start: &K, span_end: &K, key: &K) -> bool {
        if span_start >= span_end {
            // cyclic span case
            if key >= span_start || key < span_end {
                return true;
            }
        } else {
            // normal span case
            if key >= span_start && key < span_end {
                return true;
            }
        }

        false
    }

    /// Find the span produced by the provided locations that contains `key`, if any.
    async fn find_span(
        &self,
        locs: impl IntoIterator<Item = Location<F>>,
        key: &K,
    ) -> Result<LocatedKey<F, K, V>, crate::qmdb::Error<F>> {
        let reader = self.log.reader().await;
        for loc in locs {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update_op(&reader, loc).await?;
            if Self::span_contains(&data.key, &data.next_key, key) {
                return Ok(Some((loc, data)));
            }
        }

        Ok(None)
    }

    /// Get the operation that defines the span whose range contains `key`, or None if the DB is
    /// empty.
    pub async fn get_span(&self, key: &K) -> Result<LocatedKey<F, K, V>, crate::qmdb::Error<F>> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = self.snapshot.get(key).copied().collect();
        let span = self.find_span(locs, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let Some((iter, _)) = self.snapshot.prev_translated_key(key) else {
            // DB is empty.
            return Ok(None);
        };

        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = iter.copied().collect();
        let span = self
            .find_span(locs, key)
            .await?
            .expect("a span that includes any given key should always exist if db is non-empty");

        Ok(Some(span))
    }

    /// Get the (value, next-key) pair of `key` in the db, or None if it has no value.
    pub async fn get_all(&self, key: &K) -> Result<Option<(V::Value, K)>, crate::qmdb::Error<F>> {
        self.get_with_loc(key)
            .await
            .map(|res| res.map(|(data, _)| (data.value, data.next_key)))
    }

    /// Returns the key data for `key` with its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(Update<K, V>, Location<F>)>, crate::qmdb::Error<F>> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = self.snapshot.get(key).copied().collect();
        let reader = self.log.reader().await;
        for loc in locs {
            let op = reader.read(*loc).await?;
            assert!(
                op.is_update(),
                "location does not reference update operation. loc={loc}"
            );
            if op.key().expect("update operation must have key") == key {
                let Operation::Update(data) = op else {
                    unreachable!("expected update operation");
                };
                return Ok(Some((data, loc)));
            }
        }

        Ok(None)
    }

    /// Streams all active (key, value) pairs in the database in key order, starting from the first
    /// active key greater than or equal to `start`.
    pub async fn stream_range<'a>(
        &'a self,
        start: K,
    ) -> Result<
        impl Stream<Item = Result<(K, V::Value), crate::qmdb::Error<F>>> + 'a,
        crate::qmdb::Error<F>,
    >
    where
        V: 'a,
    {
        let start_iter = self.snapshot.get(&start);
        let mut init_pending = self.fetch_all_updates(start_iter).await?;
        init_pending.retain(|x| x.key >= start);

        Ok(stream::unfold(
            (start, init_pending),
            move |(driver_key, mut pending): (K, Vec<Update<K, V>>)| async move {
                if !pending.is_empty() {
                    let item = pending.pop().expect("pending is not empty");
                    return Some((Ok((item.key, item.value)), (driver_key, pending)));
                }

                let Some((iter, wrapped)) = self.snapshot.next_translated_key(&driver_key) else {
                    return None; // DB is empty
                };
                if wrapped {
                    return None; // End of DB
                }

                // TODO(https://github.com/commonwarexyz/monorepo/issues/2527): concurrently
                // fetch a much larger batch of "pending" keys.
                match self.fetch_all_updates(iter).await {
                    Ok(mut pending) => {
                        let item = pending.pop().expect("pending is not empty");
                        let key = item.key.clone();
                        Some((Ok((item.key, item.value)), (key, pending)))
                    }
                    Err(e) => Some((Err(e), (driver_key, pending))),
                }
            },
        ))
    }

    /// Fetches all update operations corresponding to the input locations, returning the result in
    /// reverse order of the keys.
    async fn fetch_all_updates(
        &self,
        locs: impl IntoIterator<Item = &Location<F>>,
    ) -> Result<Vec<Update<K, V>>, crate::qmdb::Error<F>> {
        let reader = self.log.reader().await;
        let futures = locs
            .into_iter()
            .map(|loc| Self::get_update_op(&reader, *loc));
        let mut updates = try_join_all(futures).await?;
        updates.sort_by(|a, b| b.key.cmp(&a.key));

        Ok(updates)
    }
}

/// Returns the next key to `key` within `possible_next` (a sorted, deduplicated slice). The
/// result will "cycle around" to the first key if `key` is the last key.
///
/// # Panics
///
/// Panics if `possible_next` is empty.
pub(crate) fn find_next_key<K: Ord + Clone>(key: &K, possible_next: &[K]) -> K {
    let idx = possible_next.partition_point(|k| k <= key);
    if idx < possible_next.len() {
        return possible_next[idx].clone();
    }
    possible_next
        .first()
        .expect("possible_next should not be empty")
        .clone()
}

/// Returns the previous key to `key` within `possible_previous` (sorted by `.0`, deduplicated).
/// The result will "cycle around" to the last entry if `key` is the first key.
///
/// # Panics
///
/// Panics if `possible_previous` is empty.
pub(crate) fn find_prev_key<'a, K: Ord, V>(
    key: &K,
    possible_previous: &'a [(K, V)],
) -> (&'a K, &'a V) {
    let idx = possible_previous.partition_point(|(k, _)| k < key);
    let (k, v) = if idx > 0 {
        &possible_previous[idx - 1]
    } else {
        possible_previous
            .last()
            .expect("possible_previous should not be empty")
    };
    (k, v)
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, C, I, H] Db<F, E, C, I, H, Update<K, V>>
    where {
        F: crate::merkle::Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + 'static,
        H: Hasher,
        Operation<F, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = F, Key = K, Value = V::Value, Digest = H::Digest
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_provable! {
    [F, E, K, V, C, I, H] Db<F, E, C, I, H, Update<K, V>>
    where {
        F: crate::merkle::Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: PersistableMutableLog<Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + 'static,
        H: Hasher,
        Operation<F, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = F, Operation = Operation<F, K, V>
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        merkle::mmr,
        qmdb::any::traits::{DbAny, UnmerkleizedBatch as _},
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::{deterministic::Context, Metrics};
    use commonware_utils::sequence::FixedBytes;
    use core::{future::Future, pin::Pin};

    pub(crate) async fn test_ordered_any_db_empty<
        D: DbAny<mmr::Family, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(db.prune(db.sync_boundary().await).await, Ok(())));

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = FixedBytes::from([1u8; 4]);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        // Write without applying (unapplied batch should be lost on reopen).
        {
            let _batch = db.new_batch().write(d1, Some(d2));
            // Don't merkleize/apply -- simulates uncommitted write
        }
        let mut db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.root(), root);

        // Test applying an empty batch on an empty db.
        let metadata = Sha256::fill(3u8);
        let merkleized = db.new_batch().merkleize(&db, Some(metadata)).await.unwrap();
        let range = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(range.start, Location::new(1));
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.sync_boundary().await).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        for _ in 1..100 {
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            let _ = db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
        }
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_ordered_any_db_basic<
        D: DbAny<mmr::Family, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = FixedBytes::from([1u8; 4]);
        let key2 = FixedBytes::from([2u8; 4]);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.get(&key1).await.unwrap().is_none());
        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val1))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.get(&key2).await.unwrap().is_none());
        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let merkleized = db
            .new_batch()
            .write(key1.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(new_val))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(new_val))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // Empty commit batch (no preceding uncommitted writes).
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Make sure key1 is already active.
        assert!(db.get(&key1).await.unwrap().is_some());

        // Delete all keys.
        assert!(db.get(&key1).await.unwrap().is_some());
        let merkleized = db
            .new_batch()
            .write(key1.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert!(db.get(&key2).await.unwrap().is_some());
        let merkleized = db
            .new_batch()
            .write(key2.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        // Empty commit batch.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Multiple deletions of the same key should be a no-op.
        assert!(db.get(&key1).await.unwrap().is_none());

        // Deletions of non-existent keys should be a no-op.
        let key3 = FixedBytes::from([6u8; 4]);
        assert!(db.get(&key3).await.unwrap().is_none());

        // Make sure closing/reopening gets us back to the same state.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        let op_count = db.bounds().await.end;
        let root = db.root();
        let mut db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);

        // Re-activate the keys by updating them.
        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val1))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key1.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val1))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Empty commit batch.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.bounds().await.end;
        let root = db.root();
        let mut db = reopen_db(context.with_label("reopen2")).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, op_count);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        db.prune(db.sync_boundary().await).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Builds a db with colliding keys to make sure the "cycle around when there are translated
    /// key collisions" edge case is exercised.
    pub(crate) async fn test_ordered_any_update_collision_edge_case<
        D: DbAny<mmr::Family, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        mut db: D,
    ) {
        // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
        // collisions.
        let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
        let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
        // Our last must precede the others to trigger previous-key cycle around.
        let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 0u8, 0u8]);
        let val = Sha256::fill(1u8);

        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val))
            .write(key2.clone(), Some(val))
            .write(key3.clone(), Some(val))
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let _ = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        db.destroy().await.unwrap();
    }
}
