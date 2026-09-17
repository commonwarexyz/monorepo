use crate::{
    Context,
    index::Ordered as Index,
    journal::contiguous::Contiguous,
    merkle::{Family, Location},
    qmdb::{
        any::{ValueEncoding, db::Db},
        operation::{Key, Operation as OperationTrait},
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::contains_cyclic;
use core::ops::Bound::{Excluded, Included};
use futures::{
    future::try_join_all,
    stream::{self, Stream},
};

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{Ordered as Operation, update::Ordered as Update};

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
    const N: usize,
    S: Strategy,
> Db<F, E, C, I, H, Update<K, V>, N, S>
where
    Operation<F, K, V>: Codec,
{
    async fn get_update_op(
        reader: &impl Contiguous<Item = Operation<F, K, V>>,
        loc: Location<F>,
    ) -> Result<Update<K, V>, crate::qmdb::Error<F>> {
        match reader.read(*loc).await? {
            Operation::Update(key_data) => Ok(key_data),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }

    /// Find the span produced by the provided locations that contains `key`, if any.
    async fn find_span(
        &self,
        locs: impl IntoIterator<Item = Location<F>>,
        key: &K,
    ) -> Result<LocatedKey<F, K, V>, crate::qmdb::Error<F>> {
        for loc in locs {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update_op(&self.log, loc).await?;
            if contains_cyclic(&data.key..&data.next_key, key) {
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

    /// Returns the smallest active key strictly greater than `key`, or `None` if there is none.
    ///
    /// The query key need not be active. This lookup does not wrap around to the first key.
    pub async fn get_next_key(&self, key: &K) -> Result<Option<K>, crate::qmdb::Error<F>> {
        let Some((_, data)) = self.get_span(key).await? else {
            return Ok(None);
        };
        Ok((data.next_key > *key).then_some(data.next_key))
    }

    /// Returns the largest active key strictly less than `key`, or `None` if there is none.
    ///
    /// The query key need not be active. This lookup does not wrap around to the last key.
    pub async fn get_prev_key(&self, key: &K) -> Result<Option<K>, crate::qmdb::Error<F>> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = self.snapshot.get(key).copied().collect();
        if let Some(prev) = self.find_strict_prev_key(locs, key).await? {
            return Ok(Some(prev));
        }

        let Some((iter, false)) = self.snapshot.prev_translated_key(key) else {
            return Ok(None);
        };

        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = iter.copied().collect();
        self.find_strict_prev_key(locs, key).await
    }

    /// Returns the database's strict predecessor of `key` if it is among these snapshot entries.
    async fn find_strict_prev_key(
        &self,
        locs: impl IntoIterator<Item = Location<F>>,
        key: &K,
    ) -> Result<Option<K>, crate::qmdb::Error<F>> {
        for loc in locs {
            // A cyclic owner is a strict linear predecessor only when its key is smaller.
            let data = Self::get_update_op(&self.log, loc).await?;
            if data.key < *key
                && contains_cyclic((Excluded(&data.key), Included(&data.next_key)), key)
            {
                return Ok(Some(data.key));
            }
        }
        Ok(None)
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
        for loc in locs {
            let op = self.log.read(*loc).await?;
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
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let start_locs: Vec<Location<F>> = self.snapshot.get(&start).copied().collect();
        let mut init_pending = self.fetch_all_updates(start_locs.iter()).await?;
        init_pending.retain(|x| x.key >= start);

        Ok(stream::unfold(
            (start, init_pending),
            move |(driver_key, mut pending): (K, Vec<Update<K, V>>)| async move {
                if !pending.is_empty() {
                    let item = pending.pop().expect("pending is not empty");
                    return Some((Ok((item.key, item.value)), (driver_key, pending)));
                }

                // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
                let locs: Vec<Location<F>> = {
                    let Some((iter, wrapped)) = self.snapshot.next_translated_key(&driver_key)
                    else {
                        return None; // DB is empty
                    };
                    if wrapped {
                        return None; // End of DB
                    }
                    iter.copied().collect()
                };

                // TODO(https://github.com/commonwarexyz/monorepo/issues/2527): concurrently
                // fetch a much larger batch of "pending" keys.
                match self.fetch_all_updates(locs.iter()).await {
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
        let futures = locs
            .into_iter()
            .map(|loc| Self::get_update_op(&self.log, *loc));
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

/// Streaming equivalent of [`find_next_key`] for an ascending sequence of queries: `idx`
/// advances in a linear merge instead of binary-searching per query. Queries must be
/// non-decreasing; `idx` must start at 0 and be threaded through every call.
///
/// # Panics
///
/// Panics if `possible_next` is empty, or on any out-of-order query that would return a
/// wrong result (`idx` has already advanced past a candidate above the query).
pub(crate) fn find_next_key_ascending<K: Ord + Clone>(
    key: &K,
    possible_next: &[K],
    idx: &mut usize,
) -> K {
    assert!(
        *idx == 0 || possible_next[*idx - 1] <= *key,
        "queries must be non-decreasing"
    );
    while *idx < possible_next.len() && possible_next[*idx] <= *key {
        *idx += 1;
    }
    if *idx < possible_next.len() {
        return possible_next[*idx].clone();
    }
    possible_next
        .first()
        .expect("possible_next should not be empty")
        .clone()
}

/// Returns the previous key to `key` and its mutable value within `possible_previous`
/// (sorted by `.0`, deduplicated).
/// The result will "cycle around" to the last entry if `key` is the first key.
///
/// # Panics
///
/// Panics if `possible_previous` is empty.
pub(crate) fn find_prev_key_mut<'a, K: Ord, V>(
    key: &K,
    possible_previous: &'a mut [(K, V)],
) -> (&'a K, &'a mut V) {
    let idx = possible_previous.partition_point(|(k, _)| k < key);
    let (k, v) = if idx > 0 {
        &mut possible_previous[idx - 1]
    } else {
        possible_previous
            .last_mut()
            .expect("possible_previous should not be empty")
    };
    (k, v)
}

#[cfg(any(test, feature = "test-traits"))]
crate::qmdb::any::traits::impl_db_any! {
    [F, E, K, V, C, I, H, const N: usize, S] Db<F, E, C, I, H, Update<K, V>, N, S>
    where {
        F: crate::merkle::Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: crate::journal::contiguous::Mutable<Item = Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + 'static,
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
        C: crate::journal::contiguous::Mutable<Item = Operation<F, K, V>>,
        I: Index<Value = crate::merkle::Location<F>> + 'static,
        H: Hasher,
        S: Strategy,
        Operation<F, K, V>: Codec,
        V::Value: Send + Sync,
    }
    Family = F, Operation = Operation<F, K, V>
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        merkle::Family,
        mmb, mmr,
        qmdb::{
            any::{
                self,
                traits::{DbAny, UnmerkleizedBatch as _},
            },
            current,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::boxed;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::{self, Context},
    };
    use commonware_utils::{sequence::FixedBytes, test_rng};
    use core::{future::Future, pin::Pin};
    use rand::{RngExt as _, seq::SliceRandom as _};
    use std::{collections::BTreeSet, ops::Bound};

    /// [`find_next_key_ascending`] must return exactly what [`find_next_key`] returns for any
    /// ascending query sequence, including queries past the last candidate (cyclic wrap).
    #[test]
    fn find_next_key_ascending_matches_binary_search() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let mut candidates: Vec<u64> = (0..rng.random_range(1..40))
                .map(|_| rng.random_range(0..60u64))
                .collect();
            candidates.sort_unstable();
            candidates.dedup();

            let mut queries: Vec<u64> = (0..rng.random_range(1..80))
                .map(|_| rng.random_range(0..70u64))
                .collect();
            queries.sort_unstable();

            let mut idx = 0;
            for q in queries {
                assert_eq!(
                    find_next_key(&q, &candidates),
                    find_next_key_ascending(&q, &candidates, &mut idx),
                    "query {q} diverged"
                );
            }
        }
    }

    /// An out-of-order query that would return a wrong result must panic instead.
    #[test]
    #[should_panic(expected = "queries must be non-decreasing")]
    fn find_next_key_ascending_rejects_out_of_order_query() {
        let candidates = vec![1u64, 5, 9];
        let mut idx = 0;
        assert_eq!(find_next_key_ascending(&5, &candidates, &mut idx), 9);
        find_next_key_ascending(&1, &candidates, &mut idx);
    }

    #[boxed]
    pub(crate) async fn test_ordered_any_db_empty<
        F: Family,
        D: DbAny<F, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        assert!(db.get_metadata().await.unwrap().is_none());
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();

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
        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.root(), root);

        // Test applying an empty batch on an empty db.
        let metadata = Sha256::fill(3u8);
        let merkleized = db.new_batch().merkleize(&db, Some(metadata)).await.unwrap();
        let (db, range) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(range.start, Location::new(1));
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        let boundary = db.sync_boundary();
        db.prune(boundary).await.unwrap();

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.child("reopen").with_attribute("index", 2)).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        for _ in 1..100 {
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            db = db.commit().await.unwrap();
        }
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[boxed]
    pub(crate) async fn test_ordered_any_db_basic<
        F: Family,
        D: DbAny<F, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        context: Context,
        db: D,
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
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.get(&key2).await.unwrap().is_none());
        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let merkleized = db
            .new_batch()
            .write(key1.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(new_val))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(new_val))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // Empty commit batch (no preceding uncommitted writes).
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

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
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert!(db.get(&key2).await.unwrap().is_some());
        let merkleized = db
            .new_batch()
            .write(key2.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        // Empty commit batch.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Multiple deletions of the same key should be a no-op.
        assert!(db.get(&key1).await.unwrap().is_none());

        // Deletions of non-existent keys should be a no-op.
        let key3 = FixedBytes::from([6u8; 4]);
        assert!(db.get(&key3).await.unwrap().is_none());

        // Make sure closing/reopening gets us back to the same state.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let op_count = db.bounds().end;
        let root = db.root();
        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.bounds().end, op_count);
        assert_eq!(db.root(), root);

        // Re-activate the keys by updating them.
        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val1))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key1.clone(), None)
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key2.clone(), Some(val1))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        let merkleized = db
            .new_batch()
            .write(key1.clone(), Some(val2))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Empty commit batch.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.bounds().end;
        let root = db.root();
        let db = reopen_db(context.child("reopen").with_attribute("index", 2)).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().end, op_count);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Builds a db with colliding keys to make sure the "cycle around when there are translated
    /// key collisions" edge case is exercised.
    #[boxed]
    pub(crate) async fn test_ordered_any_update_collision_edge_case<
        F: Family,
        D: DbAny<F, Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    >(
        db: D,
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
        let (db, _) = db.apply_batch(merkleized).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        db.destroy().await.unwrap();
    }

    fn neighbor_key(prefix: [u8; 3]) -> Digest {
        let mut bytes = [0; 32];
        bytes[..3].copy_from_slice(&prefix);
        bytes.into()
    }

    fn require_send<F: Future + Send>(future: F) -> F {
        future
    }

    macro_rules! assert_neighbors {
        ($view:expr, $active:expr, $queries:expr, $stage:expr $(, $db:expr)?) => {
            for query in $queries {
                let prev = ($active).range(..query.clone()).next_back().cloned();
                let next = ($active)
                    .range((Bound::Excluded(query.clone()), Bound::Unbounded))
                    .next()
                    .cloned();
                assert_eq!(
                    require_send(($view).get_prev_key(query $(, $db)?)).await.unwrap(),
                    prev,
                    "{}, previous query {query:?}",
                    $stage
                );
                assert_eq!(
                    require_send(($view).get_next_key(query $(, $db)?)).await.unwrap(),
                    next,
                    "{}, next query {query:?}",
                    $stage
                );
            }
        };
    }

    macro_rules! test_neighbors {
        ($name:ident, $db:ty, $config:path) => {
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    type TestDb = $db;

                    let config = $config("neighbors", &context);
                    let mut db = TestDb::init(context.child("db"), config.clone())
                        .await
                        .unwrap();
                    let mut active = BTreeSet::new();
                    let value = Sha256::fill(1);

                    // Exercise conflicts within a translated key, neighboring index entries, and
                    // distinct partitions. Insert out of order so conflict order cannot be assumed.
                    let a = neighbor_key([0x20, 0x20, 0x20]);
                    let b = neighbor_key([0x20, 0x20, 0x60]);
                    let c = neighbor_key([0x20, 0x60, 0x20]);
                    let d = neighbor_key([0x60, 0x20, 0x20]);
                    let min = Sha256::fill(0);
                    let max = Sha256::fill(0xFF);
                    let mut phases = vec![
                        vec![],
                        vec![(b, Some(value))],
                        vec![(d, Some(value)), (a, Some(value)), (c, Some(value))],
                        vec![(b, None), (a, Some(Sha256::fill(2))), (d, None)],
                        vec![(min, Some(value)), (max, Some(value)), (b, Some(value))],
                        vec![(a, None), (b, None), (c, None), (min, None), (max, None)],
                    ];
                    let mut queries = vec![max];
                    for i in [0, 0x20, 0x40, 0x60, 0xFF] {
                        for j in [0, 0x20, 0x40, 0x60, 0xFF] {
                            for k in [0, 0x20, 0x40, 0x60, 0xFF] {
                                queries.push(neighbor_key([i, j, k]));
                            }
                        }
                    }

                    // Flood one translated key and force partitioned indices past their spill
                    // threshold. Leave gaps between keys and scramble the conflict iteration order.
                    let mut rng = test_rng();
                    let mut crowded: Vec<Digest> = (0u16..520)
                        .map(|i| {
                            let mut bytes = [0x20; 32];
                            bytes[30..].copy_from_slice(&(i * 2).to_be_bytes());
                            bytes.into()
                        })
                        .collect();
                    let survivor = *crowded.last().unwrap();
                    let probes: Vec<_> = crowded
                        .iter()
                        .step_by(31)
                        .chain(crowded.last())
                        .copied()
                        .collect();
                    for key in &probes {
                        queries.push(*key);
                        let mut gap: [u8; 32] = (*key).into();
                        gap[31] += 1;
                        queries.push(gap.into());
                    }
                    crowded.shuffle(&mut rng);
                    phases.push(crowded.iter().map(|&key| (key, Some(value))).collect());
                    phases.push(probes.iter().map(|&key| (key, None)).collect());
                    phases.push(
                        probes
                            .iter()
                            .rev()
                            .map(|&key| (key, Some(Sha256::fill(2))))
                            .collect(),
                    );

                    // Leave one live collision behind the tombstones before emptying the view.
                    phases.push(
                        crowded
                            .iter()
                            .filter(|&&key| key != survivor)
                            .map(|&key| (key, None))
                            .collect(),
                    );
                    phases.push(vec![(survivor, None)]);

                    assert_neighbors!(&db, &active, &queries, "fresh");
                    for (phase, writes) in phases.into_iter().enumerate() {
                        let committed = active.clone();
                        let mut batch = db.new_batch();
                        for (key, value) in writes {
                            if value.is_some() {
                                active.insert(key);
                            } else {
                                active.remove(&key);
                            }
                            batch = batch.write(key, value);
                        }

                        let batch = batch.merkleize(&db, None).await.unwrap();
                        assert_neighbors!(
                            batch,
                            &active,
                            &queries,
                            format_args!("phase {phase}, merkleized"),
                            &db
                        );

                        if active.len() == 1 && active.contains(&survivor) {
                            let mut below: [u8; 32] = survivor.into();
                            below[31] -= 1;
                            let below = Digest::from(below);
                            let mut deleted_predecessor: [u8; 32] = survivor.into();
                            deleted_predecessor[31] -= 2;
                            let deleted_predecessor = Digest::from(deleted_predecessor);
                            assert!(committed.contains(&deleted_predecessor));
                            assert!(!active.contains(&deleted_predecessor));
                            assert_neighbors!(
                                batch,
                                &active,
                                &[below, survivor],
                                "singleton after deletions",
                                &db
                            );
                        }

                        // Merkleizing must leave the DB view unchanged.
                        assert_neighbors!(
                            &db,
                            &committed,
                            &[min, a, max],
                            format_args!("phase {phase}, merkleized db")
                        );
                        (db, _) = db.apply_batch(batch).await.unwrap();

                        assert_neighbors!(
                            &db,
                            &active,
                            &queries,
                            format_args!("phase {phase}, applied")
                        );
                        db = db.commit().await.unwrap();
                        assert_neighbors!(
                            &db,
                            &active,
                            &queries,
                            format_args!("phase {phase}, committed")
                        );
                        let boundary = db.sync_boundary();
                        db = db.prune(boundary).await.unwrap();
                        assert_neighbors!(
                            &db,
                            &active,
                            &queries,
                            format_args!("phase {phase}, pruned")
                        );
                        drop(db);
                        db = TestDb::init(context.child("reopen"), config.clone())
                            .await
                            .unwrap();
                        assert_neighbors!(
                            &db,
                            &active,
                            &queries,
                            format_args!("phase {phase}, reopened")
                        );
                    }
                    db.destroy().await.unwrap();
                });
            }
        };
    }

    test_neighbors!(
        test_neighbors_any_fixed,
        any::ordered::fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, Sequential>,
        any::test::fixed_db_config::<OneCap>
    );
    test_neighbors!(
        test_neighbors_any_variable,
        any::ordered::variable::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, Sequential>,
        any::test::variable_db_config::<OneCap>
    );
    test_neighbors!(
        test_neighbors_any_fixed_partitioned,
        any::ordered::fixed::partitioned::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 1, Sequential>,
        any::test::fixed_db_config_partitioned::<OneCap>
    );
    test_neighbors!(
        test_neighbors_any_variable_partitioned,
        any::ordered::variable::partitioned::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 1, Sequential>,
        any::test::variable_db_config_partitioned::<OneCap>
    );
    test_neighbors!(
        test_neighbors_current_fixed,
        current::ordered::fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Sequential>,
        current::tests::fixed_config::<OneCap>
    );
    test_neighbors!(
        test_neighbors_current_variable,
        current::ordered::variable::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Sequential>,
        current::tests::variable_config::<OneCap>
    );
    test_neighbors!(
        test_neighbors_current_fixed_partitioned,
        current::ordered::fixed::partitioned::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 1, 32, Sequential>,
        current::tests::fixed_config_partitioned::<OneCap>
    );
    test_neighbors!(
        test_neighbors_current_variable_partitioned,
        current::ordered::variable::partitioned::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 1, 32, Sequential>,
        current::tests::variable_config_partitioned::<OneCap>
    );

    fn layered_neighbor_key(n: u16) -> Digest {
        let mut bytes = [0; 32];
        bytes[0] = 0x40;
        bytes[30..].copy_from_slice(&n.to_be_bytes());
        bytes.into()
    }

    macro_rules! any_batch {
        (any, $batch:expr) => {
            $batch
        };
        (current, $batch:expr) => {
            $batch.inner
        };
    }

    macro_rules! test_layered_batch_neighbors {
        ($name:ident, $db:ty, $config:path, $layer:ident) => {
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    type TestDb = $db;

                    let config = $config("layered-neighbors", &context);
                    let db = TestDb::init(context.child("db"), config).await.unwrap();
                    let value = Sha256::fill(1);
                    let empty_active: BTreeSet<Digest> = BTreeSet::new();
                    let empty_queries =
                        [Sha256::fill(0), layered_neighbor_key(1), Sha256::fill(0xFF)];
                    let empty_batch = db.to_batch();
                    assert!(any_batch!($layer, empty_batch).diff.is_empty());
                    assert_neighbors!(
                        empty_batch,
                        &empty_active,
                        &empty_queries,
                        "empty to_batch",
                        &db
                    );

                    let base_keys: Vec<_> = (0..64).map(|i| layered_neighbor_key(i * 4)).collect();
                    let base_active: BTreeSet<_> = base_keys.iter().copied().collect();

                    let mut seed = db.new_batch();
                    for &key in base_keys.iter().rev() {
                        seed = seed.write(key, Some(value));
                    }
                    let seed = seed.merkleize(&db, None).await.unwrap();
                    let (db, _) = db.apply_batch(seed).await.unwrap();
                    let db = db.commit().await.unwrap();

                    let parent_key = layered_neighbor_key(81);
                    let parent_deleted = layered_neighbor_key(120);
                    let parent = db
                        .new_batch()
                        .write(layered_neighbor_key(160), Some(Sha256::fill(2)))
                        .write(parent_deleted, None)
                        .write(parent_key, Some(Sha256::fill(3)));
                    let mut parent_active = base_active.clone();
                    parent_active.remove(&parent_deleted);
                    parent_active.insert(parent_key);
                    let queries = [
                        Sha256::fill(0),
                        layered_neighbor_key(0),
                        layered_neighbor_key(1),
                        layered_neighbor_key(39),
                        layered_neighbor_key(40),
                        layered_neighbor_key(41),
                        layered_neighbor_key(44),
                        layered_neighbor_key(45),
                        layered_neighbor_key(48),
                        layered_neighbor_key(49),
                        layered_neighbor_key(80),
                        parent_key,
                        layered_neighbor_key(82),
                        layered_neighbor_key(119),
                        parent_deleted,
                        layered_neighbor_key(121),
                        layered_neighbor_key(159),
                        layered_neighbor_key(160),
                        layered_neighbor_key(161),
                        layered_neighbor_key(252),
                        layered_neighbor_key(253),
                        Sha256::fill(0xFF),
                    ];
                    let base_batch = db.to_batch();
                    assert!(any_batch!($layer, base_batch).diff.is_empty());
                    assert_neighbors!(base_batch, &base_active, &queries, "nonempty to_batch", &db);

                    let parent = parent.merkleize(&db, None).await.unwrap();
                    assert_neighbors!(parent, &parent_active, &queries, "parent merkleized", &db);
                    assert_neighbors!(&db, &base_active, &queries, "parent pending db");

                    // A floor raise may copy untouched keys into the local diff. Both directions
                    // need a span owner absent from that diff to exercise DB fallback.
                    let parent_diff = any_batch!($layer, parent).diff.as_slice();
                    assert!(
                        parent_diff
                            .iter()
                            .any(|(key, entry)| key == &parent_key && entry.value().is_some())
                    );
                    let (committed_index, &committed_only) = base_keys
                        .iter()
                        .enumerate()
                        .skip(1)
                        .find(|(_, key)| {
                            let Some(prev) = parent_active.range(..**key).next_back() else {
                                return false;
                            };
                            parent_active.contains(*key)
                                && parent_diff
                                    .iter()
                                    .all(|(diff_key, _)| diff_key != *key && diff_key != prev)
                        })
                        .expect("enough base keys to retain a committed-only source");
                    let committed_n = committed_index as u16 * 4;
                    let committed_predecessor =
                        parent_active.range(..committed_only).next_back().unwrap();
                    assert!(parent_diff.iter().all(|(key, _)| key != &committed_only));
                    assert!(
                        parent_diff
                            .iter()
                            .all(|(key, _)| key != committed_predecessor),
                        "the successor's span owner must reside only in the DB"
                    );
                    assert_eq!(
                        parent
                            .get_prev_key(&layered_neighbor_key(committed_n + 1), &db)
                            .await
                            .unwrap(),
                        Some(committed_only)
                    );
                    assert_eq!(
                        parent
                            .get_next_key(&layered_neighbor_key(committed_n - 1), &db)
                            .await
                            .unwrap(),
                        Some(committed_only)
                    );
                    assert_eq!(
                        parent
                            .get_prev_key(&layered_neighbor_key(82), &db)
                            .await
                            .unwrap(),
                        Some(parent_key)
                    );
                    assert_eq!(
                        parent
                            .get_next_key(&layered_neighbor_key(80), &db)
                            .await
                            .unwrap(),
                        Some(parent_key)
                    );

                    let child_key = layered_neighbor_key(45);
                    let child = parent
                        .new_batch::<Sha256>()
                        .write(layered_neighbor_key(48), None)
                        .write(parent_key, None)
                        .write(layered_neighbor_key(40), None)
                        .write(child_key, Some(Sha256::fill(4)))
                        .write(layered_neighbor_key(44), None);
                    let mut child_active = parent_active.clone();
                    for key in [
                        layered_neighbor_key(40),
                        layered_neighbor_key(44),
                        layered_neighbor_key(48),
                        parent_key,
                    ] {
                        child_active.remove(&key);
                    }
                    child_active.insert(child_key);
                    let child = child.merkleize(&db, None).await.unwrap();
                    assert_neighbors!(child, &child_active, &queries, "child merkleized", &db);

                    let grandchild = child
                        .new_batch::<Sha256>()
                        .write(child_key, None)
                        .write(parent_key, Some(Sha256::fill(5)))
                        .write(layered_neighbor_key(44), Some(Sha256::fill(6)));
                    let mut grandchild_active = child_active.clone();
                    grandchild_active.remove(&child_key);
                    grandchild_active.insert(parent_key);
                    grandchild_active.insert(layered_neighbor_key(44));
                    let grandchild = grandchild.merkleize(&db, None).await.unwrap();
                    assert_neighbors!(
                        grandchild,
                        &grandchild_active,
                        &queries,
                        "grandchild merkleized",
                        &db
                    );
                    assert_neighbors!(&db, &base_active, &queries, "descendants pending db");

                    // Advance the DB only along this chain. Descendants retain the same view while
                    // an applied ancestor is live and after they fall through to the advanced DB.
                    let (db, _) = db
                        .apply_batch(std::sync::Arc::clone(&parent))
                        .await
                        .unwrap();
                    assert_neighbors!(&db, &parent_active, &queries, "parent applied");
                    assert_neighbors!(
                        child,
                        &child_active,
                        &queries,
                        "child after parent apply",
                        &db
                    );
                    assert_neighbors!(
                        grandchild,
                        &grandchild_active,
                        &queries,
                        "grandchild after parent apply",
                        &db
                    );
                    drop(parent);
                    assert_neighbors!(
                        child,
                        &child_active,
                        &queries,
                        "child after parent drop",
                        &db
                    );
                    assert_neighbors!(
                        grandchild,
                        &grandchild_active,
                        &queries,
                        "grandchild after parent drop",
                        &db
                    );

                    let (db, _) = db.apply_batch(std::sync::Arc::clone(&child)).await.unwrap();
                    assert_neighbors!(&db, &child_active, &queries, "child applied");
                    drop(child);
                    assert_neighbors!(
                        grandchild,
                        &grandchild_active,
                        &queries,
                        "grandchild after child drop",
                        &db
                    );

                    let (db, _) = db.apply_batch(grandchild).await.unwrap();
                    assert_neighbors!(&db, &grandchild_active, &queries, "grandchild applied");
                    let db = db.commit().await.unwrap();
                    db.destroy().await.unwrap();
                });
            }
        };
    }

    test_layered_batch_neighbors!(
        test_layered_batch_neighbors_any,
        any::ordered::fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, Sequential>,
        any::test::fixed_db_config::<OneCap>,
        any
    );
    test_layered_batch_neighbors!(
        test_layered_batch_neighbors_current,
        current::ordered::fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Sequential>,
        current::tests::fixed_config::<OneCap>,
        current
    );

    #[test]
    fn test_neighbors_variable_length_keys() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = current::ordered::variable::partitioned::Db<
                mmb::Family,
                deterministic::Context,
                Vec<u8>,
                Vec<u8>,
                Sha256,
                OneCap,
                2,
                32,
                Sequential,
            >;
            let config =
                current::tests::variable_config_partitioned::<OneCap>("neighbors", &context);
            let config = current::VariableConfig {
                journal_config: crate::journal::contiguous::variable::Config {
                    codec_config: (((..=3).into(), ()), ((..=4096).into(), ())),
                    partition: config.journal_config.partition,
                    items_per_section: config.journal_config.items_per_section,
                    compression: config.journal_config.compression,
                    page_cache: config.journal_config.page_cache,
                    write_buffer: config.journal_config.write_buffer,
                    replay_buffer: config.journal_config.replay_buffer,
                },
                merkle_config: config.merkle_config,
                grafted_metadata_partition: config.grafted_metadata_partition,
                translator: config.translator,
                init_cache: config.init_cache,
                init_buffer: config.init_buffer,
                init_concurrency: config.init_concurrency,
            };
            let mut db = TestDb::init(context.child("db"), config.clone())
                .await
                .unwrap();

            // Include empty keys, keys shorter than the partition prefix, and keys differing only
            // by trailing zeros. All must retain their full lexicographic ordering after translation.
            let mut queries = vec![vec![]];
            for a in [0, 1, 255] {
                queries.push(vec![a]);
                for b in [0, 1, 255] {
                    queries.push(vec![a, b]);
                    for c in [0, 1, 255] {
                        queries.push(vec![a, b, c]);
                    }
                }
            }
            let active: BTreeSet<_> = queries.iter().step_by(2).cloned().collect();
            let mut batch = db.new_batch();
            for (i, key) in active.iter().rev().enumerate() {
                batch = batch.write(key.clone(), Some(vec![1; i * 100]));
            }

            let batch = batch.merkleize(&db, None).await.unwrap();
            assert_neighbors!(batch, &active, &queries, "merkleized", &db);
            let empty: BTreeSet<Vec<u8>> = BTreeSet::new();
            assert_neighbors!(&db, &empty, &queries, "pending db");
            (db, _) = db.apply_batch(batch).await.unwrap();
            for recovered in [false, true] {
                if recovered {
                    db = db.commit().await.unwrap();
                    drop(db);
                    db = TestDb::init(context.child("reopen"), config.clone())
                        .await
                        .unwrap();
                }
                assert_neighbors!(
                    &db,
                    &active,
                    &queries,
                    format_args!("recovered={recovered}")
                );
            }
            db.destroy().await.unwrap();
        });
    }
}
