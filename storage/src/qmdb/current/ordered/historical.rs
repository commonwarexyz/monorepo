//! Read-only views of retained ordered Current QMDB commits.

use super::{ExclusionProof, db::KeyValueProof};
use crate::{
    Context,
    index::Ordered as OrderedIndex,
    journal::contiguous::Contiguous,
    merkle::{self, Location, Position, hasher::Hasher as _, mem::Mem, storage::Storage},
    qmdb::{
        self, Error,
        any::{
            ValueEncoding,
            ordered::{Operation, Update},
        },
        current::{db::rebuild_grafted_tree, grafting, proof::OperationProof},
        operation::Key,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::bitmap::Prunable;
use std::collections::BTreeMap;

/// A borrowing view of one retained commit, reconstructed from its operation log.
///
/// Construction reads the operations from the commit's inactivity floor through its final
/// operation. Memory holds their activity bits, the latest update for each active key, and the
/// grafted Merkle tree. Work and memory therefore scale with that window, not the proof size.
/// Dropping the view or cancelling its construction does not mutate the database.
pub struct HistoricalView<
    'a,
    F: merkle::Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    const N: usize,
    S: Strategy,
> {
    ops: Prefix<'a, F, merkle::full::Merkle<F, E, H::Digest, S>>,
    entries: BTreeMap<K, (Location<F>, Update<K, V>)>,
    bitmap: Prunable<N>,
    grafted_tree: Mem<F, H::Digest>,
    floor: Location<F>,
    metadata: Option<V::Value>,
    ops_root: H::Digest,
    root: H::Digest,
}

/// Nodes are immutable, but the target size also determines peak and pending-chunk selection.
struct Prefix<'a, F: merkle::Family, T> {
    inner: &'a T,
    size: Position<F>,
}

impl<F: merkle::Family, T: Storage<F>> Storage<F> for Prefix<'_, F, T> {
    type Digest = T::Digest;

    fn size(&self) -> Position<F> {
        self.size
    }

    async fn get_node(
        &self,
        position: Position<F>,
    ) -> Result<Option<Self::Digest>, merkle::Error<F>> {
        if position >= self.size {
            return Ok(None);
        }
        self.inner.get_node(position).await
    }
}

impl<
    F: merkle::Graftable,
    E: Context,
    C: Contiguous<Item = Operation<F, K, V>>,
    K: Key,
    V: ValueEncoding,
    I: OrderedIndex<Value = Location<F>>,
    H: Hasher,
    const N: usize,
    S: Strategy,
> super::db::Db<F, E, C, K, V, I, H, N, S>
where
    Operation<F, K, V>: Codec,
{
    /// Reconstruct a read-only view at the commit ending at `size` (exclusive).
    ///
    /// Both the operation log and its Merkle nodes must retain the commit's active window.
    /// Zero, future, non-commit and pruned targets return errors before reconstruction.
    /// Construction costs scale with the historical active operation window; no historical
    /// state is cached or persisted. The database remains borrowed until the view is dropped.
    pub async fn historical_view(
        &self,
        size: Location<F>,
    ) -> Result<HistoricalView<'_, F, E, K, V, H, N, S>, Error<F>> {
        if size > self.any.log.size() {
            return Err(merkle::Error::RangeOutOfBounds(size).into());
        }
        let floor = qmdb::find_inactivity_floor_at::<F, _>(&self.any.log, size).await?;
        let retained = self.any.log.merkle.bounds().start.max(self.bounds().start);
        if floor < retained {
            return Err(Error::OperationPruned(floor));
        }
        let ops = Prefix {
            inner: &self.any.log.merkle,
            size: F::location_to_position(size),
        };
        let height = grafting::height::<N>();
        let pruned_chunks = *crate::qmdb::current::db::sync_boundary::<F, N>(
            *floor / Prunable::<N>::CHUNK_SIZE_BITS,
            *size,
        ) / Prunable::<N>::CHUNK_SIZE_BITS;
        let pruned_chunks = usize::try_from(pruned_chunks)
            .map_err(|_| Error::DataCorrupted("historical bitmap exceeds address space"))?;
        usize::try_from(*size / Prunable::<N>::CHUNK_SIZE_BITS)
            .map_err(|_| Error::DataCorrupted("historical bitmap exceeds address space"))?;

        let mut peaks = Vec::new();
        for (position, _) in F::peaks(ops.size()) {
            peaks.push(
                ops.get_node(position)
                    .await?
                    .ok_or(merkle::Error::MissingNode(position))?,
            );
        }
        let ops_root =
            qmdb::hasher::<H>().root(size, F::inactive_peaks(size, floor), peaks.iter())?;

        // All chunks below the historical floor are inactive. Their grafted pinned digests
        // equal the corresponding ops digests by the zero-chunk identity.
        let mut pinned = Vec::new();
        for position in F::nodes_to_pin(Location::new(pruned_chunks as u64)) {
            let position = grafting::grafted_to_ops_pos::<F>(position, height);
            pinned.push(
                ops.get_node(position)
                    .await?
                    .ok_or(merkle::Error::MissingNode(position))?,
            );
        }
        let mut bitmap = Prunable::<N>::new_with_pruned_chunks(pruned_chunks)
            .map_err(|_| Error::DataCorrupted("historical bitmap exceeds address space"))?;
        bitmap.extend_to(*size);
        let mut entries = BTreeMap::new();
        let mut metadata = None;
        for loc in *floor..*size {
            let old = match self.any.log.read(loc).await? {
                Operation::Update(update) => {
                    bitmap.set_bit(loc, true);
                    entries.insert(update.key.clone(), (Location::new(loc), update))
                }
                Operation::Delete(key) => entries.remove(&key),
                Operation::CommitFloor(value, _) => {
                    if loc == *size - 1 {
                        bitmap.set_bit(loc, true);
                        metadata = value;
                    }
                    None
                }
            };
            if let Some((old_loc, _)) = old {
                bitmap.set_bit(*old_loc, false);
            }
        }
        let (grafted_tree, root) = rebuild_grafted_tree::<F, H, S, N>(
            &bitmap,
            &pinned,
            &ops,
            floor,
            ops_root,
            &self.strategy,
        )
        .await?;
        Ok(HistoricalView {
            ops,
            entries,
            bitmap,
            grafted_tree,
            floor,
            metadata,
            ops_root,
            root,
        })
    }
}

impl<
    F: merkle::Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    const N: usize,
    S: Strategy,
> HistoricalView<'_, F, E, K, V, H, N, S>
where
    Operation<F, K, V>: Codec,
{
    /// The canonical Current root at this commit.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// The value assigned to `key` at this commit.
    pub fn get(&self, key: &K) -> Option<&V::Value> {
        self.entries.get(key).map(|(_, update)| &update.value)
    }

    async fn operation_proof(
        &self,
        loc: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, Error<F>> {
        let storage = grafting::Storage::<F, H, _, _>::new(
            &self.grafted_tree,
            grafting::height::<N>(),
            &self.ops,
        );
        OperationProof::new::<H, _>(&self.bitmap, &storage, self.floor, loc, self.ops_root).await
    }

    /// Prove the value of `key` at this commit, or return [`Error::KeyNotFound`].
    pub async fn key_value_proof(
        &self,
        key: K,
    ) -> Result<KeyValueProof<F, K, H::Digest, N>, Error<F>> {
        let (loc, update) = self.entries.get(&key).ok_or(Error::KeyNotFound)?;
        Ok(KeyValueProof {
            proof: self.operation_proof(*loc).await?,
            next_key: update.next_key.clone(),
        })
    }

    /// Prove absence of `key` at this commit, or return [`Error::KeyExists`].
    pub async fn exclusion_proof(
        &self,
        key: &K,
    ) -> Result<ExclusionProof<F, K, V, H::Digest, N>, Error<F>> {
        let span = self
            .entries
            .range(..=key)
            .next_back()
            .or_else(|| self.entries.last_key_value());
        if let Some((span_key, (loc, update))) = span {
            if span_key == key {
                return Err(Error::KeyExists);
            }
            return Ok(ExclusionProof::KeyValue(
                self.operation_proof(*loc).await?,
                update.clone(),
            ));
        }
        let loc = Location::try_from(self.ops.size())? - 1;
        if self.floor != loc {
            return Err(Error::DataCorrupted(
                "empty historical snapshot has a nonempty commit floor",
            ));
        }
        Ok(ExclusionProof::Commit(
            self.operation_proof(loc).await?,
            self.metadata.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{mmb, mmr},
        qmdb::current::{
            ordered::{fixed, variable},
            tests::{fixed_config, variable_config},
        },
        translator::OneCap,
    };
    use commonware_codec::varint::UInt;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    type TestDb<F> =
        fixed::Db<F, deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    fn edits<F: merkle::Graftable>() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = TestDb::<F>::init(
                context.child("db"),
                fixed_config::<OneCap>("history", &context),
            )
            .await
            .unwrap();
            let mut expected = BTreeMap::new();
            let mut checkpoints = vec![(db.bounds().end, db.root(), expected.clone())];
            for (key, value) in [
                (2, Some(20)),
                (4, Some(40)),
                (6, Some(60)),
                (4, Some(41)),
                (2, None),
                (4, None),
                (6, None),
                (4, Some(42)),
            ] {
                let key = Sha256::fill(key);
                let value = value.map(Sha256::fill);
                let batch = db
                    .new_batch()
                    .write(key, value)
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                if let Some(value) = value {
                    expected.insert(key, value);
                } else {
                    expected.remove(&key);
                }
                checkpoints.push((db.bounds().end, db.root(), expected.clone()));
            }
            db = db.commit().await.unwrap();
            let live_root = db.root();
            for (size, root, expected) in checkpoints {
                let view = db.historical_view(size).await.unwrap();
                assert_eq!(view.root(), root);
                assert_eq!(
                    view.entries
                        .iter()
                        .map(|(k, (_, update))| (*k, update.value))
                        .collect::<BTreeMap<_, _>>(),
                    expected
                );
                for key in (1..=7).map(Sha256::fill) {
                    assert_eq!(view.get(&key), expected.get(&key));
                    if let Some(value) = expected.get(&key) {
                        let proof = view.key_value_proof(key).await.unwrap();
                        assert!(TestDb::<F>::verify_key_value_proof(
                            key, *value, &proof, &root
                        ));
                        assert!(matches!(
                            view.exclusion_proof(&key).await,
                            Err(Error::KeyExists)
                        ));
                        if root != live_root {
                            assert!(!TestDb::<F>::verify_key_value_proof(
                                key, *value, &proof, &live_root
                            ));
                        }
                    } else {
                        let proof = view.exclusion_proof(&key).await.unwrap();
                        assert!(TestDb::<F>::verify_exclusion_proof(&key, &proof, &root));
                        assert!(matches!(
                            view.key_value_proof(key).await,
                            Err(Error::KeyNotFound)
                        ));
                    }
                }
            }
            assert!(matches!(
                db.historical_view(Location::new(0)).await,
                Err(Error::HistoricalFloorPruned(_))
            ));
            assert!(matches!(
                db.historical_view(Location::new(2)).await,
                Err(Error::HistoricalFloorPruned(_))
            ));
            for size in [db.bounds().end + 1, Location::new(u64::MAX)] {
                assert!(matches!(
                    db.historical_view(size).await,
                    Err(Error::Merkle(merkle::Error::RangeOutOfBounds(_)))
                ));
            }
            assert_eq!(db.root(), live_root);
            let batch = db
                .new_batch()
                .write(Sha256::fill(6), Some(Sha256::fill(63)))
                .merkleize(&db, None)
                .await
                .unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.commit().await.unwrap();
            assert_eq!(
                db.get(&Sha256::fill(6)).await.unwrap(),
                Some(Sha256::fill(63))
            );
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn historical_view_mmr_edits() {
        edits::<mmr::Family>();
    }

    #[test]
    fn historical_view_mmb_edits() {
        edits::<mmb::Family>();
    }

    #[test]
    fn historical_view_variable_values_and_wide_chunks() {
        type VariableDb = variable::Db<
            mmb::Family,
            deterministic::Context,
            Digest,
            UInt<u64>,
            Sha256,
            OneCap,
            64,
            Sequential,
        >;
        deterministic::Runner::default().start(|context| async move {
            let mut db = VariableDb::init(
                context.child("db"),
                variable_config::<OneCap>("variable-history", &context),
            )
            .await
            .unwrap();
            while db.bounds().end < 513 {
                let batch = db.new_batch().merkleize(&db, None).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            let key = Sha256::fill(2);
            let absent = Sha256::fill(3);
            let mut checkpoints = Vec::new();
            for value in [Some(UInt(0)), Some(UInt(128)), None, Some(UInt(u64::MAX))] {
                let batch = db
                    .new_batch()
                    .write(key, value.clone())
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                checkpoints.push((db.bounds().end, db.root(), value));
            }
            for (size, root, value) in checkpoints {
                let view = db.historical_view(size).await.unwrap();
                assert_eq!(view.root(), root);
                assert_eq!(view.get(&key), value.as_ref());
                if let Some(value) = value {
                    let proof = view.key_value_proof(key).await.unwrap();
                    assert!(VariableDb::verify_key_value_proof(
                        key, value, &proof, &root
                    ));
                } else {
                    let proof = view.exclusion_proof(&key).await.unwrap();
                    assert!(VariableDb::verify_exclusion_proof(&key, &proof, &root));
                }
                let proof = view.exclusion_proof(&absent).await.unwrap();
                assert!(VariableDb::verify_exclusion_proof(&absent, &proof, &root));
            }
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn historical_view_mmb_active_chunks() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = TestDb::<mmb::Family>::init(
                context.child("db"),
                fixed_config::<OneCap>("active-chunks", &context),
            )
            .await
            .unwrap();
            let keys: Vec<_> = (0u64..300)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .collect();
            let mut batch = db.new_batch();
            for &key in &keys {
                batch = batch.write(key, Some(key));
            }
            let batch = batch.merkleize(&db, None).await.unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            let mut checkpoints = vec![(db.bounds().end, db.root(), keys[0])];
            for i in 0u64..200 {
                let value = Sha256::hash(&[&i.to_le_bytes()]);
                let batch = db
                    .new_batch()
                    .write(keys[0], Some(value))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                if i % 25 == 0 {
                    checkpoints.push((db.bounds().end, db.root(), value));
                }
            }
            assert!(db.bounds().end > 768);
            for (size, root, value) in checkpoints {
                let view = db.historical_view(size).await.unwrap();
                assert_eq!(view.root(), root, "size {size}");
                for (key, value) in [
                    (keys[0], value),
                    (keys[150], keys[150]),
                    (keys[299], keys[299]),
                ] {
                    assert_eq!(view.get(&key), Some(&value));
                    let proof = view.key_value_proof(key).await.unwrap();
                    assert!(TestDb::<mmb::Family>::verify_key_value_proof(
                        key, value, &proof, &root
                    ));
                }
                let absent = Sha256::fill(0);
                let proof = view.exclusion_proof(&absent).await.unwrap();
                assert!(TestDb::<mmb::Family>::verify_exclusion_proof(
                    &absent, &proof, &root
                ));
            }
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn historical_view_rejects_pruned_floor_with_retained_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = TestDb::<mmb::Family>::init(
                context.child("db"),
                fixed_config::<OneCap>("pruned-floor", &context),
            )
            .await
            .unwrap();
            let keys: Vec<_> = (0u64..600)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .collect();
            let mut old_size = Location::new(0);
            let mut old_floor = Location::new(0);
            for round in 0..2 {
                let mut batch = db.new_batch();
                for &key in &keys {
                    batch = batch.write(key, Some(Sha256::fill(round)));
                }
                let batch = batch.merkleize(&db, None).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                if round == 0 {
                    old_size = db.bounds().end;
                    old_floor = db.inactivity_floor_loc();
                }
            }
            let boundary = Location::new((*old_floor / 256 + 1) * 256);
            assert!(boundary <= db.sync_boundary() && boundary < old_size);
            db = db.prune(boundary).await.unwrap();
            assert!(db.any.log.read(*old_size - 1).await.is_ok());
            assert!(matches!(
                db.historical_view(old_size).await,
                Err(Error::OperationPruned(_))
            ));
            assert_eq!(
                db.historical_view(db.bounds().end).await.unwrap().root(),
                db.root()
            );
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn historical_view_mmb_empty_boundaries_and_pruning() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = TestDb::<mmb::Family>::init(
                context.child("db"),
                fixed_config::<OneCap>("boundaries", &context),
            )
            .await
            .unwrap();
            let mut checkpoints = Vec::new();
            while db.bounds().end < 800 {
                let batch = db.new_batch().merkleize(&db, None).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                if [255, 256, 257, 382, 383, 384, 511, 512, 513, 766, 767, 768]
                    .contains(&*db.bounds().end)
                {
                    checkpoints.push((db.bounds().end, db.root()));
                }
            }
            assert_eq!(checkpoints.len(), 12);
            for &(size, root) in &checkpoints {
                let view = db.historical_view(size).await.unwrap();
                assert_eq!(view.root(), root, "size {size}");
                assert!(view.entries.is_empty());
                let key = Sha256::fill(7);
                let proof = view.exclusion_proof(&key).await.unwrap();
                assert!(
                    TestDb::<mmb::Family>::verify_exclusion_proof(&key, &proof, &root),
                    "size {size}"
                );
            }
            let boundary = db.sync_boundary();
            assert!(boundary > 256);
            db = db.prune(boundary).await.unwrap();
            assert!(db.historical_view(Location::new(256)).await.is_err());
            let (size, root) = *checkpoints.last().unwrap();
            let view = db.historical_view(size).await.unwrap();
            assert_eq!(view.root(), root);
            let proof = view.exclusion_proof(&Sha256::fill(7)).await.unwrap();
            assert!(TestDb::<mmb::Family>::verify_exclusion_proof(
                &Sha256::fill(7),
                &proof,
                &root
            ));
            drop(view);
            assert_eq!(
                db.historical_view(db.bounds().end).await.unwrap().root(),
                db.root()
            );
            db.destroy().await.unwrap();
        });
    }
}
