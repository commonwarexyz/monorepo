//! [`ManagedDb`] implementations for compact QMDBs.

use crate::stateful::db::{
    BatchContext, InitError, ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized as UnmerkleizedTrait, sync_compact_db, validate_initialization,
};
use commonware_codec::Read as CodecRead;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        compact::{Config, Db, MerkleizedBatch, Operation, UnmerkleizedBatch, initial_root},
        sync,
    },
};
use commonware_utils::channel::mpsc;
use std::{ops::Deref, sync::Arc};

/// Wraps a compact batch before merkleization.
pub struct CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    pub(super) batch: UnmerkleizedBatch<F, H, O, S>,
    db: Shared<Db<F, E, O, H, S>>,
    metadata: Option<O::Metadata>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, O, H, S> Deref for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = UnmerkleizedBatch<F, H, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, O, H, S> CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    /// Set commit metadata included in the next merkleization.
    pub fn with_metadata(mut self, metadata: O::Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor included in the next merkleization.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }
}

impl<F, E, O, H, S> UnmerkleizedTrait for CompactUnmerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self
            .batch
            .merkleize(
                &db,
                self.metadata,
                self.inactivity_floor.unwrap_or_default(),
            )
            .await;
        Ok(CompactMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

/// Wraps a compact batch after merkleization.
pub struct CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    inner: Arc<MerkleizedBatch<F, H::Digest, O, S>>,
    db: Shared<Db<F, E, O, H, S>>,
}

impl<F, E, O, H, S> Clone for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            db: self.db.clone(),
        }
    }
}

impl<F, E, O, H, S> Deref for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Target = MerkleizedBatch<F, H::Digest, O, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, O, H, S> MerkleizedTrait for CompactMerkleized<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        CompactUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, O, H, S> ManagedDb<E> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    type Unmerkleized = CompactUnmerkleized<F, E, O, H, S>;
    type Merkleized = CompactMerkleized<F, E, O, H, S>;
    type Error = Error<F>;
    type Config = Config<<O as CodecRead>::Cfg, S>;
    type SyncTarget = sync::CompactTarget<F, H::Digest>;

    async fn init(
        context: E,
        config: Self::Config,
        expected: Option<Self::SyncTarget>,
    ) -> Result<Self, InitError<Error<F>, Self::SyncTarget>> {
        let db = <Self>::init(context, config, expected.as_ref().map(|target| target.size))
            .await
            .map_err(InitError::Database)?;
        validate_initialization(db, expected)
    }

    fn initial_sync_target() -> Self::SyncTarget {
        sync::CompactTarget {
            root: initial_root::<F, O, H>(),
            size: Location::new(1),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> Self::Unmerkleized {
        let (database, shared) = database.into_parts();
        CompactUnmerkleized {
            batch: database.new_batch(),
            db: shared,
            metadata: None,
            inactivity_floor: None,
        }
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.root() == target.root && target.size == batch.bounds().tip.size
    }

    async fn apply(self, batch: Self::Merkleized) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch.inner).await?;
        Ok(db)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Error<F>> {
        Self::prune(self, target.size).await
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target()
    }
}

impl<F, E, O, H, S, R> StateSyncDb<E, R> for Db<F, E, O, H, S>
where
    F: Family,
    E: Context + Spawner,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
    R: sync::SourceFor<Self>,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        source: R,
        target: Self::SyncTarget,
        tip_updates: mpsc::Receiver<Self::SyncTarget>,
        finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        sync_compact_db(
            context,
            config,
            source,
            target,
            tip_updates,
            finish,
            reached_target,
            sync_config,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::variable::Config as JournalConfig,
        merkle::{mmb, mmr},
        qmdb::{immutable, keyless, verify_proof_and_pinned_nodes},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};

    type TestDb<F, O> = Db<F, deterministic::Context, O, Sha256, Sequential>;
    type TestBatch<F, O> = UnmerkleizedBatch<F, Sha256, O, Sequential>;

    fn bounded_initialization<F, O>(
        codec_config: O::Cfg,
        mutate: impl Fn(TestBatch<F, O>, u64) -> TestBatch<F, O>,
        metadata: impl Fn(u64) -> O::Metadata,
    ) where
        F: Family,
        O: Operation<F, Metadata: PartialEq + std::fmt::Debug>,
    {
        deterministic::Runner::default().start(|context| async move {
            let cfg = Config {
                strategy: Sequential,
                witness: JournalConfig {
                    partition: "compact-initialization-matrix".into(),
                    items_per_section: NZU64!(1),
                    compression: None,
                    codec_config,
                    page_cache: CacheRef::from_pooler(&context, NZU16!(101), NZUsize!(11)),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            };
            let db = <TestDb<F, O> as ManagedDb<_>>::init(context.child("seed"), cfg.clone(), None).await.unwrap();
            let batch = mutate(mutate(mutate(db.new_batch(), 1), 2), 3)
                .merkleize(&db, Some(metadata(11)), Location::new(0)).await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let first = db.target();
            assert_eq!(first.size, Location::new(5));
            let batch = mutate(db.new_batch(), 4).merkleize(&db, Some(metadata(22)), Location::new(1)).await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let latest = db.target();
            drop(db);

            let mut wrong_root = latest.clone();
            wrong_root.root = Sha256::fill(0xff);
            assert!(matches!(
                <TestDb<F, O> as ManagedDb<_>>::init(context.child("wrong_root"), cfg.clone(), Some(wrong_root.clone())).await,
                Err(InitError::TargetMismatch { expected, recovered }) if expected == wrong_root && recovered == latest
            ));
            // A cap inside a batch selects the preceding commit, but is not an exact sync target.
            let mut between = first.clone();
            between.size += 1;
            assert!(matches!(
                <TestDb<F, O> as ManagedDb<_>>::init(context.child("between"), cfg.clone(), Some(between.clone())).await,
                Err(InitError::TargetMismatch { expected, recovered }) if expected == between && recovered == first
            ));
            let db = <TestDb<F, O> as ManagedDb<_>>::init(context.child("exact"), cfg.clone(), Some(first.clone())).await.unwrap();
            assert_eq!(db.get_metadata(), Some(metadata(11)));
            assert_eq!(db.inactivity_floor_loc(), Location::new(0));
            let (response, _) = sync::Source::serve(&db, sync::Request::Boundary { size: first.size, start: first.size - 1 }).await.unwrap();
            let sync::Response::Boundary { proof, op, pinned_nodes } = response else { panic!("expected boundary response") };
            assert!(verify_proof_and_pinned_nodes::<Sha256, _, _>(&proof, first.size - 1, &[op], &pinned_nodes, &first.root));
            drop(db);
            let db = TestDb::<F, O>::init(context.child("reopen"), cfg.clone(), None).await.unwrap();
            assert_eq!(db.target(), first);

            let batch = mutate(db.new_batch(), 5).merkleize(&db, Some(metadata(33)), first.size - 1).await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let latest = db.target();
            let db = db.prune(latest.size).await.unwrap();
            drop(db);
            assert!(matches!(
                <TestDb<F, O> as ManagedDb<_>>::init(context.child("pruned"), cfg.clone(), Some(first)).await,
                Err(InitError::Database(Error::HistoricalFloorPruned(_)))
            ));
            let db = <TestDb<F, O> as ManagedDb<_>>::init(context.child("latest"), cfg, Some(latest)).await.unwrap();
            assert_eq!(db.get_metadata(), Some(metadata(33)));
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_fixed_mmr() {
        bounded_initialization::<mmr::Family, keyless::fixed::Operation<mmr::Family, U64>>(
            (),
            |batch, seed| batch.append(U64::new(seed)),
            U64::new,
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_variable_mmr() {
        bounded_initialization::<mmr::Family, keyless::variable::Operation<mmr::Family, Vec<u8>>>(
            ((..).into(), ()),
            |batch, seed| batch.append(seed.to_le_bytes().to_vec()),
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_fixed_mmr() {
        bounded_initialization::<
            mmr::Family,
            immutable::fixed::Operation<mmr::Family, Digest, Digest>,
        >(
            (),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    Sha256::hash(&[&seed.to_le_bytes()]),
                )
            },
            |seed| Sha256::hash(&[&seed.to_le_bytes()]),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_variable_mmr() {
        bounded_initialization::<
            mmr::Family,
            immutable::variable::Operation<mmr::Family, Digest, Vec<u8>>,
        >(
            ((), ((..).into(), ())),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    seed.to_le_bytes().to_vec(),
                )
            },
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_fixed_mmb() {
        bounded_initialization::<mmb::Family, keyless::fixed::Operation<mmb::Family, U64>>(
            (),
            |batch, seed| batch.append(U64::new(seed)),
            U64::new,
        );
    }

    #[test]
    fn test_compact_bounded_initialization_keyless_variable_mmb() {
        bounded_initialization::<mmb::Family, keyless::variable::Operation<mmb::Family, Vec<u8>>>(
            ((..).into(), ()),
            |batch, seed| batch.append(seed.to_le_bytes().to_vec()),
            |seed| seed.to_le_bytes().to_vec(),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_fixed_mmb() {
        bounded_initialization::<
            mmb::Family,
            immutable::fixed::Operation<mmb::Family, Digest, Digest>,
        >(
            (),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    Sha256::hash(&[&seed.to_le_bytes()]),
                )
            },
            |seed| Sha256::hash(&[&seed.to_le_bytes()]),
        );
    }

    #[test]
    fn test_compact_bounded_initialization_immutable_variable_mmb() {
        bounded_initialization::<
            mmb::Family,
            immutable::variable::Operation<mmb::Family, Digest, Vec<u8>>,
        >(
            ((), ((..).into(), ())),
            |batch, seed| {
                batch.set(
                    Sha256::hash(&[&seed.to_be_bytes()]),
                    seed.to_le_bytes().to_vec(),
                )
            },
            |seed| seed.to_le_bytes().to_vec(),
        );
    }
}
