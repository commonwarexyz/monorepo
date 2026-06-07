use crate::stateful::{
    db::{Anchor, DatabaseSet},
    Application,
};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    marshal::{
        core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant},
        Identifier,
    },
    simplex::types::Finalization,
    types::Height,
    Block as ConsensusBlock, CertifiableBlock, Heightable, Roundable,
};
use commonware_cryptography::{certificate::Scheme, Digest, Digestible};
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use rand::Rng;
use std::future::Future;

mod actor;
pub(crate) use actor::{Config, Syncer};

mod mailbox;
pub(crate) use mailbox::Mailbox;

mod plan;
pub use plan::SyncPlan;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_STATE_KEY: FixedBytes<1> = fixed_bytes!("C0");

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Durable identity for an in-progress state sync floor.
///
/// The height enforces monotonic restarts, and the commitment distinguishes
/// conflicting blocks at the same height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FloorMarker<C>
where
    C: Digest,
{
    height: Height,
    commitment: C,
}

impl<C> FloorMarker<C>
where
    C: Digest,
{
    /// Constructs a durable floor marker from the resolved floor block.
    pub(crate) const fn new(height: Height, commitment: C) -> Self {
        Self { height, commitment }
    }

    /// Ensures a newly selected floor is compatible with this persisted one.
    ///
    /// Restarts may resume from the same floor or advance to a newer one, but
    /// must never move backward or switch to a different block at the same height.
    pub(crate) fn ensure_not_behind(&self, selected: &Self) {
        assert!(
            selected.height >= self.height,
            "selected state sync floor cannot move behind the persisted in-progress floor",
        );

        if selected.height == self.height {
            assert!(
                selected.commitment == self.commitment,
                "selected state sync floor conflicts with the persisted in-progress floor",
            );
        }
    }
}

impl<C> Write for FloorMarker<C>
where
    C: Digest,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.height.write(writer);
        self.commitment.write(writer);
    }
}

impl<C> EncodeSize for FloorMarker<C>
where
    C: Digest,
{
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.commitment.encode_size()
    }
}

impl<C> Read for FloorMarker<C>
where
    C: Digest,
{
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            height: Height::read(reader)?,
            commitment: C::read_cfg(reader, &())?,
        })
    }
}

/// Durable sync progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncState<C>
where
    C: Digest,
{
    InProgress(FloorMarker<C>),
    Complete(Height),
}

impl<C> SyncState<C>
where
    C: Digest,
{
    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) const fn sync_height(&self) -> Option<Height> {
        match self {
            Self::InProgress(_) => None,
            Self::Complete(height) => Some(*height),
        }
    }
}

impl<C> Write for SyncState<C>
where
    C: Digest,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::InProgress(floor) => {
                0u8.write(writer);
                floor.write(writer);
            }
            Self::Complete(height) => {
                1u8.write(writer);
                height.write(writer);
            }
        }
    }
}

impl<C> EncodeSize for SyncState<C>
where
    C: Digest,
{
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::InProgress(floor) => floor.encode_size(),
                Self::Complete(height) => height.encode_size(),
            }
    }
}

impl<C> Read for SyncState<C>
where
    C: Digest,
{
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::InProgress(FloorMarker::<C>::read(reader)?)),
            1 => Ok(Self::Complete(Height::read(reader)?)),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

/// The result of a state sync operation.
pub struct SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The database handle set.
    pub databases: A::Databases,
    /// The anchor at which state sync completed.
    pub anchor: Anchor<BlockDigest<A, E>>,
}

impl<E, A> Clone for SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            databases: self.databases.clone(),
            anchor: self.anchor,
        }
    }
}

/// Resolved state sync floor data derived from the selected finalization.
pub(crate) struct ResolvedFloor<E, A, C>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    C: Digest,
{
    pub anchor: Anchor<BlockDigest<A, E>>,
    pub targets: <A::Databases as DatabaseSet<E>>::SyncTargets,
    pub marker: FloorMarker<C>,
}

/// Durable state-sync metadata.
pub(crate) struct StateSyncMetadata<E, C>
where
    E: Storage + Clock + Metrics,
    C: Digest,
{
    partition_prefix: String,
    metadata: Metadata<E, FixedBytes<1>, SyncState<C>>,
}

impl<E, C> StateSyncMetadata<E, C>
where
    E: Storage + Clock + Metrics,
    C: Digest,
{
    /// Load the durable state-sync metadata partition, creating it if needed.
    pub(crate) async fn init(context: &E, partition_prefix: impl AsRef<str>) -> Self {
        let partition_prefix = partition_prefix.as_ref().to_string();
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to load sync metadata");
        Self {
            partition_prefix,
            metadata,
        }
    }

    /// Returns the partition prefix for this state-sync metadata store.
    pub(crate) const fn partition_prefix(&self) -> &str {
        self.partition_prefix.as_str()
    }

    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) fn sync_height(&self) -> Option<Height> {
        self.metadata
            .get(&SYNC_STATE_KEY)
            .map(SyncState::sync_height)
            .unwrap_or_default()
    }

    /// Returns whether state sync is in progress.
    pub(crate) fn in_progress(&self) -> bool {
        matches!(
            self.metadata.get(&SYNC_STATE_KEY),
            Some(SyncState::InProgress(_))
        )
    }

    /// Marks state sync as in progress for the resolved floor.
    ///
    /// This must be persisted before any state sync database mutation begins so the database
    /// sync engine can reopen partial sync state and validate the next selected floor after a crash.
    ///
    /// If an interrupted state sync already stored a floor, the newly selected
    /// floor must resume from that same floor or a later one.
    pub(crate) async fn begin_sync(&mut self, floor: FloorMarker<C>) {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(existing)) => {
                existing.ensure_not_behind(&floor);
            }
            Some(SyncState::Complete(_)) => {
                panic!("completed state sync cannot be marked in-progress");
            }
            None => {}
        }

        self.metadata
            .put_sync(SYNC_STATE_KEY, SyncState::InProgress(floor))
            .await
            .expect("failed to set state sync state to in-progress");
    }

    /// Records that one-time state sync completed at the given height.
    ///
    /// Once this height is set, future startups skip peer state sync and initialize
    /// from the later of this height and marshal's processed height instead. This
    /// action is irreversible.
    pub(crate) async fn set_complete(&mut self, height: Height) {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(floor)) => {
                assert!(
                    height >= floor.height,
                    "completed state sync height cannot be behind the in-progress floor",
                );
            }
            Some(SyncState::Complete(existing)) => {
                assert!(
                    height >= *existing,
                    "completed state sync height cannot move backward",
                );
            }
            None => {}
        }

        self.metadata
            .put_sync(SYNC_STATE_KEY, SyncState::<C>::Complete(height))
            .await
            .expect("failed to set state sync state to complete");
    }
}

/// Resolves the selected state sync floor into the anchor, targets, and
/// durable floor marker used by restart validation.
pub(crate) async fn resolve_state_sync_floor<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    finalization: &Finalization<S, V::Commitment>,
) -> ResolvedFloor<E, A, V::Commitment>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    // Wait to retrieve the floor block from marshal. We use `Wait` here,
    // since marshal triggers a fetch for the floor block if it is not
    // already available.
    let floor = {
        let block = marshal
            .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
            .await
            .expect("marshal must yield floor block");
        V::into_inner(block)
    };

    ResolvedFloor {
        anchor: Anchor::from(&floor),
        targets: A::sync_targets(&floor),
        marker: FloorMarker::new(floor.height(), finalization.proposal.payload),
    }
}

/// The result of initializing state from marshal on startup.
pub(crate) struct StartupResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The initialized database set and anchor.
    pub sync: SyncResult<E, A>,

    /// Finalized marshal blocks at or below this height are already reflected
    /// in the initialized database set and should be acknowledged without
    /// applying them again.
    pub skip_finalized_until: Option<Height>,
}

/// Initializes databases at marshal's current startup anchor.
///
/// This initialization route is used when startup should recover from marshal
/// instead of running peer state sync. If marshal has not yet recorded a
/// processed height, this falls back to marshal's genesis block so fresh boots
/// and post-sync restarts share the same path.
///
/// If the databases are found to be inconsistent with the marshal floor, this
/// function will attempt to repair by rewinding the databases which are ahead. If the
/// databases are entirely inconsistent, this function will panic.
pub(crate) async fn init_databases_from_marshal<E, A, S, V>(
    context: &E,
    application: &mut A,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    mut sync_metadata: StateSyncMetadata<E, V::Commitment>,
) -> StartupResult<E, A>
where
    E: Rng + Storage + Spawner + Clock + Metrics,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let sync_height = sync_metadata.sync_height();
    let processed_height = marshal.get_processed_height().await;
    let skip_finalized_until = match (sync_height, processed_height) {
        (Some(sync_height), Some(processed_height)) if processed_height < sync_height => {
            Some(sync_height)
        }
        (Some(sync_height), None) => Some(sync_height),
        _ => None,
    };
    let marshal_floor = sync_height
        .into_iter()
        .chain(processed_height)
        .max()
        .unwrap_or_else(Height::zero);
    let floor_block = {
        let marshal_block = marshal
            .get_block(Identifier::Height(marshal_floor))
            .await
            .expect("marshal must return floor block");
        V::into_inner(marshal_block)
    };

    let databases = A::Databases::init(context.child("db_set"), db_config).await;
    let floor_block = replay_databases_to_marshal_floor::<E, A, _, _>(
        context,
        application,
        &databases,
        floor_block,
        {
            let marshal = marshal.clone();
            move |height| {
                let marshal = marshal.clone();
                async move {
                    marshal
                        .get_block(Identifier::Height(height))
                        .await
                        .map(V::into_inner)
                }
            }
        },
    )
    .await;

    // Once startup has aligned databases with marshal, future boots should skip peer
    // state sync and recover from the later of this anchor and marshal's durable
    // processed height.
    sync_metadata.set_complete(floor_block.height()).await;

    let anchor = Anchor {
        height: floor_block.height(),
        round: floor_block.context().round(),
        digest: floor_block.digest(),
    };
    StartupResult {
        sync: SyncResult { databases, anchor },
        skip_finalized_until,
    }
}

async fn replay_databases_to_marshal_floor<E, A, G, Fut>(
    context: &E,
    application: &mut A,
    databases: &A::Databases,
    floor_block: A::Block,
    mut get_block: G,
) -> A::Block
where
    E: Rng + Storage + Spawner + Clock + Metrics,
    A: Application<E>,
    G: FnMut(Height) -> Fut,
    Fut: Future<Output = Option<A::Block>> + Send,
{
    let floor_height = floor_block.height();
    let floor_targets = A::sync_targets(&floor_block);
    let committed_targets = databases.committed_targets().await;
    if committed_targets == floor_targets {
        return floor_block;
    }

    let mut cursor = floor_block;
    let found_replay_anchor = loop {
        if A::sync_targets(&cursor) == committed_targets {
            break true;
        }
        let Some(previous_height) = cursor.height().previous() else {
            break false;
        };
        let Some(previous) = get_block(previous_height).await else {
            break false;
        };
        cursor = previous;
    };
    if !found_replay_anchor {
        let anchor_targets = A::sync_targets(&cursor);
        databases.rewind_to_targets(anchor_targets.clone()).await;
        let recovered_targets = databases.committed_targets().await;
        assert!(
            recovered_targets == anchor_targets,
            "databases must be consistent with marshal recovery anchor after rewind",
        );
    }
    let mut previous = cursor;
    let mut height = previous.height().next();
    while height <= floor_height {
        let block = get_block(height)
            .await
            .expect("marshal must retain blocks after the database recovery anchor");
        assert_eq!(
            block.parent(),
            previous.digest(),
            "marshal recovery blocks must be contiguous",
        );

        let targets = A::sync_targets(&block);
        let batches = databases.new_batches().await;
        let merkleized = application
            .apply(
                (context.child("startup_replay"), block.context()),
                &block,
                batches,
            )
            .await;
        assert!(
            A::Databases::matches_sync_targets(&merkleized, &targets),
            "startup replay state root must match block commitments",
        );
        databases.finalize(merkleized).await;

        previous = block;
        height = height.next();
    }

    let recovered_targets = databases.committed_targets().await;
    assert!(
        recovered_targets == floor_targets,
        "databases must be consistent with marshal floor after startup replay",
    );
    previous
}

#[cfg(test)]
mod tests {
    use super::replay_databases_to_marshal_floor;
    use crate::stateful::{
        db::{DatabaseSet, ManagedDb, Merkleized, Unmerkleized},
        Application, Proposed,
    };
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        simplex::{mocks::scheme as scheme_mocks, types::Context as ConsensusContext},
        types::{Epoch, Height, Round, View},
        Block as ConsensusBlock, CertifiableBlock, Heightable,
    };
    use commonware_cryptography::{
        ed25519, sha256::Digest as Sha256Digest, Digestible, Signer as _,
    };
    use commonware_runtime::{deterministic, Buf, BufMut, Runner as _};
    use commonware_utils::sync::AsyncRwLock;
    use futures::Stream;
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    type TestContext = ConsensusContext<Sha256Digest, ed25519::PublicKey>;
    type ReplayDatabases = Arc<AsyncRwLock<ReplayDb>>;

    #[derive(Clone, Copy)]
    struct ReplayUnmerkleized;

    #[derive(Clone, Copy)]
    struct ReplayMerkleized {
        target: u64,
    }

    impl Unmerkleized for ReplayUnmerkleized {
        type Merkleized = ReplayMerkleized;
        type Error = Infallible;

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(ReplayMerkleized { target: 0 })
        }
    }

    impl Merkleized for ReplayMerkleized {
        type Digest = Sha256Digest;
        type Unmerkleized = ReplayUnmerkleized;

        fn root(&self) -> Self::Digest {
            digest(self.target)
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            ReplayUnmerkleized
        }
    }

    struct ReplayDb {
        target: u64,
        rewind_count: Arc<AtomicUsize>,
    }

    impl ReplayDb {
        fn new(target: u64, rewind_count: Arc<AtomicUsize>) -> Self {
            Self {
                target,
                rewind_count,
            }
        }
    }

    impl ManagedDb<deterministic::Context> for ReplayDb {
        type Unmerkleized = ReplayUnmerkleized;
        type Merkleized = ReplayMerkleized;
        type Error = Infallible;
        type Config = (u64, Arc<AtomicUsize>);
        type SyncTarget = u64;

        async fn init(
            _context: deterministic::Context,
            config: Self::Config,
        ) -> Result<Self, Self::Error> {
            Ok(Self::new(config.0, config.1))
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            ReplayUnmerkleized
        }

        fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
            batch.target == *target
        }

        async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Self::Error> {
            self.target = batch.target;
            Ok(())
        }

        async fn persist(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            self.target
        }

        async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Self::Error> {
            self.rewind_count.fetch_add(1, Ordering::SeqCst);
            self.target = target;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ReplayApp {
        replay_count: Arc<AtomicUsize>,
    }

    impl Application<deterministic::Context> for ReplayApp {
        type SigningScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = ReplayBlock;
        type Databases = ReplayDatabases;
        type InputProvider = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            ReplayBlock::new(Height::zero(), Sha256Digest::from([0; 32]))
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            None
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            self.replay_count.fetch_add(1, Ordering::SeqCst);
            ReplayMerkleized {
                target: block.height().get(),
            }
        }
    }

    #[derive(Clone)]
    struct TupleReplayApp {
        replay_count: Arc<AtomicUsize>,
    }

    impl Application<deterministic::Context> for TupleReplayApp {
        type SigningScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = ReplayBlock;
        type Databases = (Arc<AsyncRwLock<ReplayDb>>, Arc<AsyncRwLock<ReplayDb>>);
        type InputProvider = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            let target = block.height().get();
            (target, target)
        }

        async fn genesis(&mut self) -> Self::Block {
            ReplayBlock::new(Height::zero(), Sha256Digest::from([0; 32]))
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            None
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            self.replay_count.fetch_add(1, Ordering::SeqCst);
            let target = block.height().get();
            (ReplayMerkleized { target }, ReplayMerkleized { target })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReplayBlock {
        context: TestContext,
        parent: Sha256Digest,
        height: Height,
        digest: Sha256Digest,
    }

    impl ReplayBlock {
        fn new(height: Height, parent: Sha256Digest) -> Self {
            Self {
                context: TestContext {
                    round: Round::new(Epoch::zero(), View::new(height.get())),
                    leader: ed25519::PrivateKey::from_seed(0).public_key(),
                    parent: (
                        height
                            .previous()
                            .map_or(View::zero(), |height| View::new(height.get())),
                        parent,
                    ),
                },
                parent,
                height,
                digest: digest(height.get()),
            }
        }
    }

    impl Write for ReplayBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.context.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.digest.write(buf);
        }
    }

    impl EncodeSize for ReplayBlock {
        fn encode_size(&self) -> usize {
            self.context.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.digest.encode_size()
        }
    }

    impl Read for ReplayBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                context: TestContext::read(buf)?,
                parent: Sha256Digest::read(buf)?,
                height: Height::read(buf)?,
                digest: Sha256Digest::read(buf)?,
            })
        }
    }

    impl Digestible for ReplayBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl Heightable for ReplayBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl ConsensusBlock for ReplayBlock {
        fn parent(&self) -> Self::Digest {
            self.parent
        }
    }

    impl CertifiableBlock for ReplayBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    fn digest(value: u64) -> Sha256Digest {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Sha256Digest::from(bytes)
    }

    fn retained_blocks(from: u64, to: u64) -> BTreeMap<Height, ReplayBlock> {
        let mut blocks = BTreeMap::new();
        let mut parent = if from == 0 {
            Sha256Digest::from([0; 32])
        } else {
            digest(from - 1)
        };
        for height in from..=to {
            let block = ReplayBlock::new(Height::new(height), parent);
            parent = block.digest();
            blocks.insert(block.height(), block);
        }
        blocks
    }

    #[test]
    fn startup_replay_rederives_processed_floor_from_retained_blocks() {
        deterministic::Runner::default().start(|context| async move {
            let replay_count = Arc::new(AtomicUsize::new(0));
            let rewind_count = Arc::new(AtomicUsize::new(0));
            let databases = Arc::new(AsyncRwLock::new(ReplayDb {
                target: 2,
                rewind_count: rewind_count.clone(),
            }));
            let blocks = Arc::new(retained_blocks(2, 5));
            let floor = blocks
                .get(&Height::new(5))
                .expect("floor block should exist")
                .clone();
            let mut app = ReplayApp {
                replay_count: replay_count.clone(),
            };

            let recovered = replay_databases_to_marshal_floor::<_, ReplayApp, _, _>(
                &context,
                &mut app,
                &databases,
                floor,
                {
                    let blocks = blocks.clone();
                    move |height| {
                        let blocks = blocks.clone();
                        async move { blocks.get(&height).cloned() }
                    }
                },
            )
            .await;

            assert_eq!(recovered.height(), Height::new(5));
            assert_eq!(databases.read().await.target, 5);
            assert_eq!(
                replay_count.load(Ordering::SeqCst),
                3,
                "startup should replay every block after the durable database boundary",
            );
            assert_eq!(
                rewind_count.load(Ordering::SeqCst),
                0,
                "database should not rewind when it matches a retained marshal ancestor",
            );
        });
    }

    #[test]
    fn startup_replay_rewinds_to_retained_anchor_before_replay() {
        deterministic::Runner::default().start(|context| async move {
            let replay_count = Arc::new(AtomicUsize::new(0));
            let rewind_count = Arc::new(AtomicUsize::new(0));
            let databases = Arc::new(AsyncRwLock::new(ReplayDb {
                target: 99,
                rewind_count: rewind_count.clone(),
            }));
            let blocks = Arc::new(retained_blocks(2, 5));
            let floor = blocks
                .get(&Height::new(5))
                .expect("floor block should exist")
                .clone();
            let mut app = ReplayApp {
                replay_count: replay_count.clone(),
            };

            let recovered = replay_databases_to_marshal_floor::<_, ReplayApp, _, _>(
                &context,
                &mut app,
                &databases,
                floor,
                {
                    let blocks = blocks.clone();
                    move |height| {
                        let blocks = blocks.clone();
                        async move { blocks.get(&height).cloned() }
                    }
                },
            )
            .await;

            assert_eq!(recovered.height(), Height::new(5));
            assert_eq!(databases.read().await.target, 5);
            assert_eq!(
                rewind_count.load(Ordering::SeqCst),
                1,
                "startup should rewind inconsistent database state to the retained anchor",
            );
            assert_eq!(
                replay_count.load(Ordering::SeqCst),
                3,
                "startup should replay from the retained anchor to the processed floor",
            );
        });
    }

    #[test]
    fn startup_replay_rewinds_misaligned_database_set_before_replay() {
        deterministic::Runner::default().start(|context| async move {
            let replay_count = Arc::new(AtomicUsize::new(0));
            let left_rewind_count = Arc::new(AtomicUsize::new(0));
            let right_rewind_count = Arc::new(AtomicUsize::new(0));
            let databases = (
                Arc::new(AsyncRwLock::new(ReplayDb {
                    target: 2,
                    rewind_count: left_rewind_count.clone(),
                })),
                Arc::new(AsyncRwLock::new(ReplayDb {
                    target: 99,
                    rewind_count: right_rewind_count.clone(),
                })),
            );
            let blocks = Arc::new(retained_blocks(2, 5));
            let floor = blocks
                .get(&Height::new(5))
                .expect("floor block should exist")
                .clone();
            let mut app = TupleReplayApp {
                replay_count: replay_count.clone(),
            };

            let recovered = replay_databases_to_marshal_floor::<_, TupleReplayApp, _, _>(
                &context,
                &mut app,
                &databases,
                floor,
                {
                    let blocks = blocks.clone();
                    move |height| {
                        let blocks = blocks.clone();
                        async move { blocks.get(&height).cloned() }
                    }
                },
            )
            .await;

            assert_eq!(recovered.height(), Height::new(5));
            assert_eq!(databases.0.read().await.target, 5);
            assert_eq!(databases.1.read().await.target, 5);
            assert_eq!(
                left_rewind_count.load(Ordering::SeqCst),
                0,
                "aligned database should not rewind",
            );
            assert_eq!(
                right_rewind_count.load(Ordering::SeqCst),
                1,
                "misaligned database should rewind to the retained anchor",
            );
            assert_eq!(
                replay_count.load(Ordering::SeqCst),
                3,
                "startup should replay the full database set to the processed floor",
            );
        });
    }
}
