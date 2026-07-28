use crate::stateful::{
    Application, Input, Proposed,
    db::{ManagedDb, Merkleized, MerkleizedOf, SyncTargetsOf, Unmerkleized, UnmerkleizedOf},
};
use commonware_actor::Feedback;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, Reporter,
    marshal::{
        self, Update,
        ancestry::Ancestry,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::handler,
        standard::Standard,
    },
    simplex::{
        mocks::scheme as scheme_mocks,
        types::{Context as SimplexContext, Finalization},
    },
    types::{Epoch, FixedEpocher, Height, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digestible, Signer as _, certificate::ConstantProvider, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_resolver::{Fetch, Resolver, TargetedResolver};
use commonware_runtime::{
    Buf, BufMut, Error as RuntimeError, Handle, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::archive::{Archive as _, immutable};
use commonware_utils::{
    Acknowledgement as _, NZU16, NZU64, NZUsize, channel::oneshot, sync::Mutex, vec::NonEmptyVec,
};
use std::{convert::Infallible, marker::PhantomData, sync::Arc};

pub(crate) type TestDatabases = crate::stateful::db::Single<TestDb>;
pub(crate) type TestScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
pub(crate) type TestVariant = Standard<TestBlock>;

/// No-op batch for mock databases, parameterized by the owning database type
/// so every mock satisfies `ManagedDb::Unmerkleized: Unmerkleized<Db = Self>`.
pub(crate) struct TestUnmerkleized<D = TestDb>(PhantomData<fn(D)>);

pub(crate) struct TestMerkleized<D = TestDb>(PhantomData<fn(D)>);

impl<D> TestUnmerkleized<D> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<D> TestMerkleized<D> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<D> Clone for TestUnmerkleized<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D> Copy for TestUnmerkleized<D> {}

impl<D> Clone for TestMerkleized<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D> Copy for TestMerkleized<D> {}

impl<D: Send + Sync> Unmerkleized for TestUnmerkleized<D> {
    type Merkleized = TestMerkleized<D>;
    type Db = D;
    type Error = Infallible;

    async fn merkleize(self, _db: &Self::Db) -> Result<Self::Merkleized, Self::Error> {
        Ok(TestMerkleized::new())
    }
}

impl<D: Send + Sync> Merkleized for TestMerkleized<D> {
    type Digest = Sha256Digest;
    type Unmerkleized = TestUnmerkleized<D>;

    fn root(&self) -> Self::Digest {
        Sha256Digest::from([0; 32])
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized::new()
    }
}

#[derive(Default)]
pub(crate) struct TestDb;

impl<E: Send> ManagedDb<E> for TestDb {
    type Unmerkleized = TestUnmerkleized;
    type Merkleized = TestMerkleized;
    type Error = Infallible;
    type Config = ();
    type SyncTarget = u64;
    type Snapshot = ();

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
        Ok((self, ()))
    }

    fn initial_sync_target() -> Self::SyncTarget {
        unreachable!("TestDb is constructed directly in tests")
    }

    async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
        Ok(Self)
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized::new()
    }

    fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
        true
    }

    async fn finalize(
        self,
        _batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
        Ok((self, (), Handle::ready(Ok(()))))
    }

    fn sync_target(&self) -> Self::SyncTarget {
        0
    }

    async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestBlock {
    context: SimplexContext<Sha256Digest, ed25519::PublicKey>,
    height: Height,
    digest: Sha256Digest,
}

impl TestBlock {
    pub(crate) fn new(height: u64, digest_byte: u8) -> Self {
        Self {
            context: SimplexContext {
                round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), Sha256Digest::EMPTY),
            },
            height: Height::new(height),
            digest: Sha256Digest::from([digest_byte; 32]),
        }
    }
}

impl Write for TestBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        buf.put_u64(self.height.get());
        buf.put_slice(self.digest.as_ref());
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size() + 8 + 32
    }
}

impl Read for TestBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let context = SimplexContext::read(buf)?;
        let height = Height::new(buf.get_u64());
        let mut digest = [0u8; 32];
        buf.copy_to_slice(&mut digest);
        Ok(Self {
            context,
            height,
            digest: Sha256Digest::from(digest),
        })
    }
}

impl Digestible for TestBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for TestBlock {
    fn parent(&self) -> Self::Digest {
        Sha256Digest::EMPTY
    }
}

impl CertifiableBlock for TestBlock {
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

#[derive(Clone)]
pub(crate) struct TestApp;

impl<
    E: rand_core::Rng
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + Send
        + Sync,
> Application<E> for TestApp
{
    type SigningScheme = TestScheme;
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
    type Block = TestBlock;
    type Databases = TestDatabases;
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> SyncTargetsOf<Self::Databases, E> {
        block.height().get()
    }

    async fn genesis(&mut self) -> Self::Block {
        TestBlock::new(0, 0)
    }

    async fn propose(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        None
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Option<MerkleizedOf<Self::Databases, E>> {
        None
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> MerkleizedOf<Self::Databases, E> {
        TestMerkleized::new()
    }
}

pub(crate) fn test_databases() -> TestDatabases {
    TestDb.into()
}

pub(crate) fn anchor(height: u64, digest_byte: u8) -> crate::stateful::db::Anchor<Sha256Digest> {
    crate::stateful::db::Anchor {
        height: Height::new(height),
        round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
        digest: Sha256Digest::from([digest_byte; 32]),
    }
}

/// Completes one parked flush when released by the test.
pub(crate) type FlushRelease = oneshot::Sender<Result<(), RuntimeError>>;

/// Shared observer for [`GatedFlushDb`]: parked flush releases and
/// recorded prune targets.
#[derive(Clone, Default)]
pub(crate) struct FlushControl {
    pub(crate) flushes: Arc<Mutex<Vec<FlushRelease>>>,
    pub(crate) pruned: Arc<Mutex<Vec<u64>>>,
}

/// Database whose finalize flush completes only when the test releases it.
///
/// Its `prune` records immediately, eliding the impl-side barrier real
/// databases provide (pruning waits for pending flushes, pinned in
/// `stateful::db::any` tests), so the actor's own scheduling is exposed.
pub(crate) struct GatedFlushDb {
    pub(crate) control: FlushControl,
}

impl ManagedDb<deterministic::Context> for GatedFlushDb {
    type Unmerkleized = TestUnmerkleized<Self>;
    type Merkleized = TestMerkleized<Self>;
    type Error = Infallible;
    type Config = ();
    type SyncTarget = u64;
    type Snapshot = ();

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
        Ok((self, ()))
    }

    fn initial_sync_target() -> Self::SyncTarget {
        unreachable!("GatedFlushDb is constructed directly in tests")
    }

    async fn init(
        _context: deterministic::Context,
        _config: Self::Config,
    ) -> Result<Self, Self::Error> {
        unreachable!("GatedFlushDb is constructed directly in tests")
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized::new()
    }

    fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
        true
    }

    async fn finalize(
        self,
        _batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
        let (release, released) = oneshot::channel();
        self.control.flushes.lock().push(release);
        Ok((self, (), Handle::from_receiver(released)))
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Self::Error> {
        self.control.pruned.lock().push(*target);
        Ok(self)
    }

    fn sync_target(&self) -> Self::SyncTarget {
        0
    }

    async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
        Ok(self)
    }
}

/// Reporter for started marshal fixtures that acknowledges every dispatched block.
#[derive(Clone)]
pub(crate) struct NoopReporter;

impl Reporter for NoopReporter {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// Backfill resolver for started marshal fixtures: their archives are pre-seeded, so
/// every fetch is ignored.
#[derive(Clone)]
pub(crate) struct IgnoreResolver;

impl Resolver for IgnoreResolver {
    type Key = handler::Key<Sha256Digest>;
    type Subscriber = handler::Annotation;

    fn fetch<F>(&mut self, _key: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn fetch_all<F>(&mut self, _keys: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn retain(
        &mut self,
        _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        Feedback::Ok
    }
}

impl TargetedResolver for IgnoreResolver {
    type PublicKey = ed25519::PublicKey;

    fn fetch_targeted(
        &mut self,
        _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        Feedback::Ok
    }

    fn fetch_all_targeted<F>(&mut self, _keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }
}

/// Archive configuration for marshal test fixtures.
pub(crate) fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
    immutable::Config {
        metadata_partition: format!("{partition}-metadata"),
        freezer_table_partition: format!("{partition}-freezer-table"),
        freezer_table_initial_size: 4,
        freezer_table_resize_frequency: 2,
        freezer_table_resize_chunk_size: 2,
        freezer_key_partition: format!("{partition}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{partition}-freezer-value"),
        freezer_value_target_size: 128,
        freezer_value_compression: None,
        ordinal_partition: format!("{partition}-ordinal"),
        items_per_section: NZU64!(4),
        codec_config: (),
        replay_buffer: NZUsize!(64),
        freezer_key_write_buffer: NZUsize!(64),
        freezer_value_write_buffer: NZUsize!(64),
        ordinal_write_buffer: NZUsize!(64),
    }
}

/// Initializes a fresh genesis marshal and returns its mailbox without starting the
/// actor: queries needing the actor loop resolve to `None`.
pub(crate) async fn init_marshal_mailbox(
    mut context: deterministic::Context,
) -> MarshalMailbox<TestScheme, TestVariant> {
    let fixture = scheme_mocks::fixture(&mut context, b"marshal-harness", 1);
    let provider = ConstantProvider::new(fixture.schemes[0].clone());
    let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
    let finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config(page_cache.clone(), "marshal-finalizations"),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        archive_config(page_cache.clone(), "marshal-blocks"),
    )
    .await
    .expect("failed to initialize blocks archive");

    let (_actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
        context.child("marshal_actor"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider,
            epocher: FixedEpocher::new(NZU64!(u64::MAX)),
            start: marshal::Start::Genesis(TestBlock::new(0, 0)),
            partition_prefix: "marshal-harness".to_string(),
            mailbox_size: NZUsize!(8),
            view_retention: ViewDelta::new(1),
            prunable_items_per_section: NZU64!(4),
            page_cache,
            replay_buffer: NZUsize!(64),
            key_write_buffer: NZUsize!(64),
            value_write_buffer: NZUsize!(64),
            block_codec_config: (),
            max_repair: NZUsize!(1),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;
    mailbox
}

/// Initializes a genesis marshal, optionally pre-seeding `block`'s finalization, then
/// starts it so queries are served without any peer fetching. The returned handler and
/// handle must stay alive for the marshal to keep running.
pub(crate) async fn start_marshal(
    context: deterministic::Context,
    scheme: TestScheme,
    block: &TestBlock,
    finalization: Option<Finalization<TestScheme, Sha256Digest>>,
) -> (
    MarshalMailbox<TestScheme, TestVariant>,
    handler::Handler<Sha256Digest>,
    Handle<()>,
) {
    let provider = ConstantProvider::new(scheme);
    let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
    let mut finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config(page_cache.clone(), "marshal-finalizations"),
    )
    .await
    .expect("failed to initialize finalizations archive");
    if let Some(finalization) = finalization {
        finalizations_by_height = finalizations_by_height
            .put(block.height().get(), block.digest(), finalization)
            .await
            .expect("failed to seed finalization")
            .sync()
            .await
            .expect("failed to sync finalizations archive");
    }
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        archive_config(page_cache.clone(), "marshal-blocks"),
    )
    .await
    .expect("failed to initialize blocks archive");

    let (actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
        context.child("marshal_actor"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider,
            epocher: FixedEpocher::new(NZU64!(u64::MAX)),
            start: marshal::Start::Genesis(TestBlock::new(0, 0)),
            partition_prefix: "marshal-harness".to_string(),
            mailbox_size: NZUsize!(8),
            view_retention: ViewDelta::new(1),
            prunable_items_per_section: NZU64!(4),
            page_cache,
            replay_buffer: NZUsize!(64),
            key_write_buffer: NZUsize!(64),
            value_write_buffer: NZUsize!(64),
            block_codec_config: (),
            max_repair: NZUsize!(1),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;
    let (resolver_receiver, resolver_handler) =
        handler::init(context.child("resolver_handler"), NZUsize!(8));
    let handle = actor.start_unbuffered(NoopReporter, (resolver_receiver, IgnoreResolver));
    (mailbox, resolver_handler, handle)
}
