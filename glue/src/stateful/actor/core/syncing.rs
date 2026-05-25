use crate::stateful::{
    actor::{
        core::{
            mailbox::{ErasedAncestorStream, Message},
            processing::Processing,
        },
        processor::{FinalizeStatus, Processor, ProcessorMetrics},
        syncer::{self, SyncResult},
    },
    db::{Anchor, AttachableResolverSet},
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, Storage};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    Acknowledgement,
};
use rand::Rng;
use tracing::{debug, error};

/// Verify request buffered while startup sync is still in progress.
pub(super) struct HeldVerify<C, B> {
    context: C,
    ancestry: ErasedAncestorStream<B>,
    response: oneshot::Sender<bool>,
}

type HeldVerifyRequest<E, A> =
    HeldVerify<(E, <A as Application<E>>::Context), <A as Application<E>>::Block>;

pub(super) struct Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Inner application.
    pub(super) application: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal actor mailbox.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// Prefix for durable state-sync metadata.
    pub(super) partition_prefix: String,

    /// Syncer actor mailbox.
    pub(super) syncer: syncer::Mailbox<E, A>,

    /// Verify requests held while syncing.
    pub(super) held_verify_requests: Vec<HeldVerifyRequest<E, A>>,

    /// Open subscriptions to the synced databases.
    pub(super) database_subscribers: Vec<oneshot::Sender<A::Databases>>,

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// The state sync resolvers used for startup sync fetching and post-bootstrap
    /// serving.
    pub(super) resolvers: R,

    /// Signals that the syncer has produced a usable artifact.
    pub(super) sync_completed: oneshot::Receiver<SyncResult<E, A>>,
}

impl<E, A, S, V, R> Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.held_verify_requests
                    .retain(|request| !request.response.is_closed());
                self.database_subscribers
                    .retain(|subscriber| !subscriber.is_closed());
            },
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Ok(artifact) = &mut self.sync_completed else {
                error!("syncer stopped before publishing state sync artifact");
                break;
            } => {
                self.artifact = Some(artifact);
                self.transition(None).await;
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down processor");
                break;
            } => match message {
                Message::Propose {
                    context: (_, context),
                    response,
                    ..
                } => {
                    debug!(epoch = %context.epoch(), view = %context.view(), "proposal rejected: state sync in progress");
                    response.send_lossy(None);
                }
                Message::Verify {
                    context,
                    ancestry,
                    response,
                } => {
                    self.held_verify_requests
                        .retain(|request| !request.response.is_closed());
                    self.held_verify_requests.push(HeldVerify {
                        context,
                        ancestry,
                        response,
                    });
                    debug!(
                        held_verify_requests = self.held_verify_requests.len(),
                        "verify held: state sync in progress"
                    );
                }
                Message::Finalized {
                    block,
                    acknowledgement,
                } => {
                    if let Some(handoff) = self.process_finalized(block, acknowledgement).await {
                        self.transition(handoff).await;
                        return;
                    }
                }
                Message::SubscribeDatabases { response } => {
                    self.database_subscribers
                        .retain(|subscriber| !subscriber.is_closed());
                    if !response.is_closed() {
                        self.database_subscribers.push(response);
                    }
                }
            },
        }
    }

    /// Processes a finalized block during state sync.
    async fn process_finalized(
        &mut self,
        block: A::Block,
        acknowledgement: Exact,
    ) -> Option<Option<(A::Block, Exact)>> {
        if self.artifact.is_none() {
            let anchor = Anchor::from(&block);
            let targets = A::sync_targets(&block);

            // Do not acknowledge marshal until the live sync session has recorded this
            // block's tip update. If we ack after merely enqueueing it, sync can still
            // complete on the previous anchor and handoff would observe marshal ahead of
            // `artifact.anchor.height.next()`.
            match self.syncer.update_targets(anchor, targets).await {
                Some(artifact) => {
                    self.artifact = Some(artifact);
                }
                None => {
                    acknowledgement.acknowledge();
                    return None;
                }
            }
        }

        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");

        if block.height() == artifact.anchor.height {
            assert_eq!(
                block.digest(),
                artifact.anchor.digest,
                "finalized block at sync anchor height must match sync anchor digest",
            );
            acknowledgement.acknowledge();
            return Some(None);
        }

        assert_eq!(
            block.height(),
            artifact.anchor.height.next(),
            "finalized block after sync anchor must be the next finalized block",
        );
        Some(Some((block, acknowledgement)))
    }

    /// Transitions to [`Processing`] state following the alignment of marshal's processed height
    /// on the converged database [`Anchor`].
    async fn transition(mut self, handoff: Option<(A::Block, Exact)>) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let synced_height = artifact.anchor.height;

        let metrics = ProcessorMetrics::new(self.context.child("processor_metrics"));
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            metrics,
        );

        if let Some((handoff_finalized, acknowledgement)) = handoff {
            if let FinalizeStatus::Persisted { height } = processor
                .finalize(self.context.as_present(), handoff_finalized)
                .await
            {
                debug!(
                    height = height.get(),
                    "persisted finalized database batch during sync handoff"
                );
            }
            acknowledgement.acknowledge();
        }

        let marshal = self.marshal.clone();
        let partition_prefix = self.partition_prefix.clone();
        self.context
            .as_present()
            .child("state_sync_complete")
            .spawn(move |context| async move {
                if marshal.wait_processed_height(synced_height).await {
                    syncer::set_sync_complete(&context, partition_prefix.as_str()).await;
                }
            });

        // Attach the resolvers to the initialized databases before starting the processor,
        // so that this instance can serve peers database operations and proofs.
        self.resolvers
            .attach_databases(processor.databases().clone())
            .await;

        // `subscribe_databases` promises a database set that is already attached to the
        // serving actor, so keep subscribers waiting until the resolver handoff is complete.
        for subscriber in self.database_subscribers.drain(..) {
            subscriber.send_lossy(processor.databases().clone());
        }

        for request in self.held_verify_requests.drain(..) {
            processor
                .verify(
                    self.context.as_present(),
                    self.marshal.clone(),
                    request.context,
                    request.ancestry,
                    request.response,
                )
                .await;
        }

        Processing {
            context: self.context,
            mailbox: self.mailbox,
            input_provider: self.input_provider,
            marshal: self.marshal,
            resolvers: self.resolvers,
            processor,
        }
        .start()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::Syncing;
    use crate::stateful::{
        actor::syncer::{self, SyncResult},
        db::{Anchor, AttachableResolver, ManagedDb, Merkleized, Unmerkleized},
        Application, Proposed,
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        marshal::{self, core::Actor as MarshalActor, standard::Standard},
        simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
        types::{Epoch, FixedEpocher, Height, View, ViewDelta},
        Block as ConsensusBlock, CertifiableBlock, Heightable,
    };
    use commonware_cryptography::{
        certificate::ConstantProvider, ed25519, sha256::Digest as Sha256Digest, Digest as _,
        Digestible, Signer as _,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Buf, BufMut, ContextCell, Runner as _,
        Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        acknowledgement::Exact, channel::oneshot, sync::AsyncRwLock, Acknowledgement, NZUsize,
        NZU16, NZU64,
    };
    use futures::{FutureExt, Stream};
    use std::{convert::Infallible, sync::Arc};

    type TestDatabases = Arc<AsyncRwLock<TestDb>>;
    type TestVariant = Standard<TestBlock>;
    type TestScheme = scheme_mocks::Scheme<ed25519::PublicKey>;

    #[derive(Clone, Copy)]
    struct TestUnmerkleized;

    #[derive(Clone, Copy)]
    struct TestMerkleized;

    impl Unmerkleized for TestUnmerkleized {
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(TestMerkleized)
        }
    }

    impl Merkleized for TestMerkleized {
        type Digest = Sha256Digest;
        type Unmerkleized = TestUnmerkleized;

        fn root(&self) -> Self::Digest {
            Sha256Digest::from([0; 32])
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }
    }

    #[derive(Default)]
    struct TestDb;

    impl<E: Send> ManagedDb<E> for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        context: SimplexContext<Sha256Digest, ed25519::PublicKey>,
        height: Height,
        digest: Sha256Digest,
    }

    impl TestBlock {
        fn new(height: u64, digest_byte: u8) -> Self {
            Self {
                context: SimplexContext {
                    round: commonware_consensus::types::Round::new(
                        Epoch::zero(),
                        View::new(height),
                    ),
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
    struct TestApp;

    impl Application<deterministic::Context> for TestApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type InputProvider = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as crate::stateful::db::DatabaseSet<deterministic::Context>>::SyncTargets{
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            TestBlock::new(0, 0)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as crate::stateful::db::DatabaseSet<deterministic::Context>>::Merkleized>{
            None
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Unmerkleized,
        ) -> <Self::Databases as crate::stateful::db::DatabaseSet<deterministic::Context>>::Merkleized
        {
            TestMerkleized
        }
    }

    #[derive(Clone)]
    struct NoopResolver;

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for NoopResolver {
        async fn attach_database(&self, _db: Arc<AsyncRwLock<DB>>) {}
    }

    struct TestHarness {
        syncing: Syncing<deterministic::Context, TestApp, TestScheme, TestVariant, NoopResolver>,
    }

    impl TestHarness {
        async fn new(context: deterministic::Context, anchor: Anchor<Sha256Digest>) -> Self {
            let (_mailbox_sender, mailbox) =
                actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, _syncer_receiver) =
                actor_mailbox::new(context.child("syncer_mailbox"), NZUsize!(1));
            let (_sync_complete, sync_completed) = oneshot::channel();

            Self {
                syncing: Syncing {
                    context: ContextCell::new(context.child("syncing")),
                    mailbox,
                    application: TestApp,
                    input_provider: (),
                    marshal: init_marshal_mailbox(context.child("marshal")).await,
                    partition_prefix: "syncing-test".to_string(),
                    syncer: syncer::Mailbox::new(syncer_sender),
                    held_verify_requests: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: Some(SyncResult {
                        databases: Arc::new(AsyncRwLock::new(TestDb)),
                        anchor,
                    }),
                    resolvers: NoopResolver,
                    sync_completed,
                },
            }
        }
    }

    fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
        immutable::Config {
            metadata_partition: format!("{partition}-metadata"),
            freezer_table_partition: format!("{partition}-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-value"),
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

    async fn init_marshal_mailbox(
        mut context: deterministic::Context,
    ) -> commonware_consensus::marshal::core::Mailbox<TestScheme, TestVariant> {
        let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), "syncing-finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "syncing-blocks"),
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
                partition_prefix: "syncing-harness".to_string(),
                mailbox_size: NZUsize!(8),
                view_retention_timeout: ViewDelta::new(1),
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

    fn anchor(height: u64, digest_byte: u8) -> Anchor<Sha256Digest> {
        Anchor {
            height: Height::new(height),
            round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
            digest: Sha256Digest::from([digest_byte; 32]),
        }
    }

    #[test]
    fn anchor_height_block_acknowledges_and_transitions_without_handoff() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, waiter) = Exact::handle();

            let action = harness
                .syncing
                .process_finalized(TestBlock::new(7, 9), acknowledgement)
                .await;

            assert!(waiter.await.is_ok());
            assert!(matches!(action, Some(None)));
        });
    }

    #[test]
    fn next_height_block_transitions_with_handoff_without_early_ack() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, waiter) = Exact::handle();

            let action = harness
                .syncing
                .process_finalized(TestBlock::new(8, 10), acknowledgement)
                .await;

            assert!(waiter.now_or_never().is_none());

            let Some(Some((block, acknowledgement))) = action else {
                panic!("post-anchor block should be handed off to processor");
            };
            assert_eq!(block.height().get(), 8);
            acknowledgement.acknowledge();
        });
    }

    #[test]
    fn anchor_height_block_with_conflicting_digest_panics() {
        let panic = std::panic::catch_unwind(|| {
            deterministic::Runner::default().start(|context| async move {
                let mut harness = TestHarness::new(context, anchor(7, 9)).await;
                let (acknowledgement, _waiter) = Exact::handle();
                let _ = harness
                    .syncing
                    .process_finalized(TestBlock::new(7, 10), acknowledgement)
                    .await;
            });
        })
        .expect_err("conflicting anchor digest should panic");

        let panic = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&'static str>().copied())
            .expect("panic should be a string");
        assert!(panic.contains("sync anchor digest"));
    }

    #[test]
    fn non_anchor_non_next_block_panics() {
        let panic = std::panic::catch_unwind(|| {
            deterministic::Runner::default().start(|context| async move {
                let mut harness = TestHarness::new(context, anchor(7, 9)).await;
                let (acknowledgement, _waiter) = Exact::handle();
                let _ = harness
                    .syncing
                    .process_finalized(TestBlock::new(9, 10), acknowledgement)
                    .await;
            });
        })
        .expect_err("unexpected finalized height should panic");

        let panic = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&'static str>().copied())
            .expect("panic should be a string");
        assert!(panic.contains("next finalized block"));
    }
}
