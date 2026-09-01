//! Backfill actor tests: fetch registry, local rechecks, peer responses, and serving.

use super::{
    mailbox::{Incoming, Message},
    rechecks::Rechecks,
    registry::Registry,
    validate::{SharedHeaders, SharedHistory, validate_header_segment, validate_history_segment},
    waiter::{BlockMode, ExactPrefix, Reply, Target, Waiter},
    *,
};
use crate::{
    Epochable as _,
    multimmit::{
        marshal::{
            actors::{catalog, delivery, metrics::FetchReason},
            bodies::Bodies,
            config::{ArchiveConfig, ArchiveMode, Config as MarshalConfig, Start},
            open::{Opened, storage as open_storage},
            types::LqcVerifier,
            wire::BackfillKey,
        },
        mocks::Committee,
        testing::{TestBody, expect_within},
        types::{
            BlockRef, CertificateId, ChainId, Lqc, PathLimits, TipRecord, TransactionBlock,
            TransactionBlockHeader, genesis_history,
        },
    },
    types::{Height, View},
};
use bytes::{Bytes, BytesMut};
use commonware_actor::{Feedback, mailbox::Policy};
use commonware_codec::{Decode as _, Encode, EncodeSize as _, RangeCfg};
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_resolver::{Consumer as _, Delivery, Fetch, Outcome, Resolver, p2p::Producer as _};
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Runner as _, Spawner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic,
    mocks::{
        DelayedReadContext, DelayedSyncContext, Gates, PendingSyncs, release_next_pending_syncs,
    },
};
use commonware_storage::{Context as StorageContext, translator::TwoCap};
use commonware_utils::{NZU16, NZUsize, channel::oneshot, sync::Mutex, vec::NonEmptyVec};
use futures::future::Either;
use rstest::rstest;
use std::{
    collections::VecDeque,
    convert::Infallible,
    future::pending,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing::{Span, Subscriber as TracingSubscriber, span};
use tracing_subscriber::{
    Layer, filter::filter_fn, layer::Context as LayerContext, prelude::*, registry::LookupSpan,
};
type TestBlock = TransactionBlock<Sha256, TestBody>;
type TestMailbox = Mailbox<Sha256, MinPk, TestBody>;
type Key = BackfillKey<Sha256Digest>;

#[derive(Default)]
struct RecordedTrace {
    spans: Vec<(&'static str, Option<&'static str>)>,
    ambient_links: usize,
}

#[derive(Clone, Default)]
struct Traces(Arc<Mutex<RecordedTrace>>);

impl<S: TracingSubscriber + for<'a> LookupSpan<'a>> Layer<S> for Traces {
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: LayerContext<'_, S>) {
        let parent = ctx
            .span(id)
            .unwrap()
            .parent()
            .map(|parent| parent.metadata().name());
        self.0.lock().spans.push((attrs.metadata().name(), parent));
    }

    fn on_follows_from(&self, id: &span::Id, _: &span::Id, ctx: LayerContext<'_, S>) {
        if ctx.span(id).unwrap().metadata().name() == "filter_ambient" {
            self.0.lock().ambient_links += 1;
        }
    }
}

#[rstest]
#[case(true, true)]
#[case(false, true)]
#[case(true, false)]
#[case(false, false)]
fn filtered_response_spans_do_not_capture_ambient(#[case] process: bool, #[case] stage: bool) {
    const PROCESS: &str = "multimmit.marshal.resolver.fetch.response.process";
    const STAGE: &str = "multimmit.marshal.resolver.fetch.response.stage";
    const ADMIT: &str = "multimmit.marshal.catalog.stage_blocks";
    let traces = Traces::default();
    let subscriber = tracing_subscriber::registry()
        .with(traces.clone())
        .with(filter_fn(move |metadata| {
            (process || metadata.name() != PROCESS) && (stage || metadata.name() != STAGE)
        }));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info_span!("filter_ambient")
            .in_scope(fetched_block_deliveries_share_one_catalog_admission_cut);
    });
    let recorded = traces.0.lock();
    assert_eq!(
        recorded.ambient_links, 0,
        "disabled processing must not link the ambient span"
    );
    let stages = recorded
        .spans
        .iter()
        .filter(|(name, _)| *name == STAGE)
        .collect::<Vec<_>>();
    assert_eq!(stages.len(), usize::from(stage));
    if stage {
        assert_eq!(stages[0].1, process.then_some(PROCESS));
    }
    let admissions = recorded
        .spans
        .iter()
        .filter(|(name, _)| *name == ADMIT)
        .collect::<Vec<_>>();
    assert_eq!(admissions.len(), 1);
    assert_eq!(
        admissions[0].1,
        Some(if stage { STAGE } else { "filter_ambient" }),
        "catalog admission must not retain a disabled staging span's ambient context"
    );
}

/// One fetch the actor issued to the network resolver.
#[derive(Clone, Copy)]
struct Issued {
    key: Key,
    subscriber: BackfillSubscriber,
}

/// A network resolver that records every fetch and answers with a fixed feedback.
#[derive(Clone)]
struct RecordingResolver {
    issued: Arc<Mutex<Vec<Issued>>>,
    retains: Arc<Mutex<usize>>,
    feedback: Feedback,
}

impl RecordingResolver {
    fn new(feedback: Feedback) -> Self {
        Self {
            issued: Arc::default(),
            retains: Arc::default(),
            feedback,
        }
    }

    /// Returns the number of fetches issued.
    fn fetches(&self) -> usize {
        self.issued.lock().len()
    }

    /// Returns the subscribers fetching `key`, in issue order.
    fn subscribers(&self, key: Key) -> Vec<BackfillSubscriber> {
        self.issued
            .lock()
            .iter()
            .filter(|issued| issued.key == key)
            .map(|issued| issued.subscriber)
            .collect()
    }

    /// Returns the only subscriber fetching `key`.
    fn subscriber(&self, key: Key) -> BackfillSubscriber {
        let subscribers = self.subscribers(key);
        assert_eq!(subscribers.len(), 1, "expected one fetch for {key}");
        subscribers[0]
    }

    fn record(&self, fetch: Fetch<Key, BackfillSubscriber>) {
        self.issued.lock().push(Issued {
            key: fetch.key,
            subscriber: fetch.subscriber,
        });
    }
}

impl Resolver for RecordingResolver {
    type Key = Key;
    type Subscriber = BackfillSubscriber;

    fn fetch<F>(&mut self, fetch: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.record(fetch.into());
        self.feedback
    }

    fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        for fetch in fetches {
            self.record(fetch.into());
        }
        self.feedback
    }

    fn retain(
        &mut self,
        _: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        *self.retains.lock() += 1;
        Feedback::Ok
    }
}

#[derive(Clone)]
struct AcceptVerifier;

impl LqcVerifier<Sha256, MinPk> for AcceptVerifier {
    type Error = Infallible;

    async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A verifier that holds the first verification until the test releases it, and rejects it if the
/// release is dropped. Later verifications pass at once.
#[derive(Clone)]
struct GatedVerifier {
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    calls: Arc<Mutex<usize>>,
}

impl GatedVerifier {
    /// Returns the verifier, a receiver for the first verification's start, and its release.
    fn new() -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, verification_started) = oneshot::channel();
        let (release, verification_release) = oneshot::channel();
        let verifier = Self {
            started: Arc::new(Mutex::new(Some(started))),
            release: Arc::new(Mutex::new(Some(verification_release))),
            calls: Arc::default(),
        };
        (verifier, verification_started, release)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("verification gate closed")]
struct GateClosed;

impl LqcVerifier<Sha256, MinPk> for GatedVerifier {
    type Error = GateClosed;

    async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
        *self.calls.lock() += 1;
        let started = self.started.lock().take();
        let release = self.release.lock().take();
        if let Some(started) = started {
            let _ = started.send(());
        }
        match release {
            Some(release) => release.await.map_err(|_| GateClosed),
            None => Ok(()),
        }
    }
}

fn delivery(key: Key, subscriber: BackfillSubscriber) -> Delivery<Key, BackfillSubscriber> {
    Delivery {
        key,
        subscribers: NonEmptyVec::new((subscriber, Span::none())),
    }
}

fn block_key(reference: BlockRef<Sha256Digest>) -> Key {
    BackfillKey::producer_block(reference.chain(), reference.digest())
}

/// Registers a waiter for `target` through the actor mailbox and returns its reply receiver.
fn request<T>(
    mailbox: &TestMailbox,
    target: Target<Sha256Digest>,
    reply: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Reply<Sha256, MinPk, TestBody>,
    reason: FetchReason,
) -> oneshot::Receiver<Result<T, Error>> {
    let (sender, receiver) = oneshot::channel();
    assert!(
        mailbox
            .commands
            .enqueue(Message::Fetch {
                span: Span::none(),
                target,
                reply: reply(sender),
                reason,
            })
            .accepted()
    );
    receiver
}

fn request_block(
    mailbox: &TestMailbox,
    reference: BlockRef<Sha256Digest>,
    mode: BlockMode,
    reason: FetchReason,
) -> oneshot::Receiver<Result<Arc<TestBlock>, Error>> {
    request(
        mailbox,
        Target::Block { reference, mode },
        Reply::Block,
        reason,
    )
}

fn request_blocks(
    mailbox: &TestMailbox,
    references: Vec<BlockRef<Sha256Digest>>,
    reason: FetchReason,
) -> oneshot::Receiver<Result<ExactPrefix<Sha256, TestBody>, Error>> {
    request(
        mailbox,
        Target::Blocks(Arc::new(references)),
        Reply::Blocks,
        reason,
    )
}

fn request_headers(
    mailbox: &TestMailbox,
    reference: BlockRef<Sha256Digest>,
) -> oneshot::Receiver<Result<SharedHeaders<Sha256Digest>, Error>> {
    request(
        mailbox,
        Target::Headers(reference),
        Reply::Headers,
        FetchReason::Finality,
    )
}

fn request_history(
    mailbox: &TestMailbox,
    commitment: Sha256Digest,
    reason: FetchReason,
) -> oneshot::Receiver<Result<SharedHistory<Sha256Digest>, Error>> {
    request(mailbox, Target::History(commitment), Reply::History, reason)
}

fn is_pending<T>(receiver: &mut oneshot::Receiver<T>) -> bool {
    matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    )
}

/// Lets every task that is not waiting on a timer or gate run to completion.
async fn settle(context: &deterministic::Context) {
    context.sleep(Duration::from_millis(50)).await;
}

fn producer_chain(committee: &Committee<MinPk>, count: usize) -> Vec<Arc<TestBlock>> {
    let mut parent = committee.config.genesis().tips()[0].digest();
    (1..=count)
        .map(|height| {
            let height = Height::new(height as u64);
            let body = TestBody::new(
                Sha256::hash(&[b"range application parent"]),
                height,
                height.get(),
            );
            let header = TransactionBlockHeader::new(
                committee.config.epoch(),
                ChainId::new(0),
                height,
                parent,
                body.digest(),
            )
            .unwrap();
            let block = Arc::new(TransactionBlock::new(header, body).unwrap());
            parent = block.reference().digest();
            block
        })
        .collect()
}

/// A single block at height one on `chain`, distinguished by `salt`.
fn first_block(committee: &Committee<MinPk>, chain: u32, salt: u64) -> Arc<TestBlock> {
    let body = TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), salt);
    Arc::new(
        TransactionBlock::<Sha256, _>::new(
            committee.transaction_header(ChainId::new(chain), body.digest()),
            body,
        )
        .unwrap(),
    )
}

fn catalog_config(
    context: &deterministic::Context,
    committee: &Committee<MinPk>,
    partition: &str,
) -> MarshalConfig<TwoCap, MinPk, TestBody> {
    let archive = ArchiveConfig::new(
        TwoCap,
        CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
    );
    let mut catalog_config = MarshalConfig::new(
        Start::Genesis(committee.config.genesis().clone()),
        partition.into(),
        committee.codec(),
        (),
        archive,
    );
    catalog_config.retention.blocks = ArchiveMode::Prunable;
    catalog_config
}

/// Bounds of a test harness.
struct Options {
    max_value_bytes: NonZeroUsize,
    max_pending: NonZeroUsize,
    max_active: NonZeroUsize,
    max_hot_block_bytes: NonZeroUsize,
    catalog_mailbox_size: NonZeroUsize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_value_bytes: NZUsize!(1024 * 1024),
            max_pending: NZUsize!(16),
            max_active: NZUsize!(16),
            max_hot_block_bytes: NonZeroUsize::MAX,
            catalog_mailbox_size: NZUsize!(1024),
        }
    }
}

/// A started backfill actor, its serving actor and catalog.
struct Harness {
    bridge: BackfillBridge<Sha256, MinPk, TestBody>,
    mailbox: TestMailbox,
    catalog: catalog::Mailbox<Sha256, MinPk, TestBody>,
    _delivery: delivery::Receiver<Sha256, TestBody>,
    backfill: Handle<Result<(), Error>>,
    serve: Handle<Result<(), super::serve::Error>>,
    catalog_handle: Handle<Result<(), catalog::Fatal>>,
}

/// An opened catalog with the configuration of a backfill actor that has not been created.
struct Parts {
    catalog: catalog::Mailbox<Sha256, MinPk, TestBody>,
    delivery: delivery::Receiver<Sha256, TestBody>,
    catalog_handle: Handle<Result<(), catalog::Fatal>>,
    serve: super::serve::Actor<deterministic::Context, Sha256, MinPk, TestBody>,
    config: Config<Sha256, MinPk, TestBody>,
}

impl Parts {
    async fn open<E>(
        context: &deterministic::Context,
        catalog_context: E,
        committee: &Committee<MinPk>,
        partition: &str,
        label: &'static str,
        options: &Options,
    ) -> Self
    where
        E: StorageContext + Spawner,
    {
        let mut catalog_config = catalog_config(context, committee, partition);
        catalog_config.limits.max_hot_block_bytes = options.max_hot_block_bytes;
        catalog_config.capacities.catalog_mailbox_size = options.catalog_mailbox_size;
        catalog_config.capacities.admission_cut_capacity = options.catalog_mailbox_size;
        catalog_config.capacities.pending_segment_items =
            NonZeroU64::new(options.catalog_mailbox_size.get() as u64).unwrap();
        let (delivery, delivery_commands) = delivery::channel(context.child("delivery"));
        let Opened {
            catalog,
            catalog_handle,
            promoter,
            delivery_store: _,
        } = open_storage::<_, _, Sha256, _, _>(
            catalog_context,
            &catalog_config,
            &catalog_config.actor_bounds().unwrap(),
            delivery,
        )
        .await
        .unwrap();
        let promoter = promoter.as_ref().map(|promoter| promoter.mailbox.clone());
        let bodies = Bodies::new(catalog.clone(), promoter);
        let label = context.child(label);
        let (serve, serve_mailbox) = super::serve::Actor::new(
            &label,
            super::serve::Config {
                catalog: catalog.clone(),
                bodies: bodies.clone(),
                max_block_bytes: NZUsize!(112),
                max_value_bytes: options.max_value_bytes,
                mailbox_size: NZUsize!(16),
                max_pending: options.max_pending,
                max_active: options.max_active,
            },
        );
        let config = Config {
            epoch: committee.config.epoch(),
            codec: committee.codec(),
            body: (),
            max_block_bytes: NZUsize!(112),
            max_value_bytes: options.max_value_bytes,
            catalog: catalog.clone(),
            bodies,
            serve: serve_mailbox,
            mailbox_size: NZUsize!(16),
            max_pending: options.max_pending,
            max_rechecks: options.max_active,
            max_staging: options.max_active,
        };
        Self {
            catalog,
            delivery: delivery_commands,
            catalog_handle,
            serve,
            config,
        }
    }
}

impl Harness {
    async fn open<R>(
        context: &deterministic::Context,
        committee: &Committee<MinPk>,
        partition: &str,
        resolver: R,
    ) -> Self
    where
        R: Resolver<Key = Key, Subscriber = BackfillSubscriber>,
    {
        Self::open_with(
            context,
            context.child("catalog"),
            committee,
            partition,
            "backfill",
            Options::default(),
            resolver,
            AcceptVerifier,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_with<E, R, Q>(
        context: &deterministic::Context,
        catalog_context: E,
        committee: &Committee<MinPk>,
        partition: &str,
        label: &'static str,
        options: Options,
        resolver: R,
        verifier: Q,
    ) -> Self
    where
        E: StorageContext + Spawner,
        R: Resolver<Key = Key, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<Sha256, MinPk> + Clone,
    {
        let parts = Parts::open(
            context,
            catalog_context,
            committee,
            partition,
            label,
            &options,
        )
        .await;
        let (actor, bridge, mailbox) = Actor::new(&context.child(label), parts.config);
        Self {
            bridge,
            mailbox,
            catalog: parts.catalog,
            _delivery: parts.delivery,
            backfill: actor.start(resolver, verifier),
            serve: parts.serve.start(),
            catalog_handle: parts.catalog_handle,
        }
    }

    /// Drops every handle and asserts that each actor stops cleanly.
    async fn close(self) {
        let Self {
            bridge,
            mailbox,
            catalog,
            _delivery,
            backfill,
            serve,
            catalog_handle,
        } = self;
        drop(mailbox);
        drop(bridge);
        drop(catalog);
        assert!(backfill.await.unwrap().is_ok());
        assert!(serve.await.unwrap().is_ok());
        assert!(catalog_handle.await.unwrap().is_ok());
    }

    /// Aborts every actor.
    async fn abort(self) {
        self.backfill.abort();
        self.serve.abort();
        self.catalog_handle.abort();
        let _ = self.backfill.await;
        let _ = self.serve.await;
        let _ = self.catalog_handle.await;
    }
}

#[test]
fn compact_segments_require_exact_linked_ancestry() {
    let committee = Committee::<MinPk>::builder(41, 6)
        .limits(PathLimits::new(1, 0).unwrap())
        .build();
    let tips = committee.config.genesis().tips().to_vec();
    let oldest = TipRecord::at_tips(Sha256::hash(&[b"history floor"]), tips.clone()).unwrap();
    let newest = TipRecord::at_tips(oldest.commitment::<Sha256>(), tips).unwrap();
    let head = newest.commitment::<Sha256>();
    assert!(validate_history_segment::<Sha256>(head, vec![newest.clone(), oldest]).is_some());
    assert!(validate_history_segment::<Sha256>(head, vec![newest.clone(), newest]).is_none());

    let epoch = committee.config.epoch();
    let first = TransactionBlockHeader::new(
        epoch,
        ChainId::new(0),
        Height::new(1),
        Sha256::hash(&[b"block floor"]),
        Sha256::hash(&[b"body 1"]),
    )
    .unwrap();
    let second = TransactionBlockHeader::new(
        epoch,
        ChainId::new(0),
        Height::new(2),
        first.digest::<Sha256>(),
        Sha256::hash(&[b"body 2"]),
    )
    .unwrap();
    let head = second.block_ref::<Sha256>();
    assert!(validate_header_segment::<Sha256>(epoch, head, vec![second.clone(), first]).is_some());
    assert!(validate_header_segment::<Sha256>(epoch, head, vec![second.clone(), second]).is_none());
}

#[test]
fn block_modes_follow_the_documented_transitions() {
    assert_eq!(BlockMode::Wait.on_certified(), BlockMode::Subscribe);
    for mode in [BlockMode::Fetch, BlockMode::Subscribe, BlockMode::Certified] {
        assert_eq!(mode.on_certified(), mode);
    }
    assert_eq!(BlockMode::Wait.merge_certified(), BlockMode::Subscribe);
    assert_eq!(BlockMode::Fetch.merge_certified(), BlockMode::Fetch);
    assert_eq!(BlockMode::Subscribe.merge_certified(), BlockMode::Fetch);
    assert!(!BlockMode::Wait.fetches() && !BlockMode::Certified.fetches());
    assert!(BlockMode::Fetch.fetches() && BlockMode::Subscribe.fetches());
    assert!(BlockMode::Fetch.stages() && BlockMode::Certified.stages());
    assert!(!BlockMode::Wait.stages() && !BlockMode::Subscribe.stages());
}

/// A registered waiter for `commitment` whose reply the test keeps.
fn history_waiter(
    registry: &mut Registry<Sha256, MinPk, TestBody>,
    commitment: &[u8],
    reason: FetchReason,
) -> (
    Key,
    oneshot::Receiver<Result<SharedHistory<Sha256Digest>, Error>>,
) {
    let (reply, receiver) = oneshot::channel();
    let target = Target::History(Sha256::hash(&[commitment]));
    let key = target.key();
    let waiter = Waiter {
        id: registry.allocate(),
        target,
        reply: Some(Reply::History(reply)),
        span: Span::none(),
        reason,
        state: waiter::FetchState::Idle,
    };
    registry.insert(key, waiter);
    (key, receiver)
}

#[test]
fn registry_makes_room_by_closed_then_marker_then_oldest() {
    let mut registry = Registry::<Sha256, MinPk, TestBody>::new(3);
    let (closed, closed_receiver) = history_waiter(&mut registry, b"closed", FetchReason::Explicit);
    let (oldest, _oldest_receiver) =
        history_waiter(&mut registry, b"oldest", FetchReason::Explicit);
    let reference = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"marker"]));
    let marker = Target::Block {
        reference,
        mode: BlockMode::Certified,
    };
    let marker_key = marker.key();
    let id = registry.allocate();
    registry.insert(
        marker_key,
        Waiter {
            id,
            target: marker,
            reply: None,
            span: Span::none(),
            reason: FetchReason::Certified,
            state: waiter::FetchState::Idle,
        },
    );
    assert!(registry.is_full());
    drop(closed_receiver);

    let explicit = Target::History(Sha256::hash(&[b"explicit"]));
    let eviction = registry.make_room(&explicit, FetchReason::Explicit);
    assert!(eviction.room);
    assert_eq!(eviction.evicted.len(), 1);
    assert_eq!(eviction.evicted[0].key, closed);
    assert!(eviction.evicted[0].emptied);

    let (_, _explicit_receiver) = history_waiter(&mut registry, b"explicit", FetchReason::Explicit);
    let eviction = registry.make_room(&explicit, FetchReason::Explicit);
    assert!(eviction.room);
    assert_eq!(eviction.evicted.len(), 1);
    assert_eq!(eviction.evicted[0].key, marker_key);

    let (_, _next_receiver) = history_waiter(&mut registry, b"next", FetchReason::Explicit);
    let eviction = registry.make_room(&explicit, FetchReason::Explicit);
    assert!(!eviction.room);
    assert!(eviction.evicted.is_empty());

    let finality = Target::History(Sha256::hash(&[b"finality"]));
    let eviction = registry.make_room(&finality, FetchReason::Finality);
    assert!(eviction.room);
    assert_eq!(eviction.evicted.len(), 1);
    assert_eq!(eviction.evicted[0].key, oldest);
    assert_eq!(registry.len(), 2);
}

#[test]
fn rechecks_run_one_per_key_and_cancel_queued_or_active() {
    let mut rechecks = Rechecks::<Sha256, MinPk, TestBody>::new(1);
    let first = BackfillKey::tip_record(Sha256::hash(&[b"first"]));
    let second = BackfillKey::tip_record(Sha256::hash(&[b"second"]));
    assert!(rechecks.queue(first));
    assert!(!rechecks.queue(first));
    assert!(rechecks.queue(second));
    assert_eq!(rechecks.next_queued(), Some(first));
    rechecks.start(first, pending());
    assert_eq!(rechecks.next_queued(), None);
    assert_eq!((rechecks.active(), rechecks.queued()), (1, 1));

    rechecks.cancel(&second);
    assert!(!rechecks.contains(&second));
    assert_eq!(rechecks.queued(), 0);
    assert!(rechecks.finish(&first));
    assert!(!rechecks.finish(&first));
    assert!(!rechecks.contains(&first));
}

#[test]
fn oversized_peer_blocks_are_invalid_without_stopping_the_actor() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(55, 6).build();
        let height = Height::new(u64::MAX);
        let body = TestBody::new(
            Sha256::hash(&[b"oversized application parent"]),
            height,
            u64::MAX,
        );
        let header = TransactionBlockHeader::new(
            committee.config.epoch(),
            ChainId::new(0),
            height,
            committee.config.genesis().tips()[0].digest(),
            body.digest(),
        )
        .unwrap();
        let block = Arc::new(TransactionBlock::<Sha256, _>::new(header, body).unwrap());
        assert!(block.encode_size() > 112);
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "oversized_peer_block_test",
            resolver.clone(),
        )
        .await;

        let reference = block.reference();
        let scalar = request_block(
            &harness.mailbox,
            reference,
            BlockMode::Fetch,
            FetchReason::FinalizedBody,
        );
        settle(&context).await;
        let key = block_key(reference);
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, resolver.subscriber(key)), block.encode())
                .await
                .unwrap(),
            Outcome::Invalid
        );

        let range = request_blocks(
            &harness.mailbox,
            vec![reference],
            FetchReason::FinalizedBody,
        );
        settle(&context).await;
        let key = BackfillKey::producer_blocks(reference, NonZeroU16::new(1).unwrap());
        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(key, resolver.subscriber(key)),
                    vec![block].encode(),
                )
                .await
                .unwrap(),
            Outcome::Invalid
        );
        harness.mailbox.retire_certified(Vec::new()).await.unwrap();

        drop(scalar);
        drop(range);
        harness.close().await;
    });
}

#[test]
fn body_range_rechecks_local_custody_and_accepts_late_admission() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(56, 6).build();
        let blocks = producer_chain(&committee, 2);
        let harness = Harness::open(
            &context,
            &committee,
            "local_body_range_test",
            RecordingResolver::new(Feedback::Ok),
        )
        .await;

        harness
            .catalog
            .admit_block(blocks[1].reference(), Arc::clone(&blocks[1]))
            .await
            .unwrap();
        let local = request_blocks(
            &harness.mailbox,
            vec![blocks[1].reference(), blocks[0].reference()],
            FetchReason::FinalizedBody,
        );
        let local = local.await.unwrap().unwrap();
        assert_eq!(local.blocks().len(), 1);
        assert_eq!(local.blocks()[0].reference(), blocks[1].reference());

        let late = request_blocks(
            &harness.mailbox,
            vec![blocks[0].reference()],
            FetchReason::FinalizedBody,
        );
        settle(&context).await;
        harness
            .catalog
            .admit_block(blocks[0].reference(), Arc::clone(&blocks[0]))
            .await
            .unwrap();
        harness
            .mailbox
            .admitted_block(blocks[0].reference(), Arc::clone(&blocks[0]))
            .await
            .unwrap();
        let late = late.await.unwrap().unwrap();
        assert_eq!(late.blocks().len(), 1);
        assert_eq!(late.blocks()[0].reference(), blocks[0].reference());

        harness.close().await;
    });
}

#[test]
fn admitted_block_notice_rejects_a_mismatched_reference() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(58, 6).build();
        let blocks = producer_chain(&committee, 2);
        let harness = Harness::open(
            &context,
            &committee,
            "admitted_reference_mismatch_test",
            RecordingResolver::new(Feedback::Ok),
        )
        .await;

        // A notice naming another block's reference is rejected before it completes a waiter.
        assert!(matches!(
            harness
                .mailbox
                .admitted_block(blocks[0].reference(), Arc::clone(&blocks[1]))
                .await,
            Err(Error::Invalid("admitted block identity mismatch"))
        ));

        harness.close().await;
    });
}

#[test]
fn header_fetch_accepts_late_durable_body_admission() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(57, 6).build();
        let blocks = producer_chain(&committee, 2);
        let head = blocks[1].reference();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let harness = Harness::open(
            &context,
            &committee,
            "late_header_body_admission_test",
            resolver.clone(),
        )
        .await;
        harness
            .catalog
            .admit_block(blocks[0].reference(), Arc::clone(&blocks[0]))
            .await
            .unwrap();

        let headers = request_headers(&harness.mailbox, head);
        settle(&context).await;
        assert_eq!(resolver.fetches(), 1);

        harness
            .catalog
            .admit_block(head, Arc::clone(&blocks[1]))
            .await
            .unwrap();
        let custody = harness.catalog.wait_for_custody(vec![head]).await.unwrap();
        assert_eq!(custody[0].as_ref().unwrap().reference(), head);
        harness
            .mailbox
            .admitted_block(head, Arc::clone(&blocks[1]))
            .await
            .unwrap();

        let headers = expect_within(
            &context,
            Duration::from_millis(100),
            headers,
            "locally durable body did not complete its pending header fetch",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(headers.first(), Some(blocks[1].header()));
        assert!(
            validate_header_segment::<Sha256>(
                committee.config.epoch(),
                head,
                headers.as_ref().clone(),
            )
            .is_some()
        );
        assert_eq!(resolver.fetches(), 1);

        harness.close().await;
    });
}

#[test]
fn peer_bodies_complete_only_exact_header_fetches() {
    for range in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = Committee::<MinPk>::builder(58, 6).build();
            let blocks = producer_chain(&committee, 3);
            let expected = blocks
                .iter()
                .rev()
                .take(if range { 2 } else { 1 })
                .cloned()
                .collect::<Vec<_>>();
            let references = expected
                .iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>();
            let head = references[0];
            let other = BlockRef::new(
                head.chain(),
                head.height(),
                Sha256::hash(&[b"different producer header"]),
            );
            let resolver = RecordingResolver::new(Feedback::Ok);
            let mut harness = Harness::open(
                &context,
                &committee,
                "peer_body_header_completion_test",
                resolver.clone(),
            )
            .await;

            let mut headers = Vec::new();
            for reference in references.iter().copied().chain([other]) {
                headers.push(request_headers(&harness.mailbox, reference));
            }
            let (response, key, value) = if range {
                let key = BackfillKey::producer_blocks(head, NonZeroU16::new(2).unwrap());
                let receiver = request_blocks(
                    &harness.mailbox,
                    references.clone(),
                    FetchReason::FinalizedBody,
                );
                (Either::Left(receiver), key, expected.encode())
            } else {
                let receiver = request_block(
                    &harness.mailbox,
                    head,
                    BlockMode::Fetch,
                    FetchReason::FinalizedBody,
                );
                (Either::Right(receiver), block_key(head), expected[0].encode())
            };
            settle(&context).await;
            assert_eq!(resolver.fetches(), headers.len() + 1);
            assert_eq!(
                harness
                    .bridge
                    .deliver(delivery(key, resolver.subscriber(key)), value)
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            let received = match response {
                Either::Left(response) => response.await.unwrap().unwrap().blocks().to_vec(),
                Either::Right(response) => vec![response.await.unwrap().unwrap()],
            };
            assert_eq!(received, expected);

            let mut unmatched = headers.pop().unwrap();
            for (receiver, block) in headers.into_iter().zip(&expected) {
                let headers = select! {
                    result = receiver => result.unwrap().unwrap(),
                    _ = context.sleep(Duration::from_millis(100)) => {
                        panic!("peer body did not complete its pending header fetch (range={range})")
                    },
                };
                assert_eq!(headers.first(), Some(block.header()));
                assert!(
                    validate_header_segment::<Sha256>(
                        committee.config.epoch(),
                        block.reference(),
                        headers.as_ref().clone(),
                    )
                    .is_some()
                );
            }
            select! {
                result = &mut unmatched => {
                    panic!("peer body completed a different header head: {result:?}")
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            drop(unmatched);
            harness.close().await;
        });
    }
}

#[test]
fn body_range_delivery_requires_an_exact_prefix_and_stages_once() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(53, 6).build();
        let blocks = producer_chain(&committee, 3);
        let references = blocks
            .iter()
            .rev()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let key = BackfillKey::producer_blocks(references[0], NonZeroU16::new(3).unwrap());
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "consumer_body_range_test",
            resolver.clone(),
        )
        .await;
        let receiver = request_blocks(
            &harness.mailbox,
            references.clone(),
            FetchReason::FinalizedBody,
        );
        settle(&context).await;
        let subscriber = resolver.subscriber(key);

        let malformed = vec![Arc::clone(&blocks[1]), Arc::clone(&blocks[0])].encode();
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), malformed)
                .await
                .unwrap(),
            Outcome::Invalid
        );

        let prefix = vec![Arc::clone(&blocks[2]), Arc::clone(&blocks[1])];
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), prefix.encode())
                .await
                .unwrap(),
            Outcome::Complete
        );
        let resolved = receiver.await.unwrap().unwrap();
        assert_eq!(resolved.blocks().len(), 2);
        assert_eq!(resolved.blocks()[0].reference(), references[0]);
        assert_eq!(resolved.blocks()[1].reference(), references[1]);
        assert!(
            harness
                .catalog
                .wait_for_custody(references[..2].to_vec())
                .await
                .unwrap()
                .into_iter()
                .all(|custody| custody.is_some())
        );
        let metrics = context.encode();
        assert!(metrics.contains("range_requests_total 1"));
        assert!(metrics.contains("range_requested_blocks_total 3"));
        assert!(metrics.contains("range_received_blocks_total 2"));
        assert!(metrics.contains("range_short_responses_total 1"));

        harness.close().await;
    });
}

#[test]
fn blocked_range_staging_does_not_stall_resolver_commands() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(54, 6).build();
        let blocks = producer_chain(&committee, 5);
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open_with(
            &context,
            delayed.child("catalog"),
            &committee,
            "blocked_range_staging_test",
            "backfill",
            Options {
                max_pending: NZUsize!(2),
                max_active: NZUsize!(1),
                catalog_mailbox_size: NZUsize!(1),
                ..Options::default()
            },
            resolver.clone(),
            AcceptVerifier,
        )
        .await;

        syncs.arm();
        let first = harness
            .catalog
            .stage_block(Arc::clone(&blocks[0]))
            .await
            .unwrap();
        harness.catalog.progress().await.unwrap();
        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        let first_cut_syncs = syncs.calls();
        assert!(first_cut_syncs > 0, "first custody cut did not start");
        let second = harness
            .catalog
            .stage_block(Arc::clone(&blocks[1]))
            .await
            .unwrap();

        let reference = blocks[2].reference();
        let receiver = request_blocks(&harness.mailbox, vec![reference], FetchReason::FinalizedBody);
        settle(&context).await;
        let key = BackfillKey::producer_blocks(reference, NonZeroU16::new(1).unwrap());
        let mut delivery_future = Box::pin(harness.bridge.deliver(
            delivery(key, resolver.subscriber(key)),
            vec![Arc::clone(&blocks[2])].encode(),
        ));
        select! {
            result = &mut delivery_future => panic!("range staging crossed a full trailing cut: {result:?}"),
            _ = context.sleep(Duration::from_millis(1)) => {},
        }

        expect_within(
            &context,
            Duration::from_millis(100),
            harness.mailbox.retire_certified(Vec::new()),
            "blocked range staging stalled an independent resolver command",
        )
        .await
        .unwrap();

        // Later waiters recheck behind the blocked catalog and have not fetched yet, but a
        // response for a key with waiters is still admitted.
        let next = blocks[3].reference();
        let next_receiver =
            request_blocks(&harness.mailbox, vec![next], FetchReason::FinalizedBody);
        let next_key = BackfillKey::producer_blocks(next, NonZeroU16::new(1).unwrap());
        let next_bytes = vec![Arc::clone(&blocks[3])].encode();
        // No fetch is registered yet, so no resolver subscriber exists for this key; admission
        // is judged by key.
        let mut next_delivery = Box::pin(harness.bridge.deliver(
            delivery(next_key, BackfillSubscriber::default()),
            next_bytes.clone(),
        ));
        harness.mailbox.retire_certified(Vec::new()).await.unwrap();
        select! {
            result = &mut next_delivery => panic!("queued range staging completed early: {result:?}"),
            _ = context.sleep(Duration::from_millis(1)) => {},
        }
        let metrics = context.encode();
        assert!(metrics.contains("staging_active 1"), "{metrics}");
        assert!(metrics.contains("staging_queued 1"), "{metrics}");
        assert!(
            metrics.contains(&format!("staging_queued_bytes {}", next_bytes.len())),
            "{metrics}"
        );
        drop(receiver);
        drop(next_receiver);

        let overflow = blocks[4].reference();
        let overflow_receiver =
            request_blocks(&harness.mailbox, vec![overflow], FetchReason::FinalizedBody);
        let overflow_key = BackfillKey::producer_blocks(overflow, NonZeroU16::new(1).unwrap());
        // As above, the waiter is still rechecking behind the blocked catalog.
        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(overflow_key, BackfillSubscriber::default()),
                    vec![Arc::clone(&blocks[4])].encode(),
                )
                .await
                .unwrap(),
            Outcome::Ambiguous
        );
        drop(overflow_receiver);

        let Harness {
            bridge,
            mailbox,
            catalog,
            _delivery,
            backfill,
            serve,
            catalog_handle,
        } = harness;
        drop(mailbox);
        drop(bridge);
        select! {
            result = &mut delivery_future => {
                panic!("backfill shutdown aborted accepted range staging: {result:?}")
            },
            _ = context.sleep(Duration::from_millis(1)) => {},
        }
        release_next_pending_syncs(&syncs, first_cut_syncs);
        assert_eq!(delivery_future.await.unwrap(), Outcome::Complete);
        syncs.unblock();
        assert_eq!(next_delivery.await.unwrap(), Outcome::Complete);
        first.wait().await.unwrap();
        second.wait().await.unwrap();

        drop(catalog);
        assert!(backfill.await.unwrap().is_ok());
        assert!(serve.await.unwrap().is_ok());
        assert!(catalog_handle.await.unwrap().is_ok());
    });
}

#[test]
fn consumer_overflow_is_ambiguous_and_closure_is_ignored() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let mut parts = Parts::open(
            &context,
            context.child("catalog"),
            &committee,
            "consumer_overflow_test",
            "backfill",
            &Options::default(),
        )
        .await;
        parts.config.mailbox_size = NZUsize!(1);
        let (actor, mut bridge, mailbox) = Actor::new(&context.child("backfill"), parts.config);
        assert!(
            mailbox
                .certified_block(BlockRef::new(
                    ChainId::new(0),
                    Height::new(1),
                    Sha256::hash(&[b"occupied"]),
                ))
                .accepted()
        );
        let key = BackfillKey::tip_record(Sha256::hash(&[b"history"]));
        let outcome = bridge.deliver(delivery(key, BackfillSubscriber::default()), Bytes::new());
        assert_eq!(outcome.await.unwrap(), Outcome::Ambiguous);

        drop(actor);
        let outcome = bridge.deliver(delivery(key, BackfillSubscriber::default()), Bytes::new());
        assert_eq!(outcome.await.unwrap(), Outcome::Ignored);

        drop(parts.catalog);
        parts.catalog_handle.abort();
        let _ = parts.catalog_handle.await;
    });
}

#[test]
fn overflow_discards_canceled_exact_fetches() {
    let fetch = |label: &[u8]| {
        let (reply, receiver) = oneshot::channel();
        let message: Message<Sha256, MinPk, TestBody> = Message::Fetch {
            span: Span::none(),
            target: Target::Lqc(CertificateId::new(Sha256::hash(&[label]))),
            reply: Reply::Lqc(reply),
            reason: FetchReason::Explicit,
        };
        (message, receiver)
    };
    let mut overflow = VecDeque::new();
    let (first, first_receiver) = fetch(b"canceled overflow fetch");
    <Message<Sha256, MinPk, TestBody> as Policy>::handle(&mut overflow, first);
    assert_eq!(overflow.len(), 1);
    drop(first_receiver);

    let (second, second_receiver) = fetch(b"already canceled overflow fetch");
    drop(second_receiver);
    <Message<Sha256, MinPk, TestBody> as Policy>::handle(&mut overflow, second);

    assert!(overflow.is_empty());
}

#[test]
fn overflowing_deliveries_are_ambiguous_and_certified_hints_dropped() {
    let mut overflow = VecDeque::new();
    let (reply, outcome) = oneshot::channel();
    let incoming = Incoming {
        span: Span::none(),
        delivery: delivery(
            BackfillKey::tip_record(Sha256::hash(&[b"overflow"])),
            BackfillSubscriber::default(),
        ),
        value: Bytes::new(),
        response: mailbox::DeliveryReply::new(reply),
    };
    <Message<Sha256, MinPk, TestBody> as Policy>::handle(&mut overflow, Message::Deliver(incoming));
    <Message<Sha256, MinPk, TestBody> as Policy>::handle(
        &mut overflow,
        Message::CertifiedBlock {
            reference: BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"hint"])),
        },
    );
    assert!(overflow.is_empty());
    assert_eq!(
        futures::executor::block_on(outcome).unwrap(),
        Outcome::Ambiguous
    );
}

#[test]
fn waiters_joining_a_fetching_key_fetch_under_their_own_subscriber() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "joining_waiter_test",
            resolver.clone(),
        )
        .await;
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let key = BackfillKey::tip_record(commitment);

        let first = request_history(&harness.mailbox, commitment, FetchReason::Finality);
        settle(&context).await;
        let second = request_history(&harness.mailbox, commitment, FetchReason::Finality);
        settle(&context).await;
        let subscribers = resolver.subscribers(key);
        assert_eq!(subscribers.len(), 2);
        assert_ne!(subscribers[0], subscribers[1]);

        // A response for the first waiter completes every waiter of the key.
        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(key, subscribers[0]),
                    vec![record.as_ref().clone()].encode(),
                )
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(
            first.await.unwrap().unwrap().as_slice(),
            &[Arc::clone(&record)]
        );
        assert_eq!(second.await.unwrap().unwrap().as_slice(), &[record]);

        harness.close().await;
    });
}

#[test]
fn stale_subscriber_delivery_completes_live_waiters() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "stale_subscriber_test",
            resolver.clone(),
        )
        .await;
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let key = BackfillKey::tip_record(commitment);

        let canceled = request_history(&harness.mailbox, commitment, FetchReason::Finality);
        settle(&context).await;
        let stale = resolver.subscriber(key);
        drop(canceled);
        settle(&context).await;
        let live = request_history(&harness.mailbox, commitment, FetchReason::Finality);
        settle(&context).await;

        // The response names only the canceled waiter, yet a live waiter of the key needs it.
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, stale), vec![record.as_ref().clone()].encode())
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(live.await.unwrap().unwrap().as_slice(), &[record]);

        harness.close().await;
    });
}

#[test]
fn canceled_waiters_are_reclaimed_at_capacity() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_capacity_test",
            "backfill",
            Options {
                max_value_bytes: NZUsize!(1024),
                max_pending: NZUsize!(2),
                max_active: NZUsize!(2),
                ..Options::default()
            },
            RecordingResolver::new(Feedback::Ok),
            AcceptVerifier,
        )
        .await;

        let mut canceled = Vec::new();
        for commitment in [
            Sha256::hash(&[b"canceled 0"]),
            Sha256::hash(&[b"canceled 1"]),
        ] {
            canceled.push(request_history(
                &harness.mailbox,
                commitment,
                FetchReason::Finality,
            ));
        }
        settle(&context).await;
        drop(canceled);

        let mut active = request_history(
            &harness.mailbox,
            Sha256::hash(&[b"active"]),
            FetchReason::Finality,
        );
        settle(&context).await;
        assert!(is_pending(&mut active));

        harness.abort().await;
    });
}

#[test]
fn finality_fetch_has_capacity_under_explicit_pressure() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_finality_capacity_test",
            "backfill",
            Options {
                max_value_bytes: NZUsize!(1024),
                max_pending: NZUsize!(1),
                max_active: NZUsize!(1),
                ..Options::default()
            },
            RecordingResolver::new(Feedback::Ok),
            AcceptVerifier,
        )
        .await;

        let mut explicit = request_history(
            &harness.mailbox,
            Sha256::hash(&[b"explicit pressure"]),
            FetchReason::Explicit,
        );
        settle(&context).await;

        let mut finality = request_history(
            &harness.mailbox,
            Sha256::hash(&[b"finality"]),
            FetchReason::Finality,
        );
        settle(&context).await;
        assert!(is_pending(&mut finality));
        assert!(matches!(explicit.try_recv(), Ok(Err(Error::PendingFull))));

        harness.abort().await;
    });
}

#[test]
fn local_custody_completes_before_peer_fetch() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let resolver = RecordingResolver::new(Feedback::Closed);
        let harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_local_first_test",
            "backfill",
            Options {
                max_value_bytes: NZUsize!(1024),
                max_pending: NZUsize!(8),
                max_active: NZUsize!(8),
                ..Options::default()
            },
            resolver.clone(),
            AcceptVerifier,
        )
        .await;
        let parent = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let record = Arc::new(
            TipRecord::at_tips(
                parent.commitment::<Sha256>(),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        harness
            .catalog
            .admit_history(
                View::new(1),
                parent.commitment::<Sha256>(),
                Arc::clone(&parent),
            )
            .await
            .unwrap();
        harness
            .catalog
            .admit_history(View::new(2), commitment, record.clone())
            .await
            .unwrap();

        let segment = harness
            .mailbox
            .history(FetchReason::Finality, View::new(1), commitment)
            .await
            .unwrap();
        assert_eq!(segment.as_slice(), &[record]);
        assert_eq!(resolver.fetches(), 0);

        let invalid = BlockRef::new(
            ChainId::new(committee.codec().chains() as u32),
            Height::new(1),
            Sha256::hash(&[b"invalid producer chain"]),
        );
        assert!(matches!(
            harness.mailbox.block(FetchReason::Explicit, invalid).await,
            Err(Error::Invalid("producer chain is outside the epoch"))
        ));
        assert_eq!(resolver.fetches(), 0);

        harness.close().await;
    });
}

#[test]
fn certified_blocks_fetch_only_for_live_authorized_waiters() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_certified_floor_test",
            "backfill",
            Options {
                max_value_bytes: NZUsize!(1024),
                max_pending: NZUsize!(4),
                max_active: NZUsize!(4),
                ..Options::default()
            },
            resolver.clone(),
            AcceptVerifier,
        )
        .await;
        let first = BlockRef::new(
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"first certified block"]),
        );
        let second = BlockRef::new(
            ChainId::new(0),
            Height::new(2),
            Sha256::hash(&[b"second certified block"]),
        );

        assert!(harness.mailbox.certified_block(first).accepted());
        assert!(harness.mailbox.certified_block(second).accepted());
        settle(&context).await;
        assert_eq!(resolver.fetches(), 0);
        let metrics = context.encode();
        assert!(metrics.contains("requests_started_total{reason=\"Certified\"} 0"));
        assert!(metrics.contains("requests_started_total{reason=\"Finality\"} 0"));

        harness.mailbox.retire_certified(vec![first]).await.unwrap();
        let mut retired = request_block(
            &harness.mailbox,
            first,
            BlockMode::Wait,
            FetchReason::CertifiedSubscription,
        );
        let mut authorized = request_block(
            &harness.mailbox,
            second,
            BlockMode::Wait,
            FetchReason::CertifiedSubscription,
        );
        settle(&context).await;
        assert!(is_pending(&mut retired));
        assert!(is_pending(&mut authorized));
        assert_eq!(resolver.fetches(), 1);
        assert!(
            context
                .encode()
                .contains("requests_started_total{reason=\"CertifiedSubscription\"} 1")
        );

        let explicit = BlockRef::new(
            ChainId::new(1),
            Height::new(3),
            Sha256::hash(&[b"explicit certified block"]),
        );
        assert!(harness.mailbox.certified_block(explicit).accepted());
        settle(&context).await;
        let explicit_receiver = request_block(
            &harness.mailbox,
            explicit,
            BlockMode::Fetch,
            FetchReason::Explicit,
        );
        settle(&context).await;
        assert_eq!(resolver.fetches(), 2);
        assert!(
            context
                .encode()
                .contains("requests_started_total{reason=\"Explicit\"} 1")
        );

        drop(retired);
        drop(authorized);
        drop(explicit_receiver);
        harness.close().await;
    });
}

#[test]
fn deliver_enforces_the_exact_value_byte_bound() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let key = BackfillKey::tip_record(commitment);
        let encoded = vec![record.as_ref().clone()].encode();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_value_bound_test",
            "backfill",
            Options {
                max_value_bytes: NonZeroUsize::new(encoded.len()).unwrap(),
                ..Options::default()
            },
            resolver.clone(),
            AcceptVerifier,
        )
        .await;
        let mut receiver = request_history(&harness.mailbox, commitment, FetchReason::Finality);
        settle(&context).await;
        let subscriber = resolver.subscriber(key);

        let mut oversized = BytesMut::from(encoded.as_ref());
        oversized.extend_from_slice(&[0]);
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), oversized.freeze())
                .await
                .unwrap(),
            Outcome::Invalid
        );
        assert!(is_pending(&mut receiver));
        assert!(harness.catalog.history(commitment).await.unwrap().is_none());

        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), encoded)
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(receiver.await.unwrap().unwrap().as_slice(), &[record]);
        assert!(harness.catalog.history(commitment).await.unwrap().is_none());

        harness.close().await;
    });
}

#[test]
fn deliver_rejects_malformed_and_wrong_identity_values() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let proof = Arc::new(committee.lqc(View::new(3)));
        let wrong_proof = committee.lqc(View::new(4));
        let id = proof.id::<Sha256>();
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let wrong_record = TipRecord::at_tips(
            Sha256::hash(&[b"wrong history parent"]),
            committee.config.genesis().tips().to_vec(),
        )
        .unwrap();
        let commitment = record.commitment::<Sha256>();
        let block = first_block(&committee, 0, 10);
        let reference = block.reference();
        let wrong_height = BlockRef::new(
            reference.chain(),
            reference.height().next(),
            reference.digest(),
        );
        let wrong_body = TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), 11);
        let wrong_block = TransactionBlock::<Sha256, _>::new(
            committee.transaction_header(ChainId::new(0), wrong_body.digest()),
            wrong_body,
        )
        .unwrap();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "resolver_adversarial_delivery_test",
            resolver.clone(),
        )
        .await;
        let mut lqc_receiver = request(
            &harness.mailbox,
            Target::Lqc(id),
            Reply::Lqc,
            FetchReason::Explicit,
        );
        let mut history_receiver =
            request_history(&harness.mailbox, commitment, FetchReason::Explicit);
        let mut block_receiver = request_block(
            &harness.mailbox,
            reference,
            BlockMode::Fetch,
            FetchReason::Explicit,
        );
        let mut wrong_height_receiver = request_block(
            &harness.mailbox,
            wrong_height,
            BlockMode::Fetch,
            FetchReason::Explicit,
        );
        settle(&context).await;
        let keys = [
            BackfillKey::lqc_by_id(id),
            BackfillKey::tip_record(commitment),
            block_key(reference),
        ];
        let block_subscribers = resolver.subscribers(keys[2]);
        assert_eq!(block_subscribers.len(), 2);
        let subscribers = [
            resolver.subscriber(keys[0]),
            resolver.subscriber(keys[1]),
            block_subscribers[0],
        ];

        let values = [
            proof.encode(),
            vec![record.as_ref().clone()].encode(),
            block.encode(),
        ];
        for ((key, subscriber), value) in keys.into_iter().zip(subscribers).zip(values) {
            let truncated = value.slice(..value.len() - 1);
            let mut trailing = BytesMut::from(value.as_ref());
            trailing.extend_from_slice(&[0]);
            for malformed in [truncated, trailing.freeze()] {
                assert_eq!(
                    harness
                        .bridge
                        .deliver(delivery(key, subscriber), malformed)
                        .await
                        .unwrap(),
                    Outcome::Invalid
                );
            }
        }

        for ((key, subscriber), value) in keys.into_iter().zip(subscribers).zip([
            wrong_proof.encode(),
            vec![wrong_record.clone()].encode(),
            wrong_block.encode(),
        ]) {
            assert_eq!(
                harness
                    .bridge
                    .deliver(delivery(key, subscriber), value)
                    .await
                    .unwrap(),
                Outcome::Invalid
            );
        }
        assert!(is_pending(&mut lqc_receiver));
        assert!(is_pending(&mut history_receiver));
        assert!(is_pending(&mut block_receiver));
        assert!(harness.catalog.lqc(id).await.unwrap().is_none());
        assert!(harness.catalog.history(commitment).await.unwrap().is_none());
        assert!(harness.catalog.block(reference).await.unwrap().is_none());
        assert!(
            harness
                .catalog
                .lqc(wrong_proof.id::<Sha256>())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            harness
                .catalog
                .history(wrong_record.commitment::<Sha256>())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            harness
                .catalog
                .block(wrong_block.reference())
                .await
                .unwrap()
                .is_none()
        );

        for ((key, subscriber), value) in keys.into_iter().zip(subscribers).zip([
            proof.encode(),
            vec![record.as_ref().clone()].encode(),
            block.encode(),
        ]) {
            assert_eq!(
                harness
                    .bridge
                    .deliver(delivery(key, subscriber), value)
                    .await
                    .unwrap(),
                Outcome::Complete
            );
        }
        assert_eq!(lqc_receiver.await.unwrap().unwrap(), proof);
        assert_eq!(
            history_receiver.await.unwrap().unwrap().as_slice(),
            &[record]
        );
        assert_eq!(block_receiver.await.unwrap().unwrap(), block);
        assert!(is_pending(&mut wrong_height_receiver));
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(keys[2], block_subscribers[1]), block.encode())
                .await
                .unwrap(),
            Outcome::Ambiguous
        );
        assert!(is_pending(&mut wrong_height_receiver));
        assert!(harness.catalog.block(wrong_height).await.unwrap().is_none());

        harness.close().await;
    });
}

#[test]
fn lqc_verification_does_not_block_other_deliveries() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let proof = Arc::new(committee.lqc(View::new(3)));
        let id = proof.id::<Sha256>();
        let record = Arc::new(
            TipRecord::at_tips(
                genesis_history::<Sha256>(committee.config.genesis()),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let (verifier, verification_started, release) = GatedVerifier::new();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open_with(
            &context,
            context.child("catalog"),
            &committee,
            "resolver_verification_lane_test",
            "backfill",
            Options::default(),
            resolver.clone(),
            verifier,
        )
        .await;
        let lqc = request(
            &harness.mailbox,
            Target::Lqc(id),
            Reply::Lqc,
            FetchReason::Explicit,
        );
        let history = request_history(&harness.mailbox, commitment, FetchReason::Explicit);
        settle(&context).await;
        let lqc_key = BackfillKey::lqc_by_id(id);
        let history_key = BackfillKey::tip_record(commitment);

        let mut lqc_outcome = Box::pin(harness.bridge.deliver(
            delivery(lqc_key, resolver.subscriber(lqc_key)),
            proof.encode(),
        ));
        select! {
            result = &mut lqc_outcome => panic!("gated verification completed: {result:?}"),
            result = verification_started => result.unwrap(),
        }

        // The history response completes while the L-QC verification is still held.
        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(history_key, resolver.subscriber(history_key)),
                    vec![record.as_ref().clone()].encode(),
                )
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(history.await.unwrap().unwrap().as_slice(), &[record]);

        release.send(()).unwrap();
        assert_eq!(lqc_outcome.await.unwrap(), Outcome::Complete);
        assert_eq!(lqc.await.unwrap().unwrap(), proof);
        assert_eq!(harness.catalog.lqc(id).await.unwrap(), Some(proof));

        harness.close().await;
    });
}

/// Opens a harness whose L-QC verifications go through `verifier`.
async fn verifying_harness(
    context: &deterministic::Context,
    committee: &Committee<MinPk>,
    partition: &str,
    options: Options,
    resolver: &RecordingResolver,
    verifier: GatedVerifier,
) -> Harness {
    Harness::open_with(
        context,
        context.child("catalog"),
        committee,
        partition,
        "backfill",
        options,
        resolver.clone(),
        verifier,
    )
    .await
}

#[test]
fn rejected_lqc_is_invalid_and_keeps_its_waiter() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let proof = Arc::new(committee.lqc(View::new(3)));
        let id = proof.id::<Sha256>();
        let (verifier, started, release) = GatedVerifier::new();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = verifying_harness(
            &context,
            &committee,
            "rejected_lqc_test",
            Options::default(),
            &resolver,
            verifier.clone(),
        )
        .await;
        let mut lqc = request(
            &harness.mailbox,
            Target::Lqc(id),
            Reply::Lqc,
            FetchReason::Explicit,
        );
        settle(&context).await;
        let key = BackfillKey::lqc_by_id(id);
        let subscriber = resolver.subscriber(key);
        let first = harness
            .bridge
            .deliver(delivery(key, subscriber), proof.encode());
        started.await.unwrap();

        // A second delivery while the key verifies is retried later instead of verified again.
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), proof.encode())
                .await
                .unwrap(),
            Outcome::Ambiguous
        );

        drop(release);
        assert_eq!(first.await.unwrap(), Outcome::Invalid);
        settle(&context).await;
        assert!(is_pending(&mut lqc));
        assert_eq!(harness.catalog.lqc(id).await.unwrap(), None);
        assert_eq!(*verifier.calls.lock(), 1);

        // The rejection released the key, so a later delivery verifies and completes the waiter.
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscriber), proof.encode())
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(*verifier.calls.lock(), 2);
        assert_eq!(lqc.await.unwrap().unwrap().id::<Sha256>(), id);
        assert!(harness.catalog.lqc(id).await.unwrap().is_some());

        harness.close().await;
    });
}

#[test]
fn rerequested_lqc_reuses_the_running_verification() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let proof = Arc::new(committee.lqc(View::new(3)));
        let id = proof.id::<Sha256>();
        let (verifier, started, release) = GatedVerifier::new();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = verifying_harness(
            &context,
            &committee,
            "rerequested_lqc_test",
            Options::default(),
            &resolver,
            verifier.clone(),
        )
        .await;
        let canceled = request(
            &harness.mailbox,
            Target::Lqc(id),
            Reply::Lqc,
            FetchReason::Explicit,
        );
        settle(&context).await;
        let key = BackfillKey::lqc_by_id(id);
        let first = harness
            .bridge
            .deliver(delivery(key, resolver.subscriber(key)), proof.encode());
        started.await.unwrap();

        // The caller gives up mid-verification and asks again.
        drop(canceled);
        settle(&context).await;
        let lqc = request(
            &harness.mailbox,
            Target::Lqc(id),
            Reply::Lqc,
            FetchReason::Explicit,
        );
        settle(&context).await;
        let subscribers = resolver.subscribers(key);
        assert_eq!(subscribers.len(), 2);
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, subscribers[1]), proof.encode())
                .await
                .unwrap(),
            Outcome::Ambiguous
        );

        // The running verification completes the new waiter.
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Outcome::Complete);
        assert_eq!(lqc.await.unwrap().unwrap(), proof);
        assert_eq!(harness.catalog.lqc(id).await.unwrap(), Some(proof));
        assert_eq!(*verifier.calls.lock(), 1);

        harness.close().await;
    });
}

#[test]
fn saturated_lqc_verifications_are_ambiguous() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let held = Arc::new(committee.lqc(View::new(3)));
        let other = Arc::new(committee.lqc(View::new(4)));
        let (verifier, started, release) = GatedVerifier::new();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = verifying_harness(
            &context,
            &committee,
            "saturated_lqc_test",
            Options {
                max_active: NZUsize!(1),
                ..Options::default()
            },
            &resolver,
            verifier.clone(),
        )
        .await;
        let mut replies = [&held, &other].map(|proof| {
            request(
                &harness.mailbox,
                Target::Lqc(proof.id::<Sha256>()),
                Reply::Lqc,
                FetchReason::Explicit,
            )
        });
        settle(&context).await;
        let [held_key, other_key] =
            [&held, &other].map(|proof| BackfillKey::lqc_by_id(proof.id::<Sha256>()));
        let first = harness.bridge.deliver(
            delivery(held_key, resolver.subscriber(held_key)),
            held.encode(),
        );
        started.await.unwrap();

        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(other_key, resolver.subscriber(other_key)),
                    other.encode()
                )
                .await
                .unwrap(),
            Outcome::Ambiguous
        );
        assert!(is_pending(&mut replies[1]));

        release.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Outcome::Complete);
        assert_eq!(
            harness
                .bridge
                .deliver(
                    delivery(other_key, resolver.subscriber(other_key)),
                    other.encode()
                )
                .await
                .unwrap(),
            Outcome::Complete
        );
        let [held_reply, other_reply] = replies;
        assert_eq!(held_reply.await.unwrap().unwrap(), held);
        assert_eq!(other_reply.await.unwrap().unwrap(), other);
        assert_eq!(*verifier.calls.lock(), 2);

        harness.close().await;
    });
}

#[test]
fn subscribed_fetch_defers_custody_to_the_service() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(9, 6).build();
        let block = first_block(&committee, 0, 12);
        let reference = block.reference();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "resolver_subscription_custody_test",
            resolver.clone(),
        )
        .await;
        let receiver = request_block(
            &harness.mailbox,
            reference,
            BlockMode::Wait,
            FetchReason::CertifiedSubscription,
        );
        assert!(harness.mailbox.certified_block(reference).accepted());
        settle(&context).await;
        let key = block_key(reference);
        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, resolver.subscriber(key)), block.encode())
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(receiver.await.unwrap().unwrap(), block);
        assert!(harness.catalog.block(reference).await.unwrap().is_none());

        harness.close().await;
    });
}

#[rstest]
#[case::spare_slot(false, false)]
#[case::completed_locally(true, false)]
#[case::canceled(false, true)]
fn blocked_local_recheck_does_not_stall_independent_fetch(
    #[case] complete_locally: bool,
    #[case] cancel_locally: bool,
) {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(49, 6).build();
        let blocks: [Arc<TestBlock>; 3] =
            std::array::from_fn(|index| first_block(&committee, index as u32, 49 + index as u64));
        let partition = "resolver_concurrent_recheck_test";
        let initial = Harness::open_with(
            &context,
            context.child("initial_catalog"),
            &committee,
            partition,
            "initial",
            Options {
                max_hot_block_bytes: NZUsize!(1),
                catalog_mailbox_size: NZUsize!(2),
                ..Options::default()
            },
            RecordingResolver::new(Feedback::Ok),
            AcceptVerifier,
        )
        .await;
        for block in &blocks {
            initial
                .catalog
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        initial.close().await;

        let reads = Gates::default();
        let delayed = DelayedReadContext {
            inner: context.child("reopened_catalog"),
            pending: reads.clone(),
        };
        let resolver = RecordingResolver::new(Feedback::Closed);
        let harness = Harness::open_with(
            &context,
            delayed,
            &committee,
            partition,
            "reopened",
            Options {
                max_active: NonZeroUsize::new(if complete_locally || cancel_locally { 1 } else { 16 })
                    .unwrap(),
                max_hot_block_bytes: NZUsize!(1),
                catalog_mailbox_size: NZUsize!(2),
                ..Options::default()
            },
            resolver.clone(),
            AcceptVerifier,
        )
        .await;

        let gate = reads.arm();
        let mut local = Box::pin(
            harness
                .mailbox
                .block(FetchReason::Explicit, blocks[0].reference()),
        );
        select! {
            result = &mut local => panic!("local block completed before its storage gate: {result:?}"),
            blocked = gate.blocked => blocked.unwrap(),
            _ = context.sleep(Duration::from_secs(1)) => panic!("local recheck never reached storage"),
        }

        let mut shared = Box::pin(
            harness
                .mailbox
                .block(FetchReason::Explicit, blocks[0].reference()),
        );
        select! {
            result = &mut shared => panic!("shared recheck completed before its storage gate: {result:?}"),
            _ = context.sleep(Duration::from_millis(10)) => {},
        }
        drop(shared);
        select! {
            result = &mut local => panic!("canceling one caller completed another: {result:?}"),
            _ = context.sleep(Duration::from_millis(10)) => {},
        }

        let missing = BlockRef::new(
            ChainId::new(1),
            Height::new(1),
            Sha256::hash(&[b"independent missing block"]),
        );
        if complete_locally || cancel_locally {
            let mut queued = Box::pin(harness.mailbox.block(FetchReason::Explicit, missing));
            select! {
                result = &mut queued => panic!("queued recheck bypassed the occupied slot: {result:?}"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }
            let metrics = context.encode();
            assert!(metrics.contains("reopened_resolver_local_rechecks_queued 1"), "{metrics}");
            drop(queued);
            context.sleep(Duration::from_millis(10)).await;
            let metrics = context.encode();
            assert!(metrics.contains("reopened_resolver_local_rechecks_queued 0"), "{metrics}");
        }

        if complete_locally {
            harness
                .mailbox
                .admitted_block(blocks[0].reference(), Arc::clone(&blocks[0]))
                .await
                .unwrap();
            assert_eq!((&mut local).await.unwrap(), blocks[0]);
        }
        let mut local = if cancel_locally {
            drop(local);
            None
        } else {
            Some(local)
        };

        let independent = expect_within(
            &context,
            Duration::from_millis(100),
            harness.mailbox.block(FetchReason::Explicit, missing),
            "a blocked local recheck stalled an independent fetch",
        )
        .await;
        assert!(matches!(independent, Err(Error::NetworkClosed)));
        assert_eq!(resolver.fetches(), 1);

        let _ = gate.release.send(());
        if !complete_locally && let Some(local) = local.as_mut() {
            assert_eq!(local.await.unwrap(), blocks[0]);
        }
        drop(local);
        assert_eq!(resolver.fetches(), 1);

        harness.close().await;
    });
}

#[test]
fn late_custody_waiter_stages_shared_delivery() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(10, 6).build();
        let block = first_block(&committee, 0, 13);
        let reference = block.reference();
        let resolver = RecordingResolver::new(Feedback::Ok);
        let mut harness = Harness::open(
            &context,
            &committee,
            "resolver_late_custody_waiter_test",
            resolver.clone(),
        )
        .await;
        let subscription = request_block(
            &harness.mailbox,
            reference,
            BlockMode::Subscribe,
            FetchReason::Explicit,
        );
        let fetch = request_block(
            &harness.mailbox,
            reference,
            BlockMode::Fetch,
            FetchReason::Explicit,
        );
        settle(&context).await;
        let key = block_key(reference);

        assert_eq!(
            harness
                .bridge
                .deliver(delivery(key, resolver.subscribers(key)[0]), block.encode())
                .await
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(subscription.await.unwrap().unwrap(), block);
        assert_eq!(fetch.await.unwrap().unwrap(), block);
        assert_eq!(
            harness.catalog.block(reference).await.unwrap().as_deref(),
            Some(block.as_ref())
        );

        harness.close().await;
    });
}

#[test]
fn fetched_block_deliveries_share_one_catalog_admission_cut() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(43, 6).build();
        let blocks = [0, 1].map(|chain| first_block(&committee, chain, u64::from(chain)));
        let syncs = PendingSyncs::default();
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: syncs.clone(),
        };
        let resolver = RecordingResolver::new(Feedback::Ok);
        let harness = Harness::open_with(
            &context,
            delayed.child("catalog"),
            &committee,
            "resolver_block_slice_test",
            "backfill",
            Options::default(),
            resolver.clone(),
            AcceptVerifier,
        )
        .await;
        let mut _block_receivers = Vec::new();
        for block in &blocks {
            _block_receivers.push(request_block(
                &harness.mailbox,
                block.reference(),
                BlockMode::Fetch,
                FetchReason::FinalizedBody,
            ));
        }
        settle(&context).await;

        syncs.arm();
        let keys = blocks.each_ref().map(|block| block_key(block.reference()));
        let [first, second] = [0, 1].map(|index| {
            harness.bridge.clone().deliver(
                delivery(keys[index], resolver.subscriber(keys[index])),
                blocks[index].encode(),
            )
        });
        let (first, second) = futures::join!(first, second);
        assert_eq!(first.unwrap(), Outcome::Complete);
        assert_eq!(second.unwrap(), Outcome::Complete);

        for _ in 0..100 {
            if syncs.calls() > 0 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        let cut_syncs = syncs.calls();
        assert!(cut_syncs > 0, "block slice did not start durability");
        release_next_pending_syncs(&syncs, cut_syncs);

        let references = blocks.iter().map(|block| block.reference()).collect();
        let durable = expect_within(
            &context,
            Duration::from_millis(100),
            harness.catalog.wait_for_custody(references),
            "block slice did not become durable after one admission cut",
        )
        .await
        .unwrap();
        assert_eq!(
            syncs.calls(),
            cut_syncs,
            "fetched blocks were split across durability cuts"
        );
        assert!(durable.into_iter().all(|value| value.is_some()));

        syncs.unblock();
        harness.close().await;
    });
}

#[test]
fn exact_identity_and_ambiguity_are_distinct() {
    let committee = Committee::<MinPk>::builder(7, 6).build();
    let proof = committee.lqc(View::new(3));
    let received = proof.id::<Sha256>();
    let other = committee.lqc(View::new(4)).id::<Sha256>();
    assert_ne!(received, other);
    assert_eq!(proof.epoch(), committee.config.epoch());
    assert_eq!(
        Lqc::<MinPk, Sha256Digest>::decode_cfg(proof.encode(), &committee.codec())
            .unwrap()
            .id::<Sha256>(),
        received
    );
}

mod serve {
    use super::*;

    #[test]
    fn producer_caps_consecutive_body_ranges_to_response_budget() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(52, 6).build();
            let blocks = producer_chain(&committee, 4);
            assert!(blocks.iter().all(|block| block.encode_size() <= 112));
            let mut harness = Harness::open_with(
                &context,
                context.child("catalog"),
                &committee,
                "producer_body_range_test",
                "backfill",
                Options {
                    max_value_bytes: NonZeroUsize::new(3 * 112 + 3usize.encode_size()).unwrap(),
                    ..Options::default()
                },
                RecordingResolver::new(Feedback::Ok),
                AcceptVerifier,
            )
            .await;
            for block in &blocks {
                harness
                    .catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let head = blocks.last().unwrap().reference();
            let value = harness
                .bridge
                .produce(BackfillKey::producer_blocks(
                    head,
                    NonZeroU16::new(4).unwrap(),
                ))
                .await
                .unwrap();
            let decoded =
                Vec::<TestBlock>::decode_cfg(value, &(RangeCfg::from(1..=4), ())).unwrap();
            assert_eq!(
                decoded
                    .iter()
                    .map(TransactionBlock::reference)
                    .collect::<Vec<_>>(),
                blocks
                    .iter()
                    .rev()
                    .take(3)
                    .map(|block| block.reference())
                    .collect::<Vec<_>>()
            );

            harness.close().await;
        });
    }

    #[test]
    fn blocked_producer_key_does_not_stall_independent_serves() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(47, 6).build();
            let blocks: [Arc<TestBlock>; 3] = std::array::from_fn(|index| {
                first_block(&committee, [0, 1, 0][index], 47 + index as u64)
            });
            let history_parent = genesis_history::<Sha256>(committee.config.genesis());
            let history = Arc::new(
                TipRecord::at_tips(history_parent, committee.config.genesis().tips().to_vec())
                    .unwrap(),
            );
            let history_commitment = history.commitment::<Sha256>();
            let partition = "resolver_concurrent_produce_test";
            let options = || Options {
                max_hot_block_bytes: NZUsize!(1),
                catalog_mailbox_size: NZUsize!(2),
                ..Options::default()
            };
            let initial = Harness::open_with(
                &context,
                context.child("initial_catalog"),
                &committee,
                partition,
                "initial",
                options(),
                RecordingResolver::new(Feedback::Ok),
                AcceptVerifier,
            )
            .await;
            for block in &blocks {
                initial
                    .catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            initial
                .catalog
                .admit_history(View::new(1), history_commitment, Arc::clone(&history))
                .await
                .unwrap();
            initial.close().await;

            let reads = Gates::default();
            let delayed = DelayedReadContext {
                inner: context.child("reopened_catalog"),
                pending: reads.clone(),
            };
            let mut harness = Harness::open_with(
                &context,
                delayed,
                &committee,
                partition,
                "reopened",
                options(),
                RecordingResolver::new(Feedback::Ok),
                AcceptVerifier,
            )
            .await;

            let gate = reads.arm();
            let mut first = Box::pin(harness.bridge.produce(block_key(blocks[0].reference())));
            select! {
                result = &mut first => panic!("first producer read completed before its gate: {result:?}"),
                blocked = gate.blocked => blocked.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first producer read never reached storage"),
            }
            let duplicate = harness.bridge.produce(block_key(blocks[0].reference()));
            let second = harness
                .bridge
                .produce(BackfillKey::tip_record(history_commitment));
            let second = expect_within(
                &context,
                Duration::from_secs(1),
                second,
                "a blocked producer key stalled an independent serve",
            )
            .await;
            assert_eq!(second.unwrap(), vec![history.as_ref().clone()].encode());

            let Harness {
                bridge,
                mailbox,
                catalog,
                _delivery,
                backfill,
                serve,
                catalog_handle,
            } = harness;
            drop(mailbox);
            drop(bridge);
            let mut serve = Box::pin(serve);
            select! {
                result = &mut serve => {
                    panic!("clean shutdown aborted an accepted producer read: {result:?}")
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }
            let _ = gate.release.send(());
            assert_eq!(first.await.unwrap(), blocks[0].encode());
            let duplicate = expect_within(
                &context,
                Duration::from_secs(1),
                duplicate,
                "an exact duplicate started a second storage read",
            )
            .await;
            assert_eq!(duplicate.unwrap(), blocks[0].encode());

            drop(catalog);
            assert!(backfill.await.unwrap().is_ok());
            assert!(serve.await.unwrap().is_ok());
            assert!(catalog_handle.await.unwrap().is_ok());
        });
    }

    #[test]
    fn admitted_producer_request_waits_for_actor_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(51, 6).build();
            let blocks: [Arc<TestBlock>; 3] =
                std::array::from_fn(|index| first_block(&committee, index as u32, 51 + index as u64));
            let block = &blocks[0];
            let history = Arc::new(
                TipRecord::at_tips(
                    genesis_history::<Sha256>(committee.config.genesis()),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let history_commitment = history.commitment::<Sha256>();
            let partition = "resolver_producer_admission_test";
            let options = || Options {
                max_pending: NZUsize!(1),
                max_active: NZUsize!(1),
                max_hot_block_bytes: NZUsize!(1),
                catalog_mailbox_size: NZUsize!(2),
                ..Options::default()
            };
            let initial = Harness::open_with(
                &context,
                context.child("initial_catalog"),
                &committee,
                partition,
                "initial",
                options(),
                RecordingResolver::new(Feedback::Ok),
                AcceptVerifier,
            )
            .await;
            for block in &blocks {
                initial
                    .catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            initial
                .catalog
                .admit_history(View::new(1), history_commitment, Arc::clone(&history))
                .await
                .unwrap();
            initial.close().await;

            let reads = Gates::default();
            let delayed = DelayedReadContext {
                inner: context.child("reopened_catalog"),
                pending: reads.clone(),
            };
            let mut harness = Harness::open_with(
                &context,
                delayed,
                &committee,
                partition,
                "reopened",
                options(),
                RecordingResolver::new(Feedback::Ok),
                AcceptVerifier,
            )
            .await;

            let gate = reads.arm();
            let mut first = Box::pin(harness.bridge.produce(block_key(block.reference())));
            select! {
                result = &mut first => panic!("first producer read completed before its gate: {result:?}"),
                result = gate.blocked => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first producer read never reached storage"),
            }

            let mut second = Box::pin(
                harness
                    .bridge
                    .produce(BackfillKey::tip_record(history_commitment)),
            );
            select! {
                result = &mut second => panic!("admitted producer request was rejected internally: {result:?}"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }

            gate.release.send(()).unwrap();
            assert_eq!(first.await.unwrap(), block.encode());
            assert_eq!(second.await.unwrap(), vec![history.as_ref().clone()].encode());

            harness.close().await;
        });
    }
}
