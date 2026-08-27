//! Shared marshal fixtures for stateful actor tests.

use super::mocks::{TestBlock, TestScheme, TestVariant};
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{
        self, Update,
        core::{Actor as MarshalActor, Floor, Mailbox as MarshalMailbox},
        resolver::handler,
    },
    simplex::types::{Finalization, Finalize, Proposal},
    types::{Epoch, FixedEpocher, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _,
    certificate::{ConstantProvider, mocks::Fixture},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_resolver::{Fetch, Resolver, TargetedResolver};
use commonware_runtime::{Handle, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    archive::{Archive as _, immutable, prunable},
    translator::TwoCap,
};
use commonware_utils::{
    NZU16, NZU64, NZUsize,
    acknowledgement::{Acknowledgement as _, Exact},
    non_empty,
    sync::Mutex,
    vec::NonEmptyVec,
};
use std::{num::NonZeroUsize, sync::Arc};

#[derive(Clone)]
struct FixtureReporter {
    acknowledge: bool,
    pending: Arc<Mutex<Vec<Exact>>>,
}

impl Reporter for FixtureReporter {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = activity {
            if self.acknowledge {
                ack.acknowledge();
            } else {
                self.pending.lock().push(ack);
            }
        }
        Feedback::Ok
    }
}

#[derive(Clone, Copy)]
enum Dispatch {
    Stopped,
    Acknowledge,
    Hold,
}

struct Options<'a> {
    seed: Option<(&'a TestBlock, Finalization<TestScheme, Sha256Digest>)>,
    block: Option<&'a TestBlock>,
    floor: Option<Finalization<TestScheme, Sha256Digest>>,
    max_pending_acks: NonZeroUsize,
    dispatch: Dispatch,
}

/// Backfill resolver for a started marshal fixture: its archives are pre-seeded, so
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

/// Builds a finalization for `view` over `payload`, signed by every scheme in `fixture`.
pub(crate) fn finalization(
    fixture: &Fixture<TestScheme>,
    view: u64,
    payload: Sha256Digest,
) -> Finalization<TestScheme, Sha256Digest> {
    let proposal = Proposal {
        round: Round::new(Epoch::zero(), View::new(view)),
        parent: View::new(view.saturating_sub(1)),
        payload,
    };
    let finalizes = fixture
        .schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
        .collect::<Vec<_>>();
    Finalization::from_finalizes(
        &fixture.verifier,
        non_empty![@finalizes.iter()],
        &Sequential,
    )
    .expect("recover finalization")
}

fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
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

fn prunable_archive_config(page_cache: CacheRef, partition: &str) -> prunable::Config<TwoCap, ()> {
    prunable::Config {
        translator: TwoCap,
        key_partition: format!("{partition}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{partition}-value"),
        compression: None,
        codec_config: (),
        items_per_section: NZU64!(4),
        key_write_buffer: NZUsize!(64),
        value_write_buffer: NZUsize!(64),
        replay_buffer: NZUsize!(64),
    }
}

/// A marshal actor fixture over initialized finalization and block archives.
pub(crate) struct MarshalFixture {
    pub(crate) mailbox: MarshalMailbox<TestScheme, TestVariant>,
    pub(crate) floor: Floor,
    /// Keeps the fixture alive: the unstarted actor (its mailbox dead-letters once this
    /// drops) or the started actor's resolver handler and task handle.
    pub(crate) guards: Box<dyn std::any::Any>,
}

impl MarshalFixture {
    /// Aborts a started fixture so its durable storage can be reopened.
    pub(crate) fn abort(self) {
        let guards = self
            .guards
            .downcast::<(handler::Handler<Sha256Digest>, Handle<()>)>()
            .unwrap_or_else(|_| panic!("marshal fixture was not started"));
        let (_, handle) = *guards;
        handle.abort();
    }
}

/// Initializes a marshal actor whose finalization archive is pre-seeded with `seed`.
///
/// When `start` is set, the actor runs with a reporter that acknowledges every dispatched
/// block and a resolver that ignores every fetch, so `get_finalization` serves the seeded
/// finalization without any peer fetching. Otherwise the actor is returned unstarted
/// inside [`MarshalFixture::guards`].
pub(crate) async fn marshal_fixture(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    seed: Option<(&TestBlock, Finalization<TestScheme, Sha256Digest>)>,
    max_pending_acks: NonZeroUsize,
    start: bool,
) -> MarshalFixture {
    let dispatch = if start {
        Dispatch::Acknowledge
    } else {
        Dispatch::Stopped
    };
    marshal_fixture_inner(
        context,
        prefix,
        scheme,
        Options {
            seed,
            block: None,
            floor: None,
            max_pending_acks,
            dispatch,
        },
    )
    .await
}

/// Initializes a marshal actor whose finalized-block archive is pre-seeded with `block`.
pub(crate) async fn marshal_fixture_with_finalized_block(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    block: &TestBlock,
    max_pending_acks: NonZeroUsize,
    start: bool,
) -> MarshalFixture {
    let dispatch = if start {
        Dispatch::Acknowledge
    } else {
        Dispatch::Stopped
    };
    marshal_fixture_inner(
        context,
        prefix,
        scheme,
        Options {
            seed: None,
            block: Some(block),
            floor: None,
            max_pending_acks,
            dispatch,
        },
    )
    .await
}

/// Initializes a started marshal actor with `block` as its floor anchor and freezes the
/// anchor acknowledgement so the durable processed height remains at its predecessor.
pub(crate) async fn marshal_fixture_with_floor(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    block: &TestBlock,
    finalization: Finalization<TestScheme, Sha256Digest>,
    max_pending_acks: NonZeroUsize,
) -> MarshalFixture {
    marshal_fixture_inner(
        context,
        prefix,
        scheme,
        Options {
            seed: None,
            block: Some(block),
            floor: Some(finalization),
            max_pending_acks,
            dispatch: Dispatch::Hold,
        },
    )
    .await
}

/// Initializes a started marshal actor over prunable finalized archives.
///
/// When provided, `block` is pre-seeded. Dispatched blocks are held open unless
/// `acknowledge` is set.
pub(crate) async fn prunable_marshal_fixture(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    block: Option<&TestBlock>,
    floor: Option<Finalization<TestScheme, Sha256Digest>>,
    max_pending_acks: NonZeroUsize,
    acknowledge: bool,
) -> MarshalFixture {
    let options = Options {
        seed: None,
        block,
        floor,
        max_pending_acks,
        dispatch: if acknowledge {
            Dispatch::Acknowledge
        } else {
            Dispatch::Hold
        },
    };
    let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        prunable_archive_config(page_cache.clone(), &format!("{prefix}-finalizations")),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let mut finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        prunable_archive_config(page_cache.clone(), &format!("{prefix}-blocks")),
    )
    .await
    .expect("failed to initialize blocks archive");
    if let Some(block) = options.block {
        finalized_blocks = finalized_blocks
            .put(block.height().get(), block.digest(), block.clone())
            .await
            .expect("failed to seed finalized block")
            .sync()
            .await
            .expect("failed to sync finalized blocks archive");
    }

    start_marshal_fixture(
        context,
        prefix,
        scheme,
        options,
        page_cache,
        finalizations_by_height,
        finalized_blocks,
    )
    .await
}

async fn marshal_fixture_inner(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    mut options: Options<'_>,
) -> MarshalFixture {
    let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
    let mut finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config(page_cache.clone(), &format!("{prefix}-finalizations")),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let mut finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        archive_config(page_cache.clone(), &format!("{prefix}-blocks")),
    )
    .await
    .expect("failed to initialize blocks archive");
    if let Some(block) = options.block {
        finalized_blocks = finalized_blocks
            .put(block.height().get(), block.digest(), block.clone())
            .await
            .expect("failed to seed finalized block")
            .sync()
            .await
            .expect("failed to sync finalized blocks archive");
    }
    if let Some((block, finalization)) = options.seed.take() {
        finalizations_by_height = finalizations_by_height
            .put(block.height().get(), block.digest(), finalization)
            .await
            .expect("failed to seed finalization")
            .sync()
            .await
            .expect("failed to sync finalizations archive");
    }

    start_marshal_fixture(
        context,
        prefix,
        scheme,
        options,
        page_cache,
        finalizations_by_height,
        finalized_blocks,
    )
    .await
}

async fn start_marshal_fixture<FC, FB>(
    context: deterministic::Context,
    prefix: &str,
    scheme: TestScheme,
    options: Options<'_>,
    page_cache: CacheRef,
    finalizations_by_height: FC,
    finalized_blocks: FB,
) -> MarshalFixture
where
    FC: marshal::store::Certificates<
            BlockDigest = Sha256Digest,
            Commitment = Sha256Digest,
            Scheme = TestScheme,
        >,
    FB: marshal::store::Blocks<Block = TestBlock>,
{
    let provider = ConstantProvider::new(scheme);
    let (actor, mailbox, floor) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
        context.child("marshal_actor"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider,
            epocher: FixedEpocher::new(NZU64!(u64::MAX)),
            start: options.floor.map_or_else(
                || marshal::Start::Genesis(TestBlock::new(0, 0)),
                marshal::Start::Floor,
            ),
            partition_prefix: format!("{prefix}-marshal"),
            mailbox_size: NZUsize!(8),
            view_retention: ViewDelta::new(1),
            prunable_items_per_section: NZU64!(4),
            page_cache,
            replay_buffer: NZUsize!(64),
            key_write_buffer: NZUsize!(64),
            value_write_buffer: NZUsize!(64),
            block_codec_config: (),
            max_repair: NZUsize!(1),
            max_pending_acks: options.max_pending_acks,
            strategy: Sequential,
        },
    )
    .await;
    if matches!(options.dispatch, Dispatch::Stopped) {
        return MarshalFixture {
            mailbox,
            floor,
            guards: Box::new(actor),
        };
    }

    let (resolver_receiver, resolver_handler) =
        handler::init(context.child("resolver_handler"), NZUsize!(8));
    let reporter = FixtureReporter {
        acknowledge: matches!(options.dispatch, Dispatch::Acknowledge),
        pending: Arc::new(Mutex::new(Vec::new())),
    };
    let handle = actor.start_unbuffered(reporter, (resolver_receiver, IgnoreResolver));
    MarshalFixture {
        mailbox,
        floor,
        guards: Box::new((resolver_handler, handle)),
    }
}
