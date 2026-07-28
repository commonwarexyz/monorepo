//! Shared marshal fixtures for stateful actor tests.

use super::mocks::{TestBlock, TestScheme, TestVariant};
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{
        self, Update,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
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
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::archive::{Archive as _, immutable};
use commonware_utils::{
    NZU16, NZU64, NZUsize, acknowledgement::Acknowledgement as _, vec::NonEmptyVec,
};

/// Reporter for a started marshal fixture that acknowledges every dispatched block.
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
    Finalization::from_finalizes(&fixture.verifier, &finalizes, &Sequential)
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

/// A marshal actor fixture over freshly initialized immutable archives.
pub(crate) struct MarshalFixture {
    pub(crate) mailbox: MarshalMailbox<TestScheme, TestVariant>,
    /// Keeps the fixture alive: the unstarted actor (its mailbox dead-letters once this
    /// drops) or the started actor's resolver handler and task handle.
    pub(crate) guards: Box<dyn std::any::Any>,
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
    start: bool,
) -> MarshalFixture {
    let provider = ConstantProvider::new(scheme);
    let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
    let mut finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config(page_cache.clone(), &format!("{prefix}-finalizations")),
    )
    .await
    .expect("failed to initialize finalizations archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        archive_config(page_cache.clone(), &format!("{prefix}-blocks")),
    )
    .await
    .expect("failed to initialize blocks archive");
    if let Some((block, finalization)) = seed {
        finalizations_by_height = finalizations_by_height
            .put(block.height().get(), block.digest(), finalization)
            .await
            .expect("failed to seed finalization")
            .sync()
            .await
            .expect("failed to sync finalizations archive");
    }

    let (actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
        context.child("marshal_actor"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider,
            epocher: FixedEpocher::new(NZU64!(u64::MAX)),
            start: marshal::Start::Genesis(TestBlock::new(0, 0)),
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
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;
    if !start {
        return MarshalFixture {
            mailbox,
            guards: Box::new(actor),
        };
    }

    let (resolver_receiver, resolver_handler) =
        handler::init(context.child("resolver_handler"), NZUsize!(8));
    let handle = actor.start_unbuffered(NoopReporter, (resolver_receiver, IgnoreResolver));
    MarshalFixture {
        mailbox,
        guards: Box::new((resolver_handler, handle)),
    }
}
