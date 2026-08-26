//! Application and Marshal adapters plus validator, network, engine, and
//! liveness setup for the end-to-end Twins backend.

use super::{
    super::{
        ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE,
        app::{
            AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, DeliveryReporter,
            FaultyConfig, SelectedBlockBuilderApp,
        },
    },
    B, Ctx, PublicKeyOf, SchemeOf,
};
use crate::{
    NetworkChannels,
    network::{WedgeChannel, WedgeNode, WedgeReceiver},
    simplex::Simplex,
};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    marshal::{
        Config, Start, Update,
        core::{Actor, Buffer, Mailbox},
        mocks::{
            application::Application,
            block::Block as MockBlock,
            harness::{BLOCKS_PER_EPOCH, LINK, PAGE_CACHE_SIZE, PAGE_SIZE, TEST_QUOTA},
        },
        resolver::{handler, p2p as resolver},
        standard::{Deferred, Inline, Standard},
    },
    simplex::{
        Engine, Floor, Plan, SkipBudget, SkipPolicy, config,
        elector::Config as ElectorConfig,
        types::{Context as SimplexContext, Finalization},
    },
    types::{Delta, Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digest, Hasher as _, PublicKey, Sha256,
    certificate::{ConstantProvider, Verifier as _},
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Sender,
    simulated::{Config as NetworkConfig, Network as SimulatedNetwork, Oracle},
};
use commonware_parallel::Sequential;
use commonware_resolver::TargetedResolver;
use commonware_runtime::{
    Clock, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::immutable;
use commonware_utils::{NZU64, NZUsize, channel::oneshot};
use std::{fmt, num::NonZeroUsize, sync::Arc, time::Duration};

pub(crate) const DEFAULT_MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(64);
const POLL: Duration = Duration::from_millis(50);
/// Marshal Twins' budget includes its scripted prefix and slower links.
const MARSHAL_TWINS_LIVENESS_WINDOW: Duration = Duration::from_secs(360);
const LEADER_TIMEOUT_MILLIS: u64 = 1_000;
const CERTIFICATION_TIMEOUT_MILLIS: u64 = 2_000;
const ATTACK_TIMING_MARGIN_MILLIS: u64 = 250;
const LEADER_TIMEOUT: Duration = Duration::from_millis(LEADER_TIMEOUT_MILLIS);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_millis(CERTIFICATION_TIMEOUT_MILLIS);
// The slow validator must time out in the precursor view, then finish early
// enough to vote for the good header in the attack view.
pub(crate) const ATTACK_SLOW_VERIFY_DELAY: Duration =
    Duration::from_millis(CERTIFICATION_TIMEOUT_MILLIS + ATTACK_TIMING_MARGIN_MILLIS);
// The victim must remain uncertified while the attack-view header is checked.
pub(crate) const ATTACK_VICTIM_VERIFY_DELAY: Duration = Duration::from_millis(
    CERTIFICATION_TIMEOUT_MILLIS + LEADER_TIMEOUT_MILLIS + ATTACK_TIMING_MARGIN_MILLIS,
);

pub(crate) trait TwinsBlockBuilder<P: Simplex>:
    commonware_consensus::Application<
        deterministic::Context,
        SigningScheme = SchemeOf<P>,
        Context = Ctx<P>,
        Block = B<P>,
        Input = (),
    > + Clone
    + Reporter<Activity = Update<B<P>>>
{
    fn create(
        choice: ApplicationChoice,
        config: FaultyConfig,
        verification_delay: Option<(View, Duration)>,
        block_contexts: BlockContextRegistry<Ctx<P>>,
        reporter: DeliveryReporter<Ctx<P>>,
    ) -> Self;

    fn rejects(choice: ApplicationChoice, config: FaultyConfig, context: &Ctx<P>) -> bool;
}

impl<P: Simplex> TwinsBlockBuilder<P> for AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>> {
    fn create(
        _choice: ApplicationChoice,
        _config: FaultyConfig,
        verification_delay: Option<(View, Duration)>,
        block_contexts: BlockContextRegistry<Ctx<P>>,
        reporter: DeliveryReporter<Ctx<P>>,
    ) -> Self {
        let application = match verification_delay {
            Some((view, delay)) => Self::with_verification_delay(view, delay),
            None => Self::default(),
        };
        application
            .with_block_contexts(block_contexts)
            .with_reporter(reporter)
    }

    fn rejects(_choice: ApplicationChoice, _config: FaultyConfig, _context: &Ctx<P>) -> bool {
        false
    }
}

impl<P: Simplex> TwinsBlockBuilder<P> for SelectedBlockBuilderApp<Ctx<P>, SchemeOf<P>> {
    fn create(
        choice: ApplicationChoice,
        config: FaultyConfig,
        verification_delay: Option<(View, Duration)>,
        block_contexts: BlockContextRegistry<Ctx<P>>,
        reporter: DeliveryReporter<Ctx<P>>,
    ) -> Self {
        Self::new(choice, config, verification_delay)
            .with_block_contexts(block_contexts)
            .with_reporter(reporter)
    }

    fn rejects(choice: ApplicationChoice, config: FaultyConfig, context: &Ctx<P>) -> bool {
        Self::rejects(choice, config, context)
    }
}

/// Instantiates the standard marshal wrapper used as the Simplex automaton and relay.
pub(crate) trait TwinsMarshal<P: Simplex, A: TwinsBlockBuilder<P>> {
    type Wrapper: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>
        + Relay<Digest = Sha256Digest, PublicKey = PublicKeyOf<P>, Plan = Plan<PublicKeyOf<P>>>
        + Reporter<Activity = Update<B<P>>>;

    fn create(
        choice: MarshalChoice,
        context: &deterministic::Context,
        application: A,
        mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    ) -> Self::Wrapper;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarshalChoice {
    Deferred,
    Inline,
}

impl fmt::Display for MarshalChoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deferred => formatter.write_str("deferred"),
            Self::Inline => formatter.write_str("inline"),
        }
    }
}

pub(crate) struct DeferredMarshal;

impl<P: Simplex, A: TwinsBlockBuilder<P>> TwinsMarshal<P, A> for DeferredMarshal {
    type Wrapper = Deferred<deterministic::Context, SchemeOf<P>, A, B<P>, FixedEpocher>;

    fn create(
        _choice: MarshalChoice,
        context: &deterministic::Context,
        application: A,
        mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    ) -> Self::Wrapper {
        Deferred::new(
            context.child("deferred"),
            application,
            mailbox,
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        )
    }
}

pub(crate) struct InlineMarshal;

impl<P: Simplex, A: TwinsBlockBuilder<P>> TwinsMarshal<P, A> for InlineMarshal {
    type Wrapper = Inline<deterministic::Context, SchemeOf<P>, A, B<P>, FixedEpocher>;

    fn create(
        _choice: MarshalChoice,
        context: &deterministic::Context,
        application: A,
        mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    ) -> Self::Wrapper {
        Inline::new(
            context.child("inline"),
            application,
            mailbox,
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        )
    }
}

pub(crate) struct SelectedMarshal;

pub(crate) enum SelectedMarshalWrapper<P: Simplex, A: TwinsBlockBuilder<P>> {
    Deferred(Deferred<deterministic::Context, SchemeOf<P>, A, B<P>, FixedEpocher>),
    Inline(Inline<deterministic::Context, SchemeOf<P>, A, B<P>, FixedEpocher>),
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> Clone for SelectedMarshalWrapper<P, A> {
    fn clone(&self) -> Self {
        match self {
            Self::Deferred(wrapper) => Self::Deferred(wrapper.clone()),
            Self::Inline(wrapper) => Self::Inline(wrapper.clone()),
        }
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> Automaton for SelectedMarshalWrapper<P, A> {
    type Context = Ctx<P>;
    type Digest = Sha256Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        match self {
            Self::Deferred(wrapper) => wrapper.propose(context).await,
            Self::Inline(wrapper) => wrapper.propose(context).await,
        }
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(wrapper) => wrapper.verify(context, digest).await,
            Self::Inline(wrapper) => wrapper.verify(context, digest).await,
        }
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> CertifiableAutomaton for SelectedMarshalWrapper<P, A> {
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(wrapper) => wrapper.certify(round, digest).await,
            Self::Inline(wrapper) => wrapper.certify(round, digest).await,
        }
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> Relay for SelectedMarshalWrapper<P, A> {
    type Digest = Sha256Digest;
    type PublicKey = PublicKeyOf<P>;
    type Plan = Plan<PublicKeyOf<P>>;

    fn broadcast(&mut self, digest: Self::Digest, plan: Self::Plan) -> Feedback {
        match self {
            Self::Deferred(wrapper) => wrapper.broadcast(digest, plan),
            Self::Inline(wrapper) => wrapper.broadcast(digest, plan),
        }
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> Reporter for SelectedMarshalWrapper<P, A> {
    type Activity = Update<B<P>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Deferred(wrapper) => wrapper.report(activity),
            Self::Inline(wrapper) => wrapper.report(activity),
        }
    }
}

impl<P: Simplex, A: TwinsBlockBuilder<P>> TwinsMarshal<P, A> for SelectedMarshal {
    type Wrapper = SelectedMarshalWrapper<P, A>;

    fn create(
        choice: MarshalChoice,
        context: &deterministic::Context,
        application: A,
        mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    ) -> Self::Wrapper {
        match choice {
            MarshalChoice::Deferred => Self::Wrapper::Deferred(Deferred::new(
                context.child("deferred"),
                application,
                mailbox,
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            )),
            MarshalChoice::Inline => Self::Wrapper::Inline(Inline::new(
                context.child("inline"),
                application,
                mailbox,
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            )),
        }
    }
}

type Finalizations<P> = immutable::Archive<
    deterministic::Context,
    Sha256Digest,
    Finalization<SchemeOf<P>, Sha256Digest>,
>;
type FinalizedBlocks<P> = immutable::Archive<deterministic::Context, Sha256Digest, B<P>>;
type MarshalActor<P> = Actor<
    deterministic::Context,
    Standard<B<P>>,
    ConstantProvider<SchemeOf<P>, Epoch>,
    Finalizations<P>,
    FinalizedBlocks<P>,
    FixedEpocher,
    Sequential,
>;
type MarshalResolver<P> = (
    handler::Receiver<Sha256Digest>,
    resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>,
);
type AuditedApplication<D, K> = Application<MockBlock<Sha256Digest, SimplexContext<D, K>>>;

pub(crate) struct Validator<P: Simplex> {
    pub(crate) mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    pub(crate) application: Application<B<P>>,
    actor: Option<MarshalActor<P>>,
    pub(crate) buffer: buffered::Mailbox<PublicKeyOf<P>, B<P>>,
    resolver: Option<MarshalResolver<P>>,
}

impl<P: Simplex> Validator<P> {
    pub(crate) fn start(&mut self, reporter: impl Reporter<Activity = Update<B<P>>>) {
        let actor = self
            .actor
            .take()
            .expect("marshal actor must be started exactly once");
        let resolver = self
            .resolver
            .take()
            .expect("marshal resolver must be installed before actor startup");
        actor.start(reporter, self.buffer.clone(), resolver);
    }

    /// Removes the installed resolver so a caller can wrap it (for example in an
    /// observing adapter) before starting the actor with [`Self::start_with_buffer`].
    pub(crate) fn take_resolver(&mut self) -> MarshalResolver<P> {
        self.resolver
            .take()
            .expect("marshal resolver must be installed before actor startup")
    }

    /// Starts the actor with a caller-supplied resolver (for example one wrapping
    /// the real resolver taken via [`Self::take_resolver`]) and broadcast buffer
    /// (for example a recording wrapper around the real buffer), so a scenario can
    /// observe the fetches and blocks the marshal issues. The `handler::Receiver`
    /// half of the resolver tuple must be the one the real resolver engine feeds.
    pub(crate) fn start_with_buffer<R, Buf>(
        &mut self,
        reporter: impl Reporter<Activity = Update<B<P>>>,
        resolver: (handler::Receiver<Sha256Digest>, R),
        buffer: Buf,
    ) where
        R: TargetedResolver<
                Key = handler::Key<Sha256Digest>,
                Subscriber = handler::Annotation,
                PublicKey = PublicKeyOf<P>,
            >,
        Buf: Buffer<Standard<B<P>>, PublicKey = PublicKeyOf<P>>,
    {
        let actor = self
            .actor
            .take()
            .expect("marshal actor must be started exactly once");
        actor.start(reporter, buffer, resolver);
    }
}

pub(crate) fn genesis_block<P: Simplex>(leader: PublicKeyOf<P>) -> B<P> {
    let parent = Sha256::hash(&[b""]);
    let context = Ctx::<P> {
        round: Round::new(Epoch::zero(), View::zero()),
        leader,
        parent: (View::zero(), parent),
    };
    B::<P>::new::<Sha256>(context, parent, Height::zero(), 0)
}

pub(crate) async fn setup_network<P: Simplex>(
    context: deterministic::Context,
    participants: Vec<PublicKeyOf<P>>,
) -> Oracle<PublicKeyOf<P>, deterministic::Context> {
    let (network, oracle) = SimulatedNetwork::new_with_peers(
        context,
        NetworkConfig {
            max_size: 1024 * 1024,
            // The Twins scenario owns connectivity; protocol-level blocking
            // must not rewrite its topology.
            max_peers_per_set: NZUsize!(participants.len()),
            disconnect_on_block: false,
            tracked_peer_sets: NZUsize!(1),
        },
        participants,
    )
    .await;
    network.start();
    oracle
}

pub(crate) async fn setup_network_links<P: Simplex>(
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
) {
    for sender in participants {
        for receiver in participants {
            if sender == receiver {
                continue;
            }
            let _ = oracle
                .add_link(sender.clone(), receiver.clone(), LINK.clone())
                .await;
        }
    }
}

/// `resolver` overrides the marshal backfill resolver: `None` registers the
/// backfill channel and builds the standard P2P resolver here; `Some` uses a
/// caller-built pair (the caller has already registered the backfill channel,
/// and the wedge does not apply to it).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn setup_validator<P: Simplex>(
    context: deterministic::Context,
    oracle: &mut Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    provider: ConstantProvider<SchemeOf<P>, Epoch>,
    start: Start<SchemeOf<P>, Sha256Digest, B<P>>,
    resolver: Option<MarshalResolver<P>>,
    max_pending_acks: NonZeroUsize,
    wedge: Option<WedgeNode<SchemeOf<P>, Sha256Digest>>,
) -> Validator<P> {
    let application = Application::<B<P>>::manual_ack();
    let acknowledger = application.clone();
    context.child("acknowledger").spawn(move |_| async move {
        loop {
            acknowledger.acknowledged().await;
        }
    });
    let config = Config {
        provider,
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start,
        mailbox_size: NZUsize!(100),
        view_retention: ViewDelta::new(10),
        max_repair: NZUsize!(10),
        max_pending_acks,
        block_codec_config: (),
        partition_prefix: format!("validator-{validator}"),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    };
    let control = oracle.control(validator.clone());
    let resolver = match resolver {
        Some(resolver) => resolver,
        None => {
            let (backfill_sender, backfill_receiver) =
                control.register(1, TEST_QUOTA).await.unwrap();
            let backfill = (
                backfill_sender,
                WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                    backfill_receiver,
                    wedge.clone(),
                    WedgeChannel::MarshalBackfill,
                ),
            );
            resolver::init(
                context.child("resolver"),
                resolver::Config {
                    public_key: validator.clone(),
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(validator.clone()),
                    mailbox_size: config.mailbox_size,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
                backfill,
            )
        }
    };

    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let (broadcast_sender, broadcast_receiver) = control.register(2, TEST_QUOTA).await.unwrap();
    broadcast_engine.start((
        broadcast_sender,
        WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
            broadcast_receiver,
            wedge,
            WedgeChannel::MarshalBroadcast,
        ),
    ));

    let finalizations_by_height = immutable::Archive::init(
        context.child("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!(
                "{}-finalizations-by-height-metadata",
                config.partition_prefix
            ),
            freezer_table_partition: format!(
                "{}-finalizations-by-height-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalizations-by-height-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalizations-by-height-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!(
                "{}-finalizations-by-height-ordinal",
                config.partition_prefix
            ),
            items_per_section: NZU64!(10),
            codec_config: SchemeOf::<P>::certificate_codec_config_unbounded(),
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");
    let finalized_blocks = immutable::Archive::init(
        context.child("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{}-finalized-blocks-metadata", config.partition_prefix),
            freezer_table_partition: format!(
                "{}-finalized-blocks-freezer-table",
                config.partition_prefix
            ),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!(
                "{}-finalized-blocks-freezer-key",
                config.partition_prefix
            ),
            freezer_key_page_cache: config.page_cache.clone(),
            freezer_value_partition: format!(
                "{}-finalized-blocks-freezer-value",
                config.partition_prefix
            ),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{}-finalized-blocks-ordinal", config.partition_prefix),
            items_per_section: NZU64!(10),
            codec_config: config.block_codec_config,
            replay_buffer: config.replay_buffer,
            freezer_key_write_buffer: config.key_write_buffer,
            freezer_value_write_buffer: config.value_write_buffer,
            ordinal_write_buffer: config.key_write_buffer,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    Validator {
        mailbox,
        application,
        actor: Some(actor),
        buffer,
        resolver: Some(resolver),
    }
}

pub(crate) async fn register_engine_networks<P: Simplex>(
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
) -> NetworkChannels<PublicKeyOf<P>> {
    let control = oracle.control(validator);
    let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
    let certificate = control
        .register(ENGINE_CERTIFICATE, TEST_QUOTA)
        .await
        .unwrap();
    let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();
    (vote, certificate, resolver)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_engine<P: Simplex, EC, A, R>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: EC,
    automaton: A,
    relay: R,
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    genesis: Sha256Digest,
    partition: String,
    forwarding: commonware_consensus::simplex::ForwardPolicy,
    vote: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) where
    EC: ElectorConfig<SchemeOf<P>> + Clone + Send + 'static,
    A: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>,
    R: Relay<Digest = Sha256Digest, PublicKey = PublicKeyOf<P>, Plan = Plan<PublicKeyOf<P>>>,
{
    start_engine_with_floor::<P, EC, A, R>(
        context,
        oracle,
        validator,
        scheme,
        elector,
        automaton,
        relay,
        mailbox,
        Floor::Genesis(genesis),
        partition,
        forwarding,
        vote,
        certificate,
        resolver,
    );
}

/// Like [`start_engine`], but starts the Simplex engine from an explicit floor.
///
/// A [`Floor::Finalized`] floor lets a cluster begin consensus above a
/// prefabricated finalization instead of genesis, so a scripted marshal prefix
/// can drive nodes to an interesting state before the engine takes over.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_engine_with_floor<P: Simplex, EC, A, R>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
    scheme: SchemeOf<P>,
    elector: EC,
    automaton: A,
    relay: R,
    mailbox: Mailbox<SchemeOf<P>, Standard<B<P>>>,
    floor: Floor<SchemeOf<P>, Sha256Digest>,
    partition: String,
    forwarding: commonware_consensus::simplex::ForwardPolicy,
    vote: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) where
    EC: ElectorConfig<SchemeOf<P>> + Clone + Send + 'static,
    A: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>,
    R: Relay<Digest = Sha256Digest, PublicKey = PublicKeyOf<P>, Plan = Plan<PublicKeyOf<P>>>,
{
    let engine = Engine::new(
        context.child("engine"),
        config::Config {
            blocker: oracle.control(validator),
            scheme,
            elector,
            automaton,
            relay,
            reporter: mailbox,
            partition,
            mailbox_size: NZUsize!(1024),
            epoch: Epoch::zero(),
            floor,
            leader_timeout: LEADER_TIMEOUT,
            certification_timeout: CERTIFICATION_TIMEOUT,
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            view_retention: Delta::new(10),
            skip: SkipPolicy::Enabled {
                timeout: Duration::from_secs(11),
                budget: SkipBudget::Participants,
            },
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forward: forwarding,
            track_historical_votes: false,
        },
    );
    engine.start(vote, certificate, resolver);
}

fn trailing_blocks<D: Digest, K: PublicKey>(
    application: &AuditedApplication<D, K>,
    prefix_end: View,
) -> usize {
    application
        .blocks()
        .values()
        .filter(|block| block.context.round.view() > prefix_end)
        .count()
}

pub(crate) async fn wait_for_liveness<D: Digest, K: PublicKey>(
    context: &deterministic::Context,
    honest: &[(usize, AuditedApplication<D, K>)],
    prefix_end: View,
    required: usize,
    stack: Arc<str>,
) {
    select! {
        _ = context.sleep(MARSHAL_TWINS_LIVENESS_WINDOW) => {
            let progress = honest
                .iter()
                .map(|(idx, application)| {
                    (*idx, trailing_blocks(application, prefix_end))
                })
                .collect::<Vec<_>>();
            panic!(
                "marshal Twins mutator made no post-prefix progress: \
                 required={required} observed={progress:?} stack={stack}"
            );
        },
        _ = async {
            loop {
                if honest
                    .iter()
                    .all(|(_, application)| {
                        trailing_blocks(application, prefix_end) >= required
                    })
                {
                    return;
                }
                context.sleep(POLL).await;
            }
        } => {},
    }
}
