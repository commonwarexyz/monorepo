//! Construction of one reshare engine: buffered block dissemination, marshal
//! in the Standard `Deferred` configuration, the reshare actor, the reshare
//! application wrapper, the orchestrator with its per-epoch Simplex engines,
//! and the probe.
//!
//! An engine is spawned as one supervised task. Every actor it starts is a
//! descendant of that task, so the engine's handle resolves as soon as any of
//! its actors stops, and aborting it takes the whole node down.
//!
//! The harness supplies what the DKG module asks of its caller and nothing
//! else: the block and the inner application, the secret store, the
//! participants provider, the registrar with the scheme provider it fills,
//! the peer manager, and the blocker. Consensus signs with the schemes the
//! engine's own reshare actor registers; marshal and the probe verify with
//! the certificate verifier of the group public key.
//!
//! What a marshal of the reshare chain is built from is defined once here
//! ([`backfill_config`], [`archives`], [`marshal_config`]), for the engine and
//! for the probe driver, whose marshals have no engine above them.
//!
//! The engine's task assembles the engine, and part of the assembly is the
//! harness's own: the configurations it builds, the height-zero block, and
//! what it requires of the archives it opens. Those steps run as belonging to
//! no engine, so that a panic in one of them is reported as the harness's,
//! whichever engine is being assembled. What the DKG module, marshal, and the
//! storage do while they are constructed stays the engine's.

use super::{
    COMMITTEE, Digest, EPOCH_LENGTH, Info, PublicKey, RESHARE_NAMESPACE,
    app::{BLOCK_CFG, Block, BlockContext, Input},
    context::EngineContext,
    invariants::Records,
    joiner::{Entry, Joiner},
    schedule::Schedule,
    scheme::{Registrar, Scheme, Schemes, certificate_verifier},
    stack::{self, Endpoint, FETCH_RETRY_DELAY, FETCH_TIMEOUT, MAX_SUPPORTED_MODE, SECTION_ITEMS},
    store::Secrets,
};
use crate::stateful::{
    IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE,
    runner::unattributed,
    stack::{TEST_QUOTA, archive_config},
};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Application, Heightable as _, Reporter, Reporters,
    marshal::{
        self, Start, Update,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector,
        types::Finalization,
    },
    types::{Epoch, Epocher as _, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Digested, Digestible as _, Signer as _,
    bls12381::{dkg::feldman_desmedt::Reveal, primitives::sharing::Mode},
    certificate::ConstantProvider,
    ed25519,
};
use commonware_glue::dkg::{
    ReshareBlock as _,
    fence::Fence,
    orchestrator, probe, reshare,
    state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan},
    types::Payload,
};
use commonware_p2p::{
    Receiver as ReceiverTrait, Sender as SenderTrait,
    simulated::{Control, Manager, Oracle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZDuration, NZUsize, NonZeroDuration, sequence::Unit};
use std::{sync::Arc, time::Duration};

/// Channel identifier of the probe, after the six channels of the chain that
/// [`stack::register`] registers.
const CHANNEL_PROBE: u64 = 6;

/// Simplex timing of every epoch's engine.
const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);
const TIMEOUT_RETRY: Duration = Duration::from_millis(500);
const SKIP_TIMEOUT: Duration = Duration::from_secs(5);
const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);

/// How long a discovering probe waits before it asks again.
const PROBE_RETRY: Duration = Duration::from_millis(500);

/// Blocks the buffered broadcast keeps per sender.
const BROADCAST_DEQUE: usize = 10;

/// One identity's unsplit channels: the six of the chain and the probe's.
pub(super) struct Channels {
    pub(super) chain: stack::Channels,
    pub(super) probe: Endpoint,
}

/// Register one identity's seven channels.
pub(super) async fn register(
    oracle: &Oracle<PublicKey, deterministic::Context>,
    identity: &PublicKey,
) -> Channels {
    let chain = stack::register(oracle, identity).await;
    let probe = oracle
        .control(identity.clone())
        .register(CHANNEL_PROBE, TEST_QUOTA)
        .await
        .expect("channel registration failed");
    Channels { chain, probe }
}

/// What one reshare engine runs with.
pub(super) struct Config<A, L> {
    /// The identity's key.
    pub(super) signer: ed25519::PrivateKey,
    /// Storage partition prefix, distinct per engine.
    pub(super) partition: String,
    /// The engine's secret store.
    pub(super) secrets: Secrets,
    /// How the ceremonies assign evaluation points.
    pub(super) sharing_mode: Mode,
    /// The description of epoch zero, which the height-zero block carries.
    pub(super) genesis: Info,
    /// The player set of every epoch's ceremony.
    pub(super) schedule: Schedule,
    /// Where the engine's reports are recorded for the oracle.
    pub(super) records: Records,
    /// The application the reshare wrapper drives.
    pub(super) application: A,
    /// Leader election of every epoch's Simplex engine.
    pub(super) elector: L,
    /// How the engine enters the chain: from the height-zero block, or
    /// through the probe and state sync.
    pub(super) entry: Entry,
}

/// The height-zero block every engine of a run starts from.
pub(super) fn genesis_block(info: &Info) -> Block {
    let leader = info
        .output
        .players()
        .iter()
        .next()
        .expect("the first committee has members")
        .clone();
    Block::genesis(leader, info.clone())
}

/// Records what each finalized block that marshal delivers to an engine
/// carries, and the description of each epoch among them, before forwarding
/// the delivery to the engine's actors.
#[derive(Clone)]
struct Observer<R> {
    records: Records,
    epocher: FixedEpocher,
    inner: R,
}

impl<R> Observer<R> {
    /// Record the kind of payload `block` carries, and the epoch description
    /// it carries if `block` ends an epoch.
    fn observe(&self, block: &Block) {
        let payload = block.payload();
        self.records.placed(block.height(), payload.as_ref());
        self.records.committed(block.height(), block.digest());
        let Some(bounds) = self.epocher.containing(block.height()) else {
            return;
        };
        if bounds.last() != block.height() {
            return;
        }
        if let Some(Payload::EpochInfo(info)) = payload {
            self.records.delivered(bounds.epoch().next(), info);
        }
    }
}

impl<R: Reporter<Activity = Update<Block>>> Reporter for Observer<R> {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // The observer is called inside marshal's task and is the harness's
        // code, not the engine's.
        unattributed(|| match &activity {
            Update::Tip(round, height, digest) => self.records.finalized(*round, *height, *digest),
            Update::Block(block, _) => self.observe(block.inner()),
        });
        self.inner.report(activity)
    }
}

/// The peer manager and the blocker of an engine on the simulated network.
pub(super) type Peers = Manager<PublicKey, deterministic::Context>;
pub(super) type Blocker = Control<PublicKey, deterministic::Context>;

/// The marshal variant of the reshare chain.
pub(super) type Variant = Standard<Block>;

/// The archives a marshal keeps its finalizations and its finalized blocks
/// in.
type Finalizations = prunable::Archive<TwoCap, EngineContext, Digest, Finalization<Scheme, Digest>>;
type Blocks = prunable::Archive<TwoCap, EngineContext, Digest, Arc<Block>>;

/// The configuration of a marshal of the reshare chain.
type MarshalConfig = marshal::Config<
    ConstantProvider<Scheme, Epoch>,
    FixedEpocher,
    Sequential,
    Block,
    Digested<Block>,
>;

/// The configuration of the resolver through which the marshal of
/// `identity` backfills. A fetch waits `fetch_timeout` for a peer.
pub(super) fn backfill_config(
    identity: &PublicKey,
    manager: Peers,
    blocker: Blocker,
    fetch_timeout: NonZeroDuration,
) -> marshal_resolver::Config<PublicKey, Peers, Blocker> {
    marshal_resolver::Config {
        public_key: identity.clone(),
        peer_provider: manager,
        blocker,
        mailbox_size: MAILBOX_SIZE,
        fetch_timeout,
        fetch_retry_delay: FETCH_RETRY_DELAY,
        priority_requests: false,
        priority_responses: false,
    }
}

/// Open the archives of the marshal whose storage is under `partition`: its
/// finalizations by height and its finalized blocks.
///
/// An archive that does not open is the harness's failure: it is reported as
/// belonging to no engine, whatever task opens the archives.
pub(super) async fn archives(
    context: &EngineContext,
    partition: &str,
    page_cache: &CacheRef,
) -> (Finalizations, Blocks) {
    let config =
        unattributed(|| archive_config(partition, "finalizations", page_cache.clone(), ()));
    let finalizations =
        prunable::Archive::init(context.child("finalizations_by_height"), config).await;
    let finalizations =
        unattributed(|| finalizations.expect("failed to initialize finalizations archive"));
    let config =
        unattributed(|| archive_config(partition, "blocks", page_cache.clone(), BLOCK_CFG));
    let blocks = prunable::Archive::init(context.child("finalized_blocks"), config).await;
    let blocks = unattributed(|| blocks.expect("failed to initialize blocks archive"));
    (finalizations, blocks)
}

/// The configuration of a marshal that verifies every epoch's certificates
/// with `verifier`, starts from `start`, and stores under `partition`.
pub(super) fn marshal_config(
    verifier: Scheme,
    epocher: FixedEpocher,
    start: Start<Scheme, Digest, Digested<Block>>,
    partition: String,
    page_cache: CacheRef,
) -> MarshalConfig {
    marshal::Config {
        provider: ConstantProvider::new(verifier),
        epocher,
        start,
        partition_prefix: partition,
        mailbox_size: MAILBOX_SIZE,
        view_retention: VIEW_RETENTION,
        prunable_items_per_section: SECTION_ITEMS,
        page_cache,
        replay_buffer: IO_BUFFER_SIZE,
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        block_codec_config: BLOCK_CFG,
        max_repair: NZUsize!(10),
        max_pending_acks: NZUsize!(1),
        strategy: Sequential,
    }
}

/// The configuration of an engine's probe.
type ProbeConfig = probe::Config<EngineContext, Peers, Scheme, Variant, Sequential, Blocker>;

/// The configuration of an engine's probe.
///
/// An engine that enters through state sync hands its probe the floor an
/// interrupted sync left on its caller's record, if `joiner` holds one, so
/// that discovery cannot return the description of an earlier epoch. An
/// engine that starts at the height-zero block has no joiner and no floor.
fn probe_config(
    context: EngineContext,
    manager: Peers,
    blocker: Blocker,
    verifier: Scheme,
    genesis: &Info,
    joiner: Option<&Joiner<EngineContext>>,
) -> ProbeConfig {
    probe::Config {
        context,
        manager,
        bootstrap: probe::Bootstrap {
            epoch: Epoch::zero(),
            participants: genesis.participants(),
            directory: Unit,
        },
        floor: joiner.and_then(Joiner::floor),
        verifier,
        genesis: genesis.clone(),
        strategy: Sequential,
        blocker,
        blocks_per_epoch: EPOCH_LENGTH,
        retry_timeout: NZDuration!(PROBE_RETRY),
        mailbox_size: MAILBOX_SIZE,
        block_codec_config: BLOCK_CFG,
    }
}

/// Start one real reshare engine over the given channels.
///
/// The three Simplex channels share one sender and one receiver type, because
/// the orchestrator multiplexes them by epoch through one muxer type.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn<A, L, S, R>(
    context: EngineContext,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    config: Config<A, L>,
    votes: (S, R),
    certificates: (S, R),
    resolver: (S, R),
    backfill: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    broadcast: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    dkg: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    probe: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
) -> Handle<()>
where
    A: Application<
            EngineContext,
            SigningScheme = Scheme,
            Context = BlockContext,
            Block = Block,
            Input = Input,
        >,
    L: elector::Config<Scheme>,
    S: SenderTrait<PublicKey = PublicKey>,
    R: ReceiverTrait<PublicKey = PublicKey>,
{
    let oracle = oracle.clone();

    // The engine's storage is paced like its secret store.
    let context = context.paced(config.secrets.pacing());
    context.spawn(move |context| {
        run(
            context,
            oracle,
            config,
            votes,
            certificates,
            resolver,
            backfill,
            broadcast,
            dkg,
            probe,
        )
    })
}

#[allow(clippy::too_many_arguments)]
async fn run<A, L, S, R>(
    context: EngineContext,
    oracle: Oracle<PublicKey, deterministic::Context>,
    config: Config<A, L>,
    votes: (S, R),
    certificates: (S, R),
    resolver: (S, R),
    backfill: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    broadcast: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    dkg: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    probe_channel: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
) where
    A: Application<
            EngineContext,
            SigningScheme = Scheme,
            Context = BlockContext,
            Block = Block,
            Input = Input,
        >,
    L: elector::Config<Scheme>,
    S: SenderTrait<PublicKey = PublicKey>,
    R: ReceiverTrait<PublicKey = PublicKey>,
{
    let Config {
        signer,
        partition,
        secrets,
        sharing_mode,
        genesis,
        schedule,
        records,
        application,
        elector,
        entry,
    } = config;
    let identity = signer.public_key();
    let manager = oracle.manager();
    let blocker = oracle.control(identity.clone());
    let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
    let epocher = FixedEpocher::new(EPOCH_LENGTH);

    // The group public key is the same in every epoch, so one verifier checks
    // every epoch's certificates.
    let verifier = unattributed(|| certificate_verifier(*genesis.output.public().public()));

    // Marshal's backfill resolver.
    let backfill_config = unattributed(|| {
        backfill_config(
            &identity,
            manager.clone(),
            blocker.clone(),
            NZDuration!(FETCH_TIMEOUT),
        )
    });
    let backfill =
        marshal_resolver::init(context.child("marshal_resolver"), backfill_config, backfill);

    // Block dissemination.
    let (buffer, buffer_mailbox) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: identity.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: BROADCAST_DEQUE,
            priority: false,
            codec_config: BLOCK_CFG,
            peer_provider: manager.clone(),
            blocker: blocker.clone(),
            strategy: Sequential,
        },
    );
    let buffer_handle = buffer.start(broadcast);

    // Marshal archives.
    let (finalizations, blocks) = archives(&context, &partition, &page_cache).await;

    // An engine that enters through state sync has a caller that keeps the
    // floor of its sync across restarts.
    let mut joiner = Joiner::open(&context, entry, &partition, &records).await;

    // The probe. An engine that starts at the height-zero block discovers no
    // boundary, so its probe only serves. One that state syncs hands its
    // probe the floor an interrupted sync left.
    let probe_config = unattributed(|| {
        probe_config(
            context.child("probe"),
            manager.clone(),
            blocker.clone(),
            verifier.clone(),
            &genesis,
            joiner.as_ref(),
        )
    });
    let (probe, probe_mailbox) = probe::Actor::new(probe_config);
    let probe_handle = probe.start(probe_channel);

    // A start that state syncs waits for what the probe discovers, and
    // starts marshal and the DKG actors from it. An engine whose probe stops
    // before that stops with it.
    let material = match joiner.as_mut() {
        Some(joiner) => match joiner.discover(&probe_mailbox).await {
            Ok(material) => material,
            Err(_) => {
                let _ = probe_handle.await;
                return;
            }
        },
        None => None,
    };
    let marshal_config = unattributed(|| {
        let start = material.as_ref().map_or_else(
            || Start::Genesis(genesis_block(&genesis).digested()),
            |material| Start::Floor(material.floor.clone()),
        );
        marshal_config(
            verifier,
            epocher.clone(),
            start,
            partition.clone(),
            page_cache.clone(),
        )
    });
    let (marshal_actor, marshal, _) = MarshalActor::init(
        context.child("marshal"),
        finalizations,
        blocks,
        marshal_config,
    )
    .await;

    // The orchestrator enters an epoch only once the reshare actor has
    // registered the epoch's scheme and marked the fence.
    let schemes = Schemes::default();
    let registrar = unattributed(|| Registrar::new(schemes.clone(), records.clone()));
    let (fence, gate) = Fence::new();
    let state_sync = StateSyncPlan::init(
        context.child("state_sync_plan"),
        StateSyncConfig {
            partition_prefix: partition.clone(),
            max_participants: COMMITTEE,
            max_supported_mode: MAX_SUPPORTED_MODE,
        },
        material,
    )
    .await;

    let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
        context.child("reshare"),
        reshare::Config {
            signer,
            manager: manager.clone(),
            blocker: blocker.clone(),
            participants_provider: schedule,
            secret_store: secrets,
            strategy: Sequential,
            registrar,
            marshal: marshal.clone(),
            state_sync: state_sync.clone(),
            fence,
            namespace: RESHARE_NAMESPACE,
            sharing_mode,
            reveal: Reveal::V1,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{partition}-reshare"),
            page_cache: page_cache.clone(),
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            max_participants: COMMITTEE,
            blocks_per_epoch: EPOCH_LENGTH,
        },
    );
    let reshare_handle = reshare_actor.start(dkg);

    // The reshare wrapper selects each block's payload for the application.
    let deferred = Deferred::new(
        context.child("deferred"),
        reshare::Application::new(application, reshare_mailbox.clone(), EPOCH_LENGTH),
        marshal.clone(),
        epocher.clone(),
    );

    let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
        context.child("orchestrator"),
        orchestrator::Config {
            oracle: blocker,
            manager,
            provider: schemes,
            marshal: marshal.clone(),
            application: deferred,
            strategy: Sequential,
            simplex: orchestrator::SimplexConfig {
                elector,
                mailbox_size: MAILBOX_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: LEADER_TIMEOUT,
                certification_timeout: CERTIFICATION_TIMEOUT,
                timeout_retry: TIMEOUT_RETRY,
                fetch_timeout: NZDuration!(FETCH_TIMEOUT),
                fetch_retry_delay: FETCH_TIMEOUT,
                view_retention: VIEW_RETENTION,
                skip: SkipPolicy::Enabled {
                    timeout: SKIP_TIMEOUT,
                    budget: simplex::SkipBudget::Participants,
                },
                track_historical_votes: false,
                forward: ForwardPolicy::Disabled,
            },
            gate,
            state_sync,
            blocks_per_epoch: EPOCH_LENGTH,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{partition}-orchestrator"),
        },
    );
    let orchestrator_handle = orchestrator.start(votes, certificates, resolver);

    let marshal_handle = marshal_actor.start(
        Observer {
            records,
            epocher,
            inner: Reporters::from((orchestrator_mailbox, reshare_mailbox)),
        },
        buffer_mailbox,
        backfill,
    );
    probe_mailbox.attach(marshal);
    if let Some(joiner) = joiner {
        joiner.settle(context.child("joined"));
    }

    // The engine runs until one of its actors stops, which takes the others
    // down with it.
    let _ = Handle::select([
        buffer_handle,
        probe_handle,
        reshare_handle,
        orchestrator_handle,
        marshal_handle,
    ])
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            MockGroup, RESHARE_IDENTITIES,
            app::App,
            fixtures::{identities, raised},
            invariants::{Reshare, Resharer, Step, check_placement},
            joiner::tests::{artifact, finalization},
            reshare_cluster::Elector,
            signers,
        },
        stateful::runner,
    };
    use commonware_consensus::{CertifiableBlock as _, types::Height};
    use commonware_cryptography::bls12381::dkg::feldman_desmedt::deal;
    use commonware_glue::dkg::types::EpochOutcome;
    use commonware_runtime::{Clock as _, Runner as _};
    use commonware_utils::{N3f1, TestRng, ordered::Set};

    /// The description of an epoch among the first committee.
    fn info() -> Info {
        let players = Set::from_iter_dedup(identities().into_iter().take(COMMITTEE.get() as usize));
        let (output, _) =
            deal::<MockGroup, _, N3f1>(TestRng::new(3), Mode::NonZeroCounter, players.clone())
                .expect("a trusted deal must succeed");
        Info {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: players.clone(),
            next_players: players,
            directory: Unit,
        }
    }

    /// The blocks at `heights` above the height-zero block, each carrying
    /// the payload given with its height.
    fn chain(heights: &[(u64, Option<Payload<MockGroup, PublicKey>>)]) -> Vec<Block> {
        let genesis = Block::genesis(identities()[0].clone(), info());
        let mut blocks = vec![genesis.clone()];
        for (height, payload) in heights {
            blocks.push(Block::new(
                genesis.context(),
                genesis.digest(),
                Height::new(*height),
                payload.clone(),
            ));
        }
        blocks
    }

    /// Hand `blocks` to an engine's observer and check what it recorded
    /// under I18. Returns the number of blocks the check examined.
    fn observed(blocks: &[Block]) -> usize {
        let identities = identities();
        let records = Records::default();
        let observer = Observer {
            records: records.clone(),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            inner: (),
        };
        for block in blocks {
            observer.observe(block);
        }
        let reshare = Reshare {
            genesis: info(),
            schedule: Schedule::new(&identities, COMMITTEE.get() as usize, &[]),
            nodes: vec![Resharer::observed(
                0,
                identities[0].clone(),
                &records,
                Vec::new(),
            )],
        };
        check_placement(&FixedEpocher::new(EPOCH_LENGTH), &reshare).blocks
    }

    #[test]
    fn observed_chain_with_payloads_in_place_is_accepted() {
        let last = EPOCH_LENGTH.get() - 1;
        let blocks = chain(&[(1, None), (last, Some(Payload::EpochInfo(info())))]);
        assert_eq!(observed(&blocks), 2);
    }

    #[test]
    #[should_panic(expected = "I18 violated: engine 0")]
    fn observed_epoch_description_before_the_final_block_is_rejected() {
        observed(&chain(&[(5, Some(Payload::EpochInfo(info())))]));
    }

    /// The panics of a run in which the engine `engine` is started on storage
    /// under `partition` and left to run for a moment, each with the engine
    /// it is attributed to and what it said.
    fn assembled(engine: usize, partition: &str) -> Vec<(Option<usize>, String)> {
        let partition = partition.to_string();
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, panics) = runner::tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let identities = identities();
                let oracle = runner::network(&context, &identities).await;
                let channels = register(&oracle, &identities[engine]).await;
                let config = Config {
                    signer: signers(RESHARE_IDENTITIES)[engine].clone(),
                    partition,
                    secrets: Secrets::default(),
                    sharing_mode: Mode::NonZeroCounter,
                    genesis: info(),
                    schedule: Schedule::new(&identities, COMMITTEE.get() as usize, &[]),
                    records: Records::default(),
                    application: App,
                    elector: Elector::default(),
                    entry: Entry::Genesis,
                };
                let handle = spawn(
                    EngineContext::new(context.child("engine"), engine),
                    &oracle,
                    config,
                    channels.chain.votes,
                    channels.chain.certificates,
                    channels.chain.resolver,
                    channels.chain.backfill,
                    channels.chain.broadcast,
                    channels.chain.dkg,
                    channels.probe,
                );
                context.sleep(Duration::from_millis(100)).await;
                handle.abort();
            })
        });
        result.expect("the root task returns");
        raised(panics)
    }

    /// The engine's task assembles the engine, and the harness's own part of
    /// the assembly belongs to no engine. The storage refuses the name of
    /// this engine's partition, so its archives do not open, which the
    /// harness does not accept: the panic is the harness's, not that of the
    /// engine being assembled, and no half would be excused it.
    #[test]
    fn harness_panic_in_assembly_belongs_to_no_engine() {
        let panics = assembled(3, "engine.3");
        let [(engine, said)] = &panics[..] else {
            panic!("one panic was raised: {panics:?}");
        };
        assert_eq!(*engine, None, "{said}");
        assert!(
            said.contains("failed to initialize finalizations archive"),
            "{said}"
        );

        // On storage it can open, the same assembly raises nothing.
        assert_eq!(assembled(3, "engine-3"), Vec::new());
    }

    /// R24: an engine restarted in the middle of its state sync hands the
    /// floor its caller kept to its probe, and no other start hands its
    /// probe a floor. This is the harness's own caller that is checked, on
    /// the configuration it builds, and not the probe.
    #[test]
    fn probe_is_handed_the_floor_an_interrupted_sync_left() {
        deterministic::Runner::default().start(|context| async move {
            let identities = identities();
            let oracle = runner::network(&context, &identities).await;
            let genesis = info();
            let verifier = certificate_verifier(*genesis.output.public().public());
            let records = Records::default();
            let engine = |label| EngineContext::new(context.child(label), 0);
            let floor_of = |label, joiner: Option<&Joiner<EngineContext>>| {
                probe_config(
                    engine(label),
                    oracle.manager(),
                    oracle.control(identities[0].clone()),
                    verifier.clone(),
                    &genesis,
                    joiner,
                )
                .floor
            };
            let opened = |label, entry| {
                let (context, records) = (engine(label), records.clone());
                async move { Joiner::open(&context, entry, "engine-0", &records).await }
            };

            // An engine that starts at the height-zero block has no joiner,
            // and the first start of one that state syncs has no floor.
            assert!(opened("genesis", Entry::Genesis).await.is_none());
            assert_eq!(floor_of("genesis_probe", None), None);
            let mut joiner = opened("first", Entry::StateSync)
                .await
                .expect("an engine that state syncs has a joiner");
            assert_eq!(floor_of("first_probe", Some(&joiner)), None);

            // The start enters from a floor and is crashed before its sync
            // completes. The engine that comes back hands its probe that
            // floor.
            let floor = finalization(1, 4, b"floor");
            joiner.enter(artifact(&floor)).await;
            drop(joiner);
            let mut joiner = opened("second", Entry::StateSync)
                .await
                .expect("an engine that state syncs has a joiner");
            assert_eq!(floor_of("second_probe", Some(&joiner)), Some(floor.clone()));

            // Once the sync has completed, a start has no floor for its
            // probe.
            joiner.enter(artifact(&floor)).await;
            let settling = engine("settling").spawn(|context| async move {
                joiner.settle(context.child("joined"));
                std::future::pending::<()>().await
            });
            records.committed(Height::new(36), floor.proposal.payload);
            context.sleep(Duration::from_millis(10)).await;
            assert!(matches!(records.steps().last(), Some(Step::Synced(_))));
            settling.abort();
            let _ = settling.await;
            context.sleep(Duration::from_millis(10)).await;
            let joiner = opened("third", Entry::StateSync)
                .await
                .expect("an engine that state syncs has a joiner");
            assert_eq!(floor_of("third_probe", Some(&joiner)), None);
        });
    }
}
