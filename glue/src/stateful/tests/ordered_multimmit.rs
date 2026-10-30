//! The ordered mode on a Multimmit committee.
//!
//! Every validator runs the engine with an [`Inline`] producer, the marshal, an executor whose
//! application is stateful's ordered mode, aggregation over the executed chain's checkpoints, and
//! a checkpoint probe. A validator that joins late state-syncs to a checkpoint its peers certified,
//! and resumes its marshal from a floor they serve, instead of executing the chain from genesis.
//!
//! [`a_late_validator_state_syncs_to_a_certified_checkpoint`] is the end-to-end state sync example.
//! Its documentation lists each step it shows.

use super::{
    checkpoint_recovery::{Archive, archive as checkpoint_archive},
    common::{PAGE_CACHE_SIZE, PAGE_SIZE},
    mocks::digested,
    ordered::{Stage, State, Tally, Worth, read_counter, until_applied},
    single_db_app::{Qmdb, qmdb_config},
};
use crate::{
    executor::{
        self, Checkpoints, Executor, Halt, StoreConfig,
        probe::{self, Local, Probe},
    },
    stateful::{
        PruneConfig,
        db::{AttachableResolver, Shared, SyncEngineConfig, p2p as qmdb_resolver},
        ordered,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::Decode as _;
use commonware_consensus::{
    Application, Epochable as _, Heightable as _,
    aggregation::{
        self,
        types::{Certificate, RecoveryKey},
    },
    ancestry::Ancestry,
    multimmit::{
        self, Planes, Running,
        checkpoint::Scheme as CheckpointScheme,
        config::Tuning,
        marshal::{
            self as marshal, ArchiveConfig, ArchiveMode, Inline, Retention, SchemeVerifier,
            ServiceHandle, Start,
        },
        mocks::{Committee, MockBody},
        types::{Context as Producing, TransactionBlock},
    },
    types::{Epoch, Height, Participant, ViewDelta},
};
use commonware_cryptography::{
    Digested, Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    certificate::Verifier as _, ed25519, sha256::Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::p2p as resolver;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Quota, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
    telemetry::metrics::metric_sum,
};
use commonware_storage::{
    mmr,
    qmdb::{
        any::operation::Operation as QmdbOperation,
        sync::{Feedback, Request, Response, Source, source},
    },
    translator::TwoCap,
};
use commonware_utils::{
    NZDuration, NZU64, NZUsize,
    acknowledgement::Exact,
    channel::{mpsc, oneshot},
    probability,
    sync::Mutex,
};
use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_MULTIMMIT_TEST";
const CHECKPOINT_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_MULTIMMIT_TEST_CHECKPOINTS";
const VALIDATORS: u32 = 6;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Blocks per checkpoint.
const INTERVAL: NonZeroU64 = NZU64!(8);

/// Inputs marshal delivers before one is acknowledged.
const ACK_WINDOW: NonZeroUsize = NZUsize!(16);

const DATA: u64 = 0;
const CONSENSUS: u64 = 1;
const CERTIFICATES: u64 = 2;
const ENGINE_RESOLVER: u64 = 3;
const MARSHAL_RESOLVER: u64 = 4;
const MARSHAL_BROADCAST: u64 = 5;
const AGGREGATION: u64 = 6;
const PROBE: u64 = 7;
const CHECKPOINT_RESOLVER: u64 = 9;
const QMDB: u64 = 8;

type Input = TransactionBlock<Sha256, MockBody>;
type Marshal = marshal::Mailbox<Sha256, MinPk, MockBody>;
type Scheme = CheckpointScheme<ed25519::PublicKey, MinPk>;
type Chain = executor::Mailbox<State>;
type Resolver = qmdb_resolver::Mailbox<Qmdb<deterministic::Context>, mmr::Family, Op, Digest>;
type Op = <Qmdb<deterministic::Context> as Source>::Op;
type SyncResponse = Response<mmr::Family, Op, Digest>;

/// Returns the epoch and the inclusive position range of the executed chain's checkpoints.
fn checkpoint_scope(committee: &Committee<MinPk>) -> (Epoch, Height, Height) {
    (
        committee.config.epoch(),
        Height::zero(),
        Height::new(u64::MAX / INTERVAL.get() - 1),
    )
}

/// One injected corruption of a state sync response, and the sync engine's verdict on it.
#[derive(Clone)]
struct Corruption {
    /// Set until a response is corrupted.
    armed: Arc<AtomicBool>,
    /// The sync engine's verdict on each corrupted response.
    verdicts: Arc<Mutex<Vec<bool>>>,
}

impl Corruption {
    fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(true)),
            verdicts: Arc::default(),
        }
    }

    /// Records the sync engine's verdict on a corrupted response, then passes it, and the
    /// verdicts on every later candidate for the same request, to the resolver's `feedback`.
    fn judge(
        &self,
        context: deterministic::Context,
        feedback: Feedback<SyncResponse>,
    ) -> Feedback<SyncResponse> {
        let (verdict, mut judged) = oneshot::channel();
        let (candidates, next) = mpsc::channel(1);
        let corruption = self.clone();
        context.spawn(move |_| async move {
            let mut feedback = feedback;
            let mut corrupted = true;
            loop {
                let Ok(valid) = judged.await else {
                    // The engine dropped the corrupted response unjudged, so corrupt another.
                    if corrupted {
                        corruption.armed.store(true, Ordering::SeqCst);
                    }
                    return;
                };
                if corrupted {
                    corruption.verdicts.lock().push(valid);
                    corrupted = false;
                }
                if valid {
                    feedback.accept();
                    return;
                }
                let Some((response, next_feedback)) = feedback.reject().await else {
                    return;
                };
                let (verdict, next_judged) = oneshot::channel();
                if candidates.send((response, verdict)).await.is_err() {
                    return;
                }
                feedback = next_feedback;
                judged = next_judged;
            }
        });
        Feedback::new(verdict, next)
    }
}

/// The QMDB resolver of a validator, which may corrupt one response it fetched from a peer.
///
/// A corrupted response sets a different value for a key it updates. It is still well formed and
/// matches its request, so only its proof against the state root of the certified block can
/// show that it is wrong. Once the sync engine rejects it, the resolver blocks the peer that
/// served it, as it would block a peer that corrupted it, and fetches it from another peer.
#[derive(Clone)]
struct Snapshots {
    context: Arc<deterministic::Context>,
    resolver: Resolver,
    corruption: Option<Corruption>,
}

impl Source for Snapshots {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Op;
    type Error = <Resolver as Source>::Error;

    async fn serve(&self, request: Request<mmr::Family>) -> source::Result<Self> {
        let (mut response, feedback) = self.resolver.serve(request).await?;
        let Some(corruption) = &self.corruption else {
            return Ok((response, feedback));
        };
        let Some(feedback) = feedback else {
            return Ok((response, None));
        };
        if !corruption.armed.load(Ordering::SeqCst) || !corrupt(&mut response) {
            return Ok((response, Some(feedback)));
        }
        corruption.armed.store(false, Ordering::SeqCst);
        let feedback = corruption.judge(self.context.child("verdict"), feedback);
        Ok((response, Some(feedback)))
    }
}

/// Changes the value of the first update in `response`, and returns whether there was one.
fn corrupt(response: &mut SyncResponse) -> bool {
    let mut ops: Vec<&mut Op> = match response {
        Response::Operations { operations, .. } => operations.iter_mut().collect(),
        Response::Boundary { op, .. } => vec![op],
    };
    let Some(update) = ops.iter_mut().find_map(|op| match op {
        QmdbOperation::Update(update) => Some(update),
        _ => None,
    }) else {
        return false;
    };
    update.1 = Sha256::hash(&[b"corrupted", update.1.as_ref()]);
    true
}

impl AttachableResolver<Qmdb<deterministic::Context>> for Snapshots {
    async fn attach_database(&self, db: Shared<Qmdb<deterministic::Context>>) {
        self.resolver.attach_database(db);
    }
}

/// Builds each producer block with a body worth its chain and height.
#[derive(Clone)]
struct Producer;

impl Application<deterministic::Context> for Producer {
    type Context = Producing<Digest>;
    type Block = Input;
    type Input = ();

    async fn propose(
        &mut self,
        (_, context): (deterministic::Context, Self::Context),
        _: impl Ancestry<Input>,
        _: (),
    ) -> Option<Digested<Input>> {
        let value = u64::from(context.chain().get()) * 1_000 + context.height().get();
        Some(digested(TransactionBlock::from_context(
            context,
            MockBody(value),
        )))
    }

    async fn verify(
        &mut self,
        _: (deterministic::Context, Self::Context),
        _: impl Ancestry<Input>,
    ) -> bool {
        true
    }
}

impl Worth for Input {
    fn worth(&self) -> u64 {
        self.body().0
    }
}

/// Asserts that every prepared input `tally` executed was prepared before it executed, and that
/// nearly every executed input was prepared.
///
/// Marshal reports inputs final before it orders them, so the executor prepares them well ahead.
/// Preparing only the inputs delivered behind others that have not executed leaves many more
/// unprepared.
fn assert_prepared_ahead(tally: &Tally<Input>) {
    let mut first: HashMap<(Stage, Digest), usize> = HashMap::new();
    for (position, entry) in tally.stages.lock().iter().enumerate() {
        first.entry(*entry).or_insert(position);
    }
    let (mut executed, mut ahead) = (0, 0);
    for (&(stage, digest), &position) in &first {
        if stage != Stage::Executed {
            continue;
        }
        executed += 1;
        if let Some(&prepared) = first.get(&(Stage::Prepared, digest)) {
            assert!(
                prepared < position,
                "an input executed before it was prepared"
            );
            ahead += 1;
        }
    }
    assert!(
        ahead * 10 >= executed * 9,
        "only {ahead} of {executed} executed inputs were prepared"
    );
}

/// A running validator.
struct Validator {
    chain: Chain,
    marshal: Marshal,
    stateful: ordered::Mailbox<deterministic::Context, Tally<Input>, Sequential>,
    checkpoints: Checkpoints<Scheme, State>,
    archive: Archive,
    tally: Tally<Input>,
    _engine: Running<Digest>,
    _marshal: ServiceHandle,
    _handles: Vec<Handle<()>>,
    _recovery: aggregation::Recovery,
    _executor: Handle<Result<(), Halt>>,
}

impl Validator {
    /// Returns the applied counter.
    async fn counter(&self) -> u64 {
        let databases = self
            .stateful
            .subscribe_databases()
            .await
            .expect("stateful is running");
        read_counter(&databases).await
    }
}

/// A Multimmit committee on a simulated network.
struct Cluster {
    context: deterministic::Context,
    committee: Committee<MinPk>,
    oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
}

impl Cluster {
    async fn new(context: deterministic::Context) -> Self {
        let committee = Committee::<MinPk>::builder(7, VALIDATORS)
            .namespace(NAMESPACE)
            .build();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 8 * 1024 * 1024,
                max_peers_per_set: NZUsize!(committee.identities.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            committee.identities.clone(),
        )
        .await;
        network.start();
        for a in &committee.identities {
            for b in &committee.identities {
                if a != b {
                    oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
                }
            }
        }
        Self {
            context,
            committee,
            oracle,
        }
    }

    /// Starts validator `index`. A joining validator starts its executor from the newest
    /// checkpoint its peers certified, and its marshal from a floor they serve. With a
    /// `corruption`, the validator corrupts one state sync response it fetches.
    async fn start(
        &self,
        index: usize,
        joining: bool,
        corruption: Option<Corruption>,
    ) -> Validator {
        let context = self
            .context
            .child("validator")
            .with_attribute("index", index);
        let identity = self.committee.identities[index].clone();
        let control = self.oracle.control(identity.clone());
        let mut channels = Vec::new();
        for channel in [
            DATA,
            CONSENSUS,
            CERTIFICATES,
            ENGINE_RESOLVER,
            MARSHAL_RESOLVER,
            MARSHAL_BROADCAST,
            AGGREGATION,
            PROBE,
            QMDB,
            CHECKPOINT_RESOLVER,
        ] {
            channels.push(Some(control.register(channel, QUOTA).await.unwrap()));
        }
        let mut channel = |id: u64| channels[id as usize].take().unwrap();
        let prefix = format!("validator_{index}");
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut handles = Vec::new();

        // Marshal disseminates, stores, and orders producer blocks.
        let (broadcast, buffer) = buffered::Engine::new(
            context.child("body_broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(256),
                ingress_size: NZUsize!(256),
                deque_size: 256,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        handles.push(broadcast.start(channel(MARSHAL_BROADCAST)));
        let mut archive =
            ArchiveConfig::new(TwoCap, CacheRef::new(paged::page_size(4_096), NZUsize!(16)));
        archive.items_per_section = NZU64!(16);
        let config = marshal::Config::new(
            Start::Genesis(self.committee.config.genesis().clone()),
            prefix.clone(),
            self.committee.codec(),
            (),
            archive,
        )
        .with_max_pending_acks(ACK_WINDOW)
        .with_retention(Retention::uniform(ArchiveMode::Prunable));
        let (mut service, bridge) = marshal::open(context.child("marshal"), config, buffer)
            .await
            .expect("marshal opens");
        let (resolver_engine, resolver) = resolver::Engine::new(
            context.child("marshal_resolver"),
            resolver::Config {
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                consumer: bridge.clone(),
                producer: bridge,
                mailbox_size: NZUsize!(256),
                me: Some(identity.clone()),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        handles.push(resolver_engine.start(channel(MARSHAL_RESOLVER)));
        let relay = service.relay(
            self.committee
                .config
                .producer_chain(Participant::from_usize(index)),
        );

        // The ordered mode is both the executor's application and its consumer.
        let (qmdb_resolver, resolvers): (_, Resolver) =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, mmr::Family, Qmdb<_>>::new(
                context.child("qmdb_resolver"),
                qmdb_resolver::Config {
                    peer_provider: self.oracle.manager(),
                    blocker: control.clone(),
                    database: None,
                    mailbox_size: NZUsize!(256),
                    me: Some(identity.clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: NZU64!(64),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        handles.push(qmdb_resolver.start(channel(QMDB)));
        let resolvers = Snapshots {
            context: Arc::new(context.child("snapshots")),
            resolver: resolvers,
            corruption,
        };
        let tally = Tally::default();
        let (stateful, stateful_mailbox) = ordered::Stateful::init(
            context.child("stateful"),
            ordered::Config {
                application: tally.clone(),
                db_config: qmdb_config(&prefix, page_cache.clone()),
                resolvers,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: NZUsize!(4),
                },
                mailbox_size: NZUsize!(256),
                // Multimmit finalizes several blocks a view, so peers must retain a checkpoint's
                // state for longer than a joining validator waits between sampled targets.
                prune_config: Some(PruneConfig {
                    maintenance_interval: NZUsize!(4),
                    retained_marshal_blocks: 64,
                    retained_qmdb_blocks: 64,
                }),
                strategy: Sequential,
            },
        );
        let (executor, inbox, chain) =
            Executor::<_, _, Marshal, _, TwoCap, Exact, Sequential>::init(
                context.child("executor"),
                executor::Config {
                    execute: stateful_mailbox.clone(),
                    consumer: stateful_mailbox.clone(),
                    ack_window: ACK_WINDOW,
                    start: if joining {
                        executor::Start::Checkpoint
                    } else {
                        executor::Start::Genesis
                    },
                    store: StoreConfig {
                        partition_prefix: prefix.clone(),
                        translator: TwoCap,
                        page_cache: page_cache.clone(),
                        items_per_section: NZU64!(16),
                        write_buffer: NZUsize!(4_096),
                        replay_buffer: NZUsize!(4_096),
                        codec_config: (),
                    },
                    mailbox_size: NZUsize!(256),
                    strategy: Sequential,
                },
            )
            .await;
        let verifier = SchemeVerifier::new(
            context.child("marshal_verifier"),
            self.committee.verifier.clone(),
            Sequential,
        );
        let (marshal, marshal_handle) = service.start(resolver, verifier, inbox);

        // Aggregation certifies the executed chain's checkpoints with the committee's
        // nullification key.
        let scheme = self.committee.signers[index].checkpoint(CHECKPOINT_NAMESPACE);
        let checkpoint_scope = checkpoint_scope(&self.committee);
        let checkpoints = Checkpoints::<Scheme, State>::new(chain.clone(), INTERVAL);
        let (reporter, archive, writer) = checkpoint_archive(
            context.child("checkpoint_archive"),
            format!("{prefix}_checkpoint_archive"),
            page_cache.clone(),
            &scheme,
            checkpoint_scope,
            checkpoints.clone(),
        )
        .await;
        handles.push(writer);
        let (coordinator, recovery, consumer) = aggregation::RecoveryCoordinator::new(
            context.child("checkpoint_recovery"),
            NZUsize!(8),
            NZUsize!(16),
        );
        let (recovery_resolver, resolver_mailbox) = resolver::Engine::new(
            context.child("checkpoint_resolver"),
            resolver::Config {
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                consumer,
                producer: archive.clone(),
                mailbox_size: NZUsize!(256),
                me: Some(identity.clone()),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        handles.push(coordinator.start(resolver_mailbox));
        let aggregation = aggregation::Engine::new(
            context.child("aggregation"),
            aggregation::Config {
                epoch: checkpoint_scope.0,
                first: checkpoint_scope.1,
                last: checkpoint_scope.2,
                scheme: scheme.clone(),
                automaton: checkpoints.clone(),
                reporter,
                blocker: control.clone(),
                priority_acks: false,
                rebroadcast_timeout: NZDuration!(Duration::from_millis(500)),
                recovery_after_rebroadcasts: NZU64!(2),
                recoverer: recovery.clone(),
                window: NZU64!(8),
                journal_partition: format!("{prefix}_aggregation"),
                journal_write_buffer: NZUsize!(4_096),
                journal_replay_buffer: NZUsize!(4_096),
                journal_heights_per_section: NZU64!(8),
                journal_compression: None,
                journal_page_cache: page_cache.clone(),
                strategy: Sequential,
            },
        )
        .expect("checkpoint scope is not registered");
        handles.push(recovery_resolver.start(channel(CHECKPOINT_RESOLVER)));
        let aggregation = aggregation.start(channel(AGGREGATION));
        handles.push(
            context
                .child("aggregation_result")
                .spawn(move |_| async move {
                    aggregation.await.expect("aggregation runs");
                }),
        );

        // Every validator serves its newest checkpoint; a joining one also samples its peers'.
        let (probe, sampler) = Probe::new(probe::Config {
            context: context.child("probe"),
            epoch: checkpoint_scope.0,
            first: checkpoint_scope.1,
            last: checkpoint_scope.2,
            scheme,
            strategy: Sequential,
            blocker: control.clone(),
            block_codec: (),
            floor_codec: self.committee.codec(),
            retry_timeout: NZDuration!(Duration::from_millis(500)),
            max_response_size: NZUsize!(1024 * 1024),
            mailbox_size: NZUsize!(16),
        });
        handles.push(probe.start(
            channel(PROBE),
            Local {
                checkpoints: checkpoints.clone(),
                marshal: marshal.clone(),
            },
        ));

        // The engine orders the blocks the inline producer builds.
        let engine = multimmit::Engine::open(
            context.child("engine"),
            multimmit::Config::<Sha256, _, _, _, _, _, _, _, _> {
                scheme: self.committee.signers[index].clone(),
                genesis: self.committee.config.genesis().clone(),
                tuning: Tuning {
                    production_interval: Duration::from_millis(100),
                    view_retention: ViewDelta::new(16),
                    ..Tuning::new(Duration::from_millis(500))
                },
                automaton: Inline::new(context.child("producer"), Producer, marshal.clone()),
                relay,
                reporter: marshal.clone(),
                strategy: Sequential,
                critical_strategy: Sequential,
                blocker: control,
                partition_prefix: prefix,
                page_cache: CacheRef::new(paged::page_size(4_096), NZUsize!(8)),
                mailbox_size: NZUsize!(256),
            },
        )
        .await
        .expect("engine opens");
        let mut engine = engine.start(Planes {
            data: channel(DATA),
            consensus: channel(CONSENSUS),
            certificates: channel(CERTIFICATES),
            resolver: channel(ENGINE_RESOLVER),
        });

        let executor = executor.start(marshal.clone());
        handles.push(stateful.start(chain.clone()));
        if joining {
            handles.push(context.child("join").spawn({
                let (marshal, chain) = (marshal.clone(), chain.clone());
                move |context| {
                    probe::join(
                        context,
                        sampler,
                        marshal,
                        chain,
                        NZDuration!(Duration::from_millis(500)),
                    )
                }
            }));
        }
        engine.ready().await.expect("engine becomes ready");
        Validator {
            chain,
            marshal,
            stateful: stateful_mailbox,
            checkpoints,
            archive,
            tally,
            _engine: engine,
            _marshal: marshal_handle,
            _handles: handles,
            _recovery: recovery,
            _executor: executor,
        }
    }
}

#[test]
fn validators_execute_certify_and_prune_one_chain() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..VALIDATORS as usize {
            validators.push(committee.start(index, false, None).await);
        }
        // The run is long enough for pruning to reach blocks the engine still verifies: pruning
        // those would stall the chain.
        until_applied(&context, validators.iter().map(|v| &v.tally), 300).await;

        // Every validator executed the same chain, and certified checkpoints of it.
        let reference = validators[0]
            .chain
            .block_at(Height::new(300))
            .await
            .unwrap();
        for validator in &validators {
            let block = validator.chain.block_at(Height::new(300)).await.unwrap();
            assert_eq!(block, reference);
            let latest = validator
                .checkpoints
                .latest()
                .expect("a checkpoint is certified");
            let height = validator.checkpoints.height(latest.item.position).unwrap();
            if let Some(block) = validator.chain.block_at(height).await {
                assert_eq!(block.digest(), latest.item.digest);
            }
        }
        assert!(validators[0].counter().await > 0);

        // Each validator prepared inputs ahead of executing them.
        for validator in &validators {
            assert_prepared_ahead(&validator.tally);
        }

        // Pruning reclaimed the first executed block and, once the engine released it, the first
        // input's body, so retention stays bounded.
        for validator in &validators {
            assert!(validator.chain.block_at(Height::new(1)).await.is_none());
            let first = validator
                .tally
                .first
                .lock()
                .clone()
                .expect("an input is executed");
            let block = validator
                .marshal
                .get_block(first.reference())
                .await
                .unwrap();
            assert!(block.is_none(), "marshal retains the first input");
        }
    });
}

/// A late validator state-syncs to a recent certified checkpoint and resumes executing the chain.
///
/// This is the end-to-end state sync example of the executor stack. Run it with:
///
/// ```text
/// just test -p commonware-glue ordered_multimmit::a_late_validator_state_syncs_to_a_certified_checkpoint
/// ```
///
/// 1. Five of six validators order inputs with Multimmit and execute them into a chain of
///    blocks. Each block commits to its height, its parent, its input, and the state root after
///    the input. Aggregation certifies the digest of every [`INTERVAL`]-th block with the
///    committee's nullification key, so a certificate binds a position in the chain to a state.
/// 2. The sixth validator starts late, after its peers pruned the first input. Its probe samples
///    the peers and accepts a checkpoint only if the certificate verifies under the committee's
///    checkpoint key and scope, and the block it names is the one the certificate certifies.
/// 3. The executor offers that block to the application, which fetches the state the block
///    commits to from the peers. One fetched response is corrupted. The sync engine checks it
///    against the certified state root, rejects it, and fetches the range again.
/// 4. The late validator holds the chain only from the checkpoint it synced to, which is not the
///    first checkpoint. It applies no block at or below it, so it executes no earlier input.
/// 5. It then executes the inputs after the checkpoint and produces the same blocks, and so the
///    same state roots, as the validators that executed the chain from genesis.
/// 6. Its aggregation engine recovers every checkpoint certificate through the sync base from its
///    peers, then signs new checkpoints.
#[test]
fn a_late_validator_state_syncs_to_a_certified_checkpoint() {
    deterministic::Runner::timed(Duration::from_secs(180)).start(|mut context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..VALIDATORS as usize - 1 {
            validators.push(committee.start(index, false, None).await);
        }
        until_applied(&context, validators.iter().map(|v| &v.tally), 48).await;

        // Peers pruned the first input, so the late validator must resume marshal from a floor.
        for validator in &validators {
            let first = validator
                .tally
                .first
                .lock()
                .clone()
                .expect("an input is executed");
            while validator
                .marshal
                .get_block(first.reference())
                .await
                .unwrap()
                .is_some()
            {
                context.sleep(Duration::from_millis(50)).await;
            }
        }

        // The late validator holds the chain only from the checkpoint it synced to. Blocks after
        // it that change no state skip the application's hook, so the first applied block may be
        // later.
        let corruption = Corruption::new();
        let late = committee
            .start(VALIDATORS as usize - 1, true, Some(corruption.clone()))
            .await;
        until_applied(&context, [&late.tally], 1).await;
        let first = late.tally.applied.lock()[0];
        let base = first / INTERVAL.get() * INTERVAL.get() - 1;
        assert!(
            base > INTERVAL.get()
                && late.chain.block_at(Height::new(base)).await.is_some()
                && late.chain.block_at(Height::new(base - 1)).await.is_none(),
            "the late validator applied height {first}, not after a checkpoint"
        );

        // It executed nothing at or below the checkpoint.
        assert!(
            late.tally
                .applied
                .lock()
                .iter()
                .all(|&height| height > base)
        );

        // The sync engine rejected the corrupted response and fetched the range again.
        assert!(
            !corruption.armed.load(Ordering::SeqCst),
            "no state sync response was corrupted"
        );
        assert_eq!(corruption.verdicts.lock().as_slice(), &[false]);

        // It then follows the chain the validators execute. Equal blocks commit to equal state
        // roots, so the state it synced and the state it then executed match its peers'.
        let target = validators[0].tally.applied() + 16;
        until_applied(&context, [&late.tally, &validators[0].tally], target).await;
        let reference = validators[0]
            .chain
            .block_at(Height::new(target))
            .await
            .unwrap();
        assert_eq!(
            late.chain.block_at(Height::new(target)).await.unwrap(),
            reference
        );
        let sync_base = base;
        loop {
            if let Some(certificate) = late.checkpoints.latest() {
                let height = late.checkpoints.height(certificate.item.position).unwrap();
                if height.get() >= sync_base {
                    break;
                }
            }
            context.sleep(Duration::from_millis(50)).await;
        }
        assert!(
            late.checkpoints
                .height(late.checkpoints.latest().unwrap().item.position)
                .unwrap()
                .get()
                >= sync_base
        );
        let recovered = late.checkpoints.latest().unwrap().item.position;
        while late.checkpoints.latest().unwrap().item.position.get() < recovered.get() + 2 {
            context.sleep(Duration::from_millis(50)).await;
        }
        // Every mandatory checkpoint through the sync base was recovered. Progress in `latest`
        // alone could hide holes below the active window's end.
        let index = (VALIDATORS - 1).to_string();
        let base_position = (sync_base + 1) / INTERVAL.get() - 1;
        while metric_sum(
            &context.encode(),
            "aggregation_frontier",
            &[("index", &index)],
        ) <= base_position as f64
        {
            context.sleep(Duration::from_millis(50)).await;
        }

        // The certificate for the sync base verifies under the committee's checkpoint key and
        // scope, and names the block the late validator synced to at that position. It does not
        // verify under another committee's key, or under a scope that excludes its position.
        let trusted = committee
            .committee
            .verifier
            .checkpoint(CHECKPOINT_NAMESPACE);
        let (epoch, lowest, highest) = checkpoint_scope(&committee.committee);
        let key = RecoveryKey {
            namespace: aggregation::scheme::Scheme::<Digest>::recovery_namespace(&trusted),
            epoch,
            position: Height::new(base_position),
        };
        let encoded = loop {
            if let Some(encoded) = late.archive.get(&key) {
                break encoded;
            }
            context.sleep(Duration::from_millis(50)).await;
        };
        let certificate =
            Certificate::<Scheme, Digest>::decode_cfg(encoded, &trusted.certificate_codec_config())
                .expect("archived certificate decodes");
        assert!(certificate.verify_for(
            &mut context,
            &trusted,
            epoch,
            lowest,
            highest,
            &Sequential
        ));
        let base_block = late.chain.block_at(Height::new(base)).await.unwrap();
        assert_eq!(
            late.checkpoints.height(certificate.item.position),
            Some(Height::new(base))
        );
        assert_eq!(certificate.item.digest, base_block.digest());
        let other = Committee::<MinPk>::builder(8, VALIDATORS)
            .namespace(NAMESPACE)
            .build()
            .verifier
            .checkpoint(CHECKPOINT_NAMESPACE);
        assert!(!certificate.verify_for(&mut context, &other, epoch, lowest, highest, &Sequential));
        let above = Height::new(base_position + 1);
        assert!(!certificate.verify_for(
            &mut context,
            &trusted,
            epoch,
            above,
            highest,
            &Sequential
        ));

        // Only locally signed acknowledgements use the aggregation channel. The late validator
        // participates in new checkpoints after recovering its skipped history.
        let origin = committee.committee.identities[VALIDATORS as usize - 1].to_string();
        let channel = AGGREGATION.to_string();
        assert!(
            metric_sum(
                &context.encode(),
                "messages_sent_total",
                &[("origin", &origin), ("channel", &channel)],
            ) > 0.0
        );
    });
}
