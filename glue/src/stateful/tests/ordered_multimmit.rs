//! The ordered mode on a Multimmit committee.
//!
//! Every validator runs the engine with an [`Inline`] producer, the marshal, an executor whose
//! application is stateful's ordered mode, aggregation over the executed chain's checkpoints, and
//! a checkpoint probe. A validator that joins late state-syncs to a checkpoint its peers certified,
//! and resumes its marshal from a floor they serve, instead of executing the chain from genesis.

use super::{
    common::{PAGE_CACHE_SIZE, PAGE_SIZE},
    ordered::{State, Tally, Worth, read_counter, until_applied},
    single_db_app::{Qmdb, qmdb_config},
};
use crate::{
    executor::{
        self, Checkpoints, Executor, Halt, StoreConfig,
        probe::{self, Local, Probe},
    },
    stateful::{
        PruneConfig,
        db::{SyncEngineConfig, p2p as qmdb_resolver},
        ordered,
    },
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Application, Epochable as _, Heightable as _, aggregation,
    ancestry::Ancestry,
    multimmit::{
        self, Planes, Running,
        checkpoint::Scheme as CheckpointScheme,
        config::Tuning,
        marshal::{
            self as marshal, ArchiveConfig, ArchiveMode, Floor, Inline, Retention, SchemeVerifier,
            ServiceHandle, Start,
        },
        mocks::{Committee, MockBody},
        types::{Context as Producing, TransactionBlock},
    },
    types::{EpochDelta, Height, HeightDelta, Participant, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _, Sha256, bls12381::primitives::variant::MinPk, certificate::ConstantProvider,
    ed25519, sha256::Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::p2p as resolver;
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
};
use commonware_storage::{mmr, translator::TwoCap};
use commonware_utils::{NZDuration, NZU64, NZUsize, acknowledgement::Exact, probability};
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
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
const QMDB: u64 = 8;

type Input = TransactionBlock<Sha256, MockBody>;
type Marshal = marshal::Mailbox<Sha256, MinPk, MockBody>;
type Scheme = CheckpointScheme<ed25519::PublicKey, MinPk>;
type Chain = executor::Mailbox<State>;
type Resolver = qmdb_resolver::Mailbox<Qmdb<deterministic::Context>, mmr::Family, Op, Digest>;
type Op = <Qmdb<deterministic::Context> as commonware_storage::qmdb::sync::Source>::Op;

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
    ) -> Option<Input> {
        let value = u64::from(context.chain().get()) * 1_000 + context.height().get();
        Some(TransactionBlock::from_context(context, MockBody(value)))
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

/// A running validator.
struct Validator {
    chain: Chain,
    marshal: Marshal,
    stateful: ordered::Mailbox<deterministic::Context, Tally<Input>>,
    checkpoints: Checkpoints<Scheme, State>,
    tally: Tally<Input>,
    _engine: Running<Digest>,
    _marshal: ServiceHandle,
    _handles: Vec<Handle<()>>,
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
    /// checkpoint its peers certified, and its marshal from a floor they serve.
    async fn start(&self, index: usize, joining: bool) -> Validator {
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
        ] {
            channels.push(Some(control.register(channel, QUOTA).await.unwrap()));
        }
        let mut channel = |id: u64| channels[id as usize].take().unwrap();
        let prefix = format!("validator_{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
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
        let mut archive = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(16)),
        );
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
                    update_channel_size: NZUsize!(4),
                },
                mailbox_size: NZUsize!(256),
                prune_config: Some(PruneConfig {
                    maintenance_interval: NZUsize!(4),
                    retained_marshal_blocks: 8,
                    retained_qmdb_blocks: 8,
                }),
            },
        );
        let (executor, inbox, chain) = Executor::<_, _, Marshal, _, TwoCap, Exact>::init(
            context.child("executor"),
            executor::Config {
                execute: stateful_mailbox.clone(),
                consumer: stateful_mailbox.clone(),
                ack_window: ACK_WINDOW,
                epoch: self.committee.config.epoch(),
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
        let checkpoints = Checkpoints::<Scheme, State>::new(chain.clone(), INTERVAL);
        let aggregation = aggregation::Engine::new(
            context.child("aggregation"),
            aggregation::Config {
                monitor: checkpoints.clone(),
                provider: ConstantProvider::new(scheme.clone()),
                automaton: checkpoints.clone(),
                reporter: checkpoints.clone(),
                blocker: control.clone(),
                priority_acks: false,
                rebroadcast_timeout: NZDuration!(Duration::from_millis(500)),
                epoch_bounds: (EpochDelta::zero(), EpochDelta::zero()),
                window: NZU64!(8),
                activity_timeout: HeightDelta::new(64),
                journal_partition: format!("{prefix}_aggregation"),
                journal_write_buffer: NZUsize!(4_096),
                journal_replay_buffer: NZUsize!(4_096),
                journal_heights_per_section: NZU64!(8),
                journal_compression: None,
                journal_page_cache: page_cache.clone(),
                strategy: Sequential,
            },
        );
        handles.push(aggregation.start(channel(AGGREGATION)));

        // Every validator serves its newest checkpoint; a joining one also samples its peers'.
        let lqc_verifier = self.committee.verifier.clone();
        let mut rng = context.child("floor_verifier");
        let (probe, sampler) = Probe::new(probe::Config {
            context: context.child("probe"),
            scheme,
            floor_verifier: move |floor: &Floor<MinPk, Digest>| {
                lqc_verifier
                    .verify_lqc::<_, Sha256, _>(&mut rng, floor.anchor(), &Sequential)
                    .is_some()
            },
            strategy: Sequential,
            blocker: control.clone(),
            interval: INTERVAL,
            block_codec: (),
            floor_codec: self.committee.codec(),
            retry_timeout: NZDuration!(Duration::from_millis(500)),
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
                page_cache: CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
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
                    probe::join(context, sampler, marshal, chain, Duration::from_millis(500))
                }
            }));
        }
        engine.ready().await.expect("engine becomes ready");
        Validator {
            chain,
            marshal,
            stateful: stateful_mailbox,
            checkpoints,
            tally,
            _engine: engine,
            _marshal: marshal_handle,
            _handles: handles,
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
            validators.push(committee.start(index, false).await);
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
            let height = validator.checkpoints.height(latest.item.height).unwrap();
            if let Some(block) = validator.chain.block_at(height).await {
                assert_eq!(block.digest(), latest.item.digest);
            }
        }
        assert!(validators[0].counter().await > 0);

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

#[test]
fn a_late_validator_state_syncs_to_a_certified_checkpoint() {
    deterministic::Runner::timed(Duration::from_secs(180)).start(|context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..VALIDATORS as usize - 1 {
            validators.push(committee.start(index, false).await);
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

        // The late validator executes only the chain after the checkpoint it synced to.
        let late = committee.start(VALIDATORS as usize - 1, true).await;
        let target = validators[0].tally.applied() + 16;
        until_applied(&context, [&late.tally, &validators[0].tally], target).await;
        let first = late.tally.applied.lock()[0];
        assert!(
            first > INTERVAL.get() && first % INTERVAL.get() == 0,
            "the late validator executed from height {first}, not after a checkpoint"
        );
        let reference = validators[0]
            .chain
            .block_at(Height::new(target))
            .await
            .unwrap();
        assert_eq!(
            late.chain.block_at(Height::new(target)).await.unwrap(),
            reference
        );
    });
}
