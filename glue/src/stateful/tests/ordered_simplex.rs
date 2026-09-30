//! The ordered mode on a Simplex committee.
//!
//! Every validator runs the engine with an [`Inline`] producer, the marshal, an executor whose
//! application is stateful's ordered mode, aggregation over the executed chain's checkpoints,
//! signed by the same identities that sign consensus votes, and a checkpoint probe. A validator
//! that joins late state-syncs to a checkpoint its peers certified, and resumes its marshal from a
//! finalization they serve, instead of executing the chain from genesis.

use super::{
    common::{EPOCH_LENGTH, IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, archive_config},
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
use bytes::BufMut;
use commonware_broadcast::buffered;
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Application, Block, Heightable, aggregation,
    ancestry::Ancestry,
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
        marshal::{
            self, Identifier, Start,
            core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
            resolver::p2p as marshal_resolver,
            standard::{Inline, Standard},
        },
        scheme::ed25519 as simplex_ed25519,
        types::Context as Producing,
    },
    types::{Epoch, EpochDelta, FixedEpocher, Height, HeightDelta, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256,
    certificate::{ConstantProvider, Verifier as _, mocks::Fixture},
    ed25519,
    sha256::Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::{archive::prunable, mmr, translator::TwoCap};
use commonware_utils::{
    NZDuration, NZU64, NZUsize, acknowledgement::Exact, ordered::Set, probability, test_rng,
};
use futures::StreamExt as _;
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_SIMPLEX_TEST";
const CHECKPOINT_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_SIMPLEX_TEST_CHECKPOINTS";
const VALIDATORS: u32 = 4;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Executed blocks per checkpoint.
const INTERVAL: NonZeroU64 = NZU64!(8);

/// Delivered inputs that may await acknowledgement, in both marshal and the executor.
const ACK_WINDOW: NonZeroUsize = NZUsize!(16);

const VOTES: u64 = 0;
const CERTIFICATES: u64 = 1;
const ENGINE_RESOLVER: u64 = 2;
const MARSHAL_RESOLVER: u64 = 3;
const MARSHAL_BROADCAST: u64 = 4;
const AGGREGATION: u64 = 5;
const QMDB: u64 = 6;
const PROBE: u64 = 7;

type ConsensusScheme = simplex_ed25519::Scheme;
type CheckpointScheme = aggregation::scheme::ed25519::Scheme;
type Marshal = MarshalMailbox<ConsensusScheme, Standard<Input>>;
type Chain = executor::Mailbox<State>;

/// A block of the Simplex chain, worth its height to the counter.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    parent: Digest,
    height: Height,
}

impl Input {
    /// Returns the block at height zero.
    const fn genesis() -> Self {
        Self {
            parent: Digest::EMPTY,
            height: Height::zero(),
        }
    }
}

impl Write for Input {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
    }
}

impl EncodeSize for Input {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size()
    }
}

impl Read for Input {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            parent: Digest::read(buf)?,
            height: Height::read(buf)?,
        })
    }
}

impl Digestible for Input {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Heightable for Input {
    fn height(&self) -> Height {
        self.height
    }
}

impl Block for Input {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl Worth for Input {
    fn worth(&self) -> u64 {
        self.height.get()
    }
}

/// Builds each block on its parent.
#[derive(Clone)]
struct Producer;

impl Application<deterministic::Context> for Producer {
    type Context = Producing<Digest, ed25519::PublicKey>;
    type Block = Input;
    type Input = ();

    async fn propose(
        &mut self,
        _: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Input>,
        _: (),
    ) -> Option<Input> {
        let parent = Box::pin(ancestry).next().await?;
        Some(Input {
            parent: parent.digest(),
            height: parent.height.next(),
        })
    }

    async fn verify(
        &mut self,
        _: (deterministic::Context, Self::Context),
        _: impl Ancestry<Input>,
    ) -> bool {
        true
    }
}

/// A running validator.
struct Validator {
    chain: Chain,
    marshal: Marshal,
    stateful: ordered::Mailbox<deterministic::Context, Tally<Input>>,
    checkpoints: Checkpoints<CheckpointScheme, State>,
    tally: Tally<Input>,
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

/// A Simplex committee on a simulated network.
struct Cluster {
    context: deterministic::Context,
    fixture: Fixture<ConsensusScheme>,
    oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
}

impl Cluster {
    async fn new(context: deterministic::Context) -> Self {
        let fixture = simplex_ed25519::fixture(&mut test_rng(), NAMESPACE, VALIDATORS);
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(fixture.participants.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            fixture.participants.clone(),
        )
        .await;
        network.start();
        for a in &fixture.participants {
            for b in &fixture.participants {
                if a != b {
                    oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
                }
            }
        }
        Self {
            context,
            fixture,
            oracle,
        }
    }

    /// Starts validator `index`. A joining validator starts its executor from the newest
    /// checkpoint its peers certified, and its marshal from a finalization they serve.
    async fn start(&self, index: usize, joining: bool) -> Validator {
        let context = self
            .context
            .child("validator")
            .with_attribute("index", index);
        let identity = self.fixture.participants[index].clone();
        let scheme = self.fixture.schemes[index].clone();
        let control = self.oracle.control(identity.clone());
        let mut channels = Vec::new();
        for channel in [
            VOTES,
            CERTIFICATES,
            ENGINE_RESOLVER,
            MARSHAL_RESOLVER,
            MARSHAL_BROADCAST,
            AGGREGATION,
            QMDB,
            PROBE,
        ] {
            channels.push(Some(control.register(channel, QUOTA).await.unwrap()));
        }
        let mut channel = |id: u64| channels[id as usize].take().unwrap();
        let prefix = format!("validator_{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut handles = Vec::new();

        // Marshal disseminates, stores, and orders the blocks consensus finalizes.
        let (broadcast, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(256),
                ingress_size: NZUsize!(256),
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        handles.push(broadcast.start(channel(MARSHAL_BROADCAST)));
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: identity.clone(),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                mailbox_size: NZUsize!(256),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            channel(MARSHAL_RESOLVER),
        );
        let finalizations = prunable::Archive::init(
            context.child("finalizations"),
            archive_config(
                &prefix,
                "finalizations",
                page_cache.clone(),
                scheme.certificate_codec_config(),
            ),
        )
        .await
        .expect("finalizations archive opens");
        let blocks = prunable::Archive::init(
            context.child("blocks"),
            archive_config(&prefix, "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("blocks archive opens");
        let (marshal_actor, marshal, _) = MarshalActor::<_, Standard<Input>, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations,
            blocks,
            marshal::Config {
                provider: ConstantProvider::new(scheme.clone()),
                epocher: FixedEpocher::new(EPOCH_LENGTH),
                start: Start::Genesis(Arc::new(Input::genesis())),
                partition_prefix: prefix.clone(),
                mailbox_size: NZUsize!(256),
                view_retention: ViewDelta::new(10),
                prunable_items_per_section: NZU64!(10),
                page_cache: page_cache.clone(),
                replay_buffer: IO_BUFFER_SIZE,
                key_write_buffer: IO_BUFFER_SIZE,
                value_write_buffer: IO_BUFFER_SIZE,
                block_codec_config: (),
                max_repair: NZUsize!(10),
                max_pending_acks: ACK_WINDOW,
                strategy: Sequential,
            },
        )
        .await;

        // The ordered mode is both the executor's application and its consumer.
        let (qmdb_resolver, resolvers) =
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
                    max_outstanding_requests: 4,
                    update_channel_size: NZUsize!(4),
                    max_retained_roots: 8,
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
                epoch: Epoch::zero(),
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
        handles.push(marshal_actor.start(inbox, buffer, resolver));

        // Aggregation certifies the executed chain's checkpoints, signed by the identities that
        // sign consensus votes.
        let participants = Set::try_from(self.fixture.participants.clone()).unwrap();
        let checkpoint_scheme = CheckpointScheme::signer(
            CHECKPOINT_NAMESPACE,
            participants,
            self.fixture.private_keys[index].clone(),
        )
        .expect("validator is a participant");
        let checkpoints = Checkpoints::<CheckpointScheme, State>::new(chain.clone(), INTERVAL);
        let aggregation = aggregation::Engine::new(
            context.child("aggregation"),
            aggregation::Config {
                monitor: checkpoints.clone(),
                provider: ConstantProvider::new(checkpoint_scheme.clone()),
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
        let (probe, sampler) = Probe::new(probe::Config {
            context: context.child("probe"),
            scheme: checkpoint_scheme,
            strategy: Sequential,
            blocker: control.clone(),
            block_codec: (),
            floor_codec: scheme.certificate_codec_config(),
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
        let inline = Inline::new(
            context.child("producer"),
            Producer,
            marshal.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let engine = simplex::Engine::new(
            context.child("engine"),
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: control,
                automaton: inline.clone(),
                relay: inline,
                reporter: marshal.clone(),
                strategy: Sequential,
                partition: format!("{prefix}_simplex"),
                mailbox_size: NZUsize!(256),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(Input::genesis().digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: simplex::SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(2),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        handles.push(engine.start(
            channel(VOTES),
            channel(CERTIFICATES),
            channel(ENGINE_RESOLVER),
        ));

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
        Validator {
            chain,
            marshal,
            stateful: stateful_mailbox,
            checkpoints,
            tally,
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

        // Pruning reclaimed the first executed block and the first input.
        for validator in &validators {
            assert!(validator.chain.block_at(Height::new(1)).await.is_none());
            let first = validator
                .marshal
                .get_block(Identifier::Height(Height::new(1)))
                .await;
            assert!(first.is_none(), "marshal retains the first input");
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
            while validator
                .marshal
                .get_block(Identifier::Height(Height::new(1)))
                .await
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
