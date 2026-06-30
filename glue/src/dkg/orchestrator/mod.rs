//! Orchestrate [`Epoch`]-specific Simplex engines.
//!
//! The orchestrator is the bridge between finalized epoch material and
//! [`simplex`](commonware_consensus::simplex) consensus. It starts one Simplex
//! engine for the locally resolved epoch, watches marshal's finalized block
//! stream, and moves to the next epoch whenever the current epoch's final block
//! is finalized with the next [`EpochInfo`](crate::dkg::types::EpochInfo).
//!
//! # Epoch Lifecycle
//!
//! Epoch changes are driven by finalized blocks:
//!
//! 1. Startup resolves an epoch, peer set, and floor from marshal or state sync.
//! 2. The orchestrator tracks the peer set, loads the epoch scheme from its
//!    [`Provider`](commonware_cryptography::certificate::Provider), opens
//!    epoch-specific P2P subchannels, and starts Simplex.
//! 3. Marshal reports finalized blocks through [`Mailbox`].
//! 4. When the finalized block is the final block of the active epoch, the
//!    orchestrator extracts the next epoch's public `EpochInfo`, tracks the next
//!    peer set, aborts the old Simplex engine, and starts the next one from the
//!    boundary commitment.
//!
//! ```text
//! marshal boundary or state-sync artifact
//!        |
//!        v
//! Provider::scheme(epoch)
//!        |
//!        v
//! Simplex engine for epoch N
//!        |
//!        v
//! marshal finalized block stream
//!        |
//!        v
//! final block of epoch N carries EpochInfo(N + 1)
//!        |
//!        v
//! abort epoch N + start epoch N + 1
//! ```
//!
//! # Marshal Boundary
//!
//! Epoch zero is anchored by marshal's height-zero block. Later epochs are
//! anchored by the last finalized block of the previous epoch.
//!
//! # Catching Up
//!
//! Consensus votes are multiplexed by epoch. If the vote mux receives a message
//! for a future epoch that has not been registered locally, the node is behind.
//! The orchestrator hints marshal to fetch the boundary finalization needed to
//! reach that epoch, allowing normal marshal delivery to drive the transition.
//!
//! # Configuration
//!
//! [`Config`] wires together marshal, the application automaton/relay, the
//! scheme provider, P2P manager/blocker, optional state-sync material, network
//! channels, and persistence partitions. [`SimplexConfig`] contains the
//! per-epoch Simplex tunables; callers must provide these explicitly rather
//! than relying on hidden defaults.
//!
//! [`Epoch`]: commonware_consensus::types::Epoch

mod mailbox;
pub use mailbox::{Mailbox, Message};

mod actor;
pub use actor::{Actor, Config, SimplexConfig, StateSync};

#[cfg(test)]
mod tests {
    use super::{Actor, Config};
    use crate::dkg::{
        fence::Fence,
        tests::mocks,
        types::{EpochInfo, EpochOutcome, Payload},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        marshal::{self, resolver::p2p as marshal_resolver, Start as MarshalStart},
        simplex::types::{Activity, Finalization, Finalize, Proposal},
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
        Heightable, Reporter, Reporters,
    };
    use commonware_cryptography::{
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
        certificate::Verifier as _,
        sha256::Sha256,
        Digestible as _,
    };
    use commonware_p2p::{
        simulated::{Config as NetworkConfig, Link, Network, Oracle},
        utils::mux::{Builder, Muxer},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock as _, Handle, Quota, Runner, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{ordered::Set, test_rng_seeded, N3f1, NZUsize, NZU16, NZU32, NZU64};
    use std::time::Duration;

    const BACKFILL_CHANNEL: u64 = 0;
    const VOTE_CHANNEL: u64 = 1;
    const CERTIFICATE_CHANNEL: u64 = 2;
    const RESOLVER_CHANNEL: u64 = 3;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: 1.0,
    };

    struct Cluster {
        nodes: Vec<Node>,
        boundary: mocks::TestBlock,
        oracle: Oracle<mocks::TestPublicKey, deterministic::Context>,
        network_handle: Handle<()>,
    }

    impl Cluster {
        async fn start(context: &mut deterministic::Context, nodes: usize) -> Self {
            Self::start_with_seeded_first(context, nodes, true).await
        }

        async fn start_with_seeded_first(
            context: &mut deterministic::Context,
            nodes: usize,
            seed_first: bool,
        ) -> Self {
            let fixture = mocks::scheme_fixture_n(context, nodes as u32);
            Self::start_with_fixture(context, &fixture, seed_first).await
        }

        async fn start_with_fixture(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            seed_first: bool,
        ) -> Self {
            let participants = fixture.participants.clone();
            let boundary = make_height_one_block(participants[0].clone(), &participants);
            let nodes = participants.len();

            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            let network_handle = network.start();
            for from in &participants {
                for to in &participants {
                    if from != to {
                        oracle
                            .add_link(from.clone(), to.clone(), LINK)
                            .await
                            .expect("failed to add link");
                    }
                }
            }

            let mut started = Vec::with_capacity(nodes);
            for index in 0..nodes {
                let boundary = (seed_first || index > 0).then(|| boundary.clone());
                started.push(
                    Node::start(
                        context.child("node").with_attribute("index", index),
                        &oracle,
                        fixture,
                        index,
                        boundary,
                    )
                    .await,
                );
            }

            Self {
                nodes: started,
                boundary,
                oracle,
                network_handle,
            }
        }

        async fn restart(
            &mut self,
            context: deterministic::Context,
            fixture: &mocks::SchemeFixture,
            index: usize,
        ) {
            self.nodes[index].abort();
            self.nodes[index] = Node::start(context, &self.oracle, fixture, index, None).await;
        }
    }

    impl Drop for Cluster {
        fn drop(&mut self) {
            for node in &mut self.nodes {
                node.abort();
            }
            self.network_handle.abort();
        }
    }

    struct Node {
        marshal: mocks::TestMarshalMailbox,
        application: mocks::MockApplication,
        orchestrator_handle: Handle<()>,
        marshal_handle: Handle<()>,
    }

    impl Node {
        async fn start(
            context: deterministic::Context,
            oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
            fixture: &mocks::SchemeFixture,
            index: usize,
            boundary: Option<mocks::TestBlock>,
        ) -> Self {
            let public_key = fixture.participants[index].clone();
            let control = oracle.control(public_key.clone());
            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
            let partition_prefix = format!("orchestrator-node-{index}");

            let backfill = control
                .register(BACKFILL_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register marshal backfill channel");
            let resolver = marshal_resolver::init(
                context.child("marshal_resolver"),
                marshal_resolver::Config {
                    public_key: public_key.clone(),
                    peer_provider: oracle.manager(),
                    blocker: control.clone(),
                    mailbox_size: NZUsize!(16),
                    initial: Duration::from_millis(100),
                    timeout: Duration::from_millis(200),
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
                backfill,
            );

            let finalizations_by_height =
                immutable::Archive::init(context.child("finalizations_by_height"), {
                    let _: () = mocks::TestScheme::certificate_codec_config_unbounded();
                    archive_config(
                        &partition_prefix,
                        "finalizations_by_height",
                        page_cache.clone(),
                        (),
                    )
                })
                .await
                .expect("failed to initialize finalizations archive");
            let finalized_blocks = immutable::Archive::init(
                context.child("finalized_blocks"),
                archive_config(&partition_prefix, "finalized_blocks", page_cache, ()),
            )
            .await
            .expect("failed to initialize finalized blocks archive");

            let genesis =
                make_genesis_block(public_key.clone(), fixture.participants.iter().cloned());
            let (marshal_actor, mut marshal, _) = marshal::core::Actor::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                    epocher: FixedEpocher::new(NZU64!(2)),
                    start: MarshalStart::Genesis(genesis),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(16),
                    view_retention_timeout: ViewDelta::new(8),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16)),
                    replay_buffer: NZUsize!(1024),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    block_codec_config: (),
                    max_repair: NZUsize!(4),
                    max_pending_acks: NZUsize!(4),
                    strategy: Sequential,
                },
            )
            .await;
            let application = mocks::MockApplication::default();
            let (_fence, gate) = Fence::new(Epoch::new(1));
            let (actor, mailbox) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager: oracle.manager(),
                    provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                    marshal: marshal.clone(),
                    application: application.clone(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(),
                    gate,
                    state_sync: None,
                    blocks_per_epoch: NZU64!(2),
                    muxer_size: 16,
                    mailbox_size: NZUsize!(16),
                    partition_prefix,
                },
            );
            let reporters = Reporters::from((mocks::MarshalApplication::default(), mailbox));
            let marshal_handle = marshal_actor.start_unbuffered(reporters, resolver);

            if let Some(block) = &boundary {
                assert!(
                    marshal
                        .certified(block.context().round, block.clone())
                        .await
                );
                let finalization = make_finalization(
                    Proposal::new(
                        Round::new(Epoch::zero(), View::new(1)),
                        View::zero(),
                        block.digest(),
                    ),
                    &fixture.schemes,
                );
                assert_eq!(
                    marshal.report(Activity::Finalization(finalization)),
                    Feedback::Ok
                );
            }

            let votes = control
                .register(VOTE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register vote channel");
            let certificates = control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register certificate channel");
            let (certificate_mux, certificates) = Muxer::builder(
                context.child("certificate_mux"),
                certificates.0,
                certificates.1,
                16,
            )
            .build();
            certificate_mux.start();
            let simplex_resolver = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register simplex resolver channel");
            let orchestrator_handle = actor.start(votes, certificates, simplex_resolver);

            Self {
                marshal,
                application,
                orchestrator_handle,
                marshal_handle,
            }
        }

        fn abort(&mut self) {
            self.orchestrator_handle.abort();
            self.marshal_handle.abort();
        }
    }

    fn archive_config<C>(
        prefix: &str,
        name: &str,
        page_cache: CacheRef,
        codec_config: C,
    ) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}-{name}-metadata"),
            freezer_table_partition: format!("{prefix}-{name}-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{prefix}-{name}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{prefix}-{name}-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{prefix}-{name}-ordinal"),
            items_per_section: NZU64!(10),
            codec_config,
            replay_buffer: NZUsize!(1024),
            freezer_key_write_buffer: NZUsize!(1024),
            freezer_value_write_buffer: NZUsize!(1024),
            ordinal_write_buffer: NZUsize!(1024),
        }
    }

    async fn wait_for_block(
        context: &deterministic::Context,
        marshal: &mocks::TestMarshalMailbox,
        height: Height,
    ) -> mocks::TestBlock {
        for _ in 0..50 {
            if let Some(block) = marshal.get_block(height).await {
                return block;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("missing finalized block at height {height}");
    }

    async fn wait_for_proposal(
        context: &deterministic::Context,
        nodes: &[Node],
        epoch: Epoch,
    ) -> mocks::TestContext {
        for _ in 0..50 {
            for node in nodes {
                if let Some(proposal) = node
                    .application
                    .proposals()
                    .into_iter()
                    .find(|proposal| proposal.round.epoch() == epoch)
                {
                    return proposal;
                }
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("missing application proposal");
    }

    fn make_height_one_block(
        leader: mocks::TestPublicKey,
        participants: &[mocks::TestPublicKey],
    ) -> mocks::TestBlock {
        let genesis = make_genesis_block(leader.clone(), participants.iter().cloned());
        let context = mocks::TestContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (View::zero(), genesis.digest()),
        };
        let info = make_epoch_info(Epoch::new(1), participants.iter().cloned());
        mocks::TestBlock::new::<Sha256>(context, genesis.digest(), Height::new(1), 1)
            .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
            NZU32!(16),
            Payload::EpochInfo(info),
        )
    }

    fn make_genesis_block(
        leader: mocks::TestPublicKey,
        participants: impl IntoIterator<Item = mocks::TestPublicKey>,
    ) -> mocks::TestBlock {
        let info = make_epoch_info(Epoch::zero(), participants);
        mocks::genesis_block(leader)
            .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
                NZU32!(16),
                Payload::EpochInfo(info),
            )
    }

    fn make_epoch_info(
        epoch: Epoch,
        participants: impl IntoIterator<Item = mocks::TestPublicKey>,
    ) -> EpochInfo<mocks::TestBlsVariant, mocks::TestPublicKey> {
        let participants = Set::from_iter_dedup(participants);
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            test_rng_seeded(epoch.get() + 1),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("failed to create test DKG output");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch,
            output,
            players: participants.clone(),
            next_players: participants,
        }
    }

    fn make_finalization(
        proposal: Proposal<mocks::TestDigest>,
        schemes: &[mocks::TestScheme],
    ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("finalization quorum")
    }

    #[test]
    fn cluster_serves_genesis_through_marshal() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let cluster = Cluster::start_with_seeded_first(&mut context, 1, false).await;
            let block = cluster.nodes[0]
                .marshal
                .get_block(Height::zero())
                .await
                .expect("genesis should be available through marshal");

            assert_eq!(block.height(), Height::zero());
        });
    }

    #[test]
    fn initial_epoch_starts_without_mailbox_transition() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let cluster = Cluster::start_with_seeded_first(&mut context, 4, false).await;
            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::zero()).await;

            assert_eq!(proposal.round.epoch(), Epoch::zero());
        });
    }

    #[test]
    fn future_epoch_vote_hints_marshal_to_fetch_boundary_finalization() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let cluster = Cluster::start_with_seeded_first(&mut context, 4, false).await;
            let caught_up =
                wait_for_block(&context, &cluster.nodes[0].marshal, Height::new(1)).await;

            assert_eq!(caught_up.digest(), cluster.boundary.digest());
        });
    }

    #[test]
    fn finalized_boundary_enters_next_epoch() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let cluster = Cluster::start(&mut context, 4).await;
            let stored = wait_for_block(&context, &cluster.nodes[0].marshal, Height::new(1)).await;

            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::new(1)).await;

            assert_eq!(stored.digest(), cluster.boundary.digest());
            assert_eq!(proposal.round.epoch(), Epoch::new(1));
            assert_eq!(proposal.parent.1, cluster.boundary.digest());
        });
    }

    #[test]
    fn recovered_node_starts_from_processed_epoch() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let stored = wait_for_block(&context, &cluster.nodes[0].marshal, Height::new(1)).await;
            assert_eq!(stored.digest(), cluster.boundary.digest());

            cluster
                .restart(
                    context
                        .child("node")
                        .with_attribute("index", 0)
                        .with_attribute("restart", 1),
                    &fixture,
                    0,
                )
                .await;
            let proposal = wait_for_proposal(&context, &cluster.nodes[0..1], Epoch::new(1)).await;

            assert_eq!(proposal.round.epoch(), Epoch::new(1));
        });
    }
}
