//! Epoch-scoped Simplex engines driven by finalized epoch artifacts.
//!
//! The orchestrator is the bridge between finalized epoch material and
//! [`simplex`](commonware_consensus::simplex) consensus. It runs one Simplex
//! engine for the active epoch, watches marshal's finalized block stream, and
//! moves to the next epoch when the active epoch's final block is finalized with
//! the next [`EpochInfo`].
//!
//! # Epoch Lifecycle
//!
//! Upon startup, the orchestrator reads the active epoch, its [`EpochInfo`], and
//! the certified root its Simplex engine starts from: from the
//! [`state_sync::Plan`] if it resolves to material, and otherwise from marshal (see
//! [Marshal Boundary](#marshal-boundary)).
//!
//! Upon entering an epoch, the orchestrator:
//!
//! 1. Waits for the [`Gate`] to reach the epoch.
//! 2. Activates the epoch's peers from its [`EpochInfo`].
//! 3. Loads the epoch's scheme from its [`Provider`].
//! 4. Opens the epoch's vote, certificate, and resolver subchannels and starts
//!    its Simplex engine.
//!
//! Upon a finalized block reported by marshal through [`Mailbox`]:
//!
//! - If it is below the active epoch's final block, acknowledge it.
//! - If it is above the active epoch's final block, panic.
//! - Otherwise, read the next epoch's [`EpochInfo`] from it, enter the next epoch
//!   from the block's commitment, stop the previous engine, and only then
//!   acknowledge the block.
//!
//! ```text
//! finalized boundary or state-sync artifact: EpochInfo(N)
//!                         |
//!                         v
//!              Gate(N) -> activate peers
//!                         |
//!                         v
//!              Provider::scheme(N)
//!                         |
//!                         v
//!              Simplex engine for epoch N
//!                         |
//!                         v
//!              marshal finalized block stream
//!                         |
//!                         v
//!              final block carries EpochInfo(N + 1)
//!                         |
//!                         v
//!              enter N + 1 -> stop N -> acknowledge
//! ```
//!
//! Once started, the orchestrator requires marshal to deliver every finalized
//! block above the latest one it acknowledged in height order. It acknowledges
//! a redelivered block without repeating its effects. The startup state-sync
//! floor is the only permitted jump, so a live marshal floor must not leave a
//! height below it that the orchestrator has not acknowledged.
//!
//! # Marshal Boundary
//!
//! Epoch zero is anchored by marshal's height-zero block, and each later epoch by
//! the final block of the previous epoch. Without state-sync material, the
//! orchestrator recovers the epoch containing marshal's next unprocessed height
//! and reads that epoch's [`EpochInfo`] and Simplex root from its boundary block,
//! which must remain in marshal's finalized block archive (see the
//! [retention requirement](crate::dkg#marshal-retention)).
//!
//! # Catching Up
//!
//! Upon receiving a vote or certificate for an epoch later than the active one,
//! the orchestrator asks its sender for the finalization of the active epoch's
//! final block. Marshal delivery of that block then drives the transition.
//! Messages for earlier epochs are ignored.
//!
//! # Failures
//!
//! The actor exits cleanly if the gate closes, peer activation fails, marshal
//! cannot supply a boundary block, its mailbox or a consensus muxer closes, the
//! active Simplex engine stops without error, or the runtime stops. It panics if
//! a boundary block does not carry the [`EpochInfo`] of the epoch it introduces,
//! if a finalized block is above the active epoch's final block, if the
//! [`Provider`] has no scheme for an entered epoch, if the [`SimplexConfig`] is
//! invalid, if an epoch's Simplex engine fails, or if the [`state_sync::Plan`]
//! cannot access storage.
//!
//! # Configuration
//!
//! [`Config`] connects the actor to marshal, the application, the scheme
//! [`Provider`], and the network. [`SimplexConfig`] holds the per-epoch Simplex
//! settings.
//!
//! [`EpochInfo`]: crate::dkg::types::EpochInfo
//! [`state_sync::Plan`]: crate::dkg::state_sync::Plan
//! [`Gate`]: crate::dkg::fence::Gate
//! [`Provider`]: commonware_cryptography::certificate::Provider

mod mailbox;
pub use mailbox::{Mailbox, Message};

mod actor;
pub use actor::{Actor, Config, SimplexConfig};

#[cfg(test)]
mod tests {
    use super::{Actor, Config};
    use crate::dkg::{
        fence::Fence,
        network::{Addresses, Manager},
        state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
        tests::{max_supported_mode, mocks},
        types::{EpochInfo, EpochOutcome, Payload},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        Heightable, Reporter, Reporters,
        simplex::{
            marshal::{self, Start as MarshalStart, resolver::p2p as marshal_resolver},
            types::{Activity, Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digestible as _, Hasher as _,
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
        certificate::Verifier as _,
        sha256::Sha256,
    };
    use commonware_macros::select;
    use commonware_p2p::{
        Address,
        simulated::{Config as NetworkConfig, Link, Network, Oracle},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Handle, Quota, Runner, Spawner as _, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        Acknowledgement, N3f1, NZU16, NZU32, NZU64, NZUsize, TestRng, acknowledgement::Exact,
        non_empty, ordered::Set, probability, sequence::Unit,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    const BACKFILL_CHANNEL: u64 = 0;
    const VOTE_CHANNEL: u64 = 1;
    const CERTIFICATE_CHANNEL: u64 = 2;
    const RESOLVER_CHANNEL: u64 = 3;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };
    type TestStateSync = StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;

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
            Self::start_with_fixture_and_state_sync(context, fixture, seed_first, None).await
        }

        async fn start_with_state_sync(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            state_sync: TestStateSync,
        ) -> Self {
            Self::start_with_fixture_and_state_sync(context, fixture, false, Some(state_sync)).await
        }

        async fn start_with_fixture_and_state_sync(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            seed_first: bool,
            first_state_sync: Option<TestStateSync>,
        ) -> Self {
            Self::start_with_fixture_state_sync_and_gate_epoch(
                context,
                fixture,
                seed_first,
                first_state_sync,
                Epoch::new(1),
            )
            .await
        }

        async fn start_with_gate_epoch(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            seed_first: bool,
            gate_epoch: Epoch,
        ) -> Self {
            Self::start_with_fixture_state_sync_and_gate_epoch(
                context, fixture, seed_first, None, gate_epoch,
            )
            .await
        }

        async fn start_with_fixture_state_sync_and_gate_epoch(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            seed_first: bool,
            mut first_state_sync: Option<TestStateSync>,
            gate_epoch: Epoch,
        ) -> Self {
            let participants = fixture.participants.clone();
            let boundary = make_height_one_block(participants[0].clone(), &participants);
            let nodes = participants.len();

            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(nodes),
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
                let state_sync = if index == 0 {
                    first_state_sync.take()
                } else {
                    None
                };
                started.push(
                    Node::start(
                        context.child("node").with_attribute("index", index),
                        &oracle,
                        fixture,
                        index,
                        boundary,
                        state_sync,
                        gate_epoch,
                        oracle.manager(),
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
            self.nodes[index].stop().await;
            self.nodes[index] = Node::start(
                context,
                &self.oracle,
                fixture,
                index,
                None,
                None,
                Epoch::new(1),
                self.oracle.manager(),
            )
            .await;
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
        orchestrator: super::Mailbox<mocks::TestBlock, Exact>,
        application: mocks::MockApplication,
        orchestrator_handle: Handle<()>,
        marshal_handle: Handle<()>,
        // Held so the epoch gate stays open for the node's lifetime.
        _fence: Fence,
    }

    impl Node {
        #[allow(clippy::too_many_arguments)]
        async fn start<M>(
            context: deterministic::Context,
            oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
            fixture: &mocks::SchemeFixture,
            index: usize,
            boundary: Option<mocks::TestBlock>,
            state_sync: Option<TestStateSync>,
            gate_epoch: Epoch,
            manager: M,
        ) -> Self
        where
            M: Manager<PublicKey = mocks::TestPublicKey, Directory = Unit>,
        {
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
                    start: MarshalStart::Genesis(genesis.into()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(16),
                    view_retention: ViewDelta::new(8),
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
            let state_sync = StateSyncPlan::init(
                context.child("state_sync_plan"),
                StateSyncConfig {
                    partition_prefix: partition_prefix.clone(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                },
                state_sync,
            )
            .await;
            let application = mocks::MockApplication::default();
            let (fence, gate) = Fence::new(gate_epoch);
            let (actor, mailbox) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager,
                    provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                    marshal: marshal.clone(),
                    application: application.clone(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(&context),
                    gate,
                    state_sync,
                    blocks_per_epoch: NZU64!(2),
                    muxer_size: 16,
                    mailbox_size: NZUsize!(16),
                    partition_prefix,
                },
            );
            let orchestrator = mailbox.clone();
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
            let simplex_resolver = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register simplex resolver channel");
            let orchestrator_handle = actor.start(votes, certificates, simplex_resolver);

            Self {
                marshal,
                orchestrator,
                application,
                orchestrator_handle,
                marshal_handle,
                _fence: fence,
            }
        }

        fn abort(&mut self) {
            self.orchestrator_handle.abort();
            self.marshal_handle.abort();
        }

        /// Abort and join the orchestrator and marshal tasks.
        async fn stop(&mut self) {
            self.abort();
            let _ = (&mut self.orchestrator_handle).await;
            let _ = (&mut self.marshal_handle).await;
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
    ) -> Arc<mocks::TestBlock> {
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
            TestRng::new(epoch.get() + 1),
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
            directory: Unit,
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
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
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
    fn address_failure_stops_before_consensus_engine_starts() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let participants = fixture.participants.clone();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants,
            )
            .await;
            let network = network.start();
            let mut node = Node::start(
                context.child("node"),
                &oracle,
                &fixture,
                0,
                None,
                None,
                Epoch::new(1),
                mocks::FailingManager(oracle.manager()),
            )
            .await;

            select! {
                result = &mut node.orchestrator_handle => {
                    result.expect("orchestrator should stop cleanly");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("orchestrator did not stop after peer-set failure");
                },
            }
            assert!(node.application.proposals().is_empty());
            node.abort();
            network.abort();
        });
    }

    #[test]
    fn shutdown_interrupts_boundary_gate_wait() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let cluster =
                Cluster::start_with_gate_epoch(&mut context, &fixture, true, Epoch::zero()).await;
            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::zero()).await;
            assert_eq!(proposal.round.epoch(), Epoch::zero());

            context.sleep(Duration::from_millis(10)).await;

            context
                .child("shutdown")
                .stop(7, Some(Duration::from_secs(1)))
                .await
                .expect("shutdown should interrupt the boundary gate wait");
        });
    }

    #[test]
    fn marshal_shutdown_during_startup_resolution_stops_cleanly() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let participants = fixture.participants.clone();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let public_key = participants[0].clone();
            let control = oracle.control(public_key.clone());
            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
            let partition_prefix = "orchestrator-marshal-shutdown".to_string();

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
            let genesis = make_genesis_block(public_key.clone(), participants.iter().cloned());
            let (marshal_actor, marshal, _): (_, mocks::TestMarshalMailbox, _) =
                marshal::core::Actor::<_, _, _, _, _, _, _, Exact>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                        epocher: FixedEpocher::new(NZU64!(2)),
                        start: MarshalStart::Genesis(genesis.into()),
                        partition_prefix: partition_prefix.clone(),
                        mailbox_size: NZUsize!(16),
                        view_retention: ViewDelta::new(8),
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

            let (_fence, gate) = Fence::new(Epoch::new(1));
            let (actor, _mailbox): (_, super::Mailbox<mocks::TestBlock, Exact>) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager: oracle.manager(),
                    provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                    marshal: marshal.clone(),
                    application: mocks::MockApplication::default(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(&context),
                    gate,
                    state_sync: StateSyncPlan::disabled(),
                    blocks_per_epoch: NZU64!(2),
                    muxer_size: 16,
                    mailbox_size: NZUsize!(16),
                    partition_prefix,
                },
            );
            let votes = control
                .register(VOTE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register vote channel");
            let certificates = control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register certificate channel");
            let simplex_resolver = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register simplex resolver channel");

            // The marshal actor is never started, so startup resolution parks
            // on an unserved processed-height read.
            let mut orchestrator_handle = actor.start(votes, certificates, simplex_resolver);
            context.sleep(Duration::from_millis(10)).await;

            // Signal shutdown, then drop the marshal actor: its mailbox
            // cancels the pending reads only after the stop signal is visible,
            // mirroring marshal winning the shutdown race.
            let stopper = context.child("stopper");
            context.child("stop").spawn(|_| async move {
                let _ = stopper.stop(0, None).await;
            });
            context.sleep(Duration::from_millis(10)).await;
            drop(marshal_actor);

            select! {
                result = &mut orchestrator_handle => {
                    result.expect("orchestrator should stop cleanly");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("orchestrator stayed alive after marshal shutdown");
                },
            };
        });
    }

    #[test]
    fn missing_boundary_block_stops_cleanly() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let mut cluster = Cluster::start_with_seeded_first(&mut context, 1, false).await;
            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::zero()).await;
            assert_eq!(proposal.round.epoch(), Epoch::zero());

            let boundary = Arc::new(cluster.boundary.clone());
            let node = &mut cluster.nodes[0];
            let (acknowledgement, _waiter) = Exact::handle();
            assert_eq!(
                node.orchestrator
                    .report(marshal::Update::Block(boundary, acknowledgement)),
                Feedback::Ok
            );

            select! {
                result = &mut node.orchestrator_handle => {
                    result.expect("orchestrator should stop cleanly");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("orchestrator stayed alive after boundary block lookup failed");
                },
            };
        });
    }

    /// Marshal delivers finalized blocks in height order, so a block above the active epoch's
    /// final block means marshal skipped that final block. The orchestrator panics instead of
    /// acknowledging the block and remaining in the previous epoch.
    #[test]
    #[should_panic(expected = "finalized block skips the final block of epoch 0")]
    fn skipped_final_block_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            // Without the boundary block, a lone node stays in epoch zero, whose final block is
            // at height one.
            let mut cluster = Cluster::start_with_seeded_first(&mut context, 1, false).await;
            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::zero()).await;
            assert_eq!(proposal.round.epoch(), Epoch::zero());

            // Marshal reports the first block of epoch one without the final block of epoch
            // zero.
            let skipped = Arc::new(mocks::child(&cluster.boundary));
            let node = &mut cluster.nodes[0];
            let (acknowledgement, waiter) = Exact::handle();
            assert_eq!(
                node.orchestrator
                    .report(marshal::Update::Block(skipped, acknowledgement)),
                Feedback::Ok
            );
            let _ = waiter.await;
        });
    }

    #[test]
    #[should_panic(expected = "state sync artifact and floor must be in the same epoch")]
    fn state_sync_rejects_mismatched_floor_epoch() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let info = make_epoch_info(Epoch::new(1), fixture.participants.iter().cloned());
            let genesis = make_genesis_block(
                fixture.participants[0].clone(),
                fixture.participants.iter().cloned(),
            );
            let floor = make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    genesis.digest(),
                ),
                &fixture.schemes,
            );

            let state_sync = StateSync { info, floor };
            let _cluster = Cluster::start_with_state_sync(&mut context, &fixture, state_sync).await;
        });
    }

    #[test]
    fn state_sync_entry_activates_peers_from_in_band_directory() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            type AddressedBlock = mocks::MockBlock<
                mocks::TestDigest,
                mocks::TestContext,
                Addresses<mocks::TestPublicKey>,
            >;
            type AddressedVariant = marshal::standard::Standard<AddressedBlock>;

            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let participants = fixture.participants.clone();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            let network_handle = network.start();

            // A certificate-backed artifact for the synced epoch carries the
            // committee's addresses in-band: a state-syncing node has no
            // application state to resolve them from.
            let synced_epoch = Epoch::new(3);
            let directory = participants
                .iter()
                .enumerate()
                .map(|(index, peer)| {
                    let socket =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000 + index as u16);
                    (peer.clone(), Address::Symmetric(socket))
                })
                .collect::<Addresses<_>>();
            let participant_set = Set::from_iter_dedup(participants.iter().cloned());
            let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
                TestRng::new(7),
                Mode::NonZeroCounter,
                participant_set.clone(),
            )
            .expect("failed to create test DKG output");
            let info = EpochInfo {
                outcome: EpochOutcome::Success,
                epoch: synced_epoch,
                output,
                players: participant_set.clone(),
                next_players: participant_set,
                directory: directory.clone(),
            };

            let genesis_digest = Sha256::hash(&[b""]);
            let genesis: AddressedBlock = mocks::MockBlock::new::<Sha256>(
                mocks::TestContext {
                    round: Round::new(Epoch::zero(), View::zero()),
                    leader: participants[0].clone(),
                    parent: (View::zero(), genesis_digest),
                },
                genesis_digest,
                Height::zero(),
                0,
            );
            let floor = make_finalization(
                Proposal::new(
                    Round::new(synced_epoch, View::new(1)),
                    View::zero(),
                    genesis.digest(),
                ),
                &fixture.schemes,
            );

            let public_key = participants[0].clone();
            let control = oracle.control(public_key.clone());
            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
            let partition_prefix = "orchestrator-in-band-directory".to_string();

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
            let (marshal_actor, marshal, _): (
                _,
                marshal::core::Mailbox<mocks::TestScheme, AddressedVariant>,
                _,
            ) = marshal::core::Actor::<_, _, _, _, _, _, _, Exact>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                    epocher: FixedEpocher::new(NZU64!(2)),
                    start: MarshalStart::Genesis(genesis.into()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(16),
                    view_retention: ViewDelta::new(8),
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
            let state_sync = StateSyncPlan::init(
                context.child("state_sync_plan"),
                StateSyncConfig {
                    partition_prefix: partition_prefix.clone(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                },
                Some(StateSync {
                    info: info.clone(),
                    floor,
                }),
            )
            .await;

            let manager = mocks::DirectoryManager::new(oracle.manager());
            let (_fence, gate) = Fence::new(synced_epoch);
            let (actor, mailbox): (_, super::Mailbox<AddressedBlock, Exact>) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager: manager.clone(),
                    provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                    marshal: marshal.clone(),
                    application: mocks::MockApplication::default(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(&context),
                    gate,
                    state_sync,
                    blocks_per_epoch: NZU64!(2),
                    muxer_size: 16,
                    mailbox_size: NZUsize!(16),
                    partition_prefix,
                },
            );
            let marshal_handle = marshal_actor.start_unbuffered(mailbox, resolver);

            let votes = control
                .register(VOTE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register vote channel");
            let certificates = control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register certificate channel");
            let simplex_resolver = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register simplex resolver channel");
            let orchestrator_handle = actor.start(votes, certificates, simplex_resolver);

            let tracked = loop {
                let tracked = manager.tracked();
                if !tracked.is_empty() {
                    break tracked;
                }
                context.sleep(Duration::from_millis(10)).await;
            };
            assert_eq!(tracked.len(), 1);
            let (epoch, peers, tracked_directory) = &tracked[0];
            assert_eq!(*epoch, synced_epoch);
            assert_eq!(peers, &info.participants().tracked_peers());
            assert_eq!(tracked_directory, &directory);

            orchestrator_handle.abort();
            marshal_handle.abort();
            network_handle.abort();
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
