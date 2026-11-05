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
//! the certified root its Simplex engine starts from. It takes them from
//! state-sync material or the epoch's checkpoint in the [`state_sync::Plan`],
//! and otherwise from the epoch's boundary block in marshal (see
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
//! - Otherwise, read the next epoch's [`EpochInfo`] from it and record the
//!   block as that epoch's checkpoint in the [`state_sync::Plan`], with
//!   marshal's finalization of it when marshal has one. Then enter the next
//!   epoch from the block's commitment, stop the previous engine, and only then
//!   acknowledge the block.
//!
//! ```text
//! state-sync artifact, checkpoint, or finalized boundary: EpochInfo(N)
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
//!              checkpoint N + 1 -> enter N + 1 -> stop N -> acknowledge
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
//! and takes that epoch's [`EpochInfo`] and Simplex root from its
//! [checkpoint](crate::dkg#marshal-retention).
//!
//! For an epoch without a checkpoint, such as epoch zero on a new node, it
//! reads them from the boundary block in marshal's finalized block archive. It
//! then records that block as the epoch's checkpoint, with marshal's
//! finalization of it when marshal has one. The [probe](crate::dkg::probe)
//! serves the epoch to joining nodes from a checkpoint that holds the
//! finalization.
//!
//! # Catching Up
//!
//! A node that misses the active epoch's final block stays in that epoch while
//! the rest of the network moves on. It still receives votes and certificates
//! from later epochs, and even a later committee that is stalled waiting for
//! the lagging nodes keeps sending votes. The node cannot verify messages from
//! epochs it has not entered, so the orchestrator treats each one only as a
//! hint that its sender is ahead and ignores messages from earlier epochs.
//!
//! On each hint, the orchestrator asks marshal to fetch the final block's
//! finalization from the hint's sender. Further hints add their senders to the
//! same fetch, and marshal's resolver retries across them until one serves it,
//! so a fabricated hint costs the node only repeated requests to its sender.
//! Marshal verifies the finalization under the active epoch's scheme and blocks
//! any peer that answers with invalid data. Once marshal delivers the block,
//! the orchestrator enters the next epoch.
//!
//! The resolver asks only targets among the active epoch's [tracked peers],
//! primary or secondary, so the finalization can come from any honest tracked
//! peer that is still connected to the node, still holds it, and sends the node
//! later-epoch traffic. Marshal fetches any blocks the node is missing below the
//! final one from any tracked peer, so the next committee can serve them once
//! the node's own committee has departed. [Reconfiguration] describes which
//! peers qualify for a node one or more epochs behind.
//!
//! [tracked peers]: crate::dkg::types::Participants::tracked_peers
//! [Reconfiguration]: crate::dkg#reconfiguration
//!
//! # Failures
//!
//! The actor exits cleanly if the gate closes, peer activation fails, marshal
//! cannot supply a boundary block, its mailbox or a consensus muxer closes, the
//! active Simplex engine stops without error, or the runtime stops.
//!
//! The actor panics if:
//!
//! - a boundary block does not carry the [`EpochInfo`] of the epoch it
//!   introduces, or does not decode under the plan's block codec configuration
//! - a finalized block is above the active epoch's final block
//! - the [`Provider`] has no scheme for an entered epoch
//! - the [`SimplexConfig`] is invalid
//! - an epoch's Simplex engine fails
//! - the [`state_sync::Plan`] cannot access storage
//!
//! # Configuration
//!
//! [`Config`] connects the actor to marshal, the application, the scheme
//! [`Provider`], and the network. [`SimplexConfig`] holds the per-epoch Simplex
//! settings.
//!
//! # Message Sizes
//!
//! Each epoch's Simplex engine sends its votes, certificates, and resolver messages on the
//! subchannel of its epoch:
//!
//! ```text
//! Simplex message:
//! +---------------------------------+-------------------------------------------+
//! | epoch subchannel (varint, 1-10) | message (up to simplex::max_payload_size) |
//! +---------------------------------+-------------------------------------------+
//! ```
//!
//! [`max_payload_size`] is Simplex's
//! [`max_payload_size`](commonware_consensus::simplex::max_payload_size) for the largest committee
//! plus the widest epoch subchannel prefix.
//!
//! [`EpochInfo`]: crate::dkg::types::EpochInfo
//! [`state_sync::Plan`]: crate::dkg::state_sync::Plan
//! [`Gate`]: crate::dkg::fence::Gate
//! [`Provider`]: commonware_cryptography::certificate::Provider

mod mailbox;
pub use mailbox::{Mailbox, Message};

mod actor;
pub use actor::{Actor, Config, SimplexConfig};

mod limits;
pub use limits::max_payload_size;

#[cfg(test)]
mod tests {
    use super::{Actor, Config};
    use crate::dkg::{
        fence::Fence,
        network::{Addresses, Manager},
        state_sync::{Checkpoint, Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
        tests::{
            max_supported_mode,
            mocks::{self, FilteredReceiver},
        },
        types::{EpochInfo, EpochOutcome, Payload},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        Heightable, Reporter, Reporters,
        marshal::{self, Start as MarshalStart, resolver::p2p as marshal_resolver},
        simplex::types::{Activity, Finalization, Finalize, Proposal},
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digested, Digestible as _, Hasher as _,
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
    use commonware_storage::{archive::prunable, translator::TwoCap};
    use commonware_utils::{
        Acknowledgement, N3f1, NZDuration, NZU16, NZU32, NZU64, NZUsize, TestRng,
        acknowledgement::{Exact, ExactWaiter},
        non_empty,
        ordered::Set,
        probability,
        sequence::Unit,
        sync::Mutex,
    };
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    const BACKFILL_CHANNEL: u64 = 0;
    const VOTE_CHANNEL: u64 = 1;
    const CERTIFICATE_CHANNEL: u64 = 2;
    const RESOLVER_CHANNEL: u64 = 3;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_024));

    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };
    type TestStateSync = StateSync<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>;
    type TestPlan = StateSyncPlan<mocks::TestScheme, mocks::TestMarshalVariant>;

    /// Roles that the cluster's epoch infos assign and faults that its nodes exhibit.
    #[derive(Clone, Default)]
    struct Layout {
        /// Number of leading participants listed as dealers and so tracked as
        /// primary peers. The rest are players only and so tracked as secondary
        /// peers. `None` lists every participant as a dealer.
        dealers: Option<usize>,
        /// Indices of nodes whose marshal backfill receiver drops every message,
        /// so they never serve fetches.
        deaf: HashSet<usize>,
    }

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
                Layout::default(),
            )
            .await
        }

        /// Starts a cluster with `layout` whose first node lacks the boundary block.
        async fn start_with_layout(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            layout: Layout,
        ) -> Self {
            Self::start_with_fixture_state_sync_and_gate_epoch(
                context,
                fixture,
                false,
                None,
                Epoch::new(1),
                layout,
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
                context,
                fixture,
                seed_first,
                None,
                gate_epoch,
                Layout::default(),
            )
            .await
        }

        async fn start_with_fixture_state_sync_and_gate_epoch(
            context: &mut deterministic::Context,
            fixture: &mocks::SchemeFixture,
            seed_first: bool,
            mut first_state_sync: Option<TestStateSync>,
            gate_epoch: Epoch,
            layout: Layout,
        ) -> Self {
            let participants = fixture.participants.clone();
            let nodes = participants.len();
            let dealers = &participants[..layout.dealers.unwrap_or(nodes)];
            let boundary = make_height_one_block(participants[0].clone(), dealers, &participants);

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
                let context = context.child("node").with_attribute("index", index);
                let plan = node_plan(context.child("state_sync_plan"), index, state_sync).await;
                started.push(
                    Node::start(
                        context,
                        &oracle,
                        fixture,
                        index,
                        boundary,
                        plan,
                        gate_epoch,
                        oracle.manager(),
                        dealers,
                        layout.deaf.contains(&index),
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
            let plan = node_plan(context.child("state_sync_plan"), index, None).await;
            self.recover(context, fixture, index, plan, Epoch::new(1))
                .await;
        }

        /// Starts stopped node `index` from its storage with `plan`, with its gate
        /// open through `gate_epoch`.
        async fn recover(
            &mut self,
            context: deterministic::Context,
            fixture: &mocks::SchemeFixture,
            index: usize,
            plan: TestPlan,
            gate_epoch: Epoch,
        ) {
            self.nodes[index] = Node::start(
                context,
                &self.oracle,
                fixture,
                index,
                None,
                plan,
                gate_epoch,
                self.oracle.manager(),
                &fixture.participants,
                false,
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
        lagging: LaggingReporter,
        acks: AckObserver,
        orchestrator_handle: Handle<()>,
        marshal_handle: Handle<()>,
        // Held so the epoch gate stays open for the node's lifetime.
        _fence: Fence,
    }

    /// A marshal reporter that withholds its acknowledgement of one height, holding
    /// marshal's processed height below it while the other reporters move on.
    #[derive(Clone, Default)]
    struct LaggingReporter {
        held: Arc<Mutex<(Option<Height>, Vec<Exact>)>>,
    }

    impl LaggingReporter {
        fn hold(&self, height: Height) {
            self.held.lock().0 = Some(height);
        }
    }

    impl Reporter for LaggingReporter {
        type Activity = marshal::Update<mocks::TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let marshal::Update::Block(block, ack) = activity {
                let mut held = self.held.lock();
                if held.0 == Some(block.height()) {
                    held.1.push(ack);
                } else {
                    ack.acknowledge();
                }
            }
            Feedback::Ok
        }
    }

    /// Forwards marshal's updates to the orchestrator and observes when it acknowledges one
    /// chosen height.
    ///
    /// The orchestrator receives that height's block with a private acknowledgement whose
    /// waiter [`Self::acknowledged`] awaits. Marshal's own acknowledgement is held, so its
    /// processed height stays below the block.
    #[derive(Clone)]
    struct AckObserver {
        orchestrator: super::Mailbox<mocks::TestBlock, Exact>,
        observed: Arc<Mutex<Option<Height>>>,
        held: Arc<Mutex<Option<Exact>>>,
        waiter: Arc<Mutex<Option<ExactWaiter>>>,
    }

    impl AckObserver {
        fn new(orchestrator: super::Mailbox<mocks::TestBlock, Exact>) -> Self {
            Self {
                orchestrator,
                observed: Arc::new(Mutex::new(None)),
                held: Arc::new(Mutex::new(None)),
                waiter: Arc::new(Mutex::new(None)),
            }
        }

        fn observe(&self, height: Height) {
            *self.observed.lock() = Some(height);
        }

        /// Waits until the orchestrator acknowledges the observed height.
        async fn acknowledged(&self, context: &deterministic::Context) {
            let waiter = loop {
                if let Some(waiter) = self.waiter.lock().take() {
                    break waiter;
                }
                context.sleep(Duration::from_millis(10)).await;
            };
            waiter
                .await
                .expect("orchestrator must acknowledge the observed block");
        }
    }

    impl Reporter for AckObserver {
        type Activity = marshal::Update<mocks::TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            let marshal::Update::Block(block, ack) = activity else {
                return self.orchestrator.report(activity);
            };
            if *self.observed.lock() != Some(block.height()) {
                return self.orchestrator.report(marshal::Update::Block(block, ack));
            }
            let (private, waiter) = Exact::handle();
            *self.held.lock() = Some(ack);
            *self.waiter.lock() = Some(waiter);
            self.orchestrator
                .report(marshal::Update::Block(block, private))
        }
    }

    impl Node {
        #[allow(clippy::too_many_arguments)]
        async fn start<M>(
            context: deterministic::Context,
            oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
            fixture: &mocks::SchemeFixture,
            index: usize,
            boundary: Option<mocks::TestBlock>,
            state_sync: TestPlan,
            gate_epoch: Epoch,
            manager: M,
            dealers: &[mocks::TestPublicKey],
            deaf: bool,
        ) -> Self
        where
            M: Manager<PublicKey = mocks::TestPublicKey, Directory = Unit>,
        {
            let public_key = fixture.participants[index].clone();
            let control = oracle.control(public_key.clone());
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(16));
            let partition_prefix = node_partition_prefix(index);

            let (backfill_sender, backfill_receiver) = control
                .register(BACKFILL_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register marshal backfill channel");
            let backfill_receiver = if deaf {
                FilteredReceiver::drop_all(backfill_receiver)
            } else {
                FilteredReceiver::pass(backfill_receiver)
            };
            let resolver = marshal_resolver::init(
                context.child("marshal_resolver"),
                marshal_resolver::Config {
                    public_key: public_key.clone(),
                    peer_provider: oracle.manager(),
                    blocker: control.clone(),
                    mailbox_size: NZUsize!(16),
                    fetch_timeout: NZDuration!(Duration::from_millis(200)),
                    fetch_retry_delay: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
                (backfill_sender, backfill_receiver),
            );

            let finalizations_by_height =
                prunable::Archive::init(context.child("finalizations_by_height"), {
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
            let finalized_blocks = prunable::Archive::init(
                context.child("finalized_blocks"),
                archive_config(&partition_prefix, "finalized_blocks", page_cache, ()),
            )
            .await
            .expect("failed to initialize finalized blocks archive");

            let genesis = make_genesis_block(
                public_key.clone(),
                dealers.iter().cloned(),
                fixture.participants.iter().cloned(),
            );
            let (marshal_actor, mut marshal, _) = marshal::core::Actor::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                    epocher: FixedEpocher::new(NZU64!(2)),
                    start: MarshalStart::Genesis(Digested::precomputed(
                        genesis.clone(),
                        genesis.digest(),
                    )),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(16),
                    view_retention: ViewDelta::new(8),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
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

            // Mark the epoch in the reshare actor's place, as the actor does
            // once the epoch's scheme is registered.
            let (fence, gate) = Fence::new();
            fence.mark(gate_epoch);

            let (actor, mailbox) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager,
                    provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                    marshal: marshal.clone(),
                    application: application.clone(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(),
                    gate,
                    state_sync,
                    blocks_per_epoch: NZU64!(2),
                    mailbox_size: NZUsize!(16),
                    partition_prefix,
                },
            );
            let orchestrator = mailbox.clone();
            let acks = AckObserver::new(mailbox);
            let lagging = LaggingReporter::default();
            let reporters = Reporters::from((
                Reporters::from((mocks::MarshalApplication::default(), acks.clone())),
                lagging.clone(),
            ));
            let marshal_handle = marshal_actor.start_unbuffered(reporters, resolver);

            if let Some(block) = &boundary {
                finalize(&mut marshal, block, &fixture.schemes).await;
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
                lagging,
                acks,
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

    fn node_partition_prefix(index: usize) -> String {
        format!("orchestrator-node-{index}")
    }

    /// Opens the plan stored under node `index`'s partition prefix, persisting
    /// `state_sync` if given.
    async fn node_plan(
        context: deterministic::Context,
        index: usize,
        state_sync: Option<TestStateSync>,
    ) -> TestPlan {
        StateSyncPlan::init(
            context,
            StateSyncConfig {
                partition_prefix: node_partition_prefix(index),
                max_participants: NZU32!(16),
                max_supported_mode: max_supported_mode(),
                block_codec_config: (),
            },
            state_sync,
        )
        .await
    }

    /// Returns a prunable finalized archive config whose sections hold one height each.
    ///
    /// Marshal's prune does nothing to an immutable archive. With one height per section,
    /// pruning marshal below a height removes every block beneath it.
    fn archive_config<C>(
        prefix: &str,
        name: &str,
        page_cache: CacheRef,
        codec_config: C,
    ) -> prunable::Config<TwoCap, C> {
        prunable::Config {
            translator: TwoCap,
            metadata_partition: format!("{prefix}-{name}-metadata"),
            key_partition: format!("{prefix}-{name}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{prefix}-{name}-value"),
            compression: None,
            codec_config,
            items_per_section: NZU64!(1),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    /// Certifies `block` in `marshal` and reports its finalization in the round of
    /// its context.
    async fn finalize(
        marshal: &mut mocks::TestMarshalMailbox,
        block: &mocks::TestBlock,
        schemes: &[mocks::TestScheme],
    ) {
        let context = block.context();
        assert!(
            marshal
                .certified(
                    context.round,
                    Digested::precomputed(block.clone(), block.digest())
                )
                .await
        );
        let finalization = make_finalization(
            Proposal::new(context.round, context.parent.0, block.digest()),
            schemes,
        );
        assert_eq!(
            marshal.report(Activity::Finalization(finalization)),
            Feedback::Ok
        );
    }

    async fn wait_for_block(
        context: &deterministic::Context,
        marshal: &mocks::TestMarshalMailbox,
        height: Height,
        timeout: Duration,
    ) -> Digested<mocks::TestBlock> {
        let deadline = context.current() + timeout;
        loop {
            if let Some(block) = marshal.get_block(height).await {
                return block;
            }
            assert!(
                context.current() < deadline,
                "finalized block at height {height} must arrive within {timeout:?}"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
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

    async fn wait_for_processed(
        context: &deterministic::Context,
        marshal: &mocks::TestMarshalMailbox,
        height: Height,
    ) {
        for _ in 0..100 {
            let processed = marshal.get_processed().await;
            if processed.map(|processed| processed.height()) == Some(height) {
                return;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("marshal must process height {height}");
    }

    /// Finalizes the first block of epoch one on `node`, waits until marshal has
    /// processed it, and prunes marshal below it until the boundary block at height
    /// one that introduced epoch one is gone. Returns the first block of epoch one.
    async fn prune_epoch_one_boundary(
        context: &deterministic::Context,
        node: &mut Node,
        boundary: &mocks::TestBlock,
        schemes: &[mocks::TestScheme],
    ) -> mocks::TestBlock {
        let first = make_child_block(
            boundary,
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            None,
        );
        finalize(&mut node.marshal, &first, schemes).await;
        wait_for_processed(context, &node.marshal, first.height()).await;

        node.marshal.prune(first.height());
        for _ in 0..100 {
            if node.marshal.get_block(boundary.height()).await.is_none() {
                return first;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("marshal must prune the boundary block");
    }

    /// Builds the block after `parent`, proposed in `round` on a parent notarized in
    /// `parent_view`, carrying `info` if given.
    fn make_child_block(
        parent: &mocks::TestBlock,
        round: Round,
        parent_view: View,
        info: Option<EpochInfo<mocks::TestBlsVariant, mocks::TestPublicKey>>,
    ) -> mocks::TestBlock {
        let context = mocks::TestContext {
            round,
            leader: parent.context().leader.clone(),
            parent: (parent_view, parent.digest()),
        };
        let height = parent.height().next();
        let block = mocks::TestBlock::new::<Sha256>(context, parent.digest(), height, height.get());
        match info {
            Some(info) => block
                .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestPublicKey>(
                    NZU32!(16),
                    Payload::EpochInfo(info),
                ),
            None => block,
        }
    }

    fn make_height_one_block(
        leader: mocks::TestPublicKey,
        dealers: &[mocks::TestPublicKey],
        players: &[mocks::TestPublicKey],
    ) -> mocks::TestBlock {
        let genesis = make_genesis_block(
            leader.clone(),
            dealers.iter().cloned(),
            players.iter().cloned(),
        );
        let context = mocks::TestContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (View::zero(), genesis.digest()),
        };
        let info = make_epoch_info(
            Epoch::new(1),
            dealers.iter().cloned(),
            players.iter().cloned(),
        );
        mocks::TestBlock::new::<Sha256>(context, genesis.digest(), Height::new(1), 1)
            .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestPublicKey>(
            NZU32!(16),
            Payload::EpochInfo(info),
        )
    }

    fn make_genesis_block(
        leader: mocks::TestPublicKey,
        dealers: impl IntoIterator<Item = mocks::TestPublicKey>,
        players: impl IntoIterator<Item = mocks::TestPublicKey>,
    ) -> mocks::TestBlock {
        let info = make_epoch_info(Epoch::zero(), dealers, players);
        mocks::genesis_block(leader)
            .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestPublicKey>(
                NZU32!(16),
                Payload::EpochInfo(info),
            )
    }

    /// Builds an epoch info whose threshold output is held by `dealers` and whose
    /// players and next players are `players`.
    fn make_epoch_info(
        epoch: Epoch,
        dealers: impl IntoIterator<Item = mocks::TestPublicKey>,
        players: impl IntoIterator<Item = mocks::TestPublicKey>,
    ) -> EpochInfo<mocks::TestBlsVariant, mocks::TestPublicKey> {
        let dealers = Set::from_iter_dedup(dealers);
        let players = Set::from_iter_dedup(players);
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            TestRng::new(epoch.get() + 1),
            Mode::NonZeroCounter,
            dealers,
        )
        .expect("failed to create test DKG output");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch,
            output,
            players: players.clone(),
            next_players: players,
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
            let node_context = context.child("node");
            let plan = node_plan(node_context.child("state_sync_plan"), 0, None).await;
            let mut node = Node::start(
                node_context,
                &oracle,
                &fixture,
                0,
                None,
                plan,
                Epoch::new(1),
                mocks::FailingManager(oracle.manager()),
                &fixture.participants,
                false,
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
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(16));
            let partition_prefix = "orchestrator-marshal-shutdown".to_string();

            let finalizations_by_height =
                prunable::Archive::init(context.child("finalizations_by_height"), {
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
            let finalized_blocks = prunable::Archive::init(
                context.child("finalized_blocks"),
                archive_config(&partition_prefix, "finalized_blocks", page_cache, ()),
            )
            .await
            .expect("failed to initialize finalized blocks archive");
            let genesis = make_genesis_block(
                public_key.clone(),
                participants.iter().cloned(),
                participants.iter().cloned(),
            );
            let (marshal_actor, marshal, _): (_, mocks::TestMarshalMailbox, _) =
                marshal::core::Actor::<_, _, _, _, _, _, _, Exact>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                        epocher: FixedEpocher::new(NZU64!(2)),
                        start: MarshalStart::Genesis(Digested::precomputed(
                            genesis.clone(),
                            genesis.digest(),
                        )),
                        partition_prefix: partition_prefix.clone(),
                        mailbox_size: NZUsize!(16),
                        view_retention: ViewDelta::new(8),
                        prunable_items_per_section: NZU64!(10),
                        page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
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

            let (_fence, gate) = Fence::new();
            let (actor, _mailbox): (_, super::Mailbox<mocks::TestBlock, Exact>) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager: oracle.manager(),
                    provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                    marshal: marshal.clone(),
                    application: mocks::MockApplication::default(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(),
                    gate,
                    state_sync: StateSyncPlan::disabled(),
                    blocks_per_epoch: NZU64!(2),
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

            let boundary =
                Digested::precomputed(cluster.boundary.clone(), cluster.boundary.digest());
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
            let skipped = mocks::child(&cluster.boundary);
            let skipped = Digested::precomputed(skipped.clone(), skipped.digest());
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
            let info = make_epoch_info(
                Epoch::new(1),
                fixture.participants.iter().cloned(),
                fixture.participants.iter().cloned(),
            );
            let genesis = make_genesis_block(
                fixture.participants[0].clone(),
                fixture.participants.iter().cloned(),
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
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(16));
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
                    fetch_timeout: NZDuration!(Duration::from_millis(200)),
                    fetch_retry_delay: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
                backfill,
            );
            let finalizations_by_height =
                prunable::Archive::init(context.child("finalizations_by_height"), {
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
            let finalized_blocks = prunable::Archive::init(
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
                    start: MarshalStart::Genesis(Digested::precomputed(
                        genesis.clone(),
                        genesis.digest(),
                    )),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(16),
                    view_retention: ViewDelta::new(8),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
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
                    block_codec_config: (),
                },
                Some(StateSync {
                    info: info.clone(),
                    floor,
                }),
            )
            .await;

            let manager = mocks::DirectoryManager::new(oracle.manager());
            let (fence, gate) = Fence::new();
            fence.mark(synced_epoch);
            let (actor, mailbox): (_, super::Mailbox<AddressedBlock, Exact>) = Actor::new(
                context.child("orchestrator"),
                Config {
                    oracle: control.clone(),
                    manager: manager.clone(),
                    provider: mocks::TestProvider::new(fixture.schemes[0].clone()),
                    marshal: marshal.clone(),
                    application: mocks::MockApplication::default(),
                    strategy: Sequential,
                    simplex: mocks::simplex_config(),
                    gate,
                    state_sync,
                    blocks_per_epoch: NZU64!(2),
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
            let caught_up = wait_for_block(
                &context,
                &cluster.nodes[0].marshal,
                Height::new(1),
                Duration::from_millis(500),
            )
            .await;

            assert_eq!(caught_up.digest(), cluster.boundary.digest());
        });
    }

    /// A lagging node obtains the boundary finalization from a secondary peer
    /// when the other dealers do not serve fetches. The secondary peer is a
    /// player that is not a dealer.
    #[test]
    fn boundary_fetch_reaches_secondary_peer() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let layout = Layout {
                dealers: Some(3),
                deaf: HashSet::from([1, 2]),
            };
            let cluster = Cluster::start_with_layout(&mut context, &fixture, layout).await;
            let caught_up = wait_for_block(
                &context,
                &cluster.nodes[0].marshal,
                Height::new(1),
                Duration::from_secs(10),
            )
            .await;

            assert_eq!(caught_up.digest(), cluster.boundary.digest());
        });
    }

    #[test]
    fn finalized_boundary_enters_next_epoch() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let cluster = Cluster::start(&mut context, 4).await;
            let stored = wait_for_block(
                &context,
                &cluster.nodes[0].marshal,
                Height::new(1),
                Duration::from_millis(500),
            )
            .await;

            let proposal = wait_for_proposal(&context, &cluster.nodes, Epoch::new(1)).await;

            assert_eq!(stored.digest(), cluster.boundary.digest());
            assert_eq!(proposal.round.epoch(), Epoch::new(1));
            assert_eq!(proposal.parent.1, cluster.boundary.digest());
        });
    }

    /// At a live boundary the orchestrator checkpoints the boundary block with the
    /// finalization marshal holds for it, so the probe can serve the epoch. The genesis
    /// checkpoint recorded at startup has no finalization.
    #[test]
    fn live_boundary_checkpoint_carries_finalization() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            wait_for_proposal(&context, &cluster.nodes[0..1], Epoch::new(1)).await;
            cluster.nodes[0].stop().await;

            let plan = node_plan(context.child("state_sync_plan"), 0, None).await;
            let boundary = &cluster.boundary;
            let checkpoint = plan
                .checkpoint(Epoch::new(1))
                .await
                .expect("checkpoint 1 must be recorded at the boundary");
            let round = boundary.context().round;
            let parent_view = boundary.context().parent.0;
            let finalization = make_finalization(
                Proposal::new(round, parent_view, boundary.digest()),
                &fixture.schemes,
            );
            assert_eq!(checkpoint.finalization(), Some(&finalization));
            assert_eq!(checkpoint.commitment(), boundary.digest());
            assert_eq!(checkpoint.block().inner(), boundary);
            assert_eq!(checkpoint.info().epoch, Epoch::new(1));

            let genesis = make_genesis_block(
                fixture.participants[0].clone(),
                fixture.participants.iter().cloned(),
                fixture.participants.iter().cloned(),
            );
            let checkpoint = plan
                .checkpoint(Epoch::zero())
                .await
                .expect("checkpoint 0 must be recorded at startup");
            assert!(checkpoint.finalization().is_none());
            assert_eq!(checkpoint.commitment(), genesis.digest());
            assert_eq!(checkpoint.info().epoch, Epoch::zero());
        });
    }

    #[test]
    fn recovered_node_starts_from_processed_epoch() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let stored = wait_for_block(
                &context,
                &cluster.nodes[0].marshal,
                Height::new(1),
                Duration::from_millis(500),
            )
            .await;
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

    /// A restart whose plan has no checkpoint for the recovered epoch, such as a plan in a
    /// new partition, starts the epoch from its boundary block in marshal and checkpoints
    /// that block with marshal's finalization.
    #[test]
    fn restart_from_boundary_block_records_checkpoint() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let boundary = cluster.boundary.clone();
            wait_for_processed(&context, &cluster.nodes[0].marshal, boundary.height()).await;
            cluster.nodes[0].stop().await;

            let restart = context
                .child("node")
                .with_attribute("index", 0)
                .with_attribute("restart", 1);
            let plan = TestPlan::init(
                restart.child("state_sync_plan"),
                StateSyncConfig {
                    partition_prefix: "orchestrator-node-0-unrecorded".into(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                    block_codec_config: (),
                },
                None,
            )
            .await;
            assert!(plan.checkpoint(Epoch::new(1)).await.is_none());
            cluster
                .recover(restart, &fixture, 0, plan.clone(), Epoch::new(1))
                .await;
            wait_for_proposal(&context, &cluster.nodes[0..1], Epoch::new(1)).await;

            let checkpoint = plan
                .checkpoint(Epoch::new(1))
                .await
                .expect("restart must checkpoint the boundary block it starts from");
            let round = boundary.context().round;
            let parent_view = boundary.context().parent.0;
            let finalization = make_finalization(
                Proposal::new(round, parent_view, boundary.digest()),
                &fixture.schemes,
            );
            assert_eq!(checkpoint.commitment(), boundary.digest());
            assert_eq!(checkpoint.finalization(), Some(&finalization));
            assert_eq!(checkpoint.info().epoch, Epoch::new(1));
        });
    }

    /// A node restarts after marshal pruned the boundary block that introduced its
    /// epoch, so only the checkpoint recorded at that boundary can supply the epoch.
    #[test]
    fn restart_after_boundary_pruned_starts_from_checkpoint() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let boundary = cluster.boundary.clone();
            prune_epoch_one_boundary(&context, &mut cluster.nodes[0], &boundary, &fixture.schemes)
                .await;

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

    /// A crash after the orchestrator records the next epoch's checkpoint but before it
    /// acknowledges the final block leaves marshal's processed height in the earlier epoch.
    /// The test stages that state while the node is stopped, recording epoch two's
    /// checkpoint with epoch one's final block unprocessed and its boundary block pruned.
    /// Restart must start epoch one from its checkpoint and enter epoch two once marshal
    /// delivers the final block.
    #[test]
    fn restart_before_final_block_acknowledged_starts_from_previous_checkpoint() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let boundary = cluster.boundary.clone();
            let first = prune_epoch_one_boundary(
                &context,
                &mut cluster.nodes[0],
                &boundary,
                &fixture.schemes,
            )
            .await;
            let info = make_epoch_info(
                Epoch::new(2),
                fixture.participants.iter().cloned(),
                fixture.participants.iter().cloned(),
            );
            let last = make_child_block(
                &first,
                Round::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Some(info.clone()),
            );

            cluster.nodes[0].stop().await;
            let restart = context
                .child("node")
                .with_attribute("index", 0)
                .with_attribute("restart", 1);
            let plan = node_plan(restart.child("state_sync_plan"), 0, None).await;
            plan.record(
                restart.child("crash_cut"),
                Epoch::new(2),
                Checkpoint::new(Digested::precomputed(last.clone(), last.digest()), None),
                Epoch::new(1),
            )
            .await;
            cluster
                .recover(restart, &fixture, 0, plan, Epoch::new(2))
                .await;
            let proposal = wait_for_proposal(&context, &cluster.nodes[0..1], Epoch::new(1)).await;
            assert_eq!(proposal.round.epoch(), Epoch::new(1));

            let node = &mut cluster.nodes[0];
            finalize(&mut node.marshal, &last, &fixture.schemes).await;

            // The orchestrator acknowledges the final block only after entering epoch two.
            wait_for_processed(&context, &node.marshal, last.height()).await;
        });
    }

    /// A disabled plan neither records nor reads checkpoints, so a node restarted
    /// with one after marshal pruned the boundary block that introduced its epoch
    /// has no source for the epoch and stops cleanly.
    #[test]
    fn disabled_plan_restart_after_boundary_pruned_stops_cleanly() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster = Cluster::start_with_fixture(&mut context, &fixture, true).await;
            let boundary = cluster.boundary.clone();
            prune_epoch_one_boundary(&context, &mut cluster.nodes[0], &boundary, &fixture.schemes)
                .await;

            cluster.nodes[0].stop().await;
            cluster
                .recover(
                    context
                        .child("node")
                        .with_attribute("index", 0)
                        .with_attribute("restart", 1),
                    &fixture,
                    0,
                    StateSyncPlan::disabled(),
                    Epoch::new(1),
                )
                .await;
            let node = &mut cluster.nodes[0];
            select! {
                result = &mut node.orchestrator_handle => {
                    result.expect("orchestrator must stop cleanly");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("orchestrator must exit without a source for its epoch");
                },
            };
            assert!(node.application.proposals().is_empty());
        });
    }

    /// The next epoch's checkpoint must be durable before the orchestrator acknowledges the
    /// final block that carries it, since that acknowledgement lets marshal's processed
    /// height pass the block and pruning remove it. Stopping the node as soon as the
    /// orchestrator acknowledges epoch one's final block must leave epoch two's checkpoint
    /// stored.
    #[test]
    fn checkpoint_is_durable_before_final_block_acknowledged() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster =
                Cluster::start_with_gate_epoch(&mut context, &fixture, true, Epoch::new(2)).await;
            let boundary = cluster.boundary.clone();
            let first = prune_epoch_one_boundary(
                &context,
                &mut cluster.nodes[0],
                &boundary,
                &fixture.schemes,
            )
            .await;
            let participants = || fixture.participants.iter().cloned();
            let last_one = make_child_block(
                &first,
                Round::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Some(make_epoch_info(
                    Epoch::new(2),
                    participants(),
                    participants(),
                )),
            );

            // Stop the node as soon as the orchestrator acknowledges epoch one's final block.
            let node = &mut cluster.nodes[0];
            node.acks.observe(last_one.height());
            finalize(&mut node.marshal, &last_one, &fixture.schemes).await;
            node.acks.acknowledged(&context).await;
            node.stop().await;

            let plan = node_plan(context.child("state_sync_plan"), 0, None).await;
            assert!(
                plan.checkpoint(Epoch::new(2)).await.is_some(),
                "checkpoint 2 must be durable once the final block of epoch 1 is acknowledged"
            );
        });
    }

    /// Marshal delivers up to its pending acknowledgement window ahead of its processed
    /// height, so while another reporter withholds one acknowledgement the orchestrator
    /// can cross two boundaries and record two newer checkpoints. A restart still recovers
    /// epoch one from marshal's processed height, so checkpoint one must survive them.
    #[test]
    fn checkpoint_retention_follows_processed_height() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut cluster =
                Cluster::start_with_gate_epoch(&mut context, &fixture, true, Epoch::new(3)).await;
            let boundary = cluster.boundary.clone();
            let first = prune_epoch_one_boundary(
                &context,
                &mut cluster.nodes[0],
                &boundary,
                &fixture.schemes,
            )
            .await;

            // Withhold the lagging reporter's acknowledgement of epoch one's final block, then
            // finalize through epoch two's final block so the orchestrator enters epoch three
            // while marshal's processed height stays at 2.
            let participants = || fixture.participants.iter().cloned();
            let last_one = make_child_block(
                &first,
                Round::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Some(make_epoch_info(
                    Epoch::new(2),
                    participants(),
                    participants(),
                )),
            );
            let first_two = make_child_block(
                &last_one,
                Round::new(Epoch::new(2), View::new(1)),
                View::zero(),
                None,
            );
            let last_two = make_child_block(
                &first_two,
                Round::new(Epoch::new(2), View::new(2)),
                View::new(1),
                Some(make_epoch_info(
                    Epoch::new(3),
                    participants(),
                    participants(),
                )),
            );
            let node = &mut cluster.nodes[0];
            node.lagging.hold(last_one.height());
            for block in [&last_one, &first_two, &last_two] {
                finalize(&mut node.marshal, block, &fixture.schemes).await;
            }
            wait_for_proposal(&context, &cluster.nodes[0..1], Epoch::new(3)).await;
            let node = &mut cluster.nodes[0];
            assert_eq!(
                node.marshal
                    .get_processed()
                    .await
                    .map(|processed| processed.height()),
                Some(first.height())
            );
            assert!(node.marshal.get_block(boundary.height()).await.is_none());

            // The stopped node holds a checkpoint for every epoch from the recovered epoch one
            // through epoch three.
            node.stop().await;
            let restart = context
                .child("node")
                .with_attribute("index", 0)
                .with_attribute("restart", 1);
            let plan = node_plan(restart.child("state_sync_plan"), 0, None).await;
            for epoch in 1..=3 {
                assert!(
                    plan.checkpoint(Epoch::new(epoch)).await.is_some(),
                    "checkpoint {epoch} must survive"
                );
            }

            // Marshal redelivers heights 3 through 5 together, so the restarted orchestrator
            // may leave epoch one before Simplex proposes in it. Any proposal shows that it
            // started, since without checkpoint one it would exit before entering an epoch.
            cluster
                .recover(restart, &fixture, 0, plan, Epoch::new(3))
                .await;
            let node = &cluster.nodes[0];
            for _ in 0..50 {
                if !node.application.proposals().is_empty() {
                    return;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            panic!("restarted orchestrator must produce a proposal");
        });
    }
}
