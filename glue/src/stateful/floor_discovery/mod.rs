//! Gather a recent finalization to sync from.
//!
//! A node that is starting fresh (or recovering from far behind) needs a recent, trustworthy
//! finalization, the "floor", as the point to begin state sync from. It cannot trust any
//! single peer to name that point, so the [`FloorDiscovery`] asks many peers and adopts the
//! highest valid finalization from `f + 1` distinct peer replies.
//!
//! # Protocol
//!
//! ## Solicit
//!
//! Once a floor subscriber appears, [`FloorDiscovery`] broadcasts a `RequestLatest` to every
//! connected peer:
//!
//! ```text
//!                    +-- RequestLatest --> peer 1
//!                    |
//!   FloorDiscovery --+-- RequestLatest --> peer 2
//!                    |
//!                    +-- RequestLatest --> peer 3
//!                    |
//!                    +-- RequestLatest --> peer 4
//! ```
//!
//! A subscription is the request to discover a floor. If all floor subscribers are dropped before
//! a floor is selected, discovery is cancelled. Attaching marshal after that makes the node a
//! source: it transitions to responder mode without a cached floor. Callers that need a floor must
//! keep a subscription alive until it resolves and attach marshal only after consuming that floor.
//!
//! ## Collect and select
//!
//! Each peer answers with its own latest finalization (or nothing, if it has none). Every
//! response is verified against the certificate scheme for its epoch. At most one finalization is
//! counted per peer, so no single peer can inflate the sample on its own. Once `f + 1`
//! distinct peers have replied, the highest finalized round becomes the floor:
//!
//! ```text
//!   peer 1 --Finalization(view 10)-->\                 replies
//!   peer 2 --Finalization(view 12)--> +-> FloorDiscovery {10, 12, 13}
//!   peer 3 --Finalization(view 13)-->/                        |
//!                                                             v
//!                                      sample reached, highest view becomes the floor: 13
//! ```
//!
//! A peer that sends an undecodable or unverifiable finalization is blocked. A peer that sends a
//! second valid finalization in a round is ignored, never overwriting its first answer.
//!
//! ## Retry
//!
//! If too few peers reply, the collected responses are cleared and the request is re-issued after
//! a configurable `retry_timeout`. Retry is not required for safety. It is a liveness mechanism
//! for request rounds that fail to collect enough usable replies because messages were dropped,
//! peers were slow or offline, or a finalization's epoch could not yet be judged.
//!
//! ```text
//!   request --> collect --> sample reached? --yes--> highest floor
//!      ^                         |
//!      |                         no
//!      +----- clear + re-request +
//!            (retry_timeout elapsed)
//! ```
//!
//! # Why the sample is `f + 1`
//!
//! Assume at most `f` of the `n` participants are faulty. In this protocol, `f` makes no
//! distinction between Byzantine and crashed nodes: a peer that does not answer and a peer that
//! answers adversarially both count against the same fault budget.
//!
//! A finalization is self-certifying: it carries a quorum certificate, so any one that verifies
//! proves the network truly finalized that block. Accepting a single peer's finalization is
//! therefore always *safe* (it names a real block), but it is not necessarily *recent*.
//!
//! That recency gap is the attack. A Byzantine peer can replay an old (but still valid)
//! finalization to drag a joining node's floor far behind the real tip of the chain, forcing it
//! to re-sync a huge range or to settle on a stale view.
//!
//! Under simplex's synchrony assumptions, `2f + 1` honest nodes are expected to be in the same view.
//! Waiting for `f + 1` replies guarantees at least one honest response in the sample: at most `f`
//! responders can be Byzantine, and crashed nodes do not respond. The selected finalization is
//! therefore at least as recent as that honest response. Byzantine peers can still replay old
//! certificates, but old certificates lose to newer honest replies. If they report something higher,
//! it must still be a valid finalization, so it is a real finalized block rather than a rollback.
//!
//! ```text
//!   any f + 1 sample:
//!
//!     [ B   B  ...  B ]  [ H ]       at most f Byzantine
//!      \____ <= f ____/    \_ at least one honest response
//!
//!     choose max(valid finalizations)
//!       => floor is no older than the freshest honest reply in the sample
//! ```
//!
//! # Resource Bounds
//!
//! The actor retains at most one finalization candidate per peer per request round. Additional
//! valid finalizations from the same peer are verified and then ignored, preserving correctness
//! when network delivery lags across request rounds without allowing one peer to inflate a sample.
//! The p2p channel supplies rate limiting and maximum encoded message size enforcement.

mod actor;
pub use actor::{Config, FloorDiscovery};

mod mailbox;
pub use mailbox::Mailbox;

mod wire;

#[cfg(test)]
mod test {
    use super::{wire, Config, FloorDiscovery, Mailbox};
    use bytes::{Buf, BufMut};
    use commonware_actor::Feedback;
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        marshal::{
            self,
            core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
            resolver::p2p as marshal_resolver,
            standard::Standard,
            Start, Update,
        },
        simplex::{
            mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
            types::{Activity, Context as SimplexContext, Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
        Block as ConsensusBlock, CertifiableBlock, Heightable, Reporter,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Provider},
        ed25519,
        sha256::Digest as Sha256Digest,
        Digest as _, Digestible, Signer as _,
    };
    use commonware_macros::test_collect_traces;
    use commonware_p2p::{
        simulated::{Config as SimConfig, Link, Network, Oracle, Sender},
        Recipients, Sender as _,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, telemetry::traces::collector::TraceStorage, Clock,
        Handle, Metrics, Quota, Runner as _, Supervisor,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        channel::oneshot, sync::Mutex, test_rng, Acknowledgement, NZDuration, NZUsize,
        NonZeroDuration, NZU16, NZU64,
    };
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroU64},
        sync::Arc,
        time::Duration,
    };

    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_BOOTSTRAP_TEST";
    const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const BOOTSTRAP_CHANNEL: u64 = 0;
    const BACKFILL_CHANNEL: u64 = 1;

    type Scheme = MockScheme<ed25519::PublicKey>;
    type Variant = Standard<Block>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Block {
        context: SimplexContext<Sha256Digest, ed25519::PublicKey>,
        height: Height,
        digest: Sha256Digest,
    }

    impl Block {
        fn new(height: u64, digest_byte: u8) -> Self {
            Self {
                context: SimplexContext {
                    round: Round::new(Epoch::zero(), View::new(height)),
                    leader: ed25519::PrivateKey::from_seed(0).public_key(),
                    parent: (View::zero(), Sha256Digest::EMPTY),
                },
                height: Height::new(height),
                digest: Sha256Digest::from([digest_byte; 32]),
            }
        }
    }

    impl Write for Block {
        fn write(&self, buf: &mut impl BufMut) {
            self.context.write(buf);
            buf.put_u64(self.height.get());
            buf.put_slice(self.digest.as_ref());
        }
    }

    impl EncodeSize for Block {
        fn encode_size(&self) -> usize {
            self.context.encode_size() + 8 + 32
        }
    }

    impl Read for Block {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            let context = SimplexContext::read(buf)?;
            let height = Height::new(buf.get_u64());
            let mut digest = [0u8; 32];
            buf.copy_to_slice(&mut digest);
            Ok(Self {
                context,
                height,
                digest: Sha256Digest::from(digest),
            })
        }
    }

    impl Digestible for Block {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl Heightable for Block {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl ConsensusBlock for Block {
        fn parent(&self) -> Self::Digest {
            Sha256Digest::EMPTY
        }
    }

    impl CertifiableBlock for Block {
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    #[derive(Clone)]
    struct NoopReporter;

    impl Reporter for NoopReporter {
        type Activity = Update<Block>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
            Feedback::Ok
        }
    }

    /// A certificate-scheme provider keyed by epoch, with no global verifier (`all` is `None`),
    /// so verification always falls through to the epoch-scoped lookup.
    #[derive(Clone, Default)]
    struct EpochProvider(Arc<Mutex<BTreeMap<Epoch, Arc<Scheme>>>>);

    impl EpochProvider {
        fn insert(&self, epoch: Epoch, scheme: Scheme) {
            self.0.lock().insert(epoch, Arc::new(scheme));
        }

        fn forget(&self, epoch: Epoch) {
            self.0.lock().remove(&epoch);
        }
    }

    impl Provider for EpochProvider {
        type Scope = Epoch;
        type Scheme = Scheme;

        fn scoped(&self, scope: Epoch) -> Option<Arc<Scheme>> {
            self.0.lock().get(&scope).cloned()
        }
    }

    /// A single node in the harness: its floor-discovery ingress and its marshal mailbox.
    struct Node {
        bootstrap: Option<Mailbox<Scheme, Variant>>,
        marshal: MarshalMailbox<Scheme, Variant>,
        // A clone of the node's floor-discovery channel sender, used by tests to inject raw
        // bytes that appear to originate from this node.
        bootstrap_sender: Sender<ed25519::PublicKey, deterministic::Context>,
        // The floor-discovery actor, started on demand via `start_bootstrappers` once peers have
        // been seeded with finalizations. `None` once started.
        start: Option<Box<dyn FnOnce() -> Handle<()>>>,
        // Held to keep the spawned actors alive for the duration of the test.
        _handles: Vec<Handle<()>>,
    }

    impl Node {
        fn bootstrap(&self) -> &Mailbox<Scheme, Variant> {
            self.bootstrap.as_ref().expect("bootstrap mailbox present")
        }

        fn take_bootstrap(&mut self) -> Mailbox<Scheme, Variant> {
            self.bootstrap.take().expect("bootstrap mailbox present")
        }
    }

    /// A reusable harness of several real (unbuffered) marshal actors, each paired with a
    /// [`FloorDiscovery`], wired over an all-to-all simulated p2p network.
    struct Harness {
        participants: Vec<ed25519::PublicKey>,
        schemes: Vec<Scheme>,
        nodes: Vec<Node>,
        oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
        // Held to keep the network alive.
        _network: Handle<()>,
    }

    impl Harness {
        /// Spin up `n` nodes over a simulated network. Each node runs a real marshal actor
        /// (seeded with only a genesis block) and a [`FloorDiscovery`] using `retry_timeout`,
        /// configured with a [`ConstantProvider`] (single scheme, all epochs).
        async fn setup(
            context: &deterministic::Context,
            n: u32,
            retry_timeout: NonZeroDuration,
        ) -> Self {
            Self::setup_with(context, n, retry_timeout, |scheme| {
                ConstantProvider::new(scheme.clone())
            })
            .await
        }

        /// Like [`Harness::setup`], but `make_provider` builds each node's [`FloorDiscovery`]
        /// certificate provider from that node's scheme. Lets tests supply an epoch-keyed
        /// provider to exercise multi-epoch verification.
        async fn setup_with<D, F>(
            context: &deterministic::Context,
            n: u32,
            retry_timeout: NonZeroDuration,
            make_provider: F,
        ) -> Self
        where
            D: Provider<Scope = Epoch, Scheme = Scheme>,
            F: Fn(&Scheme) -> D,
        {
            let mut rng = test_rng();
            let Fixture {
                participants,
                schemes,
                ..
            } = scheme_mocks::fixture(&mut rng, NAMESPACE, n);

            // Simulated network with all participants tracked in a single peer set.
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                SimConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            let network = network.start();

            // All-to-all links so every node can reach every other node.
            for a in &participants {
                for b in &participants {
                    if a != b {
                        oracle
                            .add_link(a.clone(), b.clone(), LINK)
                            .await
                            .expect("failed to add link");
                    }
                }
            }

            let genesis = Block::new(0, 0);
            let mut nodes = Vec::with_capacity(n as usize);
            for (index, public_key) in participants.iter().enumerate() {
                let scheme = schemes[index].clone();
                let node_ctx = context.child("node").with_attribute("index", index);
                let partition_prefix = format!("node-{index}");
                let page_cache = CacheRef::from_pooler(&node_ctx, NZU16!(1024), NZUsize!(10));
                let control = oracle.control(public_key.clone());

                // Marshal backfill resolver.
                let backfill = control
                    .register(BACKFILL_CHANNEL, TEST_QUOTA)
                    .await
                    .expect("failed to register backfill channel");
                let resolver = marshal_resolver::init(
                    node_ctx.child("marshal_resolver"),
                    marshal_resolver::Config {
                        public_key: public_key.clone(),
                        peer_provider: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        mailbox_size: NZUsize!(100),
                        initial: Duration::from_secs(1),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(100),
                        priority_requests: false,
                        priority_responses: false,
                    },
                    backfill,
                );

                // Marshal storage archives.
                let finalizations_by_height = immutable::Archive::init(
                    node_ctx.child("finalizations_by_height"),
                    archive_config(&partition_prefix, "finalizations", page_cache.clone()),
                )
                .await
                .expect("failed to init finalizations archive");
                let finalized_blocks = immutable::Archive::init(
                    node_ctx.child("finalized_blocks"),
                    archive_config(&partition_prefix, "blocks", page_cache.clone()),
                )
                .await
                .expect("failed to init blocks archive");

                // Marshal actor (unbuffered: blocks arrive via `proposed`/resolver, not a buffer).
                let marshal_config = marshal::Config {
                    provider: ConstantProvider::new(scheme.clone()),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: Start::Genesis(genesis.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(100),
                    view_retention_timeout: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache,
                    replay_buffer: NZUsize!(2048),
                    key_write_buffer: NZUsize!(2048),
                    value_write_buffer: NZUsize!(2048),
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                };
                let (marshal_actor, marshal_mailbox, _) =
                    MarshalActor::<_, Variant, _, _, _, _, _>::init(
                        node_ctx.child("marshal"),
                        finalizations_by_height,
                        finalized_blocks,
                        marshal_config,
                    )
                    .await;
                let marshal_handle = marshal_actor.start_unbuffered(NoopReporter, resolver);

                // FloorDiscovery.
                let bootstrap_network = control
                    .register(BOOTSTRAP_CHANNEL, TEST_QUOTA)
                    .await
                    .expect("failed to register bootstrap channel");
                let bootstrap_sender = bootstrap_network.0.clone();
                let (bootstrapper, bootstrap_mailbox) = FloorDiscovery::new(Config {
                    context: node_ctx.child("bootstrapper"),
                    provider: make_provider(&scheme),
                    strategy: Sequential,
                    capacity: NZUsize!(100),
                    blocker: oracle.control(public_key.clone()),
                    retry_timeout,
                });
                // Node 0 is the discoverer and is left in discovery for the test to drive. Every
                // other node is a source: attach its marshal so it transitions to responder mode
                // without soliciting peers.
                if index != 0 {
                    bootstrap_mailbox.attach(marshal_mailbox.clone());
                }
                // Defer the actor's start so tests can seed peer marshals before node 0 issues
                // its first request.
                let start: Box<dyn FnOnce() -> Handle<()>> =
                    Box::new(move || bootstrapper.start(bootstrap_network));

                nodes.push(Node {
                    bootstrap: Some(bootstrap_mailbox),
                    marshal: marshal_mailbox,
                    bootstrap_sender,
                    start: Some(start),
                    _handles: vec![marshal_handle],
                });
            }

            Self {
                participants,
                schemes,
                nodes,
                oracle,
                _network: network,
            }
        }

        /// Starts every node's floor-discovery actor. Call after seeding peer marshals so each
        /// actor's first request observes the intended finalizations.
        fn start_bootstrappers(&mut self) {
            for node in &mut self.nodes {
                if let Some(start) = node.start.take() {
                    node._handles.push(start());
                }
            }
        }

        /// Builds a verifiable finalization at `height` committing to a block whose digest is
        /// `[digest_byte; 32]`, signed by this harness's scheme set. The returned block must be
        /// injected alongside it so the marshal can serve the finalization.
        fn finalization(
            &self,
            height: u64,
            digest_byte: u8,
        ) -> (Block, Finalization<Scheme, Sha256Digest>) {
            build_finalization(&self.schemes, height, digest_byte)
        }

        /// Injects a finalized block into node `index`'s marshal: caches the block, then reports
        /// the finalization so the marshal stores and serves it via `get_info`/`get_finalization`.
        async fn inject(
            &self,
            index: usize,
            block: Block,
            finalization: Finalization<Scheme, Sha256Digest>,
        ) {
            let mut marshal = self.nodes[index].marshal.clone();
            let round = finalization.proposal.round;
            assert!(marshal.proposed(round, block).await);
            let _ = marshal.report(Activity::Finalization(finalization));
        }

        /// Sends raw `bytes` on the floor-discovery channel from node `from` to node `to`,
        /// bypassing the wire encoding. Used to deliver malformed messages to a [`FloorDiscovery`].
        fn send_raw(&self, from: usize, to: usize, bytes: Vec<u8>) {
            let mut sender = self.nodes[from].bootstrap_sender.clone();
            sender.send(Recipients::One(self.participants[to].clone()), bytes, false);
        }
    }

    /// Builds an epoch-0 finalization. See [`build_finalization_at`].
    fn build_finalization(
        schemes: &[Scheme],
        height: u64,
        digest_byte: u8,
    ) -> (Block, Finalization<Scheme, Sha256Digest>) {
        build_finalization_at(schemes, Epoch::zero(), height, digest_byte)
    }

    /// Builds a finalization in `epoch` at `height` over a block whose digest is
    /// `[digest_byte; 32]`, signed by `schemes`. Verifiable only against the matching verifier;
    /// signing with a foreign scheme set yields a structurally valid but unverifiable
    /// finalization.
    fn build_finalization_at(
        schemes: &[Scheme],
        epoch: Epoch,
        height: u64,
        digest_byte: u8,
    ) -> (Block, Finalization<Scheme, Sha256Digest>) {
        let block = Block::new(height, digest_byte);
        let round = Round::new(epoch, View::new(height));
        let proposal = Proposal {
            round,
            parent: View::new(height.saturating_sub(1)),
            payload: block.digest(),
        };
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect();
        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).expect("recover");
        (block, finalization)
    }

    /// Builds an [`EpochProvider`] seeded from `entries`, where each entry's scheme set comes
    /// from its own fixture so the scopes verify independently.
    fn epoch_provider(entries: impl IntoIterator<Item = (Epoch, Scheme)>) -> EpochProvider {
        let provider = EpochProvider::default();
        for (epoch, scheme) in entries {
            provider.insert(epoch, scheme);
        }
        provider
    }

    /// Encodes a finalization as the bytes of a [`wire::Message::Finalization`].
    fn finalization_bytes(finalization: Finalization<Scheme, Sha256Digest>) -> Vec<u8> {
        wire::Message::<Scheme, Variant>::Finalization(finalization)
            .encode()
            .to_vec()
    }

    fn finalization_prefix(epoch: Epoch, height: u64, digest_byte: u8) -> Vec<u8> {
        let block = Block::new(height, digest_byte);
        let proposal = Proposal {
            round: Round::new(epoch, View::new(height)),
            parent: View::new(height.saturating_sub(1)),
            payload: block.digest(),
        };
        let mut bytes = vec![1u8];
        proposal.write(&mut bytes);
        bytes
    }

    /// Storage configuration for one of marshal's immutable archives.
    fn archive_config(prefix: &str, name: &str, page_cache: CacheRef) -> immutable::Config<()> {
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
            codec_config: (),
            replay_buffer: NZUsize!(2048),
            freezer_key_write_buffer: NZUsize!(2048),
            freezer_value_write_buffer: NZUsize!(2048),
            ordinal_write_buffer: NZUsize!(2048),
        }
    }

    /// A sample of peers answering with the same finalization lets a subscribing node resolve it
    /// as the floor.
    #[test]
    fn test_resolves_floor_from_sample_peers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            assert_eq!(harness.participants.len(), 4);

            // Seed a sample (f + 1 = 2) of peers with the same finalization, then start the
            // bootstrappers so node 0's first request already observes agreement.
            let (block, finalization) = harness.finalization(1, 1);
            for index in [1, 2] {
                harness
                    .inject(index, block.clone(), finalization.clone())
                    .await;
            }
            harness.start_bootstrappers();

            // The remaining node should resolve the agreed finalization as its floor.
            let floor = harness.nodes[0]
                .bootstrap()
                .subscribe()
                .await
                .expect("floor resolved");
            assert_eq!(floor, finalization);
        });
    }

    /// A sample of distinct valid replies resolves to the highest finalization, even without
    /// exact agreement.
    #[test]
    fn test_resolves_highest_floor_from_sample_replies() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 7, NZDuration!(Duration::from_secs(3600))).await;
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            let mut expected = None;
            for index in 1..=3u8 {
                let (_, finalization) = harness.finalization(index.into(), index);
                if index == 3 {
                    expected = Some(finalization.clone());
                }
                harness.send_raw(index as usize, 0, finalization_bytes(finalization));
            }
            let expected = expected.expect("highest finalization present");

            context.sleep(Duration::from_millis(100)).await;
            let floor = subscription
                .try_recv()
                .expect("floor should resolve once enough replies arrive");
            assert_eq!(floor, expected);
        });
    }

    /// When too few peers reply, the node waits out its retry deadline before re-requesting.
    #[test_collect_traces]
    fn test_retries_until_enough_replies(traces: TraceStorage) {
        let retry_timeout = NZDuration!(Duration::from_millis(500));
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(move |context| async move {
            let mut harness = Harness::setup(&context, 4, retry_timeout).await;
            harness.start_bootstrappers();
            let start = context.current();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Node 0's first request gathers one reply, which is below the sample size (f + 1 = 2).
            let (_, finalization_f) = harness.finalization(1, 0xF);
            let (_, finalization_g) = harness.finalization(2, 0x6);
            harness.send_raw(1, 0, finalization_bytes(finalization_f.clone()));

            // Let node 0 finish its first request round. With too few finalizations available,
            // the subscription must remain pending.
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "floor resolved before enough replies arrived"
            );

            // After the retry deadline, send a full sample. The actor should select the
            // highest valid reply.
            context.sleep(retry_timeout.get()).await;
            harness.send_raw(1, 0, finalization_bytes(finalization_f));
            harness.send_raw(2, 0, finalization_bytes(finalization_g.clone()));

            // The floor resolves to G, and only after the retry deadline has elapsed.
            context.sleep(Duration::from_millis(100)).await;
            let floor = subscription.try_recv().expect("floor resolved");
            assert_eq!(floor, finalization_g);
            let elapsed = context.current().duration_since(start).unwrap();
            assert!(
                elapsed >= retry_timeout.get(),
                "floor resolved before a retry could occur ({elapsed:?})"
            );
        });

        // The retry was driven by the deadline.
        let events = traces.get_all();
        events
            .expect_event(|event| {
                event.metadata.content == "re-requesting finalizations"
                    && event
                        .metadata
                        .expect_field_exact("reason", "deadline elapsed")
                        .is_ok()
            })
            .expect("a deadline-driven retry should have occurred");
    }

    /// Agreement below the sample size is not enough to resolve a floor.
    #[test]
    fn test_waits_for_sample_size_even_with_matching_replies() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 7, NZDuration!(Duration::from_secs(3600))).await;
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Seven participants => f + 1 = 3. Two matching replies are still not enough.
            let (_, finalization) = harness.finalization(1, 1);
            for index in 1..=2 {
                harness.send_raw(index, 0, finalization_bytes(finalization.clone()));
            }

            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "matching replies below the sample size must not resolve the floor"
            );
        });
    }

    /// Starting without a floor subscriber does not solicit peers. This lets a source node start
    /// the actor before attaching marshal without sending a useless initial request.
    #[test]
    fn test_does_not_request_without_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            harness.start_bootstrappers();

            context.sleep(Duration::from_millis(100)).await;

            let metrics = context.encode();
            assert!(
                !metrics.contains("network_messages_sent_total"),
                "unexpected network messages before subscription: {metrics}"
            );
        });
    }

    /// A peer that sends a finalization-tagged payload that cannot be decoded is blocked.
    #[test]
    fn test_blocks_peer_sending_malformed_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            harness.start_bootstrappers();

            let mut junk = vec![1u8];
            junk.extend_from_slice(&[0xAB; 32]);
            harness.send_raw(1, 0, junk);

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "node 0 should have blocked node 1"
            );
        });
    }

    /// A peer that sends a correctly encoded but unverifiable finalization (signed by a
    /// foreign key set) is blocked.
    #[test]
    fn test_blocks_peer_sending_invalid_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            harness.start_bootstrappers();

            // A finalization signed by a foreign key set: it decodes cleanly under node 0's
            // codec config but fails verification against node 0's scheme.
            let mut rng = test_rng();
            let Fixture {
                schemes: foreign, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_BOOTSTRAP_FOREIGN", 4);
            let (_, finalization) = build_finalization(&foreign, 1, 1);
            harness.send_raw(1, 0, finalization_bytes(finalization));

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "node 0 should have blocked node 1"
            );
        });
    }

    #[test]
    fn test_blocks_peer_sending_invalid_message() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            harness.start_bootstrappers();

            // An unrecognized wire tag is rejected by the decoder.
            harness.send_raw(1, 0, vec![0xFF]);

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "node 0 should have blocked node 1"
            );
        });
    }

    /// Responder mode only needs request tags. A finalization-tagged payload is ignored without
    /// attempting to decode the certificate bytes.
    #[test]
    fn test_responder_ignores_finalization_payloads() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            harness.start_bootstrappers();
            context.sleep(Duration::from_millis(100)).await;

            let mut junk = vec![1u8];
            junk.extend_from_slice(&[0xAB; 32]);
            harness.send_raw(0, 1, junk);

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[1].clone(),
                    harness.participants[0].clone(),
                )),
                "responder node should ignore finalization payloads without decoding them"
            );
        });
    }

    /// A subscriber that arrives after the floor is already resolved receives it immediately.
    #[test]
    fn test_late_subscriber_receives_resolved_floor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            let (block, finalization) = harness.finalization(1, 1);
            for index in [1, 2, 3] {
                harness
                    .inject(index, block.clone(), finalization.clone())
                    .await;
            }
            harness.start_bootstrappers();

            // Resolve the floor via a first subscriber.
            let floor = harness.nodes[0]
                .bootstrap()
                .subscribe()
                .await
                .expect("floor resolved");
            assert_eq!(floor, finalization);

            // A subscriber arriving afterwards is served the cached floor immediately.
            let late = harness.nodes[0]
                .bootstrap()
                .subscribe()
                .await
                .expect("late subscriber served");
            assert_eq!(late, finalization);
        });
    }

    /// Responder mode drains mailbox messages that were already queued before the last mailbox handle
    /// was dropped.
    #[test]
    fn test_responder_drains_queued_subscribe_after_mailbox_drop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            let (block, finalization) = harness.finalization(1, 1);
            for index in [1, 2, 3] {
                harness
                    .inject(index, block.clone(), finalization.clone())
                    .await;
            }
            harness.start_bootstrappers();

            let floor = harness.nodes[0]
                .bootstrap()
                .subscribe()
                .await
                .expect("floor resolved");
            assert_eq!(floor, finalization);

            let marshal = harness.nodes[0].marshal.clone();
            harness.nodes[0].bootstrap().attach(marshal);
            let mailbox = harness.nodes[0].take_bootstrap();
            let mut late = mailbox.subscribe();
            drop(mailbox);

            context.sleep(Duration::from_millis(100)).await;
            let served = late
                .try_recv()
                .expect("queued subscription should be drained");
            assert_eq!(served, finalization);
        });
    }

    /// Once a floor is set, further finalizations are ignored without verification: a peer
    /// that sends an otherwise-blockable (invalid) finalization is not blocked.
    #[test]
    fn test_ignores_finalizations_after_floor_set() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_millis(500))).await;
            let (block, finalization) = harness.finalization(1, 1);
            for index in [1, 2, 3] {
                harness
                    .inject(index, block.clone(), finalization.clone())
                    .await;
            }
            harness.start_bootstrappers();

            let floor = harness.nodes[0]
                .bootstrap()
                .subscribe()
                .await
                .expect("floor resolved");
            assert_eq!(floor, finalization);

            // Node 3 sends an invalid (foreign) finalization. Were the floor unset, this would
            // fail verification and block node 3; with the floor set it is ignored entirely.
            let mut rng = test_rng();
            let Fixture {
                schemes: foreign, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_BOOTSTRAP_FOREIGN", 4);
            let (_, invalid) = build_finalization(&foreign, 2, 9);
            harness.send_raw(3, 0, finalization_bytes(invalid));

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[3].clone(),
                )),
                "finalizations after the floor is set must be ignored, not verified"
            );
        });
    }

    /// A second valid finalization from a peer already counted this round is ignored (not
    /// blocked, since it verifies) and does not let a single peer inflate the sample.
    #[test]
    fn test_duplicate_finalization_from_peer_is_ignored() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 7, NZDuration!(Duration::from_secs(3600))).await;
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Deliver two different valid finalizations from node 1, then the second from node 2.
            // If node 1's second answer were counted, the second finalization would incorrectly
            // reach the sample size.
            let (_, first) = harness.finalization(1, 1);
            let (_, second) = harness.finalization(2, 2);
            harness.send_raw(1, 0, finalization_bytes(first));
            harness.send_raw(1, 0, finalization_bytes(second.clone()));
            harness.send_raw(2, 0, finalization_bytes(second));

            context.sleep(Duration::from_millis(100)).await;

            // The duplicate is ignored (not blocked), and one peer cannot inflate the sample.
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "a duplicate finalization must be ignored, not treated as a fault"
            );
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "a duplicate finalization must not satisfy the sample size"
            );
        });
    }

    /// Duplicates are still verified: a peer that follows a valid finalization with an invalid
    /// one is blocked, even though the duplicate would otherwise be ignored.
    #[test]
    fn test_invalid_duplicate_finalization_blocks_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut harness =
                Harness::setup(&context, 4, NZDuration!(Duration::from_secs(3600))).await;
            harness.start_bootstrappers();

            // Node 1 first sends a valid finalization, then an invalid (foreign) one.
            let (_, valid) = harness.finalization(1, 1);
            harness.send_raw(1, 0, finalization_bytes(valid));

            let mut rng = test_rng();
            let Fixture {
                schemes: foreign, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_BOOTSTRAP_FOREIGN", 4);
            let (_, invalid) = build_finalization(&foreign, 1, 2);
            harness.send_raw(1, 0, finalization_bytes(invalid));

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "an invalid finalization must be blocked even when it duplicates a peer"
            );
        });
    }

    /// A peer sample resolves to its highest finalization, not to the most common stale one.
    #[test]
    fn test_sample_selects_highest_over_stale_agreement() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            // Seven participants => f + 1 = 3.
            let mut harness =
                Harness::setup(&context, 7, NZDuration!(Duration::from_secs(3600))).await;
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Two peers agree on a stale finalization, but the sample also includes a newer
            // valid finalization. The highest reply should win.
            let (_, stale) = harness.finalization(1, 0x0F);
            let (_, newest) = harness.finalization(2, 0xA2);
            harness.send_raw(1, 0, finalization_bytes(stale.clone()));
            harness.send_raw(2, 0, finalization_bytes(stale.clone()));
            harness.send_raw(3, 0, finalization_bytes(newest.clone()));

            context.sleep(Duration::from_millis(100)).await;
            let floor = subscription.try_recv().expect("floor resolved");
            assert_eq!(floor, newest);
        });
    }

    /// Finalizations are verified against the scheme for their own epoch: a non-zero-epoch
    /// finalization, signed by that epoch's committee and reported by enough peers, resolves
    /// the floor (exercises the epoch-scoped scheme lookup and per-epoch sample size).
    #[test]
    fn test_resolves_floor_at_non_zero_epoch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            // A committee for epoch 1 (f + 1 = 2), distinct from the harness's epoch-0 set.
            let mut rng = test_rng();
            let Fixture {
                schemes: epoch_one, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_FD_EPOCH_ONE", 4);
            let provider = epoch_provider([(Epoch::new(1), epoch_one[0].clone())]);

            let mut harness =
                Harness::setup_with(&context, 4, NZDuration!(Duration::from_secs(3600)), {
                    let provider = provider.clone();
                    move |_scheme| provider.clone()
                })
                .await;
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Two peers report the same epoch-1 finalization, signed by the epoch-1 committee.
            let (_, finalization) = build_finalization_at(&epoch_one, Epoch::new(1), 1, 7);
            harness.send_raw(1, 0, finalization_bytes(finalization.clone()));
            harness.send_raw(2, 0, finalization_bytes(finalization.clone()));

            context.sleep(Duration::from_millis(100)).await;
            let floor = subscription.try_recv().expect("floor resolved");
            assert_eq!(floor, finalization);
        });
    }

    /// A finalization for an epoch the provider has no scheme for cannot be judged, so it is
    /// dropped without blocking the sender (and never reaches the floor).
    #[test]
    fn test_ignores_unknown_epoch_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            // The provider knows only epoch 1.
            let mut rng = test_rng();
            let Fixture {
                schemes: epoch_one, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_FD_EPOCH_ONE", 4);
            let provider = epoch_provider([(Epoch::new(1), epoch_one[0].clone())]);

            let mut harness =
                Harness::setup_with(&context, 4, NZDuration!(Duration::from_secs(3600)), {
                    let provider = provider.clone();
                    move |_scheme| provider.clone()
                })
                .await;
            harness.start_bootstrappers();

            // A finalization for the unknown epoch 5: dropped before verification, so the sender
            // is not blocked.
            let (_, unknown) = build_finalization_at(&epoch_one, Epoch::new(5), 1, 1);
            harness.send_raw(1, 0, finalization_bytes(unknown));

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "an unknown-epoch finalization must be ignored, not blocked"
            );
            let mut subscription = harness.nodes[0].bootstrap().subscribe();
            context.sleep(Duration::from_millis(50)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "an unknown-epoch finalization must not resolve the floor"
            );
        });
    }

    /// If the proposal names an epoch with no scheme, discovery ignores the payload before
    /// decoding certificate bytes.
    #[test]
    fn test_unknown_epoch_does_not_decode_certificate() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let mut rng = test_rng();
            let Fixture {
                schemes: epoch_one, ..
            } = scheme_mocks::fixture(&mut rng, b"_COMMONWARE_GLUE_FD_EPOCH_ONE", 4);
            let provider = epoch_provider([(Epoch::new(1), epoch_one[0].clone())]);

            let mut harness =
                Harness::setup_with(&context, 4, NZDuration!(Duration::from_secs(3600)), {
                    let provider = provider.clone();
                    move |_scheme| provider.clone()
                })
                .await;
            harness.start_bootstrappers();

            let mut unknown = finalization_prefix(Epoch::new(5), 1, 1);
            unknown.extend_from_slice(&[0xFF; 16]);
            harness.send_raw(1, 0, unknown);

            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[0].clone(),
                    harness.participants[1].clone(),
                )),
                "unknown-epoch certificate bytes must not be decoded or blocked"
            );
        });
    }

    /// A finalization buffered while its epoch was known stays harmless if that epoch is later
    /// forgotten: subsequent selection passes treat it as unjudgeable (still reachable) rather
    /// than counting it, and the sender is not retroactively blocked.
    #[test]
    fn test_forgotten_epoch_finalization_is_not_counted() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let provider = EpochProvider::default();

            let mut harness =
                Harness::setup_with(&context, 4, NZDuration!(Duration::from_secs(3600)), {
                    let provider = provider.clone();
                    move |_scheme| provider.clone()
                })
                .await;
            provider.insert(Epoch::new(1), harness.schemes[0].clone());
            provider.insert(Epoch::new(2), harness.schemes[0].clone());
            harness.start_bootstrappers();
            let mut subscription = harness.nodes[0].bootstrap().subscribe();

            // Peer 1 reports an epoch-1 finalization; it verifies and is buffered below the
            // sample size.
            let (_, epoch_one_finalization) =
                build_finalization_at(&harness.schemes, Epoch::new(1), 1, 1);
            harness.send_raw(1, 0, finalization_bytes(epoch_one_finalization));
            context.sleep(Duration::from_millis(50)).await;

            // Forget epoch 1, so the buffered finalization's scheme is now unavailable.
            provider.forget(Epoch::new(1));

            // One peer reports an epoch-2 finalization; ingesting it re-runs selection over
            // the buffer, where the stale epoch-1 entry can no longer be judged or counted.
            let (_, epoch_two_finalization) =
                build_finalization_at(&harness.schemes, Epoch::new(2), 1, 2);
            harness.send_raw(2, 0, finalization_bytes(epoch_two_finalization));
            context.sleep(Duration::from_millis(50)).await;

            // No floor (one currently judgeable vote, below the sample size) and nothing is
            // blocked.
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "a single judgeable vote must not resolve the floor"
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "no peer should be blocked");
        });
    }
}
