//! The application actor: builds, stages, and verifies blocks.

use super::{
    Config, Marshal, Production, ProductionStats,
    block::{Block, Body},
    mailbox::{Mailbox, Message},
};
use crate::bench::{Batch, Finality, FinalityGoal, ProposalLatency, Workload};
use commonware_actor::mailbox::{self, Receiver};
use commonware_consensus::{
    Heightable as _,
    multimmit::{
        WAN_LATENCY,
        marshal::{Custody, Error as MarshalError},
        types::{BlockRef, ChainId, Context, TransactionBlockHeader},
    },
    types::Height,
};
use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Histogram, HistogramExt as _, MetricsExt as _},
};
use commonware_utils::{channel::oneshot, futures::Pool};
use std::{collections::BTreeMap, future::Future, sync::Arc, time::SystemTime};
use tracing::{debug, warn};

/// Own blocks whose construction start is kept for their signature and ordering latencies.
const TRACKED_PRODUCTIONS: usize = 4_096;

/// Synthetic input one proposal carries.
#[derive(Clone, Copy)]
enum Input {
    /// No workload paces production, so every block carries a full body.
    Saturated,
    /// The block carries this submitted input batch.
    Batch(Batch),
    /// No input has arrived since the previous block, so the block is empty. It still takes a
    /// height.
    Empty,
}

/// A finished background step whose result updates the actor.
enum Completion {
    /// A proposal's block was built and must now be staged.
    Built {
        block: Arc<Block>,
        construction_at: SystemTime,
        input: Input,
        response: oneshot::Sender<Sha256Digest>,
    },
    /// Marshal answered a staging request for a proposal's block.
    Staged {
        block: Arc<Block>,
        custody: Result<Custody, MarshalError>,
        input: Input,
        response: oneshot::Sender<Sha256Digest>,
    },
    /// The block arrived durably and matches the verified header.
    Verified { response: oneshot::Sender<bool> },
    /// The step answered consensus itself, failed, or consensus stopped waiting.
    Done,
}

/// Runs `future` until it completes or the requester drops `response`.
async fn or_canceled<R, T>(
    response: &mut oneshot::Sender<R>,
    future: impl Future<Output = T>,
) -> Option<T> {
    select! {
        _ = response.closed() => None,
        output = future => Some(output),
    }
}

/// Waits for marshal to hold the block `header` names durably, then checks it against `header`.
///
/// A peer's block waits until marshal receives and stores it; this node's own block waits until
/// its staging is on disk. The wait is recorded in `body_wait`, when given.
async fn verify_stored(
    clock: impl Clock,
    marshal: Marshal,
    header: TransactionBlockHeader<Sha256Digest>,
    body_wait: Option<Histogram>,
    mut response: oneshot::Sender<bool>,
) -> Completion {
    let requested_at = clock.current();
    let reference = header.block_ref::<Sha256>();
    let Some(result) = or_canceled(&mut response, marshal.subscribe_block(reference)).await else {
        return Completion::Done;
    };
    match result {
        Ok(block) => {
            if let Some(body_wait) = body_wait {
                body_wait.observe_between(requested_at, clock.current());
            }
            verdict(&header, block, response)
        }
        Err(error) => {
            warn!(
                chain = header.chain().get(),
                height = header.height().get(),
                %error,
                "block subscription closed"
            );
            Completion::Done
        }
    }
}

/// Answers a verification once marshal returned `block` for `header`.
///
/// Marshal returns the block with the exact reference `header` names, so a mismatch means the
/// block does not match what consensus signed.
fn verdict(
    header: &TransactionBlockHeader<Sha256Digest>,
    block: Arc<Block>,
    response: oneshot::Sender<bool>,
) -> Completion {
    if block.header() != header {
        let _ = response.send(false);
        return Completion::Done;
    }
    Completion::Verified { response }
}

/// Returns the whole milliseconds from `start` to `end`, or zero when `end` is earlier.
fn millis_between(start: SystemTime, end: SystemTime) -> u64 {
    u64::try_from(end.duration_since(start).unwrap_or_default().as_millis()).unwrap_or(u64::MAX)
}

/// Builds, stages, and verifies blocks for consensus.
///
/// Waits (staging, block subscriptions, and each proposal's build task) run as futures in a pool
/// the actor polls, so every state change happens in its loop.
pub struct Actor<E: Clock + Spawner + Metrics> {
    context: ContextCell<E>,
    mailbox: Receiver<Message>,
    seed: u64,
    production: Production,
    workload: Option<Workload>,
    latency: ProposalLatency,
    producer_chain: Option<ChainId>,
    body_wait: Histogram,
    input_queue: Histogram,
    signing: Histogram,
    /// Own blocks by height, with their digest and construction start, until ordered.
    productions: BTreeMap<Height, (Sha256Digest, SystemTime)>,
    stats: ProductionStats,
    goal: FinalityGoal,
    pending: Pool<'static, Completion>,
}

impl<E: Clock + Spawner + Metrics> Actor<E> {
    /// Creates the actor and the mailbox consensus and marshal use to reach it.
    pub fn new(context: E, config: Config) -> (Self, Mailbox<E>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let clock = Arc::new(context.child("clock"));
        let production = config.production;
        let workload = match &production.schedule {
            Some(schedule) => Some(Workload::from_schedule(
                &context,
                schedule.clone(),
                production.body_size,
            )),
            None => production
                .offered_bytes_per_second
                .map(|rate| Workload::new(&context, rate, production.body_size)),
        }
        .transpose()
        .expect("offered load requires nonempty block bodies");
        let latency = ProposalLatency::new(&context, config.tracked_blocks, config.benchmark);
        let body_wait = context.histogram(
            "verify_body_wait",
            "time a verification waits for complete-body resolution and durable custody",
            WAN_LATENCY,
        );
        let input_queue = context.histogram(
            "input_queue_latency",
            "time from scheduled batch submission to the start of block construction",
            WAN_LATENCY,
        );
        let signing = context.histogram(
            "block_signing_latency",
            "time from the start of a local block's construction to its header signature",
            WAN_LATENCY,
        );
        (
            Self {
                context: ContextCell::new(context),
                mailbox: receiver,
                seed: config.seed,
                production,
                workload,
                latency,
                producer_chain: config.producer_chain,
                body_wait,
                input_queue,
                signing,
                productions: BTreeMap::new(),
                stats: config.stats,
                goal: config.goal,
                pending: Pool::default(),
            },
            Mailbox::new(sender, clock, config.producer_chain),
        )
    }

    /// Starts the actor, which stages and fetches blocks through `marshal`.
    pub fn start(mut self, marshal: Marshal) -> Handle<()> {
        spawn_cell!(self.context, self.run(marshal))
    }

    async fn run(mut self, marshal: Marshal) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("application stopped");
            },
            // Finish outstanding requests before accepting new ones.
            completion = self.pending.next_completed() => {
                self.complete(&marshal, completion);
            },
            Some(message) = self.mailbox.recv() else break => {
                self.handle(&marshal, message);
            },
        }
    }

    fn handle(&mut self, marshal: &Marshal, message: Message) {
        match message {
            Message::Propose { context, response } => self.propose(context, response),
            Message::Verify {
                context,
                body,
                response,
            } => self.verify(marshal, context, body, response),
            Message::Finalized { view, blocks, at } => {
                let finalized = self.latency.finalize(
                    Finality {
                        blocks: &blocks,
                        view,
                    },
                    at,
                );
                for first in finalized {
                    if let Some(views) = first.views {
                        self.stats.finalized(views);
                    }
                    if let Some(signed_at) = first.signed_at {
                        self.stats
                            .signed_finalized(millis_between(signed_at, at), first.within_goal);
                    }
                }
            }
            Message::Ordered { block, at } => {
                if let Some(signed_at) = self.latency.order(block, at) {
                    self.stats.signed_ordered(millis_between(signed_at, at));
                }
                if let Some(started) = self.production_start(block) {
                    self.stats.ordered(millis_between(started, at));
                }
                self.productions = self.productions.split_off(&block.height().next());
            }
            Message::Signed { block, view, at } => {
                self.latency.sign(block, view, at, self.goal.get());
                if let Some(started) = self.production_start(block) {
                    self.signing.observe_between(started, at);
                    self.stats.signed(millis_between(started, at));
                }
            }
        }
    }

    /// Returns when the construction of this node's block `block` started, if it is tracked.
    fn production_start(&self, block: BlockRef<Sha256Digest>) -> Option<SystemTime> {
        self.productions
            .get(&block.height())
            .filter(|(digest, _)| *digest == block.digest())
            .map(|(_, started)| *started)
    }

    /// Returns the synthetic input the block at `height` carries.
    fn input(&mut self, height: u64, now: SystemTime) -> Input {
        let Some(workload) = &mut self.workload else {
            return Input::Saturated;
        };
        workload
            .request(height, now)
            .map_or(Input::Empty, Input::Batch)
    }

    fn propose(&mut self, context: Context<Sha256Digest>, response: oneshot::Sender<Sha256Digest>) {
        // Consensus asks for the next block at its slot, one production interval after the
        // previous one. The block carries whatever input has arrived, possibly none.
        let now = self.context.current();
        let input = self.input(context.height().get(), now);
        let body_size = match input {
            Input::Saturated | Input::Batch(_) => self.production.body_size,
            Input::Empty => 0,
        };
        // Building a large body is CPU work, so it runs on the shared pool and the actor wakes
        // once, when the block is ready to stage. A canceled request skips the build.
        let seed = self.seed;
        let built = self
            .context
            .child("propose")
            .shared(true)
            .spawn(move |runtime| async move {
                if response.is_closed() {
                    return Completion::Done;
                }
                let construction_at = runtime.current();
                let block = Arc::new(Block::from_context(
                    context,
                    Body::junk(seed, context, body_size),
                ));
                Completion::Built {
                    block,
                    construction_at,
                    input,
                    response,
                }
            });
        self.pending
            .push(async move { built.await.unwrap_or(Completion::Done) });
    }

    fn verify(
        &mut self,
        marshal: &Marshal,
        context: Context<Sha256Digest>,
        body: Sha256Digest,
        response: oneshot::Sender<bool>,
    ) {
        // Only peers' blocks wait on resolution, so this node's own blocks are not recorded.
        let body_wait =
            (Some(context.chain()) != self.producer_chain).then(|| self.body_wait.clone());
        self.pending.push(verify_stored(
            self.context.child("verify"),
            marshal.clone(),
            context.header(body),
            body_wait,
            response,
        ));
    }

    fn complete(&mut self, marshal: &Marshal, completion: Completion) {
        match completion {
            Completion::Built {
                block,
                construction_at,
                input,
                mut response,
            } => {
                let input_ready_at = match input {
                    Input::Batch(batch) => Some(batch.ready_at),
                    Input::Saturated | Input::Empty => None,
                };
                if let Some(input_ready_at) = input_ready_at {
                    self.input_queue
                        .observe_between(input_ready_at, construction_at);
                }
                // Every own block, empty or not, is tracked to its signature and ordering.
                let reference = block.reference();
                self.productions
                    .insert(reference.height(), (reference.digest(), construction_at));
                if self.productions.len() > TRACKED_PRODUCTIONS {
                    self.productions.pop_first();
                }
                // An empty block carries no input whose latency could be measured, but finality
                // above it reaches older batches through its parent.
                if matches!(input, Input::Empty) {
                    self.latency.link(reference, block.header().parent());
                } else {
                    self.latency.start(
                        reference,
                        block.header().parent(),
                        input_ready_at.unwrap_or(construction_at),
                        input_ready_at,
                        construction_at,
                    );
                }
                let marshal = marshal.clone();
                self.pending.push(async move {
                    let Some(custody) =
                        or_canceled(&mut response, marshal.stage_block(Arc::clone(&block))).await
                    else {
                        return Completion::Done;
                    };
                    Completion::Staged {
                        block,
                        custody,
                        input,
                        response,
                    }
                });
            }
            Completion::Staged {
                block,
                custody,
                input,
                response,
            } => {
                let reference = block.reference();
                if let Err(error) = custody {
                    warn!(?reference, %error, "cannot stage proposed block");
                    return;
                }
                let body_digest = block.header().body_digest();
                debug!(
                    chain = reference.chain().get(),
                    height = reference.height().get(),
                    ?body_digest,
                    block_digest = ?reference.digest(),
                    body_size = self.production.body_size,
                    empty = matches!(input, Input::Empty),
                    "produced body"
                );
                if response.send(body_digest).is_ok()
                    && let (Input::Batch(batch), Some(workload)) = (input, &self.workload)
                {
                    workload.admit(batch);
                }
            }
            Completion::Verified { response } => {
                let _ = response.send(true);
            }
            Completion::Done => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::{OutputReporter, Relay},
        bench::Schedule,
    };
    use commonware_actor::Feedback;
    use commonware_broadcast::buffered;
    use commonware_consensus::{
        Automaton as _, Epochable as _, Relay as _, Reporter as _,
        multimmit::{
            marshal::{self, ArchiveConfig, LqcVerifier, OutputIndex, Start, Update},
            mocks::{
                Committee,
                cluster::{QUOTA, link_all, start_network},
            },
            types::{Activity, BlockRef, ChainSet, Lqc, Resolution, Window},
        },
        types::{Epoch, Height, Participant, View},
    };
    use commonware_cryptography::{Hasher as _, bls12381::primitives::variant::MinPk, ed25519};
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p as resolver;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::translator::EightCap;
    use commonware_utils::{Acknowledgement as _, NZU16, NZU64, NZUsize, acknowledgement::Exact};
    use std::{convert::Infallible, num::NonZeroUsize, time::Duration};

    /// Body bytes in every test block.
    const BODY_SIZE: usize = 32;

    /// Resolver mailbox capacity, which also bounds backfill concurrency.
    const RESOLVER_MAILBOX_SIZE: NonZeroUsize = NZUsize!(64);

    /// Participants in the test committee; participant 0 runs the actor and produces chain 0.
    const PARTICIPANTS: u32 = 6;

    /// Accepts every L-QC; these tests never finalize.
    #[derive(Clone)]
    struct AcceptAll;

    impl LqcVerifier<Sha256, MinPk> for AcceptAll {
        type Error = Infallible;

        fn verify(
            &mut self,
            _: &Lqc<MinPk, Sha256Digest>,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            std::future::ready(Ok(()))
        }
    }

    /// How long a test waits before concluding a message will never arrive.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// One node's application actor attached to a real marshal over a simulated network, plus a
    /// peer's buffered broadcast engine that observes what the node's relay disseminates.
    struct Harness {
        committee: Committee<MinPk>,
        marshal: Marshal,
        relay: Relay,
        mailbox: Mailbox<deterministic::Context>,
        peer: buffered::Mailbox<ed25519::PublicKey, Block>,
        stats: ProductionStats,
        goal: FinalityGoal,
    }

    impl Harness {
        async fn new(context: &deterministic::Context, production: Production) -> Self {
            let committee = Committee::<MinPk>::builder(7, PARTICIPANTS)
                .namespace(b"_COMMONWARE_LOG_MULTIMMIT_ACTOR_TEST")
                .producers(vec![Participant::new(0), Participant::new(1)])
                .window(Window::new(8).unwrap())
                .build();
            let identity = committee.identities[0].clone();
            let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;
            link_all(&oracle, &committee.identities).await;
            let peer_identity = committee.identities[1].clone();
            let peer_control = oracle.control(peer_identity.clone());
            let peer_network = peer_control.register(0, QUOTA).await.unwrap();
            let (peer_engine, peer) = buffered::Engine::new(
                context.child("peer_broadcast"),
                buffered::Config {
                    public_key: peer_identity,
                    mailbox_size: NZUsize!(64),
                    ingress_size: NZUsize!(64),
                    deque_size: 16,
                    priority: false,
                    codec_config: Body::codec_config(BODY_SIZE),
                    peer_provider: oracle.manager(),
                    blocker: peer_control,
                    strategy: Sequential,
                },
            );
            peer_engine.start(peer_network);
            let control = oracle.control(identity.clone());
            let broadcast_network = control.register(0, QUOTA).await.unwrap();
            let resolver_network = control.register(1, QUOTA).await.unwrap();
            let (broadcast_engine, buffer) = buffered::Engine::new(
                context.child("broadcast"),
                buffered::Config {
                    public_key: identity.clone(),
                    mailbox_size: NZUsize!(64),
                    ingress_size: NZUsize!(64),
                    deque_size: 16,
                    priority: false,
                    codec_config: Body::codec_config(BODY_SIZE),
                    peer_provider: oracle.manager(),
                    blocker: control.clone(),
                    strategy: Sequential,
                },
            );
            broadcast_engine.start(broadcast_network);
            let config = marshal::Config::new(
                Start::Genesis(committee.config.genesis().clone()),
                "log_multimmit_actor_test".into(),
                committee.codec(),
                Body::codec_config(BODY_SIZE),
                ArchiveConfig::new(
                    EightCap,
                    CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
                ),
            )
            .with_catalog_mailbox_size(NZUsize!(64))
            .with_admission_cut_capacity(NZUsize!(64))
            .with_pending_segment_items(NZU64!(64))
            .with_resolver_mailbox_size(RESOLVER_MAILBOX_SIZE)
            // Backfill must not exceed the resolver mailbox.
            .with_backfill_concurrency(RESOLVER_MAILBOX_SIZE);
            let (mut service, bridge) =
                marshal::open::<_, EightCap, Sha256, MinPk, Body, ed25519::PublicKey>(
                    context.child("marshal"),
                    config,
                    buffer.clone(),
                )
                .await
                .unwrap();
            let (resolver_engine, resolver) = resolver::Engine::new(
                context.child("resolver"),
                resolver::Config {
                    peer_provider: oracle.manager(),
                    blocker: control,
                    consumer: bridge.clone(),
                    producer: bridge,
                    mailbox_size: NZUsize!(64),
                    me: Some(identity),
                    timeout: Duration::from_millis(100),
                    fetch_retry_timeout: Duration::from_millis(20),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            resolver_engine.start(resolver_network);
            let producer_chain = committee.config.producer_chain(Participant::new(0));
            let relay = service.relay(producer_chain);
            let stats = ProductionStats::default();
            let goal = FinalityGoal::new(Duration::from_millis(10));
            let (application, mailbox) = Actor::new(
                context.child("application"),
                Config {
                    seed: 3,
                    production,
                    tracked_blocks: NZUsize!(16),
                    producer_chain,
                    benchmark: false,
                    mailbox_size: NZUsize!(64),
                    stats: stats.clone(),
                    goal: goal.clone(),
                },
            );
            let (marshal, _) = service.start(
                resolver,
                AcceptAll,
                OutputReporter::new(mailbox.clone(), None),
            );
            application.start(marshal.clone());
            Self {
                committee,
                marshal,
                relay,
                mailbox,
                peer,
                stats,
                goal,
            }
        }

        /// Proposes a block for `context` and returns the staged block's reference.
        async fn propose_in(&mut self, context: Context<Sha256Digest>) -> BlockRef<Sha256Digest> {
            let body = self
                .mailbox
                .propose(context)
                .await
                .await
                .expect("proposal answers");
            reference(context, body)
        }

        /// Proposes height one of this node's chain and returns the staged block's reference.
        async fn propose(&mut self) -> BlockRef<Sha256Digest> {
            let context = self.context(0);
            self.propose_in(context).await
        }

        /// Returns whether the peer receives the block with `digest` within [`PATIENCE`].
        async fn peer_receives(
            &self,
            context: &deterministic::Context,
            digest: Sha256Digest,
        ) -> bool {
            let received = self.peer.subscribe(digest);
            select! {
                block = received => block.is_ok(),
                _ = context.sleep(PATIENCE) => false,
            }
        }

        /// Returns the consensus context for height one of `chain`.
        fn context(&self, chain: u32) -> Context<Sha256Digest> {
            Context::new(
                self.committee.config.epoch(),
                ChainId::new(chain),
                Height::new(1),
                self.committee.config.genesis().tips()[chain as usize].digest(),
            )
            .unwrap()
        }
    }

    const fn saturated() -> Production {
        Production {
            body_size: BODY_SIZE,
            offered_bytes_per_second: None,
            schedule: None,
        }
    }

    fn reference(context: Context<Sha256Digest>, body: Sha256Digest) -> BlockRef<Sha256Digest> {
        TransactionBlockHeader::new(
            context.epoch(),
            context.chain(),
            context.height(),
            context.parent(),
            body,
        )
        .unwrap()
        .block_ref::<Sha256>()
    }

    fn metric(context: &deterministic::Context, name: &str) -> u64 {
        context
            .encode()
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or_else(|| panic!("missing metric {name}"))
    }

    #[test]
    fn proposals_are_staged_and_verified_after_custody() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let block_context = harness.context(0);
            let body = harness
                .mailbox
                .propose(block_context)
                .await
                .await
                .expect("proposal answers");
            let reference = reference(block_context, body);
            let block = harness
                .marshal
                .get_block(reference)
                .await
                .unwrap()
                .expect("proposal is staged with marshal");
            assert_eq!(block.header().body_digest(), body);
            assert_eq!(metric(&context, "application_proposal_started_total"), 1);

            // Every verification subscribes to marshal's durable copy; waits on this node's own
            // blocks are not recorded.
            for _ in 0..2 {
                let verdict = harness.mailbox.verify(block_context, body).await.await;
                assert_eq!(verdict, Ok(true));
            }
            assert_eq!(metric(&context, "application_verify_body_wait_count"), 0);
            let received = harness.peer.subscribe(reference.digest());
            assert_eq!(
                harness.relay.broadcast(reference.digest(), ()),
                Feedback::Ok
            );
            assert_eq!(received.await.unwrap().inner().reference(), reference);
        });
    }

    #[test]
    fn remote_blocks_verify_once_marshal_stores_them() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let block_context = harness.context(1);
            let block = Arc::new(Block::from_context(
                block_context,
                Body::junk(11, block_context, BODY_SIZE),
            ));
            let body = block.header().body_digest();
            let mut verdict = harness.mailbox.verify(block_context, body).await;
            select! {
                _ = &mut verdict => panic!("verification must wait for the block"),
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            harness.marshal.put_block(Arc::clone(&block)).await.unwrap();
            assert_eq!(verdict.await, Ok(true));
            assert_eq!(metric(&context, "application_verify_body_wait_count"), 1);
        });
    }

    #[test]
    fn canceled_proposals_do_not_build() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let block_context = harness.context(0);
            drop(harness.mailbox.propose(block_context).await);
            context.sleep(Duration::from_secs(1)).await;
            assert_eq!(metric(&context, "application_proposal_started_total"), 0);
            assert!(harness.mailbox.propose(block_context).await.await.is_ok());
            assert_eq!(metric(&context, "application_proposal_started_total"), 1);
        });
    }

    #[test]
    fn missing_input_proposes_empty_blocks() {
        deterministic::Runner::default().start(|context| async move {
            // The schedule starts an hour after the proposal, so no input has arrived.
            let schedule: Schedule = serde_yaml::from_str(
                "start_unix_ms: 3600000
phases:
- duration_ms: 1
  bytes_per_second: 1000",
            )
            .unwrap();
            let production = Production {
                schedule: Some(schedule),
                ..saturated()
            };
            let mut harness = Harness::new(&context, production).await;
            let block_context = harness.context(0);
            let body = harness
                .mailbox
                .propose(block_context)
                .await
                .await
                .expect("an empty block answers at once");
            let block = harness
                .marshal
                .get_block(reference(block_context, body))
                .await
                .unwrap()
                .expect("the empty block is staged with marshal");
            assert_eq!(block.body(), &Body::default());
            // Empty blocks carry no input, so they are not tracked.
            assert_eq!(metric(&context, "application_proposal_started_total"), 0);
            assert_eq!(
                harness.mailbox.verify(block_context, body).await.await,
                Ok(true)
            );
        });
    }

    /// Returns a production whose input is `bytes_per_second` from `start_unix_ms` for an hour.
    fn scheduled(start_unix_ms: u64, bytes_per_second: usize) -> Production {
        let schedule: Schedule = serde_yaml::from_str(&format!(
            "start_unix_ms: {start_unix_ms}
phases:
- duration_ms: 3600000
  bytes_per_second: {bytes_per_second}"
        ))
        .unwrap();
        Production {
            schedule: Some(schedule),
            ..saturated()
        }
    }

    #[test]
    fn a_proposal_without_input_answers_an_empty_block() {
        deterministic::Runner::default().start(|context| async move {
            // The schedule starts an hour after the proposal, so no input has arrived.
            let mut harness = Harness::new(&context, scheduled(3_600_000, 1_000)).await;
            let block_context = harness.context(0);
            let body = harness
                .mailbox
                .propose(block_context)
                .await
                .await
                .expect("an empty block answers");
            let block = harness
                .marshal
                .get_block(reference(block_context, body))
                .await
                .unwrap()
                .expect("the empty block is staged with marshal");
            assert_eq!(block.body(), &Body::default());
            assert_eq!(metric(&context, "application_proposal_started_total"), 0);
        });
    }

    #[test]
    fn a_proposal_carries_the_input_that_arrived_before_it() {
        deterministic::Runner::default().start(|context| async move {
            // One body arrives every 10 ms from 20 ms on; the proposal comes at 30 ms.
            let start = context.current() + Duration::from_millis(20);
            let start_unix_ms = start
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let production = scheduled(start_unix_ms as u64, BODY_SIZE * 100);
            let mut harness = Harness::new(&context, production).await;
            let block_context = harness.context(0);
            context.sleep(Duration::from_millis(30)).await;
            let body = harness
                .mailbox
                .propose(block_context)
                .await
                .await
                .expect("the batch answers");
            let block = harness
                .marshal
                .get_block(reference(block_context, body))
                .await
                .unwrap()
                .expect("the block is staged with marshal");
            assert_ne!(block.body(), &Body::default());
            assert_eq!(metric(&context, "application_proposal_started_total"), 1);
        });
    }

    #[test]
    fn ordered_delivery_records_latency_for_local_blocks() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let block_context = harness.context(0);
            let body = harness.mailbox.propose(block_context).await.await.unwrap();
            let block = harness
                .marshal
                .get_block(reference(block_context, body))
                .await
                .unwrap()
                .unwrap();
            let remote_context = harness.context(1);
            let remote = Arc::new(Block::from_context(
                remote_context,
                Body::junk(11, remote_context, BODY_SIZE),
            ));

            let mut reporter = OutputReporter::new(harness.mailbox.clone(), None);
            for (index, block) in [remote, block].into_iter().enumerate() {
                let (acknowledgement, waiter) = Exact::handle();
                reporter.report(Update {
                    index: OutputIndex::new(index as u64 + 1),
                    block,
                    acknowledgement,
                });
                assert!(waiter.await.is_ok());
            }
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                metric(&context, "application_proposal_ordering_latency_count"),
                1
            );
            assert_eq!(metric(&context, "application_proposal_outstanding"), 0);
        });
    }

    #[test]
    fn relay_broadcasts_only_held_blocks() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let unheld = Sha256::hash(&[b"unheld"]);
            assert_eq!(harness.relay.broadcast(unheld, ()), Feedback::Ok);
            assert!(!harness.peer_receives(&context, unheld).await);

            let reference = harness.propose().await;
            let received = harness.peer.subscribe(reference.digest());
            assert_eq!(
                harness.relay.broadcast(reference.digest(), ()),
                Feedback::Ok
            );
            let block = received.await.expect("the peer receives the held block");
            assert_eq!(block.inner().reference(), reference);
        });
    }

    #[test]
    fn broadcasts_skip_queued_reports() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let reference = harness.propose().await;
            let received = harness.peer.subscribe(reference.digest());

            // The relay answers from marshal, so reports queued at the application do not delay
            // the broadcast.
            for height in 2..34 {
                harness.mailbox.ordered(BlockRef::new(
                    reference.chain(),
                    Height::new(height),
                    Sha256::hash(&[&height.to_be_bytes()]),
                ));
            }
            assert_eq!(
                harness.relay.broadcast(reference.digest(), ()),
                Feedback::Ok
            );
            select! {
                block = received => assert_eq!(block.unwrap().inner().reference(), reference),
                _ = context.sleep(PATIENCE) => panic!("the broadcast waited behind reports"),
            }
        });
    }

    #[test]
    fn relay_keeps_a_parent_after_its_child_is_staged() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let first = harness.propose().await;
            let child = Context::new(
                harness.committee.config.epoch(),
                first.chain(),
                Height::new(2),
                first.digest(),
            )
            .unwrap();
            let second = harness.propose_in(child).await;

            // The relay keeps every block consensus may still ask it to publish, so staging the
            // child keeps its parent.
            harness.relay.broadcast(first.digest(), ());
            assert!(harness.peer_receives(&context, first.digest()).await);
            harness.relay.broadcast(second.digest(), ());
            assert!(harness.peer_receives(&context, second.digest()).await);
        });
    }

    #[test]
    fn reporter_forwards_final_positions_and_own_signatures() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(&context, saturated()).await;
            let (sender, mut receiver) = mailbox::new(context.child("inspected"), NZUsize!(8));
            let mut mailbox = Mailbox::new(
                sender,
                Arc::new(context.child("clock")),
                Some(ChainId::new(0)),
            );

            let header = harness
                .committee
                .genesis_child(ChainId::new(0), b"block")
                .header()
                .clone();
            let proposed = header.block_ref::<Sha256>();
            let peer = harness
                .committee
                .genesis_child(ChainId::new(1), b"peer")
                .header()
                .block_ref::<Sha256>();
            for activity in [
                Activity::TransactionProposed {
                    block: peer,
                    view: View::new(1),
                },
                Activity::HeaderAccepted {
                    header,
                    adopted: None,
                },
            ] {
                assert_eq!(mailbox.report(activity), Feedback::Ok);
            }
            assert!(receiver.try_recv().is_err());

            // This node's own signed headers are forwarded for their signing latency.
            assert_eq!(
                mailbox.report(Activity::TransactionProposed {
                    block: proposed,
                    view: View::new(2),
                }),
                Feedback::Ok
            );
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::Signed { block, view, .. }) if block == proposed && view == View::new(2)
            ));

            let genesis: Arc<[BlockRef<Sha256Digest>]> =
                harness.committee.config.genesis().tips().into();
            let mut tips = genesis.to_vec();
            tips[0] = proposed;
            let tips: Arc<[BlockRef<Sha256Digest>]> = tips.into();
            assert_eq!(
                mailbox.report(Activity::ViewSweep {
                    view: View::new(3),
                    finals: Arc::clone(&tips),
                    settled: ChainSet::empty(tips.len()),
                }),
                Feedback::Ok
            );
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::Finalized { view, blocks, .. })
                    if view == View::new(3) && blocks == tips
            ));
            assert_eq!(
                mailbox.report(Activity::ViewResolved {
                    view: View::new(3),
                    base: genesis,
                    tips: Arc::clone(&tips),
                    commitment: Sha256::hash(&[b"commitment"]),
                    parent_commitment: harness.committee.config.genesis().history(),
                    by: Resolution::Determined,
                }),
                Feedback::Ok
            );
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::Finalized { view, blocks, .. })
                    if view == View::new(3) && blocks == tips
            ));
        });
    }

    #[test]
    fn final_positions_reach_the_latency_tracker() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(&context, saturated()).await;
            let first = harness.propose().await;
            let next = Context::new(
                harness.committee.config.epoch(),
                first.chain(),
                Height::new(2),
                first.digest(),
            )
            .unwrap();
            let tip = harness.propose_in(next).await;
            assert_eq!(
                metric(&context, "application_proposal_finalization_latency_count"),
                0
            );
            // The parent was signed a view before the view whose finality covers both.
            for (block, view) in [(first, 1), (tip, 2)] {
                assert_eq!(
                    harness.mailbox.report(Activity::TransactionProposed {
                        block,
                        view: View::new(view),
                    }),
                    Feedback::Ok
                );
            }

            // A final position on the newer block covers its tracked parent too.
            let genesis = harness.committee.config.genesis().tips()[1];
            let finals: Arc<[BlockRef<Sha256Digest>]> = vec![tip, genesis].into();
            assert_eq!(
                harness.mailbox.report(Activity::ViewSweep {
                    view: View::new(2),
                    finals,
                    settled: ChainSet::empty(2),
                }),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                metric(&context, "application_proposal_finalization_latency_count"),
                2
            );
            assert_eq!(metric(&context, "application_proposal_nonfinalized"), 0);
            assert_eq!(
                metric(&context, "application_proposal_finalization_views_count"),
                2
            );
            assert!(
                context
                    .encode()
                    .lines()
                    .any(|line| line == "application_proposal_finalization_views_sum 1.0")
            );
        });
    }

    #[test]
    fn finality_above_an_empty_block_reaches_the_batch_below() {
        deterministic::Runner::default().start(|context| async move {
            // One batch arrives in the schedule's only millisecond; no input follows it.
            let schedule: Schedule = serde_yaml::from_str(
                "start_unix_ms: 0
phases:
- duration_ms: 1
  bytes_per_second: 32000",
            )
            .unwrap();
            let production = Production {
                schedule: Some(schedule),
                ..saturated()
            };
            let mut harness = Harness::new(&context, production).await;
            harness.goal.refresh(100);
            context.sleep(Duration::from_millis(10)).await;
            let batch = harness.propose().await;
            let next = Context::new(
                harness.committee.config.epoch(),
                batch.chain(),
                Height::new(2),
                batch.digest(),
            )
            .unwrap();
            let empty = harness.propose_in(next).await;
            assert_eq!(metric(&context, "application_proposal_started_total"), 1);
            assert_eq!(
                harness.mailbox.report(Activity::TransactionProposed {
                    block: batch,
                    view: View::new(1),
                }),
                Feedback::Ok
            );

            // The empty block is the final position, so only its parent link reaches the batch.
            let genesis = harness.committee.config.genesis().tips()[1];
            let finals: Arc<[BlockRef<Sha256Digest>]> = vec![empty, genesis].into();
            assert_eq!(
                harness.mailbox.report(Activity::ViewSweep {
                    view: View::new(1),
                    finals,
                    settled: ChainSet::empty(2),
                }),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(metric(&context, "application_proposal_nonfinalized"), 0);
            assert_eq!(
                metric(
                    &context,
                    "application_proposal_signed_finalization_latency_count"
                ),
                1
            );
            assert_eq!(
                metric(&context, "application_proposal_goal_finalized_total"),
                1
            );
            assert_eq!(metric(&context, "application_proposal_goal_met_total"), 1);
            assert!(harness.stats.mean_signed_finalized().is_some());
            assert_eq!(harness.stats.within_goal_pct(), Some(100));
        });
    }

    #[test]
    fn verdict_rejects_mismatched_blocks() {
        let requested = block(1, 1);
        let delivered = block(1, 2);
        let (response, mut answer) = oneshot::channel();
        assert!(matches!(
            verdict(requested.header(), delivered, response),
            Completion::Done
        ));
        assert_eq!(answer.try_recv(), Ok(false));

        let (response, _answer) = oneshot::channel();
        assert!(matches!(
            verdict(requested.header(), Arc::clone(&requested), response),
            Completion::Verified { .. }
        ));
    }

    fn block(chain: u32, height: u64) -> Arc<Block> {
        let context = Context::new(
            Epoch::new(7),
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[b"parent", &height.to_be_bytes()]),
        )
        .unwrap();
        Arc::new(Block::from_context(context, Body::junk(9, context, 32)))
    }
}
