//! The application actor: builds, stages, and verifies blocks.

use super::{
    Config, Marshal, Production,
    block::{Block, Body},
    mailbox::{Mailbox, Message},
};
use crate::bench::{ProposalLatency, Workload};
use commonware_actor::mailbox::{self, Receiver};
use commonware_consensus::{
    Heightable as _,
    multimmit::{
        WAN_LATENCY,
        marshal::{Custody, Error as MarshalError},
        types::{ChainId, Context, TransactionBlockHeader},
    },
};
use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Histogram, HistogramExt as _, MetricsExt as _},
};
use commonware_utils::{channel::oneshot, futures::Pool};
use std::{future::Future, sync::Arc, time::SystemTime};
use tracing::{debug, warn};

/// Synthetic input available for one proposal.
enum Input {
    /// No workload paces production.
    Saturated,
    /// The workload's finite schedule has ended.
    Exhausted,
    /// The batch's last byte arrives at this time.
    ReadyAt(SystemTime),
}

/// A finished background step whose result updates the actor.
enum Completion {
    /// A proposal's block was built and must now be staged.
    Built {
        block: Arc<Block>,
        construction_at: SystemTime,
        input_ready_at: Option<SystemTime>,
        response: oneshot::Sender<Sha256Digest>,
    },
    /// Marshal answered a staging request for a proposal's block.
    Staged {
        block: Arc<Block>,
        custody: Result<Custody, MarshalError>,
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
    last_build: Option<SystemTime>,
    latency: ProposalLatency,
    producer_chain: Option<ChainId>,
    body_wait: Histogram,
    input_queue: Histogram,
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
        let latency =
            ProposalLatency::new(&context, config.tracked_blocks, config.benchmark_quorum);
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
        (
            Self {
                context: ContextCell::new(context),
                mailbox: receiver,
                seed: config.seed,
                production,
                workload,
                last_build: None,
                latency,
                producer_chain: config.producer_chain,
                body_wait,
                input_queue,
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
            Message::Finalized { fact, at } => self.latency.finalize((&fact).into(), at),
            Message::Ordered { block, at } => self.latency.order(block, at),
        }
    }

    /// Returns the synthetic input available for the block at `height`.
    fn input(&mut self, height: u64, now: SystemTime) -> Input {
        let Some(workload) = &mut self.workload else {
            return Input::Saturated;
        };
        workload
            .request(height, now)
            .map_or(Input::Exhausted, Input::ReadyAt)
    }

    fn propose(
        &mut self,
        context: Context<Sha256Digest>,
        mut response: oneshot::Sender<Sha256Digest>,
    ) {
        // The optional block interval and the availability of a full input batch independently
        // constrain the build. Neither moves the input arrival schedule under backpressure.
        let now = self.context.current();
        let input = self.input(context.height().get(), now);
        let earliest = self
            .last_build
            .map_or(now, |last| last + self.production.interval)
            .max(now);
        let (next_build, input_ready_at) = match input {
            Input::ReadyAt(ready) => (ready.max(earliest), Some(ready)),
            Input::Saturated | Input::Exhausted => (earliest, None),
        };
        self.last_build = Some(next_build);
        if matches!(input, Input::Exhausted) {
            // Hold the request until consensus gives up on it.
            self.pending.push(async move {
                response.closed().await;
                Completion::Done
            });
            return;
        }
        // Waiting for the deadline and building run as one task on the shared pool, so the actor
        // wakes once, when the block is ready to stage. With `shared(true)` the task holds one
        // blocking thread through the deadline sleep: at most one per pending build, and consensus
        // keeps one build pending per producer chain. A canceled request wakes the sleep early.
        let seed = self.seed;
        let body_size = self.production.body_size;
        let built = self
            .context
            .child("propose")
            .shared(true)
            .spawn(move |runtime| async move {
                if or_canceled(&mut response, runtime.sleep_until(next_build))
                    .await
                    .is_none()
                {
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
                    input_ready_at,
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
                input_ready_at,
                mut response,
            } => {
                if let Some(input_ready_at) = input_ready_at {
                    self.input_queue
                        .observe_between(input_ready_at, construction_at);
                }
                self.latency.start(
                    block.reference(),
                    block.header().parent(),
                    input_ready_at.unwrap_or(construction_at),
                    input_ready_at,
                    construction_at,
                );
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
                        response,
                    }
                });
            }
            Completion::Staged {
                block,
                custody,
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
                    "produced body"
                );
                if response.send(body_digest).is_ok()
                    && let Some(workload) = &self.workload
                {
                    workload.admit(reference.height().get());
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
            Artifact,
            marshal::{self, ArchiveConfig, LqcVerifier, Start, Update},
            mocks::{
                Committee,
                cluster::{QUOTA, link_all, start_network},
                finality_fact,
            },
            types::{Activity, BlockRef, Lqc, PathLimits},
        },
        types::{Epoch, Height, Participant, Round, View},
    };
    use commonware_cryptography::{Hasher as _, bls12381::primitives::variant::MinPk, ed25519};
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p as resolver;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::translator::EightCap;
    use commonware_utils::{Acknowledgement as _, NZU16, NZU64, NZUsize, acknowledgement::Exact};
    use std::{convert::Infallible, time::Duration};

    /// Body bytes in every test block.
    const BODY_SIZE: usize = 32;

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

    /// DA shares needed for a certificate in the test committee (`n-2f` with `n=6`, `f=1`).
    const DA_QUORUM: usize = 4;

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
    }

    impl Harness {
        async fn new(context: &deterministic::Context, production: Production) -> Self {
            let committee = Committee::<MinPk>::builder(7, PARTICIPANTS)
                .namespace(b"_COMMONWARE_LOG_MULTIMMIT_ACTOR_TEST")
                .producers(vec![Participant::new(0), Participant::new(1)])
                .limits(PathLimits::new(8, 4).unwrap())
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
            let mut config = marshal::Config::new(
                Start::Genesis(committee.config.genesis().clone()),
                "log_multimmit_actor_test".into(),
                committee.codec(),
                Body::codec_config(BODY_SIZE),
                ArchiveConfig::new(
                    EightCap,
                    CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
                ),
            );
            config.capacities.catalog_mailbox_size = NZUsize!(64);
            config.capacities.admission_cut_capacity = NZUsize!(64);
            config.capacities.pending_segment_items = NZU64!(64);
            config.capacities.resolver_mailbox_size = NZUsize!(64);
            config.capacities.backfill_concurrency = config.capacities.resolver_mailbox_size;
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
            let (application, mailbox) = Actor::new(
                context.child("application"),
                Config {
                    seed: 3,
                    production,
                    tracked_blocks: NZUsize!(16),
                    producer_chain,
                    benchmark_quorum: None,
                    mailbox_size: NZUsize!(64),
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

        /// Returns a DA certificate for a block at `height` on `chain`.
        fn certificate(&self, chain: u32, height: u64) -> Arc<Artifact<MinPk, Sha256Digest>> {
            let header = TransactionBlockHeader::new(
                self.committee.config.epoch(),
                ChainId::new(chain),
                Height::new(height),
                Sha256::hash(&[b"parent"]),
                Sha256::hash(&[b"body"]),
            )
            .unwrap();
            let votes = (0..DA_QUORUM)
                .map(|signer| {
                    self.committee
                        .da_vote(Participant::from_usize(signer), header.clone())
                })
                .collect::<Vec<_>>();
            let certificate = self
                .committee
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .unwrap();
            Arc::new(Artifact::DaCertificate(certificate))
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
            interval: Duration::ZERO,
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
            assert_eq!(received.await.unwrap().reference(), reference);
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
            let production = Production {
                interval: Duration::from_secs(60),
                ..saturated()
            };
            let mut harness = Harness::new(&context, production).await;
            let first = harness.context(0);
            let body = harness.mailbox.propose(first).await.await.unwrap();
            let next = Context::new(
                first.epoch(),
                first.chain(),
                Height::new(2),
                reference(first, body).digest(),
            )
            .unwrap();

            // The next build waits out the production interval; dropping the request cancels it.
            drop(harness.mailbox.propose(next).await);
            context.sleep(Duration::from_secs(120)).await;
            assert_eq!(metric(&context, "application_proposal_started_total"), 1);
            assert!(harness.mailbox.propose(next).await.await.is_ok());
            assert_eq!(metric(&context, "application_proposal_started_total"), 2);
        });
    }

    #[test]
    fn exhausted_input_holds_proposals() {
        deterministic::Runner::default().start(|context| async move {
            // The schedule offers fewer bytes than one body, so no batch ever completes.
            let schedule: Schedule = serde_yaml::from_str(
                "start_unix_ms: 0\nphases:\n- duration_ms: 1\n  bytes_per_second: 1000",
            )
            .unwrap();
            let production = Production {
                schedule: Some(schedule),
                ..saturated()
            };
            let mut harness = Harness::new(&context, production).await;
            let mut proposal = harness.mailbox.propose(harness.context(0)).await;
            select! {
                _ = &mut proposal => panic!("an exhausted schedule must not answer"),
                _ = context.sleep(Duration::from_secs(10)) => {},
            }
            assert_eq!(metric(&context, "application_proposal_started_total"), 0);
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
                    index: marshal::OutputIndex::new(index as u64),
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
            assert_eq!(block.reference(), reference);
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
                block = received => assert_eq!(block.unwrap().reference(), reference),
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
    fn reporter_forwards_only_finality() {
        deterministic::Runner::default().start(|context| async move {
            let harness = Harness::new(&context, saturated()).await;
            let (sender, mut receiver) = mailbox::new(context.child("inspected"), NZUsize!(8));
            let mut mailbox = Mailbox::new(
                sender,
                Arc::new(context.child("clock")),
                Some(ChainId::new(0)),
            );

            let artifact = harness.certificate(0, 5);
            assert_eq!(
                mailbox.report(Activity::ProtocolAccepted {
                    artifact_id: artifact.id::<Sha256>(),
                    artifact,
                }),
                Feedback::Ok
            );
            let proposed =
                BlockRef::new(ChainId::new(0), Height::new(5), Sha256::hash(&[b"block"]));
            assert_eq!(
                mailbox.report(Activity::TransactionProposed { block: proposed }),
                Feedback::Ok
            );
            assert!(receiver.try_recv().is_err());

            let fact = finality_fact(
                Round::new(harness.committee.config.epoch(), View::new(3)),
                DA_QUORUM,
                vec![proposed],
                vec![Height::new(5)],
            );
            assert_eq!(
                mailbox.report(Activity::LeaderFinalized { fact: fact.clone() }),
                Feedback::Ok
            );
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::Finalized { fact: received, .. }) if received == fact
            ));
            assert_eq!(
                mailbox.report(Activity::LeaderFinalityUpdated { fact: fact.clone() }),
                Feedback::Ok
            );
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::Finalized { fact: received, .. }) if received == fact
            ));
        });
    }

    #[test]
    fn finality_facts_reach_the_latency_tracker() {
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

            // A fact finalizing the newer block covers its tracked parent too.
            let genesis = harness.committee.config.genesis().tips()[1];
            let fact = finality_fact(
                Round::new(harness.committee.config.epoch(), View::new(1)),
                DA_QUORUM,
                vec![tip, genesis],
                vec![Height::new(2), Height::zero()],
            );
            assert_eq!(
                harness.mailbox.report(Activity::LeaderFinalized { fact }),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                metric(&context, "application_proposal_finalization_latency_count"),
                2
            );
            assert_eq!(metric(&context, "application_proposal_nonfinalized"), 0);
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
