//! The resolver task: the `commonware-resolver` engine, retained proofs, and the codec pool.
//!
//! [`Actor::start`] spawns the p2p engine over the committee and one task that serves machine
//! controls, local proof queries, codec completions, and peer requests and deliveries. Peer work
//! waits while every codec worker is busy, so encode and decode work stays bounded by the pool.

use super::{
    Config, Mailbox, Message, ResolveRequest, Serve, custody::Custody,
    metrics::Metrics as ActorMetrics,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::{
            util::{self, Handler, WorkerPanicked, gated, offload, some_or_pending},
            voter::Resolutions,
        },
        machine::{ResolutionCompletion, ResolutionJob},
        scheme::bls12381_threshold::Scheme,
        types::{CodecConfig, ViewProof},
    },
    types::{Epoch, Round, View},
};
use bytes::Bytes;
use commonware_actor::{Feedback, mailbox};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Fetch, Resolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{metrics::HistogramExt as _, traces::TracedExt as _},
};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
    sequence::U64,
};
use rand_core::Rng;
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    iter::repeat_n,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, error, info_span};

/// The issuing context of one outstanding resolution job.
struct Origin {
    root: Span,
    round: Round,
    started_at: SystemTime,
}

/// A blocker that never blocks and forwards only the blocked-peer subscription.
///
/// `p2p::Engine` uses its blocker for two things: blocking peers that send invalid responses and
/// subscribing to peers blocked elsewhere. A bad response is not portable proof of a protocol
/// fault, so this actor keeps only the subscription.
#[derive(Clone)]
struct NonBlocking<B>(B);

impl<B: Blocker> Blocker for NonBlocking<B> {
    type PublicKey = B::PublicKey;

    fn block(&mut self, _: Self::PublicKey) -> Feedback {
        Feedback::Ok
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        self.0.blocked()
    }
}

/// A fetched view proof to validate or a peer request to serve one, keyed by view.
type HandlerMessage = util::HandlerMessage<U64, ResolutionJob, bool>;

/// The result of one proof encode or decode on the codec pool.
pub(super) enum CodecCompletion<V: Variant, D: Digest> {
    /// A peer response decoded for each subscribed job, or `None` if it is unusable.
    Decoded {
        proofs: Option<Vec<(ResolutionJob, ViewProof<V, D>)>>,
        response: oneshot::Sender<bool>,
    },
    /// A retained proof encoded to serve one peer request.
    Encoded {
        proof: Arc<ViewProof<V, D>>,
        value: Bytes,
        response: oneshot::Sender<Bytes>,
    },
    /// A copy of a retained proof that completes one job without a fetch.
    ///
    /// Retained proofs are shared with the serving state, while a completion hands the machine an
    /// owned proof. Copying a certificate deep-copies its transcript and signatures, so the copy
    /// runs on the codec pool instead of the actor loop.
    Materialized {
        job: ResolutionJob,
        proof: ViewProof<V, D>,
    },
}

type CodecResult<V, D> = (Span, CodecCompletion<V, D>);
type CodecResults<V, D> = Pool<'static, CodecResult<V, D>>;
/// Jobs a retained proof completes, awaiting a codec worker to copy it, with their issuing span.
type PendingLocal<V, D> = BTreeMap<ResolutionJob, (Arc<ViewProof<V, D>>, Span)>;

/// Decodes an untrusted delivery on `strategy`, counting a worker panic as an invalid response so
/// a codec defect cannot stop the actor.
pub(super) async fn decode_delivery<S, V, D>(
    strategy: S,
    span: Span,
    response: oneshot::Sender<bool>,
    decode: impl FnOnce() -> Option<Vec<(ResolutionJob, ViewProof<V, D>)>> + Send + 'static,
) -> CodecResult<V, D>
where
    S: Strategy,
    V: Variant,
    D: Digest,
{
    let (span, proofs) = offload(strategy, 1, span, move |_| decode()).await;
    let proofs = proofs.unwrap_or_else(|WorkerPanicked| {
        span.in_scope(|| error!("resolver decode worker panicked"));
        None
    });
    (span, CodecCompletion::Decoded { proofs, response })
}

/// Runs codec work over locally held proofs on `strategy`. A worker panic is a local defect and
/// propagates.
async fn encode_local<S, V, D>(
    strategy: S,
    span: Span,
    operation: impl FnOnce() -> CodecCompletion<V, D> + Send + 'static,
) -> CodecResult<V, D>
where
    S: Strategy,
    V: Variant,
    D: Digest,
{
    let (span, completion) = offload(strategy, 1, span, move |_| operation()).await;
    (span, completion.expect("resolver codec worker panicked"))
}

/// A peer delivery whose p2p response waits until the machine settles every job it completed.
struct Verdict {
    jobs: BTreeSet<ResolutionJob>,
    response: oneshot::Sender<bool>,
}

/// How the machine settled a job that a peer delivery may be waiting on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The machine retracted the job; deliveries waiting only on it settle as valid.
    Cancelled,
    /// The machine rejected the delivered proof; deliveries carrying it settle as invalid.
    Rejected,
}

/// A retained view proof and its canonical encoding, cached once a peer requests it.
pub(super) struct StoredProof<V: Variant, D: Digest> {
    proof: Arc<ViewProof<V, D>>,
    canonical: Option<Bytes>,
}

impl<V: Variant, D: Digest> From<ViewProof<V, D>> for StoredProof<V, D> {
    fn from(proof: ViewProof<V, D>) -> Self {
        Self {
            proof: Arc::new(proof),
            canonical: None,
        }
    }
}

impl<V: Variant, D: Digest> Borrow<ViewProof<V, D>> for StoredProof<V, D> {
    fn borrow(&self) -> &ViewProof<V, D> {
        &self.proof
    }
}

/// In-memory view proofs this node serves to peers.
pub(super) type State<V, D> = Custody<V, D, StoredProof<V, D>>;

impl<V: Variant, D: Digest> State<V, D> {
    /// Returns an empty state that refuses exits at the genesis view.
    pub(super) fn new() -> Self {
        let mut state = Self::empty();
        state.prune(View::zero());
        state
    }

    /// Returns the retained proof that resolves `view`.
    pub(super) fn proof(&self, view: View) -> Option<Arc<ViewProof<V, D>>> {
        self.get(view).map(|stored| Arc::clone(&stored.proof))
    }

    /// Returns the cached canonical encoding of the proof that resolves `view`.
    fn canonical(&self, view: View) -> Option<Bytes> {
        self.get(view)
            .and_then(|stored| stored.canonical.as_ref().cloned())
    }

    /// Caches `canonical` as the encoding of `proof`, if `proof` is still retained.
    fn cache(&mut self, proof: &Arc<ViewProof<V, D>>, canonical: Bytes) {
        if let Some(stored) = self.get_mut(proof.view())
            && Arc::ptr_eq(&stored.proof, proof)
        {
            stored.canonical = Some(canonical);
        }
    }
}

/// Returns the view a resolver key requests.
fn key_view(key: U64) -> View {
    View::new(key.into())
}

/// Returns `proof` if it can resolve `view`: an exit proof for exactly `view`, or an L-QC at or
/// above it.
fn usable_for<V: Variant, D: Digest>(
    view: View,
    proof: ViewProof<V, D>,
) -> Option<ViewProof<V, D>> {
    let useful = match &proof {
        ViewProof::Nullification(proof) => proof.view() == view,
        ViewProof::Vqc(proof) => proof.view() == view,
        ViewProof::Lqc(proof) => proof.view() >= view,
    };
    useful.then_some(proof)
}

/// Fetches and serves view proofs for one fixed epoch.
pub(crate) struct Actor<E, H, P, V, B, T>
where
    E: Clock + Spawner + Metrics + BufferPooler + Rng,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: Scheme<P, V>,
    blocker: B,
    strategy: T,
    fetch_timeout: Duration,
    mailbox_size: NonZeroUsize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<V, H::Digest>>,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, V, B, T> Actor<E, H, P, V, B, T>
where
    E: Clock + Spawner + Metrics + BufferPooler + Rng,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    /// Creates the resolver and its voter-facing control and query mailboxes.
    pub(crate) fn new(context: E, config: Config<P, V, B, T>) -> (Self, Mailbox<V, H::Digest>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let (query_sender, query_receiver) =
            mailbox::new_unreliable(context.child("queries"), config.mailbox_size);
        (
            Self {
                metrics: ActorMetrics::new(&context),
                context: ContextCell::new(context),
                scheme: config.scheme,
                blocker: config.blocker,
                strategy: config.strategy,
                fetch_timeout: config.fetch_timeout,
                mailbox_size: config.mailbox_size,
                mailbox: receiver,
                queries: query_receiver,
                _hasher: PhantomData,
            },
            Mailbox::new(sender, query_sender),
        )
    }

    /// Starts the resolver over the epoch's registered resolver plane.
    pub(crate) fn start(
        mut self,
        voter: Resolutions<V, H::Digest>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, network))
    }

    /// Starts the p2p engine over the committee and serves until shutdown.
    async fn run(
        self,
        voter: Resolutions<V, H::Digest>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let Self {
            context,
            scheme,
            blocker,
            strategy,
            fetch_timeout,
            mailbox_size,
            mailbox,
            queries,
            metrics,
            _hasher,
        } = self;
        let participants = scheme.participants().clone();
        let me = scheme
            .me()
            .and_then(|participant| participants.get(participant.into()))
            .cloned();
        let epoch = scheme.epoch();
        let (handler_sender, handler) =
            mailbox::new(context.as_ref().child("handler"), mailbox_size);
        let endpoint = Handler::new(handler_sender);
        let (engine, fetcher) = p2p::Engine::new(
            context.as_ref().child("p2p"),
            p2p::Config {
                peer_provider: StaticProvider::new(epoch.get(), participants),
                blocker: NonBlocking(blocker),
                consumer: endpoint.clone(),
                producer: endpoint,
                mailbox_size,
                me,
                timeout: fetch_timeout,
                fetch_retry_timeout: fetch_timeout,
                priority_requests: true,
                priority_responses: true,
            },
        );
        let engine = engine.start(network);
        Service {
            context,
            epoch,
            codec: scheme.codec_config(),
            codec_capacity: strategy.manual().parallelism(),
            strategy,
            mailbox,
            queries,
            handler,
            fetcher,
            engine,
            voter,
            state: State::new(),
            outstanding: BTreeMap::new(),
            pending_local: PendingLocal::new(),
            verdicts: Vec::new(),
            codecs: CodecResults::default(),
            peer_work_ready: true,
            metrics,
            _hasher: PhantomData::<H>,
        }
        .run()
        .await;
    }
}

/// The running resolver: its inputs, the p2p fetcher, retained proofs, and in-flight work.
struct Service<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    context: ContextCell<E>,
    epoch: Epoch,
    codec: CodecConfig,
    strategy: T,
    /// Codec jobs allowed in flight before peer requests wait.
    codec_capacity: usize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<V, H::Digest>>,
    handler: mailbox::Receiver<HandlerMessage>,
    fetcher: p2p::Mailbox<U64, P, ResolutionJob>,
    engine: Handle<()>,
    voter: Resolutions<V, H::Digest>,
    state: State<V, H::Digest>,
    outstanding: BTreeMap<ResolutionJob, Origin>,
    pending_local: PendingLocal<V, H::Digest>,
    verdicts: Vec<Verdict>,
    codecs: CodecResults<V, H::Digest>,
    /// Whether a codec worker is free for peer requests, computed before each select.
    peer_work_ready: bool,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, V, T> Service<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.peer_work_ready = self.materialize_pending();
            },
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut self.engine => break,
            result = self.codecs.next_completed() => {
                let (span, completion) = result;
                span.in_scope(|| self.on_codec(completion));
            },
            Some(message) = self.mailbox.recv() else break => self.on_control(message),
            // A closed query mailbox goes quiet instead of stopping the actor.
            query = some_or_pending(self.queries.recv()) => {
                let Serve { view, responder } = query;
                let _ = responder.send(self.state.proof(view));
            },
            // Peer requests wait while every codec worker is busy, so encode and decode work
            // stays bounded by the pool.
            Some(message) = gated(self.peer_work_ready, self.handler.recv()) else break => {
                match message {
                    HandlerMessage::Produce { key, response } => {
                        self.on_produce(key_view(key), response);
                    }
                    HandlerMessage::Deliver {
                        delivery,
                        value,
                        response,
                    } => self.on_deliver(delivery, value, response),
                }
            },
        }
    }

    /// Starts copying retained proofs for local jobs while codec workers are free.
    ///
    /// Returns whether a worker remains for peer requests.
    fn materialize_pending(&mut self) -> bool {
        while self.codecs.len() < self.codec_capacity {
            let Some((job, (proof, parent))) = self.pending_local.pop_first() else {
                break;
            };
            let span = info_span!(
                parent: &parent,
                "multimmit.resolver.resolve.materialize",
                view = job.view().get().traced(),
                job = job.issued().id().get().traced(),
            );
            let operation = move || CodecCompletion::Materialized {
                job,
                proof: proof.as_ref().clone(),
            };
            self.codecs
                .push(encode_local(self.strategy.clone(), span, operation));
        }
        self.codecs.len() < self.codec_capacity
    }

    /// Applies one finished codec job.
    fn on_codec(&mut self, completion: CodecCompletion<V, H::Digest>) {
        match completion {
            CodecCompletion::Decoded {
                proofs: None,
                response,
            } => {
                self.metrics.mismatched.inc();
                response.send_lossy(false);
            }
            CodecCompletion::Decoded {
                proofs: Some(proofs),
                response,
            } => {
                let mut jobs = BTreeSet::new();
                for (job, proof) in proofs {
                    let Some(origin) = self.outstanding.get(&job) else {
                        continue;
                    };
                    jobs.insert(job);
                    self.complete(job, origin, proof);
                }
                if jobs.is_empty() {
                    response.send_lossy(true);
                } else {
                    self.verdicts.push(Verdict { jobs, response });
                }
            }
            CodecCompletion::Encoded {
                proof,
                value,
                response,
            } => {
                self.state.cache(&proof, value.clone());
                self.metrics.served.inc();
                response.send_lossy(value);
            }
            CodecCompletion::Materialized { job, proof } => {
                if let Some(origin) = self.outstanding.get(&job) {
                    self.complete(job, origin, proof);
                }
            }
        }
    }

    /// Applies one control message from the voter.
    fn on_control(&mut self, message: Message<V, H::Digest>) {
        match message {
            Message::Resolve(request) => self.on_resolve(request),
            Message::Cancel { job } => self.retire(job, Outcome::Cancelled),
            Message::Reject { job } => {
                self.metrics.rejected.inc();
                self.retire(job, Outcome::Rejected);
            }
            Message::Retain { proof } => self.state.retain(proof),
            Message::Prune { through } => self.state.prune(through),
        }
    }

    /// Starts one machine-issued request, completing it from retained proofs when possible.
    fn on_resolve(&mut self, request: ResolveRequest) {
        let process = info_span!(
            parent: &request.span,
            "multimmit.resolver.resolve.process",
            epoch = request.round.epoch().get().traced(),
            view = request.round.view().get().traced(),
            job = request.job.issued().id().get().traced(),
        );
        let _entered = process.enter();
        let job = request.job;
        if self.outstanding.contains_key(&job) {
            return;
        }
        self.metrics.requests.inc();
        self.outstanding.insert(
            job,
            Origin {
                root: request.root,
                round: request.round,
                started_at: self.context.current(),
            },
        );
        if let Some(proof) = self.state.proof(job.view()) {
            self.pending_local.insert(job, (proof, process.clone()));
            return;
        }
        let span = info_span!(
            parent: &process,
            "multimmit.resolver.resolve.fetch",
            view = job.view().get().traced(),
            job = job.issued().id().get().traced(),
        );
        let _ = self.fetcher.fetch(Fetch {
            key: U64::new(job.view().get()),
            subscriber: job,
            span,
        });
    }

    /// Serves one peer request for `view` from retained proofs.
    fn on_produce(&mut self, view: View, response: oneshot::Sender<Bytes>) {
        if let Some(value) = self.state.canonical(view) {
            self.metrics.served.inc();
            response.send_lossy(value);
            return;
        }
        let Some(proof) = self.state.proof(view) else {
            return;
        };
        let span = info_span!(
            "multimmit.resolver.serve.encode",
            epoch = self.epoch.get().traced(),
            view = view.get().traced(),
        );
        let encoded = Arc::clone(&proof);
        let operation = move || CodecCompletion::Encoded {
            proof,
            value: encoded.encode(),
            response,
        };
        self.codecs
            .push(encode_local(self.strategy.clone(), span, operation));
    }

    /// Decodes one fetched value for every job subscribed to its view.
    fn on_deliver(
        &mut self,
        delivery: Delivery<U64, ResolutionJob>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let requested = key_view(delivery.key);
        let (_, cause) = delivery.subscribers.first();
        let deliver = info_span!(
            parent: cause,
            "multimmit.resolver.resolve.deliver",
            epoch = self.epoch.get().traced(),
            view = requested.get().traced(),
        );
        for (_, cause) in delivery.subscribers.iter().skip(1) {
            deliver.follows_from(cause.id());
        }
        let codec = self.codec;
        let decode = move || {
            let proof = ViewProof::<V, H::Digest>::decode_cfg(value, &codec)
                .ok()
                .and_then(|proof| usable_for(requested, proof))?;
            let proofs = repeat_n(proof, delivery.subscribers.len().get())
                .zip(delivery.subscribers.iter())
                .map(|(proof, (job, _))| (*job, proof))
                .collect();
            Some(proofs)
        };
        self.codecs.push(decode_delivery(
            self.strategy.clone(),
            deliver,
            response,
            decode,
        ));
    }

    /// Hands one resolved proof to the voter.
    fn complete(&self, job: ResolutionJob, origin: &Origin, proof: ViewProof<V, H::Digest>) {
        self.metrics.resolved.inc();
        self.metrics
            .resolved_latency
            .observe_between(origin.started_at, self.context.current());
        let completion = ResolutionCompletion::new(job.issued(), job.view(), proof);
        let span = info_span!(
            "multimmit.resolver.resolve.complete",
            epoch = origin.round.epoch().get().traced(),
            view = origin.round.view().get().traced()
        );
        let _ = self
            .voter
            .resolved(origin.root.clone(), span, origin.round, completion);
    }

    /// Stops tracking one job the machine settled and answers the peer deliveries waiting on it.
    fn retire(&mut self, job: ResolutionJob, outcome: Outcome) {
        self.outstanding.remove(&job);
        self.pending_local.remove(&job);
        settle(&mut self.verdicts, job, outcome);
        let _ = self.fetcher.retain(move |_, candidate| *candidate != job);
    }
}

/// Answers every delivery whose verdict `job` decides.
///
/// A rejection settles each delivery carrying `job` as invalid. A cancellation settles a delivery
/// as valid once none of its jobs remain.
fn settle(verdicts: &mut Vec<Verdict>, job: ResolutionJob, outcome: Outcome) {
    let settled = verdicts.extract_if(.., |verdict| {
        verdict.jobs.remove(&job) && (outcome == Outcome::Rejected || verdict.jobs.is_empty())
    });
    for verdict in settled {
        verdict.response.send_lossy(outcome == Outcome::Cancelled);
    }
}
