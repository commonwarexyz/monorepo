//! The resolver task: the `commonware-resolver` engine, retained proofs, and the codec pool.
//!
//! [`Actor::start`] spawns the p2p engine over the committee and one task that serves machine
//! controls, local proof queries, codec completions, and peer requests and deliveries. Codec work
//! is submitted to the strategy as it arrives, and the strategy's workers bound how much of it
//! runs at once.

use super::{
    CertificateRequest, Config, Mailbox, Message, ResolveRequest, ResolverKey, Serve,
    custody::Custody, metrics::Metrics as ActorMetrics,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::{
            util::{self, Handler, WorkerPanicked, offload, some_or_pending},
            voter::Resolutions,
        },
        machine::{CertificateCompletion, CertificateJob, ResolutionCompletion, ResolutionJob},
        scheme::{Generic, Scheme},
        types::{ChainId, CodecConfig, DaCertificate, ViewProof},
    },
    types::{Epoch, Height, Round, View},
};
use bytes::Bytes;
use commonware_actor::{Feedback, mailbox};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Fetch, Resolver, p2p};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{metrics::HistogramExt as _, traces::TracedExt as _},
};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
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
    /// The round that issued a view request; DA-certificate requests carry none.
    round: Option<Round>,
    started_at: SystemTime,
}

/// The machine job a fetch serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Subscriber {
    /// A view-proof request.
    View(ResolutionJob),
    /// A DA-certificate request.
    Certificate(CertificateJob),
}

impl Subscriber {
    /// Returns the key that fetches this job.
    const fn key(self) -> ResolverKey {
        match self {
            Self::View(job) => ResolverKey::View(job.view()),
            Self::Certificate(job) => ResolverKey::Certificate {
                chain: job.chain(),
                after: job.after(),
            },
        }
    }
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

/// A fetched value to validate or a peer request to serve one.
type HandlerMessage = util::HandlerMessage<ResolverKey, Subscriber, bool>;

/// The result of one proof encode or decode on the codec pool.
pub(super) enum CodecCompletion<S: Scheme, D: Digest> {
    /// A peer response decoded for each subscribed job, or `None` if it is unusable.
    Decoded {
        proofs: Option<Vec<(ResolutionJob, ViewProof<S, D>)>>,
        response: oneshot::Sender<bool>,
    },
    /// A peer's DA certificate decoded for each subscribed job, or `None` if it is unusable.
    DecodedCertificate {
        certificates: Option<Vec<(CertificateJob, DaCertificate<S, D>)>>,
        response: oneshot::Sender<bool>,
    },
    /// A retained DA certificate encoded to serve one peer request.
    EncodedCertificate {
        certificate: Arc<DaCertificate<S, D>>,
        value: Bytes,
        response: oneshot::Sender<Bytes>,
    },
    /// A retained proof encoded to serve one peer request.
    Encoded {
        proof: Arc<ViewProof<S, D>>,
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
        proof: ViewProof<S, D>,
    },
}

type CodecResult<S, D> = (Span, CodecCompletion<S, D>);
type CodecResults<S, D> = Pool<'static, CodecResult<S, D>>;
/// Jobs a retained proof completes, awaiting submission of its copy, with their issuing span.
type PendingLocal<S, D> = BTreeMap<ResolutionJob, (Arc<ViewProof<S, D>>, Span)>;

/// Decodes an untrusted delivery on `strategy`, counting a worker panic as an invalid response so
/// a codec defect cannot stop the actor.
pub(super) async fn decode_delivery<St, S, D>(
    strategy: St,
    span: Span,
    response: oneshot::Sender<bool>,
    decode: impl FnOnce() -> Option<Vec<(ResolutionJob, ViewProof<S, D>)>> + Send + 'static,
) -> CodecResult<S, D>
where
    St: Strategy,
    S: Scheme,
    D: Digest,
{
    let (span, proofs) = offload(strategy, 1, span, move |_| decode()).await;
    let proofs = proofs.unwrap_or_else(|WorkerPanicked| {
        span.in_scope(|| error!("resolver decode worker panicked"));
        None
    });
    (span, CodecCompletion::Decoded { proofs, response })
}

/// Decodes an untrusted DA-certificate delivery on `strategy`, counting a worker panic as an
/// invalid response.
async fn decode_certificate_delivery<St, S, D>(
    strategy: St,
    span: Span,
    response: oneshot::Sender<bool>,
    decode: impl FnOnce() -> Option<Vec<(CertificateJob, DaCertificate<S, D>)>> + Send + 'static,
) -> CodecResult<S, D>
where
    St: Strategy,
    S: Scheme,
    D: Digest,
{
    let (span, certificates) = offload(strategy, 1, span, move |_| decode()).await;
    let certificates = certificates.unwrap_or_else(|WorkerPanicked| {
        span.in_scope(|| error!("resolver decode worker panicked"));
        None
    });
    (
        span,
        CodecCompletion::DecodedCertificate {
            certificates,
            response,
        },
    )
}

/// Runs codec work over locally held proofs on `strategy`. A worker panic is a local defect and
/// propagates.
async fn encode_local<St, S, D>(
    strategy: St,
    span: Span,
    operation: impl FnOnce() -> CodecCompletion<S, D> + Send + 'static,
) -> CodecResult<S, D>
where
    St: Strategy,
    S: Scheme,
    D: Digest,
{
    let (span, completion) = offload(strategy, 1, span, move |_| operation()).await;
    (span, completion.expect("resolver codec worker panicked"))
}

/// A peer delivery whose p2p response waits until the machine settles every job it completed.
struct Verdict {
    jobs: BTreeSet<Subscriber>,
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
pub(super) struct StoredProof<S: Scheme, D: Digest> {
    proof: Arc<ViewProof<S, D>>,
    canonical: Option<Bytes>,
}

impl<S: Scheme, D: Digest> From<ViewProof<S, D>> for StoredProof<S, D> {
    fn from(proof: ViewProof<S, D>) -> Self {
        Self {
            proof: Arc::new(proof),
            canonical: None,
        }
    }
}

impl<S: Scheme, D: Digest> Borrow<ViewProof<S, D>> for StoredProof<S, D> {
    fn borrow(&self) -> &ViewProof<S, D> {
        &self.proof
    }
}

/// In-memory view proofs this node serves to peers.
pub(super) type State<S, D> = Custody<S, D, StoredProof<S, D>>;

/// A durable DA certificate and its canonical encoding, cached once a peer requests it.
pub(super) struct StoredCertificate<S: Scheme, D: Digest> {
    certificate: Arc<DaCertificate<S, D>>,
    canonical: Option<Bytes>,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Returns an empty state that refuses exits at the genesis view.
    pub(super) fn new() -> Self {
        let mut state = Self::empty();
        state.prune(View::zero());
        state
    }

    /// Returns the retained proof that resolves `view`.
    pub(super) fn proof(&self, view: View) -> Option<Arc<ViewProof<S, D>>> {
        self.get(view).map(|stored| Arc::clone(&stored.proof))
    }

    /// Returns the cached canonical encoding of the proof that resolves `view`.
    fn canonical(&self, view: View) -> Option<Bytes> {
        self.get(view)
            .and_then(|stored| stored.canonical.as_ref().cloned())
    }

    /// Caches `canonical` as the encoding of `proof`, if `proof` is still retained.
    fn cache(&mut self, proof: &Arc<ViewProof<S, D>>, canonical: Bytes) {
        if let Some(stored) = self.get_mut(proof.view())
            && Arc::ptr_eq(&stored.proof, proof)
        {
            stored.canonical = Some(canonical);
        }
    }
}

/// Returns `certificate` if it answers a request for `chain` above `after` in `epoch`.
fn usable_certificate<S: Scheme, D: Digest>(
    epoch: Epoch,
    chain: ChainId,
    after: Height,
    certificate: DaCertificate<S, D>,
) -> Option<DaCertificate<S, D>> {
    let header = certificate.header();
    (header.epoch() == epoch && header.chain() == chain && header.height() > after)
        .then_some(certificate)
}

/// Returns `proof` if it can resolve `view`: an exit proof for exactly `view`, or an L-QC at or
/// above it.
fn usable_for<S: Scheme, D: Digest>(view: View, proof: ViewProof<S, D>) -> Option<ViewProof<S, D>> {
    let useful = match &proof {
        ViewProof::Nullification(proof) => proof.view() == view,
        ViewProof::Vqc(proof) => proof.view() == view,
        ViewProof::Lqc(proof) => proof.view() >= view,
    };
    useful.then_some(proof)
}

/// Fetches and serves view proofs for one fixed epoch.
pub(crate) struct Actor<E, H, P, S, B, T>
where
    E: Clock + Spawner + Metrics + Rng,
    H: Hasher,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: Generic<S>,
    blocker: B,
    strategy: T,
    fetch_timeout: NonZeroDuration,
    mailbox_size: NonZeroUsize,
    mailbox: mailbox::Receiver<Message<S, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<S, H::Digest>>,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, S, B, T> Actor<E, H, P, S, B, T>
where
    E: Clock + Spawner + Metrics + Rng,
    H: Hasher,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    /// Creates the resolver and its voter-facing control and query mailboxes.
    pub(crate) fn new(context: E, config: Config<S, B, T>) -> (Self, Mailbox<S, H::Digest>) {
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
        voter: Resolutions<S, H::Digest>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, network))
    }

    /// Starts the p2p engine over the committee and serves until shutdown.
    async fn run(
        self,
        voter: Resolutions<S, H::Digest>,
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
                fetch_timeout,
                // A timed-out or unusable response already cost a fetch, so the next peer is
                // tried at once, paced by the channel's rate limit.
                fetch_retry_delay: Duration::ZERO,
                priority_requests: true,
                priority_responses: true,
            },
        );
        let engine = engine.start(network);
        Service {
            context,
            epoch,
            codec: scheme.codec_config(),
            strategy,
            mailbox,
            queries,
            handler,
            fetcher,
            engine,
            voter,
            state: State::new(),
            certificates: BTreeMap::new(),
            outstanding: BTreeMap::new(),
            pending_local: PendingLocal::new(),
            verdicts: Vec::new(),
            codecs: CodecResults::default(),
            metrics,
            _hasher: PhantomData::<H>,
        }
        .run()
        .await;
    }
}

/// The running resolver: its inputs, the p2p fetcher, retained proofs, and in-flight work.
struct Service<E, H, P, S, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,
    epoch: Epoch,
    codec: CodecConfig,
    strategy: T,
    mailbox: mailbox::Receiver<Message<S, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<S, H::Digest>>,
    handler: mailbox::Receiver<HandlerMessage>,
    fetcher: p2p::Mailbox<ResolverKey, P, Subscriber>,
    engine: Handle<()>,
    voter: Resolutions<S, H::Digest>,
    state: State<S, H::Digest>,
    /// The durable DA certificate of each chain this node serves.
    certificates: BTreeMap<ChainId, StoredCertificate<S, H::Digest>>,
    outstanding: BTreeMap<Subscriber, Origin>,
    pending_local: PendingLocal<S, H::Digest>,
    verdicts: Vec<Verdict>,
    codecs: CodecResults<S, H::Digest>,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, S, T> Service<E, H, P, S, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    T: Strategy,
{
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.materialize_pending();
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
            Some(message) = self.handler.recv() else break => {
                match message {
                    HandlerMessage::Produce { key, response } => match key {
                        ResolverKey::View(view) => self.on_produce(view, response),
                        ResolverKey::Certificate { chain, after } => {
                            self.on_produce_certificate(chain, after, response);
                        }
                    },
                    HandlerMessage::Deliver {
                        delivery,
                        value,
                        response,
                    } => self.on_deliver(delivery, value, response),
                }
            },
        }
    }

    /// Starts copying the retained proofs of every pending local job.
    fn materialize_pending(&mut self) {
        while let Some((job, (proof, parent))) = self.pending_local.pop_first() {
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
    }

    /// Applies one finished codec job.
    fn on_codec(&mut self, completion: CodecCompletion<S, H::Digest>) {
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
                    let Some(origin) = self.outstanding.get(&Subscriber::View(job)) else {
                        continue;
                    };
                    jobs.insert(Subscriber::View(job));
                    self.complete(job, origin, proof);
                }
                if jobs.is_empty() {
                    response.send_lossy(true);
                } else {
                    self.verdicts.push(Verdict { jobs, response });
                }
            }
            CodecCompletion::DecodedCertificate {
                certificates: None,
                response,
            } => {
                self.metrics.mismatched.inc();
                response.send_lossy(false);
            }
            CodecCompletion::DecodedCertificate {
                certificates: Some(certificates),
                response,
            } => {
                let mut jobs = BTreeSet::new();
                for (job, certificate) in certificates {
                    let Some(origin) = self.outstanding.get(&Subscriber::Certificate(job)) else {
                        continue;
                    };
                    jobs.insert(Subscriber::Certificate(job));
                    self.complete_certificate(job, origin, certificate);
                }
                if jobs.is_empty() {
                    response.send_lossy(true);
                } else {
                    self.verdicts.push(Verdict { jobs, response });
                }
            }
            CodecCompletion::EncodedCertificate {
                certificate,
                value,
                response,
            } => {
                let chain = certificate.header().chain();
                if let Some(stored) = self.certificates.get_mut(&chain)
                    && Arc::ptr_eq(&stored.certificate, &certificate)
                {
                    stored.canonical = Some(value.clone());
                }
                self.metrics.served.inc();
                response.send_lossy(value);
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
                if let Some(origin) = self.outstanding.get(&Subscriber::View(job)) {
                    self.complete(job, origin, proof);
                }
            }
        }
    }

    /// Applies one control message from the voter.
    fn on_control(&mut self, message: Message<S, H::Digest>) {
        match message {
            Message::Resolve(request) => self.on_resolve(request),
            Message::Cancel { job } => self.retire(Subscriber::View(job), Outcome::Cancelled),
            Message::Reject { job } => {
                self.metrics.rejected.inc();
                self.retire(Subscriber::View(job), Outcome::Rejected);
            }
            Message::Retain { proof } => self.state.retain(proof),
            Message::Prune { through } => self.state.prune(through),
            Message::ResolveCertificate(request) => self.on_resolve_certificate(request),
            Message::CancelCertificate { job } => {
                self.retire(Subscriber::Certificate(job), Outcome::Cancelled);
            }
            Message::RejectCertificate { job } => {
                self.metrics.rejected.inc();
                self.retire(Subscriber::Certificate(job), Outcome::Rejected);
            }
            Message::RetainCertificate { certificate } => self.retain_certificate(certificate),
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
        if self.outstanding.contains_key(&Subscriber::View(job)) {
            return;
        }
        self.metrics.requests.inc();
        self.outstanding.insert(
            Subscriber::View(job),
            Origin {
                root: request.root,
                round: Some(request.round),
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
            key: ResolverKey::View(job.view()),
            subscriber: Subscriber::View(job),
            span,
        });
    }

    /// Starts one machine-issued DA-certificate request.
    ///
    /// The request is always fetched: a node asks only for a certificate above every one it
    /// holds, so its own retained certificate never answers it.
    fn on_resolve_certificate(&mut self, request: CertificateRequest) {
        let job = request.job;
        let subscriber = Subscriber::Certificate(job);
        if self.outstanding.contains_key(&subscriber) {
            return;
        }
        self.metrics.requests.inc();
        self.outstanding.insert(
            subscriber,
            Origin {
                root: request.root,
                round: None,
                started_at: self.context.current(),
            },
        );
        let span = info_span!(
            parent: &request.span,
            "multimmit.resolver.resolve_certificate.fetch",
            chain = job.chain().get().traced(),
            after = job.after().get().traced(),
            job = job.issued().id().get().traced(),
        );
        let _ = self.fetcher.fetch(Fetch {
            key: subscriber.key(),
            subscriber,
            span,
        });
    }

    /// Serves one durable DA certificate, replacing a lower one of its chain.
    fn retain_certificate(&mut self, certificate: DaCertificate<S, H::Digest>) {
        let chain = certificate.header().chain();
        let higher = self.certificates.get(&chain).is_none_or(|stored| {
            stored.certificate.header().height() < certificate.header().height()
        });
        if higher {
            self.certificates.insert(
                chain,
                StoredCertificate {
                    certificate: Arc::new(certificate),
                    canonical: None,
                },
            );
        }
    }

    /// Serves one peer request for `chain`'s DA certificate above `after`.
    fn on_produce_certificate(
        &mut self,
        chain: ChainId,
        after: Height,
        response: oneshot::Sender<Bytes>,
    ) {
        let Some(stored) = self
            .certificates
            .get(&chain)
            .filter(|stored| stored.certificate.header().height() > after)
        else {
            return;
        };
        if let Some(value) = &stored.canonical {
            self.metrics.served.inc();
            response.send_lossy(value.clone());
            return;
        }
        let span = info_span!(
            "multimmit.resolver.serve_certificate.encode",
            epoch = self.epoch.get().traced(),
            chain = chain.get().traced(),
        );
        let certificate = Arc::clone(&stored.certificate);
        let operation = move || CodecCompletion::EncodedCertificate {
            value: certificate.encode(),
            certificate,
            response,
        };
        self.codecs
            .push(encode_local(self.strategy.clone(), span, operation));
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

    /// Decodes one fetched value for every job subscribed to its key.
    fn on_deliver(
        &mut self,
        delivery: Delivery<ResolverKey, Subscriber>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let requested = match delivery.key {
            ResolverKey::View(view) => view,
            ResolverKey::Certificate { chain, after } => {
                return self.on_deliver_certificate(chain, after, delivery, value, response);
            }
        };
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
            let proof = ViewProof::<S, H::Digest>::decode_cfg(value, &codec)
                .ok()
                .and_then(|proof| usable_for(requested, proof))?;
            let jobs = delivery
                .subscribers
                .iter()
                .filter_map(|(subscriber, _)| match subscriber {
                    Subscriber::View(job) => Some(*job),
                    Subscriber::Certificate(_) => None,
                })
                .collect::<Vec<_>>();
            let proofs = repeat_n(proof, jobs.len()).zip(jobs).map(|(proof, job)| (job, proof));
            Some(proofs.collect())
        };
        self.codecs.push(decode_delivery(
            self.strategy.clone(),
            deliver,
            response,
            decode,
        ));
    }

    /// Decodes one fetched DA certificate for every job subscribed to `chain` above `after`.
    fn on_deliver_certificate(
        &mut self,
        chain: ChainId,
        after: Height,
        delivery: Delivery<ResolverKey, Subscriber>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let (_, cause) = delivery.subscribers.first();
        let deliver = info_span!(
            parent: cause,
            "multimmit.resolver.resolve_certificate.deliver",
            epoch = self.epoch.get().traced(),
            chain = chain.get().traced(),
            after = after.get().traced(),
        );
        for (_, cause) in delivery.subscribers.iter().skip(1) {
            deliver.follows_from(cause.id());
        }
        let (codec, epoch) = (self.codec, self.epoch);
        let decode = move || {
            let certificate = DaCertificate::<S, H::Digest>::decode_cfg(value, &codec)
                .ok()
                .and_then(|certificate| usable_certificate(epoch, chain, after, certificate))?;
            let jobs = delivery
                .subscribers
                .iter()
                .filter_map(|(subscriber, _)| match subscriber {
                    Subscriber::Certificate(job) => Some(*job),
                    Subscriber::View(_) => None,
                })
                .collect::<Vec<_>>();
            let certificates = repeat_n(certificate, jobs.len())
                .zip(jobs)
                .map(|(certificate, job)| (job, certificate));
            Some(certificates.collect())
        };
        self.codecs.push(decode_certificate_delivery(
            self.strategy.clone(),
            deliver,
            response,
            decode,
        ));
    }

    /// Hands one fetched DA certificate to the voter.
    fn complete_certificate(
        &self,
        job: CertificateJob,
        origin: &Origin,
        certificate: DaCertificate<S, H::Digest>,
    ) {
        self.metrics.resolved.inc();
        self.metrics
            .resolved_latency
            .observe_between(origin.started_at, self.context.current());
        let span = info_span!(
            "multimmit.resolver.resolve_certificate.complete",
            epoch = self.epoch.get().traced(),
            chain = job.chain().get().traced(),
        );
        let _ = self.voter.certified(
            origin.root.clone(),
            span,
            CertificateCompletion::new(job, certificate),
        );
    }

    /// Hands one resolved proof to the voter.
    fn complete(&self, job: ResolutionJob, origin: &Origin, proof: ViewProof<S, H::Digest>) {
        self.metrics.resolved.inc();
        self.metrics
            .resolved_latency
            .observe_between(origin.started_at, self.context.current());
        let completion = ResolutionCompletion::new(job.issued(), job.view(), proof);
        let round = origin
            .round
            .unwrap_or_else(|| Round::new(self.epoch, job.view()));
        let span = info_span!(
            "multimmit.resolver.resolve.complete",
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced()
        );
        let _ = self
            .voter
            .resolved(origin.root.clone(), span, round, completion);
    }

    /// Stops tracking one job the machine settled and answers the peer deliveries waiting on it.
    fn retire(&mut self, job: Subscriber, outcome: Outcome) {
        self.outstanding.remove(&job);
        if let Subscriber::View(view_job) = job {
            self.pending_local.remove(&view_job);
        }
        settle(&mut self.verdicts, job, outcome);
        let _ = self.fetcher.retain(move |_, candidate| *candidate != job);
    }
}

/// Answers every delivery whose verdict `job` decides.
///
/// A rejection settles each delivery carrying `job` as invalid. A cancellation settles a delivery
/// as valid once none of its jobs remain.
fn settle(verdicts: &mut Vec<Verdict>, job: Subscriber, outcome: Outcome) {
    let settled = verdicts.extract_if(.., |verdict| {
        verdict.jobs.remove(&job) && (outcome == Outcome::Rejected || verdict.jobs.is_empty())
    });
    for verdict in settled {
        verdict.response.send_lossy(outcome == Outcome::Cancelled);
    }
}
