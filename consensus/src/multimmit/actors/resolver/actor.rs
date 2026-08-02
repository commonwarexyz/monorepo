use super::{Mailbox, Message, Query, Served, metrics::Metrics as ActorMetrics};
use crate::{
    Viewable as _,
    multimmit::{
        actors::voter,
        config::CodecConfig,
        machine::{ResolutionCompletion, ResolutionJob, ViewProof},
    },
    types::{Epoch, Round, View},
};
use bytes::Bytes;
use commonware_actor::mailbox::{self, Overflow, Policy};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Consumer, Delivery, Fetch, Resolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{metrics::HistogramExt as _, traces::TracedExt as _},
};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
    ordered::Set,
    sequence::U64,
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::pending as pending_forever,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, info_span};

/// Configuration for the resolver.
pub struct Config<P: PublicKey, B, T> {
    /// Serving candidates in participant order, including the local identity if present.
    pub peers: Vec<P>,
    /// The local identity.
    pub me: Option<P>,
    /// Peer blocker for invalid responses.
    pub blocker: B,
    /// The engine's immutable epoch.
    pub epoch: Epoch,
    /// Bounded decode configuration for the epoch.
    pub codec: CodecConfig,
    /// Execution strategy for proof codec work.
    pub strategy: T,
    /// Timeout and retry interval for unresolved peer fetches.
    pub fetch_timeout: Duration,
    /// Request mailbox capacity.
    pub mailbox_size: NonZeroUsize,
}

struct Origin {
    round: Round,
    started_at: SystemTime,
}

async fn receive_query<V: Variant, D: Digest>(
    queries: &mut mailbox::UnreliableReceiver<Query<V, D>>,
) -> Query<V, D> {
    match queries.recv().await {
        Some(query) => query,
        None => pending_forever().await,
    }
}

async fn receive_handler(
    receiver: &mut mailbox::Receiver<HandlerMessage>,
    ready: bool,
) -> Option<HandlerMessage> {
    if ready {
        receiver.recv().await
    } else {
        pending_forever().await
    }
}

enum HandlerMessage {
    Deliver {
        delivery: Delivery<U64, ResolutionJob>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

enum CodecCompletion<V: Variant, D: Digest> {
    Decoded {
        proofs: Option<Vec<(ResolutionJob, Served<V, D>)>>,
        response: oneshot::Sender<bool>,
    },
    Encoded {
        proof: Arc<Served<V, D>>,
        value: Bytes,
        response: oneshot::Sender<Bytes>,
    },
    Materialized {
        job: ResolutionJob,
        proof: Served<V, D>,
    },
}

type CodecResult<V, D> = (Span, CodecCompletion<V, D>);
type CodecResults<V, D> = Pool<CodecResult<V, D>>;

async fn run_codec_operation<P, O, V, D>(strategy: P, span: Span, operation: O) -> CodecResult<V, D>
where
    P: Strategy,
    O: FnOnce() -> CodecCompletion<V, D> + Send + 'static,
    V: Variant,
    D: Digest,
{
    let worker = span.clone();
    let completion = strategy.spawn(move |_| worker.in_scope(operation)).await;
    (span, completion)
}

impl HandlerMessage {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

#[derive(Default)]
struct HandlerPending(VecDeque<HandlerMessage>);

impl Overflow<HandlerMessage> for HandlerPending {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(HandlerMessage) -> Option<HandlerMessage>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }
            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl Policy for HandlerMessage {
    type Overflow = HandlerPending;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if matches!(&message, Self::Deliver { .. }) && !message.response_closed() {
            overflow.0.push_back(message);
        }
    }
}

#[derive(Clone)]
struct Handler {
    sender: mailbox::Sender<HandlerMessage>,
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Subscriber = ResolutionJob;
    type Outcome = bool;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(HandlerMessage::Deliver {
            delivery,
            value,
            response,
        });
        receiver
    }
}

impl p2p::Producer for Handler {
    type Key = U64;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(HandlerMessage::Produce {
            view: View::new(key.into()),
            response,
        });
        receiver
    }
}

struct Verdict {
    jobs: BTreeSet<ResolutionJob>,
    response: oneshot::Sender<bool>,
}

struct StoredProof<V: Variant, D: Digest> {
    proof: Arc<Served<V, D>>,
    canonical: Option<Bytes>,
}

impl<V: Variant, D: Digest> StoredProof<V, D> {
    fn new(proof: Served<V, D>) -> Self {
        Self {
            proof: Arc::new(proof),
            canonical: None,
        }
    }
}

/// Minimal volatile custody for view evidence.
pub(super) struct State<V: Variant, D: Digest> {
    floor: Option<StoredProof<V, D>>,
    exits: BTreeMap<View, StoredProof<V, D>>,
    retired: View,
}

impl<V: Variant, D: Digest> Default for State<V, D> {
    fn default() -> Self {
        Self {
            floor: None,
            exits: BTreeMap::new(),
            retired: View::zero(),
        }
    }
}

impl<V: Variant, D: Digest> State<V, D> {
    pub(super) fn retain(&mut self, proof: Served<V, D>) {
        match proof {
            ViewProof::Lqc(proof) => {
                if self
                    .floor
                    .as_ref()
                    .is_none_or(|current| proof.view() > current.proof.view())
                {
                    self.exits.retain(|view, _| *view > proof.view());
                    self.floor = Some(StoredProof::new(ViewProof::Lqc(proof)));
                }
            }
            proof @ ViewProof::Vqc(_) => {
                let view = proof.view();
                if view > self.retired
                    && self
                        .floor
                        .as_ref()
                        .is_none_or(|floor| view > floor.proof.view())
                {
                    self.exits.insert(view, StoredProof::new(proof));
                }
            }
            proof @ ViewProof::Nullification(_) => {
                let view = proof.view();
                if view > self.retired
                    && self
                        .floor
                        .as_ref()
                        .is_none_or(|floor| view > floor.proof.view())
                    && !matches!(
                        self.exits.get(&view).map(|stored| stored.proof.as_ref()),
                        Some(ViewProof::Vqc(_))
                    )
                {
                    self.exits.insert(view, StoredProof::new(proof));
                }
            }
        }
    }

    fn get(&self, view: View) -> Option<&StoredProof<V, D>> {
        if let Some(floor) = &self.floor
            && floor.proof.view() >= view
        {
            return Some(floor);
        }
        self.exits.get(&view)
    }

    pub(super) fn proof(&self, view: View) -> Option<Arc<Served<V, D>>> {
        self.get(view).map(|stored| Arc::clone(&stored.proof))
    }

    fn canonical(&self, view: View) -> Option<Bytes> {
        self.get(view)
            .and_then(|stored| stored.canonical.as_ref().cloned())
    }

    fn cache(&mut self, proof: &Arc<Served<V, D>>, canonical: Bytes) {
        if let Some(floor) = self.floor.as_mut()
            && Arc::ptr_eq(&floor.proof, proof)
        {
            floor.canonical = Some(canonical);
            return;
        }
        if let Some(stored) = self.exits.get_mut(&proof.view())
            && Arc::ptr_eq(&stored.proof, proof)
        {
            stored.canonical = Some(canonical);
        }
    }

    pub(super) fn prune(&mut self, through: View) {
        if through <= self.retired {
            return;
        }
        self.retired = through;
        self.exits.retain(|view, _| *view > through);
    }
}

/// View-checkpoint resolver for one fixed epoch.
pub struct Actor<E, H, P, V, B, T>
where
    E: Clock + Spawner + Metrics + BufferPooler,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,
    peers: Set<P>,
    me: Option<P>,
    blocker: Option<B>,
    epoch: Epoch,
    codec: CodecConfig,
    strategy: T,
    fetch_timeout: Duration,
    mailbox_size: NonZeroUsize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Query<V, H::Digest>>,
    state: State<V, H::Digest>,
    metrics: ActorMetrics,
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
    pub fn new(context: E, config: Config<P, B, T>) -> (Self, Mailbox<V, H::Digest>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let (query_sender, query_receiver) =
            mailbox::new_unreliable(context.child("queries"), config.mailbox_size);
        let peers =
            Set::try_from(config.peers).expect("resolver peers must be unique and non-empty");
        (
            Self {
                metrics: ActorMetrics::new(&context),
                context: ContextCell::new(context),
                peers,
                me: config.me,
                blocker: Some(config.blocker),
                epoch: config.epoch,
                codec: config.codec,
                strategy: config.strategy,
                fetch_timeout: config.fetch_timeout,
                mailbox_size: config.mailbox_size,
                mailbox: receiver,
                queries: query_receiver,
                state: State::default(),
            },
            Mailbox {
                control: sender,
                queries: query_sender,
            },
        )
    }

    /// Starts the resolver over the epoch's registered resolver plane.
    pub fn start(
        mut self,
        voter: mailbox::Sender<voter::Message<V, H::Digest>>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, network))
    }

    async fn run(
        mut self,
        voter: mailbox::Sender<voter::Message<V, H::Digest>>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (handler_sender, mut handler_receiver) =
            mailbox::new(self.context.as_ref().child("handler"), self.mailbox_size);
        let handler = Handler {
            sender: handler_sender,
        };
        let (engine, mut resolver) = p2p::Engine::new(
            self.context.as_ref().child("p2p"),
            p2p::Config {
                peer_provider: StaticProvider::new(self.epoch.get(), self.peers.clone()),
                blocker: self.blocker.take().expect("resolver blocker is installed"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                me: self.me.clone(),
                initial: self.fetch_timeout / 2,
                timeout: self.fetch_timeout,
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: true,
                priority_responses: false,
            },
        );
        let mut engine_task = engine.start(network);
        let mut outstanding = BTreeMap::<ResolutionJob, Origin>::new();
        let mut pending_local = BTreeMap::<ResolutionJob, (Arc<Served<V, H::Digest>>, Span)>::new();
        let mut verdicts = Vec::<Verdict>::new();
        let codec_capacity = self.strategy.manual().parallelism();
        let mut codecs = CodecResults::<V, H::Digest>::default();
        let mut handler_ready;

        select_loop! {
            self.context,
            on_start => {
                while codecs.len() < codec_capacity {
                    let Some((job, (proof, parent))) = pending_local.pop_first() else {
                        break;
                    };
                    let span = info_span!(
                        parent: &parent,
                        "multimmit.resolver.resolve.materialize",
                        view = job.view().get().traced(),
                        job = job.id().get().traced(),
                    );
                    let operation = move || CodecCompletion::Materialized {
                        job,
                        proof: proof.as_ref().clone(),
                    };
                    codecs.push(run_codec_operation(self.strategy.clone(), span, operation));
                }
                handler_ready = codecs.len() < codec_capacity;
            },
            on_stopped => { debug!("context shutdown, stopping resolver"); },
            _ = &mut engine_task => break,
            result = codecs.next_completed() => {
                let (span, completion) = result;
                span.in_scope(|| {
                    match completion {
                        CodecCompletion::Decoded { proofs: None, response } => {
                            self.metrics.mismatched.inc();
                            response.send_lossy(false);
                        }
                        CodecCompletion::Decoded { proofs: Some(proofs), response } => {
                            let mut jobs = BTreeSet::new();
                            for (job, proof) in proofs {
                                let Some(origin) = outstanding.get(&job) else {
                                    continue;
                                };
                                jobs.insert(job);
                                self.complete(&voter, job, origin, proof);
                            }
                            if jobs.is_empty() {
                                response.send_lossy(true);
                            } else {
                                verdicts.push(Verdict { jobs, response });
                            }
                        }
                        CodecCompletion::Encoded { proof, value, response } => {
                            self.state.cache(&proof, value.clone());
                            self.metrics.served.inc();
                            response.send_lossy(value);
                        }
                        CodecCompletion::Materialized { job, proof } => {
                            if let Some(origin) = outstanding.get(&job) {
                                self.complete(&voter, job, origin, proof);
                            }
                        }
                    }
                });
            },
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::Resolve(request) => {
                        let process = info_span!(
                            parent: &request.span,
                            "multimmit.resolver.resolve.process",
                            epoch = request.round.epoch().get().traced(),
                            view = request.round.view().get().traced(),
                            job = request.job.id().get().traced(),
                        );
                        process.in_scope(|| {
                            if outstanding.contains_key(&request.job) { return; }
                            self.metrics.requests.inc();
                            let job = request.job;
                            let origin = Origin {
                                round: request.round,
                                started_at: self.context.current(),
                            };
                            if let Some(proof) = self.state.proof(job.view()) {
                                outstanding.insert(job, origin);
                                pending_local.insert(job, (proof, process.clone()));
                                return;
                            }
                            outstanding.insert(job, origin);
                            Self::fetch(&mut resolver, job, &process);
                        });
                    }
                    Message::Cancel { job } => {
                        outstanding.remove(&job);
                        pending_local.remove(&job);
                        Self::settle(&mut verdicts, job, true);
                        let _ = resolver.retain(move |_, candidate| *candidate != job);
                    }
                    Message::Reject { job } => {
                        outstanding.remove(&job);
                        pending_local.remove(&job);
                        self.metrics.mismatched.inc();
                        Self::settle(&mut verdicts, job, false);
                        let _ = resolver.retain(move |_, candidate| *candidate != job);
                    }
                    Message::Retain { proof } => self.state.retain(proof),
                    Message::Prune { through } => self.state.prune(through),
                }
            },
            query = receive_query(&mut self.queries) => {
                match query {
                    Query::Serve { view, responder } => {
                        let _ = responder.send(self.state.proof(view));
                    }
                }
            },
            Some(message) = receive_handler(
                &mut handler_receiver,
                handler_ready,
            ) else break => {
                match message {
                    HandlerMessage::Produce { view, response } => {
                        if let Some(value) = self.state.canonical(view) {
                            self.metrics.served.inc();
                            response.send_lossy(value);
                        } else if let Some(proof) = self.state.proof(view) {
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
                            codecs.push(run_codec_operation(
                                self.strategy.clone(),
                                span,
                                operation,
                            ));
                        }
                    }
                    HandlerMessage::Deliver { delivery, value, response } => {
                        let requested = View::new(delivery.key.into());
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
                        let operation = move || {
                            let result = Served::<V, H::Digest>::decode_cfg(value, &codec)
                                .ok()
                                .and_then(|proof| Self::classify(requested, proof));
                            let proofs = result.map(|proof| {
                                let count = delivery.subscribers.len().get();
                                let mut proof = Some(proof);
                                delivery
                                    .subscribers
                                    .iter()
                                    .enumerate()
                                    .map(|(index, (job, _))| {
                                        let proof = if index + 1 == count {
                                            proof.take().expect("final resolver proof")
                                        } else {
                                            proof.as_ref().expect("resolver proof").clone()
                                        };
                                        (*job, proof)
                                    })
                                    .collect()
                            });
                            CodecCompletion::Decoded { proofs, response }
                        };
                        codecs.push(run_codec_operation(
                            self.strategy.clone(),
                            deliver,
                            operation,
                        ));
                    }
                }
            },
        }
    }

    fn fetch(
        resolver: &mut p2p::Mailbox<U64, P, ResolutionJob>,
        job: ResolutionJob,
        parent: &Span,
    ) {
        let span = info_span!(
            parent: parent,
            "multimmit.resolver.resolve.fetch",
            view = job.view().get().traced(),
            job = job.id().get().traced(),
        );
        let _ = resolver.fetch(Fetch {
            key: U64::new(job.view().get()),
            subscriber: job,
            span,
        });
    }

    fn classify(view: View, proof: Served<V, H::Digest>) -> Option<Served<V, H::Digest>> {
        let useful = match &proof {
            ViewProof::Nullification(proof) => proof.view() == view,
            ViewProof::Vqc(proof) => proof.view() == view,
            ViewProof::Lqc(proof) => proof.view() >= view,
        };
        useful.then_some(proof)
    }

    fn complete(
        &self,
        voter: &mailbox::Sender<voter::Message<V, H::Digest>>,
        job: ResolutionJob,
        origin: &Origin,
        proof: Served<V, H::Digest>,
    ) {
        self.metrics.resolved.inc();
        self.metrics
            .resolved_latency
            .observe_between(origin.started_at, self.context.current());
        let completion = ResolutionCompletion::new(job.id(), job.generation(), job.view(), proof);
        let span = info_span!(
            "multimmit.resolver.resolve.complete",
            epoch = origin.round.epoch().get().traced(),
            view = origin.round.view().get().traced()
        );
        let _ = voter.enqueue(voter::Message::Resolution {
            span,
            round: origin.round,
            completion,
        });
    }

    fn settle(verdicts: &mut Vec<Verdict>, job: ResolutionJob, accepted: bool) {
        let mut index = 0;
        while index < verdicts.len() {
            if !verdicts[index].jobs.remove(&job) {
                index += 1;
                continue;
            }
            if !accepted {
                verdicts.swap_remove(index).response.send_lossy(false);
            } else if verdicts[index].jobs.is_empty() {
                verdicts.swap_remove(index).response.send_lossy(true);
            } else {
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;

    #[test]
    fn handler_overflow_drops_peer_produce_requests() {
        let mut overflow = HandlerPending::default();
        let mut receivers = Vec::new();

        for view in 1..=64 {
            let (response, receiver) = oneshot::channel();
            <HandlerMessage as Policy>::handle(
                &mut overflow,
                HandlerMessage::Produce {
                    view: View::new(view),
                    response,
                },
            );
            receivers.push(receiver);
        }

        assert!(overflow.is_empty());
    }
}
