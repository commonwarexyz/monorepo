use super::{
    Completed, Config, Drop, IngressLimits, Message, Observed,
    lanes::{Group, LaneId, Lanes},
    metrics::Metrics as ActorMetrics,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            metrics::Traffic,
            wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig},
        },
        config::CodecConfig,
        machine::{Artifact, IdentifiedArtifact, VerificationCompletion, VerifyJob},
        scheme::bls12381_threshold::Scheme,
        types::CertificateId,
    },
    types::{Attributable as _, Round, View},
};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::{Codec, EncodeSize as _, Write as _};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Receiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{
        metrics::{Histogram, HistogramExt as _},
        traces::TracedExt as _,
    },
};
use commonware_utils::{futures::Pool, sync::Mutex};
use futures::FutureExt as _;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, pending},
    marker::PhantomData,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::SystemTime,
};
use tracing::{Instrument as _, Span, debug, debug_span, error, info_span};

type PlaneReceiver<R, M, T> = DecodingReceiver<R, Envelope<M>, T>;
type VerifyResult<P, D> = (
    Span,
    Result<(VerificationCompletion<D>, Vec<P>), VerificationTaskPanicked>,
);
type VerifyResults<P, D> = Pool<'static, VerifyResult<P, D>>;
type DecodedMessage<P, M> = (P, Result<M, commonware_codec::Error>);

#[derive(Debug)]
struct VerificationTaskPanicked;

#[derive(Debug)]
struct IngressTaskPanicked;

/// A cancellation-safe bounded decoder. Submitted jobs remain owned by the receiver when a
/// different actor arm wins the surrounding select.
struct DecodingReceiver<R, M, T>
where
    R: Receiver,
    M: Codec + Send,
    T: Strategy,
{
    receiver: R,
    config: M::Cfg,
    strategy: T,
    jobs: Pool<'static, DecodedMessage<R::PublicKey, M>>,
    capacity: usize,
    closed: bool,
}

impl<R, M, T> DecodingReceiver<R, M, T>
where
    R: Receiver,
    M: Codec + Send + 'static,
    M::Cfg: Clone + Send + 'static,
    T: Strategy,
{
    fn new(receiver: R, config: M::Cfg, strategy: T) -> Self {
        let capacity = strategy.manual().parallelism();
        Self {
            receiver,
            config,
            strategy,
            jobs: Pool::default(),
            capacity,
            closed: false,
        }
    }

    async fn recv(&mut self, accept: bool) -> Option<DecodedMessage<R::PublicKey, M>> {
        loop {
            if !accept {
                return pending().await;
            }
            if self.closed {
                if self.jobs.is_empty() {
                    return None;
                }
                return Some(self.jobs.next_completed().await);
            }
            if self.jobs.len() >= self.capacity {
                return Some(self.jobs.next_completed().await);
            }
            select! {
                decoded = self.jobs.next_completed() => return Some(decoded),
                received = self.receiver.recv() => {
                    let Ok((peer, bytes)) = received else {
                        self.closed = true;
                        continue;
                    };
                    let config = self.config.clone();
                    self.jobs.push(self.strategy.manual().spawn(bytes.len(), move |_| {
                        (peer, M::decode_cfg(bytes, &config))
                    }));
                },
            }
        }
    }
}

async fn run_verification_operation<E, P, O, T>(
    context: E,
    strategy: P,
    completion_span: Span,
    worker_span: Span,
    operation: O,
) -> (Span, Result<T, VerificationTaskPanicked>)
where
    E: Send + 'static,
    P: Strategy,
    O: FnOnce(E, P) -> T + Send + 'static,
    T: Send + 'static,
{
    let instrument = worker_span.clone();
    let operation = async move {
        strategy
            .manual()
            .spawn(1, move |_| {
                worker_span.in_scope(|| operation(context, strategy))
            })
            .await
    };
    let outcome = AssertUnwindSafe(operation)
        .catch_unwind()
        .instrument(instrument)
        .await
        .map_err(|_| VerificationTaskPanicked);
    (completion_span, outcome)
}

/// Span label for a job that ran on the view-critical pool.
const CRITICAL_POOL: &str = "critical";
/// Span label for a job that ran on the bulk pool.
const BULK_POOL: &str = "bulk";

#[derive(Copy, Clone)]
enum NetworkPlane {
    Consensus,
    Certificate,
    Data,
}

impl NetworkPlane {
    const fn next(self) -> Self {
        match self {
            Self::Consensus => Self::Certificate,
            Self::Certificate => Self::Data,
            Self::Data => Self::Consensus,
        }
    }
}

enum NetworkMessage<P: PublicKey, V: Variant, D: commonware_cryptography::Digest> {
    Consensus(DecodedMessage<P, Envelope<ConsensusMessage<V, D>>>),
    Certificate(DecodedMessage<P, Envelope<CertificateMessage<V, D>>>),
    Data(DecodedMessage<P, Envelope<DataMessage<V, D>>>),
}

type PreparedIngress<V, D> = (LaneId, Group<V, D>);

#[derive(Copy, Clone)]
enum InvalidIngress {
    ProposalParent,
    Chain,
    DaVoteSigner,
}

impl InvalidIngress {
    const fn reason(self) -> &'static str {
        match self {
            Self::ProposalParent => "proposal exact parent mismatch",
            Self::Chain => "invalid chain",
            Self::DaVoteSigner => "data-availability vote from a peer that did not sign it",
        }
    }
}

type IngressResult<P, V, D> = (P, Result<PreparedIngress<V, D>, InvalidIngress>);
type IngressResults<P, V, D> = Pool<'static, Result<IngressResult<P, V, D>, IngressTaskPanicked>>;

async fn run_ingress_operation<O, R, T>(strategy: T, operation: O) -> Result<R, IngressTaskPanicked>
where
    O: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
    T: Strategy,
{
    AssertUnwindSafe(strategy.manual().spawn(1, move |_| operation()))
        .catch_unwind()
        .await
        .map_err(|_| IngressTaskPanicked)
}

impl<P: PublicKey, V: Variant, D: commonware_cryptography::Digest> NetworkMessage<P, V, D> {
    const fn plane(&self) -> NetworkPlane {
        match self {
            Self::Consensus(_) => NetworkPlane::Consensus,
            Self::Certificate(_) => NetworkPlane::Certificate,
            Self::Data(_) => NetworkPlane::Data,
        }
    }
}

/// Votes and novotes this batcher verified, by view, for certificate transcript discharge.
///
/// The machine attaches the votes it has already accepted when it admits a certificate, but at
/// scale the view's votes are usually still in this batcher's queue at that moment. Jobs consult
/// this cache as they start, when the same batcher has typically just verified those votes.
struct VerifiedVotes<V: Variant, D: Digest> {
    views: BTreeMap<View, Vec<Arc<Artifact<V, D>>>>,
    per_view: usize,
}

impl<V: Variant, D: Digest> VerifiedVotes<V, D> {
    /// Views kept behind the newest verified vote.
    const RETAINED_VIEWS: u64 = 16;

    const fn new(participants: usize) -> Self {
        Self {
            views: BTreeMap::new(),
            // One vote and one novote per participant bound a view's distinct messages.
            per_view: participants.saturating_mul(2),
        }
    }

    fn record(&mut self, artifact: &Arc<Artifact<V, D>>) {
        let Some(view) = artifact.view() else {
            return;
        };
        let messages = self.views.entry(view).or_default();
        if messages.len() < self.per_view {
            messages.push(Arc::clone(artifact));
        }
        while let Some((&first, _)) = self.views.first_key_value() {
            if first.get().saturating_add(Self::RETAINED_VIEWS) < view.get() {
                self.views.pop_first();
            } else {
                break;
            }
        }
    }

    fn known(&self, view: View) -> Vec<Arc<Artifact<V, D>>> {
        self.views.get(&view).cloned().unwrap_or_default()
    }
}

/// Bounded ingress and verification executor for one fixed epoch.
pub struct Actor<E, H, P, V, B, T, C>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
    C: Strategy,
{
    context: ContextCell<E>,

    scheme: Arc<Scheme<P, V>>,
    verified_votes: Arc<Mutex<VerifiedVotes<V, H::Digest>>>,
    blocker: B,
    strategy: T,
    critical_strategy: C,
    codec: CodecConfig,
    limits: IngressLimits,
    observation_capacity: usize,

    mailbox: mailbox::Receiver<Message<P, V, H::Digest>>,

    metrics: ActorMetrics,

    _hasher: PhantomData<H>,
}

impl<E, H, P, V, B, T, C> Actor<E, H, P, V, B, T, C>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
    C: Strategy,
{
    /// Creates the batcher and its control mailbox.
    pub fn new(
        context: E,
        config: Config<P, V, B, T, C>,
    ) -> (Self, mailbox::Sender<Message<P, V, H::Digest>>) {
        let metrics = ActorMetrics::new(&context);
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                verified_votes: Arc::new(Mutex::new(VerifiedVotes::new(
                    config.scheme.participants().as_ref().len(),
                ))),
                scheme: Arc::new(config.scheme),
                blocker: config.blocker,
                strategy: config.strategy,
                critical_strategy: config.critical_strategy,
                codec: config.codec,
                limits: config.limits,
                observation_capacity: config.observation_capacity.get(),
                mailbox: receiver,
                metrics,
                _hasher: PhantomData,
            },
            sender,
        )
    }

    /// Starts the batcher over already-registered fixed-epoch plane receivers.
    pub fn start(
        mut self,
        observations: mailbox::UnreliableSender<Observed<P, V, H::Digest>>,
        completions: mailbox::Sender<Completed<H::Digest>>,
        data: impl Receiver<PublicKey = P>,
        consensus: impl Receiver<PublicKey = P>,
        certificates: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(observations, completions, data, consensus, certificates)
        )
    }

    /// Prepares one verification job for the execution pool its items belong to.
    ///
    /// The completion carries the caller's span and the authenticated sources of every item the
    /// verdict rejected, so attribution stays with the job that produced it.
    fn verification<S: Strategy>(
        &self,
        strategy: S,
        pool: &'static str,
        span: Span,
        round: Round,
        job: VerifyJob<V, H::Digest>,
        sources: Vec<Option<P>>,
    ) -> impl Future<Output = VerifyResult<P, H::Digest>> + Send + 'static {
        let scheme = Arc::clone(&self.scheme);
        let latency = self.metrics.verify_latency.clone();
        let verified_vote_lag = self.metrics.verified_vote_lag.clone();
        let verified_votes = Arc::clone(&self.verified_votes);
        let transcript_messages = self.metrics.certificate_transcript_messages.clone();
        let known_messages = self.metrics.certificate_known_messages.clone();
        let worker = info_span!(
            parent: &span,
            "multimmit.batcher.verify",
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced(),
            job = job.id().get().traced(),
            items = job.items().len().traced(),
            pool,
        );
        let context = self.context.child("verify");
        let operation = move |mut context: E, strategy: S| {
            let timer = latency.timer(&context);
            let mut job = job;
            {
                let cache = verified_votes.lock();
                job.extend_known(|view| cache.known(view));
            }
            for item in job.items() {
                let signers = match item.artifact() {
                    Artifact::Vqc(certificate) => certificate.tally().signers().count(),
                    Artifact::Lqc(certificate) => certificate.tally().signers().count(),
                    _ => continue,
                };
                transcript_messages.observe(signers as f64);
                known_messages.observe(item.known().len() as f64);
            }
            let completion = job.verify::<_, P, H>(&mut context, &scheme, &strategy);
            {
                let mut cache = verified_votes.lock();
                for (item, verdict) in job.items().iter().zip(completion.verdicts()) {
                    if verdict.valid()
                        && matches!(item.artifact(), Artifact::Vote(_) | Artifact::NoVote(_))
                    {
                        cache.record(item.shared_artifact());
                    }
                }
            }
            Self::record_verified_votes(&job, &completion, round, &verified_vote_lag);
            let invalid_sources = completion
                .verdicts()
                .iter()
                .zip(sources)
                .filter_map(|(verdict, source)| (!verdict.valid()).then_some(source).flatten())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            timer.observe(&context);
            (completion, invalid_sources)
        };
        run_verification_operation(context, strategy, span, worker, operation)
    }

    async fn run(
        mut self,
        observations: mailbox::UnreliableSender<Observed<P, V, H::Digest>>,
        completions: mailbox::Sender<Completed<H::Digest>>,
        data: impl Receiver<PublicKey = P>,
        consensus: impl Receiver<PublicKey = P>,
        certificates: impl Receiver<PublicKey = P>,
    ) {
        let Ok(bounds) = self.codec.encoded_bounds::<V, H::Digest>() else {
            error!("failed to compute bounded ingress frame sizes");
            return;
        };
        let mut data: PlaneReceiver<_, DataMessage<V, H::Digest>, T> = DecodingReceiver::new(
            data,
            self.plane_config(bounds.max_data_frame_bytes(), ()),
            self.strategy.clone(),
        );
        let mut consensus: PlaneReceiver<_, ConsensusMessage<V, H::Digest>, T> =
            DecodingReceiver::new(
                consensus,
                self.plane_config(bounds.max_consensus_frame_bytes(), self.codec),
                self.strategy.clone(),
            );
        let mut certificates: PlaneReceiver<_, CertificateMessage<V, H::Digest>, T> =
            DecodingReceiver::new(
                certificates,
                self.plane_config(bounds.max_certificate_frame_bytes(), self.codec),
                self.strategy.clone(),
            );

        let mut lanes: Lanes<P, V, H::Digest> =
            Lanes::new(self.codec.chains(), self.codec.participants(), self.limits);
        let mut ingress: IngressResults<P, V, H::Digest> = Pool::default();
        let ingress_capacity = self.strategy.manual().parallelism();
        let mut accept_ingress;
        let mut jobs: VerifyResults<P, H::Digest> = Pool::default();
        let mut observations_inflight = 0usize;
        let mut next_network = NetworkPlane::Consensus;

        select_loop! {
            self.context,
            on_start => {
                accept_ingress = ingress.len() < ingress_capacity;
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::Verify {
                        span,
                        round,
                        job,
                        sources,
                    } => {
                        if jobs.len() >= self.limits.inflight_jobs.get() {
                            error!("verification job accounting exceeded its configured bound");
                            return;
                        }
                        self.metrics.batch_size.observe(job.items().len() as f64);
                        // The round waits on a view-critical verdict, so it executes on the pool
                        // reserved for view work instead of queueing behind bulk header and
                        // availability jobs.
                        if job.view_critical() {
                            let strategy = self.critical_strategy.clone();
                            jobs.push(self.verification(
                                strategy, CRITICAL_POOL, span, round, job, sources,
                            ));
                        } else {
                            let strategy = self.strategy.clone();
                            jobs.push(
                                self.verification(strategy, BULK_POOL, span, round, job, sources),
                            );
                        }
                    }
                    Message::Block { peers } => {
                        for peer in peers {
                            self.block(peer, "invalid data-availability share");
                        }
                    }
                    Message::ObservationConsumed => {
                        let Some(remaining) = observations_inflight.checked_sub(1) else {
                            error!("received an observation credit with no cohort in flight");
                            break;
                        };
                        observations_inflight = remaining;
                    }
                }
            },
            completion = jobs.next_completed() => {
                if !self.deliver(&completions, completion) {
                    break;
                }
            },
            identified = ingress.next_completed() => {
                let (peer, identified) = match identified {
                    Ok(identified) => identified,
                    Err(IngressTaskPanicked) => {
                        error!("ingress identification worker panicked");
                        break;
                    }
                };
                self.apply_prepared(&mut lanes, peer, identified);
            },
            Some(message) = Self::recv_network(
                accept_ingress,
                next_network,
                &mut data,
                &mut consensus,
                &mut certificates,
            ) else break => {
                let plane = message.plane();
                next_network = plane.next();
                match message {
                    NetworkMessage::Consensus((peer, message)) => {
                        let Ok(message) = message else {
                            self.block(peer, "consensus decoding error");
                            continue;
                        };
                        self.metrics.decoded.get_or_create(&Traffic::CONSENSUS).inc();
                        let message = NetworkMessage::Consensus((peer, Ok(message)));
                        let chains = self.codec.chains();
                        let scheme = Arc::clone(&self.scheme);
                        let received_at = self.context.current();
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains, &scheme, received_at)
                        }));
                    }
                    NetworkMessage::Certificate((peer, message)) => {
                        let Ok(message) = message else {
                            self.block(peer, "certificate decoding error");
                            continue;
                        };
                        self.metrics.decoded.get_or_create(&Traffic::CERTIFICATE).inc();
                        let message = NetworkMessage::Certificate((peer, Ok(message)));
                        let chains = self.codec.chains();
                        let scheme = Arc::clone(&self.scheme);
                        let received_at = self.context.current();
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains, &scheme, received_at)
                        }));
                    }
                    NetworkMessage::Data((peer, message)) => {
                        let Ok(message) = message else {
                            self.block(peer, "data decoding error");
                            continue;
                        };
                        self.metrics.decoded.get_or_create(&Traffic::DATA).inc();
                        let message = NetworkMessage::Data((peer, Ok(message)));
                        let chains = self.codec.chains();
                        let scheme = Arc::clone(&self.scheme);
                        let received_at = self.context.current();
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains, &scheme, received_at)
                        }));
                    }
                }
            },
            on_end => {
                // Forward buffered artifacts while the voter has observation credit. Ingress only
                // accumulates in the lanes while every credit is in flight, so batching follows
                // voter backpressure instead of a timer.
                if !self.flush_pending(&mut lanes, &observations, &mut observations_inflight) {
                    error!("voter observation path failed");
                    return;
                }
            },
        }
    }

    fn identify(
        artifact: Artifact<V, H::Digest>,
        scratch: &mut Vec<u8>,
    ) -> IdentifiedArtifact<V, H::Digest> {
        let id = artifact.id_with_scratch::<H>(scratch);
        (id, artifact)
    }

    /// Performs contextual frame checks and canonical artifact identification off the actor loop.
    fn prepare(
        message: NetworkMessage<P, V, H::Digest>,
        chains: usize,
        scheme: &Scheme<P, V>,
        received_at: SystemTime,
    ) -> IngressResult<P, V, H::Digest> {
        let mut scratch = Vec::new();
        let (peer, prepared) = match message {
            NetworkMessage::Consensus((peer, message)) => {
                let message = message.expect("only decoded messages enter identification");
                let prepared = match message.into_payload() {
                    ConsensusMessage::Proposal {
                        parent: None,
                        block,
                    } => Ok((
                        LaneId::Consensus,
                        Group::one(
                            Self::identify(Artifact::LeaderBlock(*block), &mut scratch),
                            received_at,
                        ),
                    )),
                    ConsensusMessage::Proposal {
                        parent: Some(parent),
                        block,
                    } => {
                        let certificate = *parent;
                        scratch.clear();
                        scratch.reserve(certificate.encode_size());
                        certificate.write(&mut scratch);
                        let parent_reference = CertificateId::new(H::hash(&[scratch.as_slice()]));
                        if parent_reference != block.block().parent() {
                            Err(InvalidIngress::ProposalParent)
                        } else {
                            let parent = Artifact::Vqc(certificate);
                            let parent_id = parent.id_from_canonical_encoding::<H>(&scratch);
                            let block = Artifact::LeaderBlock(*block);
                            let block_id = block.id_with_scratch::<H>(&mut scratch);
                            Ok((
                                LaneId::Consensus,
                                Group::pair([(parent_id, parent), (block_id, block)], received_at),
                            ))
                        }
                    }
                    message => {
                        let artifact = message
                            .into_artifacts()
                            .next()
                            .expect("non-proposal consensus messages contain one artifact");
                        Ok((
                            LaneId::Consensus,
                            Group::one(Self::identify(artifact, &mut scratch), received_at),
                        ))
                    }
                };
                (peer, prepared)
            }
            NetworkMessage::Certificate((peer, message)) => {
                let artifact = message
                    .expect("only decoded messages enter identification")
                    .into_payload()
                    .into_artifact();
                (
                    peer,
                    Ok((
                        LaneId::Certificate,
                        Group::one(Self::identify(artifact, &mut scratch), received_at),
                    )),
                )
            }
            NetworkMessage::Data((peer, message)) => {
                let message = message
                    .expect("only decoded messages enter identification")
                    .into_payload();
                let chain = message.chain().get() as usize;
                // A share is only ever sent by its own signer to the block's producer, and a
                // failed recovery attributes an invalid share to that signer index. Binding the
                // two here stops another peer from forging an index and having an honest
                // participant blocked for it.
                let forged = matches!(
                    &message,
                    DataMessage::DaVote(vote)
                        if scheme.participants().get(vote.signer().into()) != Some(&peer)
                );
                if chain >= chains {
                    (peer, Err(InvalidIngress::Chain))
                } else if forged {
                    (peer, Err(InvalidIngress::DaVoteSigner))
                } else {
                    let artifact = message.into_artifact();
                    (
                        peer,
                        Ok((
                            LaneId::Data(chain),
                            Group::one(Self::identify(artifact, &mut scratch), received_at),
                        )),
                    )
                }
            }
        };
        (peer, prepared)
    }

    fn apply_prepared(
        &mut self,
        lanes: &mut Lanes<P, V, H::Digest>,
        peer: P,
        prepared: Result<PreparedIngress<V, H::Digest>, InvalidIngress>,
    ) {
        match prepared {
            Ok((lane, group)) => self.buffer(lanes, lane, peer, group),
            Err(invalid) => self.block(peer, invalid.reason()),
        }
    }

    /// Receives one message, starting the biased scan after the plane selected last.
    async fn recv_network<DR, CR, RR>(
        enabled: bool,
        next: NetworkPlane,
        data: &mut PlaneReceiver<DR, DataMessage<V, H::Digest>, T>,
        consensus: &mut PlaneReceiver<CR, ConsensusMessage<V, H::Digest>, T>,
        certificates: &mut PlaneReceiver<RR, CertificateMessage<V, H::Digest>, T>,
    ) -> Option<NetworkMessage<P, V, H::Digest>>
    where
        DR: Receiver<PublicKey = P>,
        CR: Receiver<PublicKey = P>,
        RR: Receiver<PublicKey = P>,
    {
        match next {
            NetworkPlane::Consensus => {
                select! {
                    message = consensus.recv(enabled) => message.map(NetworkMessage::Consensus),
                    message = certificates.recv(enabled) => message.map(NetworkMessage::Certificate),
                    message = data.recv(enabled) => message.map(NetworkMessage::Data),
                }
            }
            NetworkPlane::Certificate => {
                select! {
                    message = certificates.recv(enabled) => message.map(NetworkMessage::Certificate),
                    message = data.recv(enabled) => message.map(NetworkMessage::Data),
                    message = consensus.recv(enabled) => message.map(NetworkMessage::Consensus),
                }
            }
            NetworkPlane::Data => {
                select! {
                    message = data.recv(enabled) => message.map(NetworkMessage::Data),
                    message = consensus.recv(enabled) => message.map(NetworkMessage::Consensus),
                    message = certificates.recv(enabled) => message.map(NetworkMessage::Certificate),
                }
            }
        }
    }

    /// Returns the envelope decode configuration for one plane.
    fn plane_config<Payload>(
        &self,
        max_frame_bytes: usize,
        payload: Payload,
    ) -> EnvelopeConfig<Payload> {
        EnvelopeConfig {
            max_frame_bytes,
            epoch: self.scheme.epoch(),
            payload,
        }
    }

    /// Counts and blocks one peer for invalid traffic.
    fn block(&mut self, peer: P, reason: &str) {
        self.metrics.blocked.inc();
        commonware_p2p::block!(self.blocker, peer, "{reason}");
    }

    /// Forwards one exact verification completion to the voter's accounted control path.
    ///
    /// Returns `false` when the worker failed or the voter is gone; both are fatal for the epoch.
    fn deliver(
        &mut self,
        completions: &mailbox::Sender<Completed<H::Digest>>,
        completion: VerifyResult<P, H::Digest>,
    ) -> bool {
        let (span, outcome) = completion;
        let (completion, invalid_sources) = match outcome {
            Ok(outcome) => outcome,
            Err(VerificationTaskPanicked) => {
                span.in_scope(|| error!("verification worker panicked"));
                return false;
            }
        };
        for peer in invalid_sources {
            self.block(peer, "cryptographic verification failed");
        }
        completions
            .enqueue(Completed { span, completion })
            .accepted()
    }

    /// Records how far each verified vote trails the job's round.
    ///
    /// The distribution answers the same question a per-participant gauge family did without
    /// paying one series per validator: a peer that stops keeping up widens the upper tail.
    fn record_verified_votes(
        job: &VerifyJob<V, H::Digest>,
        completion: &VerificationCompletion<H::Digest>,
        round: Round,
        lag: &Histogram,
    ) {
        for (item, verdict) in job.items().iter().zip(completion.verdicts()) {
            if !verdict.valid() {
                continue;
            }
            let artifact = item.artifact();
            if !matches!(artifact, Artifact::Vote(_) | Artifact::NoVote(_)) {
                continue;
            }
            let Some(view) = artifact.view() else {
                continue;
            };
            lag.observe(round.view().get().saturating_sub(view.get()) as f64);
        }
    }

    /// Atomically buffers one identified ingress group with bounded fairness accounting.
    fn buffer(
        &self,
        lanes: &mut Lanes<P, V, H::Digest>,
        lane: LaneId,
        peer: P,
        group: Group<V, H::Digest>,
    ) {
        let items = group.len() as u64;
        match lanes.push_group(lane, peer, group) {
            Ok(()) => {}
            Err(Drop::Lane) => {
                debug!(items, ?lane, "artifact group dropped by a full lane");
                self.metrics.dropped_lane.inc_by(items);
            }
            Err(Drop::Peer) => {
                debug!(
                    items,
                    ?lane,
                    "artifact group dropped by a peer item or byte budget"
                );
                self.metrics.dropped_peer.inc_by(items);
            }
        }
    }

    /// Flushes every buffered plane cohort permitted by the observation capacity.
    ///
    /// Cohorts are plane-pure, so one flush emits one cohort per buffered plane while credit
    /// remains.
    fn flush_pending(
        &self,
        lanes: &mut Lanes<P, V, H::Digest>,
        observations: &mailbox::UnreliableSender<Observed<P, V, H::Digest>>,
        observations_inflight: &mut usize,
    ) -> bool {
        while *observations_inflight < self.observation_capacity && lanes.items() > 0 {
            if !self.flush(lanes, observations, observations_inflight) {
                return false;
            }
        }
        true
    }

    /// Flushes one fair bounded cohort to the voter's unreliable observation mailbox.
    fn flush(
        &self,
        lanes: &mut Lanes<P, V, H::Digest>,
        observations: &mailbox::UnreliableSender<Observed<P, V, H::Digest>>,
        observations_inflight: &mut usize,
    ) -> bool {
        assert!(*observations_inflight < self.observation_capacity);
        let selected = lanes.flush(self.limits.cohort_items.get());
        if selected.is_empty() {
            return true;
        }
        let items = selected.len() as u64;
        let span = debug_span!("multimmit.batcher.observe", items);
        let now = self.context.current();
        // Admission already measured every artifact, so the cohort carries its encoded weight
        // and the voter never re-walks a decoded certificate to account for it.
        let mut bytes = 0usize;
        let cohort = selected
            .into_iter()
            .map(|selected| {
                bytes = bytes.saturating_add(selected.bytes);
                self.metrics
                    .ingress_dwell
                    .observe_between(selected.received_at, now);
                (selected.peer, selected.artifact)
            })
            .collect();
        match observations.enqueue(Observed {
            span,
            artifacts: cohort,
            bytes,
            forwarded_at: now,
        }) {
            Unreliable::Rejected => {
                self.metrics.dropped_voter_cohorts.inc();
                false
            }
            Unreliable::Outcome(Feedback::Closed | Feedback::Backoff) => false,
            Unreliable::Outcome(Feedback::Ok) => {
                *observations_inflight += 1;
                self.metrics.forwarded.inc_by(items);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::Rayon;
    use commonware_runtime::{Runner as _, Supervisor as _, tokio};
    use commonware_utils::sync::{Condvar, Mutex};
    use std::{num::NonZeroUsize, sync::Arc, thread};

    #[test]
    fn verified_votes_retain_a_bounded_window_per_view() {
        use crate::multimmit::{config::Limits, mocks::Committee};
        use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
        let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
        let vote = |view: u64, signer: usize| {
            Arc::new(Artifact::<MinPk, Digest>::Vote(
                committee.vote(signer, &committee.leader_block(view)),
            ))
        };
        let mut cache = VerifiedVotes::<MinPk, Digest>::new(2);

        // Distinct votes accumulate up to the per-view bound of one vote and one novote each.
        for signer in 0..5 {
            cache.record(&vote(5, signer));
        }
        assert_eq!(cache.known(View::new(5)).len(), 4);
        assert!(cache.known(View::new(6)).is_empty());

        // A vote sixteen views ahead keeps view 5; one more evicts it.
        cache.record(&vote(21, 0));
        assert_eq!(cache.known(View::new(5)).len(), 4);
        cache.record(&vote(22, 0));
        assert!(cache.known(View::new(5)).is_empty());
        assert_eq!(cache.known(View::new(21)).len(), 1);
    }

    #[derive(Default)]
    struct ServiceState {
        cpu_started: bool,
        async_serviced: bool,
        cpu_released: bool,
    }

    #[derive(Default)]
    struct ServiceProbe {
        state: Mutex<ServiceState>,
        changed: Condvar,
    }

    impl ServiceProbe {
        fn block_cpu(&self) {
            let mut state = self.state.lock();
            state.cpu_started = true;
            self.changed.notify_all();
            while !state.cpu_released {
                self.changed.wait(&mut state);
            }
        }

        fn service_async(&self) {
            let mut state = self.state.lock();
            state.async_serviced = true;
            self.changed.notify_all();
        }

        fn release_after_service(&self) {
            let mut state = self.state.lock();
            while !state.cpu_started || !state.async_serviced {
                self.changed.wait(&mut state);
            }
            state.cpu_released = true;
            self.changed.notify_all();
        }
    }

    fn rayon() -> Rayon {
        Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts")
    }

    #[test]
    fn verification_operation_runs_on_strategy_pool() {
        tokio::Runner::default().start(|context| async move {
            let (_, on_strategy) = run_verification_operation(
                context.child("verify"),
                rayon(),
                Span::none(),
                Span::none(),
                |_, _| rayon::current_thread_index().is_some(),
            )
            .await;
            let on_strategy = on_strategy.expect("verification worker completes");
            assert!(on_strategy, "verification ran outside the strategy pool");
        });
    }

    #[test]
    fn verification_operation_keeps_async_executor_serviceable() {
        let runner = tokio::Runner::new(tokio::Config::default().with_worker_threads(1));
        runner.start(|context| async move {
            let probe = Arc::new(ServiceProbe::default());
            let observer = {
                let probe = Arc::clone(&probe);
                thread::spawn(move || probe.release_after_service())
            };

            let verification = {
                let probe = Arc::clone(&probe);
                context.child("verification").spawn(move |context| {
                    run_verification_operation(
                        context,
                        rayon(),
                        Span::none(),
                        Span::none(),
                        move |_, _| {
                            probe.block_cpu();
                        },
                    )
                })
            };
            let service = context.child("service").spawn(move |_| async move {
                probe.service_async();
            });

            verification
                .await
                .expect("verification task completes")
                .1
                .expect("verification worker completes");
            service.await.expect("async service completes");
            observer.join().expect("observer completes");
        });
    }

    #[test]
    fn verification_operation_panic_is_reconciled() {
        tokio::Runner::default().start(|context| async move {
            let outcome = run_verification_operation(
                context.child("verify"),
                rayon(),
                Span::none(),
                Span::none(),
                |_, _| -> () { panic!("worker panic") },
            )
            .await;
            assert!(outcome.1.is_err());
        });
    }
}
