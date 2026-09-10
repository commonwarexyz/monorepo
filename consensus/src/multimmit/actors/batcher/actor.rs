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
        machine::{Artifact, VerificationCompletion, VerifyJob},
        scheme::bls12381_threshold::Scheme,
        types::CertificateId,
    },
    types::{Attributable as _, Round, View},
};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::{Decode as _, EncodeSize as _, Write as _};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Receiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, IoBuf, Metrics, Spawner, spawn_cell,
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
    future::Future,
    marker::PhantomData,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::SystemTime,
};
use tracing::{Instrument as _, Span, debug, debug_span, error, info_span};

type VerifyResult<P, D> = (
    Span,
    Result<(VerificationCompletion<D>, Vec<P>), VerificationTaskPanicked>,
);
type VerifyResults<P, D> = Pool<'static, VerifyResult<P, D>>;

#[derive(Debug)]
struct VerificationTaskPanicked;

#[derive(Debug)]
struct IngressTaskPanicked;

/// Owns bounded decode-and-identify jobs across cancellation of the network select.
struct IngressReceiver<E, R: Receiver, H: Hasher, V: Variant, T> {
    context: E,
    receiver: R,
    plane: NetworkPlane,
    config: EnvelopeConfig<CodecConfig>,
    scheme: Arc<Scheme<R::PublicKey, V>>,
    strategy: T,
    jobs: IngressResults<R::PublicKey, V, H::Digest>,
    capacity: usize,
    closed: bool,
}

impl<E: Clock, R: Receiver, H: Hasher, V: Variant, T: Strategy> IngressReceiver<E, R, H, V, T> {
    async fn recv(&mut self) -> Option<IngressCompletion<R::PublicKey, V, H::Digest>> {
        loop {
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
                prepared = self.jobs.next_completed() => return Some(prepared),
                received = self.receiver.recv() => {
                    let Ok((peer, bytes)) = received else {
                        self.closed = true;
                        continue;
                    };
                    let received_at = self.context.current();
                    let config = self.config.clone();
                    let plane = self.plane;
                    let scheme = Arc::clone(&self.scheme);
                    let strategy = self.strategy.clone();
                    // The catch boundary includes submission because a strategy may run inline.
                    let operation = async move {
                        let strategy = strategy.manual();
                        strategy.spawn(bytes.len(), move |_| {
                            let prepared = Self::prepare(plane, &peer, bytes, &config, &scheme, received_at);
                            (peer, prepared)
                        }).await
                    };
                    self.jobs.push(AssertUnwindSafe(operation).catch_unwind().map(|outcome| {
                        outcome.map_err(|_| IngressTaskPanicked)
                    }));
                },
            }
        }
    }

    /// Checks contextual frame constraints and identifies an entire atomic ingress group.
    fn prepare(
        plane: NetworkPlane,
        peer: &R::PublicKey,
        bytes: IoBuf,
        config: &EnvelopeConfig<CodecConfig>,
        scheme: &Scheme<R::PublicKey, V>,
        received_at: SystemTime,
    ) -> Result<PreparedIngress<V, H::Digest>, InvalidIngress> {
        let mut scratch = Vec::new();
        match plane {
            NetworkPlane::Consensus => {
                let message = Envelope::<ConsensusMessage<V, H::Digest>>::decode_cfg(bytes, config)
                    .map_err(|_| InvalidIngress::Decode)?;
                match message.into_payload() {
                    ConsensusMessage::Proposal {
                        parent: None,
                        block,
                    } => Ok((
                        LaneId::Consensus,
                        Group::one(
                            Artifact::LeaderBlock(*block).identify::<H>(&mut scratch),
                            received_at,
                        ),
                    )),
                    ConsensusMessage::Proposal {
                        parent: Some(parent),
                        block,
                    } => {
                        let certificate = *parent;
                        scratch.reserve(certificate.encode_size());
                        certificate.write(&mut scratch);
                        let parent_reference = CertificateId::new(H::hash(&[scratch.as_slice()]));
                        if parent_reference != block.block().parent() {
                            return Err(InvalidIngress::ProposalParent);
                        }
                        let parent = Artifact::Vqc(certificate)
                            .identify_from_canonical_encoding::<H>(&scratch);
                        let block = Artifact::LeaderBlock(*block).identify::<H>(&mut scratch);
                        Ok((LaneId::Consensus, Group::pair([parent, block], received_at)))
                    }
                    message => {
                        let artifact = message
                            .into_artifacts()
                            .next()
                            .expect("non-proposal consensus messages contain one artifact");
                        Ok((
                            LaneId::Consensus,
                            Group::one(artifact.identify::<H>(&mut scratch), received_at),
                        ))
                    }
                }
            }
            NetworkPlane::Certificate => {
                let artifact =
                    Envelope::<CertificateMessage<V, H::Digest>>::decode_cfg(bytes, config)
                        .map_err(|_| InvalidIngress::Decode)?
                        .into_payload()
                        .into_artifact();
                Ok((
                    LaneId::Certificate,
                    Group::one(artifact.identify::<H>(&mut scratch), received_at),
                ))
            }
            NetworkPlane::Data => {
                let chains = config.payload.chains();
                let config = EnvelopeConfig {
                    max_frame_bytes: config.max_frame_bytes,
                    epoch: config.epoch,
                    payload: (),
                };
                let message = Envelope::<DataMessage<V, H::Digest>>::decode_cfg(bytes, &config)
                    .map_err(|_| InvalidIngress::Decode)?
                    .into_payload();
                let chain = message.chain().get() as usize;
                // Recovery attributes invalid shares to signer indices, so ingress binds each
                // share to its authenticated sender before it can enter a recovery job.
                let forged = matches!(&message, DataMessage::DaVote(vote)
                    if scheme.participants().get(vote.signer().into()) != Some(peer));
                if chain >= chains {
                    return Err(InvalidIngress::Chain);
                }
                if forged {
                    return Err(InvalidIngress::DaVoteSigner);
                }
                Ok((
                    LaneId::Data(chain),
                    Group::one(
                        message.into_artifact().identify::<H>(&mut scratch),
                        received_at,
                    ),
                ))
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

type PreparedIngress<V, D> = (LaneId, Group<V, D>);

#[derive(Copy, Clone, Debug)]
enum InvalidIngress {
    Decode,
    ProposalParent,
    Chain,
    DaVoteSigner,
}

impl InvalidIngress {
    const fn reason(self, plane: NetworkPlane) -> &'static str {
        match self {
            Self::Decode => match plane {
                NetworkPlane::Consensus => "consensus decoding error",
                NetworkPlane::Certificate => "certificate decoding error",
                NetworkPlane::Data => "data decoding error",
            },
            Self::ProposalParent => "proposal exact parent mismatch",
            Self::Chain => "invalid chain",
            Self::DaVoteSigner => "data-availability vote from a peer that did not sign it",
        }
    }
}

type IngressResult<P, V, D> = (P, Result<PreparedIngress<V, D>, InvalidIngress>);
type IngressCompletion<P, V, D> = Result<IngressResult<P, V, D>, IngressTaskPanicked>;
type IngressResults<P, V, D> = Pool<'static, IngressCompletion<P, V, D>>;

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
        let mut data =
            self.ingress_receiver(data, NetworkPlane::Data, bounds.max_data_frame_bytes());
        let mut consensus = self.ingress_receiver(
            consensus,
            NetworkPlane::Consensus,
            bounds.max_consensus_frame_bytes(),
        );
        let mut certificates = self.ingress_receiver(
            certificates,
            NetworkPlane::Certificate,
            bounds.max_certificate_frame_bytes(),
        );

        let mut lanes: Lanes<P, V, H::Digest> =
            Lanes::new(self.codec.chains(), self.codec.participants(), self.limits);
        let ingress_budget = self.strategy.manual().parallelism();
        let mut jobs: VerifyResults<P, H::Digest> = Pool::default();
        let mut observations_inflight = 0usize;
        let mut next_network = NetworkPlane::Consensus;

        select_loop! {
            self.context,
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
                    Message::ObservationsConsumed(count) => {
                        let Some(remaining) = observations_inflight.checked_sub(count) else {
                            error!("received more observation credits than cohorts in flight");
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
            Some((plane, prepared)) = Self::recv_network(
                next_network, &mut data, &mut consensus, &mut certificates,
            ) else break => {
                if self.apply_ready_ingress(
                    &mut lanes, (plane, prepared), &mut next_network,
                    [&mut consensus.jobs, &mut certificates.jobs, &mut data.jobs], ingress_budget,
                ).is_err() {
                    error!("ingress worker panicked");
                    break;
                }
            },
            on_end => {
                // Forward buffered artifacts while the voter has observation credit. Cohorts
                // collect ready ingress and any backlog retained while credits were in flight.
                if !self.flush_pending(&mut lanes, &observations, &mut observations_inflight) {
                    error!("voter observation path failed");
                    return;
                }
            },
        }
    }

    /// Buffers only ready completions, rotating planes within a bounded actor turn.
    fn apply_ready_ingress(
        &mut self,
        lanes: &mut Lanes<P, V, H::Digest>,
        first: (NetworkPlane, IngressCompletion<P, V, H::Digest>),
        next: &mut NetworkPlane,
        ingress: [&mut IngressResults<P, V, H::Digest>; 3],
        capacity: usize,
    ) -> Result<(), IngressTaskPanicked> {
        let mut ready = Some(first);
        for _ in 0..capacity {
            let Some((plane, outcome)) = ready.take().or_else(|| {
                let mut plane = *next;
                for _ in 0..3 {
                    if let Some(outcome) = ingress[plane as usize].next_completed().now_or_never() {
                        return Some((plane, outcome));
                    }
                    plane = plane.next();
                }
                None
            }) else {
                break;
            };
            *next = plane.next();
            let (peer, prepared) = outcome?;
            if !matches!(prepared, Err(InvalidIngress::Decode)) {
                self.metrics
                    .decoded
                    .get_or_create(&match plane {
                        NetworkPlane::Consensus => Traffic::CONSENSUS,
                        NetworkPlane::Certificate => Traffic::CERTIFICATE,
                        NetworkPlane::Data => Traffic::DATA,
                    })
                    .inc();
            }
            match prepared {
                Ok((lane, group)) => self.buffer(lanes, lane, peer, group),
                Err(invalid) => self.block(peer, invalid.reason(plane)),
            }
        }
        Ok(())
    }

    /// Receives one message, starting the biased scan after the plane selected last.
    async fn recv_network<DR, CR, RR>(
        next: NetworkPlane,
        data: &mut IngressReceiver<E, DR, H, V, T>,
        consensus: &mut IngressReceiver<E, CR, H, V, T>,
        certificates: &mut IngressReceiver<E, RR, H, V, T>,
    ) -> Option<(NetworkPlane, IngressCompletion<P, V, H::Digest>)>
    where
        DR: Receiver<PublicKey = P>,
        CR: Receiver<PublicKey = P>,
        RR: Receiver<PublicKey = P>,
    {
        match next {
            NetworkPlane::Consensus => {
                select! {
                    message = consensus.recv() => message.map(|result| (NetworkPlane::Consensus, result)),
                    message = certificates.recv() => message.map(|result| (NetworkPlane::Certificate, result)),
                    message = data.recv() => message.map(|result| (NetworkPlane::Data, result)),
                }
            }
            NetworkPlane::Certificate => {
                select! {
                    message = certificates.recv() => message.map(|result| (NetworkPlane::Certificate, result)),
                    message = data.recv() => message.map(|result| (NetworkPlane::Data, result)),
                    message = consensus.recv() => message.map(|result| (NetworkPlane::Consensus, result)),
                }
            }
            NetworkPlane::Data => {
                select! {
                    message = data.recv() => message.map(|result| (NetworkPlane::Data, result)),
                    message = consensus.recv() => message.map(|result| (NetworkPlane::Consensus, result)),
                    message = certificates.recv() => message.map(|result| (NetworkPlane::Certificate, result)),
                }
            }
        }
    }

    fn ingress_receiver<R: Receiver<PublicKey = P>>(
        &self,
        receiver: R,
        plane: NetworkPlane,
        max_frame_bytes: usize,
    ) -> IngressReceiver<E, R, H, V, T> {
        let context = self.context.child("ingress").with_attribute(
            "plane",
            match plane {
                NetworkPlane::Consensus => "consensus",
                NetworkPlane::Certificate => "certificate",
                NetworkPlane::Data => "data",
            },
        );
        IngressReceiver {
            context,
            receiver,
            plane,
            config: EnvelopeConfig {
                max_frame_bytes,
                epoch: self.scheme.epoch(),
                payload: self.codec,
            },
            scheme: Arc::clone(&self.scheme),
            strategy: self.strategy.clone(),
            jobs: Pool::default(),
            capacity: self.strategy.manual().parallelism(),
            closed: false,
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
    use crate::multimmit::{
        config::Limits,
        mocks::{Committee, RecordingBlocker},
    };
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, ed25519};
    use commonware_parallel::{
        Rayon, Sequential,
        mocks::{self, CountingStrategy},
    };
    use commonware_runtime::{IoBuf, Runner as _, Supervisor as _, deterministic, tokio};
    use commonware_utils::sync::{Condvar, Mutex};
    use std::{collections::VecDeque, future::pending, num::NonZeroUsize, sync::Arc, thread};

    type IngressActor<H = Sha256, T = Sequential> = Actor<
        deterministic::Context,
        H,
        ed25519::PublicKey,
        MinPk,
        RecordingBlocker,
        T,
        Sequential,
    >;

    fn ingress_actor<H: Hasher<Digest = <Sha256 as Hasher>::Digest>, T: Strategy>(
        context: deterministic::Context,
        committee: &Committee<MinPk>,
        strategy: T,
    ) -> IngressActor<H, T> {
        Actor::new(
            context,
            Config {
                scheme: committee.verifier.clone(),
                blocker: RecordingBlocker::default(),
                strategy,
                critical_strategy: Sequential,
                codec: committee.codec(),
                limits: IngressLimits {
                    cohort_items: NonZeroUsize::new(2).unwrap(),
                    lane_items: NonZeroUsize::new(16).unwrap(),
                    lane_bytes: NonZeroUsize::new(64 * 1024).unwrap(),
                    inflight_jobs: NonZeroUsize::new(2).unwrap(),
                },
                mailbox_size: NonZeroUsize::new(4).unwrap(),
                observation_capacity: NonZeroUsize::MIN,
            },
        )
        .0
    }

    #[test]
    fn ready_ingress_batches_before_flush_without_waiting() {
        for (capacity, ready, pending_tail) in
            [(1, 1, false), (4, 4, false), (4, 2, true), (4, 5, false)]
        {
            deterministic::Runner::default().start(move |context| async move {
                let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
                let mut actor =
                    ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
                let mut lanes = Lanes::new(
                    actor.codec.chains(),
                    actor.codec.participants(),
                    actor.limits,
                );
                let mut ingress = IngressResults::default();
                let mut certificates = IngressResults::default();
                let mut data = IngressResults::default();
                let mut next = NetworkPlane::Consensus;
                let mut expected_bytes = 0;
                let admitted = ready.min(capacity);
                let now = context.current();
                for view in 0..ready {
                    let artifact = Artifact::NoVote(committee.novote(1, view as u64 + 1));
                    if view < admitted {
                        expected_bytes += artifact.encoded_len();
                    }
                    ingress.push(std::future::ready(Ok((
                        committee.identities[1].clone(),
                        Ok((
                            LaneId::Consensus,
                            Group::one(artifact.identify::<Sha256>(&mut Vec::new()), now),
                        )),
                    ))));
                }
                if pending_tail {
                    ingress.push(pending());
                }
                let first = ingress
                    .next_completed()
                    .now_or_never()
                    .expect("first completion is ready");
                actor
                    .apply_ready_ingress(
                        &mut lanes,
                        (NetworkPlane::Consensus, first),
                        &mut next,
                        [&mut ingress, &mut certificates, &mut data],
                        capacity,
                    )
                    .unwrap();
                assert_eq!(lanes.items(), admitted);
                assert_eq!(ingress.len(), ready - admitted + usize::from(pending_tail));
                assert_eq!(context.current(), now);

                let (sender, mut observations) =
                    mailbox::new_unreliable(context.child("observations"), NonZeroUsize::MIN);
                let mut inflight = 0;
                let mut forwarded = 0;
                let mut bytes = 0;
                while lanes.items() > 0 {
                    assert!(actor.flush_pending(&mut lanes, &sender, &mut inflight));
                    assert_eq!(inflight, 1);
                    let cohort = observations
                        .try_recv()
                        .expect("ready ingress flushes with credit");
                    assert_eq!(cohort.artifacts.len(), (admitted - forwarded).min(2));
                    forwarded += cohort.artifacts.len();
                    bytes += cohort.bytes;
                    assert!(actor.flush_pending(&mut lanes, &sender, &mut inflight));
                    assert!(
                        observations.try_recv().is_err(),
                        "held credit prevents another cohort"
                    );
                    assert_eq!(lanes.items(), admitted - forwarded);
                    inflight -= 1;
                }
                assert_eq!(forwarded, admitted);
                assert_eq!(bytes, expected_bytes);
                assert_eq!(context.current(), now);
            });
        }
    }

    #[test]
    fn ready_ingress_rotates_after_invalid_results_and_stops_at_budget() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
            let mut actor =
                ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
            let mut lanes = Lanes::new(
                actor.codec.chains(),
                actor.codec.participants(),
                actor.limits,
            );
            let mut consensus = IngressResults::default();
            let mut certificates = IngressResults::default();
            let mut data = IngressResults::default();
            let mut next = NetworkPlane::Consensus;
            let now = context.current();
            let peer = committee.identities[1].clone();
            let prepared = |lane, artifact: Artifact<MinPk, <Sha256 as Hasher>::Digest>| {
                Ok((
                    peer.clone(),
                    Ok((
                        lane,
                        Group::one(artifact.identify::<Sha256>(&mut Vec::new()), now),
                    )),
                ))
            };
            for view in 2..=3 {
                consensus.push(std::future::ready(prepared(
                    LaneId::Consensus,
                    Artifact::NoVote(committee.novote(1, view)),
                )));
            }
            certificates.push(std::future::ready(Ok((
                peer.clone(),
                Err(InvalidIngress::Decode),
            ))));
            certificates.push(std::future::ready(prepared(
                LaneId::Certificate,
                Artifact::Vqc(committee.vqc(1)),
            )));
            data.push(std::future::ready(prepared(
                LaneId::Data(0),
                Artifact::TransactionBlock(committee.signed_block(1, Sha256::hash(&[b"data"]))),
            )));
            data.push(pending());
            let first = prepared(LaneId::Consensus, Artifact::NoVote(committee.novote(1, 1)));
            actor
                .apply_ready_ingress(
                    &mut lanes,
                    (NetworkPlane::Consensus, first),
                    &mut next,
                    [&mut consensus, &mut certificates, &mut data],
                    3,
                )
                .unwrap();
            assert_eq!(next, NetworkPlane::Consensus);
            assert_eq!(lanes.items(), 2);
            assert_eq!((consensus.len(), certificates.len(), data.len()), (2, 1, 1));
            assert_eq!(actor.blocker.blocked(), vec![peer]);
            let first = consensus.next_completed().now_or_never().unwrap();
            actor
                .apply_ready_ingress(
                    &mut lanes,
                    (NetworkPlane::Consensus, first),
                    &mut next,
                    [&mut consensus, &mut certificates, &mut data],
                    4,
                )
                .unwrap();
            assert_eq!(next, NetworkPlane::Certificate);
            assert_eq!(lanes.items(), 5);
            assert_eq!((consensus.len(), certificates.len(), data.len()), (0, 0, 1));
            assert_eq!(context.current(), now);
        });
    }

    #[test]
    fn ready_ingress_propagates_worker_panics() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
            let mut actor =
                ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
            let mut lanes = Lanes::new(
                actor.codec.chains(),
                actor.codec.participants(),
                actor.limits,
            );
            let mut ingress = IngressResults::default();
            let mut certificates = IngressResults::default();
            let mut data = IngressResults::default();
            let mut next = NetworkPlane::Consensus;
            assert!(
                actor
                    .apply_ready_ingress(
                        &mut lanes,
                        (NetworkPlane::Consensus, Err(IngressTaskPanicked)),
                        &mut next,
                        [&mut ingress, &mut certificates, &mut data],
                        4
                    )
                    .is_err()
            );
            assert_eq!(lanes.items(), 0);

            ingress.push(std::future::ready(Err(IngressTaskPanicked)));
            let artifact = Artifact::NoVote(committee.novote(1, 1));
            let first = Ok((
                committee.identities[1].clone(),
                Ok((
                    LaneId::Consensus,
                    Group::one(
                        artifact.identify::<Sha256>(&mut Vec::new()),
                        context.current(),
                    ),
                )),
            ));
            assert!(
                actor
                    .apply_ready_ingress(
                        &mut lanes,
                        (NetworkPlane::Consensus, first),
                        &mut next,
                        [&mut ingress, &mut certificates, &mut data],
                        4
                    )
                    .is_err()
            );
            assert_eq!(lanes.items(), 1);
            assert!(ingress.is_empty());
        });
    }

    #[derive(Debug, Default)]
    struct RawReceiver(VecDeque<(ed25519::PublicKey, IoBuf)>);

    impl Receiver for RawReceiver {
        type Error = std::io::Error;
        type PublicKey = ed25519::PublicKey;

        async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
            self.0
                .pop_front()
                .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
        }
    }

    #[test]
    fn ingress_envelope_shares_payload_buffer() {
        let payload = Bytes::from(vec![42; 96]);
        let epoch = crate::types::Epoch::new(1);
        let encoded = Envelope::new(epoch, payload.clone()).encode();
        let expected = encoded[encoded.len() - payload.len()..].as_ptr();
        let decoded = Envelope::<Bytes>::decode_cfg(
            IoBuf::from(encoded.clone()),
            &EnvelopeConfig {
                max_frame_bytes: encoded.len(),
                epoch,
                payload: (..=payload.len()).into(),
            },
        )
        .unwrap()
        .into_payload();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.as_ptr(), expected);
    }

    #[test]
    fn ingress_submits_once_per_frame() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
            let strategy = CountingStrategy::default();
            let actor =
                ingress_actor::<Sha256, _>(context.child("batcher"), &committee, strategy.clone());
            let parent = committee.vqc(1);
            let block = committee.leader_block_with_parent(2, &parent);
            let frame = Envelope::new(
                committee.config.epoch(),
                ConsensusMessage::Proposal {
                    parent: Some(Box::new(parent)),
                    block: Box::new(block),
                },
            )
            .encode();
            let peer = committee.identities[1].clone();
            let raw = RawReceiver(VecDeque::from([
                (peer.clone(), IoBuf::from(frame)),
                (peer.clone(), IoBuf::from(Bytes::from_static(b"invalid"))),
            ]));
            let bounds = committee
                .codec()
                .encoded_bounds::<MinPk, <Sha256 as Hasher>::Digest>()
                .unwrap();
            let mut receiver = actor.ingress_receiver(
                raw,
                NetworkPlane::Consensus,
                bounds.max_consensus_frame_bytes(),
            );
            let (from, prepared) = receiver.recv().await.unwrap().unwrap();
            assert_eq!(from, peer);
            let (lane, group) = prepared.unwrap();
            assert_eq!(lane, LaneId::Consensus);
            assert_eq!(group.len(), 2);
            assert_eq!(strategy.spawns(), 1);
            let (_, malformed) = receiver.recv().await.unwrap().unwrap();
            assert!(matches!(malformed, Err(InvalidIngress::Decode)));
            assert_eq!(strategy.spawns(), 2);
            assert!(receiver.recv().await.is_none());
        });
    }

    #[test]
    fn cancelled_ingress_receives_preserve_each_planes_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
            let strategy = rayon();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let manual = strategy.manual();
            let blockers = (0..2)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    manual.spawn(1, move |_| {
                        barrier.wait();
                        barrier.wait();
                    })
                })
                .collect::<Vec<_>>();
            barrier.wait();
            let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, strategy);
            let peer = committee.identities[1].clone();
            let mut receivers = [
                NetworkPlane::Consensus,
                NetworkPlane::Certificate,
                NetworkPlane::Data,
            ]
            .map(|plane| {
                let raw = RawReceiver(
                    (0..3)
                        .map(|_| (peer.clone(), IoBuf::from(Bytes::from_static(b"invalid"))))
                        .collect(),
                );
                actor.ingress_receiver(raw, plane, 1024)
            });
            for _ in 0..4 {
                for receiver in &mut receivers {
                    assert!(receiver.recv().now_or_never().is_none());
                    assert_eq!(receiver.jobs.len(), 2);
                    assert_eq!(receiver.receiver.0.len(), 1);
                }
            }
            assert_eq!(
                receivers
                    .iter()
                    .map(|receiver| receiver.jobs.len())
                    .sum::<usize>(),
                6
            );
            barrier.wait();
            futures::executor::block_on(futures::future::join_all(blockers));
            for receiver in &mut receivers {
                for _ in 0..2 {
                    assert!(matches!(
                        futures::executor::block_on(receiver.jobs.next_completed()),
                        Ok((_, Err(InvalidIngress::Decode)))
                    ));
                }
                assert!(receiver.jobs.is_empty());
                assert_eq!(receiver.receiver.0.len(), 1);
            }
        });
    }

    #[test]
    fn closed_ingress_drains_owned_completion_after_cancellation() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
            let actor = ingress_actor::<Sha256, _>(
                context.child("batcher"),
                &committee,
                mocks::inline(NonZeroUsize::new(2).unwrap()),
            );
            let mut receiver =
                actor.ingress_receiver(RawReceiver::default(), NetworkPlane::Consensus, 1024);
            let (send, receive) = futures::channel::oneshot::channel();
            receiver.jobs.push(async { receive.await.unwrap() });
            for _ in 0..4 {
                assert!(receiver.recv().now_or_never().is_none());
                assert!(receiver.closed);
                assert_eq!(receiver.jobs.len(), 1);
            }
            assert!(
                send.send(Ok((
                    committee.identities[1].clone(),
                    Err(InvalidIngress::Decode)
                )))
                .is_ok()
            );
            assert!(matches!(
                receiver.recv().await,
                Some(Ok((_, Err(InvalidIngress::Decode))))
            ));
            assert!(receiver.jobs.is_empty());
            assert!(receiver.recv().await.is_none());
        });
    }

    #[derive(Default)]
    struct PanickingHasher;

    impl Hasher for PanickingHasher {
        type Digest = <Sha256 as Hasher>::Digest;
        fn hash(_: &[&[u8]]) -> Self::Digest {
            panic!("identification panic")
        }
        fn hash_pair(_: &[&[u8]], _: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            panic!("identification panic")
        }
        fn update(&mut self, _: &[u8]) -> &mut Self {
            panic!("identification panic")
        }
        fn finalize(self) -> (Self, Self::Digest) {
            panic!("identification panic")
        }
    }

    #[test]
    fn ingress_catches_inline_and_offloaded_identification_panics() {
        for strategy in [mocks::inline(NonZeroUsize::MIN), rayon()] {
            deterministic::Runner::default().start(move |context| async move {
                let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
                let actor = ingress_actor::<PanickingHasher, _>(
                    context.child("batcher"),
                    &committee,
                    strategy.clone(),
                );
                let frame = Envelope::new(
                    committee.config.epoch(),
                    ConsensusMessage::<MinPk, <Sha256 as Hasher>::Digest>::NoVote(
                        committee.novote(1, 1),
                    ),
                )
                .encode();
                let raw = RawReceiver(VecDeque::from([(
                    committee.identities[1].clone(),
                    IoBuf::from(frame),
                )]));
                let mut receiver = actor.ingress_receiver(raw, NetworkPlane::Consensus, 1024);
                // Driving from a pool member lets Rayon execute the job without an external wake.
                let outcome = strategy
                    .manual()
                    .spawn(1, move |_| futures::executor::block_on(receiver.recv()));
                let result = futures::executor::block_on(outcome);
                assert!(matches!(result, Some(Err(IngressTaskPanicked))));
            });
        }
    }

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
