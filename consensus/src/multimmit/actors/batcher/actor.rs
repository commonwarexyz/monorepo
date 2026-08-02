use super::{
    Completed, Config, Drop, IngressLimits, Message, Observed,
    lanes::{Group, LaneId, Lanes},
    metrics::Metrics as ActorMetrics,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            metrics::{Peer, Traffic},
            wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig},
        },
        config::CodecConfig,
        machine::{Artifact, IdentifiedArtifact, VerificationCompletion, VerifyJob},
        scheme::bls12381_threshold::Scheme,
        types::CertificateId,
    },
    types::Round,
};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::{Codec, EncodeSize as _, Write as _};
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Receiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{
        metrics::{GaugeExt as _, GaugeFamily},
        traces::TracedExt as _,
    },
};
use commonware_utils::{SystemTimeExt as _, futures::Pool};
use futures::FutureExt as _;
use rand_core::CryptoRng;
use std::{
    collections::BTreeSet, future::pending, marker::PhantomData, panic::AssertUnwindSafe,
    sync::Arc, time::SystemTime,
};
use tracing::{Instrument as _, Span, debug, debug_span, error, info_span};

type PlaneReceiver<R, M, T> = DecodingReceiver<R, Envelope<M>, T>;
type VerifyResult<P, D> = (
    Span,
    Result<(Round, VerificationCompletion<D>, Vec<P>), VerificationTaskPanicked>,
);
type VerifyResults<P, D> = Pool<VerifyResult<P, D>>;
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
    jobs: Pool<DecodedMessage<R::PublicKey, M>>,
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
                    self.jobs.push(self.strategy.spawn(move |_| {
                        (peer, M::decode_cfg(bytes.as_ref(), &config))
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
            .spawn(move |strategy| worker_span.in_scope(|| operation(context, strategy)))
            .await
    };
    let outcome = AssertUnwindSafe(operation)
        .catch_unwind()
        .instrument(instrument)
        .await
        .map_err(|_| VerificationTaskPanicked);
    (completion_span, outcome)
}

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
}

impl InvalidIngress {
    const fn reason(self) -> &'static str {
        match self {
            Self::ProposalParent => "proposal exact parent mismatch",
            Self::Chain => "invalid chain",
        }
    }
}

type IngressResult<P, V, D> = (P, Result<PreparedIngress<V, D>, InvalidIngress>);
type IngressResults<P, V, D> = Pool<Result<IngressResult<P, V, D>, IngressTaskPanicked>>;

async fn run_ingress_operation<O, R, T>(strategy: T, operation: O) -> Result<R, IngressTaskPanicked>
where
    O: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
    T: Strategy,
{
    AssertUnwindSafe(strategy.spawn(move |_| operation()))
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

/// Bounded ingress and verification executor for one fixed epoch.
pub struct Actor<E, H, P, V, B, T>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,

    scheme: Arc<Scheme<P, V>>,
    blocker: B,
    strategy: T,
    codec: CodecConfig,
    limits: IngressLimits,
    observation_capacity: usize,

    mailbox: mailbox::Receiver<Message<P, V, H::Digest>>,

    metrics: ActorMetrics<P>,

    _hasher: PhantomData<H>,
}

impl<E, H, P, V, B, T> Actor<E, H, P, V, B, T>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    /// Creates the batcher and its control mailbox.
    pub fn new(
        context: E,
        config: Config<P, V, B, T>,
    ) -> (Self, mailbox::Sender<Message<P, V, H::Digest>>) {
        let metrics = ActorMetrics::new(&context, config.scheme.participants());
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: Arc::new(config.scheme),
                blocker: config.blocker,
                strategy: config.strategy,
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
        let mut flush_deadline: Option<SystemTime> = None;
        let mut observations_inflight = 0usize;
        let mut next_network = NetworkPlane::Consensus;

        select_loop! {
            self.context,
            on_start => {
                accept_ingress = ingress.len() < ingress_capacity;
                if observations_inflight < self.observation_capacity
                    && flush_deadline.is_some_and(|deadline| self.context.current() >= deadline)
                {
                    if !self.flush(&mut lanes, &observations, &mut observations_inflight) {
                        error!("voter observation path failed");
                        return;
                    }
                    flush_deadline = None;
                    continue;
                }
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
                        let scheme = Arc::clone(&self.scheme);
                        let strategy = self.strategy.clone();
                        let latency = self.metrics.verify_latency.clone();
                        let latest_verified_vote = self.metrics.latest_verified_vote.clone();
                        let worker = info_span!(
                            parent: &span,
                            "multimmit.batcher.verify",
                            epoch = round.epoch().get().traced(),
                            view = round.view().get().traced(),
                            job = job.id().get().traced(),
                            items = job.items().len().traced(),
                        );
                        let context = self.context.child("verify");
                        let operation = move |mut context: E, strategy: T| {
                            let timer = latency.timer(&context);
                            let completion =
                                job.verify::<_, P, H>(&mut context, &scheme, &strategy);
                            Self::record_verified_votes(
                                &job,
                                &completion,
                                &scheme,
                                &latest_verified_vote,
                            );
                            let invalid_sources = completion
                                .verdicts()
                                .iter()
                                .zip(sources)
                                .filter_map(|(verdict, source)| {
                                    (!verdict.valid()).then_some(source).flatten()
                                })
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect();
                            timer.observe(&context);
                            (round, completion, invalid_sources)
                        };
                        jobs.push(run_verification_operation(
                            context,
                            strategy,
                            span,
                            worker,
                            operation,
                        ));
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
            () = Self::wait(
                self.context.as_ref(),
                (observations_inflight < self.observation_capacity)
                    .then_some(flush_deadline)
                    .flatten(),
            ) => {
                if !self.flush(&mut lanes, &observations, &mut observations_inflight) {
                    error!("voter observation path failed");
                    break;
                }
                flush_deadline = None;
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
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains)
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
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains)
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
                        ingress.push(run_ingress_operation(self.strategy.clone(), move || {
                            Self::prepare(message, chains)
                        }));
                    }
                }
            },
            on_end => {
                // Flush immediately at the cohort budget; otherwise wait out the coalesce window.
                while observations_inflight < self.observation_capacity
                    && lanes.items() >= self.limits.cohort_items.get()
                {
                    if !self.flush(&mut lanes, &observations, &mut observations_inflight) {
                        error!("voter observation path failed");
                        return;
                    }
                }
                if lanes.items() == 0 {
                    flush_deadline = None;
                } else if observations_inflight < self.observation_capacity
                    && flush_deadline.is_none()
                {
                    flush_deadline = Some(
                        self.context
                            .current()
                            .saturating_add_ext(self.limits.coalesce),
                    );
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
                        Group::one(Self::identify(Artifact::LeaderBlock(*block), &mut scratch)),
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
                                Group::pair([(parent_id, parent), (block_id, block)]),
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
                            Group::one(Self::identify(artifact, &mut scratch)),
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
                        Group::one(Self::identify(artifact, &mut scratch)),
                    )),
                )
            }
            NetworkMessage::Data((peer, message)) => {
                let message = message
                    .expect("only decoded messages enter identification")
                    .into_payload();
                let chain = message.chain().get() as usize;
                if chain >= chains {
                    (peer, Err(InvalidIngress::Chain))
                } else {
                    let artifact = message.into_artifact();
                    (
                        peer,
                        Ok((
                            LaneId::Data(chain),
                            Group::one(Self::identify(artifact, &mut scratch)),
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
    fn plane_config<C>(&self, max_frame_bytes: usize, payload: C) -> EnvelopeConfig<C> {
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

    /// Waits until `deadline`, or forever when none is armed.
    async fn wait(context: &E, deadline: Option<SystemTime>) {
        match deadline {
            Some(at) => {
                context.sleep_until(at).await;
            }
            None => pending().await,
        }
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
        let (round, completion, invalid_sources) = match outcome {
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
            .enqueue(Completed {
                span,
                round,
                completion,
            })
            .accepted()
    }

    /// Records verified vote progress against the embedded signer, not the relaying peer.
    fn record_verified_votes(
        job: &VerifyJob<V, H::Digest>,
        completion: &VerificationCompletion<H::Digest>,
        scheme: &Scheme<P, V>,
        latest: &GaugeFamily<Peer<P>>,
    ) {
        for (item, verdict) in job.items().iter().zip(completion.verdicts()) {
            if !verdict.valid() {
                continue;
            }
            let artifact = item.artifact();
            if !matches!(artifact, Artifact::Vote(_) | Artifact::NoVote(_)) {
                continue;
            }
            let (Some(view), Some(signer)) = (artifact.view(), artifact.signer()) else {
                continue;
            };
            let Some(peer) = scheme.participants().as_ref().get(signer.get() as usize) else {
                continue;
            };
            let _ = latest.get_or_create_by(peer).try_set_max(view.get());
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
        let cohort = selected
            .into_iter()
            .map(|selected| (selected.peer, selected.artifact))
            .collect();
        match observations.enqueue(Observed {
            span,
            artifacts: cohort,
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
