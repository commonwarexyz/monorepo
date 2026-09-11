use super::workload::{Schedule, Workload};
use bytes::{BufMut, Bytes};
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, BufsMut, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, Write,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_consensus::{
    Automaton, Epochable as _, Heightable as _, Relay, Reporter,
    multimmit::{
        Artifact,
        marshal::{Custody, Error as MarshalError, Mailbox, Update},
        telemetry::WAN_LATENCY,
        types::{Activity, BlockRef, ChainId, Context, TransactionBlock, TransactionBlockHeader},
    },
    types::{Height, View},
};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::metrics::{Counter, Gauge, Histogram, HistogramExt as _, MetricsExt as _},
};
use commonware_utils::{Acknowledgement as _, channel::oneshot, sync::Mutex};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    future::{Future, ready},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, info, warn};

const BODY_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_BODY";
/// Attempts to subscribe to a block body while the marshal reports a full mailbox.
const BUSY_RETRIES: u32 = 8;
/// Base delay between busy retries; attempt `n` waits `n` times this.
const BUSY_BACKOFF: Duration = Duration::from_millis(25);

/// Opaque junk data carried by one producer block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body(Bytes);

impl Body {
    /// Returns a codec bound that accepts exactly `size` body bytes.
    pub const fn codec_config(size: usize) -> RangeCfg<usize> {
        RangeCfg::exact(size)
    }

    /// Returns the largest encoded transaction block accepted for `size` body bytes.
    pub const fn max_block_size(size: usize) -> usize {
        let header = 2 * MAX_U64_VARINT_SIZE + MAX_U32_VARINT_SIZE + 2 * Sha256Digest::SIZE;
        size.checked_add(header + MAX_U64_VARINT_SIZE)
            .expect("body size must fit in an encoded transaction block")
    }

    fn junk(seed: u64, context: Context<Sha256Digest>, size: usize) -> Self {
        let seed = seed.to_be_bytes();
        let epoch = context.epoch().get().to_be_bytes();
        let chain = context.chain().get().to_be_bytes();
        let height = context.height().get().to_be_bytes();
        let pattern = Sha256::hash(&[
            BODY_NAMESPACE,
            &seed,
            &epoch,
            &chain,
            &height,
            context.parent().as_ref(),
        ]);
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            let remaining = size - bytes.len();
            bytes.extend_from_slice(&pattern.as_ref()[..remaining.min(pattern.as_ref().len())]);
        }
        Self(Bytes::from(bytes))
    }
}

impl Write for Body {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.0.write_bufs(buf);
    }
}

impl Read for Body {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Bytes::read_cfg(buf, cfg).map(Self)
    }
}

impl EncodeSize for Body {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.0.encode_inline_size()
    }
}

impl Digestible for Body {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[BODY_NAMESPACE, self.0.as_ref()])
    }
}

/// Complete block type retained and delivered by marshal.
pub type Block = TransactionBlock<Sha256, Body>;

/// Marshal facade shared by the application and consensus reporter.
pub type Marshal = Mailbox<Sha256, MinPk, Body, ed25519::PublicKey>;

/// One of this producer's blocks awaiting its consensus milestones.
struct ProposalStart {
    block: BlockRef<Sha256Digest>,
    started_at: SystemTime,
    input_ready_at: Option<SystemTime>,
    finalized: bool,
}

/// Tracks a producer's blocks from build to consensus finality and to ordered delivery.
///
/// Finality is the pool fact that places the block under a directly finalized leader. Ordering
/// is the block's delivery in the total order. A start is kept until the block is ordered or
/// evicted, including after its finality sample has been recorded.
#[derive(Clone)]
pub struct ProposalLatency {
    started: Arc<Mutex<VecDeque<ProposalStart>>>,
    capacity: usize,
    finality: Histogram,
    ordering: Histogram,
    input_finality: Histogram,
    dropped: Counter,
    finality_evicted: Counter,
    benchmark_quorum: Option<usize>,
    starts: Counter,
    cancellations: Counter,
    outstanding: Gauge,
    nonfinalized: Gauge,
    proposed_early: Counter,
    proposed_late: Counter,
    extension_early: Counter,
    extension_late: Counter,
}

impl ProposalLatency {
    /// Registers the proposal latency histograms.
    pub fn new(context: &impl Metrics, capacity: NonZeroUsize) -> Self {
        Self {
            started: Arc::new(Mutex::new(VecDeque::new())),
            capacity: capacity.get(),
            benchmark_quorum: None,
            starts: context.counter(
                "proposal_started",
                "locally built blocks tracked for latency",
            ),
            cancellations: context.counter(
                "proposal_cancelled",
                "tracked proposal attempts cancelled",
            ),
            outstanding: context.gauge(
                "proposal_outstanding",
                "starts awaiting ordering or removal",
            ),
            nonfinalized: context.gauge(
                "proposal_nonfinalized",
                "retained starts without observed finality",
            ),
            proposed_early: context.counter(
                "proposal_first_finality_proposed_early",
                "first finality at or below proposed height with quorum votes",
            ),
            proposed_late: context.counter(
                "proposal_first_finality_proposed_late",
                "first finality at or below proposed height with more than quorum votes",
            ),
            extension_early: context.counter(
                "proposal_first_finality_extension_early",
                "first finality above proposed height with quorum votes",
            ),
            extension_late: context.counter(
                "proposal_first_finality_extension_late",
                "first finality above proposed height with more than quorum votes",
            ),
            finality: context.histogram(
                "proposal_finalization_latency",
                "time from block build to inclusion by a directly finalized leader",
                WAN_LATENCY,
            ),
            ordering: context.histogram(
                "proposal_ordering_latency",
                "time from block build to delivery in the total order",
                WAN_LATENCY,
            ),
            input_finality: context.histogram(
                "input_finalization_latency",
                "time from the last input byte arriving to protocol finalization, including input queueing",
                WAN_LATENCY,
            ),
            dropped: context.counter(
                "proposal_latency_dropped_total",
                "proposal latency samples evicted before ordered delivery",
            ),
            finality_evicted: context.counter(
                "proposal_finalization_latency_evicted",
                "proposal starts evicted before their finalization latency was recorded",
            ),
        }
    }

    /// Enables unsampled INFO events and first-finality classification for a benchmark run.
    ///
    /// Supply the consensus quorum before cloning this tracker. Samples cover locally built
    /// blocks while retained in memory; restart, eviction, and missing staged ancestry can
    /// prevent observing finality. Logger or process loss must be checked against metric counts.
    pub const fn enable_benchmark(mut self, quorum: NonZeroUsize) -> Self {
        self.benchmark_quorum = Some(quorum.get());
        self
    }

    fn sample(
        &self,
        start: &ProposalStart,
        event: &str,
        reason: &str,
        now: SystemTime,
        evidence: Option<(View, usize)>,
    ) {
        if self.benchmark_quorum.is_none() {
            return;
        }
        let micros = |time: SystemTime| {
            u64::try_from(
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros(),
            )
            .unwrap_or(u64::MAX)
        };
        let elapsed = |time: SystemTime| {
            u64::try_from(now.duration_since(time).unwrap_or_default().as_micros())
                .unwrap_or(u64::MAX)
        };
        info!(
            benchmark_event = event,
            reason,
            chain = start.block.chain().get(),
            height = start.block.height().get(),
            digest = %start.block.digest(),
            timestamp_us = micros(now),
            started_at_us = micros(start.started_at),
            input_ready_at_us = start.input_ready_at.map(micros),
            elapsed_us = elapsed(start.started_at),
            input_elapsed_us = start.input_ready_at.map(elapsed),
            finalized = start.finalized,
            view = evidence.map(|(view, _)| view.get()),
            votes = evidence.map(|(_, votes)| votes as u64),
            quorum = self.benchmark_quorum.map(|quorum| quorum as u64),
            starts = self.starts.get(),
            cancellations = self.cancellations.get(),
            drops = self.dropped.get(),
            finality_evictions = self.finality_evicted.get(),
            proposed_early = self.proposed_early.get(),
            proposed_late = self.proposed_late.get(),
            extension_early = self.extension_early.get(),
            extension_late = self.extension_late.get(),
            outstanding = self.outstanding.get(),
            nonfinalized = self.nonfinalized.get(),
            "proposal benchmark sample"
        );
    }

    fn start(
        &self,
        block: BlockRef<Sha256Digest>,
        started_at: SystemTime,
        input_ready_at: Option<SystemTime>,
    ) {
        let mut started = self.started.lock();
        if started.iter().any(|start| start.block == block) {
            return;
        }
        while started.len() >= self.capacity {
            let evicted = started.pop_front().expect("proposal capacity is nonzero");
            if !evicted.finalized {
                self.finality_evicted.inc();
                self.nonfinalized.dec();
            }
            self.dropped.inc();
            self.outstanding.dec();
            self.sample(&evicted, "eviction", "capacity", SystemTime::now(), None);
        }
        self.starts.inc();
        self.outstanding.inc();
        self.nonfinalized.inc();
        let start = ProposalStart {
            block,
            started_at,
            input_ready_at,
            finalized: false,
        };
        self.sample(&start, "start", "built", started_at, None);
        started.push_back(start);
    }

    fn cancel(&self, block: BlockRef<Sha256Digest>, reason: &str) {
        let mut started = self.started.lock();
        if let Some(index) = started.iter().position(|start| start.block == block) {
            let start = started.remove(index).unwrap();
            self.cancellations.inc();
            self.outstanding.dec();
            if !start.finalized {
                self.nonfinalized.dec();
            }
            self.sample(&start, "cancellation", reason, SystemTime::now(), None);
        }
    }

    fn finalize(
        &self,
        blocks: &[BlockRef<Sha256Digest>],
        proposed: &[Height],
        votes: usize,
        view: View,
        staged: &Staged,
    ) {
        let finalized = {
            let staged = staged.0.lock();
            let mut finalized = BTreeSet::new();
            for tip in blocks {
                let mut cursor = *tip;
                loop {
                    finalized.insert(cursor);
                    let Some(parent_height) = cursor.height().previous() else {
                        break;
                    };
                    let Some(block) = staged.get(&cursor.digest()) else {
                        break;
                    };
                    if block.reference != cursor {
                        break;
                    }
                    cursor =
                        BlockRef::new(cursor.chain(), parent_height, block.block.header().parent());
                }
            }
            finalized
        };
        let now = SystemTime::now();
        for start in self.started.lock().iter_mut() {
            if start.finalized || !finalized.contains(&start.block) {
                continue;
            }
            start.finalized = true;
            self.nonfinalized.dec();
            self.finality.observe_between(start.started_at, now);
            if let Some(input_ready_at) = start.input_ready_at {
                self.input_finality.observe_between(input_ready_at, now);
            }
            if let Some(quorum) = self.benchmark_quorum {
                let extension = start.block.height() > proposed[start.block.chain().get() as usize];
                let late = votes > quorum;
                let (counter, reason) = match (extension, late) {
                    (false, false) => (&self.proposed_early, "proposed_early"),
                    (false, true) => (&self.proposed_late, "proposed_late"),
                    (true, false) => (&self.extension_early, "extension_early"),
                    (true, true) => (&self.extension_late, "extension_late"),
                };
                counter.inc();
                self.sample(
                    start,
                    "first_finalization",
                    reason,
                    now,
                    Some((view, votes)),
                );
            }
        }
    }

    /// Records the ordered delivery of `block` and forgets its start.
    pub fn order(&self, block: BlockRef<Sha256Digest>) {
        let mut started = self.started.lock();
        if let Some(index) = started.iter().position(|start| start.block == block) {
            let start = started.remove(index).unwrap();
            let now = SystemTime::now();
            self.outstanding.dec();
            if !start.finalized {
                self.nonfinalized.dec();
            }
            self.ordering.observe_between(start.started_at, now);
            self.sample(&start, "ordered", "delivery", now, None);
        }
    }
}

struct StagedBlock {
    reference: BlockRef<Sha256Digest>,
    block: Arc<Block>,
    custody: Option<Custody>,
}

#[derive(Clone, Default)]
struct Staged(Arc<Mutex<BTreeMap<Sha256Digest, StagedBlock>>>);

impl Staged {
    fn insert(&self, block: Arc<Block>) -> bool {
        self.insert_with_custody(block, None)
    }

    fn insert_with_custody(&self, block: Arc<Block>, custody: Option<Custody>) -> bool {
        let reference = block.reference();
        match self.0.lock().entry(reference.digest()) {
            Entry::Vacant(entry) => {
                entry.insert(StagedBlock {
                    reference,
                    block,
                    custody,
                });
                true
            }
            Entry::Occupied(entry) => entry.get().reference == reference,
        }
    }

    fn take_custody(&self, reference: BlockRef<Sha256Digest>) -> Option<Custody> {
        let mut staged = self.0.lock();
        let block = staged.get_mut(&reference.digest())?;
        if block.reference != reference {
            return None;
        }
        block.custody.take()
    }

    fn retain_verified(&self, producer_chain: Option<ChainId>, block: Arc<Block>) -> bool {
        if Some(block.reference().chain()) != producer_chain {
            return true;
        }
        self.insert(block)
    }

    /// Retires bodies below the bounded window that can still have live egress obligations.
    fn certify(&self, reference: BlockRef<Sha256Digest>, retention: NonZeroUsize) {
        let retention = u64::try_from(retention.get()).unwrap_or(u64::MAX);
        let oldest = reference
            .height()
            .get()
            .saturating_sub(retention.saturating_sub(1));
        self.0.lock().retain(|_, staged| {
            staged.reference.chain() != reference.chain()
                || staged.reference.height().get() >= oldest
        });
    }
}

/// Telemetry registered by the example application.
#[derive(Clone)]
pub struct ApplicationMetrics {
    pub proposal_latency: ProposalLatency,
    /// Time a remote block verification waits for its complete body from marshal.
    ///
    /// Splits marshal body dissemination out of the engine's end-to-end validation latency.
    pub body_wait: Histogram,
    input_queue: Histogram,
}

impl ApplicationMetrics {
    /// Registers the example application's metrics.
    pub fn new(context: &impl Metrics, proposal_capacity: NonZeroUsize) -> Self {
        Self {
            proposal_latency: ProposalLatency::new(context, proposal_capacity),
            body_wait: context.histogram(
                "verify_body_wait",
                "time a remote verification waits for complete-body resolution and durable custody",
                WAN_LATENCY,
            ),
            input_queue: context.histogram(
                "input_queue_latency",
                "time from the last input byte arriving to the start of block construction",
                WAN_LATENCY,
            ),
        }
    }
}

/// How this producer shapes its blocks.
#[derive(Clone, Debug)]
pub struct Production {
    /// Bytes of junk data placed in every block body.
    pub body_size: usize,
    /// Minimum time between two blocks this producer builds; zero builds as fast as block
    /// custody admits.
    pub interval: Duration,
    /// Independent payload arrival rate per producer; absent means saturated input.
    pub offered_bytes_per_second: Option<NonZeroU64>,
    /// Finite benchmark arrivals, mutually exclusive with the constant input rate.
    pub schedule: Option<Schedule>,
}

/// Deterministic application attachment backed by marshal block custody.
pub struct Application<E: Clock + Spawner> {
    context: Arc<E>,
    seed: u64,
    production: Production,
    last_build: Arc<Mutex<Option<SystemTime>>>,
    workload: Option<Arc<Mutex<Workload>>>,
    publication_retention: NonZeroUsize,
    producer_chain: Option<ChainId>,
    marshal: Marshal,
    staged: Staged,
    metrics: ApplicationMetrics,
}

impl<E: Clock + Spawner> Clone for Application<E> {
    fn clone(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            seed: self.seed,
            production: self.production.clone(),
            last_build: Arc::clone(&self.last_build),
            workload: self.workload.clone(),
            publication_retention: self.publication_retention,
            producer_chain: self.producer_chain,
            marshal: self.marshal.clone(),
            staged: self.staged.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<E: Clock + Spawner + Metrics> Application<E> {
    /// Creates an application whose complete blocks are transported and retained by `marshal`.
    pub fn new(
        context: E,
        seed: u64,
        production: Production,
        publication_retention: NonZeroUsize,
        producer_chain: Option<ChainId>,
        marshal: Marshal,
        metrics: ApplicationMetrics,
    ) -> Self {
        assert!(production.schedule.is_none() || production.offered_bytes_per_second.is_none());
        let workload = match &production.schedule {
            Some(schedule) => Some(
                Workload::from_schedule(&context, schedule.clone(), production.body_size)
                    .expect("valid benchmark schedule"),
            ),
            None => production
                .offered_bytes_per_second
                .map(|rate| Workload::new(&context, rate, production.body_size)),
        }
        .map(|workload| Arc::new(Mutex::new(workload)));
        Self {
            context: Arc::new(context),
            seed,
            production,
            last_build: Arc::new(Mutex::new(None)),
            workload,
            publication_retention,
            producer_chain,
            marshal,
            staged: Staged::default(),
            metrics,
        }
    }
}

impl<E: Clock + Spawner> Automaton for Application<E> {
    type Context = Context<Sha256Digest>;
    type Digest = Sha256Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let seed = self.seed;
        let body_size = self.production.body_size;
        let marshal = self.marshal.clone();
        let staged = self.staged.clone();
        let proposal_latency = self.metrics.proposal_latency.clone();
        let input_queue = self.metrics.input_queue.clone();
        let workload = self.workload.clone();
        let input_ready_at = workload.as_ref().map(|workload| {
            workload
                .lock()
                .ready_at(context.height().get(), self.context.current())
        });
        let exhausted = input_ready_at == Some(None);
        let input_ready_at = input_ready_at.flatten();
        let (mut sender, receiver) = oneshot::channel();
        // The optional block interval and the availability of a full input batch independently
        // constrain the build. Neither moves the input arrival schedule under backpressure.
        let next_build = {
            let mut last_build = self.last_build.lock();
            let now = self.context.current();
            let next = last_build
                .map_or(now, |last| last + self.production.interval)
                .max(now);
            let next = input_ready_at.map_or(next, |ready| ready.max(next));
            *last_build = Some(next);
            next
        };
        self.context
            .child("propose")
            .shared(true)
            .spawn(move |runtime| async move {
                if exhausted {
                    sender.closed().await;
                    return;
                }
                select! {
                    _ = sender.closed() => return,
                    () = runtime.sleep_until(next_build) => {},
                }
                // Proposal latency starts at construction; input queueing is measured separately.
                let started_at = runtime.current();
                if let Some(input_ready_at) = input_ready_at {
                    input_queue.observe_between(input_ready_at, started_at);
                }
                let block = Arc::new(TransactionBlock::from_context(
                    context,
                    Body::junk(seed, context, body_size),
                ));
                let body_digest = block.header().body_digest();
                let block_digest = block.digest();
                let reference = block.reference();
                proposal_latency.start(reference, started_at, input_ready_at);
                let custody = select! {
                    _ = sender.closed() => {
                        proposal_latency.cancel(reference, "receiver_closed");
                        return;
                    },
                    result = marshal.stage_block(Arc::clone(&block)) => result,
                };
                let custody = match custody {
                    Ok(custody) => custody,
                    Err(error) => {
                        proposal_latency.cancel(reference, "stage_error");
                        warn!(?reference, %error, "cannot stage proposed block");
                        return;
                    }
                };
                if !staged.insert_with_custody(block, Some(custody)) {
                    proposal_latency.cancel(reference, "staged_identity_conflict");
                    return;
                }
                debug!(
                    chain = context.chain().get(),
                    height = context.height().get(),
                    ?body_digest,
                    ?block_digest,
                    body_size,
                    "produced body"
                );
                if sender.send(body_digest).is_err() {
                    proposal_latency.cancel(reference, "receiver_closed");
                } else if let Some(workload) = workload {
                    workload.lock().admit(context.height().get());
                }
            });
        ready(receiver)
    }

    fn verify(
        &mut self,
        context: Self::Context,
        body_digest: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        let header = TransactionBlockHeader::new(
            context.epoch(),
            context.chain(),
            context.height(),
            context.parent(),
            body_digest,
        )
        .expect("consensus supplies a live producer height");
        let reference = header.block_ref::<Sha256>();
        let marshal = self.marshal.clone();
        let staged = self.staged.clone();
        let producer_chain = self.producer_chain;
        let body_wait = self.metrics.body_wait.clone();
        let (mut sender, receiver) = oneshot::channel();
        self.context
            .child("verify")
            .spawn(move |runtime| async move {
                if let Some(custody) = staged.take_custody(reference) {
                    let result = select! {
                        _ = sender.closed() => return,
                        result = custody.wait() => result,
                    };
                    match result {
                        Ok(()) => {
                            let _ = sender.send(true);
                        }
                        Err(error) => {
                            warn!(
                                chain = context.chain().get(),
                                height = context.height().get(),
                                %error,
                                "proposed block custody failed"
                            );
                        }
                    }
                    return;
                }
                let requested_at = runtime.current();
                // A full marshal mailbox rejects the request outright; back off briefly and retry
                // before reporting no verdict, which consensus answers by validating again later.
                let mut attempt = 0u32;
                let subscription = loop {
                    let result = select! {
                        _ = sender.closed() => return,
                        result = marshal.subscribe_block(reference) => result,
                    };
                    match result {
                        Err(MarshalError::Busy) if attempt < BUSY_RETRIES => {
                            attempt += 1;
                            select! {
                                _ = sender.closed() => return,
                                _ = runtime.sleep(BUSY_BACKOFF * attempt) => {}
                            }
                        }
                        result => break result,
                    }
                };
                match subscription {
                    Ok(block) => {
                        body_wait.observe_between(requested_at, runtime.current());
                        if block.header() != &header {
                            let _ = sender.send(false);
                            return;
                        }
                        let _ = sender.send(staged.retain_verified(producer_chain, block));
                    }
                    Err(error) => {
                        warn!(
                            chain = context.chain().get(),
                            height = context.height().get(),
                            %error,
                            "block subscription closed"
                        );
                    }
                }
            });
        ready(receiver)
    }
}

impl<E: Clock + Spawner> Relay for Application<E> {
    type Digest = Sha256Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = ();

    fn broadcast(&mut self, block_digest: Self::Digest, (): Self::Plan) -> Feedback {
        let block = {
            let staged = self.staged.0.lock();
            let Some(staged) = staged.get(&block_digest) else {
                warn!(?block_digest, "relay requested an unstaged block");
                return Feedback::Closed;
            };
            Arc::clone(&staged.block)
        };
        self.marshal.broadcast_block(Recipients::All, block)
    }
}

impl<E: Clock + Spawner> Reporter for Application<E> {
    type Activity = Activity<MinPk, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } =
            &activity
        {
            self.metrics.proposal_latency.finalize(
                fact.blocks(),
                fact.proposed(),
                fact.votes(),
                fact.round().view(),
                &self.staged,
            );
        }
        let certified = match &activity {
            Activity::ProtocolAccepted { artifact, .. } => match artifact.as_ref() {
                Artifact::DaCertificate(certificate)
                    if Some(certificate.header().chain()) == self.producer_chain =>
                {
                    Some(certificate.block_ref::<Sha256>())
                }
                _ => None,
            },
            Activity::HistoryAccepted { .. }
            | Activity::LeaderFinalized { .. }
            | Activity::LeaderFinalityUpdated { .. } => None,
        };
        let feedback = self.marshal.report(activity);
        if let Some(reference) = certified {
            self.staged.certify(reference, self.publication_retention);
        }
        feedback
    }
}

/// Headless ordered-output sink that advances marshal without inspecting block contents.
#[derive(Clone, Copy)]
pub struct NoopReporter;

impl Reporter for NoopReporter {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block {
            acknowledgement, ..
        } = activity;
        acknowledgement.acknowledge();
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf as _;
    use commonware_codec::{Decode, Encode};
    use commonware_consensus::types::{Epoch, Height};
    use commonware_runtime::{
        BufferPooler as _, Runner as _, deterministic, iobuf::EncodeExt as _,
    };
    use commonware_utils::NZUsize;

    fn context() -> Context<Sha256Digest> {
        Context::new(
            Epoch::new(7),
            commonware_consensus::multimmit::types::ChainId::new(2),
            Height::new(11),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap()
    }

    #[test]
    fn body_codec_and_block_identities_are_canonical() {
        let context = context();
        let body = Body::junk(9, context, 4_097);
        let mut encoded = body.encode();
        let decoded = Body::read_cfg(&mut encoded, &Body::codec_config(4_097)).unwrap();
        assert_eq!(decoded, body);

        let block = TransactionBlock::<Sha256, _>::from_context(context, body);
        assert_eq!(block.header().body_digest(), block.body().digest());
        assert_ne!(block.digest(), block.header().body_digest());
        assert!(block.encode_size() <= Body::max_block_size(4_097));
    }

    #[test]
    fn block_encoding_shares_body_buffer() {
        deterministic::Runner::default().start(|runtime| async move {
            for size in [0, 1, 127, 128, 256 * 1024] {
                let block = Block::from_context(context(), Body::junk(9, context(), size));
                let payload = block.body().0.clone();
                let inline = block.header().encode_size() + size.encode_size();
                let encoded = block.encode_with_pool(runtime.network_buffer_pool());
                assert_eq!(encoded.clone().coalesce().as_ref(), block.encode().as_ref());
                assert_eq!(block.encode_inline_size(), inline);

                let decoded =
                    Block::decode_cfg(encoded.clone(), &Body::codec_config(size)).unwrap();
                assert_eq!(decoded, block);
                if size != 0 {
                    let mut body = encoded;
                    body.advance(inline);
                    assert_eq!(body.chunk().as_ptr(), payload.as_ptr());
                    assert_eq!(decoded.body().0.as_ptr(), payload.as_ptr());
                }
                drop(block);
                assert_eq!(decoded.body().0, payload);
            }
        });
    }

    #[test]
    fn benchmark_events_include_raw_microseconds_and_loss_accounting() {
        #[derive(Clone, Default)]
        struct Output(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        deterministic::Runner::default().start(|runtime| async move {
            let output = Output::default();
            let writer = output.clone();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                let latency = ProposalLatency::new(&runtime, NZUsize!(1));
                let block = |height| {
                    BlockRef::new(
                        ChainId::new(0),
                        Height::new(height),
                        Sha256::hash(&[&height.to_be_bytes()]),
                    )
                };
                let started = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
                latency.start(block(1), started, None);
                latency.cancel(block(1), "receiver_closed");
                assert!(output.0.lock().is_empty());
                let latency = latency.enable_benchmark(NZUsize!(3));
                latency.start(block(2), started, Some(started - Duration::from_secs(2)));
                latency.finalize(
                    &[block(2)],
                    &[Height::new(2)],
                    3,
                    View::new(4),
                    &Staged::default(),
                );
                latency.order(block(2));
                latency.start(block(3), started, None);
                latency.start(block(4), started, None);
                latency.cancel(block(4), "stage_error");
            });
            let output = String::from_utf8(output.0.lock().clone()).unwrap();
            let events: Vec<serde_yaml::Value> = output
                .lines()
                .map(|line| serde_yaml::from_str(line).unwrap())
                .collect();
            assert_eq!(events.len(), 7);
            let first = &events[0]["fields"];
            assert_eq!(first["benchmark_event"].as_str(), Some("start"));
            assert_eq!(first["started_at_us"].as_u64(), Some(10_000_000));
            assert_eq!(first["input_ready_at_us"].as_u64(), Some(8_000_000));
            assert_eq!(first["elapsed_us"].as_u64(), Some(0));
            let finality = &events[1]["fields"];
            assert_eq!(
                finality["benchmark_event"].as_str(),
                Some("first_finalization")
            );
            assert!(finality["elapsed_us"].as_u64().unwrap() > 1_000_000);
            assert_eq!(
                finality["input_elapsed_us"].as_u64().unwrap()
                    - finality["elapsed_us"].as_u64().unwrap(),
                2_000_000
            );
            assert_eq!(finality["reason"].as_str(), Some("proposed_early"));
            assert_eq!(
                events[2]["fields"]["benchmark_event"].as_str(),
                Some("ordered")
            );
            assert_eq!(
                events[4]["fields"]["benchmark_event"].as_str(),
                Some("eviction")
            );
            let last = &events[6]["fields"];
            assert_eq!(last["benchmark_event"].as_str(), Some("cancellation"));
            assert_eq!(last["starts"].as_u64(), Some(4));
            assert_eq!(last["cancellations"].as_u64(), Some(2));
            assert_eq!(last["drops"].as_u64(), Some(1));
            assert_eq!(last["outstanding"].as_u64(), Some(0));
            assert_eq!(last["nonfinalized"].as_u64(), Some(0));
        });
    }

    #[test]
    fn benchmark_first_finality_classifies_exact_blocks_once() {
        deterministic::Runner::default().start(|runtime| async move {
            let latency = ProposalLatency::new(&runtime, NZUsize!(8)).enable_benchmark(NZUsize!(3));
            let staged = Staged::default();
            let mut parent = Sha256::hash(&[b"genesis"]);
            let blocks: Vec<_> = (1..=4)
                .map(|height| {
                    let context =
                        Context::new(Epoch::new(7), ChainId::new(0), Height::new(height), parent)
                            .unwrap();
                    let block = Arc::new(Block::from_context(context, Body::junk(9, context, 32)));
                    parent = block.digest();
                    assert!(staged.insert(Arc::clone(&block)));
                    latency.start(block.reference(), SystemTime::now(), None);
                    block
                })
                .collect();
            let conflicting = BlockRef::new(
                ChainId::new(0),
                Height::new(2),
                Sha256::hash(&[b"conflict"]),
            );
            latency.start(conflicting, SystemTime::now(), None);
            // Height one is proposed; height two is covered by the quorum's extension.
            latency.finalize(
                &[blocks[1].reference()],
                &[Height::new(1)],
                3,
                View::new(1),
                &staged,
            );
            assert_eq!(latency.proposed_early.get(), 1);
            assert_eq!(latency.extension_early.get(), 1);
            assert_eq!(latency.nonfinalized.get(), 3);
            // A larger fact counts only newly covered blocks, with the configured quorum.
            for _ in 0..2 {
                latency.finalize(
                    &[blocks[3].reference()],
                    &[Height::new(3)],
                    4,
                    View::new(1),
                    &staged,
                );
            }
            assert_eq!(latency.proposed_early.get(), 1);
            assert_eq!(latency.extension_early.get(), 1);
            assert_eq!(latency.proposed_late.get(), 1);
            assert_eq!(latency.extension_late.get(), 1);
            assert_eq!(latency.outstanding.get(), 5);
            assert_eq!(latency.nonfinalized.get(), 1);
            assert!(
                latency
                    .started
                    .lock()
                    .iter()
                    .any(|start| start.block == conflicting && !start.finalized)
            );
            assert!(
                runtime
                    .encode()
                    .contains("proposal_finalization_latency_count 4\n")
            );
        });
    }

    #[test]
    fn benchmark_censored_starts_remain_visible_until_cancel_or_eviction() {
        deterministic::Runner::default().start(|runtime| async move {
            let latency = ProposalLatency::new(&runtime, NZUsize!(2)).enable_benchmark(NZUsize!(2));
            let block = |height| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[&height.to_be_bytes()]),
                )
            };
            let now = SystemTime::now();
            latency.start(block(1), now, Some(now - Duration::from_secs(2)));
            latency.start(block(1), now, None);
            latency.start(block(2), now, None);
            assert_eq!(latency.starts.get(), 2);
            assert_eq!(latency.outstanding.get(), 2);
            assert_eq!(latency.nonfinalized.get(), 2);
            latency.start(block(3), now, None);
            assert_eq!(latency.dropped.get(), 1);
            assert_eq!(latency.finality_evicted.get(), 1);
            assert_eq!(latency.outstanding.get(), 2);
            assert_eq!(latency.nonfinalized.get(), 2);
            latency.cancel(block(2), "stage_error");
            latency.cancel(block(2), "receiver_closed");
            assert_eq!(latency.cancellations.get(), 1);
            assert_eq!(latency.outstanding.get(), 1);
            assert_eq!(latency.nonfinalized.get(), 1);
            latency.order(block(3));
            assert_eq!(latency.outstanding.get(), 0);
            assert_eq!(latency.nonfinalized.get(), 0);
        });
    }

    #[test]
    fn proposal_latency_retention_is_bounded_without_finality() {
        deterministic::Runner::default().start(|context| async move {
            let latency = ProposalLatency::new(&context, NZUsize!(2));
            for height in 1..=3 {
                latency.start(
                    BlockRef::new(
                        commonware_consensus::multimmit::types::ChainId::new(0),
                        Height::new(height),
                        Sha256::hash(&[&height.to_be_bytes()]),
                    ),
                    SystemTime::now(),
                    None,
                );
            }
            let started = latency.started.lock();
            assert_eq!(started.len(), 2);
            assert_eq!(started.front().unwrap().block.height(), Height::new(2));
            assert_eq!(latency.dropped.get(), 1);
            assert_eq!(latency.finality_evicted.get(), 1);
        });
    }

    #[test]
    fn proposal_latency_distinguishes_finality_and_ordering_evictions() {
        deterministic::Runner::default().start(|runtime| async move {
            let latency = ProposalLatency::new(&runtime, NZUsize!(1));
            let staged = Staged::default();
            let reference = |height: u64| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[&height.to_be_bytes()]),
                )
            };
            latency.start(reference(1), runtime.current(), None);
            latency.finalize(
                &[reference(1)],
                &[Height::new(100)],
                3,
                View::new(1),
                &staged,
            );
            latency.start(reference(2), runtime.current(), None);
            assert_eq!(latency.dropped.get(), 1);
            assert_eq!(latency.finality_evicted.get(), 0);

            latency.start(reference(3), runtime.current(), None);
            assert_eq!(latency.dropped.get(), 2);
            assert_eq!(latency.finality_evicted.get(), 1);

            latency.cancel(reference(3), "test");
            latency.start(reference(4), runtime.current(), None);
            latency.order(reference(4));
            latency.start(reference(5), runtime.current(), None);
            assert_eq!(latency.dropped.get(), 2);
            assert_eq!(latency.finality_evicted.get(), 1);
        });
    }

    #[test]
    fn input_finality_includes_queueing_and_ignores_cancelled_proposals() {
        deterministic::Runner::default().start(|context| async move {
            let latency = ProposalLatency::new(&context, NZUsize!(2));
            let staged = Staged::default();
            let block = |height| {
                BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[b"block"]),
                )
            };
            let started = SystemTime::now();
            let input = started - Duration::from_secs(1);
            latency.start(block(1), started, Some(input));
            latency.cancel(block(1), "test");
            latency.finalize(&[block(1)], &[Height::new(100)], 3, View::new(1), &staged);
            latency.start(block(2), started, Some(input));
            latency.finalize(&[block(2)], &[Height::new(100)], 3, View::new(1), &staged);
            latency.finalize(&[block(2)], &[Height::new(100)], 3, View::new(1), &staged);
            let encoded = context.encode();
            assert!(encoded.contains("input_finalization_latency_count 1\n"));
            let sum = |name: &str| {
                encoded
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap()
                    .trim()
                    .parse::<f64>()
                    .unwrap()
            };
            assert!(
                (sum("input_finalization_latency_sum ")
                    - sum("proposal_finalization_latency_sum ")
                    - 1.0)
                    .abs()
                    < 1e-9
            );
        });
    }

    #[test]
    fn proposal_latency_evicts_the_oldest_start_across_chains() {
        deterministic::Runner::default().start(|context| async move {
            let latency = ProposalLatency::new(&context, NZUsize!(2));
            let old = BlockRef::new(
                commonware_consensus::multimmit::types::ChainId::new(1),
                Height::new(1),
                Sha256::hash(&[b"old"]),
            );
            let newer = BlockRef::new(
                commonware_consensus::multimmit::types::ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"newer"]),
            );
            let newest = BlockRef::new(
                commonware_consensus::multimmit::types::ChainId::new(0),
                Height::new(2),
                Sha256::hash(&[b"newest"]),
            );
            for reference in [old, newer, newest] {
                latency.start(reference, SystemTime::now(), None);
            }

            let started = latency.started.lock();
            assert!(!started.iter().any(|start| start.block == old));
            assert!(started.iter().any(|start| start.block == newer));
            assert!(started.iter().any(|start| start.block == newest));
        });
    }

    #[test]
    fn proposal_latency_requires_exact_finalized_ancestry() {
        deterministic::Runner::default().start(|context| async move {
            let latency = ProposalLatency::new(&context, NZUsize!(2));
            let staged = Staged::default();
            let context = Context::new(
                Epoch::new(7),
                commonware_consensus::multimmit::types::ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"genesis"]),
            )
            .unwrap();
            let left = Arc::new(TransactionBlock::<Sha256, _>::from_context(
                context,
                Body::junk(1, context, 32),
            ));
            let right = Arc::new(TransactionBlock::<Sha256, _>::from_context(
                context,
                Body::junk(2, context, 32),
            ));
            assert!(staged.insert(Arc::clone(&left)));
            assert!(staged.insert(Arc::clone(&right)));
            latency.start(left.reference(), SystemTime::now(), None);

            latency.finalize(
                &[right.reference()],
                &[Height::new(100)],
                3,
                View::new(1),
                &staged,
            );
            assert!(
                latency
                    .started
                    .lock()
                    .iter()
                    .any(|start| start.block == left.reference() && !start.finalized)
            );

            latency.finalize(
                &[left.reference()],
                &[Height::new(100)],
                3,
                View::new(1),
                &staged,
            );
            assert!(latency.started.lock().iter().all(|start| start.finalized));
            latency.order(left.reference());
            assert!(latency.started.lock().is_empty());

            let parent = Arc::new(TransactionBlock::<Sha256, _>::from_context(
                context,
                Body::junk(3, context, 32),
            ));
            let child_context = Context::new(
                context.epoch(),
                context.chain(),
                context.height().next(),
                parent.digest(),
            )
            .unwrap();
            let child = Arc::new(TransactionBlock::<Sha256, _>::from_context(
                child_context,
                Body::junk(4, child_context, 32),
            ));
            assert!(staged.insert(Arc::clone(&parent)));
            assert!(staged.insert(Arc::clone(&child)));
            latency.start(parent.reference(), SystemTime::now(), None);

            latency.finalize(
                &[child.reference()],
                &[Height::new(100)],
                3,
                View::new(1),
                &staged,
            );
            assert!(latency.started.lock().iter().all(|start| start.finalized));
            latency.order(parent.reference());
            assert!(latency.started.lock().is_empty());
        });
    }

    #[test]
    fn proposal_latency_orders_blocks_that_were_never_directly_finalized() {
        deterministic::Runner::default().start(|context| async move {
            let latency = ProposalLatency::new(&context, NZUsize!(2));
            let block = BlockRef::new(
                commonware_consensus::multimmit::types::ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"block"]),
            );
            latency.start(block, SystemTime::now(), None);
            latency.order(block);
            assert!(latency.started.lock().is_empty());
            latency.order(block);
            assert!(latency.started.lock().is_empty());
        });
    }

    #[test]
    fn verified_bodies_are_retained_only_for_the_local_producer() {
        let staged = Staged::default();
        let local_chain = ChainId::new(0);
        let block = |chain| {
            let context = Context::new(
                Epoch::new(7),
                chain,
                Height::new(1),
                Sha256::hash(&[b"parent"]),
            )
            .unwrap();
            Arc::new(TransactionBlock::<Sha256, _>::from_context(
                context,
                Body::junk(9, context, 32),
            ))
        };
        let local = block(local_chain);
        let remote = block(ChainId::new(1));

        assert!(staged.retain_verified(Some(local_chain), Arc::clone(&local)));
        assert!(staged.retain_verified(Some(local_chain), remote));
        let retained = staged.0.lock();
        assert_eq!(retained.len(), 1);
        assert!(retained.contains_key(&local.digest()));
    }

    #[test]
    fn certified_frontier_respects_the_publication_window() {
        let staged = Staged::default();
        let blocks = [10, 11, 12].map(|height| {
            let context = Context::new(
                Epoch::new(7),
                commonware_consensus::multimmit::types::ChainId::new(2),
                Height::new(height),
                Sha256::hash(&[b"parent", &height.to_be_bytes()]),
            )
            .unwrap();
            Arc::new(TransactionBlock::<Sha256, _>::from_context(
                context,
                Body::junk(9, context, 32),
            ))
        });
        for block in &blocks {
            assert!(staged.insert(Arc::clone(block)));
        }

        staged.certify(blocks[2].reference(), NonZeroUsize::new(2).unwrap());
        let retained = staged.0.lock();
        assert!(!retained.contains_key(&blocks[0].digest()));
        assert!(retained.contains_key(&blocks[1].digest()));
        assert!(retained.contains_key(&blocks[2].digest()));
    }
}
