use bytes::{BufMut, Bytes};
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, Write,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_consensus::{
    Automaton, Epochable as _, Heightable as _, LATENCY, Relay, Reporter,
    multimmit::{
        Artifact,
        marshal::{Custody, Error as MarshalError, Mailbox, Update},
        types::{Activity, BlockRef, ChainId, Context, TransactionBlock, TransactionBlockHeader},
    },
};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::metrics::{Counter, Histogram, HistogramExt as _, MetricsExt as _},
};
use commonware_utils::{Acknowledgement as _, channel::oneshot, sync::Mutex};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    future::{Future, ready},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{info, warn};

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
    finalized: bool,
}

/// Tracks a producer's blocks from build to consensus finality and to ordered delivery.
///
/// Finality is the pool fact that places the block under a directly finalized leader. Ordering
/// is the block's delivery in the total order, the point DAG-based protocols report as commit
/// latency. A start is kept until the block is ordered or evicted.
#[derive(Clone)]
pub struct ProposalLatency {
    started: Arc<Mutex<VecDeque<ProposalStart>>>,
    capacity: usize,
    finality: Histogram,
    ordering: Histogram,
    dropped: Counter,
}

impl ProposalLatency {
    /// Registers the proposal latency histograms.
    pub fn new(context: &impl Metrics, capacity: NonZeroUsize) -> Self {
        Self {
            started: Arc::new(Mutex::new(VecDeque::new())),
            capacity: capacity.get(),
            finality: context.histogram(
                "proposal_finalization_latency",
                "time from block build to inclusion by a directly finalized leader",
                LATENCY,
            ),
            ordering: context.histogram(
                "proposal_ordering_latency",
                "time from block build to delivery in the total order",
                LATENCY,
            ),
            dropped: context.counter(
                "proposal_latency_dropped_total",
                "proposal latency samples evicted before ordered delivery",
            ),
        }
    }

    fn start(&self, block: BlockRef<Sha256Digest>, started_at: SystemTime) {
        let mut started = self.started.lock();
        if started.iter().any(|start| start.block == block) {
            return;
        }
        while started.len() >= self.capacity {
            started.pop_front();
            self.dropped.inc();
        }
        started.push_back(ProposalStart {
            block,
            started_at,
            finalized: false,
        });
    }

    fn cancel(&self, block: BlockRef<Sha256Digest>) {
        let mut started = self.started.lock();
        if let Some(index) = started.iter().position(|start| start.block == block) {
            started.remove(index);
        }
    }

    fn finalize(&self, blocks: &[BlockRef<Sha256Digest>], staged: &Staged) {
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
        let mut samples = Vec::new();
        for start in self.started.lock().iter_mut() {
            if !start.finalized && finalized.contains(&start.block) {
                start.finalized = true;
                samples.push(start.started_at);
            }
        }
        let now = SystemTime::now();
        for started_at in samples {
            self.finality.observe_between(started_at, now);
        }
    }

    /// Records the ordered delivery of `block` and forgets its start.
    pub fn order(&self, block: BlockRef<Sha256Digest>) {
        let start = {
            let mut started = self.started.lock();
            started
                .iter()
                .position(|start| start.block == block)
                .and_then(|index| started.remove(index))
        };
        if let Some(start) = start {
            self.ordering
                .observe_between(start.started_at, SystemTime::now());
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
}

impl ApplicationMetrics {
    /// Registers the example application's metrics.
    pub fn new(context: &impl Metrics, proposal_capacity: NonZeroUsize) -> Self {
        Self {
            proposal_latency: ProposalLatency::new(context, proposal_capacity),
            body_wait: context.histogram(
                "verify_body_wait",
                "time a remote block verification waits for its complete body from marshal",
                LATENCY,
            ),
        }
    }
}

/// How this producer shapes its blocks.
#[derive(Clone, Copy, Debug)]
pub struct Production {
    /// Bytes of junk data placed in every block body.
    pub body_size: usize,
    /// Minimum time between two blocks this producer builds; zero builds as fast as block
    /// custody admits.
    pub interval: Duration,
}

/// Deterministic application attachment backed by marshal block custody.
pub struct Application<E: Clock + Spawner> {
    context: Arc<E>,
    seed: u64,
    production: Production,
    last_build: Arc<Mutex<Option<SystemTime>>>,
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
            production: self.production,
            last_build: Arc::clone(&self.last_build),
            publication_retention: self.publication_retention,
            producer_chain: self.producer_chain,
            marshal: self.marshal.clone(),
            staged: self.staged.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<E: Clock + Spawner> Application<E> {
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
        Self {
            context: Arc::new(context),
            seed,
            production,
            last_build: Arc::new(Mutex::new(None)),
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
        let (mut sender, receiver) = oneshot::channel();
        // Pace this producer to its interval: the next build starts no earlier than the
        // interval after the previous one began.
        let next_build = {
            let mut last_build = self.last_build.lock();
            let now = self.context.current();
            let next = last_build
                .map_or(now, |last| last + self.production.interval)
                .max(now);
            *last_build = Some(next);
            next
        };
        self.context
            .child("propose")
            .shared(true)
            .spawn(move |runtime| async move {
                select! {
                    _ = sender.closed() => return,
                    () = runtime.sleep_until(next_build) => {},
                }
                // Latency is measured from the moment the block is built, not from the
                // request: the pacing wait above is production policy, not consensus time.
                let started_at = runtime.current();
                let block = Arc::new(TransactionBlock::from_context(
                    context,
                    Body::junk(seed, context, body_size),
                ));
                let body_digest = block.header().body_digest();
                let block_digest = block.digest();
                let reference = block.reference();
                let custody = select! {
                    _ = sender.closed() => return,
                    result = marshal.stage_block(Arc::clone(&block)) => result,
                };
                let custody = match custody {
                    Ok(custody) => custody,
                    Err(error) => {
                        warn!(?reference, %error, "cannot stage proposed block");
                        return;
                    }
                };
                if !staged.insert_with_custody(block, Some(custody)) {
                    return;
                }
                proposal_latency.start(reference, started_at);
                info!(
                    chain = context.chain().get(),
                    height = context.height().get(),
                    ?body_digest,
                    ?block_digest,
                    body_size,
                    "produced body"
                );
                if sender.send(body_digest).is_err() {
                    proposal_latency.cancel(reference);
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
                let requested_at = SystemTime::now();
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
                        body_wait.observe_between(requested_at, SystemTime::now());
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
            self.metrics
                .proposal_latency
                .finalize(fact.blocks(), &self.staged);
        }
        let certified = match &activity {
            Activity::ProtocolAccepted { artifact, .. } => match artifact.as_ref() {
                Artifact::DaCertificate(certificate) => Some(certificate.block_ref::<Sha256>()),
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
    use commonware_codec::Encode;
    use commonware_consensus::types::{Epoch, Height};
    use commonware_runtime::{Runner as _, deterministic};
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
        let encoded = body.encode();
        let decoded = Body::read_cfg(&mut encoded.as_ref(), &Body::codec_config(4_097)).unwrap();
        assert_eq!(decoded, body);

        let block = TransactionBlock::<Sha256, _>::from_context(context, body);
        assert_eq!(block.header().body_digest(), block.body().digest());
        assert_ne!(block.digest(), block.header().body_digest());
        assert!(block.encode_size() <= Body::max_block_size(4_097));
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
                );
            }
            let started = latency.started.lock();
            assert_eq!(started.len(), 2);
            assert_eq!(started.front().unwrap().block.height(), Height::new(2));
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
                latency.start(reference, SystemTime::now());
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
            latency.start(left.reference(), SystemTime::now());

            latency.finalize(&[right.reference()], &staged);
            assert!(
                latency
                    .started
                    .lock()
                    .iter()
                    .any(|start| start.block == left.reference() && !start.finalized)
            );

            latency.finalize(&[left.reference()], &staged);
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
            latency.start(parent.reference(), SystemTime::now());

            latency.finalize(&[child.reference()], &staged);
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
            latency.start(block, SystemTime::now());
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
