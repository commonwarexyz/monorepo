use bytes::{Buf, BufMut, Bytes};
use commonware_actor::Feedback;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, Write,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_consensus::{
    Automaton, Epochable as _, Heightable as _, Relay, Reporter,
    multimmit::{
        Artifact,
        marshal::{Custody, Mailbox, Update},
        types::{Activity, BlockRef, Context, TransactionBlock, TransactionBlockHeader},
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
    time::SystemTime,
};
use tracing::{info, warn};

const BODY_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_BODY";

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

type ProposalStarts = VecDeque<(BlockRef<Sha256Digest>, SystemTime)>;

/// Tracks temporary proposal-to-consensus-finality latency for the example dashboard.
#[derive(Clone)]
pub struct ProposalLatency {
    started: Arc<Mutex<ProposalStarts>>,
    capacity: usize,
    latency: Histogram,
    dropped: Counter,
}

impl ProposalLatency {
    /// Registers the proposal latency histogram.
    pub fn new(context: &impl Metrics, capacity: NonZeroUsize) -> Self {
        Self {
            started: Arc::new(Mutex::new(VecDeque::new())),
            capacity: capacity.get(),
            latency: context.histogram(
                "proposal_finalization_latency",
                "time from proposal preparation to inclusion by a directly finalized leader",
                (1..=200)
                    .map(|step| f64::from(step) * 0.005)
                    .chain([2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]),
            ),
            dropped: context.counter(
                "proposal_finalization_dropped_total",
                "proposal latency samples dropped before direct finality",
            ),
        }
    }

    fn start(&self, block: BlockRef<Sha256Digest>, started_at: SystemTime) {
        let mut started = self.started.lock();
        if started.iter().any(|(reference, _)| *reference == block) {
            return;
        }
        while started.len() >= self.capacity {
            started.pop_front();
            self.dropped.inc();
        }
        started.push_back((block, started_at));
    }

    fn cancel(&self, block: BlockRef<Sha256Digest>) {
        let mut started = self.started.lock();
        if let Some(index) = started
            .iter()
            .position(|(reference, _)| *reference == block)
        {
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
        self.started.lock().retain(|(reference, started_at)| {
            if finalized.contains(reference) {
                samples.push(*started_at);
                false
            } else {
                true
            }
        });
        let now = SystemTime::now();
        for started_at in samples {
            self.latency.observe_between(started_at, now);
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

/// Deterministic application attachment backed by marshal block custody.
pub struct Application<E: Clock + Spawner> {
    context: Arc<E>,
    seed: u64,
    body_size: usize,
    publication_retention: NonZeroUsize,
    marshal: Marshal,
    staged: Staged,
    proposal_latency: ProposalLatency,
}

impl<E: Clock + Spawner> Clone for Application<E> {
    fn clone(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            seed: self.seed,
            body_size: self.body_size,
            publication_retention: self.publication_retention,
            marshal: self.marshal.clone(),
            staged: self.staged.clone(),
            proposal_latency: self.proposal_latency.clone(),
        }
    }
}

impl<E: Clock + Spawner> Application<E> {
    /// Creates an application whose complete blocks are transported and retained by `marshal`.
    pub fn new(
        context: E,
        seed: u64,
        body_size: usize,
        publication_retention: NonZeroUsize,
        marshal: Marshal,
        proposal_latency: ProposalLatency,
    ) -> Self {
        Self {
            context: Arc::new(context),
            seed,
            body_size,
            publication_retention,
            marshal,
            staged: Staged::default(),
            proposal_latency,
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
        let body_size = self.body_size;
        let marshal = self.marshal.clone();
        let staged = self.staged.clone();
        let proposal_latency = self.proposal_latency.clone();
        let started_at = SystemTime::now();
        let (mut sender, receiver) = oneshot::channel();
        self.context
            .child("propose")
            .shared(true)
            .spawn(move |_| async move {
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
        let (mut sender, receiver) = oneshot::channel();
        self.context.child("verify").spawn(move |_| async move {
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
            let subscription = select! {
                _ = sender.closed() => return,
                result = marshal.subscribe_block(reference) => result,
            };
            match subscription {
                Ok(block) => {
                    if block.header() != &header {
                        let _ = sender.send(false);
                        return;
                    }
                    let _ = sender.send(staged.insert(block));
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
        if let Activity::LeaderFinalized { fact } = &activity {
            self.proposal_latency.finalize(fact.blocks(), &self.staged);
        }
        let certified = match &activity {
            Activity::ProtocolAccepted { artifact, .. } => match artifact.as_ref() {
                Artifact::DaCertificate(certificate) => Some(certificate.block_ref::<Sha256>()),
                _ => None,
            },
            Activity::HistoryAccepted { .. } => None,
            Activity::LeaderFinalized { .. } => None,
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
            assert_eq!(started.front().unwrap().0.height(), Height::new(2));
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
            assert!(!started.iter().any(|(reference, _)| *reference == old));
            assert!(started.iter().any(|(reference, _)| *reference == newer));
            assert!(started.iter().any(|(reference, _)| *reference == newest));
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
                    .any(|(reference, _)| *reference == left.reference())
            );

            latency.finalize(&[left.reference()], &staged);
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
            assert!(latency.started.lock().is_empty());
        });
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
