//! Synchronizer tests: shared fixtures here, one module per concern.

use super::{
    actor::{Config, Core},
    custody::{Completion, CustodyWindow, WindowBounds},
    inbox::{Absorb, Idle, Inbox},
    mailbox::{Error, Message, Target},
    ports::{CatalogPort, Fetcher, HeaderSegments},
    publish::{COMMIT_WINDOW, PlannedOutput, PublicationBatch},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::Append,
        marshal::{
            OutputIndex,
            actors::{
                backfill::{CustodiedBlock, SharedHeaders, SharedHistory},
                delivery,
                metrics::{self, FetchReason},
            },
            config::{ArchiveMode, Retention},
            protocol::{floor::Error as FloorError, order},
            storage::{
                catalog_state::{Checkpoint, CheckpointParts, PendingFloors, frontier_index},
                commit::{Commit, CustodyRef, OutputRow},
                scratch::{BlockStack, HistoryLink, HistoryStack},
            },
            testing,
            types::{CustodyValues, Floor, LqcVerifier},
            wire::max_block_segment_items,
        },
        mocks::Committee,
        testing::{SpanRecorder, TestBody},
        types::{
            BlockRef, CertificateId, ChainId, ChainSet, CodecConfig, HistoryRecord, Lqc,
            TransactionBlock, TransactionBlockHeader,
        },
    },
    types::{Epoch, Height, Participant, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy as _},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{channel::oneshot, sync::Mutex};
use rstest::rstest;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tracing::{Span, info_span, subscriber::with_default};
use tracing_subscriber::{prelude::*, registry};

mod custody;
mod floor;
mod mocks;
mod publish;
mod run;
mod sweep;
mod walk;

use mocks::{
    FetchGates, MockBlockStack, MockBlocks, MockCatalog, MockError, MockFetcher, MockStack,
    MockVerifier, StallGate,
};

type TestBlock = TransactionBlock<Sha256, TestBody>;

type CommitWaiters = Arc<Mutex<VecDeque<oneshot::Sender<Result<(), MockError>>>>>;

type TestCore<I> = Core<
    I,
    MockCatalog,
    MockFetcher,
    MockStack,
    MockBlockStack,
    MockVerifier,
    Sha256,
    MinPk,
    TestBody,
>;

type TestSynchronizer = TestCore<Idle>;

type TestInbox = Inbox<MinPk, Sha256Digest>;

fn digest(label: &[u8], value: u64) -> Sha256Digest {
    Sha256::hash(&[label, &value.to_be_bytes()])
}

fn committee(seed: u64, chains: u32) -> Committee<MinPk> {
    Committee::builder(seed, 6)
        .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_SYNCHRONIZER")
        .producers((0..chains).map(Participant::new).collect())
        .build()
}

/// Returns the opening of view 1 that keeps every chain at genesis.
fn genesis_record(committee: &Committee<MinPk>) -> Arc<HistoryRecord<Sha256Digest>> {
    let genesis = committee.config.genesis();
    Arc::new(HistoryRecord::new(genesis.history(), genesis.tips().to_vec()).unwrap())
}

/// Returns the openings of views 1 through `views`, each keeping every chain at genesis.
fn genesis_views(
    committee: &Committee<MinPk>,
    views: usize,
) -> Vec<Arc<HistoryRecord<Sha256Digest>>> {
    let tips = committee.config.genesis().tips().to_vec();
    let mut parent = committee.config.genesis().history();
    (0..views)
        .map(|_| {
            let record = Arc::new(HistoryRecord::new(parent, tips.clone()).unwrap());
            parent = record.commitment::<Sha256>();
            record
        })
        .collect()
}

/// Returns the L-QC of `signers` for view `view`, whose leader commits to `history`.
fn lqc(
    committee: &Committee<MinPk>,
    view: u64,
    history: Sha256Digest,
    signers: impl IntoIterator<Item = usize>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    Arc::new(testing::lqc(committee, view, history, signers))
}

/// Returns the L-QC of view 2, which pins the opening of view 1 from [`genesis_record`].
fn genesis_lqc(
    committee: &Committee<MinPk>,
    signers: impl IntoIterator<Item = usize>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    lqc(
        committee,
        2,
        genesis_record(committee).commitment::<Sha256>(),
        signers,
    )
}

/// Returns the command synchronizing through `view`, opened by `record`.
fn resolve_message(
    view: u64,
    record: &Arc<HistoryRecord<Sha256Digest>>,
) -> Message<MinPk, Sha256Digest> {
    Message::Synchronize {
        span: Span::none(),
        target: Target::resolved(
            View::new(view),
            record.commitment::<Sha256>(),
            Arc::clone(record),
            2,
        ),
    }
}

/// Returns the command synchronizing through the view `proof` pins.
fn finalize_message(proof: &Arc<Lqc<MinPk, Sha256Digest>>) -> Message<MinPk, Sha256Digest> {
    Message::Synchronize {
        span: Span::none(),
        target: Target::finalized(proof.id::<Sha256>(), Arc::clone(proof), None, 2),
    }
}

fn base(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
    BlockRef::new(
        ChainId::new(chain),
        Height::new(height),
        digest(b"base", (u64::from(chain) << 32) | height),
    )
}

fn chain(epoch: Epoch, base: BlockRef<Sha256Digest>, count: usize) -> Vec<Arc<TestBlock>> {
    branch(epoch, base, count, b"body parent")
}

/// Returns `count` blocks above `base` whose bodies are derived from `label`, so distinct labels
/// fork at `base`.
fn branch(
    epoch: Epoch,
    base: BlockRef<Sha256Digest>,
    count: usize,
    label: &[u8],
) -> Vec<Arc<TestBlock>> {
    let mut parent = base.digest();
    (1..=count)
        .map(|offset| {
            let height = base.height().get() + offset as u64;
            let body = TestBody::new(digest(label, height), Height::new(height), height);
            let header = TransactionBlockHeader::new(
                epoch,
                base.chain(),
                Height::new(height),
                parent,
                body.digest(),
            )
            .unwrap();
            let block = Arc::new(TransactionBlock::new(header, body).unwrap());
            parent = block.reference().digest();
            block
        })
        .collect()
}

fn tip(blocks: &[Arc<TestBlock>]) -> BlockRef<Sha256Digest> {
    blocks.last().unwrap().reference()
}

fn checkpoint(
    epoch: Epoch,
    view: u64,
    history: Sha256Digest,
    ordered: Vec<BlockRef<Sha256Digest>>,
    emitted: Vec<BlockRef<Sha256Digest>>,
) -> Checkpoint<Sha256Digest> {
    // Every test starts from a floor, with no output rows below its frontier.
    let floor_index = frontier_index(&emitted).unwrap();
    Checkpoint::try_from(CheckpointParts {
        epoch,
        floor_generation: 0,
        archive_layout: Retention {
            lqc: ArchiveMode::Immutable,
            history: ArchiveMode::Immutable,
            blocks: ArchiveMode::Immutable,
        },
        floor: CertificateId::new(digest(b"floor", epoch.get())),
        view: View::new(view),
        history,
        history_index: None,
        ordered,
        emitted,
        floor_index,
    })
    .unwrap()
}

fn single_chain_opening(
    epoch: Epoch,
    base: BlockRef<Sha256Digest>,
    count: usize,
    history: Sha256Digest,
) -> (
    Checkpoint<Sha256Digest>,
    Vec<Vec<Arc<TestBlock>>>,
    HistoryLink<Sha256>,
) {
    let blocks = vec![chain(epoch, base, count)];
    let record = Arc::new(HistoryRecord::new(history, vec![tip(&blocks[0])]).unwrap());
    let commitment = record.commitment::<Sha256>();
    (
        checkpoint(epoch, 0, record.parent(), vec![base], vec![base]),
        blocks,
        HistoryLink { commitment, record },
    )
}

async fn actor(
    context: &deterministic::Context,
    checkpoint: Checkpoint<Sha256Digest>,
    blocks: Vec<Vec<Arc<TestBlock>>>,
    codec: CodecConfig,
    max: usize,
) -> TestSynchronizer {
    actor_with_backfill(context, checkpoint, blocks, codec, max, 32).await
}

async fn actor_with_backfill(
    context: &deterministic::Context,
    checkpoint: Checkpoint<Sha256Digest>,
    blocks: Vec<Vec<Arc<TestBlock>>>,
    codec: CodecConfig,
    max: usize,
    backfill_concurrency: usize,
) -> TestSynchronizer {
    let catalog_blocks = MockBlocks::default();
    let fetcher = MockFetcher {
        blocks: Arc::new(blocks),
        catalog_blocks: Arc::clone(&catalog_blocks),
        ..MockFetcher::default()
    };
    recover(
        context,
        mock_catalog(checkpoint, catalog_blocks),
        fetcher,
        codec,
        max,
        backfill_concurrency,
    )
    .await
    .unwrap()
}

fn mock_catalog(checkpoint: Checkpoint<Sha256Digest>, blocks: MockBlocks) -> MockCatalog {
    MockCatalog {
        checkpoint,
        latest: None,
        blocks,
        block_batches: Arc::default(),
        block_calls: Arc::new(AtomicUsize::new(0)),
        header_limits: Arc::default(),
        header_gate: Arc::default(),
        outputs: Vec::new(),
        handoff: Vec::new(),
        batches: Vec::new(),
        history_commits: 0,
        selected: Vec::new(),
        selected_calls: Arc::default(),
        proofs: BTreeMap::new(),
        commit_calls: Arc::new(AtomicUsize::new(0)),
        commit_waiters: None,
        commit_start_gate: None,
        installed: 0,
        calls: Arc::default(),
    }
}

async fn recover(
    context: &deterministic::Context,
    catalog: MockCatalog,
    fetcher: MockFetcher,
    codec: CodecConfig,
    max: usize,
    backfill_concurrency: usize,
) -> Result<TestSynchronizer, Error> {
    Core::recover(
        Config {
            catalog,
            fetcher,
            history_stack: MockStack::default(),
            block_stack: MockBlockStack::default(),
            verifier: MockVerifier {
                valid: true,
                ..MockVerifier::default()
            },
            codec,
            mailbox_size: NonZeroUsize::MIN,
            header_cache_capacity: NonZeroUsize::new(16 * 1024).unwrap(),
            backfill_concurrency: NonZeroUsize::new(backfill_concurrency).unwrap(),
            max_commit_outputs: NonZeroUsize::new(max).unwrap(),
            max_commit_block_bytes: NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
            max_block_bytes: NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
            max_value_bytes: NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
        },
        metrics::Synchronizer::new(context),
    )
    .await
}

async fn genesis_actor(
    context: &deterministic::Context,
    committee: &Committee<MinPk>,
    max: usize,
) -> TestSynchronizer {
    let genesis = committee.config.genesis();
    let mut actor = actor(
        context,
        checkpoint(
            committee.config.epoch(),
            0,
            genesis.history(),
            genesis.tips().to_vec(),
            genesis.tips().to_vec(),
        ),
        vec![Vec::new(); committee.codec().chains()],
        committee.codec(),
        max,
    )
    .await;
    // Peers serve the openings of the first views, which keep every chain at genesis.
    actor.fetcher.histories = genesis_views(committee, 3)
        .into_iter()
        .map(|record| (record.commitment::<Sha256>(), record))
        .collect();
    actor
}

async fn commit_opening<I: Absorb<MinPk, Sha256Digest>>(
    actor: &mut TestCore<I>,
    link: HistoryLink<Sha256>,
) {
    let mut batch = PublicationBatch::new(actor.bounds.max_commit_outputs, 0);
    actor
        .open_window(vec![link], &mut BTreeMap::new(), &mut batch)
        .await
        .unwrap();
    actor.commit(batch).await.unwrap();
}

fn planned(index: u64, block: &Arc<TestBlock>) -> PlannedOutput<Sha256, TestBody> {
    PlannedOutput {
        index: OutputIndex::new(index),
        custody: CustodyRef::for_test(block),
        block: None,
    }
}

fn publication(
    outputs: Vec<PlannedOutput<Sha256, TestBody>>,
) -> PublicationBatch<Sha256, MinPk, TestBody> {
    let output_bytes = outputs
        .iter()
        .map(|output| output.custody.meta().encoded_len())
        .sum();
    PublicationBatch {
        selected: Vec::new(),
        history: Vec::new(),
        outputs,
        output_bytes,
    }
}
