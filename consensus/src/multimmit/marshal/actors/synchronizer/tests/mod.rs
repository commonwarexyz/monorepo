//! Synchronizer tests: shared fixtures here, one module per concern.

use super::{
    actor::{Config, Core},
    custody::{Completion, CustodyWindow, WindowBounds},
    inbox::{Absorb, Idle, Inbox},
    mailbox::{Error, FinalityBatch, Message},
    ports::{CatalogPort, Fetcher, HeaderSegments},
    publish::{COMMIT_WINDOW, PlannedOutput, PublicationBatch},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            actors::{
                backfill::{CustodiedBlock, SharedHeaders, SharedHistory},
                delivery,
                metrics::{self, FetchReason},
            },
            config::{ArchiveMode, Retention},
            protocol::{
                floor::Error as FloorError,
                order::{Slot, SlotStream},
            },
            storage::{
                catalog_state::{Checkpoint, CheckpointParts, PendingFloors},
                commit::{Commit, CustodyRef, OutputRow},
                scratch::{BlockStack, HistoryLink, HistoryStack},
            },
            types::{CustodyValues, Floor, LqcVerifier, OutputIndex},
            wire::max_block_segment_items,
        },
        mocks::Committee,
        testing::{SpanRecorder, TestBody},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, CodecConfig, DigestedLeader,
            Extension, FinalityFact, FinalityId, LeaderBlock, Lqc, PathLimits, Position,
            SelectedCommitments, TipRecord, TransactionBlock, TransactionBlockHeader, VoteBody,
            genesis_history,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
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
use commonware_parallel::Sequential;
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
mod walk;

use mocks::{
    FetchGates, HeaderGate, MockBlockStack, MockBlocks, MockCatalog, MockError, MockFetcher,
    MockStack, MockVerifier,
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

fn committee(seed: u64, chains: u32, limits: PathLimits) -> Committee<MinPk> {
    Committee::builder(seed, 6)
        .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_SYNCHRONIZER")
        .producers((0..chains).map(Participant::new).collect())
        .limits(limits)
        .build()
}

fn genesis_record(committee: &Committee<MinPk>) -> Arc<TipRecord<Sha256Digest>> {
    let genesis = committee.config.genesis();
    Arc::new(
        TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec()).unwrap(),
    )
}

fn lqc(
    committee: &Committee<MinPk>,
    view: u64,
    signers: impl IntoIterator<Item = usize>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    let leader = committee.leader_block(View::new(view));
    let votes = signers
        .into_iter()
        .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
        .collect::<Vec<_>>();
    Arc::new(
        committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
            .unwrap(),
    )
}

fn lqc_with_history(
    committee: &Committee<MinPk>,
    view: u64,
    history: Sha256Digest,
    tip: BlockRef<Sha256Digest>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    let leader = LeaderBlock::new(
        Round::new(committee.config.epoch(), View::new(view)),
        committee.config.genesis().vqc(),
        history,
        vec![
            ChainProposal::new(
                ChainId::new(0),
                Anchor::Tip(tip),
                Vec::new(),
                committee.codec().pipeline_depth(),
            )
            .unwrap(),
        ],
        committee.codec(),
    )
    .unwrap();
    let vote = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(0)],
        vec![Extension::empty()],
        committee.codec(),
    )
    .unwrap();
    let votes = (0..committee.codec().view_quorum())
        .map(|signer| committee.signers[signer].sign_vote(vote.clone()).unwrap())
        .collect::<Vec<_>>();
    Arc::new(
        committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
            .unwrap(),
    )
}

/// Returns the direct-pool finality fact for `proof`'s leader proposal, supported by a view
/// quorum, that finalizes `tips` with every chain settled at position zero.
fn pool_fact(
    committee: &Committee<MinPk>,
    proof: &Lqc<MinPk, Sha256Digest>,
    tips: Vec<BlockRef<Sha256Digest>>,
) -> FinalityFact<Sha256Digest> {
    let leader = proof.leader();
    let chains = tips.len();
    FinalityFact::new(
        FinalityId::Direct(digest(b"direct pool", leader.round().view().get())),
        leader.round(),
        leader.digest::<Sha256>(),
        leader.parent(),
        committee.codec().view_quorum(),
        tips,
        leader.proposed_heights(),
        vec![Position::new(0); chains],
        vec![true; chains],
    )
}

fn base(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
    BlockRef::new(
        ChainId::new(chain),
        Height::new(height),
        digest(b"base", (u64::from(chain) << 32) | height),
    )
}

fn chain(epoch: Epoch, base: BlockRef<Sha256Digest>, count: usize) -> Vec<Arc<TestBlock>> {
    let mut parent = base.digest();
    (1..=count)
        .map(|offset| {
            let height = base.height().get() + offset as u64;
            let body = TestBody::new(digest(b"body parent", height), Height::new(height), height);
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

fn selected(epoch: Epoch, blocks: &[Vec<Arc<TestBlock>>]) -> SelectedCommitments<Sha256Digest> {
    SelectedCommitments::new(
        epoch,
        blocks
            .iter()
            .filter(|chain| !chain.is_empty())
            .map(|chain| {
                let first = chain[0].header();
                std::iter::once(BlockRef::new(
                    first.chain(),
                    first.height().previous().unwrap(),
                    first.parent(),
                ))
                .chain(chain.iter().map(|block| block.reference()))
                .collect::<Vec<_>>()
                .into()
            })
            .collect(),
    )
}

fn tip(blocks: &[Arc<TestBlock>]) -> BlockRef<Sha256Digest> {
    blocks.last().unwrap().reference()
}

fn checkpoint(
    epoch: Epoch,
    history: Sha256Digest,
    ordered: Vec<BlockRef<Sha256Digest>>,
    emitted: Vec<BlockRef<Sha256Digest>>,
) -> Checkpoint<Sha256Digest> {
    Checkpoint::try_from(CheckpointParts {
        epoch,
        floor_generation: 0,
        archive_layout: Retention {
            lqc: ArchiveMode::Immutable,
            history: ArchiveMode::Immutable,
            blocks: ArchiveMode::Immutable,
        },
        floor: CertificateId::new(digest(b"floor", epoch.get())),
        history,
        history_index: None,
        ordered,
        emitted,
        committed: None,
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
    let record = Arc::new(TipRecord::at_tips(history, vec![tip(&blocks[0])]).unwrap());
    let commitment = record.commitment::<Sha256>();
    (
        checkpoint(epoch, record.parent(), vec![base], vec![base]),
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
    let history = genesis_record(committee);
    let mut actor = actor(
        context,
        checkpoint(
            committee.config.epoch(),
            genesis_history::<Sha256>(genesis),
            genesis.tips().to_vec(),
            genesis.tips().to_vec(),
        ),
        vec![Vec::new(); committee.codec().chains()],
        committee.codec(),
        max,
    )
    .await;
    actor
        .fetcher
        .histories
        .push((history.commitment::<Sha256>(), history));
    actor
}

async fn commit_opening<I: Absorb<MinPk, Sha256Digest>>(
    actor: &mut TestCore<I>,
    link: HistoryLink<Sha256>,
) {
    let mut batch = PublicationBatch::new(actor.bounds.max_commit_outputs, 0);
    actor.open(link, &mut batch).await.unwrap();
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
