//! Fuzz driver for marshal with prunable finalized archives.

use crate::{
    marshal::end_to_end::twins::{PublicKeyOf, SchemeOf},
    scenarios::recording_resolver::{RecordingResolver, init_injectable},
};
use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Heightable, Reporter,
    marshal::{
        Config, Identifier, Start, Update,
        ancestry::Ancestry as _,
        core::{Actor, CommitmentFallback, DigestFallback, Mailbox},
        mocks::{
            application::Application,
            harness::{
                B, BLOCKS_PER_EPOCH, D, NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE, PAGE_SIZE,
                QUORUM, StandardHarness, TEST_QUOTA, TestHarness, setup_network_with_participants,
            },
        },
        resolver::handler::{Annotation, Finalized, Key},
        standard::Standard,
        store::{Blocks as StoreBlocks, Certificates as StoreCertificates},
    },
    simplex::types::{Activity, Finalization, Finalize, Proposal},
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{SimplexCertificateMock, simplex::Simplex as _};
use commonware_cryptography::{
    Digested, Digestible,
    certificate::{ConstantProvider, Verifier as _},
};
use commonware_macros::select;
use commonware_p2p::{Recipients, simulated::Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::Outcome;
use commonware_runtime::{
    Clock, Handle, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
    telemetry::metrics::histogram::Timed,
};
use commonware_storage::{
    archive::{Identifier as ArchiveIdentifier, prunable},
    translator::EightCap,
};
use commonware_utils::{FuzzRng, NZU64, NZUsize, non_empty, vec::NonEmptyVec};
use futures::StreamExt as _;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// The store fuzzer runs on the cheap certificate mock; `K` is unchanged
/// (ed25519), so only the certificate scheme differs from the harness default.
type CertScheme = SchemeOf<SimplexCertificateMock>;
type K = PublicKeyOf<SimplexCertificateMock>;
type StoreVariant = Standard<B>;
/// The actor's resolver, held by the harness so scripted deliveries can answer
/// the fetches it records.
type StoreResolver = RecordingResolver<SimplexCertificateMock>;

/// The actor's application: the mock, with acknowledgements the driver can hold.
#[derive(Clone)]
struct StoreApplication {
    inner: Application<B>,
    hold: Arc<AtomicBool>,
}

impl Default for StoreApplication {
    fn default() -> Self {
        Self {
            inner: Application::manual_ack(),
            hold: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl StoreApplication {
    /// Acknowledges every block the application holds, oldest first.
    fn acknowledge_all(&self) {
        while self.inner.acknowledge_next().is_some() {}
    }
}

impl Reporter for StoreApplication {
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let block = matches!(activity, Update::Block(..));
        let feedback = self.inner.report(activity);
        if block && !self.hold.load(Ordering::Relaxed) {
            self.acknowledge_all();
        }
        feedback
    }
}

/// Certificate-mock port of the harness prunable-validator setup: identical
/// wiring, with the BLS scheme replaced by the certificate mock and the
/// resolver built around a handler the harness keeps.
#[allow(clippy::type_complexity)]
async fn setup_prunable_validator_cert_mock(
    context: deterministic::Context,
    oracle: &Oracle<K, deterministic::Context>,
    validator: K,
    schemes: &[CertScheme],
    partition_prefix: &str,
    page_cache: CacheRef,
    unbuffered: bool,
) -> (
    Mailbox<CertScheme, StoreVariant>,
    buffered::Mailbox<K, B>,
    StoreApplication,
    Handle<()>,
    StoreResolver,
) {
    let control = oracle.control(validator.clone());
    let provider = ConstantProvider::new(schemes[0].clone());
    let config = Config {
        provider,
        epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
        start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
        mailbox_size: MAILBOX_SIZE,
        view_retention: VIEW_RETENTION,
        max_repair: NZUsize!(10),
        max_pending_acks: NZUsize!(1),
        block_codec_config: (),
        partition_prefix: partition_prefix.to_string(),
        prunable_items_per_section: NZU64!(10),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        page_cache: page_cache.clone(),
        strategy: Sequential,
    };

    // Backfill channel 1 and broadcast channel 2, as marshal numbers them.
    let ((receiver, resolver_mailbox), handler) =
        init_injectable::<SimplexCertificateMock>(&context, oracle, validator.clone()).await;
    let resolver = RecordingResolver::injectable(handler, resolver_mailbox);

    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
            blocker: control.clone(),
            strategy: Sequential,
        },
    );
    let network = control.register(2, TEST_QUOTA).await.unwrap();
    broadcast_engine.start(network);

    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        prunable::Config {
            translator: EightCap,
            metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
            key_partition: format!("{partition_prefix}-finalizations-by-height-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalizations-by-height-value"),
            compression: None,
            codec_config: CertScheme::certificate_codec_config_unbounded(),
            items_per_section: NZU64!(10),
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            replay_buffer: config.replay_buffer,
        },
    )
    .await
    .expect("failed to initialize finalizations by height archive");

    let finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        prunable::Config {
            translator: EightCap,
            metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
            key_partition: format!("{partition_prefix}-finalized-blocks-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-finalized-blocks-value"),
            compression: None,
            codec_config: config.block_codec_config,
            items_per_section: NZU64!(10),
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            replay_buffer: config.replay_buffer,
        },
    )
    .await
    .expect("failed to initialize finalized blocks archive");

    let (actor, mailbox, _) = Actor::init(
        context.child("actor"),
        finalizations_by_height,
        finalized_blocks,
        config,
    )
    .await;
    let application = StoreApplication::default();
    let handle = if unbuffered {
        actor.start_unbuffered(application.clone(), (receiver, resolver.clone()))
    } else {
        actor.start(
            application.clone(),
            buffer.clone(),
            (receiver, resolver.clone()),
        )
    };

    (mailbox, buffer, application, handle, resolver)
}

const NUM_BLOCKS: u64 = 16;
const FORCED_OPS: usize = 29;
/// Raised with `FORCED_OPS`, so the byte that draws the extra operations keeps
/// its meaning.
const MAX_OPS: usize = 98;
const EVENT_SETTLE: Duration = Duration::from_millis(20);
/// Views of verified blocks the actor keeps below an earlier finalization.
const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);
/// How long one ancestry step may wait for the next block.
const ANCESTRY_STEP: Duration = EVENT_SETTLE;
/// Enough steps to walk from the newest block down to genesis and see the end,
/// when every parent is local.
const MAX_ANCESTRY_STEPS: usize = NUM_BLOCKS as usize + 2;
/// Actor mailbox capacity; a burst longer than this spills into the overflow
/// policy that coalesces hints, floors, and prunes.
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(100);
/// Settle periods the driver waits for a block the actor owes the application.
const DISPATCH_STEPS: usize = 5;

fn block_idx(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=((NUM_BLOCKS - 1) as u8))
}

fn block_index(idx: u8) -> usize {
    (idx as u64 % NUM_BLOCKS) as usize
}

/// Canonical finalization round of `height`. Views advance two per height so
/// every block also has a spare view, above its canonical one and below the
/// next height's, for a finalization at a later view.
fn round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(2 * height.get() - 1))
}

/// The spare view of `height`: a re-proposal finalized after a nullification.
/// A floor at this round stays below the next canonical round, so it neither
/// hides later canonical finalizations nor prunes seeded views above the floor.
fn late_round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(2 * height.get()))
}

fn hint_targets(participants: &[K], selector: u8) -> NonEmptyVec<K> {
    let count = usize::from(selector % 3) + 1;
    let peers = participants
        .iter()
        .skip(1)
        .take(count)
        .cloned()
        .collect::<Vec<_>>();
    NonEmptyVec::try_from(peers).expect("fixture has peers")
}

fn parent_view(height: Height) -> View {
    height
        .previous()
        .filter(|parent| parent.get() > 0)
        .map_or(View::zero(), |parent| round_for_height(parent).view())
}

#[derive(Debug, Clone, Copy)]
pub enum StoreOp {
    SeedBlock {
        block_idx: u8,
    },
    ReportFinalization {
        block_idx: u8,
    },
    GetBlock {
        block_idx: u8,
        by_digest: bool,
    },
    GetInfo {
        block_idx: u8,
        latest: bool,
    },
    GetFinalization {
        block_idx: u8,
    },
    /// `clamp` bounds the height by the processed height so the prune takes
    /// effect; otherwise it may land above the floor and be rejected.
    Prune {
        block_idx: u8,
        clamp: bool,
    },
    /// `late_round` finalizes the block at a view above every canonical round,
    /// so the floor passes the round check even when its height is already
    /// processed.
    SetFloor {
        block_idx: u8,
        late_round: bool,
    },
    HintFinalized {
        block_idx: u8,
        targets: u8,
    },
    /// Enqueues more fire-and-forget messages than the mailbox holds without
    /// yielding, so the tail goes through the overflow policy.
    MessageBurst {
        block_idx: u8,
        count: u8,
    },
    Forward {
        block_idx: u8,
    },
    /// Subscribes to a block and drops the subscription if it is not served
    /// within one settle period.
    Subscribe {
        block_idx: u8,
        by_digest: bool,
    },
    /// Answers a block fetch the actor issued with the canonical block, as a
    /// peer response would. No-op when the block was never requested.
    DeliverBlock {
        block_idx: u8,
        annotation: DeliverAnnotation,
    },
    Restart,
    ObserveApplication,
    DirectPutBlock {
        block_idx: u8,
    },
    DirectSyncBlocks,
    DirectGetBlock {
        block_idx: u8,
        by_digest: bool,
    },
    DirectPruneBlocks {
        block_idx: u8,
    },
    DirectMissingBlocks {
        block_idx: u8,
        max: u8,
    },
    DirectLastBlock,
    DirectPutCertificate {
        block_idx: u8,
    },
    DirectSyncCertificates,
    DirectGetCertificate {
        block_idx: u8,
        by_digest: bool,
    },
    DirectPruneCertificates {
        block_idx: u8,
    },
    DirectCertificateRanges {
        block_idx: u8,
    },
    DirectLastCertificate,
    /// Walks the ancestry stream from a canonical block. `bounded` asks for a
    /// round-bound fallback; `serve` answers each parent fetch the stream
    /// issues with the canonical parent.
    Ancestry {
        block_idx: u8,
        bounded: bool,
        serve: bool,
    },
    /// Reads the verified block of a canonical block's round.
    GetVerified {
        block_idx: u8,
    },
    /// Holds application acknowledgements, or acknowledges every held block
    /// and stops holding.
    HoldAcks {
        hold: bool,
    },
    /// Acknowledges up to `count` held blocks, oldest first, one settle
    /// period apart.
    AckBlocks {
        count: u8,
    },
    /// Builds a floor that waits for a pruned anchor while the round floor lags
    /// behind the processed height, then (unless `waiting`) reports the
    /// finalization at the processed height.
    LagFloor {
        waiting: bool,
    },
}

/// First floor of [`StoreOp::LagFloor`]. The anchor of its second floor is one
/// block above, the last height of the first archive section, so one clamped
/// prune removes it and keeps the processed block.
const LAG_FLOOR_BLOCK: u8 = 7;

/// The operations [`StoreOp::LagFloor`] stands for.
fn lag_floor_steps(waiting: bool) -> Vec<StoreOp> {
    let floor = LAG_FLOOR_BLOCK;
    let (anchor, processed, next) = (floor + 1, floor + 2, floor + 3);
    let mut steps = vec![
        StoreOp::SeedBlock { block_idx: floor },
        StoreOp::SetFloor {
            block_idx: floor,
            late_round: false,
        },
        StoreOp::HoldAcks { hold: true },
        StoreOp::SeedBlock {
            block_idx: processed,
        },
        StoreOp::SeedBlock { block_idx: next },
        StoreOp::ReportFinalization { block_idx: next },
        StoreOp::DeliverBlock {
            block_idx: anchor,
            annotation: DeliverAnnotation::Finalized,
        },
        StoreOp::AckBlocks { count: 2 },
        StoreOp::Prune {
            block_idx: processed,
            clamp: true,
        },
        StoreOp::SetFloor {
            block_idx: anchor,
            late_round: false,
        },
        StoreOp::AckBlocks { count: 1 },
    ];
    if !waiting {
        steps.push(StoreOp::ReportFinalization {
            block_idx: processed,
        });
    }
    steps
}

/// Local annotation of a scripted block delivery, mirroring the block-bearing
/// variants of the resolver's [`Annotation`].
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum DeliverAnnotation {
    Untrusted,
    Certified,
    Finalized,
}

impl DeliverAnnotation {
    /// The annotation the actor itself attaches to a fetch of `height`.
    fn annotation(self, height: Height) -> Annotation {
        match self {
            Self::Untrusted => Annotation::Untrusted {
                height,
                round: None,
            },
            Self::Certified => Annotation::Certified { height },
            Self::Finalized => Annotation::Finalized(Finalized::ByHeight { height }),
        }
    }
}

impl Arbitrary<'_> for StoreOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=255)? {
            0..=24 => Self::SeedBlock {
                block_idx: block_idx(u)?,
            },
            25..=49 => Self::ReportFinalization {
                block_idx: block_idx(u)?,
            },
            50..=61 => Self::GetBlock {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            62..=73 => Self::GetInfo {
                block_idx: block_idx(u)?,
                latest: u.arbitrary()?,
            },
            74..=83 => Self::GetFinalization {
                block_idx: block_idx(u)?,
            },
            84..=91 => Self::Prune {
                block_idx: block_idx(u)?,
                clamp: u.arbitrary()?,
            },
            92..=96 => Self::Restart,
            97..=101 => Self::ObserveApplication,
            102..=109 => Self::DirectPutBlock {
                block_idx: block_idx(u)?,
            },
            110..=115 => Self::DirectSyncBlocks,
            116..=123 => Self::DirectGetBlock {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            124..=129 => Self::DirectPruneBlocks {
                block_idx: block_idx(u)?,
            },
            130..=137 => Self::DirectMissingBlocks {
                block_idx: block_idx(u)?,
                max: u.arbitrary()?,
            },
            138..=141 => Self::DirectLastBlock,
            142..=147 => Self::DirectPutCertificate {
                block_idx: block_idx(u)?,
            },
            148..=151 => Self::DirectSyncCertificates,
            152..=155 => Self::DirectGetCertificate {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
            156 => Self::DirectPruneCertificates {
                block_idx: block_idx(u)?,
            },
            157..=158 => Self::DirectCertificateRanges {
                block_idx: block_idx(u)?,
            },
            159 => Self::DirectLastCertificate,
            160..=167 => Self::SetFloor {
                block_idx: block_idx(u)?,
                late_round: u.arbitrary()?,
            },
            168..=175 => Self::HintFinalized {
                block_idx: block_idx(u)?,
                targets: u.arbitrary()?,
            },
            176..=179 => Self::MessageBurst {
                block_idx: block_idx(u)?,
                count: u.arbitrary()?,
            },
            180..=184 => Self::Forward {
                block_idx: block_idx(u)?,
            },
            190..=199 => Self::DeliverBlock {
                block_idx: block_idx(u)?,
                annotation: u.arbitrary()?,
            },
            200..=229 => Self::Ancestry {
                block_idx: block_idx(u)?,
                bounded: u.arbitrary()?,
                serve: u.arbitrary()?,
            },
            230..=243 => Self::GetVerified {
                block_idx: block_idx(u)?,
            },
            244..=249 => Self::LagFloor {
                waiting: u.arbitrary()?,
            },
            250..=252 => Self::HoldAcks {
                hold: u.arbitrary()?,
            },
            253..=255 => Self::AckBlocks {
                count: u.int_in_range(1..=NUM_BLOCKS as u8)?,
            },
            _ => Self::Subscribe {
                block_idx: block_idx(u)?,
                by_digest: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct MarshalActorStoreInput {
    pub raw_bytes: Vec<u8>,
    pub ops: Vec<StoreOp>,
    /// Start the actor without a broadcast buffer, so blocks come only from
    /// the cache, the archives, and the resolver.
    pub unbuffered: bool,
}

impl Arbitrary<'_> for MarshalActorStoreInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let extra_ops = u.int_in_range(0..=MAX_OPS - FORCED_OPS)?;
        let mut ops = Vec::with_capacity(FORCED_OPS + extra_ops);
        let forced_ops: [StoreOp; FORCED_OPS] = [
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ReportFinalization { block_idx: 0 },
            StoreOp::GetBlock {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::GetInfo {
                block_idx: 0,
                latest: false,
            },
            StoreOp::GetFinalization { block_idx: 0 },
            StoreOp::ObserveApplication,
            StoreOp::Prune {
                block_idx: 0,
                clamp: true,
            },
            StoreOp::DirectPutBlock { block_idx: 0 },
            StoreOp::DirectPutBlock { block_idx: 2 },
            StoreOp::DirectSyncBlocks,
            StoreOp::DirectGetBlock {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::DirectGetBlock {
                block_idx: 2,
                by_digest: true,
            },
            StoreOp::DirectMissingBlocks {
                block_idx: 0,
                max: 4,
            },
            StoreOp::DirectLastBlock,
            StoreOp::DirectPruneBlocks { block_idx: 15 },
            StoreOp::DirectPutBlock { block_idx: 0 },
            StoreOp::DirectPutCertificate { block_idx: 0 },
            StoreOp::DirectPutCertificate { block_idx: 2 },
            StoreOp::DirectSyncCertificates,
            StoreOp::DirectGetCertificate {
                block_idx: 0,
                by_digest: false,
            },
            StoreOp::DirectGetCertificate {
                block_idx: 2,
                by_digest: true,
            },
            StoreOp::DirectCertificateRanges { block_idx: 0 },
            StoreOp::DirectLastCertificate,
            StoreOp::DirectPruneCertificates { block_idx: 15 },
            StoreOp::DirectPutCertificate { block_idx: 0 },
            StoreOp::Restart,
            StoreOp::ObserveApplication,
            StoreOp::GetVerified { block_idx: 0 },
            StoreOp::Ancestry {
                block_idx: 0,
                bounded: false,
                serve: true,
            },
        ];
        ops.extend(forced_ops);
        for _ in 0..extra_ops {
            ops.push(StoreOp::arbitrary(u)?);
        }
        let unbuffered = u.arbitrary()?;

        let remaining = u.len().min(commonware_consensus_fuzz_core::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self {
            raw_bytes,
            ops,
            unbuffered,
        })
    }
}

fn make_chain() -> Vec<Digested<B>> {
    let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
    let mut parent = genesis.digest();
    let mut blocks = Vec::with_capacity(NUM_BLOCKS as usize);
    for h in 1..=NUM_BLOCKS {
        let height = Height::new(h);
        let block =
            StandardHarness::make_test_block(parent, parent, height, h, NUM_VALIDATORS as u16);
        parent = block.digest();
        blocks.push(block);
    }
    blocks
}

fn make_finalization(block: &Digested<B>, schemes: &[CertScheme]) -> Finalization<CertScheme, D> {
    make_finalization_at(block, round_for_height(block.height()), schemes)
}

fn make_finalization_at(
    block: &Digested<B>,
    round: Round,
    schemes: &[CertScheme],
) -> Finalization<CertScheme, D> {
    let proposal = Proposal::new(round, parent_view(block.height()), block.digest());
    let finalizes: Vec<_> = schemes
        .iter()
        .take(QUORUM as usize)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();
    Finalization::from_finalizes(&schemes[0], non_empty![@&finalizes], &Sequential).unwrap()
}

fn assert_returned_block(block: &Digested<B>, returned: &B, label: &str) {
    assert_eq!(
        returned.digest(),
        block.digest(),
        "{label} returned wrong digest for height {}",
        block.height().get(),
    );
}

/// The block of `height` in the model: genesis at 0, else the canonical block.
fn model_block<'a>(
    canonical: &'a [Digested<B>],
    genesis: &'a Digested<B>,
    height: Height,
) -> &'a Digested<B> {
    match height.get() {
        0 => genesis,
        h => &canonical[(h - 1) as usize],
    }
}

/// What the harness has handed the actor, for the verified-block and ancestry
/// checks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StoreModel {
    pub(crate) verified_ever: [bool; NUM_BLOCKS as usize],
    pub(crate) verified_since_restart: [bool; NUM_BLOCKS as usize],
    pub(crate) finalization_given: [bool; NUM_BLOCKS as usize],
    pub(crate) max_final_view: Option<View>,
}

impl StoreModel {
    /// A `SeedBlock` whose persistence returned `persisted`: only a persisted
    /// block counts as verified.
    fn seeded(&mut self, idx: usize, persisted: bool, hooks: &StoreHooks) {
        if !persisted {
            return;
        }
        if hooks.suppress_verified_ever != Some(idx) {
            self.verified_ever[idx] = true;
        }
        self.verified_since_restart[idx] = true;
    }

    fn finalization(&mut self, idx: usize, round: Round) {
        self.finalization_given[idx] = true;
        self.max_final_view = Some(
            self.max_final_view
                .map_or(round.view(), |view| view.max(round.view())),
        );
    }

    /// A block verified since the last restart, at a view no finalization the
    /// actor holds can have pruned yet.
    fn verified_is_retained(&self, idx: usize, round: Round) -> bool {
        self.verified_since_restart[idx]
            && self
                .max_final_view
                .is_none_or(|max| round.view() >= max.saturating_sub(VIEW_RETENTION))
    }
}

/// Test-only changes to the model; the fuzz entry uses the default.
#[derive(Clone, Debug, Default)]
pub(crate) struct StoreHooks {
    /// Leaves `verified_ever` unset for this block index after its seed.
    pub(crate) suppress_verified_ever: Option<usize>,
}

/// How an `Ancestry` walk ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AncestryEnd {
    /// `Mailbox::ancestry` gave no stream within a step.
    NoStream,
    /// The stream yielded genesis and then ended.
    Genesis,
    /// The stream ended before genesis.
    Early,
    /// A step timed out and nothing was served.
    Pending,
    /// The step bound was reached.
    StepCap,
}

/// One event of a store run, recorded for the crate's tests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StoreEvent {
    TimedRegistered {
        label: &'static str,
    },
    /// The clock an ancestry call gets: one id per distinct `Arc`.
    AncestryClock {
        id: usize,
    },
    Model {
        op: usize,
        model: StoreModel,
    },
    AncestryFallback {
        block_idx: usize,
        fallback: DigestFallback,
    },
    AncestryYield {
        height: Height,
    },
    AncestryDone {
        end: AncestryEnd,
        polls: usize,
    },
    Delivery {
        height: Height,
        verdict: Option<Outcome>,
    },
    VerifiedQuery {
        round: Round,
        returned: Option<D>,
    },
}

/// Events of a store run. Only test builds record them. The second field
/// keeps every clock an ancestry call got alive until the run ends, so two
/// clocks never share an address.
#[derive(Debug, Default)]
pub(crate) struct StoreTrace(
    #[cfg(test)] pub(crate) Vec<StoreEvent>,
    #[cfg(test)] Vec<Arc<dyn std::any::Any + Send + Sync>>,
);

impl StoreTrace {
    #[cfg_attr(not(test), allow(unused_variables))]
    fn record(&mut self, event: impl FnOnce() -> StoreEvent) {
        #[cfg(test)]
        self.0.push(event());
    }

    /// Records which clock an ancestry call gets.
    #[cfg_attr(not(test), allow(unused_variables))]
    fn record_clock<C: Send + Sync + 'static>(&mut self, clock: &Arc<C>) {
        #[cfg(test)]
        {
            let clock: Arc<dyn std::any::Any + Send + Sync> = clock.clone();
            let id = self
                .1
                .iter()
                .position(|seen| Arc::ptr_eq(seen, &clock))
                .unwrap_or_else(|| {
                    self.1.push(clock);
                    self.1.len() - 1
                });
            self.0.push(StoreEvent::AncestryClock { id });
        }
    }

    /// Drops the clocks kept for `record_clock` before the trace leaves the
    /// runtime.
    fn release_clocks(&mut self) {
        #[cfg(test)]
        self.1.clear();
    }
}

/// Crypto: `SimplexCertificateMock`. Marshal: standard, store driven directly
/// below the wrapper, buffered or unbuffered from fuzz input. Cluster: single
/// validator, prunable archives. Liveness: only SF-1, checked in
/// `ReportFinalization`: when every floor set since the last restart is at or
/// below the reported round, the application holds no block, the reported block
/// is local at or below the processed height and the next block is stored, a
/// block must reach the application, or the processed height must rise, within
/// `DISPATCH_STEPS` settle periods; otherwise it panics with `SF-1 violated:`.
/// App: the marshal mock, acknowledging each block on delivery unless the input
/// holds acknowledgements (`HoldAcks`, `AckBlocks`).
pub fn fuzz_marshal_actor_store(input: MarshalActorStoreInput) {
    let _ = run_store(input, &StoreHooks::default());
}

/// Runs one store input and returns its trace (empty outside tests).
pub(crate) fn run_store(input: MarshalActorStoreInput, hooks: &StoreHooks) -> StoreTrace {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let unbuffered = input.unbuffered;
    let cfg = deterministic::Config::new().with_rng(rng);
    let executor = deterministic::Runner::new(cfg);
    let hooks = hooks.clone();

    executor.start(|mut context| async move {
        let mut trace = StoreTrace::default();
        let mut model = StoreModel::default();
        let mut newest_floor: Option<View> = None;
        let (participants, schemes) =
            SimplexCertificateMock::setup(&mut context, NAMESPACE, NUM_VALIDATORS);
        let oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
            1024 * 1024,
        )
        .await;
        let validator = participants[0].clone();
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        let partition_prefix = format!("store-fuzz-{validator}");
        let canonical = make_chain();
        let finalizations = canonical
            .iter()
            .map(|block| make_finalization(block, &schemes))
            .collect::<Vec<_>>();

        let mut direct_finalizations = prunable::Archive::init(
            context.child("direct_finalizations"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-direct-finalizations-metadata"),
                key_partition: format!("{partition_prefix}-direct-finalizations-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-direct-finalizations-value"),
                compression: None,
                codec_config: CertScheme::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize direct finalizations archive");
        let mut direct_blocks = prunable::Archive::init(
            context.child("direct_blocks"),
            prunable::Config {
                translator: EightCap,
                metadata_partition: format!("{partition_prefix}-direct-blocks-metadata"),
                key_partition: format!("{partition_prefix}-direct-blocks-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-direct-blocks-value"),
                compression: None,
                codec_config: (),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize direct blocks archive");

        let setup = setup_prunable_validator_cert_mock(
            context.child("validator"),
            &oracle,
            validator.clone(),
            &schemes,
            &partition_prefix,
            page_cache.clone(),
            unbuffered,
        )
        .await;
        let mut application = setup.2;
        let mut mailbox = setup.0;
        let mut actor_handle = setup.3;
        let mut resolver = setup.4;

        let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
        let ancestry_context = context.child("ancestry");
        let timed = Timed::register(
            &ancestry_context,
            "ancestor_fetch_duration",
            "Time to fetch a parent through the ancestry stream",
        );
        trace.record(|| StoreEvent::TimedRegistered { label: "ancestry" });
        let clock = Arc::new(ancestry_context);

        let steps = input.ops.into_iter().flat_map(|op| match op {
            StoreOp::LagFloor { waiting } => lag_floor_steps(waiting),
            op => vec![op],
        });
        for (op_index, op) in steps.enumerate() {
            match op {
                StoreOp::LagFloor { .. } => unreachable!("expanded into its steps"),
                StoreOp::SeedBlock { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let persisted = mailbox
                        .verified(block.inner().context.round, block.clone())
                        .await;
                    model.seeded(block_index(block_idx), persisted, &hooks);
                    assert!(persisted);
                }
                StoreOp::ReportFinalization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let finalization = finalizations[block_index(block_idx)].clone();
                    let view = finalization.round().view();
                    // The actor owes the application the next block when every floor
                    // set since the last restart is at or below this round, the
                    // application holds no block, the reported block is local at or
                    // below the processed height, and the next block is stored.
                    let mut owed = None;
                    if newest_floor.is_some_and(|floor| floor <= view)
                        && application.inner.pending_ack_heights().is_empty()
                    {
                        let processed = mailbox
                            .get_processed()
                            .await
                            .map_or(Height::zero(), |processed| processed.height());
                        if block.height() <= processed
                            && mailbox.get_block(&block.digest()).await.is_some()
                            && mailbox.get_block(processed.next()).await.is_some()
                        {
                            owed = Some((processed, application.inner.delivered().len()));
                        }
                    }
                    model.finalization(block_index(block_idx), finalization.round());
                    let feedback = mailbox.report(Activity::Finalization(finalization));
                    if let Some((processed, delivered)) = owed.filter(|_| feedback == Feedback::Ok)
                    {
                        let mut resumed = false;
                        for _ in 0..DISPATCH_STEPS {
                            context.sleep(EVENT_SETTLE).await;
                            let now = mailbox
                                .get_processed()
                                .await
                                .map_or(Height::zero(), |processed| processed.height());
                            if now > processed || application.inner.delivered().len() > delivered {
                                resumed = true;
                                break;
                            }
                        }
                        assert!(
                            resumed,
                            "SF-1 violated: no block reached the application after the round \
                             floor passed every floor set, with height {} stored above the \
                             processed height {}",
                            processed.next().get(),
                            processed.get(),
                        );
                    }
                }
                StoreOp::GetBlock {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        mailbox.get_block(&block.digest()).await
                    } else {
                        mailbox.get_block(block.height()).await
                    };
                    if let Some(returned) = returned {
                        assert_returned_block(block, returned.inner(), "GetBlock");
                    }
                }
                StoreOp::GetInfo { block_idx, latest } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if latest {
                        mailbox.get_info(Identifier::Latest).await
                    } else {
                        mailbox.get_info(block.height()).await
                    };
                    if let Some((height, digest)) = returned
                        && height.get() != 0
                    {
                        let Some(expected) = canonical.get((height.get() - 1) as usize) else {
                            panic!("GetInfo returned unexpected height {}", height.get());
                        };
                        assert_eq!(
                            digest,
                            expected.digest(),
                            "GetInfo returned wrong digest for height {}",
                            height.get(),
                        );
                    }
                }
                StoreOp::GetFinalization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    if let Some(finalization) = mailbox.get_finalization(block.height()).await {
                        assert_eq!(
                            finalization.proposal.payload,
                            block.digest(),
                            "GetFinalization returned wrong payload for height {}",
                            block.height().get(),
                        );
                    }
                }
                StoreOp::Prune { block_idx, clamp } => {
                    let mut height = Height::new(block_index(block_idx) as u64 + 1);
                    if clamp {
                        let processed = mailbox
                            .get_processed()
                            .await
                            .map_or(Height::zero(), |processed| processed.height());
                        height = height.min(processed);
                    }
                    mailbox.prune(height);
                }
                StoreOp::SetFloor {
                    block_idx,
                    late_round,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let finalization = if late_round {
                        make_finalization_at(block, late_round_for_height(block.height()), &schemes)
                    } else {
                        finalizations[block_index(block_idx)].clone()
                    };
                    model.finalization(block_index(block_idx), finalization.round());
                    newest_floor = newest_floor.max(Some(finalization.round().view()));
                    mailbox.set_floor(finalization);
                }
                StoreOp::HintFinalized { block_idx, targets } => {
                    let height = canonical[block_index(block_idx)].height();
                    mailbox.hint_finalized(height, hint_targets(&participants, targets));
                }
                StoreOp::MessageBurst { block_idx, count } => {
                    let start = block_index(block_idx);
                    for i in 0..MAILBOX_SIZE.get() + 1 + usize::from(count) {
                        let idx = (start + i) % NUM_BLOCKS as usize;
                        let height = canonical[idx].height();
                        match i % 8 {
                            5 => mailbox.prune(height),
                            6 => {
                                model.finalization(idx, finalizations[idx].round());
                                newest_floor =
                                    newest_floor.max(Some(finalizations[idx].round().view()));
                                mailbox.set_floor(finalizations[idx].clone());
                            }
                            7 => {
                                model.finalization(idx, finalizations[idx].round());
                                let _ = mailbox
                                    .report(Activity::Finalization(finalizations[idx].clone()));
                            }
                            _ => {
                                mailbox.hint_finalized(height, hint_targets(&participants, i as u8))
                            }
                        }
                    }
                }
                StoreOp::Forward { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let _ = mailbox.forward(
                        block.inner().context.round,
                        block.digest(),
                        Recipients::All,
                    );
                }
                StoreOp::Subscribe {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let receiver = if by_digest {
                        mailbox.subscribe_by_digest(block.digest(), DigestFallback::Wait)
                    } else {
                        mailbox.subscribe_by_commitment(
                            block.digest(),
                            CommitmentFallback::FetchByCommitment {
                                height: block.height(),
                                round: None,
                            },
                        )
                    };
                    select! {
                        returned = receiver => {
                            if let Ok(returned) = returned {
                                assert_returned_block(block, returned.inner(), "Subscribe");
                            }
                        },
                        _ = context.sleep(EVENT_SETTLE) => {},
                    }
                }
                StoreOp::DeliverBlock {
                    block_idx,
                    annotation,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let key = Key::Block(block.digest());
                    let requested = resolver
                        .fetches()
                        .iter()
                        .any(|(fetched, _)| *fetched == key);
                    let processed_before = mailbox
                        .get_processed()
                        .await
                        .map_or(Height::zero(), |processed| processed.height());
                    let held_before = mailbox.get_block(&block.digest()).await.is_some();
                    let verdict = if requested {
                        let verdict = resolver.deliver(
                            key,
                            annotation.annotation(block.height()),
                            block.encode(),
                        );
                        select! {
                            verdict = verdict => verdict.ok(),
                            _ = context.sleep(EVENT_SETTLE) => None,
                        }
                    } else {
                        None
                    };
                    if let Some(verdict) = verdict {
                        // A delivery below the floor is ignored rather than admitted; only a
                        // rejection blames the canonical block.
                        assert_ne!(
                            verdict,
                            Outcome::Invalid,
                            "canonical block delivery rejected at height {}",
                            block.height().get(),
                        );
                        // An admitted block above the processed height is
                        // served by digest; one at or below the floor is not
                        // admitted.
                        let returned = mailbox.get_block(&block.digest()).await;
                        let processed = mailbox
                            .get_processed()
                            .await
                            .map_or(Height::zero(), |processed| processed.height());
                        if block.height() > processed {
                            let returned =
                                returned.expect("delivered block above the floor is held");
                            assert_returned_block(block, returned.inner(), "DeliverBlock");
                        } else if !held_before && block.height() <= processed_before {
                            assert!(
                                returned.is_none(),
                                "block at or below the processed floor admitted at height {}",
                                block.height().get(),
                            );
                        }
                    }
                }
                StoreOp::Restart => {
                    drop(mailbox);
                    drop(application);
                    // Let the actor exit on its closed mailbox, then abort it if it is
                    // still busy so its archives are released before the same
                    // partitions reopen.
                    context.sleep(EVENT_SETTLE).await;
                    actor_handle.abort();
                    let _ = actor_handle.await;
                    let setup = setup_prunable_validator_cert_mock(
                        context.child("validator_restart"),
                        &oracle,
                        validator.clone(),
                        &schemes,
                        &partition_prefix,
                        page_cache.clone(),
                        unbuffered,
                    )
                    .await;
                    application = setup.2;
                    mailbox = setup.0;
                    actor_handle = setup.3;
                    resolver = setup.4;
                    model.verified_since_restart = [false; NUM_BLOCKS as usize];
                    newest_floor = None;
                }
                StoreOp::ObserveApplication => {
                    let _ = application.inner.tip();
                    let _ = application.inner.blocks();
                    let _ = mailbox.get_processed().await;
                }
                StoreOp::DirectPutBlock { block_idx } => {
                    let block = canonical[block_index(block_idx)].clone();
                    direct_blocks = StoreBlocks::put(direct_blocks, block.digest(), block.inner())
                        .await
                        .expect("direct block put failed");
                }
                StoreOp::DirectSyncBlocks => {
                    direct_blocks = StoreBlocks::sync(direct_blocks)
                        .await
                        .expect("direct block sync failed");
                }
                StoreOp::DirectGetBlock {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        let digest = block.digest();
                        StoreBlocks::get(&direct_blocks, ArchiveIdentifier::Key(&digest)).await
                    } else {
                        StoreBlocks::get(
                            &direct_blocks,
                            ArchiveIdentifier::Index(block.height().get()),
                        )
                        .await
                    }
                    .expect("direct block get failed");
                    if let Some(returned) = returned {
                        assert_returned_block(block, &returned, "DirectGetBlock");
                    }
                }
                StoreOp::DirectPruneBlocks { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    direct_blocks = StoreBlocks::prune(direct_blocks, height)
                        .await
                        .expect("direct block prune failed");
                }
                StoreOp::DirectMissingBlocks { block_idx, max } => {
                    let start = Height::new(block_index(block_idx) as u64 + 1);
                    let max = usize::from(max % 8) + 1;
                    let missing = StoreBlocks::missing_items(&direct_blocks, start, max);
                    assert!(missing.len() <= max, "too many missing direct blocks");
                }
                StoreOp::DirectLastBlock => {
                    let _ = StoreBlocks::last_index(&direct_blocks);
                }
                StoreOp::DirectPutCertificate { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    direct_finalizations = StoreCertificates::put(
                        direct_finalizations,
                        block.height(),
                        block.digest(),
                        &finalizations[block_index(block_idx)],
                    )
                    .await
                    .expect("direct finalization put failed");
                }
                StoreOp::DirectSyncCertificates => {
                    direct_finalizations = StoreCertificates::sync(direct_finalizations)
                        .await
                        .expect("direct finalization sync failed");
                }
                StoreOp::DirectGetCertificate {
                    block_idx,
                    by_digest,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let returned = if by_digest {
                        let digest = block.digest();
                        StoreCertificates::get(
                            &direct_finalizations,
                            ArchiveIdentifier::Key(&digest),
                        )
                        .await
                    } else {
                        StoreCertificates::get(
                            &direct_finalizations,
                            ArchiveIdentifier::Index(block.height().get()),
                        )
                        .await
                    }
                    .expect("direct finalization get failed");
                    if let Some(finalization) = returned {
                        assert_eq!(
                            finalization.proposal.payload,
                            block.digest(),
                            "DirectGetCertificate returned wrong payload for height {}",
                            block.height().get(),
                        );
                    }
                }
                StoreOp::DirectPruneCertificates { block_idx } => {
                    let height = Height::new(block_index(block_idx) as u64 + 1);
                    direct_finalizations = StoreCertificates::prune(direct_finalizations, height)
                        .await
                        .expect("direct finalization prune failed");
                }
                StoreOp::DirectCertificateRanges { block_idx } => {
                    let from = Height::new(block_index(block_idx) as u64);
                    let ranges = StoreCertificates::ranges_from(&direct_finalizations, from)
                        .collect::<Vec<_>>();
                    for (start, end) in ranges {
                        assert!(start <= end, "invalid direct finalization range");
                    }
                }
                StoreOp::DirectLastCertificate => {
                    let _ = StoreCertificates::last_index(&direct_finalizations);
                }
                StoreOp::Ancestry {
                    block_idx,
                    bounded,
                    serve,
                } => {
                    let idx = block_index(block_idx);
                    let start = &canonical[idx];
                    let round = start.inner().context.round;
                    // `Wait` passes no bound, so it starts only from a block
                    // whose finalization the actor was given.
                    let fallback = if bounded || !model.finalization_given[idx] {
                        DigestFallback::FetchByRound { round }
                    } else {
                        DigestFallback::Wait
                    };
                    trace.record(|| StoreEvent::AncestryFallback {
                        block_idx: idx,
                        fallback,
                    });
                    let call_clock = clock.clone();
                    trace.record_clock(&call_clock);
                    let stream = select! {
                        stream = mailbox.ancestry(
                            call_clock,
                            (fallback, start.digest()),
                            timed.clone(),
                        ) => stream,
                        _ = context.sleep(ANCESTRY_STEP) => None,
                    };
                    let Some(mut stream) = stream else {
                        trace.record(|| StoreEvent::AncestryDone {
                            end: AncestryEnd::NoStream,
                            polls: 0,
                        });
                        trace.record(|| StoreEvent::Model {
                            op: op_index,
                            model: model.clone(),
                        });
                        context.sleep(EVENT_SETTLE).await;
                        continue;
                    };
                    assert_eq!(
                        stream.peek().map(|peeked| peeked.digest()),
                        Some(start.digest()),
                        "RA-10 violated: peek before the first yield is not the start at height {}",
                        start.height().get(),
                    );

                    // `None` once genesis was yielded: the next step must end the stream.
                    let mut expected = Some(start.height());
                    let mut resolved = false;
                    let mut polls = 0;
                    let mut end = AncestryEnd::StepCap;
                    while polls < MAX_ANCESTRY_STEPS {
                        polls += 1;
                        let step = select! {
                            next = stream.next() => Some(next),
                            _ = context.sleep(ANCESTRY_STEP) => None,
                        };
                        let Some(height) = expected else {
                            assert!(
                                matches!(step, Some(None)),
                                "RA-14 violated: the stream did not end at once after genesis",
                            );
                            end = AncestryEnd::Genesis;
                            break;
                        };
                        match step {
                            Some(Some(block)) => {
                                let want = model_block(&canonical, &genesis, height);
                                assert_eq!(
                                    block.digest(),
                                    want.digest(),
                                    "RA-11 violated: ancestry yielded a block other than the \
                                     canonical one at height {}",
                                    height.get(),
                                );
                                resolved = false;
                                trace.record(|| StoreEvent::AncestryYield { height });
                                expected = height.previous();
                            }
                            Some(None) => {
                                assert!(
                                    !resolved,
                                    "RA-12 violated: the stream ended after its parent at height \
                                     {} was delivered",
                                    height.get(),
                                );
                                end = AncestryEnd::Early;
                                break;
                            }
                            None => {
                                assert!(
                                    !resolved,
                                    "RA-12 violated: the parent at height {} was delivered but \
                                     not yielded",
                                    height.get(),
                                );
                                end = AncestryEnd::Pending;
                                // A delivery needs one more step to check its parent.
                                if !serve || polls == MAX_ANCESTRY_STEPS {
                                    break;
                                }
                                let parent = model_block(&canonical, &genesis, height);
                                let key = Key::Block(parent.digest());
                                let Some((_, annotation)) = resolver
                                    .active_fetches()
                                    .into_iter()
                                    .find(|(fetched, _)| *fetched == key)
                                else {
                                    break;
                                };
                                let verdict = resolver.deliver(key, annotation, parent.encode());
                                let verdict = select! {
                                    verdict = verdict => verdict.ok(),
                                    _ = context.sleep(EVENT_SETTLE) => None,
                                };
                                trace.record(|| StoreEvent::Delivery { height, verdict });
                                assert_ne!(
                                    verdict,
                                    Some(Outcome::Invalid),
                                    "RA-13 violated: canonical parent rejected at height {}",
                                    height.get(),
                                );
                                if !matches!(verdict, Some(Outcome::Resolved(_))) {
                                    break;
                                }
                                resolved = true;
                                end = AncestryEnd::StepCap;
                            }
                        }
                    }
                    drop(stream);
                    trace.record(|| StoreEvent::AncestryDone { end, polls });
                }
                StoreOp::HoldAcks { hold } => {
                    application.hold.store(hold, Ordering::Relaxed);
                    if !hold {
                        application.acknowledge_all();
                    }
                }
                StoreOp::AckBlocks { count } => {
                    for _ in 0..count {
                        if application.inner.acknowledge_next().is_none() {
                            break;
                        }
                        context.sleep(EVENT_SETTLE).await;
                    }
                }
                StoreOp::GetVerified { block_idx } => {
                    let idx = block_index(block_idx);
                    let block = &canonical[idx];
                    let round = block.inner().context.round;
                    let returned = mailbox.get_verified(round).await;
                    trace.record(|| StoreEvent::VerifiedQuery {
                        round,
                        returned: returned.as_ref().map(|returned| returned.digest()),
                    });
                    if let Some(returned) = &returned {
                        assert_eq!(
                            returned.digest(),
                            block.digest(),
                            "RA-15 violated: verified block of round {round} is not the one \
                             verified there",
                        );
                    }
                    if !model.verified_ever[idx] {
                        assert!(
                            returned.is_none(),
                            "RA-16 violated: a block is verified at round {round}, where none \
                             was verified",
                        );
                    }
                    if model.verified_is_retained(idx, round) {
                        assert!(
                            returned.is_some(),
                            "RA-17 violated: the block verified at round {round} is missing \
                             within retention",
                        );
                    }
                }
            }
            trace.record(|| StoreEvent::Model {
                op: op_index,
                model: model.clone(),
            });
            context.sleep(EVENT_SETTLE).await;
        }
        trace.release_clocks();
        trace
    })
}

#[cfg(test)]
#[path = "../../tests/ancestry_acceptance/store.rs"]
mod ancestry_acceptance;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_floor_steps_are_the_recipe() {
        let recipe = vec![
            StoreOp::SeedBlock { block_idx: 7 },
            StoreOp::SetFloor {
                block_idx: 7,
                late_round: false,
            },
            StoreOp::HoldAcks { hold: true },
            StoreOp::SeedBlock { block_idx: 9 },
            StoreOp::SeedBlock { block_idx: 10 },
            StoreOp::ReportFinalization { block_idx: 10 },
            StoreOp::DeliverBlock {
                block_idx: 8,
                annotation: DeliverAnnotation::Finalized,
            },
            StoreOp::AckBlocks { count: 2 },
            StoreOp::Prune {
                block_idx: 9,
                clamp: true,
            },
            StoreOp::SetFloor {
                block_idx: 8,
                late_round: false,
            },
            StoreOp::AckBlocks { count: 1 },
            StoreOp::ReportFinalization { block_idx: 9 },
        ];
        assert_eq!(
            format!("{:?}", lag_floor_steps(false)),
            format!("{recipe:?}")
        );
        assert_eq!(
            format!("{:?}", lag_floor_steps(true)),
            format!("{:?}", &recipe[..11])
        );
    }

    #[test]
    fn lag_floor_selector_band() {
        for selector in 0..=255u8 {
            for waiting in [0u8, 1] {
                let bytes = [selector, waiting];
                let op = StoreOp::arbitrary(&mut arbitrary::Unstructured::new(&bytes)).unwrap();
                let lag = matches!(op, StoreOp::LagFloor { waiting: w } if w == (waiting == 1));
                assert_eq!(
                    lag,
                    (244..=249).contains(&selector),
                    "selector {selector}, byte {waiting}: {op:?}"
                );
            }
        }
    }

    /// Runs `ops` in one actor mode and returns the recorded events.
    fn run_ops(ops: Vec<StoreOp>, unbuffered: bool) -> Vec<StoreEvent> {
        run_store(
            MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops,
                unbuffered,
            },
            &StoreHooks::default(),
        )
        .0
    }

    fn seeds(indices: impl IntoIterator<Item = u8>) -> Vec<StoreOp> {
        indices
            .into_iter()
            .map(|block_idx| StoreOp::SeedBlock { block_idx })
            .collect()
    }

    fn finalizations(indices: impl IntoIterator<Item = u8>) -> Vec<StoreOp> {
        indices
            .into_iter()
            .map(|block_idx| StoreOp::ReportFinalization { block_idx })
            .collect()
    }

    fn yields(events: &[StoreEvent]) -> Vec<u64> {
        events
            .iter()
            .filter_map(|event| match event {
                StoreEvent::AncestryYield { height } => Some(height.get()),
                _ => None,
            })
            .collect()
    }

    fn deliveries(events: &[StoreEvent]) -> Vec<(u64, Option<Outcome>)> {
        events
            .iter()
            .filter_map(|event| match event {
                StoreEvent::Delivery { height, verdict } => Some((height.get(), *verdict)),
                _ => None,
            })
            .collect()
    }

    fn ancestry_ends(events: &[StoreEvent]) -> Vec<AncestryEnd> {
        events
            .iter()
            .filter_map(|event| match event {
                StoreEvent::AncestryDone { end, .. } => Some(*end),
                _ => None,
            })
            .collect()
    }

    /// A seeded block is returned for its round; a block never verified is not.
    #[test]
    fn get_verified_returns_seeded_blocks() {
        let canonical = make_chain();
        let mut ops = seeds(0..=5);
        ops.push(StoreOp::GetVerified { block_idx: 4 });
        ops.push(StoreOp::GetVerified { block_idx: 10 });
        for unbuffered in [false, true] {
            let queries: Vec<_> = run_ops(ops.clone(), unbuffered)
                .into_iter()
                .filter_map(|event| match event {
                    StoreEvent::VerifiedQuery { round, returned } => Some((round, returned)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                queries,
                vec![
                    (
                        canonical[4].inner().context.round,
                        Some(canonical[4].digest())
                    ),
                    (canonical[10].inner().context.round, None),
                ],
            );
        }
    }

    /// A bounded walk over local blocks yields every height down to genesis
    /// and then ends.
    #[test]
    fn ancestry_walks_local_blocks_to_genesis() {
        let mut ops = seeds(0..=5);
        ops.extend(finalizations(0..=2));
        ops.push(StoreOp::Ancestry {
            block_idx: 5,
            bounded: true,
            serve: true,
        });
        for unbuffered in [false, true] {
            let events = run_ops(ops.clone(), unbuffered);
            assert_eq!(yields(&events), vec![6, 5, 4, 3, 2, 1, 0]);
            assert!(deliveries(&events).is_empty());
            assert_eq!(ancestry_ends(&events), vec![AncestryEnd::Genesis]);
        }
    }

    /// The parent at height 5 is never given to the actor, so the walk from
    /// the finalized height 6 fetches it; the delivered parent is yielded
    /// and the walk reaches genesis.
    #[test]
    fn ancestry_yields_a_delivered_parent() {
        let mut ops = seeds([0, 1, 2, 3, 5]);
        ops.extend(finalizations([0, 1, 2, 3, 5]));
        ops.push(StoreOp::Ancestry {
            block_idx: 5,
            bounded: false,
            serve: true,
        });
        for unbuffered in [false, true] {
            let events = run_ops(ops.clone(), unbuffered);
            assert!(events.contains(&StoreEvent::AncestryFallback {
                block_idx: 5,
                fallback: DigestFallback::Wait,
            }));
            let delivered = deliveries(&events);
            assert_eq!(delivered.len(), 1, "one delivery expected: {delivered:?}");
            assert_eq!(delivered[0].0, 5);
            assert!(matches!(delivered[0].1, Some(Outcome::Resolved(_))));
            assert_eq!(yields(&events), vec![6, 5, 4, 3, 2, 1, 0]);
            assert_eq!(ancestry_ends(&events), vec![AncestryEnd::Genesis]);
        }
    }

    /// The same walk without serving stops at the missing parent.
    #[test]
    fn ancestry_waits_on_an_unserved_parent() {
        let mut ops = seeds([0, 1, 2, 3, 5]);
        ops.extend(finalizations([0, 1, 2, 3, 5]));
        ops.push(StoreOp::Ancestry {
            block_idx: 5,
            bounded: false,
            serve: false,
        });
        for unbuffered in [false, true] {
            let events = run_ops(ops.clone(), unbuffered);
            assert!(events.contains(&StoreEvent::AncestryFallback {
                block_idx: 5,
                fallback: DigestFallback::Wait,
            }));
            assert_eq!(yields(&events), vec![6]);
            assert!(deliveries(&events).is_empty());
            assert_eq!(ancestry_ends(&events), vec![AncestryEnd::Pending]);
        }
    }

    #[test]
    fn forced_script_allows_zero_extra_operations() {
        let bytes = [0u8; 64];
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let input = MarshalActorStoreInput::arbitrary(&mut unstructured).unwrap();
        assert_eq!(input.ops.len(), FORCED_OPS);
        assert!(!input.unbuffered);
    }

    /// Floors, hints, bursts, and effective prunes on both actor start modes.
    #[test]
    fn scripted_floor_hint_and_prune_ops_run() {
        let ops = vec![
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ReportFinalization { block_idx: 0 },
            StoreOp::SeedBlock { block_idx: 1 },
            StoreOp::ReportFinalization { block_idx: 1 },
            StoreOp::SeedBlock { block_idx: 2 },
            StoreOp::ReportFinalization { block_idx: 2 },
            StoreOp::ObserveApplication,
            StoreOp::Prune {
                block_idx: 1,
                clamp: true,
            },
            StoreOp::Prune {
                block_idx: 10,
                clamp: false,
            },
            StoreOp::HintFinalized {
                block_idx: 0,
                targets: 0,
            },
            StoreOp::HintFinalized {
                block_idx: 9,
                targets: 2,
            },
            // Floor at height 6 waits for its anchor, which a later seed supplies.
            StoreOp::SetFloor {
                block_idx: 5,
                late_round: false,
            },
            StoreOp::SeedBlock { block_idx: 5 },
            StoreOp::GetInfo {
                block_idx: 0,
                latest: true,
            },
            StoreOp::GetBlock {
                block_idx: 5,
                by_digest: false,
            },
            StoreOp::GetFinalization { block_idx: 5 },
            // The floor block finalized again at its spare view: a floor whose
            // anchor is already at the processed height.
            StoreOp::SetFloor {
                block_idx: 5,
                late_round: true,
            },
            StoreOp::SeedBlock { block_idx: 5 },
            StoreOp::MessageBurst {
                block_idx: 3,
                count: 40,
            },
            StoreOp::Forward { block_idx: 5 },
            StoreOp::Subscribe {
                block_idx: 5,
                by_digest: true,
            },
            StoreOp::Subscribe {
                block_idx: 9,
                by_digest: false,
            },
            StoreOp::Subscribe {
                block_idx: 12,
                by_digest: true,
            },
            StoreOp::GetBlock {
                block_idx: 5,
                by_digest: true,
            },
            StoreOp::Restart,
            StoreOp::ObserveApplication,
            StoreOp::GetInfo {
                block_idx: 0,
                latest: true,
            },
            StoreOp::SeedBlock { block_idx: 6 },
            StoreOp::ReportFinalization { block_idx: 6 },
            StoreOp::ObserveApplication,
        ];
        for unbuffered in [false, true] {
            fuzz_marshal_actor_store(MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops: ops.clone(),
                unbuffered,
            });
        }
    }

    /// Scripted backfill answers: untrusted and certified deliveries above the
    /// processed height land in the certified cache, finalized ones in the
    /// archive, and a repeated delivery is a no-op.
    #[test]
    fn scripted_block_deliveries_are_admitted() {
        let ops = vec![
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ReportFinalization { block_idx: 0 },
            StoreOp::Subscribe {
                block_idx: 2,
                by_digest: false,
            },
            StoreOp::DeliverBlock {
                block_idx: 2,
                annotation: DeliverAnnotation::Untrusted,
            },
            StoreOp::GetBlock {
                block_idx: 2,
                by_digest: true,
            },
            StoreOp::Subscribe {
                block_idx: 3,
                by_digest: false,
            },
            StoreOp::DeliverBlock {
                block_idx: 3,
                annotation: DeliverAnnotation::Certified,
            },
            StoreOp::DeliverBlock {
                block_idx: 2,
                annotation: DeliverAnnotation::Certified,
            },
            StoreOp::Subscribe {
                block_idx: 5,
                by_digest: false,
            },
            StoreOp::DeliverBlock {
                block_idx: 5,
                annotation: DeliverAnnotation::Finalized,
            },
            // A finalization for a block the actor never saw fetches it by
            // commitment; the delivery completes the finalized chain.
            StoreOp::ReportFinalization { block_idx: 1 },
            StoreOp::DeliverBlock {
                block_idx: 1,
                annotation: DeliverAnnotation::Finalized,
            },
            StoreOp::ObserveApplication,
            StoreOp::GetInfo {
                block_idx: 0,
                latest: true,
            },
        ];
        for unbuffered in [false, true] {
            fuzz_marshal_actor_store(MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops: ops.clone(),
                unbuffered,
            });
        }
    }

    /// Bursts keep the actor busy past the settle period, so `Restart` has to
    /// stop it before reopening its archives. The burst sizes are the ones from
    /// the campaign input that reopened them while the actor was still alive.
    #[test]
    fn restart_stops_a_busy_actor() {
        let bytes = [0u8; 64];
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let mut ops = MarshalActorStoreInput::arbitrary(&mut unstructured)
            .unwrap()
            .ops;
        ops.extend([
            StoreOp::MessageBurst {
                block_idx: 2,
                count: 13,
            },
            StoreOp::MessageBurst {
                block_idx: 2,
                count: 179,
            },
            StoreOp::Restart,
            StoreOp::SeedBlock { block_idx: 0 },
            StoreOp::ObserveApplication,
        ]);
        for unbuffered in [false, true] {
            fuzz_marshal_actor_store(MarshalActorStoreInput {
                raw_bytes: vec![0],
                ops: ops.clone(),
                unbuffered,
            });
        }
    }
}
