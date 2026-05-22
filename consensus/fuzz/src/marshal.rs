//! Fuzz driver for the marshal actor.
//!
//! Drives a single marshal actor under test by synthesizing every input
//! marshal would normally receive from the consensus engine and from peers
//! (blocks, notarizations, finalizations) and feeding them through the
//! mailbox directly. Generic over `H: TestHarness` so the standard and
//! coding variants share the same driver and corpora-per-binary discipline.
//!
//! # Invariants checked
//!
//! - **In-order delivery, no gaps within a marshal instance.** Within each
//!   actor lifetime (segment between restarts), the first delivery is
//!   `setup.height + 1` and subsequent deliveries advance strictly by one.
//!   Marshal documents this guarantee on `Update::Block`.
//! - **Ready-prefix delivery (anchor-based, chain-aware repair).**
//!   When a `ReportFinalization` at height `h` arrives while block
//!   `h` is locally available (durable or variant), marshal stores a
//!   finalized anchor at `h` in its finalized archive. The driver
//!   mirrors this with a persistent `finalized_anchors` set.
//!
//!   A `ReportFinalization` only triggers a repair wake when its
//!   height is strictly above marshal's `processed_height` AND the
//!   block is locally available. At-or-below-floor finalizations
//!   are dropped by marshal's `store_finalization` (see
//!   actor.rs:1732) and `try_repair_gaps` is gated on store success
//!   (actor.rs:648). The driver mirrors this with a shadow
//!   `processed_height`: initialized to `setup.height.get()`,
//!   advanced on non-stale `AckNext`, and reset to
//!   `setup.height.get()` after `Restart`.
//!
//!   On each repair wake (every above-floor `ReportFinalization`
//!   that found its block, and every `Restart` after the variant
//!   cache is cleared, since marshal's startup path runs
//!   `try_repair_gaps` unconditionally) the driver finds the largest
//!   anchor `a` for
//!   which every height `1..=a` is currently available in
//!   (`durable_available` union `variant_available`). If `a >
//!   ready_prefix`, the gap is repairable: marshal can walk the
//!   chain from `a` back to 1 and deliver. The driver bumps
//!   `ready_prefix = a` and promotes heights `prev_ready+1..=a` into
//!   `durable_available` (marshal moves them to the finalized
//!   archive, so they survive future restarts even if originally
//!   sourced from the variant cache).
//!
//!   Availability state:
//!     - `durable_available`: heights set by Propose / Verify /
//!       Certify (marshal persists them), anchor blocks persisted by
//!       `ReportFinalization` when the block was locally available
//!       at that moment (marshal writes the block to
//!       `finalized_blocks` alongside the finalization), plus
//!       heights promoted by `ready_prefix` advances. Survives
//!       restart.
//!     - `variant_available`: heights set by `PublishViaVariant`
//!       after confirmed local availability. Lives only in the
//!       in-memory buffered / shards cache; cleared on `Restart`.
//!     - `finalized_anchors`: heights at which a usable finalization
//!       is stored. Survives restart.
//! - **At-least-once across restart.** Heights pending ack at the moment
//!   of restart are tracked. The new actor instance must redeliver each
//!   of them at least once before the run ends.
//! - **Digest fidelity.** Every block surfaced in `application.blocks()`
//!   must match the canonical chain digest at its height.
//! - **Durability acks.** `H::propose`/`H::verify`/`H::certify` return
//!   `true` on durable persist; `false` surfaces an actor-died panic.
//!
//! # Variant buffer coverage
//!
//! `PublishViaVariant` exercises marshal's interaction with the local
//! variant cache (buffered broadcast engine for Standard, shards engine
//! for Coding). After publishing, the driver verifies the block actually
//! landed in the local cache before counting it as `provided`; a publish
//! that silently drops does not register.
//!
//! The marshal-mailbox path (`H::propose`/`H::verify`/`H::certify`) does
//! NOT route through the shards mailbox for the coding harness: those
//! wrappers call `handle.mailbox.proposed/verified/certified` directly.
//! Shards-mailbox coverage is therefore exclusively via
//! `PublishViaVariant`.
//!
//! # Known scope limitations
//!
//! - Single-validator only: peer-to-peer shard *dissemination* and
//!   *reconstruction-from-peer-shards* are not exercised. Multi-validator
//!   coding fuzz is a follow-up.

use arbitrary::Arbitrary;
use commonware_broadcast::{buffered, Broadcaster as _};
use commonware_codec::Codec;
use commonware_coding::Scheme as CodingScheme;
use commonware_consensus::{
    marshal::{
        coding::{shards, types::CodedBlock},
        mocks::{
            application::Application,
            harness::{
                setup_network_with_participants, TestHarness, ValidatorHandle, NAMESPACE,
                NUM_VALIDATORS, QUORUM,
            },
        },
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Proposal},
    },
    types::{Epoch, Height, Round, View},
    CertifiableBlock, Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk,
    certificate::{mocks::Fixture, ConstantProvider},
    sha256::Sha256,
    Committable, Digestible, Hasher as _, PublicKey,
};
use commonware_p2p::Recipients;
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::{FuzzRng, NZUsize};
use std::{collections::HashSet, num::NonZeroUsize, time::Duration};

const MIN_EVENTS: usize = 1;
const MAX_EVENTS: usize = 128;

/// Number of blocks in the canonical chain. Kept well below
/// `BLOCKS_PER_EPOCH` so every height maps to epoch 0 and the driver
/// does not need to model epoch boundaries.
const NUM_BLOCKS: u64 = 16;

/// Generous backlog so the actor never blocks on ack pressure during the
/// run. The driver intentionally leaves blocks unacked between events so
/// that `Restart` exercises at-least-once redelivery; high headroom keeps
/// marshal dispatching while the backlog accumulates.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(4 * NUM_BLOCKS as usize);

/// Settle delay applied after each event so spawned actor tasks can drain
/// pending mailbox traffic before the next event lands.
const EVENT_SETTLE: Duration = Duration::from_millis(20);

/// Final drain delay before the invariant check so any in-flight
/// finalization deliveries reach the application.
const FINAL_DRAIN: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum MarshalEvent {
    /// Notify marshal that a block was locally proposed.
    Propose { block_idx: u8 },
    /// Notify marshal that a block was verified.
    Verify { block_idx: u8 },
    /// Notify marshal that a block was certified.
    Certify { block_idx: u8 },
    /// Report a finalization for a block.
    ReportFinalization { block_idx: u8 },
    /// Report a notarization for a block.
    ReportNotarization { block_idx: u8 },
    /// Publish a block through the variant's local buffer (buffered
    /// broadcast engine for Standard, shards engine for Coding) without
    /// going through marshal's mailbox.
    PublishViaVariant { block_idx: u8 },
    /// Release one pending application ack, recording the popped height
    /// as a delivery observation.
    AckNext,
    /// Abort the marshal actor and re-initialize from the same on-disk
    /// state. Pending acks at the moment of restart are NOT signaled,
    /// so marshal's persistent state retains them as un-processed and
    /// the new instance must redeliver them (at-least-once).
    Restart,
    /// Yield without dispatching a marshal-facing event.
    Idle,
}

#[derive(Debug, Clone)]
pub struct MarshalFuzzInput {
    pub raw_bytes: Vec<u8>,
    pub events: Vec<MarshalEvent>,
}

impl Arbitrary<'_> for MarshalFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let event_count = u.int_in_range(MIN_EVENTS..=MAX_EVENTS)?;
        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            events.push(MarshalEvent::arbitrary(u)?);
        }
        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self { raw_bytes, events })
    }
}

/// Variant-agnostic adapter for publishing a block through the variant's
/// local cache and confirming it landed.
pub trait VariantPublish<Block: Clone + Send + 'static>: Sync {
    /// Best-effort publish. The implementation may silently drop the
    /// request if the underlying mailbox enqueue fails; the driver
    /// confirms availability via [`Self::locally_available`] before
    /// counting the publish.
    fn publish_via_variant(&self, round: Round, block: &Block);

    /// Whether the variant's local cache currently holds the block.
    /// Used after [`Self::publish_via_variant`] to verify the publish
    /// was accepted before the driver treats the block as provided.
    fn locally_available(&self, block: &Block) -> impl std::future::Future<Output = bool> + Send;
}

impl<P, M> VariantPublish<M> for buffered::Mailbox<P, M>
where
    P: PublicKey,
    M: Codec + Digestible + Clone + Send + 'static,
{
    fn publish_via_variant(&self, _round: Round, block: &M) {
        let _ = self.broadcast(Recipients::All, block.clone());
    }
    async fn locally_available(&self, block: &M) -> bool {
        self.get(block.digest()).await.is_some()
    }
}

impl<B, C, H, P> VariantPublish<CodedBlock<B, C, H>> for shards::Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: commonware_cryptography::Hasher,
    P: PublicKey,
{
    fn publish_via_variant(&self, round: Round, block: &CodedBlock<B, C, H>) {
        self.proposed(round, block.clone());
    }
    async fn locally_available(&self, block: &CodedBlock<B, C, H>) -> bool {
        self.get(block.commitment()).await.is_some()
    }
}

fn round_for_height(height: Height) -> Round {
    Round::new(Epoch::zero(), View::new(height.get()))
}

fn parent_view(height: Height) -> View {
    height
        .previous()
        .map(|h| View::new(h.get()))
        .unwrap_or(View::zero())
}

fn block_index(idx: u8) -> usize {
    (idx as u64 % NUM_BLOCKS) as usize
}

/// Run the marshal fuzz driver against `H` (StandardHarness or CodingHarness).
pub fn fuzz_marshal<H: TestHarness>(input: MarshalFuzzInput)
where
    H::ValidatorExtra: VariantPublish<H::TestBlock>,
    H::TestBlock: Clone + Send + 'static,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let me = participants[0].clone();
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;

        let application = Application::<H::ApplicationBlock>::manual_ack();
        let provider = ConstantProvider::new(schemes[0].clone());

        let setup = H::setup_validator_with(
            context.child("validator"),
            &mut oracle,
            me.clone(),
            provider.clone(),
            MAX_PENDING_ACKS,
            application.clone(),
        )
        .await;
        let mut actor_handle = setup.actor_handle;
        let mut handle = ValidatorHandle::<H> {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Canonical chain: every block fed to marshal is drawn from here.
        let num_participants = participants.len() as u16;
        let mut canonical = Vec::with_capacity(NUM_BLOCKS as usize);
        let mut parent_digest = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(num_participants);
        for h in 1..=NUM_BLOCKS {
            let block = H::make_test_block(
                parent_digest,
                parent_commitment,
                Height::new(h),
                h,
                num_participants,
            );
            parent_digest = H::digest(&block);
            parent_commitment = H::commitment(&block);
            canonical.push(block);
        }

        // Shadow state for the invariant check.
        //
        // - `durable_available`: blocks marshal has persisted to disk
        //   (via Propose / Verify / Certify, or via delivery on a
        //   ready_prefix advance). Survives restart.
        // - `variant_available`: blocks confirmed in the in-memory
        //   variant cache via PublishViaVariant. Cleared on Restart.
        // - `finalized_anchors`: heights at which marshal has stored
        //   a usable finalization. Survives restart.
        let mut durable_available: HashSet<u64> = HashSet::new();
        let mut variant_available: HashSet<u64> = HashSet::new();
        let mut finalized_anchors: HashSet<u64> = HashSet::new();
        // ready_prefix is monotone non-decreasing. It advances when
        // an anchor's chain becomes complete (chain-walk repair).
        let mut ready_prefix: u64 = 0;
        // Shadow of marshal's persistent processed_height. Mirrors
        // marshal's `store_finalization` floor check: a finalization
        // at or below this height is stale and does not trigger
        // repair.
        let mut processed_height: u64 = setup.height.get();
        let mut delivery_log: Vec<Height> = Vec::new();
        // segment_bounds[i]..segment_bounds[i+1] is the i-th segment of
        // delivery_log. segment_starts[i] is the height the i-th actor
        // instance is expected to begin delivery at (its restored
        // processed height + 1).
        let mut segment_bounds: Vec<usize> = vec![0];
        let mut segment_starts: Vec<u64> = vec![setup.height.get() + 1];
        // For each restart, the heights pending ack at the moment of
        // restart. The next actor instance must redeliver each one.
        let mut expected_redeliveries: Vec<Vec<Height>> = Vec::new();
        // Count of stale queue entries to silently skip on subsequent
        // acks. Stale entries are the pre-restart pending acks whose
        // ack handles are tied to the dead actor.
        let mut stale_to_skip: usize = 0;
        let mut restart_counter: usize = 0;

        for event in input.events.iter().copied() {
            // Set inside the ReportFinalization arm when marshal's
            // store_finalization would have stored the finalization
            // (block found AND height above the persisted floor).
            // This mirrors actor.rs gating try_repair_gaps on
            // store_finalization's return value.
            let mut repair_wake = false;
            match event {
                MarshalEvent::Propose { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    H::propose(&mut handle, round_for_height(height), block).await;
                    durable_available.insert(height.get());
                }
                MarshalEvent::Verify { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let mut peers: [ValidatorHandle<H>; 0] = [];
                    H::verify(&mut handle, round_for_height(height), block, &mut peers).await;
                    durable_available.insert(height.get());
                }
                MarshalEvent::Certify { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    assert!(
                        H::certify(&mut handle, round_for_height(height), block).await,
                        "marshal certified() returned false: actor died mid-fuzz",
                    );
                    durable_available.insert(height.get());
                }
                MarshalEvent::ReportFinalization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let proposal = Proposal::new(
                        round_for_height(height),
                        parent_view(height),
                        H::commitment(block),
                    );
                    let finalization = H::make_finalization(proposal, &schemes, QUORUM);
                    handle.mailbox.report(Activity::Finalization(finalization));
                    // Marshal stores the finalization (as an anchor)
                    // only if the block is locally available AND
                    // the height is strictly above the persisted
                    // processed_height. At-or-below-floor
                    // finalizations are dropped (actor.rs:1732), so
                    // they neither create an anchor nor trigger
                    // try_repair_gaps. When stored, marshal also
                    // writes the block into the finalized_blocks
                    // archive, making it durable.
                    let h = height.get();
                    let block_available =
                        durable_available.contains(&h) || variant_available.contains(&h);
                    if block_available && h > processed_height {
                        finalized_anchors.insert(h);
                        durable_available.insert(h);
                        repair_wake = true;
                    }
                }
                MarshalEvent::ReportNotarization { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let proposal = Proposal::new(
                        round_for_height(height),
                        parent_view(height),
                        H::commitment(block),
                    );
                    let notarization = H::make_notarization(proposal, &schemes, QUORUM);
                    handle.mailbox.report(Activity::Notarization(notarization));
                    // When the notarized block is locally available
                    // and above the processed floor, marshal calls
                    // cache_block (actor.rs:616) which persists it in
                    // the prunable cache. This is NOT a repair wake:
                    // notarization does not drive finalization
                    // repair. We mirror the durability so a later
                    // restart does not forget a variant-sourced
                    // block.
                    let h = height.get();
                    if (durable_available.contains(&h) || variant_available.contains(&h))
                        && h > processed_height
                    {
                        durable_available.insert(h);
                    }
                }
                MarshalEvent::PublishViaVariant { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    handle
                        .extra
                        .publish_via_variant(round_for_height(height), block);
                    // Yield so the variant engine processes the publish
                    // before we ask whether it landed locally.
                    context.sleep(EVENT_SETTLE).await;
                    if handle.extra.locally_available(block).await {
                        // Variant cache is in-memory only; cleared on
                        // Restart.
                        variant_available.insert(height.get());
                    }
                }
                MarshalEvent::AckNext => {
                    if let Some(height) = application.acknowledge_next() {
                        if stale_to_skip > 0 {
                            stale_to_skip -= 1;
                        } else {
                            delivery_log.push(height);
                            // Marshal persists processed_height in
                            // its metadata as each ack returns.
                            processed_height = processed_height.max(height.get());
                        }
                    }
                }
                MarshalEvent::Restart => {
                    // Let in-flight dispatches reach the application
                    // before we snapshot pending acks.
                    context.sleep(EVENT_SETTLE).await;

                    // Drain stale entries left over from prior restarts
                    // so pending_ack_heights() reflects only the
                    // soon-to-die actor. Their handles tie to dead
                    // channels so the ack signal is a no-op.
                    while stale_to_skip > 0 {
                        if application.acknowledge_next().is_none() {
                            break;
                        }
                        stale_to_skip -= 1;
                    }

                    // Heights pending ack right now were dispatched by
                    // the live actor in the current segment. Record
                    // them as observations of the current segment
                    // BEFORE pushing the segment boundary so they
                    // participate in the segment ordering check. We do
                    // NOT acknowledge them, so marshal's persistent
                    // state retains them as unprocessed and the new
                    // instance must redeliver.
                    let pending_now = application.pending_ack_heights();
                    for h in &pending_now {
                        delivery_log.push(*h);
                    }
                    let pending_count = pending_now.len();
                    expected_redeliveries.push(pending_now);
                    // The pending entries are now in delivery_log;
                    // mark them stale so the next pop doesn't
                    // re-record them.
                    stale_to_skip = pending_count;

                    segment_bounds.push(delivery_log.len());

                    actor_handle.abort();
                    let _ = actor_handle.await;

                    restart_counter += 1;
                    let setup = H::setup_validator_with(
                        context
                            .child("validator")
                            .with_attribute("restart", restart_counter),
                        &mut oracle,
                        me.clone(),
                        provider.clone(),
                        MAX_PENDING_ACKS,
                        application.clone(),
                    )
                    .await;
                    actor_handle = setup.actor_handle;
                    handle.mailbox = setup.mailbox;
                    handle.extra = setup.extra;
                    segment_starts.push(setup.height.get() + 1);
                    // The new buffered / shards engine starts with an
                    // empty cache, so anything that was only available
                    // via the prior variant publish is no longer
                    // visible to marshal.
                    variant_available.clear();
                    // Marshal's processed_height for the new instance
                    // comes from its persistent metadata, which
                    // setup.height reflects. Pending deliveries that
                    // never got acked do NOT advance this floor.
                    processed_height = setup.height.get();
                }
                MarshalEvent::Idle => {}
            }

            // Repair wake: an above-floor ReportFinalization that
            // found its block (mirrored by `repair_wake`), or a
            // Restart (marshal runs try_repair_gaps on startup
            // unconditionally). Both can deliver up to the highest
            // anchor whose chain is now fully populated. Newly
            // delivered heights are promoted into durable_available
            // because marshal moves them into the finalized archive
            // on delivery.
            if repair_wake || matches!(event, MarshalEvent::Restart) {
                let mut best: u64 = 0;
                for &anchor in finalized_anchors.iter() {
                    let mut chain_complete = true;
                    for hh in 1..=anchor {
                        if !durable_available.contains(&hh) && !variant_available.contains(&hh) {
                            chain_complete = false;
                            break;
                        }
                    }
                    if chain_complete {
                        best = best.max(anchor);
                    }
                }
                if best > ready_prefix {
                    for hh in (ready_prefix + 1)..=best {
                        durable_available.insert(hh);
                    }
                    ready_prefix = best;
                }
            }

            context.sleep(EVENT_SETTLE).await;
        }

        // Final drain: pull every remaining pending entry. Stale entries
        // (orphaned by an earlier restart) are skipped; fresh entries
        // (from the live actor) are recorded and advance the
        // processed_height floor for symmetry with AckNext.
        context.sleep(FINAL_DRAIN).await;
        while let Some(height) = application.acknowledge_next() {
            if stale_to_skip > 0 {
                stale_to_skip -= 1;
            } else {
                delivery_log.push(height);
                processed_height = processed_height.max(height.get());
            }
        }
        segment_bounds.push(delivery_log.len());

        // ready_prefix was maintained incrementally during the event
        // loop. Every height in `1..=ready_prefix` was, at some wake
        // event, simultaneously block-available (in the contiguous
        // prefix) and at-or-below the highest reported finalization.
        let delivered_set: HashSet<u64> = delivery_log.iter().map(|h| h.get()).collect();
        for h in 1..=ready_prefix {
            assert!(
                delivered_set.contains(&h),
                "marshal violated at-least-once delivery: ready height {h} never reached \
                 the application (ready_prefix={ready_prefix}, delivered={delivered_set:?})",
            );
        }

        // Per-segment ordering. Each segment begins at the restored
        // processed height + 1 and advances strictly by one.
        assert_eq!(
            segment_bounds.len(),
            segment_starts.len() + 1,
            "segment bookkeeping inconsistency",
        );
        for (segment_idx, window) in segment_bounds.windows(2).enumerate() {
            let (start_idx, end_idx) = (window[0], window[1]);
            if start_idx == end_idx {
                continue;
            }
            let segment = &delivery_log[start_idx..end_idx];
            let expected_start = segment_starts[segment_idx];
            assert_eq!(
                segment[0].get(),
                expected_start,
                "segment #{segment_idx} must start at restored processed height + 1 \
                 ({expected_start}), got {} (segment={:?})",
                segment[0].get(),
                segment,
            );
            for (offset, h) in segment.iter().enumerate() {
                let expected = expected_start + offset as u64;
                assert_eq!(
                    h.get(),
                    expected,
                    "marshal violated in-order delivery within segment #{segment_idx}: \
                     expected height {expected}, observed {} (segment={:?})",
                    h.get(),
                    segment,
                );
            }
        }

        // At-least-once across restart. Each height pending at the moment
        // of restart i must reappear in delivery_log at some segment
        // strictly after i (i.e., at byte offset >= segment_bounds[i+1]).
        for (restart_idx, expected) in expected_redeliveries.iter().enumerate() {
            if expected.is_empty() {
                continue;
            }
            let post_restart_start = segment_bounds[restart_idx + 1];
            let post_restart: HashSet<u64> = delivery_log[post_restart_start..]
                .iter()
                .map(|h| h.get())
                .collect();
            for h in expected {
                assert!(
                    post_restart.contains(&h.get()),
                    "marshal violated at-least-once across restart: height {} was \
                     pending at restart #{} but was never redelivered \
                     (post-restart deliveries={post_restart:?})",
                    h.get(),
                    restart_idx + 1,
                );
            }
        }

        // Digest fidelity for every block surfaced in the application's
        // height map. Re-emits after restart overwrite the prior entry,
        // so the latest delivery at each height is what we compare.
        for (height, block) in application.blocks().iter() {
            let canonical_block = &canonical[(height.get() - 1) as usize];
            assert_eq!(
                block.digest(),
                H::digest(canonical_block),
                "marshal delivered a block whose digest does not match the canonical \
                 chain at height {}",
                height.get(),
            );
        }
    });
}
