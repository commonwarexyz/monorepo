//! Single-node marshal harness runner.
//!
//! Replays a [`MarshalFuzzInput`] event sequence against a single
//! marshal actor (with restarts), maintains the shadow state described
//! in the module-level docs, and asserts the marshal invariants at the
//! end of the run.

use super::{
    input::{MarshalEvent, MarshalFuzzInput, QueryKind},
    invariant,
    variant::VariantPublish,
    NUM_BLOCKS,
};
use commonware_consensus::{
    marshal::{
        ancestry::{self, Ancestry as _, BlockProvider},
        core::{CommitmentFallback, DigestFallback, Mailbox, Variant},
        mocks::{
            application::Application,
            harness::{
                setup_network_with_participants, TestHarness, ValidatorHandle, D, K, NAMESPACE,
                NUM_VALIDATORS, QUORUM, S,
            },
        },
        Identifier,
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Heightable, Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk,
    certificate::{mocks::Fixture, ConstantProvider},
    Digestible,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    deterministic,
    telemetry::metrics::{
        histogram::{Buckets, Timed},
        MetricsExt as _,
    },
    Clock, Runner, Supervisor as _,
};
use commonware_storage::archive;
use commonware_utils::{vec::NonEmptyVec, FuzzRng, NZUsize};
use futures::{future::BoxFuture, task::noop_waker_ref, FutureExt, StreamExt};
use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    hint::black_box,
    num::NonZeroUsize,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

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

/// Well above the harness mailbox capacity (`100`) so a single event reaches
/// the overflow policy before yielding back to the deterministic scheduler.
const MAILBOX_BURST_FILL: usize = 256;

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

fn apply_pending_floor(
    pending_floor: &mut Option<u64>,
    height: Height,
    durable_available: &mut HashSet<u64>,
    finalized_available: &mut HashSet<u64>,
    processed_height: &mut u64,
    segment_starts: &mut [u64],
) -> bool {
    let h = height.get();
    if *pending_floor != Some(h) {
        return false;
    }
    durable_available.insert(h);
    finalized_available.insert(h);
    *processed_height = h.saturating_sub(1);
    if let Some(start) = segment_starts.last_mut() {
        *start = h;
    }
    *pending_floor = None;
    true
}

fn block_available(
    durable_available: &HashSet<u64>,
    variant_available: &HashSet<u64>,
    height: u64,
) -> bool {
    durable_available.contains(&height) || variant_available.contains(&height)
}

fn application_block<H: TestHarness>(block: &H::TestBlock) -> H::ApplicationBlock {
    <H::Variant as Variant>::into_inner(block.clone().into())
}

fn expected_digest<H: TestHarness>(
    canonical: &[H::TestBlock],
    genesis: &H::TestBlock,
    height: Height,
) -> Option<D> {
    if height.get() == 0 {
        Some(H::digest(genesis))
    } else {
        canonical.get((height.get() - 1) as usize).map(H::digest)
    }
}

fn assert_known_digest<H: TestHarness>(
    canonical: &[H::TestBlock],
    genesis: &H::TestBlock,
    height: Height,
    digest: D,
    label: &str,
) {
    let Some(expected) = expected_digest::<H>(canonical, genesis, height) else {
        panic!(
            "{label} returned unexpected height {} beyond canonical chain length {}",
            height.get(),
            canonical.len(),
        );
    };
    assert_eq!(
        digest,
        expected,
        "{label} returned wrong digest for height {}",
        height.get(),
    );
}

fn advance_ready_prefix(finalized_available: &HashSet<u64>, ready_prefix: &mut u64) {
    while *ready_prefix < NUM_BLOCKS && finalized_available.contains(&(*ready_prefix + 1)) {
        *ready_prefix += 1;
    }
}

fn shadow_repair(
    processed_height: u64,
    durable_available: &mut HashSet<u64>,
    variant_available: &HashSet<u64>,
    finalized_available: &mut HashSet<u64>,
    ready_prefix: &mut u64,
) {
    // Marshal also has a trailing-anchor repair path for a stored finalization
    // whose anchor block is not yet in `finalized_blocks`. This driver records
    // finalizations only when the block is locally available, so that path is
    // unreachable and every recorded anchor is immediately finalized_available.
    let start = processed_height.saturating_add(1);
    let mut cursor = start;
    while cursor <= NUM_BLOCKS {
        if finalized_available.contains(&cursor) {
            cursor += 1;
            continue;
        }

        let Some(gap_end) =
            ((cursor + 1)..=NUM_BLOCKS).find(|height| finalized_available.contains(height))
        else {
            break;
        };

        let mut repair = gap_end - 1;
        loop {
            if block_available(durable_available, variant_available, repair) {
                durable_available.insert(repair);
                finalized_available.insert(repair);
            } else {
                advance_ready_prefix(finalized_available, ready_prefix);
                return;
            }

            if repair == cursor {
                break;
            }
            repair -= 1;
        }
    }

    advance_ready_prefix(finalized_available, ready_prefix);
}

fn assert_ready_delivery(ready_prefix: u64, height: Height) {
    assert!(
        height.get() <= ready_prefix,
        "marshal delivered height {} before the fuzz model made it ready \
         (ready_prefix={ready_prefix})",
        height.get(),
    );
}

fn assert_stale_ack(expected: Height, observed: Height) {
    assert_eq!(
        observed,
        expected,
        "stale ack bookkeeping mismatch: expected to skip height {}, observed {}",
        expected.get(),
        observed.get(),
    );
}

fn targets(participants: &[K], offset: usize) -> NonEmptyVec<K> {
    let first = participants[offset % participants.len()].clone();
    let second = participants[(offset + 1) % participants.len()].clone();
    NonEmptyVec::from_unchecked(vec![first, second])
}

#[inline(never)]
fn hint_finalized_via_mailbox<H: TestHarness>(
    mailbox: &Mailbox<S, H::Variant>,
    height: Height,
    targets: NonEmptyVec<K>,
) {
    let hint: fn(&Mailbox<S, H::Variant>, Height, NonEmptyVec<K>) =
        Mailbox::<S, H::Variant>::hint_finalized;
    black_box(hint)(mailbox, height, targets);
}

fn park_mailbox_future<F, T>(parked: &mut Vec<BoxFuture<'static, ()>>, future: F)
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut future = async move {
        let _ = future.await;
    }
    .boxed();
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(()) | Poll::Pending => {}
    }
    parked.push(future);
}

/// Run the marshal fuzz driver against `H` (StandardHarness or CodingHarness).
pub fn fuzz_marshal<H: TestHarness>(input: MarshalFuzzInput)
where
    H::ValidatorExtra: VariantPublish<H::TestBlock>,
    H::TestBlock: Clone + Send + 'static,
    Mailbox<S, H::Variant>: BlockProvider<Block = H::ApplicationBlock>,
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
        // Seed the parent from the same genesis block the actor is started with
        // (`Start::Genesis`), so height 1 links to the real genesis digest and
        // the live standard/coding ancestry checks accept the chain.
        let num_participants = participants.len() as u16;
        let mut canonical = Vec::with_capacity(NUM_BLOCKS as usize);
        let genesis = H::genesis_block(num_participants);
        let mut parent_digest = H::digest(&genesis);
        let mut parent_commitment = H::commitment(&genesis);
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
        //   (via Propose / Verify / Certify, notarization, finalization,
        //   floor application, or finalized-archive repair). Survives restart.
        // - `variant_available`: blocks confirmed in the in-memory variant
        //   cache via PublishViaVariant. Cleared on Restart, and FIFO-evicted
        //   per the variant's `VariantPublish::CACHE_CAPACITY` to
        //   mirror a bounded broadcast cache (otherwise the shadow would think
        //   an evicted block is still repairable and assert a delivery that
        //   cannot happen).
        // - `finalized_available`: blocks in marshal's finalized archive,
        //   either as direct anchors or as ancestors repaired from a later
        //   anchor. Survives restart.
        let mut durable_available: HashSet<u64> = HashSet::new();
        let mut variant_available: HashSet<u64> = HashSet::new();
        let mut finalized_available: HashSet<u64> = HashSet::new();
        // Publish order backing `variant_available`'s FIFO eviction.
        let mut variant_order: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
        // ready_prefix is monotone non-decreasing. It advances when the
        // finalized archive becomes contiguous from height 1.
        let mut ready_prefix: u64 = 0;
        // Shadow of marshal's persistent processed_height. Mirrors
        // marshal's `store_finalization` floor check: a finalization
        // at or below this height is stale and does not trigger
        // repair.
        let mut processed_height: u64 = setup.height.map_or(0, |h| h.get());
        let mut delivery_log: Vec<Height> = Vec::new();
        // segment_bounds[i]..segment_bounds[i+1] is the i-th segment of
        // delivery_log. segment_starts[i] is the height the i-th actor
        // instance is expected to begin delivery at (its restored
        // processed height + 1).
        let mut segment_bounds: Vec<usize> = vec![0];
        let mut segment_starts: Vec<u64> = vec![setup.height.map_or(0, |h| h.get()) + 1];
        // For each restart, the heights pending ack at the moment of
        // restart. A later actor instance must redeliver each one.
        let mut expected_redeliveries: Vec<Vec<Height>> = Vec::new();
        // Stale queue entries to skip on subsequent acks. These are application
        // ack handles whose corresponding marshal waiters were orphaned by a
        // restart or floor update.
        let mut stale_to_skip: VecDeque<Height> = VecDeque::new();
        let mut restart_counter: usize = 0;
        let mut pending_floor: Option<u64> = None;
        let mut subscriptions = Vec::new();
        let mut parked_queries: Vec<BoxFuture<'static, ()>> = Vec::new();
        let ancestry_fetch_duration = Timed::new(context.histogram(
            "marshal_fuzz_ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the marshal fuzz ancestry stream, in seconds",
            Buckets::LOCAL,
        ));

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
                    repair_wake |= apply_pending_floor(
                        &mut pending_floor,
                        height,
                        &mut durable_available,
                        &mut finalized_available,
                        &mut processed_height,
                        &mut segment_starts,
                    );
                }
                MarshalEvent::Verify { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let mut peers: [ValidatorHandle<H>; 0] = [];
                    H::verify(&mut handle, round_for_height(height), block, &mut peers).await;
                    durable_available.insert(height.get());
                    repair_wake |= apply_pending_floor(
                        &mut pending_floor,
                        height,
                        &mut durable_available,
                        &mut finalized_available,
                        &mut processed_height,
                        &mut segment_starts,
                    );
                }
                MarshalEvent::Certify { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    assert!(
                        H::certify(&mut handle, round_for_height(height), block).await,
                        "marshal certified() returned false: actor died mid-fuzz",
                    );
                    durable_available.insert(height.get());
                    repair_wake |= apply_pending_floor(
                        &mut pending_floor,
                        height,
                        &mut durable_available,
                        &mut finalized_available,
                        &mut processed_height,
                        &mut segment_starts,
                    );
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
                    if block_available(&durable_available, &variant_available, h)
                        && pending_floor == Some(h)
                    {
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            height,
                            &mut durable_available,
                            &mut finalized_available,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    } else if block_available(&durable_available, &variant_available, h)
                        && h > processed_height
                    {
                        durable_available.insert(h);
                        finalized_available.insert(h);
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
                    if block_available(&durable_available, &variant_available, h)
                        && pending_floor == Some(h)
                    {
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            height,
                            &mut durable_available,
                            &mut finalized_available,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    }
                    if block_available(&durable_available, &variant_available, h)
                        && h > processed_height
                    {
                        durable_available.insert(h);
                    }
                }
                MarshalEvent::GetBlock { block_idx, query } => {
                    // Read of the finalized archive by height. Absence can be
                    // valid before finalization or after pruning, but any
                    // returned block must match the canonical chain.
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let digest = H::digest(block);
                    let returned = match query {
                        QueryKind::Height => handle.mailbox.get_block(height).await,
                        QueryKind::Digest => handle.mailbox.get_block(&digest).await,
                        QueryKind::ArchiveIndex => {
                            handle
                                .mailbox
                                .get_block(archive::Identifier::Index(height.get()))
                                .await
                        }
                        QueryKind::ArchiveKey => {
                            handle
                                .mailbox
                                .get_block(archive::Identifier::Key(&digest))
                                .await
                        }
                        QueryKind::Latest => handle.mailbox.get_block(Identifier::Latest).await,
                    };
                    if let Some(returned) = returned {
                        assert_known_digest::<H>(
                            &canonical,
                            &genesis,
                            returned.height(),
                            returned.digest(),
                            "GetBlock",
                        );
                    }
                }
                MarshalEvent::GetInfo { block_idx, query } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let digest = H::digest(block);
                    let returned = match query {
                        QueryKind::Height => handle.mailbox.get_info(height).await,
                        QueryKind::Digest => handle.mailbox.get_info(&digest).await,
                        QueryKind::ArchiveIndex => {
                            handle
                                .mailbox
                                .get_info(archive::Identifier::Index(height.get()))
                                .await
                        }
                        QueryKind::ArchiveKey => {
                            handle
                                .mailbox
                                .get_info(archive::Identifier::Key(&digest))
                                .await
                        }
                        QueryKind::Latest => handle.mailbox.get_info(Identifier::Latest).await,
                    };
                    if let Some((height, digest)) = returned {
                        assert_known_digest::<H>(
                            &canonical,
                            &genesis,
                            height,
                            digest,
                            "GetInfo",
                        );
                    }
                }
                MarshalEvent::Ancestry {
                    block_idx,
                    max_items,
                } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    if !block_available(&durable_available, &variant_available, height.get()) {
                        continue;
                    }
                    let stream = select! {
                        result = handle.mailbox.ancestry(
                            Arc::new(context.child("fuzz_ancestry")),
                            (DigestFallback::Wait, H::digest(block)),
                            ancestry_fetch_duration.clone(),
                        ) => result,
                        _ = context.sleep(EVENT_SETTLE) => None,
                    };
                    let Some(mut stream) = stream else {
                        continue;
                    };

                    let mut previous = None;
                    let budget = usize::from(max_items % 8) + 1;
                    for _ in 0..budget {
                        let _ = stream.peek();
                        context.sleep(EVENT_SETTLE).await;
                        let next = select! {
                            result = stream.next() => result,
                            _ = context.sleep(EVENT_SETTLE) => None,
                        };
                        let Some(item) = next else {
                            break;
                        };
                        if let Some(previous_height) = previous {
                            assert!(
                                item.height() < previous_height,
                                "ancestry stream must walk toward lower heights"
                            );
                        }
                        previous = Some(item.height());
                        assert_known_digest::<H>(
                            &canonical,
                            &genesis,
                            item.height(),
                            item.digest(),
                            "Ancestry",
                        );
                    }
                }
                MarshalEvent::BoundedAncestry {
                    block_idx,
                    len,
                    reverse,
                    max_items,
                } => {
                    let start = block_index(block_idx);
                    let len = usize::from(len % 8) + 1;
                    let mut blocks = (0..len)
                        .map(|offset| {
                            let idx = (start + offset) % canonical.len();
                            application_block::<H>(&canonical[idx])
                        })
                        .collect::<Vec<_>>();
                    if reverse {
                        blocks.reverse();
                    }
                    let mut stream = ancestry::from_iter(blocks);
                    let budget = usize::from(max_items % 8) + 1;
                    for _ in 0..budget {
                        let _ = stream.peek();
                        if stream.next().await.is_none() {
                            break;
                        }
                    }
                }
                MarshalEvent::Subscribe {
                    block_idx,
                    by_commitment,
                } => {
                    // When the block is missing locally this drives the fallback
                    // fetch + subscriber registration path. Keep the receiver alive
                    // so the mailbox policy does not discard the request before the
                    // actor can observe it.
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let round = round_for_height(height);
                    if by_commitment {
                        subscriptions.push(handle.mailbox.subscribe_by_commitment(
                            H::commitment(block),
                            CommitmentFallback::FetchByCommitment { height },
                        ));
                    } else {
                        subscriptions.push(handle.mailbox.subscribe_by_digest(
                            H::digest(block),
                            DigestFallback::FetchByRound { round },
                        ));
                    }
                }
                MarshalEvent::MailboxBurst { block_idx } => {
                    let start = block_index(block_idx);
                    let floor_block = &canonical[processed_height as usize % canonical.len()];
                    let floor_height = H::height(floor_block);
                    let floor_proposal = Proposal::new(
                        round_for_height(floor_height),
                        parent_view(floor_height),
                        H::commitment(floor_block),
                    );
                    let floor_finalization =
                        H::make_finalization(floor_proposal, &schemes, QUORUM);
                    let stale = &canonical[0];
                    let stale_height = H::height(stale);
                    let stale_digest = H::digest(stale);
                    let fresh = &canonical[8];
                    let fresh_height = H::height(fresh);
                    let fresh_round = round_for_height(fresh_height);
                    let fresh_digest = H::digest(fresh);
                    let fresh_commitment = H::commitment(fresh);

                    for offset in 0..MAILBOX_BURST_FILL {
                        let block = &canonical[(start + offset) % canonical.len()];
                        handle.mailbox.forward(
                            round_for_height(H::height(block)),
                            H::commitment(block),
                            Recipients::Some(Vec::new()),
                        );
                    }
                    let pending_acks = application.pending_ack_heights();
                    // Existing stale entries are orphaned by earlier restarts.
                    // A live floor update only clears acks owned by the current actor.
                    let stale_pending = stale_to_skip.len().min(pending_acks.len());
                    let live_pending_acks = &pending_acks[stale_pending..];
                    let only_genesis_pending = live_pending_acks.iter().all(|h| h.get() == 0);
                    let current_segment_empty =
                        delivery_log.len() == *segment_bounds.last().unwrap();
                    let mut burst_floor = false;
                    if pending_floor.is_none()
                        && floor_height.get() == processed_height + 1
                        && current_segment_empty
                        && only_genesis_pending
                    {
                        handle.mailbox.set_floor(floor_finalization.clone());
                        handle.mailbox.set_floor(floor_finalization);
                        stale_to_skip.extend(live_pending_acks.iter().copied());
                        pending_floor = Some(floor_height.get());
                        burst_floor = true;
                    }

                    hint_finalized_via_mailbox::<H>(
                        &handle.mailbox,
                        Height::new(9),
                        targets(&participants, 1),
                    );
                    handle.mailbox.prune(Height::new(2));
                    handle.mailbox.prune(Height::new(8));
                    handle.mailbox.prune(Height::new(4));
                    hint_finalized_via_mailbox::<H>(
                        &handle.mailbox,
                        Height::new(1),
                        targets(&participants, 0),
                    );
                    hint_finalized_via_mailbox::<H>(
                        &handle.mailbox,
                        Height::new(9),
                        targets(&participants, 2),
                    );
                    hint_finalized_via_mailbox::<H>(
                        &handle.mailbox,
                        Height::new(9),
                        targets(&participants, 1),
                    );

                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_info(stale_height).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_block(stale_height).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_finalization(stale_height).await
                        });
                    }

                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_info(Identifier::Digest(fresh_digest)).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_info(Identifier::Latest).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_block(Identifier::Digest(fresh_digest)).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_block(Identifier::Latest).await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_processed_height().await
                        });
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        park_mailbox_future(&mut parked_queries, async move {
                            mailbox.get_verified(fresh_round).await
                        });
                    }

                    {
                        let mailbox = handle.mailbox.clone();
                        let _ = async move {
                            mailbox.get_block(Identifier::Digest(stale_digest)).await
                        }
                        .now_or_never();
                    }
                    {
                        let mailbox = handle.mailbox.clone();
                        let _ = async move {
                            mailbox.get_info(Identifier::Latest).await
                        }
                        .now_or_never();
                    }

                    let mut closed_digest =
                        handle
                            .mailbox
                            .subscribe_by_digest(fresh_digest, DigestFallback::Wait);
                    closed_digest.close();
                    drop(closed_digest);
                    let mut closed_commitment = handle.mailbox.subscribe_by_commitment(
                        fresh_commitment,
                        CommitmentFallback::FetchByCommitment {
                            height: fresh_height,
                        },
                    );
                    closed_commitment.close();
                    drop(closed_commitment);
                    subscriptions.push(
                        handle
                            .mailbox
                            .subscribe_by_digest(fresh_digest, DigestFallback::Wait),
                    );
                    subscriptions.push(handle.mailbox.subscribe_by_commitment(
                        fresh_commitment,
                        CommitmentFallback::FetchByCommitment {
                            height: fresh_height,
                        },
                    ));
                    handle.mailbox.hint_notarized(fresh_round, fresh_commitment);

                    // Only report consensus certificates for a locally missing
                    // block outside the pending floor transition. If marshal
                    // already has the block, Finalization can store a trailing
                    // finalized anchor and trigger repair, which must be modeled
                    // by the dedicated ReportFinalization arm.
                    if !block_available(
                        &durable_available,
                        &variant_available,
                        fresh_height.get(),
                    ) && pending_floor != Some(fresh_height.get())
                    {
                        let proposal =
                            Proposal::new(fresh_round, parent_view(fresh_height), fresh_commitment);
                        let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
                        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
                        handle.mailbox.report(Activity::Notarization(notarization));
                        handle.mailbox.report(Activity::Finalization(finalization));
                    }

                    if burst_floor {
                        let round = round_for_height(floor_height);
                        let proposed = floor_block.clone().into();
                        let verified = floor_block.clone().into();
                        let certified = floor_block.clone().into();
                        {
                            let mailbox = handle.mailbox.clone();
                            park_mailbox_future(&mut parked_queries, async move {
                                mailbox.proposed(round, proposed).await
                            });
                        }
                        {
                            let mailbox = handle.mailbox.clone();
                            park_mailbox_future(&mut parked_queries, async move {
                                mailbox.verified(round, verified).await
                            });
                        }
                        {
                            let mailbox = handle.mailbox.clone();
                            park_mailbox_future(&mut parked_queries, async move {
                                mailbox.certified(round, certified).await
                            });
                        }
                        durable_available.insert(floor_height.get());
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            floor_height,
                            &mut durable_available,
                            &mut finalized_available,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    }
                }
                MarshalEvent::SetFloor { block_idx } => {
                    let block = &canonical[block_index(block_idx)];
                    let height = H::height(block);
                    let h = height.get();
                    let pending_acks = application.pending_ack_heights();
                    // Existing stale entries are orphaned by earlier restarts.
                    // A live SetFloor only clears acks owned by the current actor.
                    let stale_pending = stale_to_skip.len().min(pending_acks.len());
                    let live_pending_acks = &pending_acks[stale_pending..];
                    let only_genesis_pending = live_pending_acks.iter().all(|h| h.get() == 0);
                    let current_segment_empty =
                        delivery_log.len() == *segment_bounds.last().unwrap();
                    if pending_floor.is_none()
                        && h == processed_height + 1
                        && current_segment_empty
                        && only_genesis_pending
                    {
                        let proposal = Proposal::new(
                            round_for_height(height),
                            parent_view(height),
                            H::commitment(block),
                        );
                        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
                        handle.mailbox.set_floor(finalization);
                        stale_to_skip.extend(live_pending_acks.iter().copied());
                        pending_floor = Some(h);
                        if block_available(&durable_available, &variant_available, h) {
                            repair_wake |= apply_pending_floor(
                                &mut pending_floor,
                                height,
                                &mut durable_available,
                                &mut finalized_available,
                                &mut processed_height,
                                &mut segment_starts,
                            );
                        }
                    }
                }
                MarshalEvent::Prune { block_idx } => {
                    // Above-floor pruning is ignored. At-or-below-floor pruning
                    // removes only already-delivered data, so it leaves the
                    // delivery shadow unchanged.
                    let target = block_index(block_idx) as u64 + 1;
                    handle.mailbox.prune(Height::new(target));
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
                        // Variant cache is in-memory only; cleared on Restart.
                        let h = height.get();
                        variant_available.insert(h);
                        // Mirror the variant engine's cache bound. A fixed-size
                        // FIFO (buffered engine) refreshes a re-published entry
                        // and evicts the oldest past capacity; an unbounded
                        // cache (shards engine, `None`) keeps every publish.
                        if let Some(capacity) =
                            <H::ValidatorExtra as VariantPublish<H::TestBlock>>::CACHE_CAPACITY
                        {
                            variant_order.retain(|&x| x != h);
                            variant_order.push_back(h);
                            while variant_order.len() > capacity {
                                if let Some(evicted) = variant_order.pop_front() {
                                    variant_available.remove(&evicted);
                                }
                            }
                        }
                        // Marshal holds a buffer subscription for a pending
                        // floor anchor; the publish completes it and marshal
                        // ingests the block as the durable floor anchor.
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            height,
                            &mut durable_available,
                            &mut finalized_available,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    }
                }
                MarshalEvent::AckNext => {
                    if let Some(height) = application.acknowledge_next() {
                        if let Some(expected) = stale_to_skip.pop_front() {
                            assert_stale_ack(expected, height);
                        } else if height.get() != 0 {
                            // Height 0 is the genesis floor block marshal
                            // surfaces on a fresh start; it is not a finalized
                            // container, so it is not recorded or validated.
                            assert_ready_delivery(ready_prefix, height);
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
                    // or floor updates so pending_ack_heights() reflects
                    // only the soon-to-die actor. Their marshal waiters
                    // were already orphaned, so the ack signal is a no-op.
                    while let Some(expected) = stale_to_skip.front().copied() {
                        let observed = application.acknowledge_next().unwrap_or_else(|| {
                            panic!(
                                "stale ack bookkeeping expected queued height {} but application \
                                 queue was empty",
                                expected.get(),
                            )
                        });
                        assert_stale_ack(expected, observed);
                        stale_to_skip.pop_front();
                    }

                    // Heights pending ack right now were dispatched by
                    // the live actor in the current segment. Record
                    // them as observations of the current segment
                    // BEFORE pushing the segment boundary so they
                    // participate in the segment ordering check. We do
                    // NOT acknowledge them, so marshal's persistent
                    // state retains them as unprocessed and a later
                    // instance must redeliver.
                    let pending_now = application.pending_ack_heights();
                    // All pending entries (including a genesis floor block) are
                    // orphaned once this actor dies, so the next instance's
                    // acks must skip every one of them.
                    stale_to_skip = pending_now.iter().copied().collect();
                    // Only real finalized containers (height > 0) participate
                    // in the segment ordering and redelivery checks.
                    let pending_real: Vec<Height> =
                        pending_now.into_iter().filter(|h| h.get() != 0).collect();
                    for h in &pending_real {
                        assert_ready_delivery(ready_prefix, *h);
                        delivery_log.push(*h);
                    }
                    expected_redeliveries.push(pending_real);
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
                    segment_starts.push(setup.height.map_or(0, |h| h.get()) + 1);
                    // The new buffered / shards engine starts with an
                    // empty cache, so anything that was only available
                    // via the prior variant publish is no longer
                    // visible to marshal.
                    variant_available.clear();
                    variant_order.clear();
                    // Marshal's processed_height for the new instance
                    // comes from its persistent metadata, which
                    // setup.height reflects. Pending deliveries that
                    // never got acked do NOT advance this floor.
                    processed_height = setup.height.map_or(0, |h| h.get());
                    pending_floor = None;
                }
                MarshalEvent::Idle => {}
            }

            // Repair wake: an above-floor ReportFinalization that found its
            // block (mirrored by `repair_wake`), or a Restart (marshal runs
            // try_repair_gaps on startup unconditionally). Gap repair can
            // persist ancestors above an unrepaired lower gap; those ancestors
            // survive restart even if they came from the variant cache. Delivery
            // is ready once the finalized archive is contiguous from height 1.
            if pending_floor.is_none() && (repair_wake || matches!(event, MarshalEvent::Restart)) {
                shadow_repair(
                    processed_height,
                    &mut durable_available,
                    &variant_available,
                    &mut finalized_available,
                    &mut ready_prefix,
                );
            }

            context.sleep(EVENT_SETTLE).await;
        }

        // Final drain: pull every remaining pending entry. Stale entries
        // (orphaned by an earlier restart) are skipped; fresh entries
        // (from the live actor) are recorded and advance the
        // processed_height floor for symmetry with AckNext.
        context.sleep(FINAL_DRAIN).await;
        while let Some(height) = application.acknowledge_next() {
            if let Some(expected) = stale_to_skip.pop_front() {
                assert_stale_ack(expected, height);
            } else if height.get() != 0 {
                // Skip the genesis floor block (height 0); see AckNext.
                assert_ready_delivery(ready_prefix, height);
                delivery_log.push(height);
                processed_height = processed_height.max(height.get());
            }
        }
        assert!(
            stale_to_skip.is_empty(),
            "stale ack bookkeeping retained unmatched entries: {stale_to_skip:?}",
        );
        segment_bounds.push(delivery_log.len());

        invariant::check_all::<H>(
            ready_prefix,
            &delivery_log,
            &segment_bounds,
            &segment_starts,
            &expected_redeliveries,
            &application.delivered(),
            &canonical,
        );
    });
}
