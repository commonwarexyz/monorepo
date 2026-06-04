//! Single-node marshal harness runner.
//!
//! Replays a [`MarshalFuzzInput`] event sequence against a single
//! marshal actor (with restarts), maintains the shadow state described
//! in the module-level docs, and asserts the marshal invariants at the
//! end of the run.

use super::{
    input::{MarshalEvent, MarshalFuzzInput},
    invariant,
    variant::VariantPublish,
    NUM_BLOCKS,
};
use commonware_consensus::{
    marshal::{
        core::{CommitmentFallback, DigestFallback},
        mocks::{
            application::Application,
            harness::{
                setup_network_with_participants, TestHarness, ValidatorHandle, NAMESPACE,
                NUM_VALIDATORS, QUORUM,
            },
        },
        Identifier,
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk,
    certificate::{mocks::Fixture, ConstantProvider},
    Digestible,
};
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::{FuzzRng, NZUsize};
use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroUsize,
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
    finalized_anchors: &mut HashSet<u64>,
    processed_height: &mut u64,
    segment_starts: &mut [u64],
) -> bool {
    let h = height.get();
    if *pending_floor != Some(h) {
        return false;
    }
    durable_available.insert(h);
    finalized_anchors.insert(h);
    *processed_height = h.saturating_sub(1);
    if let Some(start) = segment_starts.last_mut() {
        *start = h;
    }
    *pending_floor = None;
    true
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
        //   (via Propose / Verify / Certify, or via delivery on a
        //   ready_prefix advance). Survives restart.
        // - `variant_available`: blocks confirmed in the in-memory variant
        //   cache via PublishViaVariant. Cleared on Restart, and FIFO-evicted
        //   per the variant's `VariantPublish::CACHE_CAPACITY` to
        //   mirror a bounded broadcast cache (otherwise the shadow would think
        //   an evicted block is still repairable and assert a delivery that
        //   cannot happen).
        // - `finalized_anchors`: heights at which marshal has stored
        //   a usable finalization. Survives restart.
        let mut durable_available: HashSet<u64> = HashSet::new();
        let mut variant_available: HashSet<u64> = HashSet::new();
        // Publish order backing `variant_available`'s FIFO eviction.
        let mut variant_order: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
        let mut finalized_anchors: HashSet<u64> = HashSet::new();
        // ready_prefix is monotone non-decreasing. It advances when
        // an anchor's chain becomes complete (chain-walk repair).
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
                        &mut finalized_anchors,
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
                        &mut finalized_anchors,
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
                        &mut finalized_anchors,
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
                    let block_available =
                        durable_available.contains(&h) || variant_available.contains(&h);
                    if block_available && pending_floor == Some(h) {
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            height,
                            &mut durable_available,
                            &mut finalized_anchors,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    } else if block_available && h > processed_height {
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
                        && pending_floor == Some(h)
                    {
                        repair_wake |= apply_pending_floor(
                            &mut pending_floor,
                            height,
                            &mut durable_available,
                            &mut finalized_anchors,
                            &mut processed_height,
                            &mut segment_starts,
                        );
                    }
                    if (durable_available.contains(&h) || variant_available.contains(&h))
                        && h > processed_height
                    {
                        durable_available.insert(h);
                    }
                }
                MarshalEvent::GetBlock { block_idx } => {
                    // Read of the finalized archive by height. Absence can be
                    // valid before finalization or after pruning, but any
                    // returned block must match the canonical chain.
                    let block = &canonical[block_index(block_idx)];
                    if let Some(returned) = handle
                        .mailbox
                        .get_block(Identifier::Height(H::height(block)))
                        .await
                    {
                        assert_eq!(
                            returned.digest(),
                            H::digest(block),
                            "GetBlock returned wrong digest for height {}",
                            H::height(block).get(),
                        );
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
                        if durable_available.contains(&h) || variant_available.contains(&h) {
                            repair_wake |= apply_pending_floor(
                                &mut pending_floor,
                                height,
                                &mut durable_available,
                                &mut finalized_anchors,
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

            // Repair wake: an above-floor ReportFinalization that
            // found its block (mirrored by `repair_wake`), or a
            // Restart (marshal runs try_repair_gaps on startup
            // unconditionally). Both can deliver up to the highest
            // anchor whose chain is now fully populated. Newly
            // delivered heights are promoted into durable_available
            // because marshal moves them into the finalized archive
            // on delivery.
            if pending_floor.is_none() && (repair_wake || matches!(event, MarshalEvent::Restart)) {
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
