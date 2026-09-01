//! Shared input generators, crash-recovery flows, and raw-image oracles for storage fuzz
//! targets.

use arbitrary::Unstructured;
use commonware_runtime::{
    deterministic::{self, PartialWriteMode},
    mocks::PendingSyncs,
};
use commonware_utils::{Probability, probability};
use futures::future::poll_immediate;
use rand::{Rng, RngExt as _};
use std::future::Future;

/// Complete the oldest parked durability completion, if any.
///
/// Interrupted-sync arms call this between polls so each iteration advances the
/// interrupted future one durability barrier deeper before the crash cuts it. The
/// final release may stay unobserved, leaving that barrier's data volatile.
pub fn release_oldest_pending_sync(pending: &PendingSyncs) {
    let released = {
        let mut parked = pending.lock();
        if parked.is_empty() {
            None
        } else {
            Some(parked.remove(0))
        }
    };
    if let Some(sync) = released {
        let _ = sync.release.send(Ok(()));
    }
}

/// Poll `fut` up to `polls` times, completing the oldest parked durability barrier between
/// unfinished polls.
///
/// Returns the output when the future completes within the budget. Otherwise returns `None`
/// and drops the abandoned future, so the crash lands between its internal barriers. Arming
/// the pending gate and crediting durability from a completed output stay with the caller.
pub async fn poll_interrupted<F: Future>(
    pending: &PendingSyncs,
    fut: F,
    polls: usize,
) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    for _ in 0..polls {
        if let Some(output) = poll_immediate(fut.as_mut()).await {
            return Some(output);
        }
        release_oldest_pending_sync(pending);
    }
    None
}

/// Draw one faulted recovery attempt's fault config from `rng`.
///
/// Separate draws select the mutation (write, sync, resize, or remove failures), its
/// failure rate, the crash retention rate, the resize partial rate, and the partial-write
/// mode, so each knob stays independently steerable by the fuzzer. Crash retention and
/// mode stay live for every mutation so the crash after the attempt can still tear
/// whatever the attempt wrote.
fn recovery_fault_config(rng: &mut impl Rng) -> deterministic::FaultConfig {
    fn rate(rng: &mut impl Rng, from: u64) -> Probability {
        Probability::new(rng.random_range(from..=100), 100)
            .expect("a percentage in 0..=100 is valid")
    }

    let mutation: u8 = rng.random_range(0..4);
    let failure_rate = rate(rng, 1);
    let mut config = deterministic::FaultConfig {
        write_rate: Some(deterministic::WriteConfig {
            failure_rate: if mutation == 0 {
                failure_rate
            } else {
                probability!(0, 1)
            },
            retention_rate: rate(rng, 0),
            mode: if rng.random_range(0..2) == 0 {
                PartialWriteMode::Prefix
            } else {
                PartialWriteMode::Subset
            },
        }),
        ..Default::default()
    };
    match mutation {
        0 => {}
        1 => config.sync_rate = Some(failure_rate),
        2 => {
            config.resize_rate = Some(deterministic::ResizeConfig {
                failure_rate,
                partial_rate: rate(rng, 0),
            });
        }
        3 => config.remove_rate = Some(failure_rate),
        _ => unreachable!("the draw range spans four mutations"),
    }
    config
}

/// Run a chain of 1..=4 recovery attempts, each with a mutable storage fault enabled and
/// each crashing into the next, then return the final crash image.
///
/// The chain draws from the runtime rng, which the checkpoint carries across attempts: the
/// first attempt draws the chain depth, and every attempt draws its fault selector
/// (mutation, failure and retention rates, and partial-write mode) before its faults arm.
/// Chaining interrupts the recovery of an already-interrupted recovery, so images
/// reachable only through repeated repair interruption are also explored.
///
/// Each attempt's recovered object or error is discarded because mutable-operation errors
/// retire the instance. The fault config is cleared before each crash (retention policies
/// bind when a write is issued), so the returned checkpoint recovers fault-free.
pub fn faulted_recovery<F, Fut, T, E>(
    mut checkpoint: deterministic::Checkpoint,
    recover: F,
) -> deterministic::Checkpoint
where
    F: Fn(deterministic::Context) -> Fut + Clone,
    Fut: Future<Output = Result<T, E>>,
{
    let mut remaining = None;
    loop {
        let recover = recover.clone();
        let (left, next) = deterministic::Runner::from(checkpoint).start_and_recover(
            move |mut context| async move {
                // The first attempt draws the chain depth, later attempts count down.
                // Both draws land before the faults arm.
                let left: u32 = match remaining {
                    None => context.random_range(1..=4u32) - 1,
                    Some(left) => left - 1,
                };
                let fault_config = recovery_fault_config(&mut context);
                let config = context.storage_fault_config();
                *config.write() = fault_config;
                drop(recover(context).await);
                *config.write() = deterministic::FaultConfig::default();
                left
            },
        );
        checkpoint = next;
        if left == 0 {
            break;
        }
        remaining = Some(left);
    }
    checkpoint
}

/// Generate a logical page size in `1..=256`.
pub fn bounded_page_size(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(1..=256)
}

/// Generate a page-cache size in `1..=16`.
pub fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=16)
}

/// Generate an item count in `1..=64`.
pub fn bounded_items(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(1..=64)
}

/// Generate a buffer size in `1..=2048`.
pub fn bounded_buffer(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(1..=2048)
}

/// Generate a nonzero failure rate in `(0, 1]` at percentage granularity.
pub fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<Probability> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(probability!(u64::from(percent), 100))
}
