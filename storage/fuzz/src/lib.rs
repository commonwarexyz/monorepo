//! Shared input generators, crash-recovery flows, and raw-image oracles for storage fuzz
//! targets.

use arbitrary::Unstructured;
use commonware_cryptography::Crc32;
use commonware_runtime::{
    buffer::paged::CHECKSUM_SIZE,
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

/// Select a page's authoritative checksum slot, falling back to the other slot if a write tore.
///
/// `page` is one raw physical page: `page_size` logical bytes followed by the dual-slot
/// checksum footer. Returns the CRC-validated logical length, or `None` when neither slot
/// verifies.
pub fn valid_page_len(page: &[u8], page_size: usize) -> Option<usize> {
    let footer = page.get(page_size..)?;
    if footer.len() != CHECKSUM_SIZE as usize {
        return None;
    }
    let slots = [
        (
            u16::from_be_bytes(footer[0..2].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[2..6].try_into().unwrap()),
        ),
        (
            u16::from_be_bytes(footer[6..8].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[8..12].try_into().unwrap()),
        ),
    ];
    let authoritative = usize::from(slots[1].0 > slots[0].0);
    for slot in [authoritative, authoritative ^ 1] {
        let (len, checksum) = slots[slot];
        if len > 0 && len <= page_size && Crc32::checksum(&page[..len]) == checksum {
            return Some(len);
        }
    }
    None
}

/// Cap on the entropy stream a recovery target draws its randomness from.
const MAX_ENTROPY_BYTES: usize = 4096;

/// Consume the input's remaining bytes (capped) as the entropy stream driving the runtime
/// rng: all in-run randomness, fault sampling, and the faulted recovery chain's depth and
/// shapes.
pub fn bounded_entropy(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let remaining = u.len().min(MAX_ENTROPY_BYTES);
    Ok(u.bytes(remaining)?.to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::TestRng;

    /// Pin the drawn-config invariants: exactly one failure family arms per draw with a
    /// nonzero rate, and every mutation arm is reachable. A regression here would
    /// silently skew or disable fault injection in every recovery target's faulted pass.
    #[test]
    fn test_recovery_fault_config_draws() {
        let mut seen = [false; 4];
        for seed in 0..256u64 {
            let mut rng = TestRng::new(seed);
            let config = recovery_fault_config(&mut rng);
            let write = config.write_rate.expect("write config must always be set");
            let families = [
                write.failure_rate != probability!(0, 1),
                config.sync_rate.is_some(),
                config.resize_rate.is_some(),
                config.remove_rate.is_some(),
            ];
            assert_eq!(
                families.iter().filter(|armed| **armed).count(),
                1,
                "exactly one failure family must arm per draw"
            );
            seen[families.iter().position(|armed| *armed).unwrap()] = true;
        }
        assert_eq!(seen, [true; 4], "every mutation arm must be reachable");
    }
}
