//! Shared input generators and crash-recovery flows for storage fuzz targets.

use arbitrary::Unstructured;
use commonware_runtime::{
    deterministic::{self, PartialWriteMode},
    mocks::PendingSyncs,
};
use commonware_utils::{Probability, TestRng, probability};
use rand::{Rng as _, RngExt as _};
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

fn recovery_fault_config(seed: u64) -> deterministic::FaultConfig {
    let selectors = seed.to_le_bytes();
    let mutation = selectors[0] & 0x03;
    let failure_rate = Probability::new(u64::from(selectors[1] % 100) + 1, 100)
        .expect("a percentage in 1..=100 is valid");
    let rate = |selector: u8| {
        Probability::new(u64::from(selector) % 101, 100).expect("a percentage in 0..=100 is valid")
    };
    let mut config = deterministic::FaultConfig {
        write_rate: Some(deterministic::WriteConfig {
            failure_rate: if mutation == 0 {
                failure_rate
            } else {
                probability!(0, 1)
            },
            retention_rate: rate(selectors[2]),
            mode: if selectors[4] & 1 == 0 {
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
                partial_rate: rate(selectors[3]),
            });
        }
        3 => config.remove_rate = Some(failure_rate),
        _ => unreachable!("two bits select one of four mutations"),
    }
    config
}

/// Run a chain of 1..=4 recovery attempts, each with a mutable storage fault enabled and
/// each crashing into the next, then return the final crash image.
///
/// `fault_seed` seeds an rng that draws the chain depth and a fresh fault selector per
/// attempt (mutation, failure and retention rates, and partial-write mode). Chaining
/// interrupts the recovery of an already-interrupted recovery, so images reachable only
/// through repeated repair interruption are also explored.
///
/// Each attempt's recovered object or error is discarded because mutable-operation errors
/// retire the instance. The fault config is cleared before each crash (retention policies
/// bind when a write is issued), so the returned checkpoint recovers fault-free.
pub fn faulted_recovery<F, Fut, T, E>(
    mut checkpoint: deterministic::Checkpoint,
    fault_seed: u64,
    recover: F,
) -> deterministic::Checkpoint
where
    F: Fn(deterministic::Context) -> Fut + Clone,
    Fut: Future<Output = Result<T, E>>,
{
    let mut rng = TestRng::new(fault_seed);
    let depth = rng.random_range(1..=4);
    for _ in 0..depth {
        let seed = rng.next_u64();
        let recover = recover.clone();
        let (_, next) =
            deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
                let config = context.storage_fault_config();
                *config.write() = recovery_fault_config(seed);
                drop(recover(context).await);
                *config.write() = deterministic::FaultConfig::default();
            });
        checkpoint = next;
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::deterministic::PartialWriteMode;

    /// Build a fault seed from the selector bytes the decoder consumes.
    fn seed(mutation: u8, failure: u8, retention: u8, partial: u8, mode: u8) -> u64 {
        u64::from_le_bytes([mutation, failure, retention, partial, mode, 0, 0, 0])
    }

    /// Pin the seed-to-config decoding: a regression here would silently skew or
    /// disable fault injection in every recovery target's faulted pass.
    #[test]
    fn test_recovery_fault_config_decoding() {
        // Mutation 0 injects write failures with the selected retention and mode.
        let config = recovery_fault_config(seed(0, 49, 25, 0, 0));
        let write = config.write_rate.unwrap();
        assert_eq!(write.failure_rate, probability!(50, 100));
        assert_eq!(write.retention_rate, probability!(25, 100));
        assert_eq!(write.mode, PartialWriteMode::Prefix);
        assert!(config.sync_rate.is_none());
        assert!(config.resize_rate.is_none());
        assert!(config.remove_rate.is_none());

        // Mutations 1..=3 zero the write failure rate but keep crash retention and
        // mode, routing the failure rate to sync, resize, or remove respectively.
        let config = recovery_fault_config(seed(1, 99, 100, 0, 1));
        let write = config.write_rate.unwrap();
        assert_eq!(write.failure_rate, probability!(0, 1));
        assert_eq!(write.retention_rate, probability!(100, 100));
        assert_eq!(write.mode, PartialWriteMode::Subset);
        assert_eq!(config.sync_rate, Some(probability!(100, 100)));
        assert!(config.resize_rate.is_none());
        assert!(config.remove_rate.is_none());

        let config = recovery_fault_config(seed(2, 0, 0, 75, 0));
        let resize = config.resize_rate.unwrap();
        assert_eq!(resize.failure_rate, probability!(1, 100));
        assert_eq!(resize.partial_rate, probability!(75, 100));
        assert_eq!(config.write_rate.unwrap().failure_rate, probability!(0, 1));
        assert!(config.sync_rate.is_none());
        assert!(config.remove_rate.is_none());

        let config = recovery_fault_config(seed(3, 199, 0, 0, 0));
        assert_eq!(config.remove_rate, Some(probability!(100, 100)));
        assert!(config.sync_rate.is_none());
        assert!(config.resize_rate.is_none());

        // Selector bits above the two-bit mutation mask are ignored.
        let config = recovery_fault_config(seed(0x04, 0, 0, 0, 0));
        assert_eq!(
            config.write_rate.unwrap().failure_rate,
            probability!(1, 100)
        );
    }
}
