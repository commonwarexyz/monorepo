//! Shared input generators and crash-recovery flows for storage fuzz targets.

use arbitrary::Unstructured;
use commonware_runtime::deterministic::{self, PartialWriteMode};
use commonware_utils::{Probability, probability};
use std::future::Future;

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

/// Run one ordinary recovery attempt with a mutable storage fault enabled, then crash.
///
/// `fault_seed` selects the mutation, failure and retention rates, and partial-write mode.
///
/// The recovered object or error is discarded because mutable-operation errors retire the
/// instance. The returned checkpoint is suitable for a fault-free recovery and verification.
pub fn faulted_recovery<F, Fut, T, E>(
    checkpoint: deterministic::Checkpoint,
    fault_seed: u64,
    recover: F,
) -> deterministic::Checkpoint
where
    F: FnOnce(deterministic::Context) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            *context.storage_fault_config().write() = recovery_fault_config(fault_seed);
            drop(recover(context).await);
        });
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
