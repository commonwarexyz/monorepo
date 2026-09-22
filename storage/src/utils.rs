//! Utilities for storage tests and fuzz targets.

#[cfg(test)]
pub(crate) mod codec;
#[cfg(test)]
pub(crate) mod detached;

#[cfg(test)]
use commonware_runtime::{BufferPoolConfig, BufferPooler, Metrics, iobuf::PoolError};
use commonware_utils::bitmap::BitMap;
#[cfg(test)]
use commonware_utils::{NZU32, NZUsize};
use std::{collections::BTreeMap, num::NonZeroU64};

#[cfg(test)]
pub(crate) const RESOURCE_TEST_PAGE_SIZE: usize = 4096;
#[cfg(test)]
const RESOURCE_TEST_POOL_SLOTS: u32 = 64;

/// Configure enough tracked slots that the resource workloads cannot silently fall back to
/// untracked allocations before their live backing is measured.
#[cfg(test)]
pub(crate) fn resource_test_pool_config() -> BufferPoolConfig {
    BufferPoolConfig::for_storage()
        .with_size_class_range(
            NZUsize!(RESOURCE_TEST_PAGE_SIZE),
            NZUsize!(64 * RESOURCE_TEST_PAGE_SIZE),
            NZU32!(RESOURCE_TEST_POOL_SLOTS),
        )
        .with_pool_min_size(0)
        .with_alignment(NZUsize!(RESOURCE_TEST_PAGE_SIZE))
        .with_thread_cache_disabled()
}

/// Measure live pooled backing by exhausting every configured size class while its probe leases
/// remain held. Deliberate native allocations are outside this measurement.
///
/// Capture `previous_metrics` before the workload. Each measurement advances it past the probe's
/// own exhaustion events so later measurements check only intervening workload allocations.
#[cfg(test)]
pub(crate) fn pooled_bytes_in_use(
    context: &(impl BufferPooler + Metrics),
    previous_metrics: &mut String,
) -> usize {
    fn metric(metrics: &str, name: &str) -> Option<u64> {
        metrics.lines().find_map(|line| {
            let (label, value) = line.split_once(' ')?;
            (label == name).then(|| value.parse().expect("invalid buffer pool metric"))
        })
    }

    let pool = context.storage_buffer_pool();
    let classes = pool.config().size_classes().collect::<Vec<_>>();
    let metrics = context.encode();
    let oversized = "runtime_storage_buffer_pool_buffer_pool_oversized_total";
    assert_eq!(
        metric(&metrics, oversized).expect("missing oversized allocation metric"),
        metric(previous_metrics, oversized).expect("missing oversized allocation baseline"),
        "oversized allocations must not hide live pooled backing"
    );
    for class in &classes {
        let size = class.size.get();
        let exhausted = format!(
            "runtime_storage_buffer_pool_buffer_pool_exhausted_total{{size_class=\"{size}\"}}"
        );
        assert_eq!(
            metric(&metrics, &exhausted).unwrap_or(0),
            metric(previous_metrics, &exhausted).unwrap_or(0),
            "pool exhaustion must not hide live pooled backing for class {size}"
        );
    }

    let live_bytes = classes
        .into_iter()
        .map(|class| {
            let size = class.size.get();
            let max_buffers = class.max_buffers.get() as usize;
            let mut free_leases = Vec::with_capacity(max_buffers);
            let mut exhausted = false;
            for _ in 0..=max_buffers {
                match pool.try_alloc(size) {
                    Ok(lease) => free_leases.push(lease),
                    Err(PoolError::Exhausted) => {
                        exhausted = true;
                        break;
                    }
                    Err(err) => panic!("configured size class {size} rejected probe: {err}"),
                }
            }
            assert!(exhausted, "configured size class {size} did not exhaust");
            let live_slots = max_buffers - free_leases.len();
            live_slots * size
        })
        .sum();
    *previous_metrics = context.encode();
    live_bytes
}

/// Build ordinal recovery bitmaps from absolute item indices.
///
/// Each index maps to blob `index / items_per_blob` and sets bit
/// `index % items_per_blob` in that blob's bitmap of `items_per_blob` bits.
pub fn bits_for_indices<const N: usize>(
    items_per_blob: NonZeroU64,
    indices: impl IntoIterator<Item = u64>,
) -> BTreeMap<u64, Option<BitMap<N>>> {
    let items_per_blob = items_per_blob.get();
    let mut bits = BTreeMap::new();
    for index in indices {
        let blob = index / items_per_blob;
        let offset = index % items_per_blob;
        bits.entry(blob)
            .or_insert_with(|| Some(BitMap::zeroes(items_per_blob)))
            .as_mut()
            .unwrap()
            .set(offset, true);
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZU64;

    #[test]
    fn test_pooled_bytes_in_use_repeated() {
        let config = deterministic::Config::default().with_storage_buffer_pool_config(
            resource_test_pool_config().with_max_per_class(NZU32!(2)),
        );
        deterministic::Runner::new(config).start(move |context| async move {
            let mut metrics = context.encode();
            let pool = context.storage_buffer_pool();
            let first = pool.alloc(RESOURCE_TEST_PAGE_SIZE);
            let second = pool.alloc(2 * RESOURCE_TEST_PAGE_SIZE);
            assert_eq!(
                pooled_bytes_in_use(&context, &mut metrics),
                3 * RESOURCE_TEST_PAGE_SIZE
            );
            assert_eq!(
                pooled_bytes_in_use(&context, &mut metrics),
                3 * RESOURCE_TEST_PAGE_SIZE
            );
            drop((first, second));
            assert_eq!(pooled_bytes_in_use(&context, &mut metrics), 0);
        });
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[should_panic(expected = "pool exhaustion must not hide live pooled backing")]
    fn test_pooled_bytes_in_use_rejects_exhaustion(#[case] measured_before: bool) {
        let config = deterministic::Config::default().with_storage_buffer_pool_config(
            resource_test_pool_config().with_max_per_class(NZU32!(1)),
        );
        deterministic::Runner::new(config).start(move |context| async move {
            let mut metrics = context.encode();
            if measured_before {
                assert_eq!(pooled_bytes_in_use(&context, &mut metrics), 0);
            }
            let pool = context.storage_buffer_pool();
            let pooled = pool.alloc(RESOURCE_TEST_PAGE_SIZE);
            let fallback = pool.alloc(RESOURCE_TEST_PAGE_SIZE);
            pooled_bytes_in_use(&context, &mut metrics);
            drop((pooled, fallback));
        });
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[should_panic(expected = "oversized allocations must not hide live pooled backing")]
    fn test_pooled_bytes_in_use_rejects_oversized(#[case] measured_before: bool) {
        let config = deterministic::Config::default()
            .with_storage_buffer_pool_config(resource_test_pool_config());
        deterministic::Runner::new(config).start(move |context| async move {
            let mut metrics = context.encode();
            if measured_before {
                assert_eq!(pooled_bytes_in_use(&context, &mut metrics), 0);
            }
            let pool = context.storage_buffer_pool();
            let fallback = pool.alloc(pool.config().max_size().get() + 1);
            pooled_bytes_in_use(&context, &mut metrics);
            drop(fallback);
        });
    }

    #[test]
    fn test_bits_for_indices() {
        let empty = bits_for_indices::<1>(NZU64!(10), core::iter::empty());
        assert!(empty.is_empty());

        let bits = bits_for_indices::<1>(NZU64!(10), [0, 1, 9, 10, 25]);
        assert_eq!(bits.len(), 3);

        let blob_0 = bits.get(&0).unwrap().as_ref().unwrap();
        assert_eq!(blob_0.len(), 10);
        assert_eq!(blob_0.count_ones(), 3);
        assert!(blob_0.get(0));
        assert!(blob_0.get(1));
        assert!(blob_0.get(9));

        let blob_1 = bits.get(&1).unwrap().as_ref().unwrap();
        assert_eq!(blob_1.len(), 10);
        assert_eq!(blob_1.count_ones(), 1);
        assert!(blob_1.get(0));

        let blob_2 = bits.get(&2).unwrap().as_ref().unwrap();
        assert_eq!(blob_2.len(), 10);
        assert_eq!(blob_2.count_ones(), 1);
        assert!(blob_2.get(5));
    }
}
