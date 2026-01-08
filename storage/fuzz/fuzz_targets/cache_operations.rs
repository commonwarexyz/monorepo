#![no_main]

use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::cache::{Cache, Config};
use commonware_utils::{NZUsize, NZU64};
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeMap, num::NonZeroU16};

const MAX_OPERATIONS: usize = 50;
const MAX_INDEX: u64 = 10000;
const MAX_VALUE: u32 = 1000000;
const MIN_ITEMS_PER_BLOB: u64 = 256;
const MAX_ITEMS_PER_BLOB: u64 = 2048;
const MIN_WRITE_BUFFER: usize = 256;
const MAX_WRITE_BUFFER: usize = 4 * 1024 * 1024;
const MIN_REPLAY_BUFFER: usize = 256;
const MAX_REPLAY_BUFFER: usize = 2 * 8192;
const MIN_COMPRESSION_LEVEL: u8 = 1;
const MAX_COMPRESSION_LEVEL: u8 = 21;
const MIN_BUFFER_POOL_PAGE_SIZE: u16 = 511;
const MAX_BUFFER_POOL_PAGE_SIZE: u16 = 4097;
const MIN_BUFFER_POOL_CAPACITY: usize = 10;
const MAX_BUFFER_POOL_CAPACITY: usize = 64;

#[derive(Clone, Debug)]
enum Operation {
    Put { index: u64, value: u32 },
    Get { index: u64 },
    Has { index: u64 },
    First,
    NextGap { from: u64 },
    MissingItems { from: u64, limit: usize },
    Sync,
    Prune { min: u64 },
    Reinit,
}

#[derive(Clone, Debug)]
struct CacheConfig {
    items_per_blob: u64,
    write_buffer: usize,
    replay_buffer: usize,
    compression: Option<u8>,
    buffer_pool_pages_size: NonZeroU16,
    buffer_pool_capacity: usize,
}

#[derive(Clone, Debug)]
struct FuzzInput {
    seed: u64,
    config: CacheConfig,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        let seed = u64::arbitrary(u)?;

        let items_per_blob =
            (u16::arbitrary(u)? as u64 % MAX_ITEMS_PER_BLOB).max(MIN_ITEMS_PER_BLOB);
        let write_buffer = (u16::arbitrary(u)? as usize % MAX_WRITE_BUFFER).max(MIN_WRITE_BUFFER);
        let replay_buffer =
            (u16::arbitrary(u)? as usize % MAX_REPLAY_BUFFER).max(MIN_REPLAY_BUFFER);
        let compression = if bool::arbitrary(u)? {
            Some(u.int_in_range(MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL)?)
        } else {
            None
        };
        let buffer_pool_pages_size =
            NonZeroU16::new(u.int_in_range(MIN_BUFFER_POOL_PAGE_SIZE..=MAX_BUFFER_POOL_PAGE_SIZE)?)
                .unwrap();
        let buffer_pool_capacity =
            u.int_in_range(MIN_BUFFER_POOL_CAPACITY..=MAX_BUFFER_POOL_CAPACITY)?;

        let config = CacheConfig {
            items_per_blob,
            write_buffer,
            replay_buffer,
            compression,
            buffer_pool_capacity,
            buffer_pool_pages_size,
        };

        let num_operations = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_operations);

        for _ in 0..num_operations {
            let op = match u8::arbitrary(u)? % 9 {
                0 => Operation::Put {
                    index: u64::arbitrary(u)? % MAX_INDEX,
                    value: u32::arbitrary(u)? % MAX_VALUE,
                },
                1 => Operation::Get {
                    index: u64::arbitrary(u)? % MAX_INDEX,
                },
                2 => Operation::Has {
                    index: u64::arbitrary(u)? % MAX_INDEX,
                },
                3 => Operation::First,
                4 => Operation::NextGap {
                    from: u64::arbitrary(u)? % MAX_INDEX,
                },
                5 => Operation::MissingItems {
                    from: u64::arbitrary(u)? % MAX_INDEX,
                    limit: (u8::arbitrary(u)? as usize % 100) + 1,
                },
                6 => Operation::Sync,
                7 => Operation::Prune {
                    min: u64::arbitrary(u)? % MAX_INDEX,
                },
                _ => Operation::Reinit,
            };
            operations.push(op);
        }

        Ok(FuzzInput {
            seed,
            config,
            operations,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let _rng = StdRng::seed_from_u64(input.seed);

    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let cfg = Config {
            partition: "fuzz_cache".into(),
            codec_config: (),
            compression: input.config.compression,
            write_buffer: NZUsize!(input.config.write_buffer),
            replay_buffer: NZUsize!(input.config.replay_buffer),
            items_per_blob: NZU64!(input.config.items_per_blob),
            buffer_pool: PoolRef::new(
                input.config.buffer_pool_pages_size,
                NZUsize!(input.config.buffer_pool_capacity),
            ),
        };

        let mut cache_opt = Some(
            Cache::<_, u32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize cache"),
        );

        let mut expected_data = BTreeMap::new();
        let mut pruned_min: Option<u64> = None;

        for op in input.operations {
            match op {
                Operation::Put { index, value } => {
                    if let Some(ref mut cache) = cache_opt {
                        let result = cache.put(index, value).await;
                        if result.is_ok() {
                            // Cache put only inserts if index doesn't already exist
                            // Only update expected_data if this is a new index
                            expected_data.entry(index).or_insert(value);
                        }
                    }
                }

                Operation::Get { index } => {
                    if let Some(ref cache) = cache_opt {
                        let result = cache.get(index).await.expect("Get should not error");

                        let section =
                            (index / input.config.items_per_blob) * input.config.items_per_blob;
                        let not_pruned = pruned_min.is_none_or(|min| section >= min);
                        let should_exist = not_pruned && expected_data.contains_key(&index);

                        if should_exist {
                            assert_eq!(result, expected_data.get(&index).cloned());
                        } else {
                            assert_eq!(result, None);
                        }
                    }
                }

                Operation::Has { index } => {
                    if let Some(ref cache) = cache_opt {
                        let has = cache.has(index);

                        let section =
                            (index / input.config.items_per_blob) * input.config.items_per_blob;
                        let not_pruned = pruned_min.is_none_or(|min| section >= min);
                        let should_exist = not_pruned && expected_data.contains_key(&index);

                        assert_eq!(has, should_exist);
                    }
                }

                Operation::First => {
                    if let Some(ref cache) = cache_opt {
                        let first = cache.first();

                        let expected_first = expected_data
                            .keys()
                            .filter(|&&k| {
                                pruned_min.is_none_or(|min| {
                                    let section = (k / input.config.items_per_blob)
                                        * input.config.items_per_blob;
                                    section >= min
                                })
                            })
                            .min()
                            .cloned();

                        assert_eq!(first, expected_first);
                    }
                }

                Operation::NextGap { from } => {
                    if let Some(ref cache) = cache_opt {
                        let (current_end, start_next) = cache.next_gap(from);
                        if let Some(current_end) = current_end {
                            assert!(expected_data.contains_key(&current_end));
                        }
                        if let Some(start_next) = start_next {
                            assert!(expected_data.contains_key(&start_next));
                        }
                    }
                }

                Operation::MissingItems { from, limit } => {
                    if let Some(ref cache) = cache_opt {
                        let missing = cache.missing_items(from, limit);
                        assert!(missing.len() <= limit);

                        for &item in &missing {
                            assert!(item >= from);
                        }
                    }
                }

                Operation::Sync => {
                    if let Some(ref mut cache) = cache_opt {
                        cache.sync().await.expect("Sync should not error");
                    }
                }

                Operation::Prune { min } => {
                    if let Some(ref mut cache) = cache_opt {
                        cache.prune(min).await.expect("Prune should not error");

                        let section_min =
                            (min / input.config.items_per_blob) * input.config.items_per_blob;
                        pruned_min =
                            Some(pruned_min.map_or(section_min, |old| old.max(section_min)));

                        expected_data.retain(|&k, _| {
                            let section =
                                (k / input.config.items_per_blob) * input.config.items_per_blob;
                            section >= pruned_min.unwrap()
                        });
                    }
                }

                Operation::Reinit => {
                    if cache_opt.is_none() {
                        let cache = Cache::<_, u32>::init(context.clone(), cfg.clone())
                            .await
                            .expect("Failed to reinitialize cache");

                        pruned_min = None;
                        cache_opt = Some(cache);
                    }
                }
            }
        }

        if let Some(mut cache) = cache_opt {
            cache.sync().await.ok();
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
