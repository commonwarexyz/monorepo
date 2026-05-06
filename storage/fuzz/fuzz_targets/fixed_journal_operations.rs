#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_storage::journal::{
    contiguous::{
        fixed::{Config as JournalConfig, Journal},
        Many, Mutable as _, Reader,
    },
    Error,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use futures::{pin_mut, StreamExt};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_REPLAY_BUF: usize = 2048;
const MAX_WRITE_BUF: usize = 2048;
const MAX_OPERATIONS: usize = 50;
const MAX_APPEND_MANY: u8 = 20;
const MAX_READ_MANY: usize = 16;

fn bounded_non_zero(u: &mut Unstructured<'_>) -> Result<usize> {
    let v = u.int_in_range(1..=MAX_REPLAY_BUF)?;
    Ok(v)
}

fn bounded_append_count(u: &mut Unstructured<'_>) -> Result<u8> {
    u.int_in_range(0..=MAX_APPEND_MANY)
}

fn bounded_positions(u: &mut Unstructured<'_>) -> Result<Vec<u64>> {
    let len = u.int_in_range(0..=MAX_READ_MANY)?;
    (0..len).map(|_| u64::arbitrary(u)).collect()
}

#[derive(Arbitrary, Debug, Clone)]
enum JournalOperation {
    Append {
        value: u64,
    },
    Read {
        pos: u64,
    },
    Size,
    Sync,
    Rewind {
        size: u64,
    },
    Bounds,
    Prune {
        min_pos: u64,
    },
    Replay {
        #[arbitrary(with = bounded_non_zero)]
        buffer: usize,
        start_pos: u64,
    },
    Restart,
    Destroy,
    ReadMany {
        #[arbitrary(with = bounded_positions)]
        positions: Vec<u64>,
    },
    AppendMany {
        #[arbitrary(with = bounded_append_count)]
        count: u8,
    },
    AppendNested {
        #[arbitrary(with = bounded_append_count)]
        count_a: u8,
        #[arbitrary(with = bounded_append_count)]
        count_b: u8,
    },
    RewindTo {
        keep_value: u64,
    },
    MultipleSync,
    TryReadSync {
        pos: u64,
    },
    PruningBoundary,
    InitAtSize {
        size: u64,
    },
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<JournalOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| JournalOperation::arbitrary(u))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(57);
const PAGE_CACHE_SIZE: usize = 1;

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = JournalConfig {
            partition: "fixed-journal-operations-fuzz-test".into(),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(MAX_WRITE_BUF),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        };

        let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

        let mut next_value = 0u64;
        let mut journal_size = 0u64;
        let mut oldest_retained_pos = 0u64;
        let mut restarts = 0usize;

        for op in input.ops.iter() {
            match op {
                JournalOperation::Append { value } => {
                    let digest = Sha256::hash(&value.to_be_bytes());
                    let _pos = journal.append(&digest).await.unwrap();
                    journal_size += 1;
                }

                JournalOperation::Read { pos } => {
                    let bounds = journal.bounds();
                    if bounds.contains(pos) {
                        journal.read(*pos).await.unwrap();
                    }
                }

                JournalOperation::ReadMany { positions } => {
                    let reader = journal.reader();
                    let bounds = reader.bounds();
                    // Map fuzz positions into valid, sorted, deduplicated positions
                    let mut mapped: Vec<u64> = positions
                        .iter()
                        .filter_map(|p| {
                            if bounds.is_empty() {
                                return None;
                            }
                            let len = bounds.end - bounds.start;
                            Some(bounds.start + (*p % len))
                        })
                        .collect();
                    mapped.sort_unstable();
                    mapped.dedup();
                    if !mapped.is_empty() {
                        let batch = reader.read_many(&mapped).await.unwrap();
                        assert_eq!(batch.len(), mapped.len());
                        // Cross-check against individual reads
                        for (i, &pos) in mapped.iter().enumerate() {
                            let single = reader.read(pos).await.unwrap();
                            assert_eq!(batch[i], single);
                        }
                    }
                }

                JournalOperation::Size => {
                    let size = journal.size();
                    assert_eq!(journal_size, size, "unexpected size");
                }

                JournalOperation::Sync => {
                    journal.sync().await.unwrap();
                }

                JournalOperation::Rewind { size } => {
                    if *size <= journal_size && *size >= oldest_retained_pos {
                        journal.rewind(*size).await.unwrap();
                        journal.sync().await.unwrap();
                        journal_size = *size;
                        oldest_retained_pos = journal.bounds().start;
                    }
                }

                JournalOperation::Bounds => {
                    let _bounds = journal.bounds();
                }

                JournalOperation::Prune { min_pos } => {
                    if *min_pos <= journal_size {
                        journal.prune(*min_pos).await.unwrap();
                        oldest_retained_pos = journal.bounds().start;
                    }
                }

                JournalOperation::Replay { buffer, start_pos } => {
                    let bounds = journal.bounds();
                    let start_pos = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                    let replay = journal.replay(NZUsize!(*buffer), start_pos).await;

                    match replay {
                        Ok(stream) => {
                            pin_mut!(stream);
                            // Consume first few items to test stream - panic on stream errors
                            for _ in 0..3 {
                                match stream.next().await {
                                    Some(result) => {
                                        result.unwrap();
                                    }
                                    None => break,
                                }
                            }
                        }
                        Err(e) => panic!("unexpected replay error: {e:?}"),
                    }
                }

                JournalOperation::Restart => {
                    drop(journal);
                    journal = Journal::init(
                        context
                            .with_label("journal")
                            .with_attribute("instance", restarts),
                        cfg.clone(),
                    )
                    .await
                    .unwrap();
                    restarts += 1;
                    // Reset tracking variables to match recovered state
                    journal_size = journal.size();
                    oldest_retained_pos = journal.bounds().start;
                }

                JournalOperation::Destroy => {
                    journal.destroy().await.unwrap();
                    return;
                }

                JournalOperation::AppendMany { count } => {
                    if *count == 0 {
                        // Exercise the EmptyAppend error path
                        let err = journal.append_many(Many::Flat(&[])).await;
                        assert!(matches!(err, Err(Error::EmptyAppend)));
                    } else {
                        let items: Vec<_> = (0..*count)
                            .map(|_| {
                                let d = Sha256::hash(&next_value.to_be_bytes());
                                next_value += 1;
                                d
                            })
                            .collect();
                        journal.append_many(Many::Flat(&items)).await.unwrap();
                        journal_size += *count as u64;
                    }
                }

                JournalOperation::MultipleSync => {
                    journal.sync().await.unwrap();
                    journal.sync().await.unwrap();
                    journal.sync().await.unwrap();
                }

                JournalOperation::AppendNested { count_a, count_b } => {
                    if *count_a == 0 && *count_b == 0 {
                        let err = journal.append_many(Many::Nested(&[&[], &[]])).await;
                        assert!(matches!(err, Err(Error::EmptyAppend)));
                    } else {
                        let items_a: Vec<_> = (0..*count_a)
                            .map(|_| {
                                let d = Sha256::hash(&next_value.to_be_bytes());
                                next_value += 1;
                                d
                            })
                            .collect();
                        let items_b: Vec<_> = (0..*count_b)
                            .map(|_| {
                                let d = Sha256::hash(&next_value.to_be_bytes());
                                next_value += 1;
                                d
                            })
                            .collect();
                        let slices: &[&[_]] = &[&items_a, &items_b];
                        journal.append_many(Many::Nested(slices)).await.unwrap();
                        journal_size += *count_a as u64 + *count_b as u64;
                    }
                }

                JournalOperation::RewindTo { keep_value } => {
                    if journal_size > oldest_retained_pos {
                        let target = Sha256::hash(&keep_value.to_be_bytes());
                        let new_size = journal.rewind_to(|item| *item == target).await.unwrap();
                        journal.sync().await.unwrap();
                        journal_size = new_size;
                        oldest_retained_pos = journal.reader().bounds().start;
                    }
                }

                JournalOperation::TryReadSync { pos } => {
                    let reader = journal.reader();
                    let bounds = reader.bounds();
                    if bounds.contains(pos) {
                        // Cross-check: sync result must match async result
                        if let Some(sync_val) = reader.try_read_sync(*pos) {
                            let async_val = reader.read(*pos).await.unwrap();
                            assert_eq!(sync_val, async_val);
                        }
                    }
                }

                JournalOperation::PruningBoundary => {
                    let boundary = journal.pruning_boundary();
                    assert_eq!(boundary, oldest_retained_pos);
                }

                JournalOperation::InitAtSize { size } => {
                    // Cap to avoid excessive memory use
                    let target_size = *size % 256;
                    drop(journal);
                    journal = Journal::init_at_size(
                        context
                            .with_label("journal")
                            .with_attribute("instance", restarts),
                        cfg.clone(),
                        target_size,
                    )
                    .await
                    .unwrap();
                    restarts += 1;
                    journal_size = journal.size();
                    oldest_retained_pos = journal.reader().bounds().start;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
