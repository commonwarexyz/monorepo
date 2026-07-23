#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::journal::{
    Error,
    contiguous::{
        Contiguous, Many, Mutable as _,
        fixed::{Config as JournalConfig, Journal},
    },
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::{StreamExt, pin_mut};
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

/// Generate a size for `init_at_size`, biased toward the `u64` boundary so the fuzzer reliably
/// exercises the successor-arithmetic overflow paths (e.g. `init_at_size(u64::MAX)` rejection and
/// appends that push the size to its representable limit).
fn boundary_size(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(match u.int_in_range(0..=4u8)? {
        0 => u64::MAX,
        1 => u64::MAX - 1,
        2 => u64::MAX - u.int_in_range(0..=64u64)?,
        3 => u.int_in_range(0..=256u64)?,
        _ => u64::arbitrary(u)?,
    })
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
        #[arbitrary(with = boundary_size)]
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

/// Reopen the journal, returning the recovered journal with its size and pruning
/// boundary. The errors this harness exercises reject before any mutation, so the
/// on-disk state is intact and recovery matches a restart.
async fn reopen(
    context: &deterministic::Context,
    cfg: &JournalConfig,
    restarts: &mut usize,
) -> (
    Journal<deterministic::Context, commonware_cryptography::sha256::Digest>,
    u64,
    u64,
) {
    let journal = Journal::init(
        context
            .child("journal")
            .with_attribute("instance", *restarts),
        cfg.clone(),
    )
    .await
    .unwrap();
    *restarts += 1;
    let size = journal.size();
    let start = journal.bounds().start;
    (journal, size, start)
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = JournalConfig {
            partition: "fixed-journal-operations-fuzz-test".into(),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(MAX_WRITE_BUF),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        };

        let mut journal = Journal::init(context.child("storage"), cfg.clone())
            .await
            .unwrap();

        let mut next_value = 0u64;
        let mut journal_size = 0u64;
        let mut oldest_retained_pos = 0u64;
        let mut restarts = 0usize;

        for op in input.ops.iter() {
            journal = match op {
                JournalOperation::Append { value } => {
                    let digest = Sha256::hash(&[&value.to_be_bytes()]);
                    match journal.append(&digest).await {
                        Ok((journal, _pos)) => {
                            journal_size += 1;
                            journal
                        }
                        Err(Error::SizeOverflow) => {
                            let (journal, size, start) =
                                reopen(&context, &cfg, &mut restarts).await;
                            journal_size = size;
                            oldest_retained_pos = start;
                            journal
                        }
                        Err(e) => panic!("unexpected append error: {e:?}"),
                    }
                }

                JournalOperation::Read { pos } => {
                    let bounds = journal.bounds();
                    if bounds.contains(pos) {
                        journal.read(*pos).await.unwrap();
                    }
                    journal
                }

                JournalOperation::ReadMany { positions } => {
                    let bounds = journal.bounds();
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
                        let batch = journal.read_many(&mapped).await.unwrap();
                        assert_eq!(batch.len(), mapped.len());
                        // Cross-check against individual reads
                        for (i, &pos) in mapped.iter().enumerate() {
                            let single = journal.read(pos).await.unwrap();
                            assert_eq!(batch[i], single);
                        }
                    }
                    journal
                }

                JournalOperation::Size => {
                    assert_eq!(journal_size, journal.size(), "unexpected size");
                    journal
                }

                JournalOperation::Sync => journal.sync().await.unwrap(),

                JournalOperation::Rewind { size } => {
                    if *size <= journal_size && *size >= oldest_retained_pos {
                        let journal = journal.rewind(*size).await.unwrap().sync().await.unwrap();
                        journal_size = *size;
                        oldest_retained_pos = journal.bounds().start;
                        journal
                    } else {
                        journal
                    }
                }

                JournalOperation::Bounds => {
                    let _bounds = journal.bounds();
                    journal
                }

                JournalOperation::Prune { min_pos } => {
                    if *min_pos <= journal_size {
                        let (journal, _) = journal.prune(*min_pos).await.unwrap();
                        oldest_retained_pos = journal.bounds().start;
                        journal
                    } else {
                        journal
                    }
                }

                JournalOperation::Replay { buffer, start_pos } => {
                    let bounds = journal.bounds();
                    let start_pos = bounds.start + (*start_pos % (bounds.end - bounds.start + 1));
                    match journal.replay(start_pos, NZUsize!(*buffer)).await {
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
                    journal
                }

                JournalOperation::Restart => {
                    drop(journal);
                    let (journal, size, start) = reopen(&context, &cfg, &mut restarts).await;
                    journal_size = size;
                    oldest_retained_pos = start;
                    journal
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
                        let (journal, size, start) = reopen(&context, &cfg, &mut restarts).await;
                        journal_size = size;
                        oldest_retained_pos = start;
                        journal
                    } else {
                        let items: Vec<_> = (0..*count)
                            .map(|_| {
                                let d = Sha256::hash(&[&next_value.to_be_bytes()]);
                                next_value += 1;
                                d
                            })
                            .collect();
                        match journal.append_many(Many::Flat(&items)).await {
                            Ok((journal, _)) => {
                                journal_size += *count as u64;
                                journal
                            }
                            Err(Error::SizeOverflow) => {
                                let (journal, size, start) =
                                    reopen(&context, &cfg, &mut restarts).await;
                                journal_size = size;
                                oldest_retained_pos = start;
                                journal
                            }
                            Err(e) => panic!("unexpected append_many error: {e:?}"),
                        }
                    }
                }

                JournalOperation::MultipleSync => {
                    let journal = journal.sync().await.unwrap();
                    let journal = journal.sync().await.unwrap();
                    journal.sync().await.unwrap()
                }

                JournalOperation::AppendNested { count_a, count_b } => {
                    if *count_a == 0 && *count_b == 0 {
                        let err = journal.append_many(Many::Nested(&[&[], &[]])).await;
                        assert!(matches!(err, Err(Error::EmptyAppend)));
                        let (journal, size, start) = reopen(&context, &cfg, &mut restarts).await;
                        journal_size = size;
                        oldest_retained_pos = start;
                        journal
                    } else {
                        let items_a: Vec<_> = (0..*count_a)
                            .map(|_| {
                                let d = Sha256::hash(&[&next_value.to_be_bytes()]);
                                next_value += 1;
                                d
                            })
                            .collect();
                        let items_b: Vec<_> = (0..*count_b)
                            .map(|_| {
                                let d = Sha256::hash(&[&next_value.to_be_bytes()]);
                                next_value += 1;
                                d
                            })
                            .collect();
                        let slices: &[&[_]] = &[&items_a, &items_b];
                        match journal.append_many(Many::Nested(slices)).await {
                            Ok((journal, _)) => {
                                journal_size += *count_a as u64 + *count_b as u64;
                                journal
                            }
                            Err(Error::SizeOverflow) => {
                                let (journal, size, start) =
                                    reopen(&context, &cfg, &mut restarts).await;
                                journal_size = size;
                                oldest_retained_pos = start;
                                journal
                            }
                            Err(e) => panic!("unexpected append_many error: {e:?}"),
                        }
                    }
                }

                JournalOperation::RewindTo { keep_value } => {
                    if journal_size > oldest_retained_pos {
                        let target = Sha256::hash(&[&keep_value.to_be_bytes()]);
                        let (journal, new_size) =
                            journal.rewind_to(|item| *item == target).await.unwrap();
                        let journal = journal.sync().await.unwrap();
                        journal_size = new_size;
                        oldest_retained_pos = journal.bounds().start;
                        journal
                    } else {
                        journal
                    }
                }

                JournalOperation::TryReadSync { pos } => {
                    let bounds = journal.bounds();
                    if bounds.contains(pos) {
                        // Cross-check: sync result must match async result
                        if let Some(sync_val) = journal.try_read_sync(*pos) {
                            let async_val = journal.read(*pos).await.unwrap();
                            assert_eq!(sync_val, async_val);
                        }
                    }
                    journal
                }

                JournalOperation::PruningBoundary => {
                    assert_eq!(journal.pruning_boundary(), oldest_retained_pos);
                    journal
                }

                JournalOperation::InitAtSize { size } => {
                    drop(journal);
                    let attempt = context
                        .child("journal")
                        .with_attribute("instance", restarts);
                    restarts += 1;
                    let journal = match Journal::init_at_size(attempt, cfg.clone(), *size).await {
                        Ok(journal) => journal,
                        // `u64::MAX` is rejected (no append could ever succeed) before any reset
                        // is staged, so the prior on-disk state is intact. Reopen it to continue.
                        Err(Error::SizeOverflow) => {
                            let (journal, _, _) = reopen(&context, &cfg, &mut restarts).await;
                            journal
                        }
                        Err(e) => panic!("unexpected init_at_size error: {e:?}"),
                    };
                    journal_size = journal.size();
                    oldest_retained_pos = journal.bounds().start;
                    journal
                }
            };
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
