#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_storage::journal::contiguous::fixed::{Config as JournalConfig, Journal};
use commonware_utils::{NZUsize, NZU16, NZU64};
use futures::{pin_mut, StreamExt};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_REPLAY_BUF: usize = 2048;
const MAX_WRITE_BUF: usize = 2048;

fn bounded_non_zero(u: &mut Unstructured<'_>) -> Result<usize> {
    let v = u.int_in_range(1..=MAX_REPLAY_BUF)?;
    Ok(v)
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
    OldestRetainedPos,
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
    AppendMany {
        count: u8,
    },
    MultipleSync,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<JournalOperation>,
}

const PAGE_SIZE: NonZeroU16 = NZU16!(57);
const PAGE_CACHE_SIZE: usize = 1;

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = JournalConfig {
            partition: "fixed_journal_operations_fuzz_test".to_string(),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(MAX_WRITE_BUF),
            page_cache: CacheRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        };

        let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

        let mut next_value = 0u64;
        let mut journal_size = 0u64;
        let mut oldest_retained_pos = 0u64;
        let mut restarts = 0usize;

        for op in input.operations.iter() {
            match op {
                JournalOperation::Append { value } => {
                    let digest = Sha256::hash(&value.to_be_bytes());
                    let _pos = journal.append(digest).await.unwrap();
                    journal_size += 1;
                }

                JournalOperation::Read { pos } => {
                    if *pos >= oldest_retained_pos && *pos < journal_size {
                        journal.read(*pos).await.unwrap();
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
                    }
                }

                JournalOperation::OldestRetainedPos => {
                    let _pos = journal.oldest_retained_pos();
                }

                JournalOperation::Prune { min_pos } => {
                    if *min_pos <= journal_size {
                        journal.prune(*min_pos).await.unwrap();
                        oldest_retained_pos = oldest_retained_pos.max(*min_pos);
                    }
                }

                JournalOperation::Replay { buffer, start_pos } => {
                    let start_pos = *start_pos % (journal_size + 1);
                    match journal.replay(NZUsize!(*buffer), start_pos).await {
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
                    oldest_retained_pos = journal.oldest_retained_pos().unwrap_or(0);
                }

                JournalOperation::Destroy => {
                    journal.destroy().await.unwrap();
                    return;
                }

                JournalOperation::AppendMany { count } => {
                    for _ in 0..*count {
                        let digest = Sha256::hash(&next_value.to_be_bytes());
                        journal.append(digest).await.unwrap();
                        next_value += 1;
                        journal_size += 1;
                    }
                }

                JournalOperation::MultipleSync => {
                    journal.sync().await.unwrap();
                    journal.sync().await.unwrap();
                    journal.sync().await.unwrap();
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
