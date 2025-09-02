#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::journal::{
    fixed::{
        Config as FixedConfig, Config as VariableConfig, Journal as FixedJournal,
        Journal as VariableJournal,
    },
    Error,
};
use commonware_utils::{NZUsize, NZU64};
use futures::{pin_mut, StreamExt};
use libfuzzer_sys::fuzz_target;

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
    Close,
    Destroy,
    AppendMany {
        count: u8,
    },
    MultipleSync,
}

#[derive(Arbitrary, Debug)]
enum JournalType {
    Fixed,
    Variable,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<JournalOperation>,
    journal_type: JournalType,
}

const PAGE_SIZE: usize = 128;
const PAGE_CACHE_SIZE: usize = 1;

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = match input.journal_type {
            JournalType::Fixed => FixedConfig {
                partition: "fixed_journal_operations_fuzz_test".to_string(),
                items_per_blob: NZU64!(3),
                write_buffer: NZUsize!(MAX_WRITE_BUF),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            },
            JournalType::Variable => VariableConfig {
                partition: "variable_journal_operations_fuzz_test".to_string(),
                items_per_blob: NZU64!(3),
                write_buffer: NZUsize!(MAX_WRITE_BUF),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            },
        };

        let mut journal = match input.journal_type {
            JournalType::Fixed => FixedJournal::init(context.clone(), cfg).await.unwrap(),
            JournalType::Variable => VariableJournal::init(context.clone(), cfg).await.unwrap(),
        };

        let mut next_value = 0u64;
        let mut journal_size = 0u64;
        let mut oldest_retained_pos = 0u64;

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
                    let size = journal.size().await.unwrap();
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
                    let _pos = journal.oldest_retained_pos().await.unwrap();
                }

                JournalOperation::Prune { min_pos } => {
                    if *min_pos <= journal_size {
                        journal.prune(*min_pos).await.unwrap();
                        oldest_retained_pos = oldest_retained_pos.max(*min_pos);
                    }
                }

                JournalOperation::Replay { buffer, start_pos } => {
                    match journal.replay(NZUsize!(*buffer), *start_pos).await {
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
                        Err(Error::InvalidItem(pos)) => {
                            if pos != *start_pos {
                                panic!("invalid item error: expected {start_pos} found {pos}",);
                            }
                        }
                        Err(e) => panic!("unexpected replay error: {e:?}"),
                    }
                }

                JournalOperation::Close => {
                    journal.close().await.unwrap();
                    return;
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
