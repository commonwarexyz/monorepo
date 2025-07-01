#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::hash;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::journal::fixed::{
    Config as FixedConfig, Config as VariableConfig, Journal as FixedJournal,
    Journal as VariableJournal,
};
use futures::{pin_mut, StreamExt};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum JournalOperation {
    Append { value: u64 },
    Read { pos: u64 },
    Size,
    Sync,
    Rewind { size: u64 },
    OldestRetainedPos,
    Prune { min_pos: u64 },
    Replay,
    Close,
    Destroy,
    // Edge case operations
    AppendMany { count: u8 },
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

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = match input.journal_type {
            JournalType::Fixed => FixedConfig {
                partition: "fixed_journal_operations_fuzz_test".to_string(),
                items_per_blob: 3,
                write_buffer: 512,
            },
            JournalType::Variable => VariableConfig {
                partition: "variable_journal_operations_fuzz_test".to_string(),
                items_per_blob: 3,
                write_buffer: 512,
            },
        };

        let mut journal = match input.journal_type {
            JournalType::Fixed => FixedJournal::init(context.clone(), cfg).await.unwrap(),
            JournalType::Variable => VariableJournal::init(context.clone(), cfg).await.unwrap(),
        };

        let mut next_value = 0u64;
        let mut journal_size = 0u64;

        for op in input.operations.iter() {
            match op {
                JournalOperation::Append { value } => {
                    let digest = hash(&value.to_be_bytes());
                    let _pos = journal.append(digest).await.unwrap();
                    journal_size += 1;
                }

                JournalOperation::Read { pos } => {
                    // Only read valid positions that exist in the journal
                    if *pos < journal_size {
                        journal.read(*pos).await.unwrap();
                    }
                }

                JournalOperation::Size => {
                    let _size = journal.size().await.unwrap();
                }

                JournalOperation::Sync => {
                    journal.sync().await.unwrap();
                }

                JournalOperation::Rewind { size } => {
                    // Only rewind to valid positions within current journal size
                    if *size <= journal_size {
                        journal.rewind(*size).await.unwrap();
                        journal_size = *size;
                    }
                }

                JournalOperation::OldestRetainedPos => {
                    let _pos = journal.oldest_retained_pos().await.unwrap();
                }

                JournalOperation::Prune { min_pos } => {
                    // Only prune positions within current journal size
                    if *min_pos <= journal_size {
                        journal.prune(*min_pos).await.unwrap();
                    }
                }

                JournalOperation::Replay => {
                    // Test replay functionality - panic on any replay failures
                    let stream = journal.replay(100, 1024).await.unwrap();
                    pin_mut!(stream);
                    // Consume first few items to test stream - panic on stream errors
                    for _ in 0..3 {
                        match stream.next().await {
                            Some(result) => {
                                result.unwrap(); // Panic on item errors
                            }
                            None => break,
                        }
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
                    // Append multiple items to stress test blob transitions
                    for _ in 0..*count {
                        let digest = hash(&next_value.to_be_bytes());
                        journal.append(digest).await.unwrap();
                        next_value += 1;
                        journal_size += 1;
                    }
                }

                JournalOperation::MultipleSync => {
                    // Test multiple rapid syncs
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
