#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::{
        keyless::{Config, Keyless},
        verify_proof,
    },
    mmr::{hasher::Standard, Location},
};
use commonware_utils::{NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 50;
const MAX_PROOF_OPS: u64 = 100;

#[derive(Debug)]
enum Operation {
    Append {
        value_bytes: Vec<u8>,
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
    },
    Get {
        loc_offset: u32,
    },
    GetMetadata,
    Prune,
    Sync,
    OpCount,
    LastCommitLoc,
    OldestRetainedLoc,
    Root,
    Proof {
        start_offset: u32,
        max_ops: u16,
    },
    HistoricalProof {
        size_offset: u32,
        start_offset: u32,
        max_ops: u16,
    },
    SimulateFailure {
        sync_log: bool,
        sync_mmr: bool,
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 13 {
            0 => {
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Append { value_bytes })
            }
            1 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len = ((metadata_len as usize) % 1000) + 1;
                    Some(u.bytes(actual_len)?.to_vec())
                } else {
                    None
                };
                Ok(Operation::Commit { metadata_bytes })
            }
            2 => {
                let loc_offset = u.arbitrary()?;
                Ok(Operation::Get { loc_offset })
            }
            3 => Ok(Operation::GetMetadata),
            4 => Ok(Operation::Prune),
            5 => Ok(Operation::Sync),
            6 => Ok(Operation::OpCount),
            7 => Ok(Operation::LastCommitLoc),
            8 => Ok(Operation::OldestRetainedLoc),
            9 => Ok(Operation::Root),
            10 => {
                let start_offset = u.arbitrary()?;
                let max_ops = u.arbitrary()?;
                Ok(Operation::Proof {
                    start_offset,
                    max_ops,
                })
            }
            11 => {
                let size_offset = u.arbitrary()?;
                let start_offset = u.arbitrary()?;
                let max_ops = u.arbitrary()?;
                Ok(Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                })
            }
            12 => {
                let sync_log: bool = u.arbitrary()?;
                let sync_mmr: bool = u.arbitrary()?;
                Ok(Operation::SimulateFailure { sync_log, sync_mmr })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops })
    }
}

const PAGE_SIZE: usize = 128;
const PAGE_CACHE_SIZE: usize = 8;

fn test_config(test_name: &str) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
    Config {
        mmr_journal_partition: format!("{test_name}_mmr"),
        mmr_metadata_partition: format!("{test_name}_meta"),
        mmr_items_per_blob: NZU64!(3),
        mmr_write_buffer: NZUsize!(1024),
        log_partition: format!("{test_name}_log"),
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: NZU64!(7),
        thread_pool: None,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let mut db =
            Keyless::<_, _, Sha256, _>::init(context.clone(), test_config("keyless_fuzz_test"))
                .await
                .expect("Failed to init keyless db");

        let mut has_uncommitted = false;

        for op in &input.ops {
            match op {
                Operation::Append { value_bytes } => {
                    db.append(value_bytes.clone())
                        .await
                        .expect("Append should not fail");
                    has_uncommitted = true;
                }

                Operation::Commit { metadata_bytes } => {
                    db.commit(metadata_bytes.clone())
                        .await
                        .expect("Commit should not fail");
                    has_uncommitted = false;
                }

                Operation::Get { loc_offset } => {
                    let op_count = db.op_count();
                    if op_count > 0 {
                        let loc = (*loc_offset as u64) % op_count.as_u64();
                        let _ = db.get(loc.into()).await;
                    }
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                Operation::Prune => {
                    if let Some(last_commit_loc) = db.last_commit_loc() {
                        db.prune(last_commit_loc)
                            .await
                            .expect("Prune should not fail");
                    }
                }

                Operation::Sync => {
                    db.sync().await.expect("Sync should not fail");
                }

                Operation::OpCount => {
                    let _ = db.op_count();
                }

                Operation::LastCommitLoc => {
                    let _ = db.last_commit_loc();
                }

                Operation::OldestRetainedLoc => {
                    let _ = db.oldest_retained_loc();
                }

                Operation::Root => {
                    if !has_uncommitted {
                        let _ = db.root();
                    }
                }

                Operation::Proof {
                    start_offset,
                    max_ops,
                } => {
                    let op_count = db.op_count();
                    if op_count > 0 && !has_uncommitted {
                        let start_loc = (*start_offset as u64) % op_count.as_u64();
                        let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                        let start_loc = Location::new(start_loc).unwrap();
                        let root = db.root();
                        if let Ok((proof, ops)) = db.proof(start_loc, NZU64!(max_ops_value)).await {
                            assert!(
                                verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                                "Failed to verify proof for start loc{start_loc} with ops {max_ops} ops",
                            );
                        }
                    }
                }

                Operation::HistoricalProof {
                    size_offset,
                    start_offset,
                    max_ops,
                } => {
                    db.sync().await.expect("Sync should not fail");
                    let op_count = db.op_count();
                    if op_count > 0 && !has_uncommitted {
                        let size = ((*size_offset as u64) % op_count.as_u64()) + 1;
                        let size = Location::new(size).unwrap();
                        let start_loc = (*start_offset as u64) % *size;
                        let start_loc = Location::new(start_loc).unwrap();
                        let max_ops_value = ((*max_ops as u64) % MAX_PROOF_OPS) + 1;
                        let root = db.root();
                        if let Ok((proof, ops)) = db
                            .historical_proof(op_count, start_loc, NZU64!(max_ops_value))
                            .await {
                            assert!(
                                verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                                "Failed to verify historical proof for start loc{start_loc} with max ops {max_ops}",
                            );
                        }
                    }
                }

                Operation::SimulateFailure {
                    sync_log,
                    sync_mmr,
                } => {
                    db.simulate_failure(*sync_log, *sync_mmr)
                        .await
                        .expect("Simulate failure should not fail");

                    db = Keyless::init(
                        context.clone(),
                        test_config("keyless_fuzz_test"),
                    )
                    .await
                    .expect("Failed to init keyless db");
                    has_uncommitted = false;
                }
            }
        }

        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
