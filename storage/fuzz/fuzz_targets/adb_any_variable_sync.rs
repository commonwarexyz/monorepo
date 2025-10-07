#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::{
        any::variable::{Any, Config},
        verify_proof,
    },
    mmr,
    mmr::hasher::Standard,
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use mmr::location::Location;
use std::{collections::HashMap, num::NonZeroU64};

const MAX_OPERATIONS: usize = 50;

type Key = FixedBytes<32>;

#[derive(Debug)]
enum Operation {
    Update {
        key: [u8; 32],
        value_bytes: Vec<u8>,
    },
    Delete {
        key: [u8; 32],
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
    },
    Prune,
    Get {
        key: [u8; 32],
    },
    GetLoc {
        loc_offset: u32,
    },
    GetKeyLoc {
        key: [u8; 32],
    },
    GetMetadata,
    Proof {
        start_loc: Location,
        max_ops: NonZeroU64,
    },
    HistoricalProof {
        size: u64,
        start_loc: Location,
        max_ops: NonZeroU64,
    },
    Sync,
    OldestRetainedLoc,
    InactivityFloorLoc,
    OpCount,
    Root,
    SimulateFailure {
        sync_log: bool,
        sync_locations: bool,
        sync_mmr: bool,
        write_limit: u8,
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 17 {
            0 => {
                let key = u.arbitrary()?;
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Update { key, value_bytes })
            }
            1 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            2 => {
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
            3 => Ok(Operation::Prune),
            4 => {
                let key = u.arbitrary()?;
                Ok(Operation::Get { key })
            }
            5 => {
                let loc_offset = u.arbitrary()?;
                Ok(Operation::GetLoc { loc_offset })
            }
            6 => {
                let key = u.arbitrary()?;
                Ok(Operation::GetKeyLoc { key })
            }
            7 => Ok(Operation::GetMetadata),
            8 => {
                let start_loc = u.arbitrary()?;
                let start_loc = Location::new(start_loc);
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::Proof { start_loc, max_ops })
            }
            9 => {
                let size = u.arbitrary()?;
                let start_loc = u.arbitrary()?;
                let start_loc = Location::new(start_loc);
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                })
            }
            10 => Ok(Operation::Sync),
            11 => Ok(Operation::OldestRetainedLoc),
            12 => Ok(Operation::InactivityFloorLoc),
            13 => Ok(Operation::OpCount),
            14 => Ok(Operation::Root),
            15 | 16 => {
                let sync_log: bool = u.arbitrary()?;
                let sync_locations: bool = u.arbitrary()?;
                let sync_mmr: bool = u.arbitrary()?;
                let write_limit = if sync_mmr { 0 } else { u.arbitrary()? };
                Ok(Operation::SimulateFailure {
                    sync_log,
                    sync_locations,
                    sync_mmr,
                    write_limit,
                })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
}

const PAGE_SIZE: usize = 128;

fn test_config(test_name: &str) -> Config<TwoCap, (commonware_codec::RangeCfg, ())> {
    Config {
        mmr_journal_partition: format!("{test_name}_mmr"),
        mmr_metadata_partition: format!("{test_name}_meta"),
        mmr_items_per_blob: NZU64!(3),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: format!("{test_name}_log"),
        log_items_per_section: NZU64!(3),
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        log_codec_config: ((0..=100000).into(), ()),
        locations_journal_partition: format!("{test_name}_locations"),
        locations_items_per_blob: NZU64!(3),
        translator: TwoCap,
        thread_pool: None,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(1)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let mut db = Any::<_, Key, Vec<u8>, Sha256, TwoCap>::init(
            context.clone(),
            test_config("adb_any_variable_fuzz_test"),
        )
        .await
        .expect("Failed to init source db");

        let mut historical_roots: HashMap<
            Location,
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = HashMap::new();

        let mut has_uncommitted = false;

        for op in input.ops.iter().take(MAX_OPERATIONS) {
            match op {
                Operation::Update { key, value_bytes } => {
                    db.update(Key::new(*key), value_bytes.to_vec())
                        .await
                        .expect("Update should not fail");
                    has_uncommitted = true;
                }

                Operation::Delete { key } => {
                    db.delete(Key::new(*key))
                        .await
                        .expect("Delete should not fail");
                    has_uncommitted = true;
                }

                Operation::Commit { metadata_bytes } => {
                    db.commit(metadata_bytes.clone())
                        .await
                        .expect("Commit should not fail");
                    historical_roots.insert(db.op_count(), db.root(&mut hasher));
                    has_uncommitted = false;
                }

                Operation::Prune => {
                    db.prune(db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::Get { key } => {
                    let _ = db.get(&Key::new(*key)).await;
                }

                Operation::GetLoc { loc_offset } => {
                    let op_count = db.op_count();
                    if op_count > 0 {
                        let loc = Location::new((*loc_offset as u64) % op_count.as_u64());
                        let _ = db.get_loc(loc).await;
                    }
                }

                Operation::GetKeyLoc { key } => {
                    let _ = db.get_key_loc(&Key::new(*key)).await;
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                Operation::Proof { start_loc, max_ops } => {
                    let op_count = db.op_count();
                    if op_count > 0 && !has_uncommitted {
                        if *start_loc < db.oldest_retained_loc().unwrap() || *start_loc >= op_count
                        {
                            continue;
                        }

                        db.sync().await.expect("Sync should not fail");
                        if let Ok((proof, log)) = db.proof(*start_loc, *max_ops).await {
                            let root = db.root(&mut hasher);
                            assert!(verify_proof(&mut hasher, &proof, *start_loc, &log, &root));
                        }
                    }
                }

                Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    if db.op_count() > 0 && !has_uncommitted {
                        let op_count = Location::new((*size) % db.op_count().as_u64()) + 1;

                        if *start_loc >= op_count || op_count > max_ops.get() {
                            continue;
                        }

                        if let Ok((proof, log)) =
                            db.historical_proof(op_count, *start_loc, *max_ops).await
                        {
                            if let Some(root) = historical_roots.get(&op_count) {
                                assert!(verify_proof(&mut hasher, &proof, *start_loc, &log, root));
                            }
                        }
                    }
                }

                Operation::Sync => {
                    db.sync().await.expect("Sync should not fail");
                }

                Operation::OldestRetainedLoc => {
                    let _ = db.oldest_retained_loc();
                }

                Operation::InactivityFloorLoc => {
                    let _ = db.inactivity_floor_loc();
                }

                Operation::OpCount => {
                    let _ = db.op_count();
                }

                Operation::Root => {
                    if !has_uncommitted {
                        let mut hasher = Standard::<Sha256>::new();
                        let _ = db.root(&mut hasher);
                    }
                }

                Operation::SimulateFailure {
                    sync_log,
                    sync_locations,
                    sync_mmr,
                    write_limit,
                } => {
                    db.simulate_failure(
                        *sync_log,
                        *sync_locations,
                        *sync_mmr,
                        *write_limit as usize,
                    )
                    .await
                    .expect("Simulate failure should not fail");

                    db = Any::<_, Key, Vec<u8>, Sha256, TwoCap>::init(
                        context.clone(),
                        test_config("src"),
                    )
                    .await
                    .expect("Failed to init source db");
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
