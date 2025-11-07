#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::{
        any::variable::{Any, Config},
        verify_proof,
    },
    mmr::{self, hasher::Standard, MAX_LOCATION},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use mmr::location::Location;
use std::{collections::HashMap, num::NonZeroU64};

const MAX_OPERATIONS: usize = 50;

type Key = FixedBytes<32>;

enum AdbState<
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    K: commonware_utils::sequence::Array,
    V: commonware_codec::Codec,
    H: commonware_cryptography::Hasher,
    T: commonware_storage::translator::Translator,
> {
    Clean(
        Any<
            E,
            K,
            V,
            H,
            T,
            commonware_storage::mmr::mem::Clean<<H as commonware_cryptography::Hasher>::Digest>,
        >,
    ),
    Dirty(Any<E, K, V, H, T, commonware_storage::mmr::mem::Dirty>),
}

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
        sync_mmr: bool,
        write_limit: u8,
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 15 {
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
            5 => Ok(Operation::GetMetadata),
            6 => {
                let start_loc = u.arbitrary::<u64>()? % (MAX_LOCATION + 1);
                let start_loc = Location::new(start_loc).unwrap();
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::Proof { start_loc, max_ops })
            }
            7 => {
                let size = u.arbitrary()?;
                let start_loc = u.arbitrary::<u64>()? % (MAX_LOCATION + 1);
                let start_loc = Location::new(start_loc).unwrap();
                let max_ops = u.int_in_range(1..=u32::MAX)? as u64;
                let max_ops = NZU64!(max_ops);
                Ok(Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                })
            }
            8 => Ok(Operation::Sync),
            9 => Ok(Operation::OldestRetainedLoc),
            10 => Ok(Operation::InactivityFloorLoc),
            11 => Ok(Operation::OpCount),
            12 => Ok(Operation::Root),
            13 | 14 => {
                let sync_log: bool = u.arbitrary()?;
                let sync_mmr: bool = u.arbitrary()?;
                let write_limit = if sync_mmr { 0 } else { u.arbitrary()? };
                Ok(Operation::SimulateFailure {
                    sync_log,
                    sync_mmr,
                    write_limit,
                })
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

fn test_config(test_name: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
    Config {
        mmr_journal_partition: format!("{test_name}_mmr"),
        mmr_metadata_partition: format!("{test_name}_meta"),
        mmr_items_per_blob: NZU64!(3),
        mmr_write_buffer: NZUsize!(1024),
        log_partition: format!("{test_name}_log"),
        log_items_per_section: NZU64!(3),
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        log_codec_config: ((0..=100000).into(), ()),
        translator: TwoCap,
        thread_pool: None,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(1)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let db = Any::<_, Key, Vec<u8>, Sha256, TwoCap>::init(
            context.clone(),
            test_config("adb_any_variable_fuzz_test"),
        )
        .await
        .expect("Failed to init source db");

        let mut db = AdbState::Clean(db);
        let mut historical_roots: HashMap<
            Location,
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = HashMap::new();

        for op in &input.ops {
            db = match op {
                Operation::Update { key, value_bytes } => {
                    let mut db = match db {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
                    db.update(Key::new(*key), value_bytes.to_vec())
                        .await
                        .expect("Update should not fail");
                    AdbState::Dirty(db)
                }

                Operation::Delete { key } => {
                    let mut db = match db {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
                    db.delete(Key::new(*key))
                        .await
                        .expect("Delete should not fail");
                    AdbState::Dirty(db)
                }

                Operation::Commit { metadata_bytes } => {
                    let mut db = match db {
                        AdbState::Clean(d) => d.into_dirty(),
                        AdbState::Dirty(d) => d,
                    };
                    db.commit(metadata_bytes.clone())
                        .await
                        .expect("Commit should not fail");
                    let db = db.merkleize();
                    historical_roots.insert(db.op_count(), db.root());
                    AdbState::Clean(db)
                }

                Operation::Prune => {
                    let mut db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    db.prune(db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                    AdbState::Clean(db)
                }

                Operation::Get { key } => {
                    match &db {
                        AdbState::Clean(d) => {
                            let _ = d.get(&Key::new(*key)).await;
                        }
                        AdbState::Dirty(d) => {
                            let _ = d.get(&Key::new(*key)).await;
                        }
                    }
                    db
                }

                Operation::GetMetadata => {
                    match &db {
                        AdbState::Clean(d) => {
                            let _ = d.get_metadata().await;
                        }
                        AdbState::Dirty(d) => {
                            let _ = d.get_metadata().await;
                        }
                    }
                    db
                }

                Operation::Proof { start_loc, max_ops } => {
                    let db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    let op_count = db.op_count();
                    let oldest_retained_loc = db
                        .oldest_retained_loc()
                        .unwrap_or(Location::new(0).unwrap());
                    if op_count > 0 {
                        if *start_loc < oldest_retained_loc || *start_loc >= *op_count {
                            AdbState::Clean(db)
                        } else {
                            let mut db = db;
                            db.sync().await.expect("Sync should not fail");
                            if let Ok((proof, log)) = db.proof(*start_loc, *max_ops).await {
                                let root = db.root();
                                assert!(verify_proof(&mut hasher, &proof, *start_loc, &log, &root));
                            }
                            AdbState::Clean(db)
                        }
                    } else {
                        AdbState::Clean(db)
                    }
                }

                Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    let db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    let op_count = db.op_count();
                    if op_count > 0 {
                        let op_count = Location::new(*size % *op_count).unwrap() + 1;

                        if *start_loc >= op_count || op_count > max_ops.get() {
                            AdbState::Clean(db)
                        } else {
                            let db = db;
                            if let Ok((proof, log)) =
                                db.historical_proof(op_count, *start_loc, *max_ops).await
                            {
                                if let Some(root) = historical_roots.get(&op_count) {
                                    assert!(verify_proof(
                                        &mut hasher,
                                        &proof,
                                        *start_loc,
                                        &log,
                                        root
                                    ));
                                }
                            }
                            AdbState::Clean(db)
                        }
                    } else {
                        AdbState::Clean(db)
                    }
                }

                Operation::Sync => {
                    let mut db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    db.sync().await.expect("Sync should not fail");
                    AdbState::Clean(db)
                }

                Operation::OldestRetainedLoc => {
                    match &db {
                        AdbState::Clean(d) => {
                            let _ = d.oldest_retained_loc();
                        }
                        AdbState::Dirty(d) => {
                            let _ = d.oldest_retained_loc();
                        }
                    }
                    db
                }

                Operation::InactivityFloorLoc => {
                    match &db {
                        AdbState::Clean(d) => {
                            let _ = d.inactivity_floor_loc();
                        }
                        AdbState::Dirty(d) => {
                            let _ = d.inactivity_floor_loc();
                        }
                    }
                    db
                }

                Operation::OpCount => {
                    match &db {
                        AdbState::Clean(d) => {
                            let _ = d.op_count();
                        }
                        AdbState::Dirty(d) => {
                            let _ = d.op_count();
                        }
                    }
                    db
                }

                Operation::Root => {
                    let db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    let _ = db.root();
                    AdbState::Clean(db)
                }

                Operation::SimulateFailure {
                    sync_log,
                    sync_mmr,
                    write_limit,
                } => {
                    let db = match db {
                        AdbState::Clean(d) => d,
                        AdbState::Dirty(d) => d.merkleize(),
                    };
                    db.simulate_failure(*sync_log, *sync_mmr, *write_limit as usize)
                        .await
                        .expect("Simulate failure should not fail");

                    let db = Any::<_, Key, Vec<u8>, Sha256, TwoCap>::init(
                        context.clone(),
                        test_config("src"),
                    )
                    .await
                    .expect("Failed to init source db");
                    AdbState::Clean(db)
                }
            };
        }

        match db {
            AdbState::Clean(d) => d.destroy().await.expect("Destroy should not fail"),
            AdbState::Dirty(d) => d
                .merkleize()
                .destroy()
                .await
                .expect("Destroy should not fail"),
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
