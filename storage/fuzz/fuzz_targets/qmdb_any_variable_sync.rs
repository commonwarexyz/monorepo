#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Metrics, Runner};
use commonware_storage::{
    mmr::{self, hasher::Standard, MAX_LOCATION},
    qmdb::{
        any::{unordered::variable::Db, VariableConfig as Config},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use mmr::location::Location;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroU64},
};

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
    InactivityFloorLoc,
    OpCount,
    Root,
    SimulateFailure,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 14 {
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
            9 => Ok(Operation::InactivityFloorLoc),
            10 => Ok(Operation::OpCount),
            11 => Ok(Operation::Root),
            12 | 13 => Ok(Operation::SimulateFailure {}),
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

const PAGE_SIZE: NonZeroU16 = NZU16!(128);

fn test_config(test_name: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
    Config {
        mmr_journal_partition: format!("{test_name}_mmr"),
        mmr_metadata_partition: format!("{test_name}_meta"),
        mmr_items_per_blob: NZU64!(3),
        mmr_write_buffer: NZUsize!(1024),
        log_partition: format!("{test_name}_log"),
        log_items_per_blob: NZU64!(3),
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        log_codec_config: ((0..=100000).into(), ()),
        translator: TwoCap,
        thread_pool: None,
        buffer_pool: PoolRef::new(PAGE_SIZE, NZUsize!(1)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut hasher = Standard::<Sha256>::new();
        let mut db = Db::<_, Key, Vec<u8>, Sha256, TwoCap>::init(
            context.clone(),
            test_config("qmdb_any_variable_fuzz_test"),
        )
        .await
        .expect("Failed to init source db")
        .into_mutable();
        let mut restarts = 0usize;

        let mut historical_roots: HashMap<
            Location,
            <Sha256 as commonware_cryptography::Hasher>::Digest,
        > = HashMap::new();

        for op in &input.ops {
            match op {
                Operation::Update { key, value_bytes } => {
                    db.update(Key::new(*key), value_bytes.to_vec())
                        .await
                        .expect("Update should not fail");
                }

                Operation::Delete { key } => {
                    db.delete(Key::new(*key))
                        .await
                        .expect("Delete should not fail");
                }

                Operation::Commit { metadata_bytes } => {
                    let (durable_db, _) = db
                        .commit(metadata_bytes.clone())
                        .await
                        .expect("Commit should not fail");
                    let clean_db = durable_db.into_merkleized();
                    historical_roots.insert(clean_db.op_count(), clean_db.root());
                    db = clean_db.into_mutable();
                }

                Operation::Prune => {
                    let mut merkleized_db = db.into_merkleized();
                    merkleized_db
                        .prune(merkleized_db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                    db = merkleized_db.into_mutable();
                }

                Operation::Get { key } => {
                    let _ = db.get(&Key::new(*key)).await;
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                }

                Operation::Proof { start_loc, max_ops } => {
                    let op_count = db.op_count();
                    let oldest_retained_loc = db.inactivity_floor_loc();
                    if op_count == 0 {
                        continue;
                    }
                    if *start_loc < oldest_retained_loc || *start_loc >= *op_count {
                        continue;
                    }

                    let clean_db = db.into_merkleized();
                    if let Ok((proof, log)) = clean_db.proof(*start_loc, *max_ops).await {
                        let root = clean_db.root();
                        assert!(verify_proof(&mut hasher, &proof, *start_loc, &log, &root));
                    }
                    db = clean_db.into_mutable();
                }

                Operation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    let op_count = db.op_count();
                    if op_count == 0 {
                        continue;
                    }
                    let op_count = Location::new(*size % *op_count).unwrap() + 1;

                    if *start_loc >= op_count || op_count > max_ops.get() {
                        continue;
                    }

                    let clean_db = db.into_merkleized();
                    if let Ok((proof, log)) = clean_db
                        .historical_proof(op_count, *start_loc, *max_ops)
                        .await
                    {
                        if let Some(root) = historical_roots.get(&op_count) {
                            assert!(verify_proof(&mut hasher, &proof, *start_loc, &log, root));
                        }
                    }
                    db = clean_db.into_mutable();
                }

                Operation::Sync => {
                    let (durable_db, _) = db.commit(None).await.expect("commit should not fail");
                    let mut clean_db = durable_db.into_merkleized();
                    clean_db.sync().await.expect("Sync should not fail");
                    db = clean_db.into_mutable();
                }

                Operation::InactivityFloorLoc => {
                    let _ = db.inactivity_floor_loc();
                }

                Operation::OpCount => {
                    let _ = db.op_count();
                }

                Operation::Root => {
                    let clean_db = db.into_merkleized();
                    let _ = clean_db.root();
                    db = clean_db.into_mutable();
                }

                Operation::SimulateFailure => {
                    // Simulate unclean shutdown by dropping the db without committing
                    drop(db);

                    db = Db::<_, Key, Vec<u8>, Sha256, TwoCap, _, _>::init(
                        context
                            .with_label("db")
                            .with_attribute("instance", restarts),
                        test_config("qmdb_any_variable_fuzz_test"),
                    )
                    .await
                    .expect("Failed to init source db")
                    .into_mutable();
                    restarts += 1;
                }
            }
        }

        let db = db.commit(None).await.expect("commit should not fail").0;
        let db = db.into_merkleized();
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
