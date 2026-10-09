#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::blake3::Digest;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    qmdb::store::db::{Config, Db},
    translator::TwoCap,
};
use commonware_storage_fuzz::floor::{Plan, Recorder};
use commonware_utils::{NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
};

const MAX_OPERATIONS: usize = 50;

type Key = Digest;
type Value = Vec<u8>;
type StoreDb = Db<deterministic::Context, Key, Value, TwoCap>;

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
        plan: Plan,
    },
    Get {
        key: [u8; 32],
    },
    GetMetadata,
    Sync,
    Prune,
    OpCount,
    InactivityFloorLoc,
    SimulateFailure,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 10 {
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
                let plan = u.arbitrary()?;
                Ok(Operation::Commit {
                    metadata_bytes,
                    plan,
                })
            }
            3 => {
                let key = u.arbitrary()?;
                Ok(Operation::Get { key })
            }
            4 => Ok(Operation::GetMetadata),
            5 => Ok(Operation::Sync),
            6 => Ok(Operation::Prune),
            7 => Ok(Operation::OpCount),
            8 => Ok(Operation::InactivityFloorLoc),
            9 => Ok(Operation::SimulateFailure),
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

const PAGE_SIZE: NonZeroU16 = NZU16!(125);
const PAGE_CACHE_SIZE: usize = 8;

fn test_config(
    test_name: &str,
    pooler: &impl BufferPooler,
) -> Config<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    Config {
        log: VConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            items_per_section: NZU64!(7),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        },
        translator: TwoCap,
        init_cache: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
    }
}

/// Check every key the run touched against the model of committed state.
async fn assert_matches_model(db: &StoreDb, model: &BTreeMap<Key, Value>, keys: &BTreeSet<Key>) {
    assert_eq!(db.is_empty(), model.is_empty(), "empty-db state diverged");
    for key in keys {
        let got = db.get(key).await.expect("get should not fail");
        assert_eq!(got.as_ref(), model.get(key), "db diverged from model");
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = test_config("store-fuzz-test", &context);
        let mut db = StoreDb::init(context.child("storage"), cfg, None)
            .await
            .expect("Failed to init db");
        let mut restarts = 0usize;
        let mut pending: BTreeMap<Digest, Option<Vec<u8>>> = BTreeMap::new();

        // Every applied batch commits, so the model of committed state survives restarts.
        let mut model: BTreeMap<Key, Value> = BTreeMap::new();
        let mut keys: BTreeSet<Key> = BTreeSet::new();

        for op in &input.ops {
            db = match op {
                Operation::Update { key, value_bytes } => {
                    pending.insert(Digest(*key), Some(value_bytes.clone()));
                    db
                }

                Operation::Delete { key } => {
                    pending.insert(Digest(*key), None);
                    db
                }

                Operation::Commit {
                    metadata_bytes,
                    plan,
                } => {
                    let mut batch = db.new_batch();
                    for (key, value) in std::mem::take(&mut pending) {
                        keys.insert(key);
                        batch = match value {
                            Some(v) => {
                                model.insert(key, v.clone());
                                batch.update(key, v)
                            }
                            None => {
                                model.remove(&key);
                                batch.delete(key)
                            }
                        };
                    }
                    let changeset = batch.finalize(metadata_bytes.clone());
                    let inherited = db.inactivity_floor_loc();
                    let mut policy =
                        Recorder::new(plan, |seed| vec![seed; usize::from(seed % 16) + 1]);
                    let (db, range) = db
                        .apply_batch(changeset, &mut policy)
                        .await
                        .expect("Apply batch should not fail");
                    policy.check(
                        &mut model,
                        inherited,
                        db.inactivity_floor_loc(),
                        range.end - 1,
                    );
                    db.commit().await.expect("Commit should not fail")
                }

                Operation::Get { key } => {
                    let digest = Digest(*key);
                    if let Some(value) = pending.get(&digest) {
                        let _ = value.clone();
                    } else {
                        let got = db.get(&digest).await.expect("Get should not fail");
                        assert_eq!(got.as_ref(), model.get(&digest), "db diverged from model");
                    }
                    db
                }

                Operation::GetMetadata => {
                    let _ = db.get_metadata().await;
                    db
                }

                Operation::Sync => db.sync().await.expect("Sync should not fail"),

                Operation::Prune => {
                    let floor = db.inactivity_floor_loc();
                    db.prune(floor).await.expect("Prune should not fail")
                }

                Operation::OpCount => {
                    let _ = db.bounds().end;
                    db
                }

                Operation::InactivityFloorLoc => {
                    let _ = db.inactivity_floor_loc();
                    db
                }

                Operation::SimulateFailure => {
                    pending.clear();
                    let floor = db.inactivity_floor_loc();
                    drop(db);

                    let cfg = test_config("store-fuzz-test", &context);
                    let db = StoreDb::init(
                        context.child("db").with_attribute("instance", restarts),
                        cfg,
                        None,
                    )
                    .await
                    .expect("Failed to init db");
                    restarts += 1;
                    assert_eq!(
                        db.inactivity_floor_loc(),
                        floor,
                        "floor changed across restart"
                    );
                    assert_matches_model(&db, &model, &keys).await;
                    db
                }
            };
        }

        let db = db.commit().await.expect("Commit should not fail");
        assert_matches_model(&db, &model, &keys).await;
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
