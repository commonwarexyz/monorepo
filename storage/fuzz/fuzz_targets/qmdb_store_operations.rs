#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::blake3::Digest;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    qmdb::store::{Config, Db},
    translator::TwoCap,
};
use commonware_storage_fuzz::floor::{Plan, Recorder};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
};

const MAX_OPERATIONS: usize = 50;
const MAX_GET_MANY_KEYS: usize = 8;

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
    GetMany {
        keys: Vec<[u8; 32]>,
    },
    GetMetadata,
    Sync,
    Prune,
    OpCount,
    InactivityFloorLoc,
    IsEmpty,
    SimulateFailure,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 12 {
            0 => {
                let key = u.arbitrary()?;
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len.min(u.len()))?.to_vec();
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
                    Some(u.bytes(actual_len.min(u.len()))?.to_vec())
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
            9 => Ok(Operation::IsEmpty),
            10 => Ok(Operation::SimulateFailure),
            11 => {
                let count = u.int_in_range(0..=MAX_GET_MANY_KEYS)?;
                let keys = (0..count)
                    .map(|_| u.arbitrary())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Operation::GetMany { keys })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops, raw_bytes })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(125);
const PAGE_CACHE_SIZE: usize = 8;

fn test_config(test_name: &str) -> Config<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    Config {
        log: VConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            items_per_section: NZU64!(7),
            page_cache: CacheRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
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
    let cfg = deterministic::Config::new().with_rng(FuzzRng::new(input.raw_bytes.clone()));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        let cfg = test_config("store-fuzz-test");
        let mut db = StoreDb::init(context.child("storage"), cfg, None)
            .await
            .expect("Failed to init db");
        let mut restarts = 0usize;
        let mut pending: BTreeMap<Digest, Option<Vec<u8>>> = BTreeMap::new();
        let mut committed_metadata = None;
        let mut expected_size = db.bounds().end;

        // Every applied batch commits, so the model of committed state survives restarts. It
        // takes each batch's writes before the batch applies and the floor walk's decisions
        // when the walk's record is checked.
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
                        match &value {
                            Some(v) => {
                                model.insert(key, v.clone());
                            }
                            None => {
                                model.remove(&key);
                            }
                        }
                        batch = batch.write(key, value);
                    }
                    let changeset = batch.with_metadata(metadata_bytes.clone()).finalize();
                    let inherited = db.inactivity_floor();
                    let mut policy =
                        Recorder::new(plan, |seed| vec![seed; usize::from(seed % 16) + 1]);
                    let applied_start = db.bounds().end;
                    let db = db
                        .apply_batch_with(changeset, &mut policy)
                        .await
                        .expect("Apply batch should not fail");
                    // The applied operations cover the batch's writes, the walk's operations, and
                    // the commit.
                    assert_eq!(applied_start, expected_size);
                    expected_size = db.bounds().end;
                    policy.check(
                        &mut model,
                        inherited,
                        db.inactivity_floor(),
                        db.bounds().end - 1,
                    );
                    let db = db.commit().await.expect("Commit should not fail");
                    committed_metadata = metadata_bytes.clone();
                    db
                }

                Operation::Get { key } => {
                    let digest = Digest(*key);
                    let committed_value = db.get(&digest).await.expect("Get should not fail");
                    assert_eq!(
                        committed_value,
                        model.get(&digest).cloned(),
                        "Store get disagreed with committed model",
                    );

                    let mut batch = db.new_batch();
                    for (key, value) in &pending {
                        batch = batch.write(*key, value.clone());
                    }
                    let expected = match pending.get(&digest) {
                        Some(value) => value.clone(),
                        None => model.get(&digest).cloned(),
                    };
                    assert_eq!(
                        batch.get(&digest).await.expect("Batch get should not fail"),
                        expected,
                        "Batch get disagreed with pending model",
                    );
                    db
                }

                Operation::GetMany { keys: requested } => {
                    // The store reads committed state, so compare it with the model for keys the
                    // pending writes do not shadow.
                    let requested: Vec<Digest> = requested.iter().copied().map(Digest).collect();
                    let committed: Vec<Digest> = requested
                        .iter()
                        .copied()
                        .filter(|key| !pending.contains_key(key))
                        .collect();
                    let got = db
                        .get_many(&committed)
                        .await
                        .expect("Get many should not fail");
                    assert_eq!(got.len(), committed.len());
                    for (key, value) in committed.iter().zip(&got) {
                        assert_eq!(
                            value.as_ref(),
                            model.get(key),
                            "get_many diverged from model"
                        );
                    }

                    // A batch holding the pending writes reads them first and the store otherwise.
                    let mut batch = db.new_batch();
                    for (key, value) in &pending {
                        batch = batch.write(*key, value.clone());
                    }
                    let got = batch
                        .get_many(&requested)
                        .await
                        .expect("Batch get many should not fail");
                    assert_eq!(got.len(), requested.len());
                    for (key, value) in requested.iter().zip(&got) {
                        let expected = pending
                            .get(key)
                            .map_or_else(|| model.get(key), Option::as_ref);
                        assert_eq!(
                            value.as_ref(),
                            expected,
                            "batch get_many diverged from model"
                        );
                    }
                    drop(batch);
                    db
                }

                Operation::GetMetadata => {
                    assert_eq!(
                        db.get_metadata()
                            .await
                            .expect("Get metadata should not fail"),
                        committed_metadata,
                        "Store metadata disagreed with committed model",
                    );
                    db
                }

                Operation::Sync => db.sync().await.expect("Sync should not fail"),

                Operation::Prune => {
                    let floor = db.inactivity_floor();
                    db.prune(floor).await.expect("Prune should not fail")
                }

                Operation::OpCount => {
                    assert_eq!(
                        db.bounds().end,
                        expected_size,
                        "Store bounds disagreed with the modeled operation log"
                    );
                    db
                }

                Operation::InactivityFloorLoc => {
                    assert!(
                        db.inactivity_floor() <= db.bounds().end,
                        "Inactivity floor exceeded store size",
                    );
                    db
                }

                Operation::IsEmpty => {
                    assert_eq!(
                        db.is_empty(),
                        model.is_empty(),
                        "Store emptiness disagreed with committed model",
                    );
                    db
                }

                Operation::SimulateFailure => {
                    pending.clear();
                    let floor = db.inactivity_floor();
                    drop(db);

                    let cfg = test_config("store-fuzz-test");
                    let db = StoreDb::init(
                        context.child("db").with_attribute("instance", restarts),
                        cfg,
                        None,
                    )
                    .await
                    .expect("Failed to init db");
                    expected_size = db.bounds().end;
                    restarts += 1;
                    assert_eq!(db.inactivity_floor(), floor, "floor changed across restart");
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
