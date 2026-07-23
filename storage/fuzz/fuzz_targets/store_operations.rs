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
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, num::NonZeroU16};

const MAX_OPERATIONS: usize = 50;

type Key = Digest;
type Value = Vec<u8>;
type StoreDb = Db<deterministic::Context, Key, Value, TwoCap>;

#[derive(Debug)]
enum Operation {
    Update { key: [u8; 32], value_bytes: Vec<u8> },
    Delete { key: [u8; 32] },
    Commit { metadata_bytes: Option<Vec<u8>> },
    Get { key: [u8; 32] },
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
        match choice % 11 {
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
                Ok(Operation::Commit { metadata_bytes })
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

fn test_config(
    test_name: &str,
    pooler: &impl BufferPooler,
) -> Config<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    Config {
        log: VConfig {
            partition: format!("{test_name}-log"),
            write_buffer: NZUsize!(1024),
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            items_per_section: NZU64!(7),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
    }
}

fn fuzz(input: FuzzInput) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        let cfg = test_config("store-fuzz-test", &context);
        let mut db = StoreDb::init(context.child("storage"), cfg)
            .await
            .expect("Failed to init db");
        let mut restarts = 0usize;
        let mut pending: BTreeMap<Digest, Option<Vec<u8>>> = BTreeMap::new();
        let mut committed: BTreeMap<Digest, Vec<u8>> = BTreeMap::new();
        let mut committed_metadata = None;
        let mut expected_size = db.size();

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

                Operation::Commit { metadata_bytes } => {
                    let mut batch = db.new_batch();
                    let changes = std::mem::take(&mut pending);
                    for (key, value) in &changes {
                        batch = match value {
                            Some(v) => batch.update(*key, v.clone()),
                            None => batch.delete(*key),
                        };
                    }
                    let changeset = batch.finalize(metadata_bytes.clone());
                    let (db, applied) = db
                        .apply_batch(changeset)
                        .await
                        .expect("Apply batch should not fail");
                    assert_eq!(applied.start, expected_size);
                    expected_size = applied.end;
                    let db = db.commit().await.expect("Commit should not fail");
                    for (key, value) in changes {
                        match value {
                            Some(value) => {
                                committed.insert(key, value);
                            }
                            None => {
                                committed.remove(&key);
                            }
                        }
                    }
                    committed_metadata = metadata_bytes.clone();
                    db
                }

                Operation::Get { key } => {
                    let digest = Digest(*key);
                    let committed_value = db.get(&digest).await.expect("Get should not fail");
                    assert_eq!(
                        committed_value,
                        committed.get(&digest).cloned(),
                        "Store get disagreed with committed model",
                    );

                    let mut batch = db.new_batch();
                    for (key, value) in &pending {
                        batch = match value {
                            Some(value) => batch.update(*key, value.clone()),
                            None => batch.delete(*key),
                        };
                    }
                    let expected = match pending.get(&digest) {
                        Some(value) => value.clone(),
                        None => committed.get(&digest).cloned(),
                    };
                    assert_eq!(
                        batch.get(&digest).await.expect("Batch get should not fail"),
                        expected,
                        "Batch get disagreed with pending model",
                    );
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
                    let floor = db.inactivity_floor_loc();
                    db.prune(floor).await.expect("Prune should not fail")
                }

                Operation::OpCount => {
                    assert_eq!(
                        db.bounds().end,
                        expected_size,
                        "Store bounds disagreed with the modeled operation log"
                    );
                    assert_eq!(
                        db.size(),
                        expected_size,
                        "Store size disagreed with the model"
                    );
                    db
                }

                Operation::InactivityFloorLoc => {
                    assert!(
                        db.inactivity_floor_loc() <= db.size(),
                        "Inactivity floor exceeded store size",
                    );
                    db
                }

                Operation::IsEmpty => {
                    assert_eq!(
                        db.is_empty(),
                        committed.is_empty(),
                        "Store emptiness disagreed with committed model",
                    );
                    db
                }

                Operation::SimulateFailure => {
                    pending.clear();
                    drop(db);

                    let cfg = test_config("store-fuzz-test", &context);
                    let db = StoreDb::init(
                        context.child("db").with_attribute("instance", restarts),
                        cfg,
                    )
                    .await
                    .expect("Failed to init db");
                    expected_size = db.size();
                    restarts += 1;
                    db
                }
            };
        }

        let db = db.commit().await.expect("Commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
