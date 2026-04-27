#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{full::Config as MerkleConfig, mmb, mmr, Family as MerkleFamily},
    qmdb::{
        any::{
            unordered::fixed::{Db, Operation as FixedOperation},
            FixedConfig as Config,
        },
        sync, RootSpec,
    },
    translator::TwoCap,
};
use commonware_utils::{non_empty_range, sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{num::NonZeroU16, sync::Arc};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type FixedDb<F> = Db<F, deterministic::Context, Key, Value, Sha256, TwoCap>;

const MAX_OPERATIONS: usize = 50;

#[derive(Debug)]
enum Operation {
    // Basic ops to build source state
    Update { key: [u8; 32], value: [u8; 32] },
    Delete { key: [u8; 32] },
    Commit,
    Prune,

    // Sync scenarios
    SyncFull { fetch_batch_size: u64 },

    // Failure simulation
    SimulateFailure,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 8 {
            0 | 1 => {
                let key = u.arbitrary()?;
                let value = u.arbitrary()?;
                Ok(Operation::Update { key, value })
            }
            2 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            3 => Ok(Operation::Commit),
            4 => Ok(Operation::Prune),
            5 => {
                let fetch_batch_size = u.arbitrary()?;
                Ok(Operation::SyncFull { fetch_batch_size })
            }
            6 => Ok(Operation::SimulateFailure {}),
            7 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
    commit_counter: u64,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput {
            ops,
            commit_counter: 0,
        })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(129);

fn test_config(test_name: &str, pooler: &impl BufferPooler) -> Config<TwoCap> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(1));
    Config {
        merkle_config: MerkleConfig {
            journal_partition: format!("{test_name}-merkle"),
            metadata_partition: format!("{test_name}-meta"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: format!("{test_name}-log"),
            items_per_blob: NZU64!(3),
            write_buffer: NZUsize!(1024),
            page_cache,
        },
        translator: TwoCap,
    }
}

async fn test_sync<F, R>(
    context: deterministic::Context,
    resolver: R,
    target: sync::Target<F, commonware_cryptography::sha256::Digest>,
    fetch_batch_size: u64,
    test_name: &str,
    sync_id: usize,
) -> bool
where
    F: MerkleFamily + RootSpec,
    R: sync::resolver::Resolver<
        Family = F,
        Digest = commonware_cryptography::sha256::Digest,
        Op = FixedOperation<F, Key, Value>,
    >,
{
    let db_config = test_config(test_name, &context);
    let expected_root = target.root;

    let sync_config: sync::engine::Config<FixedDb<F>, R> = sync::engine::Config {
        context: context.with_label("sync").with_attribute("id", sync_id),
        update_rx: None,
        finish_rx: None,
        reached_target_tx: None,
        db_config,
        fetch_batch_size: NZU64!((fetch_batch_size % 100) + 1),
        target,
        resolver,
        apply_batch_size: 100,
        max_outstanding_requests: 10,
        max_retained_roots: 8,
    };

    if let Ok(synced) = sync::sync(sync_config).await {
        let actual_root = synced.root();
        assert_eq!(
            actual_root, expected_root,
            "Synced root must match target root"
        );

        synced.destroy().await.is_ok()
    } else {
        false
    }
}

fn fuzz_family<F: MerkleFamily + RootSpec>(input: &mut FuzzInput, test_name: &str) {
    input.commit_counter = 0;
    let runner = deterministic::Runner::default();

    let test_name = test_name.to_string();
    runner.start(|context| async move {
        let cfg = test_config(&test_name, &context);
        let mut db: FixedDb<F> = Db::init(context.clone(), cfg)
            .await
            .expect("Failed to init source db");
        let mut restarts = 0usize;

        let mut sync_id = 0;

        let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

        for op in &input.ops {
            match op {
                Operation::Update { key, value } => {
                    pending_writes.push((Key::new(*key), Some(Value::new(*value))));
                }

                Operation::Delete { key } => {
                    pending_writes.push((Key::new(*key), None));
                }

                Operation::Commit => {
                    let mut commit_id = [0u8; 32];
                    if input.commit_counter == 0 {
                        assert!(db.get_metadata().await.unwrap().is_none());
                    } else {
                        commit_id[..8].copy_from_slice(&input.commit_counter.to_be_bytes());
                        assert_eq!(
                            db.get_metadata().await.unwrap().unwrap(),
                            FixedBytes::new(commit_id),
                        );
                    }
                    input.commit_counter += 1;
                    commit_id[..8].copy_from_slice(&input.commit_counter.to_be_bytes());
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch
                        .merkleize(&db, Some(FixedBytes::new(commit_id)))
                        .await
                        .unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("Commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                }

                Operation::Prune => {
                    db.prune(db.sync_boundary())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::SyncFull { fetch_batch_size } => {
                    if db.bounds().await.end == 0 {
                        continue;
                    }
                    input.commit_counter += 1;
                    let mut commit_id = [0u8; 32];
                    commit_id[..8].copy_from_slice(&input.commit_counter.to_be_bytes());
                    let mut batch = db.new_batch();
                    for (k, v) in pending_writes.drain(..) {
                        batch = batch.write(k, v);
                    }
                    let merkleized = batch
                        .merkleize(&db, Some(FixedBytes::new(commit_id)))
                        .await
                        .unwrap();
                    db.apply_batch(merkleized)
                        .await
                        .expect("commit should not fail");
                    db.commit().await.expect("Commit should not fail");
                    let target = sync::Target {
                        root: db.root(),
                        range: non_empty_range!(db.sync_boundary(), db.bounds().await.end),
                    };

                    let wrapped_src = Arc::new(db);
                    let _result = test_sync(
                        context.clone(),
                        wrapped_src.clone(),
                        target,
                        *fetch_batch_size,
                        &format!("{test_name}-full_{sync_id}"),
                        sync_id,
                    )
                    .await;
                    db = Arc::try_unwrap(wrapped_src)
                        .unwrap_or_else(|_| panic!("Failed to unwrap src"));
                    sync_id += 1;
                }

                Operation::SimulateFailure => {
                    // Simulate unclean shutdown by dropping the db without committing
                    pending_writes.clear();
                    drop(db);

                    let cfg = test_config(&test_name, &context);
                    db = Db::init(
                        context
                            .with_label("db")
                            .with_attribute("instance", restarts),
                        cfg,
                    )
                    .await
                    .expect("Failed to init source db");
                    restarts += 1;
                }
            }
        }

        let mut batch = db.new_batch();
        for (k, v) in pending_writes.drain(..) {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized)
            .await
            .expect("commit should not fail");
        db.destroy().await.expect("Destroy should not fail");
    });
}

fn fuzz(mut input: FuzzInput) {
    fuzz_family::<mmr::Family>(&mut input, "qmdb-any-fixed-fuzz-mmr");
    fuzz_family::<mmb::Family>(&mut input, "qmdb-any-fixed-fuzz-mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
