#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig,
    merkle::{Family, Location, mmb, mmr},
    qmdb::{
        immutable::{
            fixed::{CompactConfig as FixedConfig, CompactDb as FixedDb},
            variable::{CompactConfig as VariableConfig, CompactDb as VariableDb},
        },
        sync,
    },
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeSet, num::NonZeroU16, sync::Arc};

const MAX_OPERATIONS: usize = 40;
const PAGE_SIZE: NonZeroU16 = NZU16!(137);
type VariableCodec = ((), (commonware_codec::RangeCfg<usize>, ()));

#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Set {
        key: [u8; 32],
        value: [u8; 32],
    },
    Commit {
        metadata: Option<[u8; 32]>,
        advance_floor: bool,
    },
    Sync,
    Rewind {
        index: u8,
    },
    Prune {
        index: u8,
    },
    ToBatch,
    Target,
    CompactSync,
    Root,
    Metadata,
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let operation_count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..operation_count)
            .map(|_| Operation::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            raw_bytes,
            operations,
        })
    }
}

#[derive(Clone)]
struct Commit<D, V> {
    size: u64,
    root: D,
    metadata: Option<V>,
}

fn witness_config(name: &str, pooler: &impl BufferPooler) -> JournalConfig<()> {
    JournalConfig {
        partition: format!("{name}-witness"),
        items_per_section: NZU64!(7),
        compression: None,
        codec_config: (),
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8)),
        write_buffer: NZUsize!(1024),
    }
}

fn fixed_config(name: &str, pooler: &impl BufferPooler) -> FixedConfig<Sequential> {
    FixedConfig {
        strategy: Sequential,
        witness: witness_config(name, pooler),
        commit_codec_config: (),
    }
}

fn variable_config(
    name: &str,
    pooler: &impl BufferPooler,
) -> VariableConfig<VariableCodec, Sequential> {
    VariableConfig {
        strategy: Sequential,
        witness: witness_config(name, pooler),
        commit_codec_config: ((), ((0..=32).into(), ())),
    }
}

fn fuzz_fixed<F: Family>(input: &FuzzInput, name: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let config = fixed_config(name, &context);
        let mut db: FixedDb<F, _, Digest, Digest, Sha256, Sequential> =
            FixedDb::init(context.child("db"), config.clone())
                .await
                .expect("initialize fixed compact immutable db");
        let mut pending = Vec::new();
        let mut seen = BTreeSet::new();
        let mut commits = vec![Commit {
            size: db.size().as_u64(),
            root: db.root(),
            metadata: db.get_metadata(),
        }];
        let mut sync_id = 0usize;

        for operation in &input.operations {
            match operation {
                Operation::Set { key, value } => {
                    if seen.insert(*key) {
                        pending.push((Digest::from(*key), Digest::from(*value)));
                    }
                }
                Operation::Commit {
                    metadata,
                    advance_floor,
                } => {
                    let commit_loc = db.size().as_u64() + pending.len() as u64;
                    let floor = if *advance_floor {
                        Location::new(commit_loc)
                    } else {
                        db.inactivity_floor_loc()
                    };
                    let mut batch = db.new_batch();
                    for (key, value) in pending.drain(..) {
                        batch = batch.set(key, value);
                    }
                    let batch = batch
                        .merkleize(&db, metadata.map(Digest::from), floor)
                        .await;
                    assert!(db.validate_batch(&batch).is_ok());
                    let expected_root = batch.root();
                    let start = db.size();
                    let range;
                    (db, range) = db.apply_batch(batch).expect("apply fixed compact batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, db.size());
                    assert_eq!(db.root(), expected_root);
                    db = db.commit().await.expect("commit fixed compact db");
                    commits.push(Commit {
                        size: db.size().as_u64(),
                        root: db.root(),
                        metadata: db.get_metadata(),
                    });
                }
                Operation::Sync => {
                    let expected = (
                        db.size(),
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata(),
                    );
                    db = db.sync().await.expect("sync fixed compact db");
                    assert_eq!(
                        (
                            db.size(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata(),
                        ),
                        expected,
                        "sync should preserve fixed compact immutable state"
                    );
                    commits.push(Commit {
                        size: db.size().as_u64(),
                        root: db.root(),
                        metadata: db.get_metadata(),
                    });
                }
                Operation::Rewind { index } => {
                    let commit = commits[*index as usize % commits.len()].clone();
                    db = db
                        .rewind(Location::new(commit.size))
                        .await
                        .expect("rewind fixed compact db");
                    assert_eq!(db.root(), commit.root);
                    assert_eq!(db.get_metadata(), commit.metadata);
                    commits.retain(|candidate| candidate.size <= commit.size);
                }
                Operation::Prune { index } => {
                    let boundary = commits[*index as usize % commits.len()].size;
                    let expected = (db.size(), db.root(), db.get_metadata());
                    db = db
                        .prune(Location::new(boundary))
                        .await
                        .expect("prune fixed compact db");
                    assert_eq!(
                        (db.size(), db.root(), db.get_metadata()),
                        expected,
                        "prune should preserve fixed compact immutable state"
                    );
                    commits.retain(|candidate| candidate.size >= boundary);
                }
                Operation::ToBatch => {
                    let snapshot = db.to_batch();
                    assert_eq!(snapshot.root(), db.root());
                    assert_eq!(snapshot.bounds().tip.size, db.size());
                }
                Operation::Target => {
                    let target = db.target();
                    assert!(sync::Target::try_from(&target).is_ok());
                    assert_eq!(target.root, db.root());
                }
                Operation::CompactSync => {
                    let target = db.target();
                    let expected_size = db.size();
                    let source = Arc::new(db);
                    let client_config = fixed_config(&format!("{name}-client-{sync_id}"), &context);
                    let client: FixedDb<F, _, Digest, Digest, Sha256, Sequential> =
                        sync::sync(sync::engine::Config {
                            context: context.child("client"),
                            source: source.clone(),
                            target: sync::Target::try_from(&target)
                                .expect("compact target should be valid"),
                            max_outstanding_requests: 1,
                            fetch_batch_size: NZU64!(1),
                            apply_batch_size: NZU64!(1024),
                            db_config: client_config,
                            update_rx: None,
                            finish_rx: None,
                            reached_target_tx: None,
                            max_retained_roots: 1,
                        })
                        .await
                        .expect("compact-sync fixed immutable db");
                    assert_eq!(client.root(), target.root);
                    assert_eq!(client.size(), expected_size);
                    assert_eq!(client.get_metadata(), source.get_metadata());
                    client
                        .destroy()
                        .await
                        .expect("destroy fixed compact client");
                    db = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("source still shared"));
                    sync_id += 1;
                }
                Operation::Root => assert_eq!(db.root(), db.to_batch().root()),
                Operation::Metadata => {
                    assert_eq!(db.get_metadata(), commits.last().unwrap().metadata)
                }
            }
        }

        db.destroy()
            .await
            .expect("destroy fixed compact immutable db");
    });
}

fn fuzz_variable<F: Family>(input: &FuzzInput, name: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let config = variable_config(name, &context);
        let mut db: VariableDb<F, _, Digest, Vec<u8>, Sha256, VariableCodec, Sequential> =
            VariableDb::init(context.child("db"), config.clone())
                .await
                .expect("initialize variable compact immutable db");
        let mut pending = Vec::new();
        let mut seen = BTreeSet::new();
        let mut commits = vec![Commit {
            size: db.size().as_u64(),
            root: db.root(),
            metadata: db.get_metadata(),
        }];
        let mut sync_id = 0usize;

        for operation in &input.operations {
            match operation {
                Operation::Set { key, value } => {
                    if seen.insert(*key) {
                        pending.push((Digest::from(*key), value.to_vec()));
                    }
                }
                Operation::Commit {
                    metadata,
                    advance_floor,
                } => {
                    let commit_loc = db.size().as_u64() + pending.len() as u64;
                    let floor = if *advance_floor {
                        Location::new(commit_loc)
                    } else {
                        db.inactivity_floor_loc()
                    };
                    let mut batch = db.new_batch();
                    for (key, value) in pending.drain(..) {
                        batch = batch.set(key, value);
                    }
                    let batch = batch
                        .merkleize(&db, metadata.map(|value| value.to_vec()), floor)
                        .await;
                    assert!(db.validate_batch(&batch).is_ok());
                    let expected_root = batch.root();
                    let start = db.size();
                    let range;
                    (db, range) = db.apply_batch(batch).expect("apply variable compact batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, db.size());
                    assert_eq!(db.root(), expected_root);
                    db = db.commit().await.expect("commit variable compact db");
                    commits.push(Commit {
                        size: db.size().as_u64(),
                        root: db.root(),
                        metadata: db.get_metadata(),
                    });
                }
                Operation::Sync => {
                    let expected = (
                        db.size(),
                        db.root(),
                        db.inactivity_floor_loc(),
                        db.get_metadata(),
                    );
                    db = db.sync().await.expect("sync variable compact db");
                    assert_eq!(
                        (
                            db.size(),
                            db.root(),
                            db.inactivity_floor_loc(),
                            db.get_metadata(),
                        ),
                        expected,
                        "sync should preserve variable compact immutable state"
                    );
                    commits.push(Commit {
                        size: db.size().as_u64(),
                        root: db.root(),
                        metadata: db.get_metadata(),
                    });
                }
                Operation::Rewind { index } => {
                    let commit = commits[*index as usize % commits.len()].clone();
                    db = db
                        .rewind(Location::new(commit.size))
                        .await
                        .expect("rewind variable compact db");
                    assert_eq!(db.root(), commit.root);
                    assert_eq!(db.get_metadata(), commit.metadata);
                    commits.retain(|candidate| candidate.size <= commit.size);
                }
                Operation::Prune { index } => {
                    let boundary = commits[*index as usize % commits.len()].size;
                    let expected = (db.size(), db.root(), db.get_metadata());
                    db = db
                        .prune(Location::new(boundary))
                        .await
                        .expect("prune variable compact db");
                    assert_eq!(
                        (db.size(), db.root(), db.get_metadata()),
                        expected,
                        "prune should preserve variable compact immutable state"
                    );
                    commits.retain(|candidate| candidate.size >= boundary);
                }
                Operation::ToBatch => {
                    let snapshot = db.to_batch();
                    assert_eq!(snapshot.root(), db.root());
                    assert_eq!(snapshot.bounds().tip.size, db.size());
                }
                Operation::Target => {
                    let target = db.target();
                    assert!(sync::Target::try_from(&target).is_ok());
                    assert_eq!(target.root, db.root());
                }
                Operation::CompactSync => {
                    let target = db.target();
                    let expected_size = db.size();
                    let source = Arc::new(db);
                    let client_config =
                        variable_config(&format!("{name}-client-{sync_id}"), &context);
                    let client: VariableDb<
                        F,
                        _,
                        Digest,
                        Vec<u8>,
                        Sha256,
                        VariableCodec,
                        Sequential,
                    > = sync::sync(sync::engine::Config {
                        context: context.child("client"),
                        source: source.clone(),
                        target: sync::Target::try_from(&target)
                            .expect("compact target should be valid"),
                        max_outstanding_requests: 1,
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1024),
                        db_config: client_config,
                        update_rx: None,
                        finish_rx: None,
                        reached_target_tx: None,
                        max_retained_roots: 1,
                    })
                    .await
                    .expect("compact-sync variable immutable db");
                    assert_eq!(client.root(), target.root);
                    assert_eq!(client.size(), expected_size);
                    assert_eq!(client.get_metadata(), source.get_metadata());
                    client
                        .destroy()
                        .await
                        .expect("destroy variable compact client");
                    db = Arc::try_unwrap(source).unwrap_or_else(|_| panic!("source still shared"));
                    sync_id += 1;
                }
                Operation::Root => assert_eq!(db.root(), db.to_batch().root()),
                Operation::Metadata => {
                    assert_eq!(db.get_metadata(), commits.last().unwrap().metadata)
                }
            }
        }

        db.destroy()
            .await
            .expect("destroy variable compact immutable db");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_fixed::<mmr::Family>(&input, "qmgb-immutable-compact-fixed-mmr");
    fuzz_fixed::<mmb::Family>(&input, "qmgb-immutable-compact-fixed-mmb");
    fuzz_variable::<mmr::Family>(&input, "qmgb-immutable-compact-variable-mmr");
    fuzz_variable::<mmb::Family>(&input, "qmgb-immutable-compact-variable-mmb");
});
