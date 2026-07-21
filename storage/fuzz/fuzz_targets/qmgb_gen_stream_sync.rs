#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig,
    merkle::{Graftable, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        any::{VariableConfig as AnyConfig, ordered::variable::Db as AnyDb},
        current::{VariableConfig as CurrentConfig, ordered::variable::Db as CurrentDb},
        immutable::variable::{Config as ImmutableConfig, Db as ImmutableDb},
        keyless::variable::{Config as KeylessConfig, Db as KeylessDb},
        sync,
    },
    translator::TwoCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize, non_empty_range};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
    sync::Arc,
};

const MAX_OPERATIONS: usize = 16;
const PAGE_SIZE: NonZeroU16 = NZU16!(141);
const BITMAP_CHUNK_BYTES: usize = 32;

type Any<F> = AnyDb<F, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;
type Current<F> = CurrentDb<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;
type Immutable<F> =
    ImmutableDb<F, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;
type Keyless<F> = KeylessDb<F, deterministic::Context, Digest, Sha256, Sequential>;

#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Update { key: [u8; 32], value: [u8; 32] },
    Delete { key: [u8; 32] },
    Commit,
    StreamSync,
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    operations: Vec<Operation>,
    fetch_batch_size: u8,
    apply_batch_size: u8,
    max_outstanding: u8,
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
            fetch_batch_size: u.arbitrary()?,
            apply_batch_size: u.arbitrary()?,
            max_outstanding: u.arbitrary()?,
        })
    }
}

fn journal_config<C: Clone>(
    name: &str,
    pooler: &impl BufferPooler,
    codec_config: C,
) -> JournalConfig<C> {
    JournalConfig {
        partition: format!("{name}-log"),
        items_per_section: NZU64!(7),
        write_buffer: NZUsize!(1024),
        compression: None,
        codec_config,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8)),
    }
}

fn merkle_config(name: &str, pooler: &impl BufferPooler) -> MerkleConfig<Sequential> {
    MerkleConfig {
        journal_partition: format!("{name}-merkle"),
        metadata_partition: format!("{name}-metadata"),
        items_per_blob: NZU64!(11),
        write_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8)),
    }
}

fn any_config(name: &str, pooler: &impl BufferPooler) -> AnyConfig<TwoCap, ((), ()), Sequential> {
    AnyConfig {
        merkle_config: merkle_config(name, pooler),
        journal_config: journal_config(name, pooler, ((), ())),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(16)),
        init_buffer: NZUsize!(1 << 16),
        init_concurrency: (),
    }
}

fn current_config(
    name: &str,
    pooler: &impl BufferPooler,
) -> CurrentConfig<TwoCap, ((), ()), Sequential> {
    CurrentConfig {
        merkle_config: merkle_config(name, pooler),
        journal_config: journal_config(name, pooler, ((), ())),
        grafted_metadata_partition: format!("{name}-grafted"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(16)),
        init_buffer: NZUsize!(1 << 16),
        init_concurrency: (),
    }
}

fn immutable_config(
    name: &str,
    pooler: &impl BufferPooler,
) -> ImmutableConfig<TwoCap, ((), ()), Sequential> {
    ImmutableConfig {
        merkle_config: merkle_config(name, pooler),
        log: journal_config(name, pooler, ((), ())),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(16)),
        init_buffer: NZUsize!(1 << 16),
    }
}

fn keyless_config(name: &str, pooler: &impl BufferPooler) -> KeylessConfig<(), Sequential> {
    KeylessConfig {
        merkle: merkle_config(name, pooler),
        log: journal_config(name, pooler, ()),
    }
}

fn sync_sizes(input: &FuzzInput) -> (u64, usize, usize) {
    (
        u64::from(input.fetch_batch_size) + 1,
        usize::from(input.apply_batch_size) + 1,
        usize::from(input.max_outstanding) + 1,
    )
}

fn fuzz_any<F: Graftable>(input: &FuzzInput, family: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let source_name = format!("qmgb-sync-any-source-{family}");
        let mut source: Any<F> =
            Any::init(context.child("source"), any_config(&source_name, &context))
                .await
                .expect("init Any sync source");
        let mut mutations = BTreeMap::new();
        let mut syncs = 0usize;
        for operation in &input.operations {
            match operation {
                Operation::Update { key, value } => {
                    mutations.insert(Digest::from(*key), Some(Digest::from(*value)));
                }
                Operation::Delete { key } => {
                    mutations.insert(Digest::from(*key), None);
                }
                Operation::Commit => {
                    let mut batch = source.new_batch();
                    for (key, value) in std::mem::take(&mut mutations) {
                        batch = batch.write(key, value);
                    }
                    let start = source.bounds().end;
                    let batch = batch
                        .merkleize(&source, None)
                        .await
                        .expect("merkleize Any source");
                    let expected_root = batch.root();
                    let range;
                    (source, range) = source
                        .apply_batch(batch)
                        .await
                        .expect("apply Any source batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, source.bounds().end);
                    assert_eq!(source.root(), expected_root);
                    source = source.commit().await.expect("commit Any source");
                }
                Operation::StreamSync => {
                    let target = sync::Target::new(
                        source.root(),
                        non_empty_range!(source.sync_boundary(), source.bounds().end),
                    );
                    let expected_root = source.root();
                    let expected_bounds = target.range.start()..target.range.end();
                    let source_arc = Arc::new(source);
                    let (fetch, apply, outstanding) = sync_sizes(input);
                    let destination: Any<F> = sync::sync(sync::engine::Config {
                        context: context
                            .child("destination")
                            .with_attribute("instance", syncs),
                        resolver: source_arc.clone(),
                        target,
                        max_outstanding_requests: outstanding,
                        fetch_batch_size: NZU64!(fetch),
                        apply_batch_size: apply,
                        db_config: any_config(
                            &format!("qmgb-sync-any-dest-{family}-{syncs}"),
                            &context,
                        ),
                        update_rx: None,
                        finish_rx: None,
                        reached_target_tx: None,
                        max_retained_roots: 4,
                    })
                    .await
                    .expect("sync Any variable db");
                    assert_eq!(destination.root(), expected_root);
                    assert_eq!(destination.bounds(), expected_bounds);
                    destination
                        .destroy()
                        .await
                        .expect("destroy Any destination");
                    source = Arc::try_unwrap(source_arc)
                        .unwrap_or_else(|_| panic!("Any source still shared"));
                    syncs += 1;
                }
            }
        }
        source.destroy().await.expect("destroy Any source");
    });
}

fn fuzz_current<F: Graftable>(input: &FuzzInput, family: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let source_name = format!("qmgb-sync-current-source-{family}");
        let mut source: Current<F> = Current::init(
            context.child("source"),
            current_config(&source_name, &context),
        )
        .await
        .expect("init Current sync source");
        let mut mutations = BTreeMap::new();
        let mut syncs = 0usize;
        for operation in &input.operations {
            match operation {
                Operation::Update { key, value } => {
                    mutations.insert(Digest::from(*key), Some(Digest::from(*value)));
                }
                Operation::Delete { key } => {
                    mutations.insert(Digest::from(*key), None);
                }
                Operation::Commit => {
                    let mut batch = source.new_batch();
                    for (key, value) in std::mem::take(&mut mutations) {
                        batch = batch.write(key, value);
                    }
                    let start = source.bounds().end;
                    let batch = batch
                        .merkleize(&source, None)
                        .await
                        .expect("merkleize Current source");
                    let expected_root = batch.root();
                    let range;
                    (source, range) = source
                        .apply_batch(batch)
                        .await
                        .expect("apply Current source batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, source.bounds().end);
                    assert_eq!(source.root(), expected_root);
                    source = source.commit().await.expect("commit Current source");
                }
                Operation::StreamSync => {
                    let target = sync::Target::new(
                        source.ops_root(),
                        non_empty_range!(source.sync_boundary(), source.bounds().end),
                    );
                    let expected_root = source.root();
                    let expected_ops_root = source.ops_root();
                    let expected_bounds = target.range.start()..target.range.end();
                    let source_arc = Arc::new(source);
                    let (fetch, apply, outstanding) = sync_sizes(input);
                    let destination: Current<F> = sync::sync(sync::engine::Config {
                        context: context
                            .child("destination")
                            .with_attribute("instance", syncs),
                        resolver: source_arc.clone(),
                        target,
                        max_outstanding_requests: outstanding,
                        fetch_batch_size: NZU64!(fetch),
                        apply_batch_size: apply,
                        db_config: current_config(
                            &format!("qmgb-sync-current-dest-{family}-{syncs}"),
                            &context,
                        ),
                        update_rx: None,
                        finish_rx: None,
                        reached_target_tx: None,
                        max_retained_roots: 4,
                    })
                    .await
                    .expect("sync Current variable db");
                    assert_eq!(destination.ops_root(), expected_ops_root);
                    assert_eq!(destination.root(), expected_root);
                    assert_eq!(destination.bounds(), expected_bounds);
                    destination
                        .destroy()
                        .await
                        .expect("destroy Current destination");
                    source = Arc::try_unwrap(source_arc)
                        .unwrap_or_else(|_| panic!("Current source still shared"));
                    syncs += 1;
                }
            }
        }
        source.destroy().await.expect("destroy Current source");
    });
}

fn fuzz_immutable<F: Graftable>(input: &FuzzInput, family: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let source_name = format!("qmgb-sync-immutable-source-{family}");
        let mut source: Immutable<F> = Immutable::init(
            context.child("source"),
            immutable_config(&source_name, &context),
        )
        .await
        .expect("init Immutable sync source");
        let mut values = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut syncs = 0usize;
        for operation in &input.operations {
            match operation {
                Operation::Update { key, value } => {
                    let key = Digest::from(*key);
                    if seen.insert(key) {
                        values.insert(key, Digest::from(*value));
                    }
                }
                Operation::Delete { .. } => {}
                Operation::Commit => {
                    let mut batch = source.new_batch();
                    for (key, value) in std::mem::take(&mut values) {
                        batch = batch.set(key, value);
                    }
                    let start = source.bounds().end;
                    let batch = batch
                        .merkleize(&source, None, source.inactivity_floor_loc())
                        .await;
                    let expected_root = batch.root();
                    let range;
                    (source, range) = source
                        .apply_batch(batch)
                        .await
                        .expect("apply Immutable source batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, source.bounds().end);
                    assert_eq!(source.root(), expected_root);
                    source = source.commit().await.expect("commit Immutable source");
                }
                Operation::StreamSync => {
                    let target = sync::Target::new(
                        source.root(),
                        non_empty_range!(source.sync_boundary(), source.bounds().end),
                    );
                    let expected_root = source.root();
                    let expected_bounds = target.range.start()..target.range.end();
                    let source_arc = Arc::new(source);
                    let (fetch, apply, outstanding) = sync_sizes(input);
                    let destination: Immutable<F> = sync::sync(sync::engine::Config {
                        context: context
                            .child("destination")
                            .with_attribute("instance", syncs),
                        resolver: source_arc.clone(),
                        target,
                        max_outstanding_requests: outstanding,
                        fetch_batch_size: NZU64!(fetch),
                        apply_batch_size: apply,
                        db_config: immutable_config(
                            &format!("qmgb-sync-immutable-dest-{family}-{syncs}"),
                            &context,
                        ),
                        update_rx: None,
                        finish_rx: None,
                        reached_target_tx: None,
                        max_retained_roots: 4,
                    })
                    .await
                    .expect("sync Immutable variable db");
                    assert_eq!(destination.root(), expected_root);
                    assert_eq!(destination.bounds(), expected_bounds);
                    destination
                        .destroy()
                        .await
                        .expect("destroy Immutable destination");
                    source = Arc::try_unwrap(source_arc)
                        .unwrap_or_else(|_| panic!("Immutable source still shared"));
                    syncs += 1;
                }
            }
        }
        source.destroy().await.expect("destroy Immutable source");
    });
}

fn fuzz_keyless<F: Graftable>(input: &FuzzInput, family: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let source_name = format!("qmgb-sync-keyless-source-{family}");
        let mut source: Keyless<F> = Keyless::init(
            context.child("source"),
            keyless_config(&source_name, &context),
        )
        .await
        .expect("init Keyless sync source");
        let mut values = Vec::new();
        let mut syncs = 0usize;
        for operation in &input.operations {
            match operation {
                Operation::Update { value, .. } => values.push(Digest::from(*value)),
                Operation::Delete { key } => values.push(Digest::from(*key)),
                Operation::Commit => {
                    let mut batch = source.new_batch();
                    for value in values.drain(..) {
                        batch = batch.append(value);
                    }
                    let start = source.bounds().end;
                    let batch = batch
                        .merkleize(&source, None, source.inactivity_floor_loc())
                        .await;
                    let expected_root = batch.root();
                    let range;
                    (source, range) = source
                        .apply_batch(batch)
                        .await
                        .expect("apply Keyless source batch");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, source.bounds().end);
                    assert_eq!(source.root(), expected_root);
                    source = source.commit().await.expect("commit Keyless source");
                }
                Operation::StreamSync => {
                    let target = sync::Target::new(
                        source.root(),
                        non_empty_range!(source.sync_boundary(), source.bounds().end),
                    );
                    let expected_root = source.root();
                    let expected_bounds = target.range.start()..target.range.end();
                    let source_arc = Arc::new(source);
                    let (fetch, apply, outstanding) = sync_sizes(input);
                    let destination: Keyless<F> = sync::sync(sync::engine::Config {
                        context: context
                            .child("destination")
                            .with_attribute("instance", syncs),
                        resolver: source_arc.clone(),
                        target,
                        max_outstanding_requests: outstanding,
                        fetch_batch_size: NZU64!(fetch),
                        apply_batch_size: apply,
                        db_config: keyless_config(
                            &format!("qmgb-sync-keyless-dest-{family}-{syncs}"),
                            &context,
                        ),
                        update_rx: None,
                        finish_rx: None,
                        reached_target_tx: None,
                        max_retained_roots: 4,
                    })
                    .await
                    .expect("sync Keyless variable db");
                    assert_eq!(destination.root(), expected_root);
                    assert_eq!(destination.bounds(), expected_bounds);
                    destination
                        .destroy()
                        .await
                        .expect("destroy Keyless destination");
                    source = Arc::try_unwrap(source_arc)
                        .unwrap_or_else(|_| panic!("Keyless source still shared"));
                    syncs += 1;
                }
            }
        }
        source.destroy().await.expect("destroy Keyless source");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_any::<mmr::Family>(&input, "mmr");
    fuzz_any::<mmb::Family>(&input, "mmb");
    fuzz_current::<mmr::Family>(&input, "mmr");
    fuzz_current::<mmb::Family>(&input, "mmb");
    fuzz_immutable::<mmr::Family>(&input, "mmr");
    fuzz_immutable::<mmb::Family>(&input, "mmb");
    fuzz_keyless::<mmr::Family>(&input, "mmr");
    fuzz_keyless::<mmb::Family>(&input, "mmb");
});
