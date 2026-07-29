#![no_main]

//! Fuzzes recovery after a mismatched QMDB sync result is interrupted during discard.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Family, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        any::{FixedConfig, unordered::fixed::Db},
        sync::{self, Target, engine::Config as SyncConfig},
    },
    translator::TwoCap,
};
use commonware_storage_fuzz::{
    RNG_BYTES, bounded_items_per_section, bounded_page_cache_size, bounded_page_size, fuzz_runner,
};
use commonware_utils::{NZU64, NZUsize, non_empty_range, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{num::NonZeroU16, sync::Arc};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type Database<F> = Db<F, Context, Key, Value, Sha256, TwoCap, Sequential>;

const MAX_OPERATIONS: usize = 32;

fn bounded_operations(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_OPERATIONS)
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    raw_bytes: [u8; RNG_BYTES],
    mmb: bool,
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    #[arbitrary(with = bounded_items_per_section)]
    items_per_blob: u64,
    #[arbitrary(with = bounded_operations)]
    operations: usize,
    key_seed: [u8; 32],
    fetch_batch_size: u8,
}

#[derive(Clone, Copy)]
struct Params {
    page_size: NonZeroU16,
    page_cache_size: usize,
    items_per_blob: u64,
    operations: usize,
    key_seed: [u8; 32],
    fetch_batch_size: u64,
}

fn config(context: &Context, suffix: &str, params: Params) -> FixedConfig<TwoCap, Sequential> {
    let page_cache =
        CacheRef::from_pooler(context, params.page_size, NZUsize!(params.page_cache_size));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{suffix}-merkle-journal"),
            metadata_partition: format!("{suffix}-merkle-metadata"),
            items_per_blob: NZU64!(params.items_per_blob),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{suffix}-log"),
            items_per_blob: NZU64!(params.items_per_blob),
            write_buffer: NZUsize!(1024),
            page_cache,
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

async fn populate<F: Family>(db: Database<F>, params: Params, generation: u8) -> Database<F> {
    let mut batch = db.new_batch();
    for index in 0..params.operations {
        let mut key = params.key_seed;
        key[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let mut value = params.key_seed;
        value[..8].copy_from_slice(&(index as u64).to_be_bytes());
        value[31] ^= generation;
        batch = batch.write(Key::new(key), Some(Value::new(value)));
    }
    let batch = batch.merkleize(&db, None).await.unwrap();
    let (db, _) = db.apply_batch(batch).await.unwrap();
    db.sync().await.unwrap()
}

fn sync_config<F: Family>(
    context: Context,
    db_config: FixedConfig<TwoCap, Sequential>,
    resolver: Arc<Database<F>>,
    target: Target<F, Digest>,
    fetch_batch_size: u64,
) -> SyncConfig<Database<F>, Arc<Database<F>>> {
    SyncConfig {
        context,
        resolver,
        target,
        db_config,
        fetch_batch_size: NZU64!(fetch_batch_size),
        apply_batch_size: 4,
        max_outstanding_requests: 2,
        update_rx: None,
        finish_rx: None,
        reached_target_tx: None,
        max_retained_roots: 0,
    }
}

fn fuzz_family<F: Family>(input: &FuzzInput, suffix: &str) {
    // Keep the rejected operation history in one blob so the injected removal fault cannot fire
    // during sync-journal pruning before the root mismatch reaches discard.
    let items_per_blob = input.items_per_blob.max(input.operations as u64 + 4);
    let params = Params {
        page_size: NonZeroU16::new(input.page_size).unwrap(),
        page_cache_size: input.page_cache_size,
        items_per_blob,
        operations: input.operations,
        key_seed: input.key_seed,
        fetch_batch_size: u64::from(input.fetch_batch_size).max(1),
    };
    let runner = fuzz_runner(&input.raw_bytes);
    let suffix = suffix.to_string();

    let (target, checkpoint) = runner.start_and_recover(|context| {
        let suffix = suffix.clone();
        async move {
            let client = Database::<F>::init(
                context.child("old_client"),
                config(&context, &format!("{suffix}-client"), params),
            )
            .await
            .unwrap();
            let client = populate(client, params, 0x55).await;
            let old_bounds = client.bounds();
            let old_root = client.root();
            drop(client);

            let source = Database::<F>::init(
                context.child("source"),
                config(&context, &format!("{suffix}-source"), params),
            )
            .await
            .unwrap();
            let source = populate(source, params, 0xAA).await;
            assert_eq!(source.bounds(), old_bounds);
            assert_ne!(source.root(), old_root);

            let target = Target::new(
                source.root(),
                non_empty_range!(source.sync_boundary(), source.bounds().end),
            );
            let source = Arc::new(source);

            *context.storage_fault_config().write() = deterministic::FaultConfig::default()
                .remove(1.0)
                .remove_batch_post_commit(1.0);
            let result = sync::sync(sync_config(
                context.child("interrupted_discard"),
                config(&context, &format!("{suffix}-client"), params),
                source.clone(),
                target.clone(),
                params.fetch_batch_size,
            ))
            .await;
            assert!(matches!(result, Err(sync::Error::Database(_))));
            drop(source);
            target
        }
    });

    let retry_suffix = suffix.clone();
    let ((target, expected_root, expected_bounds, expected_sync_boundary), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let source = Database::<F>::init(
                context.child("recovered_source"),
                config(&context, &format!("{retry_suffix}-source"), params),
            )
            .await
            .unwrap();
            assert_eq!(source.root(), target.root);
            let expected_root = source.root();
            let expected_sync_boundary = source.sync_boundary();
            let expected_bounds = expected_sync_boundary..source.bounds().end;
            let source = Arc::new(source);

            let synced = sync::sync(sync_config(
                context.child("retry"),
                config(&context, &format!("{retry_suffix}-client"), params),
                source.clone(),
                target.clone(),
                params.fetch_batch_size,
            ))
            .await
            .expect("valid retry must replace the rejected Merkle projection");
            assert_eq!(synced.root(), expected_root);
            assert_eq!(synced.bounds(), expected_bounds);
            assert_eq!(synced.sync_boundary(), expected_sync_boundary);

            drop(synced);
            drop(source);
            (
                target,
                expected_root,
                expected_bounds,
                expected_sync_boundary,
            )
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let client = Database::<F>::init(
            context.child("durable_client"),
            config(&context, &format!("{suffix}-client"), params),
        )
        .await
        .unwrap();
        assert_eq!(client.root(), expected_root);
        assert_eq!(client.bounds(), expected_bounds);
        assert_eq!(client.sync_boundary(), expected_sync_boundary);

        let source = Database::<F>::init(
            context.child("durable_source"),
            config(&context, &format!("{suffix}-source"), params),
        )
        .await
        .unwrap();
        assert_eq!(source.root(), target.root);

        client.destroy().await.unwrap();
        source.destroy().await.unwrap();
    });
}

fn fuzz(input: FuzzInput) {
    if input.mmb {
        fuzz_family::<mmb::Family>(&input, "sync-discard-mmb");
    } else {
        fuzz_family::<mmr::Family>(&input, "sync-discard-mmr");
    }
}

fuzz_target!(|input: FuzzInput| fuzz(input));
