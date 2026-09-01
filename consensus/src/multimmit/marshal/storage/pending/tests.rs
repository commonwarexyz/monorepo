//! Pending store tests: appends, segment rollover, snapshots, and pruning across reopen.

use super::{
    record::PendingRecord,
    store::{SegmentSlot, segment_len},
    *,
};
use crate::{
    multimmit::{
        marshal::storage::{Error, blocks::BlockMeta},
        testing::TestBody,
        types::{BlockRef, ChainId, TransactionBlock, TransactionBlockHeader},
    },
    types::{Epoch, Height},
};
use commonware_codec::{EncodeSize as _, FixedSize as _};
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, crc32, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{
    Blob as _, Metrics as _, ReadOptions, Runner as _, Storage as _, Supervisor as _, WriteOptions,
    buffer::paged::CacheRef,
    deterministic::{self, Context as DeterministicContext},
};
use commonware_storage::journal::segmented::{fixed, glob, oversized::Record as _};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::future::try_join_all;
use rstest::rstest;
use std::{
    collections::BTreeSet,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
type TestBlock = Arc<TransactionBlock<Sha256, TestBody>>;
type TestStore = PendingBlocks<DeterministicContext, Sha256, TestBody>;
type TestReader = BodyReader<DeterministicContext, Sha256, TestBody>;
type TestSegment = commonware_storage::journal::segmented::oversized::Oversized<
    DeterministicContext,
    PendingRecord<Sha256Digest>,
    TestBlock,
>;

/// Buffers one complete block at the next position.
async fn put_block(
    store: &mut TestStore,
    reference: BlockRef<Sha256Digest>,
    block: TestBlock,
) -> Result<(), Error> {
    if let Some(append) = store.start_put(std::iter::once((reference, block)))? {
        let append = Box::pin(append.run()).await?;
        store.finish_put(append)?;
    }
    Ok(())
}

/// Buffers blocks through as many appends as segment boundaries require.
async fn put_blocks(store: &mut TestStore, blocks: &[TestBlock]) {
    let mut blocks = blocks
        .iter()
        .map(|block| (block.reference(), block.clone()))
        .peekable();
    while blocks.peek().is_some() {
        if let Some(append) = store.start_put(blocks.by_ref()).unwrap() {
            let append = Box::pin(append.run()).await.unwrap();
            store.finish_put(append).unwrap();
        }
    }
}

/// Returns a complete block only when its body survived storage recovery.
async fn get_block(
    store: &TestStore,
    reference: BlockRef<Sha256Digest>,
) -> Result<Option<TestBlock>, Error> {
    let Some(entry) = store.entry(reference) else {
        return Ok(None);
    };
    let locator = entry.locator;
    let segment = store.segment_id(locator.position);
    if store
        .active_readers
        .get(&segment)
        .is_some_and(|reader| reader.contains(locator))
    {
        let reader = open(store.body_source(segment)).await?;
        return read(&reader, locator).await.map(Some);
    }
    if let Some(slot) = store.open_segments.get(&segment) {
        let SegmentSlot::Owned(journal) = slot else {
            return Err(Error::Inconsistent("active pending segment is lent"));
        };
        let block = journal.get_value(0, locator.offset, locator.size).await?;
        super::read::validate_body(&block, locator)?;
        return Ok(Some(block));
    }
    let reader = open(store.body_source(segment)).await?;
    read(&reader, locator).await.map(Some)
}

/// Reads blocks through planned groups, in request order.
async fn get_blocks(
    store: &TestStore,
    references: &[BlockRef<Sha256Digest>],
) -> Result<Vec<Option<TestBlock>>, Error> {
    let groups = store.body_read_groups(
        references.iter().copied().enumerate(),
        NonZeroU64::MAX,
        NonZeroUsize::MIN,
    )?;
    let mut blocks = vec![None; references.len()];
    for (output, block) in try_join_all(groups.into_iter().map(read_group))
        .await?
        .into_iter()
        .flatten()
    {
        blocks[output] = Some(block);
    }
    Ok(blocks)
}

fn owned_segment(store: &TestStore, segment: u64) -> &TestSegment {
    match store.open_segments.get(&segment) {
        Some(SegmentSlot::Owned(journal)) => journal,
        _ => panic!("segment {segment} is not owned"),
    }
}

fn take_owned_segment(store: &mut TestStore, segment: u64) -> TestSegment {
    match store.open_segments.remove(&segment) {
        Some(SegmentSlot::Owned(journal)) => journal,
        _ => panic!("segment {segment} is not owned"),
    }
}

/// Opens a planned source, cold or ready.
async fn open(
    source: BodySource<DeterministicContext, Sha256, TestBody>,
) -> Result<TestReader, Error> {
    match source {
        BodySource::Ready(reader) => Ok(reader),
        BodySource::Cold(source) => source.open().await,
    }
}

/// Reads one body through a snapshot.
async fn read(
    reader: &TestReader,
    locator: super::read::BodyLocator<Sha256Digest>,
) -> Result<TestBlock, Error> {
    reader.local_position(locator.position)?;
    let block = reader.reader.get(locator.offset, locator.size).await?;
    super::read::validate_body(&block, locator)?;
    Ok(block)
}

/// Opens a group's source and reads it.
async fn read_group(
    group: BodyReadGroup<DeterministicContext, Sha256, TestBody>,
) -> Result<Vec<(usize, TestBlock)>, Error> {
    let BodyReadGroup { source, read } = group;
    read.read(open(source).await?).await
}

fn floors(values: [Option<u64>; 2]) -> ChainFloors {
    values
        .into_iter()
        .map(|floor| floor.map(Height::new))
        .collect()
}

async fn open_with_capacity(
    context: &DeterministicContext,
    label: &'static str,
    prefix: &str,
    segment_capacity: NonZeroU64,
) -> TestStore {
    let config = PendingConfig {
        prefix: prefix.to_string(),
        buffers: JournalBuffers {
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
            key_write_buffer: NZUsize!(1024 * 1024),
            value_write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
        },
        body_codec_config: (),
        epoch: Epoch::new(7),
        chains: 2,
        segment_capacity,
        max_manifest_bytes: NZUsize!(1024 * 1024),
    };
    Box::pin(TestStore::init(context.child(label), config))
        .await
        .unwrap()
}

async fn open_store(
    context: &DeterministicContext,
    label: &'static str,
    prefix: &str,
) -> TestStore {
    open_with_capacity(context, label, prefix, NZU64!(2)).await
}

fn block(chain: u32, height: u64, nonce: u64) -> TestBlock {
    let body = TestBody::new(
        Sha256::hash(&[b"application parent"]),
        Height::new(height),
        nonce,
    );
    let header = TransactionBlockHeader::new(
        Epoch::new(7),
        ChainId::new(chain),
        Height::new(height),
        Sha256Digest::from([chain as u8; 32]),
        body.digest(),
    )
    .unwrap();
    Arc::new(TransactionBlock::new(header, body).unwrap())
}

/// Starts retirement of every full segment and returns the retired segments and their sync.
fn retire(
    store: &mut TestStore,
) -> (
    Vec<u64>,
    Option<futures::future::BoxFuture<'static, Result<(), Error>>>,
) {
    match store.start_retire().unwrap() {
        Some(retirement) => (retirement.segments, Some(retirement.sync)),
        None => (Vec::new(), None),
    }
}

/// One production-shaped durability round: the admission cut, then the retirements the
/// catalog starts once the cut completes and releases once they finish.
async fn sync(store: &mut TestStore) {
    try_join_all(store.start_sync().await.unwrap())
        .await
        .unwrap();
    let (retiring, retirement) = retire(store);
    if let Some(retirement) = retirement {
        retirement.await.unwrap();
    }
    store
        .finish_retire(retiring, &BTreeSet::new())
        .await
        .unwrap();
}

/// Storage bytes read, writes, and syncs recorded so far.
fn storage_io(context: &DeterministicContext) -> (u64, u64, u64) {
    let encoded = context.encode();
    (
        counter(&encoded, "storage_read_bytes"),
        counter(&encoded, "storage_writes"),
        counter(&encoded, "storage_syncs"),
    )
}

#[test]
fn append_read_and_exact_idempotence() {
    deterministic::Runner::default().start(|context| async move {
        let block = block(0, 1, 1);
        let reference = block.reference();
        let mut store = open_store(&context, "store", "pending_append_read").await;
        put_block(&mut store, reference, Arc::clone(&block))
            .await
            .unwrap();
        put_block(&mut store, reference, Arc::clone(&block))
            .await
            .unwrap();
        assert_eq!(store.next_position, 1);
        assert_eq!(segment_len(owned_segment(&store, 0)).unwrap(), 1);
        sync(&mut store).await;

        assert_eq!(
            get_block(&store, reference).await.unwrap().as_deref(),
            Some(block.as_ref())
        );
        let blocks = get_blocks(&store, &[reference, reference]).await.unwrap();
        assert_eq!(blocks[0].as_deref(), Some(block.as_ref()));
        assert_eq!(blocks[1].as_deref(), Some(block.as_ref()));

        let mut locator = store.entry(reference).unwrap().locator;
        locator.encoded_len += 1;
        let reader = store.active_readers.get(&0).unwrap();
        assert!(read(reader, locator).await.is_err());
    });
}

#[test]
fn batched_appends_match_single_rows_across_segments_and_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let mut single = open_with_capacity(&context, "single", "pending_single", NZU64!(3)).await;
        let mut batch = open_with_capacity(&context, "batch", "pending_batch", NZU64!(3)).await;
        let blocks = (0..7)
            .map(|i| block((i % 2) as u32, i + 1, i))
            .collect::<Vec<_>>();
        for store in [&mut single, &mut batch] {
            put_block(store, blocks[0].reference(), blocks[0].clone())
                .await
                .unwrap();
        }
        let input = [0, 1, 1, 2, 3, 3, 4, 5, 6, 6].map(|i| blocks[i].clone());
        for block in &input {
            put_block(&mut single, block.reference(), block.clone())
                .await
                .unwrap();
        }
        put_blocks(&mut batch, &[]).await;
        put_blocks(&mut batch, &input).await;
        put_blocks(&mut batch, &input).await;
        for store in [&mut single, &mut batch] {
            assert_eq!(store.next_position, blocks.len() as u64);
            for &id in store.open_segments.keys() {
                let expected = (blocks.len() as u64 - id * 3).min(3);
                assert_eq!(segment_len(owned_segment(store, id)).unwrap(), expected);
            }
            sync(store).await;
        }
        let refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        for reopened in [false, true] {
            if reopened {
                drop(single);
                drop(batch);
                single = open_with_capacity(&context, "single_reopen", "pending_single", NZU64!(3))
                    .await;
                batch =
                    open_with_capacity(&context, "batch_reopen", "pending_batch", NZU64!(3)).await;
            }
            assert_eq!(single.next_position, batch.next_position);
            assert_eq!(single.segments, batch.segments);
            for reference in &refs {
                assert_eq!(single.header(*reference), batch.header(*reference));
                assert_eq!(
                    single.by_digest[&reference.digest()].locator.position,
                    batch.by_digest[&reference.digest()].locator.position
                );
            }
            let expected = blocks.iter().cloned().map(Some).collect::<Vec<_>>();
            assert_eq!(get_blocks(&single, &refs).await.unwrap(), expected);
            assert_eq!(get_blocks(&batch, &refs).await.unwrap(), expected);
        }
    });
}

#[test]
fn owned_append_preserves_snapshot_and_publishes_only_on_completion() {
    deterministic::Runner::default().start(|context| async move {
        let mut store =
            open_with_capacity(&context, "store", "pending_owned_append", NZU64!(4)).await;
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        let third = block(1, 1, 3);
        put_block(&mut store, first.reference(), first.clone())
            .await
            .unwrap();
        sync(&mut store).await;

        let append = store
            .start_put(
                [&second, &second, &third]
                    .into_iter()
                    .map(|block| (block.reference(), block.clone())),
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            store.open_segments.get(&0),
            Some(SegmentSlot::Lent)
        ));
        let refs = [
            (0, first.reference()),
            (1, second.reference()),
            (2, third.reference()),
        ];
        let mut groups = store
            .body_read_groups(refs, NonZeroU64::MAX, NonZeroUsize::MIN)
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            read_group(groups.pop().unwrap()).await.unwrap(),
            vec![(0, first.clone())]
        );
        assert_eq!(store.next_position, 1);
        for block in [&second, &third] {
            assert!(!store.by_digest.contains_key(&block.reference().digest()));
        }

        let append = Box::pin(append.run()).await.unwrap();
        for block in [&second, &third] {
            assert!(!store.by_digest.contains_key(&block.reference().digest()));
        }
        store.finish_put(append).unwrap();
        assert!(matches!(
            store.open_segments.get(&0),
            Some(SegmentSlot::Owned(_))
        ));
        assert_eq!(store.next_position, 3);
        for block in [&second, &third] {
            assert!(store.by_digest.contains_key(&block.reference().digest()));
        }
        assert!(
            store
                .body_read_groups(
                    [(0, second.reference()), (1, third.reference())],
                    NonZeroU64::MAX,
                    NonZeroUsize::MIN,
                )
                .unwrap()
                .is_empty()
        );
        sync(&mut store).await;
        let values = get_blocks(
            &store,
            &[first.reference(), second.reference(), third.reference()],
        )
        .await
        .unwrap();
        assert_eq!(values, vec![Some(first), Some(second), Some(third)]);
    });
}

#[test]
fn duplicate_admission_lends_nothing() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_duplicate_lend").await;
        let first = block(0, 1, 1);
        put_block(&mut store, first.reference(), first.clone())
            .await
            .unwrap();
        assert!(
            store
                .start_put(std::iter::once((first.reference(), first)))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store.open_segments.get(&0),
            Some(SegmentSlot::Owned(_))
        ));
    });
}

#[test]
fn segment_rollover_owns_one_oversized_section_per_segment() {
    deterministic::Runner::default().start(|context| async move {
        let prefix = "pending_single_blob_segments";
        let mut store = open_store(&context, "store", prefix).await;
        let references = fill_first_segment(&mut store).await;

        for segment in 0..=1 {
            for family in ["bodies", "metadata"] {
                let partition = format!("{prefix}_{family}_{segment}");
                assert_eq!(
                    context.scan(&partition).await.unwrap(),
                    vec![0u64.to_be_bytes().to_vec()],
                    "pending segments own one oversized section: {partition}"
                );
            }
        }

        drop(store);
        let mut store = open_store(&context, "reopened", prefix).await;
        for reference in references {
            assert_eq!(
                get_block(&store, reference)
                    .await
                    .unwrap()
                    .unwrap()
                    .reference(),
                reference
            );
        }
        let next = block(1, 2, 4);
        let reference = next.reference();
        put_block(&mut store, reference, next).await.unwrap();
        sync(&mut store).await;
        assert_eq!(store.next_position, 4);
        assert_eq!(
            get_block(&store, reference)
                .await
                .unwrap()
                .unwrap()
                .reference(),
            reference
        );
    });
}

#[test]
fn only_full_snapshots_are_exposed_as_immutable() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_snapshot_bound").await;
        for height in 1..=5 {
            let block = block(0, height, height);
            put_block(&mut store, block.reference(), block)
                .await
                .unwrap();
        }

        // The completed cut is the catalog's offer point: every cut segment has a frozen
        // reader, and only the full ones are exposed as immutable.
        try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            store.active_readers.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            store
                .immutable_body_readers()
                .iter()
                .map(BodyReader::segment)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        // Retirement keeps full segments readable while it seals their markers. The next
        // admission cut may drop advisory readers because cold opens read immutable values.
        let (retiring, retirement) = retire(&mut store);
        assert_eq!(retiring, vec![0, 1]);
        assert_eq!(
            store.active_readers.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            store.open_segments.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
        try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            store.active_readers.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
        let (_, writes, syncs) = storage_io(&context);
        retirement.unwrap().await.unwrap();
        let (_, writes_after, syncs_after) = storage_io(&context);
        assert_eq!(
            writes_after - writes,
            2,
            "one marker update per retired segment"
        );
        assert_eq!(syncs_after - syncs, 2, "no data fsync beyond the markers");
        store
            .finish_retire(retiring, &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(
            store.active_readers.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );

        sync(&mut store).await;
        assert_eq!(
            store.active_readers.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
        assert!(store.immutable_body_readers().is_empty());
    });
}

#[test]
fn retiring_segments_defer_reclamation_until_they_finish() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_retiring_reclaim").await;
        for height in 1..=5 {
            let block = block(0, height, height);
            put_block(&mut store, block.reference(), block)
                .await
                .unwrap();
        }
        try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        let (retiring, retirement) = retire(&mut store);
        assert_eq!(retiring, vec![0, 1]);

        // Pruning past every block must not destroy a segment whose checkpoints are still
        // being written; the retirement finishing reclaims the deferred segments itself.
        let reclaimed = store
            .prune(&floors([Some(6), None]), &BTreeSet::new())
            .await
            .unwrap();
        assert!(reclaimed.is_empty());
        retirement.unwrap().await.unwrap();
        let reclaimed = store
            .finish_retire(retiring, &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(reclaimed, vec![0, 1]);
    });
}

#[test]
fn asymmetric_prune_survives_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let retained = block(0, 1, 1);
        let pruned = block(1, 1, 2);
        let also_pruned = block(1, 2, 3);
        let mut store = open_store(&context, "first", "pending_asymmetric").await;
        for block in [&retained, &pruned, &also_pruned] {
            put_block(&mut store, block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        sync(&mut store).await;
        store
            .prune(&floors([None, Some(3)]), &BTreeSet::new())
            .await
            .unwrap();
        assert!(
            get_block(&store, retained.reference())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            get_block(&store, pruned.reference())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_block(&store, also_pruned.reference())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.segments.iter().copied().collect::<Vec<_>>(),
            vec![0, 1]
        );
        drop(store);

        let store = open_store(&context, "reopen", "pending_asymmetric").await;
        assert!(
            get_block(&store, retained.reference())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            get_block(&store, pruned.reference())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_block(&store, also_pruned.reference())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.segments.iter().copied().collect::<Vec<_>>(),
            vec![0, 1]
        );
    });
}

#[test]
fn fully_pruned_store_keeps_its_append_coordinate() {
    deterministic::Runner::default().start(|context| async move {
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        let mut store = open_store(&context, "first", "pending_empty").await;
        put_block(&mut store, first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        sync(&mut store).await;
        store
            .prune(&floors([Some(2), None]), &BTreeSet::new())
            .await
            .unwrap();
        drop(store);

        let mut store = open_store(&context, "reopen", "pending_empty").await;
        assert_eq!(store.next_position, 1);
        put_block(&mut store, second.reference(), Arc::clone(&second))
            .await
            .unwrap();
        sync(&mut store).await;
        drop(store);

        let store = open_store(&context, "second_reopen", "pending_empty").await;
        assert!(
            get_block(&store, second.reference())
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn durable_floor_precedes_physical_reclamation() {
    deterministic::Runner::default().start(|context| async move {
        let retained = block(0, 1, 1);
        let pruned = block(1, 1, 2);
        let mut store = open_store(&context, "first", "pending_prune_cut").await;
        put_block(&mut store, retained.reference(), Arc::clone(&retained))
            .await
            .unwrap();
        put_block(&mut store, pruned.reference(), Arc::clone(&pruned))
            .await
            .unwrap();
        sync(&mut store).await;

        assert!(store.advance_floors(&floors([None, Some(2)])).unwrap());
        store.persist_manifest().await.unwrap();
        drop(store);

        let store = open_store(&context, "reopen", "pending_prune_cut").await;
        assert!(
            get_block(&store, retained.reference())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            get_block(&store, pruned.reference())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn prune_rejects_floors_for_another_chain_count() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_prune_chains").await;
        assert!(matches!(
            store
                .prune(&ChainFloors::unchanged(3), &BTreeSet::new())
                .await,
            Err(Error::Inconsistent(_))
        ));
    });
}

#[test]
fn snapshot_survives_prune_and_segment_destruction() {
    deterministic::Runner::default().start(|context| async move {
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        let current = block(1, 1, 3);
        let first_ref = first.reference();
        let current_ref = current.reference();
        let mut store = open_store(&context, "store", "pending_snapshot_prune").await;
        put_block(&mut store, first_ref, Arc::clone(&first))
            .await
            .unwrap();
        put_block(&mut store, second.reference(), second)
            .await
            .unwrap();
        sync(&mut store).await;
        let reader = store.active_readers.get(&0).unwrap().clone();
        let locator = store.entry(first_ref).unwrap().locator;

        put_block(&mut store, current_ref, current).await.unwrap();
        sync(&mut store).await;
        let reclaimed = store
            .prune(&floors([Some(3), None]), &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(reclaimed, vec![0]);
        assert!(!store.segments.contains(&0));
        assert_eq!(read(&reader, locator).await.unwrap().reference(), first_ref);
        drop(store);

        let store = open_store(&context, "reopen", "pending_snapshot_prune").await;
        assert!(get_block(&store, first_ref).await.unwrap().is_none());
        assert!(get_block(&store, current_ref).await.unwrap().is_some());
    });
}

#[test]
fn planned_cold_read_pins_segment_until_materialized() {
    deterministic::Runner::default().start(|context| async move {
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        let current = block(1, 1, 3);
        let first_ref = first.reference();
        let mut store = open_store(&context, "store", "pending_pinned_read").await;
        put_block(&mut store, first_ref, first).await.unwrap();
        put_block(&mut store, second.reference(), second)
            .await
            .unwrap();
        sync(&mut store).await;
        put_block(&mut store, current.reference(), current)
            .await
            .unwrap();
        sync(&mut store).await;

        let group = store
            .body_read_groups([(0, first_ref)], NonZeroU64::MAX, NonZeroUsize::MIN)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(group.segment(), 0);
        let reclaimed = store
            .prune(&floors([Some(3), None]), &BTreeSet::from([0]))
            .await
            .unwrap();
        assert!(reclaimed.is_empty());
        assert!(store.segments.contains(&0));
        assert_eq!(read_group(group).await.unwrap()[0].1.reference(), first_ref);

        let reclaimed = store
            .prune(&floors([Some(3), None]), &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(reclaimed, vec![0]);
        assert!(!store.segments.contains(&0));
    });
}

#[test]
fn body_reads_fan_out_duplicate_positions_and_validate_each_locator() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_duplicate_reads").await;
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        for block in [&first, &second] {
            put_block(&mut store, block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        sync(&mut store).await;

        let mut groups = store
            .body_read_groups(
                [
                    (2, first.reference()),
                    (0, second.reference()),
                    (1, first.reference()),
                ],
                NonZeroU64::MAX,
                NonZeroUsize::MIN,
            )
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            read_group(groups.pop().unwrap()).await.unwrap(),
            vec![
                (0, second),
                (1, Arc::clone(&first)),
                (2, Arc::clone(&first))
            ],
        );

        let mut group = store
            .body_read_groups(
                [(0, first.reference()), (1, first.reference())],
                NonZeroU64::MAX,
                NonZeroUsize::MIN,
            )
            .unwrap()
            .pop()
            .unwrap();
        group.read.entries[1].1.encoded_len += 1;
        assert!(matches!(
            read_group(group).await,
            Err(Error::Inconsistent(_))
        ));
    });
}

#[test]
fn body_read_groups_plan_only_readable_references() {
    deterministic::Runner::default().start(|context| async move {
        let mut store =
            open_with_capacity(&context, "store", "pending_group_boundaries", NZU64!(3)).await;
        let blocks = (1..=7)
            .map(|height| block(0, height, height))
            .collect::<Vec<_>>();
        put_blocks(&mut store, &blocks).await;
        sync(&mut store).await;

        let block_bytes = u64::try_from(blocks[0].encode_size()).unwrap();
        let unknown = block(1, 1, 99);
        let requests = [6, 2, 4, 1, 5, 0, 3]
            .into_iter()
            .map(|index| blocks[index].reference())
            .chain([unknown.reference()]);
        let groups = store
            .body_read_groups(
                requests.enumerate(),
                NonZeroU64::new(block_bytes * 2).unwrap(),
                NonZeroUsize::MIN,
            )
            .unwrap();
        let planned = groups
            .into_iter()
            .map(|group| {
                let BodyReadGroup { read, .. } = group;
                (
                    read.segment(),
                    read.encoded_bytes(),
                    read.entries
                        .iter()
                        .map(|(_, locator)| locator.position)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            planned,
            vec![
                (0, block_bytes * 2, vec![0, 1]),
                (0, block_bytes, vec![2]),
                (1, block_bytes * 2, vec![3, 4]),
                (1, block_bytes, vec![5]),
                (2, block_bytes, vec![6]),
            ]
        );
    });
}

#[rstest]
fn asymmetric_uncommitted_tail_recovers(#[values(false, true)] index_only: bool) {
    deterministic::Runner::default().start(|context| async move {
        let first = block(0, 1, 1);
        let tail = block(0, 2, 2);
        let prefix = "pending_asymmetric_suffix";
        let mut store = open_with_capacity(&context, "first", prefix, NZU64!(4)).await;
        put_block(&mut store, first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        sync(&mut store).await;
        let values_cfg = store.body_config(0);
        let cfg = store.segment_config(0);
        take_owned_segment(&mut store, 0).close().await.unwrap();
        drop(store);

        if index_only {
            let index = fixed::Journal::<_, PendingRecord<Sha256Digest>>::init(
                context.child("missing_value"),
                fixed::Config {
                    partition: cfg.index_partition,
                    page_cache: cfg.index_page_cache,
                    write_buffer: cfg.index_write_buffer,
                },
            )
            .await
            .unwrap();
            let mut replay = index
                .replay(0, 0, cfg.replay_buffer, ReadOptions::default())
                .await
                .unwrap();
            while let Some(row) = replay.next().await {
                row.unwrap();
            }
            let index = replay.finish().unwrap();
            let missing = PendingRecord::unplaced(BlockMeta::new(
                tail.header().clone(),
                tail.encode_size() as u64,
            ))
            .with_location(
                (first.encode_size() + crc32::Digest::SIZE) as u64,
                (tail.encode_size() + crc32::Digest::SIZE) as u32,
            );
            let (index, position) = index.append(0, &missing).await.unwrap();
            assert_eq!(position, 1);
            drop(index.sync_all().await.unwrap());
        } else {
            let values =
                glob::Glob::<_, TestBlock>::init(context.child("orphan_values"), values_cfg)
                    .await
                    .unwrap();
            let (values, _, _) = values.append(0, &Arc::clone(&tail)).await.unwrap();
            drop(values.sync_all().await.unwrap());
        }

        let mut store = open_with_capacity(&context, "reopen", prefix, NZU64!(4)).await;
        assert_eq!(store.next_position, 1);
        assert_eq!(
            get_block(&store, first.reference())
                .await
                .unwrap()
                .as_deref(),
            Some(first.as_ref())
        );
        assert!(get_block(&store, tail.reference()).await.unwrap().is_none());
        put_block(&mut store, tail.reference(), Arc::clone(&tail))
            .await
            .unwrap();
        sync(&mut store).await;
        drop(store);
        let store = open_with_capacity(&context, "again", prefix, NZU64!(4)).await;
        assert_eq!(
            get_block(&store, tail.reference())
                .await
                .unwrap()
                .as_deref(),
            Some(tail.as_ref())
        );
    });
}

#[test]
fn invalid_uncommitted_middle_discards_a_valid_later_body() {
    deterministic::Runner::default().start(|context| async move {
        let prefix = "pending_middle_tail";
        let blocks = [block(0, 1, 1), block(0, 2, 2), block(1, 1, 3)];
        let mut store = open_with_capacity(&context, "first", prefix, NZU64!(4)).await;
        put_block(&mut store, blocks[0].reference(), Arc::clone(&blocks[0]))
            .await
            .unwrap();
        sync(&mut store).await;
        take_owned_segment(&mut store, 0).close().await.unwrap();
        drop(store);
        let mut store = open_with_capacity(&context, "append", prefix, NZU64!(4)).await;
        put_blocks(&mut store, &blocks[1..]).await;
        let offset = store.by_digest[&blocks[1].reference().digest()]
            .locator
            .offset;
        let partition = store.body_config(0).partition;
        drop(take_owned_segment(&mut store, 0).sync_all().await.unwrap());
        drop(store);

        let (blob, _) = context.open(&partition, &0u64.to_be_bytes()).await.unwrap();
        let bytes = blob
            .read_at(offset, 1, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        blob.write_at(offset, vec![bytes.as_ref()[0] ^ 0xff], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);

        let store = open_with_capacity(&context, "recover", prefix, NZU64!(4)).await;
        assert_eq!(store.next_position, 1);
        assert_eq!(
            get_block(&store, blocks[0].reference())
                .await
                .unwrap()
                .as_deref(),
            Some(blocks[0].as_ref())
        );
        for block in &blocks[1..] {
            assert!(store.header(block.reference()).is_none());
        }
    });
}

#[rstest]
fn unpublished_segment_is_reset_before_reuse(#[values(false, true)] corrupt: bool) {
    deterministic::Runner::default().start(|context| async move {
        let prefix = "pending_unpublished_segment";
        let blocks = [block(0, 1, 1), block(0, 2, 2), block(0, 3, 3)];
        let mut store = open_store(&context, "first", prefix).await;
        put_blocks(&mut store, &blocks[..2]).await;
        sync(&mut store).await;
        put_block(&mut store, blocks[2].reference(), Arc::clone(&blocks[2]))
            .await
            .unwrap();
        take_owned_segment(&mut store, 1).close().await.unwrap();
        let partitions = store.segment_partitions(1).all();
        drop(store);
        if corrupt {
            for partition in &partitions {
                drop(context.open(partition, b"invalid").await.unwrap());
            }
        }

        let mut store = open_store(&context, "reopen", prefix).await;
        assert_eq!(store.segments.iter().copied().collect::<Vec<_>>(), vec![0]);
        assert_eq!(store.next_position, 2);
        for block in &blocks[..2] {
            assert_eq!(
                get_block(&store, block.reference())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(block.as_ref())
            );
        }
        assert!(
            get_block(&store, blocks[2].reference())
                .await
                .unwrap()
                .is_none()
        );
        put_block(&mut store, blocks[2].reference(), Arc::clone(&blocks[2]))
            .await
            .unwrap();
        sync(&mut store).await;
        drop(store);
        let store = open_store(&context, "final", prefix).await;
        assert_eq!(
            get_block(&store, blocks[2].reference())
                .await
                .unwrap()
                .as_deref(),
            Some(blocks[2].as_ref())
        );
    });
}

#[test]
fn below_floor_admission_is_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let stale = block(0, 1, 1);
        let mut store = open_store(&context, "store", "pending_below_floor").await;
        store
            .prune(&floors([Some(2), None]), &BTreeSet::new())
            .await
            .unwrap();

        assert!(
            put_block(&mut store, stale.reference(), stale)
                .await
                .is_err()
        );
    });
}

/// Extract a metric counter's value from encoded metrics output.
fn counter(buffer: &str, name: &str) -> u64 {
    buffer
        .lines()
        .find(|line| line.contains(name) && !line.starts_with('#'))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .expect("counter missing")
}

/// Buffers blocks that fill segment 0 and roll into segment 1.
async fn put_first_segment(store: &mut TestStore) -> Vec<BlockRef<Sha256Digest>> {
    let blocks = [block(0, 1, 1), block(0, 2, 2), block(1, 1, 3)];
    let references = blocks.iter().map(|block| block.reference()).collect();
    for block in blocks {
        put_block(store, block.reference(), block).await.unwrap();
    }
    references
}

/// Fills segment 0, rolls into segment 1, and runs production-shaped durability rounds.
async fn fill_first_segment(store: &mut TestStore) -> Vec<BlockRef<Sha256Digest>> {
    let references = put_first_segment(store).await;
    sync(store).await;
    // The next cut drops segment 0's admission-time reader, so later reads are cold.
    sync(store).await;
    references
}

/// Opens segment 0 cold and asserts the open wrote and synced nothing.
async fn cold_open_without_writes(context: &DeterministicContext, store: &TestStore) -> TestReader {
    let (_, writes, syncs) = storage_io(context);
    let reader = open(store.body_source(0)).await.unwrap();
    let (_, writes_after, syncs_after) = storage_io(context);
    assert_eq!(writes_after, writes, "a retired cold open must not write");
    assert_eq!(syncs_after, syncs, "a retired cold open must not sync");
    reader
}

#[test]
fn retired_segment_cold_opens_without_replay_or_writes() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_retired_cold").await;
        let references = fill_first_segment(&mut store).await;

        // A cold source opens the immutable value section directly without recovery I/O.
        let (read_bytes, _, _) = storage_io(&context);
        let reader = cold_open_without_writes(&context, &store).await;
        let (read_after, _, _) = storage_io(&context);
        let locator = store.entry(references[0]).unwrap().locator;
        assert_eq!(read_after - read_bytes, 0, "cold open read storage data");
        assert_eq!(
            read(&reader, locator).await.unwrap().reference(),
            references[0]
        );
    });
}

#[test]
fn cold_open_preserves_the_snapshot_extent() {
    deterministic::Runner::default().start(|context| async move {
        let mut store =
            open_with_capacity(&context, "store", "pending_snapshot_extent", NZU64!(4)).await;
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        put_block(&mut store, first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        sync(&mut store).await;
        let reader = open(store.body_source(0)).await.unwrap();
        put_block(&mut store, second.reference(), Arc::clone(&second))
            .await
            .unwrap();
        sync(&mut store).await;
        let locator = store.entry(second.reference()).unwrap().locator;
        assert!(read(&reader, locator).await.is_err());
    });
}

#[test]
fn dirty_full_segment_defers_its_retirement_to_the_covering_cut() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_dirty_retire").await;
        let first = block(0, 1, 1);
        let filler = block(0, 2, 2);
        let next = block(1, 1, 3);
        let filler_reference = filler.reference();
        put_block(&mut store, first.reference(), first)
            .await
            .unwrap();
        let cut = store.start_sync().await.unwrap();
        // The segment fills while its first cut is still in flight, so its tail is not
        // covered by that cut.
        put_block(&mut store, filler_reference, filler)
            .await
            .unwrap();
        put_block(&mut store, next.reference(), next).await.unwrap();
        try_join_all(cut).await.unwrap();

        // The catalog retires on cut completion; the dirty tail defers this segment's
        // retirement and keeps its journals appendable for the covering cut.
        assert!(store.start_retire().unwrap().is_none());
        sync(&mut store).await;
        sync(&mut store).await;

        let reader = cold_open_without_writes(&context, &store).await;
        let locator = store.entry(filler_reference).unwrap().locator;
        assert_eq!(
            read(&reader, locator).await.unwrap().reference(),
            filler_reference
        );
    });
}

#[test]
fn unretired_full_segment_self_heals_on_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "first", "pending_unretired_reopen").await;
        let references = put_first_segment(&mut store).await;
        // Crash window: the admission cut completes but the retirement never runs.
        try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        drop(store);

        // Startup validates the unproven suffix and seals the recovered segment before closing it.
        let store = open_store(&context, "reopen", "pending_unretired_reopen").await;
        for reference in &references {
            assert!(get_block(&store, *reference).await.unwrap().is_some());
        }
        cold_open_without_writes(&context, &store).await;
    });
}

#[test]
fn active_and_cold_segments_batch_adjacent_runs() {
    deterministic::Runner::default().start(|context| async move {
        let mut store =
            open_with_capacity(&context, "store", "pending_replay_runs", NZU64!(4)).await;
        let blocks = (0..7)
            .map(|height| block(0, height + 1, height))
            .collect::<Vec<_>>();
        put_blocks(&mut store, &blocks).await;
        sync(&mut store).await;
        sync(&mut store).await;
        assert!(!store.active_readers.contains_key(&0));

        // Positions 0, 1, and 3 of the retired segment: two adjacent runs, one hole. Each
        // run is one sequential replay, so the reads stay bounded by runs, not by pages.
        let reader = open(store.body_source(0)).await.unwrap();
        assert!(reader.immutable);
        let requests = [
            blocks[3].reference(),
            blocks[0].reference(),
            blocks[1].reference(),
        ];
        let groups = store
            .body_read_groups(
                requests.iter().copied().enumerate(),
                NonZeroU64::MAX,
                NonZeroUsize::MIN,
            )
            .unwrap();
        assert_eq!(groups.len(), 1);
        let BodyReadGroup { read: planned, .. } = groups.into_iter().next().unwrap();
        let reads = counter(&context.encode(), "storage_reads");
        let mut results = planned.read(reader).await.unwrap();
        assert_eq!(
            counter(&context.encode(), "storage_reads") - reads,
            2,
            "two cold runs must issue two value reads"
        );
        results.sort_by_key(|(output, _)| *output);
        assert_eq!(results.len(), 3);
        for (output, block) in results {
            assert_eq!(block.reference(), requests[output]);
        }

        // The current segment uses its captured snapshot, but the same two runs still batch
        // into exactly two value reads.
        let current = store.active_readers.get(&1).unwrap();
        assert!(!current.immutable);
        let groups = store
            .body_read_groups(
                [(0, blocks[4].reference()), (1, blocks[6].reference())],
                NonZeroU64::MAX,
                NonZeroUsize::MIN,
            )
            .unwrap();
        let BodyReadGroup {
            source,
            read: planned,
        } = groups.into_iter().next().unwrap();
        let reads = counter(&context.encode(), "storage_reads");
        let results = planned.read(open(source).await.unwrap()).await.unwrap();
        assert_eq!(
            counter(&context.encode(), "storage_reads") - reads,
            2,
            "two active runs must issue two value reads"
        );
        assert_eq!(results.len(), 2);
        assert_eq!(
            get_block(&store, blocks[6].reference())
                .await
                .unwrap()
                .as_deref(),
            Some(blocks[6].as_ref())
        );
    });
}

#[test]
fn reclaimed_segments_are_removed_by_name_without_reads() {
    deterministic::Runner::default().start(|context| async move {
        let mut store = open_store(&context, "store", "pending_reclaim_by_name").await;
        let references = fill_first_segment(&mut store).await;

        // Retired contents need not be recoverable, including malformed blob names.
        let partition = store.body_config(0).partition;
        drop(context.open(&partition, b"invalid").await.unwrap());
        let reads = counter(&context.encode(), "storage_reads");
        let reclaimed = store
            .prune(&floors([Some(3), None]), &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(reclaimed, vec![0]);
        assert_eq!(counter(&context.encode(), "storage_reads"), reads);
        assert!(matches!(
            context.scan(&partition).await,
            Err(commonware_runtime::Error::PartitionMissing(_))
        ));
        drop(store);

        let store = open_store(&context, "reopen", "pending_reclaim_by_name").await;
        assert!(get_block(&store, references[0]).await.unwrap().is_none());
        assert_eq!(
            get_block(&store, references[2])
                .await
                .unwrap()
                .unwrap()
                .reference(),
            references[2]
        );
    });
}

#[test]
fn cold_segments_close_between_cuts() {
    deterministic::Runner::default().start(|context| async move {
        let first = block(0, 1, 1);
        let second = block(0, 2, 2);
        let third = block(1, 1, 3);
        let fourth = block(1, 2, 4);
        let fifth = block(0, 3, 5);
        let first_ref = first.reference();
        let second_ref = second.reference();
        let third_ref = third.reference();
        let mut store = open_store(&context, "store", "pending_cold_segments").await;

        put_block(&mut store, first.reference(), Arc::clone(&first))
            .await
            .unwrap();
        put_block(&mut store, second.reference(), second)
            .await
            .unwrap();
        sync(&mut store).await;
        put_block(&mut store, third.reference(), third)
            .await
            .unwrap();
        put_block(&mut store, fourth.reference(), fourth)
            .await
            .unwrap();
        sync(&mut store).await;
        put_block(&mut store, fifth.reference(), fifth)
            .await
            .unwrap();
        sync(&mut store).await;

        assert_eq!(
            store.open_segments.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
        put_block(&mut store, first_ref, Arc::clone(&first))
            .await
            .unwrap();
        assert_eq!(
            store.open_segments.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );

        let blocks = get_blocks(&store, &[first_ref, second_ref, third_ref])
            .await
            .unwrap();
        assert!(blocks.iter().all(Option::is_some));
        assert_eq!(
            store.open_segments.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );

        store
            .prune(&floors([Some(2), None]), &BTreeSet::new())
            .await
            .unwrap();
        assert!(get_block(&store, first_ref).await.unwrap().is_none());
        assert!(get_block(&store, second_ref).await.unwrap().is_some());
        assert_eq!(
            store.open_segments.keys().copied().collect::<Vec<_>>(),
            vec![2]
        );
    });
}
