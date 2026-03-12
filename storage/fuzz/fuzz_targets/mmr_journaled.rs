#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_storage::mmr::{
    journaled::{Config, Mmr, SyncConfig},
    location::{Location, LocationRangeExt},
    mem, Error, Position, StandardHasher as Standard,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_OPERATIONS: usize = 200;
const MAX_DATA_SIZE: usize = 64;
const PAGE_SIZE: NonZeroU16 = NZU16!(111);
const PAGE_CACHE_SIZE: usize = 5;
const ITEMS_PER_BLOB: u64 = 7;

#[derive(Arbitrary, Debug, Clone)]
enum MmrJournaledOperation {
    Add {
        data: Vec<u8>,
    },
    AddBatched {
        items: Vec<Vec<u8>>,
    },
    GetNode {
        pos: u64,
    },
    Proof {
        location: u64,
    },
    RangeProof {
        start_loc: u8,
        end_loc: u8,
    },
    HistoricalRangeProof {
        start_loc: u8,
        end_loc: u8,
    },
    Sync,
    PruneAll,
    PruneToPos {
        pos: u64,
    },
    GetRoot,
    GetSize,
    GetLeaves,
    GetPrunedToPos,
    GetOldestRetainedPos,
    Reinit,
    InitSync {
        lower_bound_seed: u16,
        upper_bound_seed: u16,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<MmrJournaledOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput { seed, operations })
    }
}

fn test_config(partition_suffix: &str, pooler: &impl BufferPooler) -> Config {
    Config {
        journal_partition: format!("journal-{partition_suffix}"),
        metadata_partition: format!("metadata-{partition_suffix}"),
        items_per_blob: NZU64!(ITEMS_PER_BLOB),
        write_buffer: NZUsize!(1024),
        thread_pool: None,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
    }
}

fn historical_root(
    leaves: &[Vec<u8>],
    requested_leaves: Location,
) -> <Sha256 as commonware_cryptography::Hasher>::Digest {
    let hasher = Standard::<Sha256>::new();
    let mut mmr = mem::Mmr::new(&hasher);
    let changeset = {
        let mut batch = mmr.new_batch();
        for element in leaves.iter().take(requested_leaves.as_u64() as usize) {
            batch.add(&hasher, element);
        }
        batch.merkleize(&hasher).finalize()
    };
    mmr.apply(changeset).unwrap();
    *mmr.root()
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|context| async move {
        let mut leaves = Vec::new();
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Mmr::init(
            context.clone(),
            &hasher,
            test_config("fuzz-test-mmr-journaled", &context),
        )
        .await
        .unwrap();

        // Historical leaf counts that are valid for proofs against the current MMR lineage.
        let mut historical_sizes: Vec<Location> = Vec::new();
        let mut restarts = 0usize;

        for op in input.operations {
            match op {
                MmrJournaledOperation::Add { data } => {
                    let limited_data = if data.len() > MAX_DATA_SIZE {
                        &data[0..MAX_DATA_SIZE]
                    } else {
                        &data
                    };

                    if limited_data.is_empty() {
                        continue;
                    }

                    let size_before = mmr.size();
                    let (pos, changeset) = {
                        let mut batch = mmr.new_batch();
                        let pos = batch.add(&hasher, limited_data);
                        (pos, batch.merkleize(&hasher).finalize())
                    };
                    mmr.apply(changeset).unwrap();
                    leaves.push(limited_data.to_vec());
                    historical_sizes.push(mmr.leaves());
                    assert!(mmr.size() > size_before);
                    assert_eq!(Position::try_from(mmr.leaves() - 1).unwrap(), pos);
                }

                MmrJournaledOperation::AddBatched { items } => {
                    let items: Vec<&[u8]> = items
                        .iter()
                        .map(|d| {
                            if d.len() > MAX_DATA_SIZE {
                                &d[..MAX_DATA_SIZE]
                            } else {
                                d.as_slice()
                            }
                        })
                        .filter(|d| !d.is_empty())
                        .collect();

                    if items.is_empty() {
                        continue;
                    }

                    let size_before = mmr.size();
                    let (positions, changeset) = {
                        let mut batch = mmr.new_batch();
                        let positions: Vec<_> =
                            items.iter().map(|item| batch.add(&hasher, item)).collect();
                        (positions, batch.merkleize(&hasher).finalize())
                    };
                    mmr.apply(changeset).unwrap();
                    assert!(mmr.size() > size_before);

                    for (item, pos) in items.iter().zip(&positions) {
                        leaves.push(item.to_vec());
                        // Convert leaf position to location, then +1 for count.
                        let loc = Location::try_from(*pos).unwrap();
                        historical_sizes.push(loc + 1);
                    }
                    assert_eq!(
                        Position::try_from(mmr.leaves() - 1).unwrap(),
                        *positions.last().unwrap()
                    );
                }

                MmrJournaledOperation::GetNode { pos } => {
                    let _ = mmr.get_node(Position::new(pos)).await;
                }

                MmrJournaledOperation::Proof { location } => {
                    if mmr.leaves() > 0 {
                        let location = location % mmr.leaves().as_u64();
                        let location = Location::new(location);
                        let bounds = mmr.bounds();
                        if bounds.contains(&location) {
                            let element = leaves.get(location.as_u64() as usize).unwrap();

                            if let Ok(proof) = mmr.proof(&hasher, location).await {
                                let root = mmr.root();
                                assert!(proof
                                    .verify_element_inclusion(&hasher, element, location, &root,));
                            }
                        }
                    }
                }

                MmrJournaledOperation::RangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc.clamp(0, u8::MAX - 1);
                    let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                    let start_loc = start_loc as u64;

                    if mmr.leaves() > 0 {
                        let range = Location::new(start_loc)..Location::new(end_loc);
                        if start_loc < mmr.leaves()
                            && end_loc < mmr.leaves()
                            && mmr.bounds().contains(&range.start)
                        {
                            if let Ok(proof) = mmr.range_proof(&hasher, range.clone()).await {
                                let root = mmr.root();
                                assert!(proof.verify_range_inclusion(
                                    &hasher,
                                    &leaves[range.to_usize_range()],
                                    Location::new(start_loc),
                                    &root
                                ));
                            }
                        }
                    }
                }

                MmrJournaledOperation::HistoricalRangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc as u64;
                    let end_loc = (end_loc as u64).clamp(start_loc, u8::MAX as u64);
                    let range = Location::new(start_loc)..Location::new(end_loc);
                    let requested_leaves = if historical_sizes.is_empty() {
                        mmr.leaves()
                    } else {
                        let seed = (start_loc + end_loc) as usize;
                        let idx = seed % historical_sizes.len();
                        historical_sizes[idx]
                    };
                    let expected_root = historical_root(&leaves, requested_leaves);

                    let result = mmr
                        .historical_range_proof(&hasher, requested_leaves, range.clone())
                        .await;
                    match result {
                        Ok(historical_proof) => {
                            let verify_hasher = Standard::<Sha256>::new();
                            assert!(historical_proof.verify_range_inclusion(
                                &verify_hasher,
                                &leaves[range.to_usize_range()],
                                range.start,
                                &expected_root
                            ));
                        }
                        Err(Error::RangeOutOfBounds(_)) => {
                            assert!(range.end > requested_leaves);
                        }
                        Err(Error::Empty) => {
                            assert!(range.is_empty());
                        }
                        Err(Error::ElementPruned(_)) => {
                            assert!(!mmr.bounds().contains(&range.start));
                        }
                        Err(err) => panic!("unexpected historical_range_proof error: {err:?}"),
                    }
                }

                MmrJournaledOperation::Sync => {
                    mmr.sync().await.unwrap();
                }

                MmrJournaledOperation::PruneAll => {
                    mmr.prune_all().await.unwrap();
                }

                MmrJournaledOperation::PruneToPos { pos } => {
                    if mmr.size() > 0 {
                        let safe_loc = Location::new(pos % (*mmr.leaves() + 1));
                        mmr.prune(safe_loc).await.unwrap();
                        assert!(mmr.bounds().start <= mmr.leaves());
                    }
                }

                MmrJournaledOperation::GetRoot => {
                    let _ = mmr.root();
                }

                MmrJournaledOperation::GetSize => {
                    let _ = mmr.size();
                }

                MmrJournaledOperation::GetLeaves => {
                    let (leaf_count, size) = (mmr.leaves().as_u64(), mmr.size().as_u64());
                    assert!(leaf_count <= size);
                }

                MmrJournaledOperation::GetPrunedToPos => {
                    let pruned_loc = mmr.bounds().start;
                    assert!(pruned_loc <= mmr.leaves());
                }

                MmrJournaledOperation::GetOldestRetainedPos => {
                    let bounds = mmr.bounds();
                    if !bounds.is_empty() {
                        assert!(bounds.start < mmr.leaves());
                    }
                }

                MmrJournaledOperation::Reinit => {
                    // Init a new MMR
                    drop(mmr);
                    mmr = Mmr::init(
                        context
                            .with_label("mmr")
                            .with_attribute("instance", restarts),
                        &hasher,
                        test_config("fuzz-test-mmr-journaled", &context),
                    )
                    .await
                    .unwrap();
                    restarts += 1;

                    // Truncate tracking variables to match recovered state
                    let recovered_leaves = mmr.leaves().as_u64() as usize;
                    leaves.truncate(recovered_leaves);
                    historical_sizes.truncate(recovered_leaves);
                }

                MmrJournaledOperation::InitSync {
                    lower_bound_seed,
                    upper_bound_seed,
                } => {
                    const MAX_RANGE_SIZE: u64 = 1000;

                    let lower_bound_loc = Location::new(lower_bound_seed as u64 % MAX_RANGE_SIZE);
                    // +1 to ensure the range is non-empty
                    let upper_bound_loc = Location::new(
                        *(lower_bound_loc + ((upper_bound_seed as u64) % MAX_RANGE_SIZE) + 1),
                    );

                    let sync_config = SyncConfig {
                        config: test_config("sync", &context),
                        range: lower_bound_loc..upper_bound_loc,
                        pinned_nodes: None,
                    };

                    if let Ok(sync_mmr) = Mmr::init_sync(
                        context
                            .with_label("sync")
                            .with_attribute("instance", restarts),
                        sync_config,
                        &hasher,
                    )
                    .await
                    {
                        assert!(sync_mmr.leaves() <= upper_bound_loc);
                        assert_eq!(sync_mmr.bounds().start, lower_bound_loc);
                        sync_mmr.destroy().await.unwrap();
                    }
                    restarts += 1;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
