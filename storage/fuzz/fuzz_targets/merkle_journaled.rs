#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_storage::merkle::{
    hasher::Standard, journaled::Config, mem::Mem, mmb, mmr, Error, Family as MerkleFamily,
    Location, LocationRangeExt as _, Position,
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
enum MerkleJournaledOperation {
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
    operations: Vec<MerkleJournaledOperation>,
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

fn test_config(partition_suffix: &str, page_cache: CacheRef) -> Config {
    Config {
        journal_partition: format!("journal-{partition_suffix}"),
        metadata_partition: format!("metadata-{partition_suffix}"),
        items_per_blob: NZU64!(ITEMS_PER_BLOB),
        write_buffer: NZUsize!(1024),
        thread_pool: None,
        page_cache,
    }
}

fn historical_root<F: MerkleFamily>(
    leaves: &[Vec<u8>],
    requested_leaves: Location<F>,
) -> <Sha256 as commonware_cryptography::Hasher>::Digest {
    let hasher = Standard::<Sha256>::new();
    let mut mem = Mem::<F, _>::new(&hasher);
    let batch = {
        let mut batch = mem.new_batch();
        for element in leaves.iter().take(requested_leaves.as_u64() as usize) {
            batch = batch.add(&hasher, element);
        }
        batch.merkleize(&mem, &hasher)
    };
    mem.apply_batch(&batch).unwrap();
    *mem.root()
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    type Journaled<F, E, D> = commonware_storage::merkle::journaled::Journaled<F, E, D>;
    type SyncConfig<F, D> = commonware_storage::merkle::journaled::SyncConfig<F, D>;

    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|context| {
        let operations = input.operations.clone();
        async move {
            let mut leaves = Vec::new();
            let hasher = Standard::<Sha256>::new();
            let page_cache = CacheRef::from_pooler(
                context.with_label("cache"),
                PAGE_SIZE,
                NZUsize!(PAGE_CACHE_SIZE),
            );
            let mut merkle = Journaled::<F, _, _>::init(
                context.with_label("merkle"),
                &hasher,
                test_config(suffix, page_cache.clone()),
            )
            .await
            .unwrap();

            // Historical leaf counts that are valid for proofs against the current lineage.
            let mut historical_sizes: Vec<Location<F>> = Vec::new();
            let mut restarts = 0usize;

            for op in operations {
                match op {
                    MerkleJournaledOperation::Add { data } => {
                        let limited_data = if data.len() > MAX_DATA_SIZE {
                            &data[0..MAX_DATA_SIZE]
                        } else {
                            &data
                        };

                        if limited_data.is_empty() {
                            continue;
                        }

                        let size_before = merkle.size();
                        let batch = merkle.new_batch();
                        let loc = batch.leaves();
                        let batch = merkle.with_mem(|mem| {
                            batch.add(&hasher, limited_data).merkleize(mem, &hasher)
                        });
                        merkle.apply_batch(&batch).unwrap();
                        leaves.push(limited_data.to_vec());
                        historical_sizes.push(merkle.leaves());
                        assert!(merkle.size() > size_before);
                        assert_eq!(merkle.leaves() - 1, loc);
                    }

                    MerkleJournaledOperation::AddBatched { items } => {
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

                        let size_before = merkle.size();
                        let (locations, batch) = {
                            let mut batch = merkle.new_batch();
                            let mut locations = Vec::with_capacity(items.len());
                            for item in &items {
                                locations.push(batch.leaves());
                                batch = batch.add(&hasher, item);
                            }
                            (
                                locations,
                                merkle.with_mem(|mem| batch.merkleize(mem, &hasher)),
                            )
                        };
                        merkle.apply_batch(&batch).unwrap();
                        assert!(merkle.size() > size_before);

                        for (item, loc) in items.iter().zip(&locations) {
                            leaves.push(item.to_vec());
                            // +1 for count.
                            historical_sizes.push(*loc + 1);
                        }
                        assert_eq!(merkle.leaves() - 1, *locations.last().unwrap());
                    }

                    MerkleJournaledOperation::GetNode { pos } => {
                        let _ = merkle.get_node(Position::<F>::new(pos)).await;
                    }

                    MerkleJournaledOperation::Proof { location } => {
                        if merkle.leaves() > 0 {
                            let location = location % merkle.leaves().as_u64();
                            let location = Location::<F>::new(location);
                            let bounds = merkle.bounds();
                            if bounds.contains(&location) {
                                let element = leaves.get(location.as_u64() as usize).unwrap();

                                if let Ok(proof) = merkle.proof(&hasher, location).await {
                                    let root = merkle.root();
                                    assert!(proof.verify_element_inclusion(
                                        &hasher, element, location, &root,
                                    ));
                                }
                            }
                        }
                    }

                    MerkleJournaledOperation::RangeProof { start_loc, end_loc } => {
                        let start_loc = start_loc.clamp(0, u8::MAX - 1);
                        let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                        let start_loc = start_loc as u64;

                        if merkle.leaves() > 0 {
                            let range = Location::<F>::new(start_loc)..Location::<F>::new(end_loc);
                            if start_loc < merkle.leaves()
                                && end_loc < merkle.leaves()
                                && merkle.bounds().contains(&range.start)
                            {
                                if let Ok(proof) = merkle.range_proof(&hasher, range.clone()).await
                                {
                                    let root = merkle.root();
                                    assert!(proof.verify_range_inclusion(
                                        &hasher,
                                        &leaves[range.to_usize_range()],
                                        Location::<F>::new(start_loc),
                                        &root
                                    ));
                                }
                            }
                        }
                    }

                    MerkleJournaledOperation::HistoricalRangeProof { start_loc, end_loc } => {
                        let start_loc = start_loc as u64;
                        let end_loc = (end_loc as u64).clamp(start_loc, u8::MAX as u64);
                        let range = Location::<F>::new(start_loc)..Location::<F>::new(end_loc);
                        let requested_leaves = if historical_sizes.is_empty() {
                            merkle.leaves()
                        } else {
                            let seed = (start_loc + end_loc) as usize;
                            let idx = seed % historical_sizes.len();
                            historical_sizes[idx]
                        };
                        let expected_root = historical_root::<F>(&leaves, requested_leaves);

                        let result = merkle
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
                                assert!(!merkle.bounds().contains(&range.start));
                            }
                            Err(err) => {
                                panic!("unexpected historical_range_proof error: {err:?}")
                            }
                        }
                    }

                    MerkleJournaledOperation::Sync => {
                        merkle.sync().await.unwrap();
                    }

                    MerkleJournaledOperation::PruneAll => {
                        merkle.prune_all().await.unwrap();
                    }

                    MerkleJournaledOperation::PruneToPos { pos } => {
                        if merkle.size() > 0 {
                            let safe_loc = Location::<F>::new(pos % (*merkle.leaves() + 1));
                            merkle.prune(safe_loc).await.unwrap();
                            assert!(merkle.bounds().start <= merkle.leaves());
                        }
                    }

                    MerkleJournaledOperation::GetRoot => {
                        let _ = merkle.root();
                    }

                    MerkleJournaledOperation::GetSize => {
                        let _ = merkle.size();
                    }

                    MerkleJournaledOperation::GetLeaves => {
                        let (leaf_count, size) = (merkle.leaves().as_u64(), merkle.size().as_u64());
                        assert!(leaf_count <= size);
                    }

                    MerkleJournaledOperation::GetPrunedToPos => {
                        let pruned_loc = merkle.bounds().start;
                        assert!(pruned_loc <= merkle.leaves());
                    }

                    MerkleJournaledOperation::GetOldestRetainedPos => {
                        let bounds = merkle.bounds();
                        if !bounds.is_empty() {
                            assert!(bounds.start < merkle.leaves());
                        }
                    }

                    MerkleJournaledOperation::Reinit => {
                        // Init a new merkle structure.
                        drop(merkle);
                        merkle = Journaled::<F, _, _>::init(
                            context
                                .with_label("merkle")
                                .with_attribute("instance", restarts),
                            &hasher,
                            test_config(suffix, page_cache.clone()),
                        )
                        .await
                        .unwrap();
                        restarts += 1;

                        // Truncate tracking variables to match recovered state.
                        let recovered_leaves = merkle.leaves().as_u64() as usize;
                        leaves.truncate(recovered_leaves);
                        historical_sizes.truncate(recovered_leaves);
                    }

                    MerkleJournaledOperation::InitSync {
                        lower_bound_seed,
                        upper_bound_seed,
                    } => {
                        const MAX_RANGE_SIZE: u64 = 1000;

                        let lower_bound_loc =
                            Location::<F>::new(lower_bound_seed as u64 % MAX_RANGE_SIZE);
                        // +1 to ensure the range is non-empty
                        let upper_bound_loc = Location::<F>::new(
                            *(lower_bound_loc + ((upper_bound_seed as u64) % MAX_RANGE_SIZE) + 1),
                        );

                        let sync_suffix = format!("{suffix}-sync");
                        let sync_config = SyncConfig::<F, _> {
                            config: test_config(&sync_suffix, page_cache.clone()),
                            range: lower_bound_loc..upper_bound_loc,
                            pinned_nodes: None,
                        };

                        if let Ok(sync_merkle) = Journaled::<F, _, _>::init_sync(
                            context
                                .with_label("sync")
                                .with_attribute("instance", restarts),
                            sync_config,
                            &hasher,
                        )
                        .await
                        {
                            assert!(sync_merkle.leaves() <= upper_bound_loc);
                            assert_eq!(sync_merkle.bounds().start, lower_bound_loc);
                            sync_merkle.destroy().await.unwrap();
                        }
                        restarts += 1;
                    }
                }
            }
        }
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "fuzz-mmr");
    fuzz_family::<mmb::Family>(&input, "fuzz-mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
