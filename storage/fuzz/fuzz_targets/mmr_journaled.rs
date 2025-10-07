#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::mmr::{
    journaled::{Config, Mmr, SyncConfig},
    location::{Location, LocationRangeExt},
    Position, StandardHasher as Standard,
};
use commonware_utils::{NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 200;
const MAX_DATA_SIZE: usize = 64;
const PAGE_SIZE: usize = 111;
const PAGE_CACHE_SIZE: usize = 5;
const ITEMS_PER_BLOB: u64 = 7;

#[derive(Arbitrary, Debug, Clone)]
enum MmrJournaledOperation {
    Add { data: Vec<u8> },
    AddBatched { data: Vec<u8> },
    Pop { count: u8 },
    GetNode { pos: u64 },
    Proof { location: u64 },
    RangeProof { start_loc: u8, end_loc: u8 },
    HistoricalRangeProof { start_loc: u8, end_loc: u8 },
    Sync,
    ProcessUpdates,
    PruneAll,
    PruneToPos { pos: u64 },
    GetRoot,
    GetSize,
    GetLeaves,
    GetLastLeafPos,
    IsDirty,
    GetPrunedToPos,
    GetOldestRetainedPos,
    Close,
    Reinit,
    InitFromPinnedNodes { size: u64 },
    InitSync { lower_bound: u64, upper_bound: u64 },
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

fn test_config(partition_suffix: &str) -> Config {
    Config {
        journal_partition: format!("journal_{partition_suffix}"),
        metadata_partition: format!("metadata_{partition_suffix}"),
        items_per_blob: NZU64!(ITEMS_PER_BLOB),
        write_buffer: NZUsize!(1024),
        thread_pool: None,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|context| async move {
        let mut leaves = Vec::new();
        let mut hasher = Standard::<Sha256>::new();
        let mmr = Mmr::init(
            context.clone(),
            &mut hasher,
            test_config("fuzz_test_mmr_journaled"),
        )
        .await
        .unwrap();

        let mut has_batched_updates = false;
        let mut historical_sizes = Vec::new();
        let mut mmr_opt = Some(mmr);

        for op in input.operations {
            if mmr_opt.is_none() && !matches!(op, MmrJournaledOperation::Reinit) {
                continue;
            }

            let mmr = match mmr_opt.as_mut() {
                Some(m) => m,
                None => continue,
            };

            match op {
                MmrJournaledOperation::Add { data } => {
                    if has_batched_updates {
                        continue;
                    }

                    let limited_data = if data.len() > MAX_DATA_SIZE {
                        &data[0..MAX_DATA_SIZE]
                    } else {
                        &data
                    };

                    if limited_data.is_empty() {
                        continue;
                    }

                    let size_before = mmr.size();
                    let pos = mmr.add(&mut hasher, limited_data).await.unwrap();
                    leaves.push(limited_data.to_vec());
                    historical_sizes.push(mmr.size());
                    assert!(mmr.size() > size_before);
                    assert_eq!(mmr.last_leaf_pos(), Some(pos));
                }

                MmrJournaledOperation::AddBatched { data } => {
                    let limited_data = if data.len() > MAX_DATA_SIZE {
                        &data[0..MAX_DATA_SIZE]
                    } else {
                        &data
                    };

                    if limited_data.is_empty() {
                        continue;
                    }

                    let size_before = mmr.size();
                    let pos = mmr.add_batched(&mut hasher, limited_data).await.unwrap();
                    leaves.push(limited_data.to_vec());
                    has_batched_updates = true;

                    historical_sizes.push(mmr.size());
                    assert!(mmr.size() > size_before);
                    assert_eq!(mmr.last_leaf_pos(), Some(pos));
                }

                MmrJournaledOperation::Pop { count } => {
                    if count as u64 > mmr.leaves() {
                        continue;
                    }
                    mmr.process_updates(&mut hasher);

                    let _ = mmr.pop(count as usize).await;
                    let new_len = mmr.leaves();
                    leaves.truncate(new_len.as_u64() as usize);
                }

                MmrJournaledOperation::GetNode { pos } => {
                    let _ = mmr.get_node(Position::new(pos)).await;
                }

                MmrJournaledOperation::Proof { location } => {
                    if mmr.leaves() == 0 {
                        continue;
                    }
                    mmr.process_updates(&mut hasher);
                    let location = location % mmr.leaves().as_u64();
                    let location = Location::new(location);
                    let position = Position::from(location);

                    if position > mmr.size() || position < mmr.pruned_to_pos() {
                        continue;
                    }

                    let element = leaves.get(location.as_u64() as usize).unwrap();

                    if let Ok(proof) = mmr.proof(location).await {
                        let root = mmr.root(&mut hasher);
                        assert!(proof.verify_element_inclusion(
                            &mut hasher,
                            element,
                            location,
                            &root,
                        ));
                    }
                }

                MmrJournaledOperation::RangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc.clamp(0, u8::MAX - 1);
                    let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                    let start_loc = start_loc as u64;

                    if mmr.leaves() == 0 {
                        continue;
                    }
                    let range = Location::new(start_loc)..Location::new(end_loc);
                    let start_pos = Position::from(range.start);

                    if start_loc >= mmr.leaves()
                        || end_loc >= mmr.leaves()
                        || start_pos < mmr.pruned_to_pos()
                        || start_pos >= mmr.size()
                    {
                        continue;
                    }

                    mmr.process_updates(&mut hasher);
                    if let Ok(proof) = mmr.range_proof(range.clone()).await {
                        let root = mmr.root(&mut hasher);
                        assert!(proof.verify_range_inclusion(
                            &mut hasher,
                            &leaves[range.to_usize_range()],
                            Location::new(start_loc),
                            &root
                        ));
                    }
                }

                MmrJournaledOperation::HistoricalRangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc.clamp(0, u8::MAX - 1);
                    let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                    let start_loc = start_loc as u64;

                    if mmr.leaves() == 0 {
                        continue;
                    }
                    // Ensure the size represents a valid MMR structure
                    let start_pos = Position::from(start_loc);
                    if start_loc >= mmr.leaves()
                        || end_loc >= mmr.leaves()
                        || start_pos < mmr.pruned_to_pos()
                        || start_pos >= mmr.size()
                    {
                        continue;
                    }
                    let range = Location::new(start_loc)..Location::new(end_loc);
                    mmr.process_updates(&mut hasher);
                    if let Ok(historical_proof) =
                        mmr.historical_range_proof(mmr.size(), range.clone()).await
                    {
                        let root = mmr.root(&mut hasher);
                        assert!(historical_proof.verify_range_inclusion(
                            &mut hasher,
                            &leaves[range.to_usize_range()],
                            Location::new(start_loc),
                            &root
                        ));
                    }
                }

                MmrJournaledOperation::Sync => {
                    mmr.sync(&mut hasher).await.unwrap();
                    has_batched_updates = false;
                    assert!(!mmr.is_dirty());
                }

                MmrJournaledOperation::ProcessUpdates => {
                    mmr.process_updates(&mut hasher);
                    has_batched_updates = false;
                    assert!(!mmr.is_dirty());
                }

                MmrJournaledOperation::PruneAll => {
                    mmr.process_updates(&mut hasher);
                    mmr.prune_all(&mut hasher).await.unwrap();
                }

                MmrJournaledOperation::PruneToPos { pos } => {
                    mmr.process_updates(&mut hasher);
                    if mmr.size() > 0 {
                        let safe_pos = pos % (mmr.size() + 1).as_u64();
                        mmr.prune_to_pos(&mut hasher, safe_pos.into())
                            .await
                            .unwrap();
                        assert!(mmr.pruned_to_pos() <= mmr.size());
                    }
                }

                MmrJournaledOperation::GetRoot => {
                    mmr.process_updates(&mut hasher);
                    let _ = mmr.root(&mut hasher);
                }

                MmrJournaledOperation::GetSize => {
                    let _ = mmr.size();
                }

                MmrJournaledOperation::GetLeaves => {
                    let leaves = mmr.leaves().as_u64();
                    assert!(leaves <= mmr.size().as_u64());
                }

                MmrJournaledOperation::GetLastLeafPos => {
                    let last_pos = mmr.last_leaf_pos();
                    if mmr.size() > 0 && mmr.leaves() > 0 {
                        assert!(last_pos.is_some());
                    }
                }

                MmrJournaledOperation::IsDirty => {
                    let _ = mmr.is_dirty();
                }

                MmrJournaledOperation::GetPrunedToPos => {
                    let pruned_pos = mmr.pruned_to_pos();
                    assert!(pruned_pos <= mmr.size());
                }

                MmrJournaledOperation::GetOldestRetainedPos => {
                    let oldest = mmr.oldest_retained_pos();
                    if let Some(pos) = oldest {
                        assert!(pos >= mmr.pruned_to_pos());
                        assert!(pos < mmr.size());
                    }
                }

                MmrJournaledOperation::Close => {
                    if let Some(mmr_instance) = mmr_opt.take() {
                        mmr_instance.close(&mut hasher).await.unwrap();
                        has_batched_updates = false;
                        historical_sizes.clear();
                    }
                }

                MmrJournaledOperation::Reinit => {
                    if mmr_opt.is_none() {
                        let new_mmr = Mmr::init(
                            context.clone(),
                            &mut hasher,
                            test_config("fuzz_test_mmr_journaled"),
                        )
                        .await
                        .unwrap();
                        has_batched_updates = false;
                        historical_sizes.clear();
                        mmr_opt = Some(new_mmr);
                    }
                }

                MmrJournaledOperation::InitFromPinnedNodes { size } => {
                    if mmr.size() > 0 {
                        // Ensure limited_size doesn't exceed current MMR size
                        let limited_size = ((size % mmr.size().as_u64()).max(1)).min(*mmr.size());

                        // Create a reasonable number of pinned nodes - use a simple heuristic
                        // For small MMRs, we need fewer pinned nodes; for larger ones, we need more
                        let estimated_pins = ((limited_size as f64).log2().ceil() as usize).max(1);

                        let pinned_nodes: Vec<Digest> = (0..estimated_pins)
                            .map(|i| Sha256::hash(&(i as u32).to_be_bytes()))
                            .collect();

                        if let Ok(new_mmr) = Mmr::<_, Sha256>::init_from_pinned_nodes(
                            context.clone(),
                            pinned_nodes.clone(),
                            limited_size.into(),
                            test_config("pinned"),
                        )
                        .await
                        {
                            assert_eq!(new_mmr.size(), limited_size);
                            assert_eq!(new_mmr.pruned_to_pos(), limited_size);
                            new_mmr.destroy().await.unwrap();
                        }
                    }
                }

                MmrJournaledOperation::InitSync {
                    lower_bound,
                    upper_bound,
                } => {
                    let safe_lower = Position::new(lower_bound % 1000);
                    let safe_upper = Position::new(*(safe_lower + (upper_bound % 100)));

                    let sync_config = SyncConfig {
                        config: test_config("sync"),
                        range: safe_lower..safe_upper,
                        pinned_nodes: None,
                    };

                    if let Ok(sync_mmr) =
                        Mmr::<_, Sha256>::init_sync(context.clone(), sync_config).await
                    {
                        assert!(sync_mmr.size() <= safe_upper);
                        assert_eq!(sync_mmr.pruned_to_pos(), safe_lower);
                        sync_mmr.destroy().await.unwrap();
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
