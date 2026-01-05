#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::mmr::{
    journaled::{CleanMmr, Config, DirtyMmr, Mmr, SyncConfig},
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
    Add {
        data: Vec<u8>,
    },
    AddBatched {
        data: Vec<u8>,
    },
    Pop {
        count: u8,
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
    Merkleize,
    PruneAll,
    PruneToPos {
        pos: u64,
    },
    GetRoot,
    GetSize,
    GetLeaves,
    GetLastLeafPos,
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

enum MmrState<
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    D: commonware_cryptography::Digest,
> {
    Clean(CleanMmr<E, D>),
    Dirty(DirtyMmr<E, D>),
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

        let mut historical_sizes = Vec::new();
        let mut mmr = MmrState::Clean(mmr);

        for op in input.operations {
            mmr = match op {
                MmrJournaledOperation::Add { data } => {
                    let limited_data = if data.len() > MAX_DATA_SIZE {
                        &data[0..MAX_DATA_SIZE]
                    } else {
                        &data
                    };

                    if limited_data.is_empty() {
                        continue;
                    }

                    // Add only works on Clean MMR, so merkleize if Dirty first
                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };

                    let size_before = mmr.size();
                    let pos = mmr.add(&mut hasher, limited_data).await.unwrap();
                    leaves.push(limited_data.to_vec());
                    historical_sizes.push(mmr.size());
                    assert!(mmr.size() > size_before);
                    assert_eq!(mmr.last_leaf_pos(), Some(pos));

                    MmrState::Clean(mmr)
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

                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m.into_dirty(),
                        MmrState::Dirty(m) => m,
                    };

                    let size_before = mmr.size();
                    let pos = mmr.add(&mut hasher, limited_data).await.unwrap();
                    assert!(mmr.size() > size_before);

                    leaves.push(limited_data.to_vec());
                    historical_sizes.push(mmr.size());
                    assert_eq!(mmr.last_leaf_pos(), Some(pos));

                    MmrState::Dirty(mmr)
                }

                MmrJournaledOperation::Pop { count } => {
                    // Pop requires Clean MMR
                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };

                    if count as u64 <= mmr.leaves() {
                        let _ = mmr.pop(&mut hasher, count as usize).await;
                        let new_len = mmr.leaves();
                        leaves.truncate(new_len.as_u64() as usize);
                    }
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::GetNode { pos } => {
                    let mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    let _ = mmr.get_node(Position::new(pos)).await;
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::Proof { location } => {
                    // Proof requires Clean MMR
                    let mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };

                    if mmr.leaves() > 0 {
                        let location = location % mmr.leaves().as_u64();
                        let location = Location::new(location).unwrap();
                        let position = Position::try_from(location).unwrap();

                        if position <= mmr.size() && position >= mmr.pruned_to_pos() {
                            let element = leaves.get(location.as_u64() as usize).unwrap();

                            if let Ok(proof) = mmr.proof(location).await {
                                let root = mmr.root();
                                assert!(proof.verify_element_inclusion(
                                    &mut hasher,
                                    element,
                                    location,
                                    &root,
                                ));
                            }
                        }
                    }
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::RangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc.clamp(0, u8::MAX - 1);
                    let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                    let start_loc = start_loc as u64;

                    // RangeProof requires Clean MMR
                    let state = mmr;
                    let mmr = match state {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };

                    if mmr.leaves() > 0 {
                        let range =
                            Location::new(start_loc).unwrap()..Location::new(end_loc).unwrap();
                        let start_pos = Position::try_from(range.start).unwrap();

                        if start_loc < mmr.leaves()
                            && end_loc < mmr.leaves()
                            && start_pos >= mmr.pruned_to_pos()
                            && start_pos < mmr.size()
                        {
                            if let Ok(proof) = mmr.range_proof(range.clone()).await {
                                let root = mmr.root();
                                assert!(proof.verify_range_inclusion(
                                    &mut hasher,
                                    &leaves[range.to_usize_range()],
                                    Location::new(start_loc).unwrap(),
                                    &root
                                ));
                            }
                        }
                    }
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::HistoricalRangeProof { start_loc, end_loc } => {
                    let start_loc = start_loc.clamp(0, u8::MAX - 1);
                    let end_loc = end_loc.clamp(start_loc + 1, u8::MAX) as u64;
                    let start_loc = start_loc as u64;

                    // HistoricalRangeProof requires Clean MMR
                    let state = mmr;
                    let mmr = match state {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };

                    if mmr.leaves() > 0 {
                        // Ensure the size represents a valid MMR structure
                        let start_pos = Position::from(start_loc);
                        if start_loc < mmr.leaves()
                            && end_loc < mmr.leaves()
                            && start_pos >= mmr.pruned_to_pos()
                            && start_pos < mmr.size()
                        {
                            let range =
                                Location::new(start_loc).unwrap()..Location::new(end_loc).unwrap();

                            if let Ok(historical_proof) =
                                mmr.historical_range_proof(mmr.size(), range.clone()).await
                            {
                                let root = mmr.root();
                                assert!(historical_proof.verify_range_inclusion(
                                    &mut hasher,
                                    &leaves[range.to_usize_range()],
                                    Location::new(start_loc).unwrap(),
                                    &root
                                ));
                            }
                        }
                    }
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::Sync => {
                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    mmr.sync().await.unwrap();
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::Merkleize => {
                    let state = mmr;
                    let mmr = match state {
                        MmrState::Clean(m) => m, // No-op for Clean
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::PruneAll => {
                    // PruneAll requires Clean MMR
                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    mmr.prune_all().await.unwrap();
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::PruneToPos { pos } => {
                    // PruneToPos requires Clean MMR
                    let mut mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    if mmr.size() > 0 {
                        let safe_pos = pos % (mmr.size() + 1).as_u64();
                        mmr.prune_to_pos(safe_pos.into()).await.unwrap();
                        assert!(mmr.pruned_to_pos() <= mmr.size());
                    }
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::GetRoot => {
                    // GetRoot requires Clean MMR
                    let mmr = match mmr {
                        MmrState::Clean(m) => m,
                        MmrState::Dirty(m) => m.merkleize(&mut hasher),
                    };
                    let _ = mmr.root();
                    MmrState::Clean(mmr)
                }

                MmrJournaledOperation::GetSize => {
                    match &mmr {
                        MmrState::Clean(m) => {
                            let _ = m.size();
                        }
                        MmrState::Dirty(m) => {
                            let _ = m.size();
                        }
                    }
                    mmr
                }

                MmrJournaledOperation::GetLeaves => {
                    let (leaves, size) = match &mmr {
                        MmrState::Clean(m) => (m.leaves().as_u64(), m.size().as_u64()),
                        MmrState::Dirty(m) => (m.leaves().as_u64(), m.size().as_u64()),
                    };
                    assert!(leaves <= size);
                    mmr
                }

                MmrJournaledOperation::GetLastLeafPos => {
                    match &mmr {
                        MmrState::Clean(m) => {
                            let last_pos = m.last_leaf_pos();
                            if m.size() > 0 && m.leaves() > 0 {
                                assert!(last_pos.is_some());
                            }
                        }
                        MmrState::Dirty(m) => {
                            let last_pos = m.last_leaf_pos();
                            if m.size() > 0 && m.leaves() > 0 {
                                assert!(last_pos.is_some());
                            }
                        }
                    }
                    mmr
                }

                MmrJournaledOperation::GetPrunedToPos => {
                    match &mmr {
                        MmrState::Clean(m) => {
                            let pruned_pos = m.pruned_to_pos();
                            assert!(pruned_pos <= m.size());
                        }
                        MmrState::Dirty(m) => {
                            let pruned_pos = m.pruned_to_pos();
                            assert!(pruned_pos <= m.size());
                        }
                    }
                    mmr
                }

                MmrJournaledOperation::GetOldestRetainedPos => {
                    match &mmr {
                        MmrState::Clean(m) => {
                            let oldest = m.oldest_retained_pos();
                            if let Some(pos) = oldest {
                                assert!(pos >= m.pruned_to_pos());
                                assert!(pos < m.size());
                            }
                        }
                        MmrState::Dirty(m) => {
                            let oldest = m.oldest_retained_pos();
                            if let Some(pos) = oldest {
                                assert!(pos >= m.pruned_to_pos());
                                assert!(pos < m.size());
                            }
                        }
                    }
                    mmr
                }

                MmrJournaledOperation::Reinit => {
                    // Init a new MMR
                    drop(mmr);
                    let new_mmr = Mmr::init(
                        context.clone(),
                        &mut hasher,
                        test_config("fuzz_test_mmr_journaled"),
                    )
                    .await
                    .unwrap();
                    // Reset tracking variables to match recovered state
                    leaves.clear();
                    historical_sizes.clear();
                    MmrState::Clean(new_mmr)
                }

                MmrJournaledOperation::InitSync {
                    lower_bound_seed,
                    upper_bound_seed,
                } => {
                    const MAX_RANGE_SIZE: u64 = 1000;

                    let lower_bound_pos = Position::new(lower_bound_seed as u64 % MAX_RANGE_SIZE);
                    // +1 to ensure the range is non-empty
                    let upper_bound_pos = Position::new(
                        *(lower_bound_pos + ((upper_bound_seed as u64) % MAX_RANGE_SIZE) + 1),
                    );

                    let sync_config = SyncConfig {
                        config: test_config("sync"),
                        range: lower_bound_pos..upper_bound_pos,
                        pinned_nodes: None,
                    };

                    if let Ok(sync_mmr) =
                        CleanMmr::init_sync(context.clone(), sync_config, &mut hasher).await
                    {
                        assert!(sync_mmr.size() <= upper_bound_pos);
                        assert_eq!(sync_mmr.pruned_to_pos(), lower_bound_pos);
                        sync_mmr.destroy().await.unwrap();
                    }
                    mmr
                }
            };
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
