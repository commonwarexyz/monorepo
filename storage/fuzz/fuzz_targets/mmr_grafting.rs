#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{Hasher as CHasher, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::mmr::{
    grafting::{Hasher, Storage, Verifier},
    hasher::Hasher as HasherTrait,
    mem::Mmr,
    stability::build_test_mmr,
    storage::Storage as StorageTrait,
    verification::range_proof,
    StandardHasher,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};

const MAX_OPERATIONS: usize = 100;
const MAX_LEAVES: usize = 50;
const MAX_ELEMENT_SIZE: usize = 128;
const MAX_GRAFTING_HEIGHT: u32 = 8;
const MAX_BATCH_SIZE: usize = 10;

#[derive(Arbitrary, Debug, Clone)]
enum GraftingOperation {
    InitBaseMmr {
        num_leaves: u8,
    },
    InitPeakTree {
        grafting_height: u8,
        num_leaves: u8,
    },
    LoadGraftedDigests {
        leaf_indices: Vec<u8>,
    },
    AddToPeakTree {
        element: Vec<u8>,
    },
    AddToBaseMmr {
        element: Vec<u8>,
    },
    ComputeLeafDigest {
        pos: u64,
        element: Vec<u8>,
    },
    ComputeNodeDigest {
        pos: u64,
    },
    ComputeRoot,
    Fork,
    CreateVerifier {
        height: u8,
        num: u64,
        elements: Vec<Vec<u8>>,
    },
    VerifyProof {
        leaf_num: u8,
    },
    VerifyRangeProof {
        start_leaf: u8,
        end_leaf: u8,
    },
    GetNodeFromStorage {
        pos: u64,
    },
    ComputeStorageRoot,
    AddBatchToBaseMmr {
        batch: Vec<Vec<u8>>,
    },
    AddBatchToPeakTree {
        batch: Vec<Vec<u8>>,
    },
    PopFromBaseMmr,
    PopFromPeakTree,
    GetSizeFromStorage,
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<GraftingOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary::<u64>()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput { seed, operations })
    }
}

fn limit_element_size(data: &[u8]) -> &[u8] {
    if data.len() > MAX_ELEMENT_SIZE {
        &data[0..MAX_ELEMENT_SIZE]
    } else {
        data
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|_context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);
        let mut standard_hasher: StandardHasher<Sha256> = StandardHasher::new();

        let mut base_mmr: Option<Mmr<Sha256>> = None;
        let mut peak_tree: Option<Mmr<Sha256>> = None;
        let mut grafting_height = 1u32;
        let mut loaded_digests: Vec<u64> = Vec::new();
        let mut fork_created = false;

        for op in input.operations {
            match op {
                GraftingOperation::InitBaseMmr { num_leaves } => {
                    let mut mmr = Mmr::new();

                    if num_leaves == 0 {
                        // Use build_test_mmr for standard initialization
                        build_test_mmr(&mut standard_hasher, &mut mmr);
                    } else {
                        // Custom initialization with specified number of leaves
                        let leaves_count = (num_leaves as usize % MAX_LEAVES).max(1);
                        for i in 0..leaves_count {
                            standard_hasher.inner().update(&i.to_be_bytes());
                            let element = standard_hasher.inner().finalize();
                            mmr.add_batched(&mut standard_hasher, &element);
                        }
                        mmr.sync(&mut standard_hasher);
                    }

                    base_mmr = Some(mmr);
                }

                GraftingOperation::InitPeakTree {
                    grafting_height: height,
                    num_leaves,
                } => {
                    grafting_height = (height as u32 % MAX_GRAFTING_HEIGHT).max(1);

                    if let Some(ref base) = base_mmr {
                        if base.leaves() == 0 {
                            // Can't create peak tree with empty base
                            continue;
                        }

                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        // Determine how many peak leaves we can have based on grafting height
                        // Each peak leaf corresponds to 2^grafting_height base leaves
                        let base_leaves_per_peak = 1u64 << grafting_height;
                        let max_peak_leaves = base.leaves() / base_leaves_per_peak;

                        if max_peak_leaves == 0 {
                            // Not enough base leaves for even one peak leaf at this height
                            continue;
                        }

                        let peak_leaves_count = if num_leaves == 0 {
                            max_peak_leaves.min(50) as usize // Default to reasonable number
                        } else {
                            (num_leaves as usize % MAX_LEAVES)
                                .min(max_peak_leaves as usize)
                                .max(1)
                        };

                        // Load all required grafted digests
                        let mut digests_to_load = Vec::new();
                        for i in 0..peak_leaves_count {
                            digests_to_load.push(i as u64);
                        }

                        let _ = hasher.load_grafted_digests(&digests_to_load, base).await;
                        loaded_digests = digests_to_load;

                        let mut mmr = Mmr::new();
                        if num_leaves == 0 {
                            // Use build_test_mmr pattern for peak tree
                            for i in 0..peak_leaves_count {
                                hasher.inner().update(&(i as u64).to_be_bytes());
                                let element = hasher.inner().finalize();
                                mmr.add_batched(&mut hasher, &element);
                            }
                            mmr.sync(&mut hasher);
                        } else {
                            // Custom elements
                            for i in 0..peak_leaves_count {
                                let data = Sha256::fill((i + 100) as u8);
                                mmr.add(&mut hasher, &data);
                            }
                        }

                        peak_tree = Some(mmr);
                    }
                }

                GraftingOperation::LoadGraftedDigests { leaf_indices } => {
                    if let (Some(ref base), Some(_)) = (&base_mmr, &peak_tree) {
                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        let mut valid_indices = Vec::new();
                        for idx in leaf_indices {
                            let leaf_idx = idx as u64 % base.leaves().max(1);
                            if leaf_idx < base.leaves() {
                                valid_indices.push(leaf_idx);
                            }
                        }

                        if !valid_indices.is_empty() {
                            let _ = hasher.load_grafted_digests(&valid_indices, base).await;
                            loaded_digests.extend(valid_indices);
                        }
                    }
                }

                GraftingOperation::AddToPeakTree { element } => {
                    if let (Some(ref base), Some(ref mut peak)) = (&base_mmr, &mut peak_tree) {
                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        let peak_leaf_count = peak.leaves();
                        let base_leaves_per_peak = 1u64 << grafting_height;
                        let max_peak_leaves = base.leaves() / base_leaves_per_peak;

                        if peak_leaf_count < max_peak_leaves {
                            // Load all previously loaded digests plus the new one
                            let mut all_digests = loaded_digests.clone();
                            if !all_digests.contains(&peak_leaf_count) {
                                all_digests.push(peak_leaf_count);
                            }
                            let _ = hasher.load_grafted_digests(&all_digests, base).await;

                            let limited = limit_element_size(&element);
                            peak.add(&mut hasher, limited);
                            loaded_digests = all_digests;
                        }
                    }
                }

                GraftingOperation::AddToBaseMmr { element } => {
                    if let Some(ref mut mmr) = base_mmr {
                        let limited = limit_element_size(&element);
                        mmr.add(&mut standard_hasher, limited);
                    }
                }

                GraftingOperation::ComputeLeafDigest { pos, element } => {
                    if let (Some(ref base), Some(_)) = (&base_mmr, &peak_tree) {
                        if !loaded_digests.is_empty() {
                            let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);
                            let _ = hasher.load_grafted_digests(&loaded_digests, base).await;

                            // Use a position that corresponds to a loaded digest
                            let safe_idx = (pos as usize) % loaded_digests.len();
                            let leaf_pos = loaded_digests[safe_idx] * 2; // Convert to position

                            let limited = limit_element_size(&element);
                            let _ = hasher.leaf_digest(leaf_pos, limited);
                        }
                    }
                }

                GraftingOperation::ComputeNodeDigest { pos } => {
                    if let (Some(ref base), Some(_)) = (&base_mmr, &peak_tree) {
                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        if !loaded_digests.is_empty() {
                            let _ = hasher.load_grafted_digests(&loaded_digests, base).await;
                        }

                        let safe_pos = pos % base.size().max(1);
                        let left = Sha256::fill(1);
                        let right = Sha256::fill(2);

                        let _ = hasher.node_digest(safe_pos, &left, &right);
                    }
                }

                GraftingOperation::ComputeRoot => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        if !loaded_digests.is_empty() {
                            let _ = hasher.load_grafted_digests(&loaded_digests, base).await;
                        }

                        let peak_root = peak.root(&mut hasher);
                        let base_root = base.root(&mut standard_hasher);

                        assert_ne!(peak_root.as_ref(), &[0u8; 32]);
                        assert_ne!(base_root.as_ref(), &[0u8; 32]);
                    }
                }

                GraftingOperation::Fork => {
                    if let (Some(ref base), Some(_)) = (&base_mmr, &peak_tree) {
                        let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                        if !loaded_digests.is_empty() {
                            let _ = hasher.load_grafted_digests(&loaded_digests, base).await;
                        }

                        let _ = hasher.fork();
                        fork_created = true;
                    }
                }

                GraftingOperation::CreateVerifier {
                    height,
                    num,
                    elements,
                } => {
                    let safe_height = (height as u32 % MAX_GRAFTING_HEIGHT).max(1);
                    let safe_num = num % 1000;

                    let mut verifier_elements = Vec::new();
                    for elem in elements.iter().take(10) {
                        let limited = limit_element_size(elem);
                        verifier_elements.push(limited);
                    }

                    let _ = Verifier::<Sha256>::new(safe_height, safe_num, verifier_elements);
                }

                GraftingOperation::VerifyProof { leaf_num } => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let storage = Storage::<Sha256, _, _>::new(peak, base, grafting_height);

                        if base.leaves() > 0 {
                            let safe_leaf = leaf_num as u64 % base.leaves();
                            let pos = safe_leaf * 2;

                            if let Ok(proof) = range_proof(&storage, pos, pos).await {
                                let root = storage.root(&mut standard_hasher).await.unwrap();

                                let peak_leaf = safe_leaf >> grafting_height;
                                let elem = Sha256::fill((peak_leaf + 100) as u8);
                                let base_elem = Sha256::fill(safe_leaf as u8);

                                let mut verifier = Verifier::<Sha256>::new(
                                    grafting_height,
                                    peak_leaf,
                                    vec![&elem],
                                );

                                let _ = proof.verify_element_inclusion(
                                    &mut verifier,
                                    &base_elem,
                                    pos,
                                    &root,
                                );
                            }
                        }
                    }
                }

                GraftingOperation::VerifyRangeProof {
                    start_leaf,
                    end_leaf,
                } => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let storage = Storage::<Sha256, _, _>::new(peak, base, grafting_height);

                        if base.leaves() > 0 {
                            let start = (start_leaf as u64) % base.leaves();
                            let end = (end_leaf as u64) % base.leaves();
                            let (start, end) = if start <= end {
                                (start, end)
                            } else {
                                (end, start)
                            };

                            let start_pos = start * 2;
                            let end_pos = end * 2;

                            if let Ok(proof) = range_proof(&storage, start_pos, end_pos).await {
                                let root = storage.root(&mut standard_hasher).await.unwrap();

                                let mut range_elements = Vec::new();
                                let mut verifier_elements = Vec::new();

                                for i in start..=end {
                                    let elem = Sha256::fill(i as u8);
                                    range_elements.push(elem);

                                    let peak_leaf = i >> grafting_height;
                                    let peak_elem = Sha256::fill((peak_leaf + 100) as u8);
                                    verifier_elements.push(peak_elem);
                                }

                                let verifier_refs: Vec<&[u8]> =
                                    verifier_elements.iter().map(|e| e.as_ref()).collect();

                                let mut verifier = Verifier::<Sha256>::new(
                                    grafting_height,
                                    start >> grafting_height,
                                    verifier_refs,
                                );

                                let range_refs: Vec<&[u8]> =
                                    range_elements.iter().map(|e| e.as_ref()).collect();

                                let _ = proof.verify_range_inclusion(
                                    &mut verifier,
                                    &range_refs,
                                    start,
                                    &root,
                                );
                            }
                        }
                    }
                }

                GraftingOperation::GetNodeFromStorage { pos } => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let storage = Storage::<Sha256, _, _>::new(peak, base, grafting_height);

                        let safe_pos = pos % base.size().max(1);
                        let _ = storage.get_node(safe_pos).await;

                        assert!(storage.size() == base.size());
                    }
                }

                GraftingOperation::ComputeStorageRoot => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let storage = Storage::<Sha256, _, _>::new(peak, base, grafting_height);

                        let root1 = storage.root(&mut standard_hasher).await.unwrap();
                        let root2 = storage.root(&mut standard_hasher).await.unwrap();

                        assert_eq!(root1, root2);
                        assert_ne!(root1.as_ref(), &[0u8; 32]);
                    }
                }

                GraftingOperation::AddBatchToBaseMmr { batch } => {
                    if let Some(ref mut mmr) = base_mmr {
                        for elem in batch.iter().take(MAX_BATCH_SIZE) {
                            let limited = limit_element_size(elem);
                            mmr.add_batched(&mut standard_hasher, limited);
                        }
                        mmr.sync(&mut standard_hasher);
                    }
                }

                GraftingOperation::AddBatchToPeakTree { batch } => {
                    if let (Some(ref base), Some(ref mut peak)) = (&base_mmr, &mut peak_tree) {
                        let base_leaves_per_peak = 1u64 << grafting_height;
                        let max_peak_leaves = base.leaves() / base_leaves_per_peak;

                        if peak.leaves() < max_peak_leaves {
                            let mut hasher = Hasher::new(&mut standard_hasher, grafting_height);

                            // Calculate how many we can actually add
                            let can_add = (max_peak_leaves - peak.leaves()) as usize;
                            let to_add = batch.len().min(MAX_BATCH_SIZE).min(can_add);

                            if to_add > 0 {
                                // Load all required digests
                                let mut all_digests = loaded_digests.clone();
                                for i in 0..to_add {
                                    let leaf_num = peak.leaves() + i as u64;
                                    if !all_digests.contains(&leaf_num) {
                                        all_digests.push(leaf_num);
                                    }
                                }
                                let _ = hasher.load_grafted_digests(&all_digests, base).await;

                                // Add the batch
                                for elem in batch.iter().take(to_add) {
                                    let limited = limit_element_size(elem);
                                    peak.add_batched(&mut hasher, limited);
                                }
                                peak.sync(&mut hasher);
                                loaded_digests = all_digests;
                            }
                        }
                    }
                }

                GraftingOperation::PopFromBaseMmr => {
                    if let Some(ref mut mmr) = base_mmr {
                        let _ = mmr.pop();
                    }
                }

                GraftingOperation::PopFromPeakTree => {
                    if let Some(ref mut peak) = peak_tree {
                        let _ = peak.pop();
                    }
                }

                GraftingOperation::GetSizeFromStorage => {
                    if let (Some(ref base), Some(ref peak)) = (&base_mmr, &peak_tree) {
                        let storage = Storage::<Sha256, _, _>::new(peak, base, grafting_height);
                        let size = storage.size();
                        assert_eq!(size, base.size());
                    }
                }
            }

            if fork_created && rng.gen_bool(0.1) {
                fork_created = false;
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
