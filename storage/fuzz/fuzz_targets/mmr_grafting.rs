#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::mmr::{
    grafting::{Hasher as GraftingHasher, Storage as GraftingStorage, Verifier},
    hasher::Hasher as HasherTrait,
    mem::Mmr,
    storage::Storage as StorageTrait,
    verification, StandardHasher,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};

const MAX_OPERATIONS: usize = 50;
const MAX_ELEMENTS: usize = 100;
const MAX_DATA_SIZE: usize = 128;
const MAX_HEIGHT: u32 = 10;

/// Returns the position of the leaf with number `leaf_num` in an MMR.
const fn leaf_num_to_pos(leaf_num: u64) -> u64 {
    // This will never underflow since 2*n >= count_ones(n).
    leaf_num.checked_mul(2).expect("leaf_num overflow") - leaf_num.count_ones() as u64
}

#[derive(Arbitrary, Debug, Clone)]
enum GraftingOperation {
    LoadGraftedDigests {
        leaf_indices: Vec<u64>,
    },
    LeafDigest {
        leaf_num: u64,
        element_size: usize,
    },
    NodeDigest {
        pos: u64,
    },
    Root {
        size: u64,
        num_peaks: usize,
    },
    Fork,
    CreateVerifier {
        height: u32,
        num: u64,
        num_elements: usize,
    },
    VerifyElementInclusion {
        pos: u64,
    },
    VerifyRangeInclusion {
        start_pos: u64,
        end_pos: u64,
    },
    CreateGraftedStorage {
        height: u32,
    },
    GetNodeFromStorage {
        pos: u64,
    },
    ComputeStorageRoot,
    AddToBaseMmr {
        element_size: usize,
    },
    AddToPeakTree {
        element_size: usize,
        height: u32,
    },
    GenerateProof {
        start_pos: u64,
        end_pos: u64,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<GraftingOperation>,
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

fn generate_digest(rng: &mut StdRng, value: u8) -> Digest {
    let mut data = vec![value; rng.gen_range(1..32)];
    for byte in &mut data {
        *byte = rng.gen();
    }
    Sha256::hash(&data)
}

fn generate_element(rng: &mut StdRng, size: usize) -> Vec<u8> {
    let actual_size = size.clamp(1, MAX_DATA_SIZE);
    (0..actual_size).map(|_| rng.gen()).collect()
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);

    runner.start(|_context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);
        let mut base_mmr = Mmr::<Sha256>::new();
        let mut peak_tree = Mmr::<Sha256>::new();

        // Initialize base MMR with some elements
        let mut standard_hasher = StandardHasher::<Sha256>::new();
        for _ in 0..rng.gen_range(1..20) {
            let val: u8 = rng.gen();
            let digest = generate_digest(&mut rng, val);
            base_mmr.add(&mut standard_hasher, &digest);
        }

        let mut loaded_leaves = Vec::new();
        let mut peak_elements = Vec::new();

        for op in input.operations {
            match op {
                GraftingOperation::LoadGraftedDigests { leaf_indices } => {
                    // Need enough leaves for grafting (at least 2 for height=1)
                    if base_mmr.leaves() < 2 || leaf_indices.is_empty() {
                        continue;
                    }

                    let mut hasher = StandardHasher::<Sha256>::new();
                    let mut grafting_hasher = GraftingHasher::new(&mut hasher, 1);

                    // Constrain indices to safe range (leaves that will have valid destination positions)
                    let max_safe_leaf = (base_mmr.leaves() / 2).max(1);
                    let valid_leaves: Vec<u64> = leaf_indices
                        .iter()
                        .map(|&idx| idx % max_safe_leaf)
                        .collect();

                    if grafting_hasher
                        .load_grafted_digests(&valid_leaves, &base_mmr)
                        .await
                        .is_ok()
                    {
                        loaded_leaves = valid_leaves;
                    }
                }

                GraftingOperation::LeafDigest {
                    leaf_num,
                    element_size,
                } => {
                    // Ensure we have enough leaves in base MMR for grafting
                    if base_mmr.leaves() == 0 {
                        continue;
                    }

                    // For height=1 grafting, we need nodes at height 1 or above to exist
                    // The destination position for leaf_num is the position of its parent
                    // We need at least 2 leaves to have any internal nodes
                    if base_mmr.leaves() < 2 {
                        continue;
                    }

                    let mut hasher = StandardHasher::<Sha256>::new();
                    let mut grafting_hasher = GraftingHasher::new(&mut hasher, 1);

                    // Constrain leaf_num to valid range (fewer leaves than base MMR leaves to be safe)
                    let max_safe_leaf = (base_mmr.leaves() / 2).max(1);
                    let valid_leaf_num = leaf_num % max_safe_leaf;
                    let leaf_pos = leaf_num_to_pos(valid_leaf_num);

                    // Load the grafted digest first (required by the assertion in leaf_digest)
                    if grafting_hasher
                        .load_grafted_digests(&[valid_leaf_num], &base_mmr)
                        .await
                        .is_ok()
                    {
                        let element = generate_element(&mut rng, element_size);
                        let _ = grafting_hasher.leaf_digest(leaf_pos, &element);
                    }
                }

                GraftingOperation::NodeDigest { pos } => {
                    let mut hasher = StandardHasher::<Sha256>::new();
                    let mut grafting_hasher = GraftingHasher::new(&mut hasher, 1);

                    // Any position is valid for node_digest
                    let left = generate_digest(&mut rng, 1);
                    let right = generate_digest(&mut rng, 2);
                    let _ = grafting_hasher.node_digest(pos, &left, &right);
                }

                GraftingOperation::Root { size, num_peaks } => {
                    let mut hasher = StandardHasher::<Sha256>::new();
                    let mut grafting_hasher = GraftingHasher::new(&mut hasher, 1);

                    // Constrain size and num_peaks to reasonable values
                    let safe_size = size.max(1);
                    let safe_num_peaks = (num_peaks % 10).max(1);
                    let peaks: Vec<Digest> = (0..safe_num_peaks)
                        .map(|i| generate_digest(&mut rng, i as u8))
                        .collect();
                    let _ = grafting_hasher.root(safe_size, peaks.iter());
                }

                GraftingOperation::Fork => {
                    let mut hasher = StandardHasher::<Sha256>::new();
                    let grafting_hasher = GraftingHasher::new(&mut hasher, 1);

                    let mut forked = grafting_hasher.fork();
                    let element = generate_element(&mut rng, 10);

                    // Only use fork if we have loaded leaves
                    if !loaded_leaves.is_empty() {
                        let leaf_pos = leaf_num_to_pos(loaded_leaves[0]);
                        let _ = forked.leaf_digest(leaf_pos, &element);
                    }
                }

                GraftingOperation::CreateVerifier {
                    height,
                    num,
                    num_elements,
                } => {
                    // Constrain parameters
                    let safe_height = height % MAX_HEIGHT;
                    let safe_num = num;
                    let safe_num_elements = (num_elements % MAX_ELEMENTS).max(1);

                    let elements: Vec<Vec<u8>> = (0..safe_num_elements)
                        .map(|_| generate_element(&mut rng, 10))
                        .collect();
                    let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();

                    let mut verifier =
                        Verifier::<Sha256>::new(safe_height, safe_num, element_refs.clone());

                    let left = generate_digest(&mut rng, 1);
                    let right = generate_digest(&mut rng, 2);
                    let _ = verifier.node_digest(safe_num, &left, &right);

                    let peaks: Vec<Digest> =
                        (0..3).map(|i| generate_digest(&mut rng, i as u8)).collect();
                    let _ = verifier.root(100, peaks.iter());

                    let _ = verifier.fork();
                    let _ = verifier.standard();
                }

                GraftingOperation::VerifyElementInclusion { pos } => {
                    // Ensure both MMRs have elements
                    if base_mmr.size() == 0 || peak_tree.size() == 0 {
                        continue;
                    }

                    // Constrain pos to valid range [0, base_mmr.size())
                    let safe_pos = pos % base_mmr.size();
                    let height = 1;
                    let storage: GraftingStorage<Sha256, _, _> =
                        GraftingStorage::new(&peak_tree, &base_mmr, height);

                    // Generate proof with constrained positions
                    if let Ok(proof) = verification::range_proof(&storage, safe_pos, safe_pos).await
                    {
                        let element = generate_element(&mut rng, 10);
                        let mut verifier = Verifier::<Sha256>::new(height, 0, vec![&element]);
                        let mut hasher = StandardHasher::<Sha256>::new();

                        if let Ok(root) = storage.root(&mut hasher).await {
                            let _ = proof.verify_element_inclusion(
                                &mut verifier,
                                &element,
                                safe_pos,
                                &root,
                            );
                        }
                    }
                }

                GraftingOperation::VerifyRangeInclusion { start_pos, end_pos } => {
                    // Ensure both MMRs have elements
                    if base_mmr.size() == 0 || peak_tree.size() == 0 {
                        continue;
                    }

                    // Constrain positions according to range_proof assertions:
                    // - start_pos < mmr.size()
                    // - end_pos < mmr.size()
                    // - start_pos <= end_pos
                    let safe_start = start_pos % base_mmr.size();
                    let safe_end = if end_pos < start_pos {
                        safe_start
                    } else {
                        safe_start + ((end_pos - start_pos) % (base_mmr.size() - safe_start))
                    };

                    // Ensure safe_end < base_mmr.size()
                    let safe_end = safe_end.min(base_mmr.size() - 1);

                    let height = 1;
                    let storage: GraftingStorage<Sha256, _, _> =
                        GraftingStorage::new(&peak_tree, &base_mmr, height);

                    if let Ok(proof) =
                        verification::range_proof(&storage, safe_start, safe_end).await
                    {
                        let num_elements = (safe_end - safe_start + 1) as usize;
                        let elements: Vec<Vec<u8>> = (0..num_elements)
                            .map(|_| generate_element(&mut rng, 10))
                            .collect();
                        let element_refs: Vec<&[u8]> =
                            elements.iter().map(|e| e.as_slice()).collect();

                        let mut verifier = Verifier::<Sha256>::new(height, 0, element_refs.clone());
                        let mut hasher = StandardHasher::<Sha256>::new();

                        if let Ok(root) = storage.root(&mut hasher).await {
                            let _ = proof.verify_range_inclusion(
                                &mut verifier,
                                &element_refs,
                                safe_start,
                                &root,
                            );
                        }
                    }
                }

                GraftingOperation::CreateGraftedStorage { height } => {
                    // Constrain height to reasonable values
                    let safe_height = (height % MAX_HEIGHT).min(5);

                    let storage: GraftingStorage<Sha256, _, _> =
                        GraftingStorage::new(&peak_tree, &base_mmr, safe_height);

                    let _ = storage.size();

                    // Only compute root if both trees have content to avoid panics
                    if base_mmr.size() > 0 && peak_tree.size() > 0 {
                        let mut hasher = StandardHasher::<Sha256>::new();
                        let _ = storage.root(&mut hasher).await;
                    }
                }

                GraftingOperation::GetNodeFromStorage { pos } => {
                    if base_mmr.size() == 0 {
                        continue;
                    }

                    // Constrain pos to valid range
                    let safe_pos = pos % base_mmr.size();
                    let height = 1;
                    let storage: GraftingStorage<Sha256, _, _> =
                        GraftingStorage::new(&peak_tree, &base_mmr, height);
                    let _ = storage.get_node(safe_pos).await;
                }

                GraftingOperation::ComputeStorageRoot => {
                    // Only compute root if both trees have content to avoid panics
                    if base_mmr.size() > 0 && peak_tree.size() > 0 {
                        let height = rng.gen_range(0..5);
                        let storage: GraftingStorage<Sha256, _, _> =
                            GraftingStorage::new(&peak_tree, &base_mmr, height);
                        let mut hasher = StandardHasher::<Sha256>::new();
                        let _ = storage.root(&mut hasher).await;
                    }
                }

                GraftingOperation::AddToBaseMmr { element_size } => {
                    let element = generate_element(&mut rng, element_size);
                    let mut hasher = StandardHasher::<Sha256>::new();
                    base_mmr.add(&mut hasher, &element);
                }

                GraftingOperation::AddToPeakTree {
                    element_size,
                    height,
                } => {
                    let element = generate_element(&mut rng, element_size);
                    let safe_height = height % MAX_HEIGHT;

                    if base_mmr.leaves() > 0 && !loaded_leaves.is_empty() {
                        let mut hasher = StandardHasher::<Sha256>::new();
                        let mut grafting_hasher = GraftingHasher::new(&mut hasher, safe_height);

                        if grafting_hasher
                            .load_grafted_digests(&loaded_leaves, &base_mmr)
                            .await
                            .is_ok()
                        {
                            peak_tree.add(&mut grafting_hasher, &element);
                            peak_elements.push(element);
                        }
                    } else {
                        // Can add without grafting if no special requirements
                        let mut hasher = StandardHasher::<Sha256>::new();
                        peak_tree.add(&mut hasher, &element);
                        peak_elements.push(element);
                    }
                }

                GraftingOperation::GenerateProof { start_pos, end_pos } => {
                    // Ensure both MMRs have elements
                    if base_mmr.size() == 0 || peak_tree.size() == 0 {
                        continue;
                    }

                    // Apply range_proof assertions:
                    // - start_pos < mmr.size()
                    // - end_pos < mmr.size()
                    // - start_pos <= end_pos
                    let safe_start = start_pos % base_mmr.size();
                    let safe_end = if end_pos < safe_start {
                        safe_start
                    } else {
                        safe_start + ((end_pos - safe_start) % (base_mmr.size() - safe_start))
                    };

                    // Ensure safe_end < base_mmr.size()
                    let safe_end = safe_end.min(base_mmr.size() - 1);

                    let height = rng.gen_range(0..3);
                    let storage: GraftingStorage<Sha256, _, _> =
                        GraftingStorage::new(&peak_tree, &base_mmr, height);
                    let _ = verification::range_proof(&storage, safe_start, safe_end).await;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
