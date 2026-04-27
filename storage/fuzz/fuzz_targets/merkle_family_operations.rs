#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::merkle::{
    hasher::Standard, mem::Mem, mmb, mmr, Error, Family as MerkleFamily, Location, Position,
    RootSpec,
};
use core::any::type_name;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum MerkleOperation {
    Add { data: Vec<u8> },
    UpdateLeaf { location: u8, new_data: Vec<u8> },
    GetNode { pos: u64 },
    GetSize,
    Proof { location: u64 },
    PruneAll,
    PruneToPos { pos_idx: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MerkleOperation>,
}

fn add<F: MerkleFamily>(
    merkle: &mut Mem<F, Digest>,
    hasher: &Standard<Sha256>,
    data: &[u8],
) -> Location<F> {
    let batch = merkle.new_batch();
    let loc = batch.leaves();
    let batch = batch.add(hasher, data).merkleize(merkle, hasher);
    merkle.apply_batch(&batch).unwrap();
    loc
}

fn update_leaf<F: MerkleFamily>(
    merkle: &mut Mem<F, Digest>,
    hasher: &Standard<Sha256>,
    loc: Location<F>,
    data: &[u8],
) -> Result<(), Error<F>> {
    let batch = merkle
        .new_batch()
        .update_leaf(hasher, loc, data)?
        .merkleize(merkle, hasher);
    merkle.apply_batch(&batch).unwrap();
    Ok(())
}

fn verify_element_proof<F: MerkleFamily>(
    merkle: &Mem<F, Digest>,
    hasher: &Standard<Sha256>,
    loc: Location<F>,
    element: &[u8],
) -> Result<bool, Error<F>> {
    let proof = merkle.proof(hasher, loc, RootSpec::FULL_FORWARD)?;
    let root = merkle.root(hasher, RootSpec::FULL_FORWARD)?;
    Ok(proof.verify_element_inclusion(hasher, element, loc, &root, RootSpec::FULL_FORWARD))
}

struct ReferenceMerkle<F: MerkleFamily> {
    leaf_locations: Vec<Location<F>>,
    leaf_data: Vec<Vec<u8>>,
    pruned_to_loc: Location<F>,
}

impl<F: MerkleFamily> ReferenceMerkle<F> {
    fn new() -> Self {
        Self {
            leaf_locations: Vec::new(),
            leaf_data: Vec::new(),
            pruned_to_loc: Location::new(0),
        }
    }

    fn add(&mut self, leaf_loc: Location<F>, data: Vec<u8>) {
        self.leaf_locations.push(leaf_loc);
        self.leaf_data.push(data);
    }

    fn update_leaf(&mut self, idx: usize, new_data: Vec<u8>) {
        if idx < self.leaf_data.len() {
            self.leaf_data[idx] = new_data;
        }
    }

    fn leaf_count(&self) -> usize {
        self.leaf_locations.len()
    }

    fn expected_size(&self) -> Position<F> {
        let leaves = Location::new(self.leaf_count() as u64);
        Position::try_from(leaves).expect("valid size for reference leaf count")
    }

    fn prune_all(&mut self) {
        self.pruned_to_loc = Location::new(self.leaf_count() as u64);
    }

    fn prune(&mut self, loc: Location<F>) {
        if loc <= Location::new(self.leaf_count() as u64) && loc > self.pruned_to_loc {
            self.pruned_to_loc = loc;
        }
    }

    fn is_leaf_pruned(&self, leaf_loc: Location<F>) -> bool {
        leaf_loc < self.pruned_to_loc
    }

    fn pruned_to_loc(&self) -> Location<F> {
        self.pruned_to_loc
    }
}

fn limit(data: &[u8]) -> &[u8] {
    if data.len() > 16 {
        &data[..16]
    } else {
        data
    }
}

fn fuzz_family<F: MerkleFamily>(operations: &[MerkleOperation]) {
    let runner = deterministic::Runner::default();

    runner.start(|_context| async move {
        let hasher = Standard::<Sha256>::new();
        let mut merkle = Mem::<F, Digest>::new();
        let mut reference = ReferenceMerkle::<F>::new();

        for (op_idx, op) in operations.iter().enumerate() {
            match op {
                MerkleOperation::Add { data } => {
                    let limited = limit(data);
                    let size_before = merkle.size();
                    let loc = add(&mut merkle, &hasher, limited);
                    reference.add(loc, limited.to_vec());

                    assert!(
                        merkle.size() > size_before,
                        "{} op {op_idx}: size should increase after add",
                        type_name::<F>()
                    );

                    assert_eq!(
                        merkle.leaves() - 1,
                        loc,
                        "{} op {op_idx}: last leaf should be the added location",
                        type_name::<F>()
                    );

                    let pos = Position::try_from(loc).unwrap();
                    assert!(
                        merkle.get_node(pos).is_some(),
                        "{} op {op_idx}: should be able to read added leaf",
                        type_name::<F>()
                    );
                }

                MerkleOperation::UpdateLeaf { location, new_data } => {
                    if reference.leaf_locations.is_empty() {
                        continue;
                    }

                    let idx = (*location as usize) % reference.leaf_locations.len();
                    let leaf_loc = reference.leaf_locations[idx];
                    let limited = limit(new_data);

                    if reference.is_leaf_pruned(leaf_loc) {
                        assert!(update_leaf(&mut merkle, &hasher, leaf_loc, limited).is_err());
                        continue;
                    }

                    let size_before = merkle.size();
                    let root_before = merkle.root(&hasher, RootSpec::FULL_FORWARD).unwrap();
                    let root_should_change = reference.leaf_data[idx].as_slice() != limited;

                    update_leaf(&mut merkle, &hasher, leaf_loc, limited).unwrap();
                    reference.update_leaf(idx, limited.to_vec());

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after update_leaf",
                        type_name::<F>()
                    );

                    if root_should_change {
                        assert_ne!(
                            merkle.root(&hasher, RootSpec::FULL_FORWARD).unwrap(),
                            root_before,
                            "{} op {op_idx}: root should change after updating a leaf to different data",
                            type_name::<F>()
                        );
                    }
                }

                MerkleOperation::GetNode { pos } => {
                    if *merkle.size() == 0 {
                        continue;
                    }

                    let safe_pos = Position::new(*pos % *merkle.size());
                    let node = merkle.get_node(safe_pos);
                    let pruned_to_pos = Position::try_from(merkle.bounds().start).unwrap();

                    if safe_pos >= pruned_to_pos {
                        assert!(
                            node.is_some(),
                            "{} op {op_idx}: missing retained node at position {safe_pos} (size: {}, pruned_to: {})",
                            type_name::<F>(),
                            merkle.size(),
                            merkle.bounds().start
                        );
                    }
                }

                MerkleOperation::GetSize => {
                    assert_eq!(
                        merkle.size(),
                        reference.expected_size(),
                        "{} op {op_idx}: size mismatch (leaves: {})",
                        type_name::<F>(),
                        reference.leaf_count()
                    );
                }

                MerkleOperation::Proof { location } => {
                    if reference.leaf_locations.is_empty() {
                        continue;
                    }

                    let idx = (*location as usize) % reference.leaf_locations.len();
                    let loc = reference.leaf_locations[idx];
                    let retained = merkle.bounds();

                    if loc >= merkle.leaves() || loc < retained.start {
                        continue;
                    }

                    assert!(
                        verify_element_proof(&merkle, &hasher, loc, reference.leaf_data[idx].as_slice()).expect("proof generation should succeed"),
                        "{} op {op_idx}: element proof verification failed for loc {loc}",
                        type_name::<F>()
                    );
                }

                MerkleOperation::PruneAll => {
                    let size_before = merkle.size();

                    merkle.prune_all();
                    reference.prune_all();

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after prune_all",
                        type_name::<F>()
                    );

                    assert_eq!(
                        merkle.bounds().start,
                        reference.pruned_to_loc(),
                        "{} op {op_idx}: pruned location mismatch after prune_all",
                        type_name::<F>()
                    );

                    let _ = merkle.root(&hasher, RootSpec::FULL_FORWARD);
                }

                MerkleOperation::PruneToPos { pos_idx } => {
                    if *merkle.size() == 0 {
                        continue;
                    }

                    let loc = Location::new(*pos_idx % (*merkle.leaves() + 1));
                    let retained_before = merkle.bounds().start;

                    if loc <= retained_before {
                        continue;
                    }

                    let size_before = merkle.size();

                    merkle.prune(loc).unwrap();
                    reference.prune(loc);

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after prune",
                        type_name::<F>()
                    );

                    assert_eq!(
                        merkle.bounds().start,
                        reference.pruned_to_loc(),
                        "{} op {op_idx}: pruned location mismatch after prune",
                        type_name::<F>()
                    );

                    assert!(
                        merkle.bounds().start >= retained_before,
                        "{} op {op_idx}: pruned location should not decrease",
                        type_name::<F>()
                    );

                    let _ = merkle.root(&hasher, RootSpec::FULL_FORWARD);
                }
            }
        }
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input.operations);
    fuzz_family::<mmb::Family>(&input.operations);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
