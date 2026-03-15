#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    merkle::{self, hasher::Standard, Family as MerkleFamily, Position},
    mmb::{self, mem::Mmb},
    mmr::{self, mem::Mmr},
};
use core::{fmt::Debug, ops::Range};
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

trait FuzzMerkle: Sized {
    type Family: MerkleFamily;
    type Error: Debug;

    const NAME: &'static str;

    fn new(hasher: &mut Standard<Self::Family, Sha256>) -> Self;
    fn size(&self) -> merkle::Position<Self::Family>;
    fn leaves(&self) -> merkle::Location<Self::Family>;
    fn retained_bounds(&self) -> Range<merkle::Location<Self::Family>>;
    fn get_node(&self, pos: merkle::Position<Self::Family>) -> Option<Digest>;
    fn root(&self) -> Digest;
    fn add(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        data: &[u8],
    ) -> merkle::Location<Self::Family>;
    fn update_leaf(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        data: &[u8],
    ) -> Result<(), Self::Error>;
    fn verify_element_proof(
        &self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        element: &[u8],
    ) -> Result<bool, Self::Error>;
    fn prune(&mut self, loc: merkle::Location<Self::Family>) -> Result<(), Self::Error>;
    fn prune_all(&mut self);
}

impl FuzzMerkle for Mmr<Digest> {
    type Family = mmr::Family;
    type Error = mmr::Error;

    const NAME: &'static str = "mmr";

    fn new(hasher: &mut Standard<Self::Family, Sha256>) -> Self {
        Self::new(hasher)
    }

    fn size(&self) -> merkle::Position<Self::Family> {
        self.size()
    }

    fn leaves(&self) -> merkle::Location<Self::Family> {
        self.leaves()
    }

    fn retained_bounds(&self) -> Range<merkle::Location<Self::Family>> {
        self.bounds()
    }

    fn get_node(&self, pos: merkle::Position<Self::Family>) -> Option<Digest> {
        self.get_node(pos)
    }

    fn root(&self) -> Digest {
        *self.root()
    }

    fn add(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        data: &[u8],
    ) -> merkle::Location<Self::Family> {
        let (loc, changeset) = {
            let mut batch = self.new_batch();
            let loc = batch.add(hasher, data);
            (loc, batch.merkleize(hasher).finalize())
        };
        self.apply(changeset).unwrap();
        loc
    }

    fn update_leaf(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let mut batch = self.new_batch();
        batch.update_leaf(hasher, loc, data)?;
        self.apply(batch.merkleize(hasher).finalize()).unwrap();
        Ok(())
    }

    fn verify_element_proof(
        &self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        element: &[u8],
    ) -> Result<bool, Self::Error> {
        let proof = self.proof(hasher, loc)?;
        let root = *self.root();
        Ok(proof.verify_element_inclusion(hasher, element, loc, &root))
    }

    fn prune(&mut self, loc: merkle::Location<Self::Family>) -> Result<(), Self::Error> {
        self.prune(loc)
    }

    fn prune_all(&mut self) {
        self.prune_all()
    }
}

impl FuzzMerkle for Mmb<Digest> {
    type Family = mmb::Family;
    type Error = mmb::Error;

    const NAME: &'static str = "mmb";

    fn new(hasher: &mut Standard<Self::Family, Sha256>) -> Self {
        Self::new(hasher)
    }

    fn size(&self) -> merkle::Position<Self::Family> {
        self.size()
    }

    fn leaves(&self) -> merkle::Location<Self::Family> {
        self.leaves()
    }

    fn retained_bounds(&self) -> Range<merkle::Location<Self::Family>> {
        self.bounds()
    }

    fn get_node(&self, pos: merkle::Position<Self::Family>) -> Option<Digest> {
        self.get_node(pos)
    }

    fn root(&self) -> Digest {
        *self.root()
    }

    fn add(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        data: &[u8],
    ) -> merkle::Location<Self::Family> {
        let (loc, changeset) = {
            let mut batch = self.new_batch();
            let loc = batch.add(hasher, data);
            (loc, batch.merkleize(hasher).finalize())
        };
        self.apply(changeset).unwrap();
        loc
    }

    fn update_leaf(
        &mut self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let mut batch = self.new_batch();
        batch.update_leaf(hasher, loc, data)?;
        self.apply(batch.merkleize(hasher).finalize()).unwrap();
        Ok(())
    }

    fn verify_element_proof(
        &self,
        hasher: &mut Standard<Self::Family, Sha256>,
        loc: merkle::Location<Self::Family>,
        element: &[u8],
    ) -> Result<bool, Self::Error> {
        let proof = self.proof(hasher, loc)?;
        let root = *self.root();
        Ok(proof.verify_element_inclusion(hasher, element, loc, &root))
    }

    fn prune(&mut self, loc: merkle::Location<Self::Family>) -> Result<(), Self::Error> {
        self.prune(loc)
    }

    fn prune_all(&mut self) {
        self.prune_all()
    }
}

struct ReferenceMerkle<F: MerkleFamily> {
    leaf_locations: Vec<merkle::Location<F>>,
    leaf_data: Vec<Vec<u8>>,
    pruned_to_loc: merkle::Location<F>,
}

impl<F: MerkleFamily> ReferenceMerkle<F> {
    fn new() -> Self {
        Self {
            leaf_locations: Vec::new(),
            leaf_data: Vec::new(),
            pruned_to_loc: merkle::Location::new(0),
        }
    }

    fn add(&mut self, leaf_loc: merkle::Location<F>, data: Vec<u8>) {
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

    fn expected_size(&self) -> merkle::Position<F> {
        let leaves = merkle::Location::new(self.leaf_count() as u64);
        merkle::Position::try_from(leaves).expect("valid size for reference leaf count")
    }

    fn prune_all(&mut self) {
        self.pruned_to_loc = merkle::Location::new(self.leaf_count() as u64);
    }

    fn prune(&mut self, loc: merkle::Location<F>) {
        if loc <= merkle::Location::new(self.leaf_count() as u64) && loc > self.pruned_to_loc {
            self.pruned_to_loc = loc;
        }
    }

    fn is_leaf_pruned(&self, leaf_loc: merkle::Location<F>) -> bool {
        leaf_loc < self.pruned_to_loc
    }

    fn pruned_to_loc(&self) -> merkle::Location<F> {
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

fn fuzz_family<T: FuzzMerkle>(operations: &[MerkleOperation]) {
    let runner = deterministic::Runner::default();

    runner.start(|_context| async move {
        let mut hasher = Standard::<T::Family, Sha256>::new();
        let mut merkle = T::new(&mut hasher);
        let mut reference = ReferenceMerkle::<T::Family>::new();

        for (op_idx, op) in operations.iter().enumerate() {
            match op {
                MerkleOperation::Add { data } => {
                    if merkle.retained_bounds().is_empty() && *merkle.size() > 0 {
                        continue;
                    }

                    let limited = limit(data);
                    let size_before = merkle.size();
                    let loc = merkle.add(&mut hasher, limited);
                    reference.add(loc, limited.to_vec());

                    assert!(
                        merkle.size() > size_before,
                        "{} op {op_idx}: size should increase after add",
                        T::NAME
                    );

                    assert_eq!(
                        merkle.leaves() - 1,
                        loc,
                        "{} op {op_idx}: last leaf should be the added location",
                        T::NAME
                    );

                    let pos = Position::try_from(loc).unwrap();
                    assert!(
                        merkle.get_node(pos).is_some(),
                        "{} op {op_idx}: should be able to read added leaf",
                        T::NAME
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
                        continue;
                    }

                    let size_before = merkle.size();
                    let root_before = merkle.root();
                    let root_should_change = reference.leaf_data[idx].as_slice() != limited;

                    merkle.update_leaf(&mut hasher, leaf_loc, limited).unwrap();
                    reference.update_leaf(idx, limited.to_vec());

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after update_leaf",
                        T::NAME
                    );

                    if root_should_change {
                        assert_ne!(
                            merkle.root(),
                            root_before,
                            "{} op {op_idx}: root should change after updating a leaf to different data",
                            T::NAME
                        );
                    }
                }

                MerkleOperation::GetNode { pos } => {
                    if *merkle.size() == 0 {
                        continue;
                    }

                    let safe_pos = Position::new(*pos % *merkle.size());
                    let node = merkle.get_node(safe_pos);
                    let pruned_to_pos = Position::try_from(merkle.retained_bounds().start).unwrap();

                    if safe_pos >= pruned_to_pos {
                        assert!(
                            node.is_some(),
                            "{} op {op_idx}: missing retained node at position {safe_pos} (size: {}, pruned_to: {})",
                            T::NAME,
                            merkle.size(),
                            merkle.retained_bounds().start
                        );
                    }
                }

                MerkleOperation::GetSize => {
                    assert_eq!(
                        merkle.size(),
                        reference.expected_size(),
                        "{} op {op_idx}: size mismatch (leaves: {})",
                        T::NAME,
                        reference.leaf_count()
                    );
                }

                MerkleOperation::Proof { location } => {
                    if reference.leaf_locations.is_empty() {
                        continue;
                    }

                    let idx = (*location as usize) % reference.leaf_locations.len();
                    let loc = reference.leaf_locations[idx];
                    let retained = merkle.retained_bounds();

                    if loc >= merkle.leaves() || loc < retained.start {
                        continue;
                    }

                    if let Ok(valid) = merkle.verify_element_proof(
                        &mut hasher,
                        loc,
                        reference.leaf_data[idx].as_slice(),
                    ) {
                        assert!(valid, "{} op {op_idx}: proof should verify", T::NAME);
                    }
                }

                MerkleOperation::PruneAll => {
                    if merkle.retained_bounds().is_empty() {
                        continue;
                    }

                    let size_before = merkle.size();

                    merkle.prune_all();
                    reference.prune_all();

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after prune_all",
                        T::NAME
                    );

                    assert_eq!(
                        merkle.retained_bounds().start,
                        reference.pruned_to_loc(),
                        "{} op {op_idx}: pruned location mismatch after prune_all",
                        T::NAME
                    );

                    let _ = merkle.root();
                }

                MerkleOperation::PruneToPos { pos_idx } => {
                    if *merkle.size() == 0 {
                        continue;
                    }

                    let loc = merkle::Location::new(*pos_idx % (*merkle.leaves() + 1));
                    let retained_before = merkle.retained_bounds().start;

                    if loc <= retained_before || loc > merkle.leaves() {
                        continue;
                    }

                    let size_before = merkle.size();

                    merkle.prune(loc).unwrap();
                    reference.prune(loc);

                    assert_eq!(
                        merkle.size(),
                        size_before,
                        "{} op {op_idx}: size should not change after prune",
                        T::NAME
                    );

                    assert_eq!(
                        merkle.retained_bounds().start,
                        reference.pruned_to_loc(),
                        "{} op {op_idx}: pruned location mismatch after prune",
                        T::NAME
                    );

                    assert!(
                        merkle.retained_bounds().start >= retained_before,
                        "{} op {op_idx}: pruned location should not decrease",
                        T::NAME
                    );

                    let _ = merkle.root();
                }
            }
        }
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<Mmr<Digest>>(&input.operations);
    fuzz_family::<Mmb<Digest>>(&input.operations);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
