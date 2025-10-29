#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::mmr::{mem::Mmr, Location, Position, StandardHasher as Standard};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum MmrOperation {
    Add { data: Vec<u8> },
    Pop,
    UpdateLeaf { location: u8, new_data: Vec<u8> },
    GetNode { pos: u64 },
    GetLastLeafPos,
    GetSize,
    GetRoot,
    Proof { location: u64 },
    PruneAll,
    PruneToPos { pos_idx: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MmrOperation>,
}

// Simple reference that tracks basic MMR state
struct ReferenceMmr {
    leaf_positions: Vec<Position>,
    leaf_data: Vec<Vec<u8>>,
    total_nodes_added: u64,
    pruned_to_pos: Position,
}

impl ReferenceMmr {
    fn new() -> Self {
        Self {
            leaf_positions: Vec::new(),
            leaf_data: Vec::new(),
            total_nodes_added: 0,
            pruned_to_pos: Position::new(0),
        }
    }

    fn add(&mut self, leaf_pos: Position, data: Vec<u8>) {
        self.leaf_positions.push(leaf_pos);
        self.leaf_data.push(data);
        // Track nodes added (leaf + any parent nodes)
        let nodes_after = self.calculate_mmr_size(self.leaf_positions.len());
        self.total_nodes_added = nodes_after;
    }

    fn pop(&mut self) -> Result<(), ()> {
        if self.leaf_positions.is_empty() {
            return Err(());
        }

        // Check if the last leaf would be pruned - if so, we can't pop it
        let last_leaf_pos = *self.leaf_positions.last().unwrap();
        if last_leaf_pos < self.pruned_to_pos {
            return Err(()); // Element is pruned, can't pop
        }

        self.leaf_positions.pop();
        self.leaf_data.pop();

        if self.leaf_positions.is_empty() {
            self.total_nodes_added = 0;
        } else {
            self.total_nodes_added = self.calculate_mmr_size(self.leaf_positions.len());
        }
        Ok(())
    }

    fn update_leaf(&mut self, idx: usize, new_data: Vec<u8>) {
        if idx < self.leaf_data.len() {
            self.leaf_data[idx] = new_data;
        }
    }

    fn last_leaf_pos(&self) -> Option<Position> {
        self.leaf_positions.last().copied()
    }

    fn leaf_count(&self) -> usize {
        self.leaf_positions.len()
    }

    fn expected_size(&self) -> u64 {
        self.total_nodes_added
    }

    fn prune_all(&mut self) {
        self.pruned_to_pos = Position::new(self.total_nodes_added);
    }

    fn prune_to_pos(&mut self, pos: Position) {
        if pos <= self.total_nodes_added {
            self.pruned_to_pos = pos;
        }
    }

    fn get_pruned_to_pos(&self) -> Position {
        self.pruned_to_pos
    }

    fn is_leaf_pruned(&self, leaf_pos: Position) -> bool {
        leaf_pos < self.pruned_to_pos
    }

    // Calculate expected MMR size for n leaves
    fn calculate_mmr_size(&self, num_leaves: usize) -> u64 {
        if num_leaves == 0 {
            return 0;
        }

        let mut size = 0u64;
        let mut remaining = num_leaves as u64;

        while remaining > 0 {
            // Find largest power of 2 <= remaining
            let height = 63 - remaining.leading_zeros();
            let subtree_leaves = 1u64 << height;
            let subtree_size = (2 * subtree_leaves) - 1;

            size += subtree_size;
            remaining -= subtree_leaves;
        }

        size
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|_context| async move {
        let mut mmr = Mmr::<Sha256>::new();
        let mut reference = ReferenceMmr::new();
        let mut hasher = Standard::new();

        for (op_idx, op) in input.operations.iter().enumerate() {
            match op {
                MmrOperation::Add { data } => {
                    // Skip adding if we're fully pruned (pruned_to_pos == size)
                    // because the MMR needs access to previous nodes to compute parent hashes
                    if mmr.pruned_to_pos() == mmr.size() && mmr.size() > 0 {
                        continue;
                    }

                    // Limit data size
                    let limited_data = if data.len() > 16 {
                        &data[0..16]
                    } else {
                        data
                    };

                    let size_before = mmr.size();
                    let mmr_pos = mmr.add(&mut hasher, limited_data);
                    reference.add(mmr_pos, limited_data.to_vec());

                    // Basic checks
                    assert!(
                        mmr.size() > size_before,
                        "Operation {op_idx}: Size should increase after add"
                    );

                    assert_eq!(
                        mmr.last_leaf_pos(),
                        Some(mmr_pos),
                        "Operation {op_idx}: Last leaf position should be the added position"
                    );

                    assert!(
                        mmr.get_node(mmr_pos).is_some(),
                        "Operation {op_idx}: Should be able to get added node"
                    );
                }

                MmrOperation::Pop => {
                    let size_before = mmr.size();
                    let mmr_result = mmr.pop();
                    let ref_result = reference.pop();

                    assert_eq!(
                        mmr_result.is_ok(), ref_result.is_ok(),
                        "Operation {op_idx}: Pop result mismatch - MMR: {mmr_result:?}, Ref: {ref_result:?}",
                    );

                    if mmr_result.is_ok() {
                        assert!(
                            mmr.size() < size_before,
                            "Operation {op_idx}: Size should decrease after successful pop"
                        );

                        assert_eq!(
                            mmr.last_leaf_pos(), reference.last_leaf_pos(),
                            "Operation {op_idx}: Last leaf position mismatch after pop"
                        );
                    }
                }

                MmrOperation::UpdateLeaf { location, new_data } => {
                    if !reference.leaf_positions.is_empty() {
                        let location = (*location as usize) % reference.leaf_positions.len();
                        let pos = reference.leaf_positions[location];

                        let limited_data = if new_data.len() > 16 {
                            &new_data[0..16]
                        } else {
                            new_data
                        };

                        if reference.is_leaf_pruned(pos) {
                            continue;
                        }

                        let size_before = mmr.size();
                        let root_before = mmr.root(&mut hasher);

                        mmr.update_leaf(&mut hasher, pos, limited_data).unwrap();
                        reference.update_leaf(location, limited_data.to_vec());

                        // Size should not change
                        assert_eq!(
                            mmr.size(), size_before,
                            "Operation {op_idx}: Size should not change after update_leaf"
                        );

                        // Root should change (unless data is identical)
                        let root_after = mmr.root(&mut hasher);
                        if limited_data != reference.leaf_data[location] {
                            assert_ne!(
                                root_before, root_after,
                                "Operation {op_idx}: Root should change after update_leaf with different data"
                            );
                        }
                    }
                }

                MmrOperation::GetNode { pos } => {
                    if mmr.size() > 0 {
                        let safe_pos = Position::new(*pos % *mmr.size());
                        let node = mmr.get_node(safe_pos);

                        // Check if the node is pruned
                        if safe_pos < mmr.pruned_to_pos() {
                            // Node is pruned, so it's expected to be None (unless it's pinned)
                            // We don't panic here as this is expected behavior
                        } else {
                            // Node is not pruned, so it should exist
                            if node.is_none() {
                                panic!("Could not get non-pruned node at position {safe_pos} (size: {}, pruned_to: {})",
                                    mmr.size(), mmr.pruned_to_pos());
                            }
                        }
                    }
                }

                MmrOperation::GetLastLeafPos => {
                    let mmr_last = mmr.last_leaf_pos();
                    let ref_last = reference.last_leaf_pos();

                    assert_eq!(
                        mmr_last, ref_last,
                        "Operation {op_idx}: Last leaf position mismatch - MMR: {mmr_last:?}, Ref: {ref_last:?}",
                    );
                }

                MmrOperation::GetSize => {
                    let mmr_size = mmr.size();
                    let expected_size = reference.expected_size();

                    assert_eq!(
                        mmr_size, expected_size,
                        "Operation {op_idx}: Size mismatch - MMR: {mmr_size}, Expected: {expected_size} (leaves: {})",
                        reference.leaf_count()
                    );
                }

                MmrOperation::GetRoot => {
                    // Root should always be computable
                    let root1 = mmr.root(&mut hasher);
                    let root2 = mmr.root(&mut hasher);
                    assert_eq!(
                        root1, root2,
                        "Operation {op_idx}: Root calculation should be deterministic"
                    );
                }

                MmrOperation::Proof { location } => {
                    if reference.leaf_positions.is_empty() {
                        return;
                    }
                    let location_idx = (*location as usize) % reference.leaf_positions.len();
                    let test_element_pos = reference.leaf_positions[location_idx];
                    let loc = Location::new(location_idx as u64).unwrap();
                    if test_element_pos >= mmr.size() || test_element_pos < mmr.pruned_to_pos() {
                        continue;
                    }

                    if let Ok(proof) = mmr.proof(loc) {
                        let root = mmr.root(&mut hasher);
                        assert!(proof.verify_element_inclusion(
                            &mut hasher,
                            reference.leaf_data[location_idx].as_slice(),
                            loc,
                            &root,
                        ));
                    }
                }

                MmrOperation::PruneAll => {
                    // Skip prune_all if we're already fully pruned to avoid issues with subsequent adds
                    if mmr.pruned_to_pos() == mmr.size() {
                        continue;
                    }

                    let size_before = mmr.size();

                    mmr.prune_all();
                    reference.prune_all();

                    // Size should remain the same
                    assert_eq!(
                        mmr.size(), size_before,
                        "Operation {op_idx}: Size should not change after prune_all"
                    );

                    // Pruned position should be updated
                    assert_eq!(
                        mmr.pruned_to_pos(), reference.get_pruned_to_pos(),
                        "Operation {op_idx}: Pruned position mismatch after prune_all"
                    );

                    // Root should still be computable
                    let root = mmr.root(&mut hasher);
                    assert!(
                        !root.as_ref().is_empty(),
                        "Operation {op_idx}: Root should be computable after prune_all"
                    );
                }

                MmrOperation::PruneToPos { pos_idx } => {
                    if mmr.size() > 0 {
                        // Only prune to positions within the current size (0 to size inclusive)
                        let pos = Position::new((*pos_idx) % (*mmr.size() + 1));

                        // Skip if trying to prune to a position before or equal to what's already pruned
                        if pos <= mmr.pruned_to_pos() {
                            continue;
                        }

                        // Skip if trying to prune beyond the current size
                        if pos > mmr.size() {
                            continue;
                        }

                        let size_before = mmr.size();
                        let pruned_to_pos_before = mmr.pruned_to_pos();

                        mmr.prune_to_pos(pos);
                        reference.prune_to_pos(pos);

                        // Size should remain the same
                        assert_eq!(
                            mmr.size(), size_before,
                            "Operation {op_idx}: Size should not change after prune_to_pos"
                        );

                        // Pruned position should be updated correctly
                        assert_eq!(
                            mmr.pruned_to_pos(), reference.get_pruned_to_pos(),
                            "Operation {op_idx}: Pruned position mismatch after prune_to_pos"
                        );

                        // Pruned position should not decrease
                        assert!(
                            mmr.pruned_to_pos() >= pruned_to_pos_before,
                            "Operation {op_idx}: Pruned position should not decrease"
                        );

                        // Root should still be computable
                        let root = mmr.root(&mut hasher);
                        assert!(
                            !root.as_ref().is_empty(),
                            "Operation {op_idx}: Root should be computable after prune_to_pos"
                        );
                    }
                }
            }

            // Global invariants
            if mmr.size() > 0 {
                // Last leaf position should be valid
                if let Some(last_pos) = mmr.last_leaf_pos() {
                    assert!(
                        last_pos < mmr.size(),
                        "Operation {op_idx}: Last leaf position {last_pos} >= size {}",
                         mmr.size()
                    );
                }
            } else {
                assert!(
                    mmr.last_leaf_pos().is_none(),
                    "Operation {op_idx}: Empty MMR should have no last leaf"
                );
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
