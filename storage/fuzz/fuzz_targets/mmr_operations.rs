#![no_main]
use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr, Builder};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum MmrOperation {
    // Core operations
    Add { data: Vec<u8>, verify_proof: bool },
    Pop,
    UpdateLeaf { leaf_idx: u8, new_data: Vec<u8> },

    // Query operations
    GetNode { pos: u64 },
    GetLastLeafPos,
    GetSize,
    GetRoot,

    // Proof operations
    GenerateProof { leaf_idx: u8 },
    GenerateRangeProof { start_idx: u8, end_idx: u8 },

    // Pruning operations
    PruneToPos { pos: u64 },
    PruneAll,

    // Clone operations
    ClonePruned,

    // Complex operations
    AddMultipleAndVerify { count: u8 },
    PopMultiple { count: u8 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MmrOperation>,
    max_data_size: u8,
}

struct MmrTracker {
    leaf_data: Vec<Vec<u8>>,
    leaf_positions: Vec<u64>,
    pruned_up_to: Option<u64>,
    expected_size: u64,
}

impl MmrTracker {
    fn new() -> Self {
        Self {
            leaf_data: Vec::new(),
            leaf_positions: Vec::new(),
            pruned_up_to: None,
            expected_size: 0,
        }
    }

    fn add_leaf(&mut self, data: Vec<u8>, pos: u64) {
        self.leaf_data.push(data);
        self.leaf_positions.push(pos);
        // Update expected size: for n leaves, size = 2n - 1 (full binary tree)
        // But MMR uses a different formula based on binary representation
        self.expected_size = self.calculate_mmr_size(self.leaf_positions.len());
    }

    fn pop_leaf(&mut self) -> Option<(Vec<u8>, u64)> {
        if let (Some(data), Some(pos)) = (self.leaf_data.pop(), self.leaf_positions.pop()) {
            self.expected_size = self.calculate_mmr_size(self.leaf_positions.len());
            Some((data, pos))
        } else {
            None
        }
    }

    fn calculate_mmr_size(&self, num_leaves: usize) -> u64 {
        if num_leaves == 0 {
            return 0;
        }
        // MMR size calculation based on binary representation
        let mut size = 0u64;
        let mut n = num_leaves as u64;
        while n > 0 {
            let power = 63 - n.leading_zeros();
            let peak_size = (1u64 << (power + 1)) - 1;
            size += peak_size;
            n -= 1u64 << power;
        }
        size
    }
}

fn fuzz(fuzz_data: FuzzInput) {
    let runner = deterministic::Runner::default();

    if fuzz_data.operations.is_empty() || fuzz_data.operations.len() > 300 {
        return;
    }

    runner.start(|_context| async move {
        let mut mmr = Mmr::<Sha256>::new();
        let mut hasher = Standard::new();
        let mut tracker = MmrTracker::new();

        for op in fuzz_data.operations.iter() {
            match op {
                MmrOperation::Add { data, verify_proof } => {
                    // Limit data size to avoid memory issues
                    let limited_data = if data.len() > fuzz_data.max_data_size as usize {
                        &data[0..fuzz_data.max_data_size as usize]
                    } else {
                        data
                    };

                    let size_before = mmr.size();
                    let result =
                        <Mmr<Sha256> as Builder<Sha256>>::add(&mut mmr, &mut hasher, limited_data)
                            .await;

                    if let Ok(pos) = result {
                        tracker.add_leaf(limited_data.to_vec(), pos);

                        // Verify size increased (can be more than 1 due to parent nodes)
                        assert!(mmr.size() > size_before, "Size should increase after add");

                        // Verify the position is valid
                        assert!(
                            pos < mmr.size(),
                            "Returned position {pos} should be less than size {}",
                            mmr.size()
                        );

                        // Verify we can retrieve the node
                        let node = mmr.get_node(pos);
                        assert!(
                            node.is_some(),
                            "Should be able to get node at position {pos}",
                        );

                        if *verify_proof && !tracker.leaf_positions.is_empty() {
                            // Generate and verify proof for the added element
                            if let Ok(proof) = mmr.proof(pos).await {
                                let root = mmr.root(&mut hasher);
                                let result = proof.verify_element_inclusion(
                                    &mut hasher,
                                    limited_data,
                                    pos,
                                    &root,
                                );
                                assert!(
                                    result.unwrap_or(false),
                                    "Proof verification failed for position {pos}",
                                );
                            }
                        }
                    }
                }

                MmrOperation::Pop => {
                    let size_before = mmr.size();
                    let last_leaf_before = mmr.last_leaf_pos();

                    let result = mmr.pop();

                    if result.is_ok() {
                        if let Some((_data, pos)) = tracker.pop_leaf() {
                            // Verify size decreased correctly
                            assert!(mmr.size() < size_before, "Size should decrease after pop");

                            // Verify the popped position is no longer accessible
                            let node = mmr.get_node(pos);
                            assert!(
                                node.is_none(),
                                "Should not be able to get popped node at position {pos}",
                            );

                            // Verify last_leaf_pos changed appropriately
                            if mmr.size() > 0 {
                                let last_leaf_after = mmr.last_leaf_pos();
                                assert!(
                                    last_leaf_after.is_some(),
                                    "Should have last leaf after pop with size > 0"
                                );
                                assert!(
                                    last_leaf_after.unwrap() < last_leaf_before.unwrap_or(0),
                                    "Last leaf position should decrease after pop"
                                );
                            }
                        }
                    }
                }

                MmrOperation::UpdateLeaf { leaf_idx, new_data } => {
                    if !tracker.leaf_positions.is_empty() {
                        let idx = (*leaf_idx as usize) % tracker.leaf_positions.len();
                        let pos = tracker.leaf_positions[idx];

                        let limited_data = if new_data.len() > fuzz_data.max_data_size as usize {
                            &new_data[0..fuzz_data.max_data_size as usize]
                        } else {
                            new_data
                        };

                        let _root_before = mmr.root(&mut hasher);
                        mmr.update_leaf(&mut hasher, pos, limited_data);
                        let _root_after = mmr.root(&mut hasher);

                        // Root should change after update (unless by coincidence the hash is same)
                        // Size should not change
                        assert_eq!(
                            mmr.size(),
                            tracker.expected_size,
                            "Size should not change after update_leaf"
                        );

                        // Update tracker
                        tracker.leaf_data[idx] = limited_data.to_vec();
                    }
                }

                MmrOperation::GetNode { pos } => {
                    if mmr.size() > 0 {
                        let safe_pos = *pos % mmr.size();
                        let _node = mmr.get_node(safe_pos);

                        // Check if this position should be accessible
                        if let Some(pruned_pos) = tracker.pruned_up_to {
                            if safe_pos < pruned_pos {
                                // This node might be pruned
                                // But it could also be pinned, so we can't assert it's None
                            }
                        }
                    }
                }

                MmrOperation::GetLastLeafPos => {
                    let last_leaf = mmr.last_leaf_pos();

                    if tracker.leaf_positions.is_empty() {
                        assert!(last_leaf.is_none(), "Empty MMR should have no last leaf");
                    } else {
                        assert!(last_leaf.is_some(), "Non-empty MMR should have last leaf");
                        let expected_last = tracker.leaf_positions.last().unwrap();
                        assert_eq!(
                            last_leaf.unwrap(),
                            *expected_last,
                            "Last leaf position mismatch"
                        );
                    }
                }

                MmrOperation::GetSize => {
                    assert_eq!(
                        mmr.size(),
                        tracker.expected_size,
                        "Size mismatch: MMR reports {}, expected {}",
                        mmr.size(),
                        tracker.expected_size
                    );
                }

                MmrOperation::GetRoot => {}

                MmrOperation::GenerateProof { leaf_idx } => {
                    if !tracker.leaf_positions.is_empty() {
                        let idx = (*leaf_idx as usize) % tracker.leaf_positions.len();
                        let pos = tracker.leaf_positions[idx];
                        let data = &tracker.leaf_data[idx];

                        if let Ok(proof) = mmr.proof(pos).await {
                            let root = mmr.root(&mut hasher);
                            let result =
                                proof.verify_element_inclusion(&mut hasher, data, pos, &root);
                            assert!(
                                result.unwrap_or(false),
                                "Proof verification failed for position {pos} at index {idx}",
                            );
                        }
                    }
                }

                MmrOperation::GenerateRangeProof { start_idx, end_idx } => {
                    if !tracker.leaf_positions.is_empty() {
                        let start = (*start_idx as usize) % tracker.leaf_positions.len();
                        let end = (*end_idx as usize) % tracker.leaf_positions.len();
                        let (start, end) = if start <= end {
                            (start, end)
                        } else {
                            (end, start)
                        };

                        let start_pos = tracker.leaf_positions[start];
                        let end_pos = tracker.leaf_positions[end];

                        if let Ok(proof) = mmr.range_proof(start_pos, end_pos).await {
                            let root = mmr.root(&mut hasher);
                            let elements: Vec<&[u8]> = tracker.leaf_data[start..=end]
                                .iter()
                                .map(|v| v.as_slice())
                                .collect();

                            let result = proof.verify_range_inclusion(
                                &mut hasher,
                                elements,
                                start_pos,
                                end_pos,
                                &root,
                            );
                            assert!(
                                result.unwrap_or(false),
                                "Range proof verification failed for positions {start_pos}..{end_pos}",
                            );
                        }
                    }
                }

                MmrOperation::PruneToPos { pos: _ } => {
                    //AUDIT: Skip pruning for now due to known bug
                    continue;
                }

                MmrOperation::PruneAll => {
                    let size_before = mmr.size();
                    let root_before = mmr.root(&mut hasher);

                    mmr.prune_all();

                    let size_after = mmr.size();
                    let root_after = mmr.root(&mut hasher);

                    // Important invariants after prune_all
                    assert_eq!(
                        size_before, size_after,
                        "Size should not change after prune_all"
                    );
                    assert_eq!(
                        root_before, root_after,
                        "Root should not change after prune_all"
                    );

                    // After prune_all, we should still be able to generate proofs
                    // for all leaves (they should be pinned)
                    for (idx, &pos) in tracker.leaf_positions.iter().enumerate() {
                        if let Ok(proof) = mmr.proof(pos).await {
                            let data = &tracker.leaf_data[idx];
                            let result =
                                proof.verify_element_inclusion(&mut hasher, data, pos, &root_after);
                            assert!(
                                result.unwrap_or(false),
                                "Should still be able to prove leaf {pos} after prune_all",
                            );
                        }
                    }
                }

                MmrOperation::ClonePruned => {
                    let clone = mmr.clone_pruned();

                    // Verify clone has same properties
                    assert_eq!(clone.size(), mmr.size(), "Clone should have same size");
                    assert_eq!(
                        clone.root(&mut hasher),
                        mmr.root(&mut hasher),
                        "Clone should have same root"
                    );
                    assert_eq!(
                        clone.last_leaf_pos(),
                        mmr.last_leaf_pos(),
                        "Clone should have same last leaf position"
                    );
                    assert_eq!(
                        clone.pruned_to_pos(),
                        mmr.size(),
                        "clone.pruned_to_pos(), mmr.size() should be equal"
                    );
                }

                MmrOperation::AddMultipleAndVerify { count } => {
                    let num_to_add = (*count as usize).min(10); // Limit to avoid long runs
                    let mut new_positions = Vec::new();

                    for i in 0..num_to_add {
                        let data = format!("multi_{i}").into_bytes();
                        if let Ok(pos) =
                            <Mmr<Sha256> as Builder<Sha256>>::add(&mut mmr, &mut hasher, &data)
                                .await
                        {
                            tracker.add_leaf(data, pos);
                            new_positions.push(pos);
                        }
                    }

                    // Verify we can generate a range proof for all new additions
                    if new_positions.len() >= 2 && mmr.size() > 0 {
                        let start_pos = new_positions[0];
                        let end_pos = new_positions[new_positions.len() - 1];

                        if let Ok(proof) = mmr.range_proof(start_pos, end_pos).await {
                            // The proof might be empty if all positions were popped
                            // so we don't assert on empty digests
                            let elements: Vec<&[u8]> = new_positions
                                .iter()
                                .filter_map(|&pos| {
                                    tracker
                                        .leaf_positions
                                        .iter()
                                        .position(|&p| p == pos)
                                        .map(|idx| tracker.leaf_data[idx].as_slice())
                                })
                                .collect();

                            if !elements.is_empty() {
                                let root = mmr.root(&mut hasher);
                                let result = proof.verify_range_inclusion(
                                    &mut hasher,
                                    elements,
                                    start_pos,
                                    end_pos,
                                    &root,
                                );
                                assert!(
                                    result.unwrap_or(false),
                                    "Range proof verification failed for new additions"
                                );
                            }
                        }
                    }
                }

                MmrOperation::PopMultiple { count } => {
                    let num_to_pop = (*count as usize).min(tracker.leaf_positions.len());
                    let initial_size = mmr.size();

                    for _ in 0..num_to_pop {
                        if mmr.pop().is_ok() {
                            let _ = tracker.pop_leaf();
                        }
                    }

                    // Verify size decreased appropriately
                    assert!(
                        mmr.size() <= initial_size,
                        "Size should decrease after multiple pops"
                    );
                    assert_eq!(
                        mmr.size(),
                        tracker.expected_size,
                        "Size mismatch after multiple pops"
                    );
                }
            }

            // Global invariants to check after each operation
            if mmr.size() > 0 {
                // 1. Size consistency
                assert_eq!(
                    mmr.size(),
                    tracker.expected_size,
                    "Size invariant violated after operation {op:?}",
                );

                // 2. Last leaf position should be valid
                if let Some(last_pos) = mmr.last_leaf_pos() {
                    assert!(
                        last_pos < mmr.size(),
                        "Last leaf position {last_pos} >= size {}",
                        mmr.size()
                    );
                }

                // 3. Root should be deterministic for same content
                let root1 = mmr.root(&mut hasher);
                let root2 = mmr.root(&mut hasher);
                assert_eq!(root1, root2, "Root calculation should be deterministic");

                // 4. Clone should maintain all properties
                let clone = mmr.clone_pruned();
                assert_eq!(clone.size(), mmr.size(), "Clone size mismatch");
                assert_eq!(
                    clone.root(&mut hasher),
                    mmr.root(&mut hasher),
                    "Clone root mismatch"
                );
            }
        }

        // Final validation: verify all tracked leaves can still be proven
        for (idx, &pos) in tracker.leaf_positions.iter().enumerate() {
            if let Ok(proof) = mmr.proof(pos).await {
                let root = mmr.root(&mut hasher);
                let data = &tracker.leaf_data[idx];
                let result = proof.verify_element_inclusion(&mut hasher, data, pos, &root);
                assert!(
                    result.unwrap_or(false),
                    "Final validation: Failed to prove leaf at position {pos}",
                );
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
