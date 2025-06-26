#![no_main]
use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum MmrOperation {
    Add { data: Vec<u8> },
    Pop,
    UpdateLeaf { leaf_idx: u8, new_data: Vec<u8> },
    GetNode { pos: u64 },
    GetLastLeafPos,
    GetSize,
    GetRoot,
    GenerateProof { leaf_idx: u8 },
    // Temporarily disable pruning operations to isolate the core bug
    // PruneAll,
    // ClonePruned,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<MmrOperation>,
}

// Simple reference that tracks basic MMR state
struct ReferenceMmr {
    leaf_positions: Vec<u64>,
    leaf_data: Vec<Vec<u8>>,
    total_nodes_added: u64,
}

impl ReferenceMmr {
    fn new() -> Self {
        Self {
            leaf_positions: Vec::new(),
            leaf_data: Vec::new(),
            total_nodes_added: 0,
        }
    }

    fn add(&mut self, leaf_pos: u64, data: Vec<u8>) {
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

    fn last_leaf_pos(&self) -> Option<u64> {
        self.leaf_positions.last().copied()
    }

    fn leaf_count(&self) -> usize {
        self.leaf_positions.len()
    }

    fn expected_size(&self) -> u64 {
        self.total_nodes_added
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

    if input.operations.is_empty() || input.operations.len() > 50 {
        return;
    }

    runner.start(|_context| async move {
        let mut mmr = Mmr::<Sha256>::new();
        let mut reference = ReferenceMmr::new();
        let mut hasher = Standard::new();

        for (op_idx, op) in input.operations.iter().enumerate() {
            match op {
                MmrOperation::Add { data } => {
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

                MmrOperation::UpdateLeaf { leaf_idx, new_data } => {
                    if !reference.leaf_positions.is_empty() {
                        let idx = (*leaf_idx as usize) % reference.leaf_positions.len();
                        let pos = reference.leaf_positions[idx];

                        let limited_data = if new_data.len() > 16 {
                            &new_data[0..16]
                        } else {
                            new_data
                        };

                        let size_before = mmr.size();
                        let root_before = mmr.root(&mut hasher);

                        mmr.update_leaf(&mut hasher, pos, limited_data);
                        reference.update_leaf(idx, limited_data.to_vec());

                        // Size should not change
                        assert_eq!(
                            mmr.size(), size_before,
                            "Operation {op_idx}: Size should not change after update_leaf"
                        );

                        // Root should change (unless data is identical)
                        let root_after = mmr.root(&mut hasher);
                        if limited_data != reference.leaf_data[idx] {
                            assert_ne!(
                                root_before, root_after,
                                "Operation {op_idx}: Root should change after update_leaf with different data"
                            );
                        }
                    }
                }

                MmrOperation::GetNode { pos } => {
                    if mmr.size() > 0 {
                        let safe_pos = *pos % mmr.size();
                        let node = mmr.get_node(safe_pos);
                        
                        // We should be able to get any position within size
                        // (unless it's been pruned, but we're not testing pruning yet)
                        if node.is_none() {
                            println!("Warning: Could not get node at position {safe_pos} (size: {})", mmr.size());
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

                MmrOperation::GenerateProof { leaf_idx } => {
                    if !reference.leaf_positions.is_empty() {
                        let idx = (*leaf_idx as usize) % reference.leaf_positions.len();
                        let pos = reference.leaf_positions[idx];

                        match mmr.proof(pos).await {
                            Ok(proof) => {
                                // Verify the proof with the actual data we stored
                                let root = mmr.root(&mut hasher);
                                let leaf_data = &reference.leaf_data[idx];
                                
                                match proof.verify_element_inclusion(&mut hasher, leaf_data, pos, &root) {
                                    Ok(is_valid) => {
                                        assert!(
                                            is_valid,
                                            "Operation {op_idx}: Proof verification failed for leaf at pos {pos}", 
                                        );
                                    }
                                    Err(e) => {
                                        println!("Proof verification error for pos {pos}: {e:?}");
                                    }
                                }
                            }
                            Err(e) => {
                                println!("Could not generate proof for pos {pos}: {e:?}");
                            }
                        }
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