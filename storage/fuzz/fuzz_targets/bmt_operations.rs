#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher as _, Sha256};
use commonware_storage::bmt::{Builder, Proof, RangeProof};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum BmtOperation {
    // Tree operations
    BuildTree {
        leaf_count: u8,
    },
    AddLeaf {
        value: u64,
    },
    BuildFromLeaves,
    GetRoot,
    // Proof operations
    GenerateProof {
        position: u32,
    },
    VerifyProof {
        leaf_value: u64,
        position: u32,
    },
    SerializeProof,
    DeserializeProof {
        data: Vec<u8>,
    },
    // Edge case operations
    BuildEmptyTree,
    BuildLargeTree {
        size: u8,
    },
    // Range proof operations
    GenerateRangeProof {
        start: u32,
        end: u32,
    },
    VerifyRangeProof {
        start_position: u32,
        leaf_values: Vec<u64>,
    },
    SerializeRangeProof,
    DeserializeRangeProof {
        data: Vec<u8>,
    },
    // Range proof edge cases
    RangeProofSingleElement {
        position: u32,
    },
    RangeProofFullTree,
    VerifyRangeProofWrongPosition {
        proof_start: u32,
        verify_start: u32,
        leaf_count: u8,
    },
    VerifyRangeProofWrongLeaves {
        start: u32,
        tampered_values: Vec<u64>,
    },
    // Multi-proof operations
    GenerateMultiProof {
        positions: Vec<u32>,
    },
    VerifyMultiProof {
        elements: Vec<(u64, u32)>,
    },
    DeserializeMultiProof {
        data: Vec<u8>,
        max_items: u8,
    },
    // Multi-proof edge cases
    MultiProofDuplicatePositions {
        position: u32,
        count: u8,
    },
    VerifyMultiProofWrongElements {
        tampered_elements: Vec<(u64, u32)>,
    },
    VerifyMultiProofPartialElements {
        skip_count: u8,
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<BmtOperation>,
}

fn fuzz(input: FuzzInput) {
    let mut builder: Option<Builder<Sha256>> = None;
    let mut tree = None;
    let mut proof: Option<Proof<Sha256Digest>> = None;
    let mut range_proof = None;
    let mut multi_proof: Option<Proof<Sha256Digest>> = None;
    let mut multi_proof_positions: Vec<u32> = Vec::new();
    let mut leaf_values = Vec::new();

    for op in input.operations.iter() {
        match op {
            BmtOperation::BuildTree { leaf_count } => {
                let count = (*leaf_count as usize).min(50); // Limit to avoid excessive memory usage
                builder = Some(Builder::new(count));
                leaf_values.clear();
            }

            BmtOperation::AddLeaf { value } => {
                if let Some(ref mut b) = builder {
                    let digest = Sha256::hash(&value.to_be_bytes());
                    b.add(&digest);
                    leaf_values.push(*value);
                }
            }

            BmtOperation::BuildFromLeaves => {
                if let Some(b) = builder.take() {
                    tree = Some(b.build());
                }
            }

            BmtOperation::GetRoot => {
                if let Some(ref t) = tree {
                    t.root();
                }
            }

            BmtOperation::GenerateProof { position } => {
                if let Some(ref t) = tree {
                    if let Ok(p) = t.proof(*position) {
                        proof = Some(p);
                    }
                }
            }

            BmtOperation::VerifyProof {
                leaf_value,
                position,
            } => {
                if let (Some(ref p), Some(ref t)) = (&proof, &tree) {
                    let mut hasher = Sha256::default();
                    let leaf_digest = Sha256::hash(&leaf_value.to_be_bytes());
                    let root = t.root();
                    let _ = p.verify_element_inclusion(&mut hasher, &leaf_digest, *position, &root);
                }
            }

            BmtOperation::SerializeProof => {
                if let Some(ref p) = proof {
                    let _ = p.encode();
                }
            }

            BmtOperation::DeserializeProof { data } => {
                // Use max_items=1 since we're fuzzing single-element proofs
                let _ = Proof::<Sha256Digest>::decode_cfg(&mut data.as_slice(), &1);
            }

            BmtOperation::BuildEmptyTree => {
                let b = Builder::<Sha256>::new(0);
                tree = Some(b.build());
                leaf_values.clear();
            }

            BmtOperation::BuildLargeTree { size } => {
                let count = (*size as usize).min(100); // Limit size
                let mut b = Builder::new(count);
                leaf_values.clear();

                for i in 0..count {
                    let digest = Sha256::hash(&(i as u64).to_be_bytes());
                    b.add(&digest);
                    leaf_values.push(i as u64);
                }
                tree = Some(b.build());
            }

            // Range proof operations
            BmtOperation::GenerateRangeProof { start, end } => {
                if let Some(ref t) = tree {
                    if let Ok(rp) = t.range_proof(*start, *end) {
                        range_proof = Some(rp);
                    }
                }
            }

            BmtOperation::VerifyRangeProof {
                start_position,
                leaf_values,
            } => {
                if let (Some(ref rp), Some(ref t)) = (&range_proof, &tree) {
                    // Convert leaf values to digests
                    let mut hasher = Sha256::default();
                    let leaf_digests: Vec<_> = leaf_values
                        .iter()
                        .map(|v| Sha256::hash(&v.to_be_bytes()))
                        .collect();

                    // Verify range proof
                    let root = t.root();
                    let _ = rp.verify(&mut hasher, *start_position, &leaf_digests, &root);
                }
            }

            BmtOperation::SerializeRangeProof => {
                if let Some(ref rp) = range_proof {
                    let _ = rp.encode();
                }
            }

            BmtOperation::DeserializeRangeProof { data } => {
                let _ = RangeProof::<Sha256Digest>::decode(&mut data.as_slice());
            }

            // Range proof edge cases
            BmtOperation::RangeProofSingleElement { position } => {
                if let Some(ref t) = tree {
                    // Test single element range proof
                    if let Ok(rp) = t.range_proof(*position, *position) {
                        range_proof = Some(rp);
                    }
                }
            }

            BmtOperation::RangeProofFullTree => {
                if let Some(ref t) = tree {
                    let last_idx = leaf_values.len().saturating_sub(1) as u32;
                    if let Ok(rp) = t.range_proof(0, last_idx) {
                        range_proof = Some(rp);
                    }
                }
            }

            BmtOperation::VerifyRangeProofWrongPosition {
                proof_start,
                verify_start,
                leaf_count,
            } => {
                if let Some(ref t) = tree {
                    // Generate a range proof at proof_start position
                    let count = (*leaf_count as usize).clamp(1, 10);
                    let start_idx = *proof_start as usize;

                    // Ensure we have enough leaves and the range is valid
                    if start_idx < leaf_values.len() {
                        let actual_count = count.min(leaf_values.len() - start_idx);
                        let end = proof_start.saturating_add(actual_count as u32 - 1);
                        if let Ok(rp) = t.range_proof(*proof_start, end) {
                            // Use real leaf values from the tree starting at proof_start
                            let mut hasher = Sha256::default();
                            let leaf_digests: Vec<_> = leaf_values
                                [start_idx..start_idx + actual_count]
                                .iter()
                                .map(|v| Sha256::hash(&v.to_be_bytes()))
                                .collect();

                            // Verify with wrong position (verify_start instead of proof_start)
                            let root = t.root();
                            let _ = rp.verify(&mut hasher, *verify_start, &leaf_digests, &root);
                        }
                    }
                }
            }

            BmtOperation::VerifyRangeProofWrongLeaves {
                start,
                tampered_values,
            } => {
                if let (Some(ref rp), Some(ref t)) = (&range_proof, &tree) {
                    // Generate tampered digests
                    let mut hasher = Sha256::default();
                    let tampered_digests: Vec<_> = tampered_values
                        .iter()
                        .map(|v| Sha256::hash(&v.to_be_bytes()))
                        .collect();

                    // Verify with tampered digests
                    let root = t.root();
                    let _ = rp.verify(&mut hasher, *start, &tampered_digests, &root);
                }
            }

            // Multi-proof operations
            BmtOperation::GenerateMultiProof { positions } => {
                if let Some(ref t) = tree {
                    // Limit positions to avoid excessive memory usage
                    let limited_positions: Vec<u32> = positions.iter().take(20).copied().collect();
                    if let Ok(mp) = t.multi_proof(&limited_positions) {
                        multi_proof = Some(mp);
                        multi_proof_positions = limited_positions;
                    }
                }
            }

            BmtOperation::VerifyMultiProof { elements } => {
                if let (Some(ref mp), Some(ref t)) = (&multi_proof, &tree) {
                    let mut hasher = Sha256::default();
                    // Convert (value, position) pairs to (digest, position)
                    let element_digests: Vec<_> = elements
                        .iter()
                        .take(20) // Limit elements
                        .map(|(v, pos)| (Sha256::hash(&v.to_be_bytes()), *pos))
                        .collect();
                    let root = t.root();
                    let _ = mp.verify_multi_inclusion(&mut hasher, &element_digests, &root);
                }
            }

            BmtOperation::DeserializeMultiProof { data, max_items } => {
                // Use max_items from fuzz input, clamped to reasonable range
                let max = (*max_items as usize).clamp(1, 100);
                let _ = Proof::<Sha256Digest>::decode_cfg(&mut data.as_slice(), &max);
            }

            BmtOperation::MultiProofDuplicatePositions { position, count } => {
                if let Some(ref t) = tree {
                    // Create a positions array with duplicates
                    let count = (*count as usize).clamp(2, 10);
                    let positions: Vec<u32> = vec![*position; count];
                    if let Ok(mp) = t.multi_proof(&positions) {
                        multi_proof = Some(mp);
                        multi_proof_positions = positions;
                    }
                }
            }

            BmtOperation::VerifyMultiProofWrongElements { tampered_elements } => {
                if let (Some(ref mp), Some(ref t)) = (&multi_proof, &tree) {
                    let mut hasher = Sha256::default();
                    // Convert tampered (value, position) pairs to (digest, position)
                    let tampered_digests: Vec<_> = tampered_elements
                        .iter()
                        .take(20)
                        .map(|(v, pos)| (Sha256::hash(&v.to_be_bytes()), *pos))
                        .collect();
                    let root = t.root();
                    let _ = mp.verify_multi_inclusion(&mut hasher, &tampered_digests, &root);
                }
            }

            BmtOperation::VerifyMultiProofPartialElements { skip_count } => {
                if let (Some(ref mp), Some(ref t)) = (&multi_proof, &tree) {
                    if !multi_proof_positions.is_empty() && !leaf_values.is_empty() {
                        let mut hasher = Sha256::default();
                        // Skip some elements from the original proof
                        let skip = (*skip_count as usize) % multi_proof_positions.len().max(1);
                        let partial_elements: Vec<_> = multi_proof_positions
                            .iter()
                            .skip(skip)
                            .filter_map(|&pos| {
                                leaf_values
                                    .get(pos as usize)
                                    .map(|v| (Sha256::hash(&v.to_be_bytes()), pos))
                            })
                            .collect();
                        let root = t.root();
                        let _ = mp.verify_multi_inclusion(&mut hasher, &partial_elements, &root);
                    }
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
