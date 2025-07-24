#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{hash, sha256::Sha256};
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
    ProofOutOfBounds {
        position: u32,
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
    RangeProofInvalidRange {
        start: u32,
        end: u32,
    },
    RangeProofOutOfBounds {
        start: u32,
        end: u32,
    },
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
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<BmtOperation>,
}

fn fuzz(input: FuzzInput) {
    let mut builder: Option<Builder<Sha256>> = None;
    let mut tree = None;
    let mut proof = None;
    let mut range_proof = None;
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
                    let digest = hash(&value.to_be_bytes());
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
                    // Only attempt proof generation for valid positions
                    if (*position as usize) < leaf_values.len() {
                        if let Ok(p) = t.proof(*position) {
                            proof = Some(p);
                        }
                    }
                }
            }

            BmtOperation::VerifyProof {
                leaf_value,
                position,
            } => {
                if let (Some(ref p), Some(ref t)) = (&proof, &tree) {
                    let mut hasher = Sha256::default();
                    let leaf_digest = hash(&leaf_value.to_be_bytes());
                    let root = t.root();
                    let _ = p.verify(&mut hasher, &leaf_digest, *position, &root);
                }
            }

            BmtOperation::SerializeProof => {
                if let Some(ref p) = proof {
                    let _ = p.encode();
                }
            }

            BmtOperation::DeserializeProof { data } => {
                let _ = Proof::<Sha256>::decode(&mut data.as_slice());
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
                    let digest = hash(&(i as u64).to_be_bytes());
                    b.add(&digest);
                    leaf_values.push(i as u64);
                }
                tree = Some(b.build());
            }

            BmtOperation::ProofOutOfBounds { position } => {
                if let Some(ref t) = tree {
                    let _ = t.proof(*position);
                }
            }

            // Range proof operations
            BmtOperation::GenerateRangeProof { start, end } => {
                if let Some(ref t) = tree {
                    // Ensure start <= end to avoid panic in range_proof
                    let safe_start = *start;
                    let safe_end = *end;

                    if safe_start <= safe_end {
                        if let Ok(rp) = t.range_proof(safe_start, safe_end) {
                            range_proof = Some(rp);
                        }
                    }
                }
            }

            BmtOperation::VerifyRangeProof {
                start_position,
                leaf_values: verify_values,
            } => {
                if let (Some(ref rp), Some(ref t)) = (&range_proof, &tree) {
                    let mut hasher = Sha256::default();
                    let root = t.root();

                    // Convert leaf values to digests
                    let leaf_digests: Vec<_> = verify_values
                        .iter()
                        .map(|v| hash(&v.to_be_bytes()))
                        .collect();
                    if !leaf_digests.is_empty() {
                        let _ = rp.verify(&mut hasher, *start_position, &leaf_digests, &root);
                    }
                }
            }

            BmtOperation::SerializeRangeProof => {
                if let Some(ref rp) = range_proof {
                    let _ = rp.encode();
                }
            }

            BmtOperation::DeserializeRangeProof { data } => {
                let _ = RangeProof::<Sha256>::decode(&mut data.as_slice());
            }

            // Range proof edge cases
            BmtOperation::RangeProofInvalidRange { start, end } => {
                if let Some(ref t) = tree {
                    // Test invalid ranges (start > end)
                    if *start > *end {
                        let _ = t.range_proof(*start, *end);
                    }
                }
            }

            BmtOperation::RangeProofOutOfBounds { start, end } => {
                if let Some(ref t) = tree {
                    // Test out of bounds ranges
                    let _ = t.range_proof(*start, *end);
                }
            }

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
                    // Test full tree range proof
                    if !leaf_values.is_empty() {
                        let last_idx = (leaf_values.len() - 1) as u32;
                        if let Ok(rp) = t.range_proof(0, last_idx) {
                            range_proof = Some(rp);
                        }
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
                    let end = proof_start.saturating_add(count as u32 - 1);

                    if let Ok(rp) = t.range_proof(*proof_start, end) {
                        let mut hasher = Sha256::default();
                        let root = t.root();

                        // Create some leaf digests for verification
                        let leaf_digests: Vec<_> = (0..count)
                            .map(|i| hash(&(i as u64).to_be_bytes()))
                            .collect();

                        // Verify with wrong position (verify_start instead of proof_start)
                        let _ = rp.verify(&mut hasher, *verify_start, &leaf_digests, &root);
                    }
                }
            }

            BmtOperation::VerifyRangeProofWrongLeaves {
                start,
                tampered_values,
            } => {
                if let (Some(ref rp), Some(ref t)) = (&range_proof, &tree) {
                    let mut hasher = Sha256::default();
                    let root = t.root();

                    // Verify with tampered values
                    let tampered_digests: Vec<_> = tampered_values
                        .iter()
                        .map(|v| hash(&v.to_be_bytes()))
                        .collect();
                    if !tampered_digests.is_empty() {
                        let _ = rp.verify(&mut hasher, *start, &tampered_digests, &root);
                    }
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
