#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{hash, sha256::Sha256};
use commonware_storage::bmt::{Builder, Proof};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum BmtOperation {
    BuildTree { leaf_count: u8 },
    AddLeaf { value: u64 },
    BuildFromLeaves,
    GetRoot,
    GenerateProof { position: u32 },
    VerifyProof { leaf_value: u64, position: u32 },
    SerializeProof,
    DeserializeProof { data: Vec<u8> },
    // Edge case operations
    BuildEmptyTree,
    BuildLargeTree { size: u8 },
    ProofOutOfBounds { position: u32 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<BmtOperation>,
}

fn fuzz(input: FuzzInput) {
    let mut builder: Option<Builder<Sha256>> = None;
    let mut tree = None;
    let mut proof = None;
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

                    // Don't panic on verification failures - they're expected
                    let _ = p.verify(&mut hasher, &leaf_digest, *position, &root);
                }
            }

            BmtOperation::SerializeProof => {
                if let Some(ref p) = proof {
                    let _serialized = p.serialize();
                }
            }

            BmtOperation::DeserializeProof { data } => {
                if Proof::<Sha256>::deserialize(data).is_ok() {}
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
                    if t.proof(*position).is_ok() {}
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
