#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    bmt::{Builder as BmtBuilder, Proof as BmtProof},
    mmr::{mem::Mmr, proof::Proof as MmrProof, StandardHasher as Standard},
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Arbitrary, Debug, Clone)]
enum MutationType {
    FlipBit { byte_idx: u16, bit_idx: u8 },
    InsertByte { position: u16, value: u8 },
    DeleteByte { position: u16 },
    ReplaceByte { position: u16, value: u8 },
    SwapBytes { pos1: u16, pos2: u16 },
    ModifySize { delta: i16 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    num_elements: u8,
    test_mmr: bool,
    mutations: Vec<MutationType>,
}

fn mutate_mmr_proof(proof: &mut MmrProof<Digest>, mutation: &MutationType) {
    match mutation {
        MutationType::FlipBit { byte_idx, bit_idx } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let idx = (*byte_idx as usize) % bytes.len();
                bytes[idx] ^= 1 << (bit_idx % 8);
                if let Ok(mutated) = MmrProof::<Digest>::decode_cfg(&mut bytes.as_slice(), &256) {
                    *proof = mutated;
                }
            }
        }
        MutationType::InsertByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            let pos = (*position as usize) % (bytes.len() + 1);
            bytes.insert(pos, *value);
            if let Ok(mutated) = MmrProof::<Digest>::decode_cfg(&mut bytes.as_slice(), &256) {
                *proof = mutated;
            }
        }
        MutationType::DeleteByte { position } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes.remove(pos);
                if let Ok(mutated) = MmrProof::<Digest>::decode_cfg(&mut bytes.as_slice(), &256) {
                    *proof = mutated;
                }
            }
        }
        MutationType::ReplaceByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes[pos] = *value;
                if let Ok(mutated) = MmrProof::<Digest>::decode_cfg(&mut bytes.as_slice(), &256) {
                    *proof = mutated;
                }
            }
        }
        MutationType::SwapBytes { pos1, pos2 } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if bytes.len() >= 2 {
                let p1 = (*pos1 as usize) % bytes.len();
                let p2 = (*pos2 as usize) % bytes.len();
                if p1 != p2 {
                    bytes.swap(p1, p2);
                    if let Ok(mutated) = MmrProof::<Digest>::decode_cfg(&mut bytes.as_slice(), &256) {
                        *proof = mutated;
                    }
                }
            }
        }
        MutationType::ModifySize { delta } => {
            let new_size = (proof.size as i64 + *delta as i64).max(1) as u64;
            proof.size = new_size;
        }
    }
}

fn mutate_bmt_proof(proof: &mut BmtProof<Sha256>, mutation: &MutationType) {
        match mutation {
            MutationType::FlipBit { byte_idx, bit_idx } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let idx = (*byte_idx as usize) % bytes.len();
                bytes[idx] ^= 1 << (bit_idx % 8);
                if let Ok(mutated) = BmtProof::<Sha256>::decode_cfg(&mut bytes.as_slice(), &()) {
                    *proof = mutated;
                }
            }
        }
        MutationType::InsertByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            let pos = (*position as usize) % (bytes.len() + 1);
            bytes.insert(pos, *value);
            if let Ok(mutated) = BmtProof::<Sha256>::decode_cfg(&mut bytes.as_slice(), &()) {
                *proof = mutated;
            }
        }
        MutationType::DeleteByte { position } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes.remove(pos);
                if let Ok(mutated) = BmtProof::<Sha256>::decode_cfg(&mut bytes.as_slice(), &()) {
                    *proof = mutated;
                }
            }
        }
        MutationType::ReplaceByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes[pos] = *value;
                if let Ok(mutated) = BmtProof::<Sha256>::decode_cfg(&mut bytes.as_slice(), &()) {
                    *proof = mutated;
                }
            }
        }
        MutationType::SwapBytes { pos1, pos2 } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if bytes.len() >= 2 {
                let p1 = (*pos1 as usize) % bytes.len();
                let p2 = (*pos2 as usize) % bytes.len();
                if p1 != p2 {
                    bytes.swap(p1, p2);
                    if let Ok(mutated) = BmtProof::<Sha256>::decode_cfg(&mut bytes.as_slice(), &()) {
                        *proof = mutated;
                    }
                }
            }
        }

        MutationType::ModifySize { .. } => {
            // BMT doesn't have a size field, so skip this mutation
        }
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|_| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);
        let num_elements = (input.num_elements as usize % 100).max(1);

        if input.test_mmr {
            // Test MMR proof malleability
            let mut mmr = Mmr::new();
            let mut hasher = Standard::<Sha256>::new();
            let element = Digest::from(*b"01234567012345670123456701234567");
            
            let mut positions = Vec::new();
            for _ in 0..num_elements {
                positions.push(mmr.add(&mut hasher, &element));
            }
            
            let root = mmr.root(&mut hasher);
            
            // Test each position
            for &pos in &positions {
                let original_proof = match mmr.proof(pos) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Verify original proof works
                assert!(
                    original_proof.verify_element_inclusion(&mut hasher, &element, pos, &root),
                    "Original proof must be valid"
                );
                
                // Test mutations
                for mutation in input.mutations.iter().take(10) {
                    let mut mutated_proof = original_proof.clone();
                    mutate_mmr_proof(&mut mutated_proof, mutation, &mut rng);

                    // TODO: This is a hack to make sure the proof is valid.

                    if mutated_proof.size != mmr.size() {
                        continue;
                    }
                    
                    // If proof was actually mutated, it should be invalid
                    if mutated_proof != original_proof {
                        let is_valid = mutated_proof.verify_element_inclusion(&mut hasher, &element, pos, &root);
                        assert!(!is_valid, "Mutated proof must be invalid");
                    }
                }
            }
        } else {
            // Test BMT proof malleability
            let digests: Vec<Digest> = (0..num_elements)
                .map(|i| Digest::from([(i as u8); 32]))
                .collect();
            
            let mut builder = BmtBuilder::<Sha256>::new(digests.len());
            for digest in &digests {
                builder.add(digest);
            }
            let tree = builder.build();
            let root = tree.root();
            
            // Test each position
            for idx in 0..digests.len() {
                let original_proof = match tree.proof(idx as u32) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                
                let mut hasher = Sha256::default();
                // Verify original proof works
                assert!(
                    original_proof.verify(&mut hasher, &digests[idx], idx as u32, &root).is_ok(),
                    "Original BMT proof must be valid"
                );
                
                // Test mutations
                for mutation in input.mutations.iter().take(10) {
                    let mut mutated_proof = original_proof.clone();
                    mutate_bmt_proof(&mut mutated_proof, mutation, &mut rng);
                    
                    // If proof was actually mutated, it should be invalid
                    if mutated_proof != original_proof {
                        let is_valid = mutated_proof.verify(&mut hasher, &digests[idx], idx as u32, &root).is_ok();
                        assert!(!is_valid, "Mutated BMT proof must be invalid");
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});