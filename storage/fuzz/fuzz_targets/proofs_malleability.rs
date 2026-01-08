#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{
    bmt::Builder as BmtBuilder,
    mmr::{mem::CleanMmr, Location, StandardHasher as Standard},
};
use libfuzzer_sys::fuzz_target;

const MAX_MUTATIONS: usize = 50;

#[derive(Arbitrary, Debug, Clone)]
enum Mutation {
    FlipBit { position: u16, bit_idx: u8 },
    InsertByte { position: u16, value: u8 },
    DeleteByte { position: u16 },
    ReplaceByte { position: u16, value: u8 },
    SwapBytes { pos1: u16, pos2: u16 },
}

#[derive(Arbitrary, Debug)]
enum ProofType {
    Mmr,
    Bmt,
}

#[derive(Debug)]
struct FuzzInput {
    num_elements: u8,
    proof: ProofType,
    mutations: Vec<Mutation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_elements = u.arbitrary()?;
        let proof = u.arbitrary()?;
        let num_mutations = u.int_in_range(1..=MAX_MUTATIONS)?;
        let mutations = (0..num_mutations)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput {
            num_elements,
            proof,
            mutations,
        })
    }
}

fn mutate_proof_bytes<P, C>(proof: &mut P, mutation: &Mutation, cfg: &C)
where
    P: Encode + Decode<Cfg = C>,
{
    match mutation {
        Mutation::FlipBit { position, bit_idx } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let idx = (*position as usize) % bytes.len();
                bytes[idx] ^= 1 << (bit_idx % 8);
                if let Ok(mutated) = P::decode_cfg(bytes.as_slice(), cfg) {
                    *proof = mutated;
                }
            }
        }
        Mutation::InsertByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            let pos = (*position as usize) % (bytes.len() + 1);
            bytes.insert(pos, *value);
            if let Ok(mutated) = P::decode_cfg(bytes.as_slice(), cfg) {
                *proof = mutated;
            }
        }
        Mutation::DeleteByte { position } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes.remove(pos);
                if let Ok(mutated) = P::decode_cfg(bytes.as_slice(), cfg) {
                    *proof = mutated;
                }
            }
        }
        Mutation::ReplaceByte { position, value } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if !bytes.is_empty() {
                let pos = (*position as usize) % bytes.len();
                bytes[pos] = *value;
                if let Ok(mutated) = P::decode_cfg(bytes.as_slice(), cfg) {
                    *proof = mutated;
                }
            }
        }
        Mutation::SwapBytes { pos1, pos2 } => {
            let serialized = proof.encode();
            let mut bytes = serialized.to_vec();
            if bytes.len() >= 2 {
                let p1 = (*pos1 as usize) % bytes.len();
                let p2 = (*pos2 as usize) % bytes.len();
                if p1 != p2 {
                    bytes.swap(p1, p2);
                    if let Ok(mutated) = P::decode_cfg(bytes.as_slice(), cfg) {
                        *proof = mutated;
                    }
                }
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|_| async move {
        let num_elements = (input.num_elements as u64).max(1);

        match input.proof {
            ProofType::Mmr => {
                let mut hasher = Standard::<Sha256>::new();
                let mut mmr = CleanMmr::new(&mut hasher);
                let element = Digest::from(*b"01234567012345670123456701234567");

                let mut leaves = Vec::new();
                for _ in 0u64..num_elements {
                    leaves.push(mmr.add(&mut hasher, &element));
                }

                let root = mmr.root();

                for leaf in 0u64..num_elements {
                    let loc = Location::new(leaf).unwrap();
                    let original_proof = mmr.proof(loc).unwrap();

                    assert!(
                        original_proof.verify_element_inclusion(&mut hasher, &element, loc, root),
                        "Original MMR proof must be valid"
                    );

                    for mutation in &input.mutations {
                        let mut mutated_proof = original_proof.clone();
                        mutate_proof_bytes(&mut mutated_proof, mutation, &256);

                        if mutated_proof != original_proof {
                            let is_valid = mutated_proof.verify_element_inclusion(
                                &mut hasher,
                                &element,
                                loc,
                                root,
                            );
                            assert!(!is_valid, "Mutated MMR proof must be invalid");
                        }
                    }
                }
            }
            ProofType::Bmt => {
                let digests: Vec<Digest> = (0..num_elements)
                    .map(|i| Digest::from([(i as u8); 32]))
                    .collect();

                let mut builder = BmtBuilder::<Sha256>::new(digests.len());
                for digest in &digests {
                    builder.add(digest);
                }
                let tree = builder.build();
                let root = tree.root();

                for (idx, digest) in digests.iter().enumerate() {
                    let original_proof = tree.proof(idx as u32).unwrap();

                    let mut hasher = Sha256::default();
                    assert!(
                        original_proof
                            .verify_element_inclusion(&mut hasher, digest, idx as u32, &root)
                            .is_ok(),
                        "Original BMT proof must be valid"
                    );

                    for mutation in &input.mutations {
                        let mut mutated_proof = original_proof.clone();
                        mutate_proof_bytes(&mut mutated_proof, mutation, &1);

                        if mutated_proof != original_proof {
                            let is_valid = mutated_proof
                                .verify_element_inclusion(&mut hasher, digest, idx as u32, &root)
                                .is_ok();
                            assert!(!is_valid, "Mutated BMT proof must be invalid");
                        }
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
