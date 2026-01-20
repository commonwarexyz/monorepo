#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
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
    MmrMulti,
    Bmt,
    BmtMulti,
}

#[derive(Debug)]
struct FuzzInput {
    proof: ProofType,
    mutations: Vec<Mutation>,
    positions: Vec<u8>,
    elements: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_elements = u.int_in_range(1..=u8::MAX)?;
        let proof = u.arbitrary()?;
        let num_mutations = u.int_in_range(1..=MAX_MUTATIONS)?;
        let mutations = (0..num_mutations)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let num_positions = u.int_in_range(0..=num_elements)?;
        let positions = (0..num_positions)
            .map(|_| u.arbitrary::<u8>())
            .collect::<Result<Vec<_>, _>>()?;
        let elements = (0..num_elements)
            .map(|_| u.arbitrary::<u8>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput {
            proof,
            mutations,
            positions,
            elements,
        })
    }
}

fn mutate_proof_bytes<P, C>(proof: &mut P, mutation: &Mutation, cfg: &C)
where
    P: Encode + Decode<Cfg = C>,
{
    let serialized = proof.encode();
    let mut bytes = serialized.to_vec();
    let mutated = match mutation {
        Mutation::FlipBit { position, bit_idx } => {
            if bytes.is_empty() {
                return;
            }
            let idx = (*position as usize) % bytes.len();
            bytes[idx] ^= 1 << (bit_idx % 8);
            true
        }
        Mutation::InsertByte { position, value } => {
            let pos = (*position as usize) % (bytes.len() + 1);
            bytes.insert(pos, *value);
            true
        }
        Mutation::DeleteByte { position } => {
            if bytes.is_empty() {
                return;
            }
            let pos = (*position as usize) % bytes.len();
            bytes.remove(pos);
            true
        }
        Mutation::ReplaceByte { position, value } => {
            if bytes.is_empty() {
                return;
            }
            let pos = (*position as usize) % bytes.len();
            bytes[pos] = *value;
            true
        }
        Mutation::SwapBytes { pos1, pos2 } => {
            if bytes.len() < 2 {
                return;
            }
            let p1 = (*pos1 as usize) % bytes.len();
            let p2 = (*pos2 as usize) % bytes.len();
            if p1 != p2 {
                bytes.swap(p1, p2);
                true
            } else {
                false
            }
        }
    };
    if mutated {
        if let Ok(m) = P::decode_cfg(bytes.as_slice(), cfg) {
            *proof = m;
        }
    }
}

fn hash_elements(elements: &[u8]) -> Vec<Digest> {
    elements.iter().map(|&v| Sha256::hash(&[v])).collect()
}

fn fuzz(input: FuzzInput) {
    let digests = hash_elements(&input.elements);

    match input.proof {
        ProofType::Mmr => {
            let mut hasher = Standard::<Sha256>::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            for digest in &digests {
                mmr.add(&mut hasher, digest);
            }
            let root = mmr.root();

            for (leaf, element) in digests.iter().enumerate() {
                let loc = Location::new(leaf as u64).unwrap();
                let original_proof = mmr.proof(loc).unwrap();
                assert!(original_proof.verify_element_inclusion(&mut hasher, element, loc, root));

                for mutation in &input.mutations {
                    let mut mutated_proof = original_proof.clone();
                    mutate_proof_bytes(&mut mutated_proof, mutation, &256);
                    if mutated_proof != original_proof {
                        assert!(!mutated_proof.verify_element_inclusion(
                            &mut hasher,
                            element,
                            loc,
                            root
                        ));
                    }
                }
            }
        }
        ProofType::MmrMulti => {
            if input.positions.len() < 2 {
                return;
            }

            let mut hasher = Standard::<Sha256>::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            for digest in &digests {
                mmr.add(&mut hasher, digest);
            }
            let root = mmr.root();

            let idx1 = (input.positions[0] as usize) % digests.len();
            let idx2 = (input.positions[1] as usize) % digests.len();
            let (start_idx, end_idx) = (idx1.min(idx2), idx1.max(idx2));
            let start_loc = Location::new(start_idx as u64).unwrap();
            let end_loc = Location::new(end_idx as u64).unwrap();

            let Ok(original_proof) = mmr.range_proof(start_loc..end_loc + 1) else {
                return;
            };
            let range_elements: Vec<Digest> =
                (start_idx..=end_idx).map(|i| digests[i]).collect();
            assert!(original_proof.verify_range_inclusion(
                &mut hasher,
                &range_elements,
                start_loc,
                root
            ));

            for mutation in &input.mutations {
                let mut mutated_proof = original_proof.clone();
                mutate_proof_bytes(&mut mutated_proof, mutation, &256);
                if mutated_proof != original_proof {
                    assert!(!mutated_proof.verify_range_inclusion(
                        &mut hasher,
                        &range_elements,
                        start_loc,
                        root
                    ));
                }
            }
        }
        ProofType::Bmt => {
            let mut builder = BmtBuilder::<Sha256>::new(digests.len());
            for digest in &digests {
                builder.add(digest);
            }
            let tree = builder.build();
            let root = tree.root();

            for (idx, digest) in digests.iter().enumerate() {
                let original_proof = tree.proof(idx as u32).unwrap();
                let mut hasher = Sha256::default();
                assert!(original_proof
                    .verify_element_inclusion(&mut hasher, digest, idx as u32, &root)
                    .is_ok());

                for mutation in &input.mutations {
                    let mut mutated_proof = original_proof.clone();
                    mutate_proof_bytes(&mut mutated_proof, mutation, &1);
                    if mutated_proof != original_proof {
                        assert!(mutated_proof
                            .verify_element_inclusion(&mut hasher, digest, idx as u32, &root)
                            .is_err());
                    }
                }
            }
        }
        ProofType::BmtMulti => {
            let mut builder = BmtBuilder::<Sha256>::new(digests.len());
            for digest in &digests {
                builder.add(digest);
            }
            let tree = builder.build();
            let root = tree.root();

            let positions: Vec<u32> = input
                .positions
                .iter()
                .map(|&p| (p as u32) % (digests.len() as u32))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            let Ok(original_proof) = tree.multi_proof(&positions) else {
                return;
            };
            let elements: Vec<(Digest, u32)> =
                positions.iter().map(|&p| (digests[p as usize], p)).collect();

            let mut hasher = Sha256::default();
            assert!(original_proof
                .verify_multi_inclusion(&mut hasher, &elements, &root)
                .is_ok());

            for mutation in &input.mutations {
                let mut mutated_proof = original_proof.clone();
                mutate_proof_bytes(&mut mutated_proof, mutation, &positions.len());
                if mutated_proof != original_proof {
                    assert!(mutated_proof
                        .verify_multi_inclusion(&mut hasher, &elements, &root)
                        .is_err());
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| fuzz(input));
