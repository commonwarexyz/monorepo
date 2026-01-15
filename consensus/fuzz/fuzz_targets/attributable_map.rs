#![no_main]

use arbitrary::Arbitrary;
use commonware_consensus::{
    simplex::{
        scheme::ed25519,
        types::{AttributableMap, Nullify},
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_cryptography::{certificate::Attestation, ed25519::PrivateKey, Signer};
use commonware_math::algebra::Random;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const MAX_OPERATIONS: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct VoteData {
    signer: Participant,
    epoch: Epoch,
    view: View,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    Insert(VoteData),
    Get(Participant),
    Clear,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    participants: u8,
    operations: Vec<Operation>,
}

fn make_vote(
    data: &VoteData,
    sig: commonware_cryptography::ed25519::Signature,
) -> Nullify<ed25519::Scheme> {
    Nullify {
        round: Round::new(data.epoch, data.view),
        attestation: Attestation {
            signer: data.signer,
            signature: sig.into(),
        },
    }
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);
    let signer = PrivateKey::random(&mut rng);
    let dummy_sig = signer.sign(b"fuzz", b"dummy");

    let mut map: AttributableMap<Nullify<ed25519::Scheme>> =
        AttributableMap::new(input.participants as usize);
    let mut inserted_signers = std::collections::HashSet::new();

    for op in input.operations.into_iter().take(MAX_OPERATIONS) {
        match op {
            Operation::Insert(data) => {
                let signer_idx = data.signer;
                let nullify = make_vote(&data, dummy_sig.clone());
                let result = map.insert(nullify);

                let in_bounds = signer_idx.get() < u32::from(input.participants);
                let already_inserted = inserted_signers.contains(&signer_idx);

                if in_bounds && !already_inserted {
                    assert!(result, "insert should succeed for new in-bounds signer");
                    inserted_signers.insert(signer_idx);
                } else {
                    assert!(!result, "insert should fail for out-of-bounds or duplicate");
                }

                assert_eq!(map.len(), inserted_signers.len());
                assert_eq!(map.is_empty(), inserted_signers.is_empty());
            }
            Operation::Get(signer) => {
                let result = map.get(signer);
                let should_exist = inserted_signers.contains(&signer);
                assert_eq!(result.is_some(), should_exist);
            }
            Operation::Clear => {
                map.clear();
                inserted_signers.clear();
                assert!(map.is_empty());
                assert_eq!(map.len(), 0);
            }
        }
    }

    assert_eq!(map.iter().count(), inserted_signers.len());
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
