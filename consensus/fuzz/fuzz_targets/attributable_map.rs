#![no_main]

use arbitrary::Arbitrary;
use commonware_consensus::{
    simplex::{
        signing_scheme::ed25519,
        types::{AttributableMap, Nullify, Signature},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{ed25519::PrivateKey, Signer};
use commonware_math::algebra::Random;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const MAX_OPERATIONS: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct VoteData {
    signer: u32,
    epoch: u64,
    view: u64,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    Insert(VoteData),
    Get(u32),
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
        round: Round::new(Epoch::new(data.epoch), View::new(data.view)),
        signature: Signature {
            signer: data.signer,
            signature: sig,
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

                let in_bounds = (signer_idx as usize) < (input.participants as usize);
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
