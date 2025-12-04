#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    simplex::{
        signing_scheme::{bls12381_multisig, bls12381_threshold, ed25519, Scheme},
        types::{AttributableMap, Nullify, Signature},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519::PublicKey,
};
use libfuzzer_sys::fuzz_target;

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type Bls12381ThresholdMinPk = bls12381_threshold::Scheme<PublicKey, MinPk>;
type Bls12381ThresholdMinSig = bls12381_threshold::Scheme<PublicKey, MinSig>;

const MAX_OPERATIONS: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct VoteData {
    signer: u32,
    epoch: u64,
    view: u64,
    signature_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    Insert(VoteData),
    Get { signer: u32 },
    Clear,
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Ed25519 {
        participants: u8,
        operations: Vec<Operation>,
    },
    Bls12381MultisigMinPk {
        participants: u8,
        operations: Vec<Operation>,
    },
    Bls12381MultisigMinSig {
        participants: u8,
        operations: Vec<Operation>,
    },
    Bls12381ThresholdMinPk {
        participants: u8,
        operations: Vec<Operation>,
    },
    Bls12381ThresholdMinSig {
        participants: u8,
        operations: Vec<Operation>,
    },
}

fn make_vote<S: Scheme>(data: &VoteData, sig: S::Signature) -> Nullify<S> {
    Nullify {
        round: Round::new(Epoch::new(data.epoch), View::new(data.view)),
        signature: Signature {
            signer: data.signer,
            signature: sig,
        },
    }
}

fn make_vote_ed25519(data: &VoteData) -> Option<Nullify<Ed25519Scheme>> {
    let sig = commonware_cryptography::ed25519::Signature::decode(data.signature_bytes.as_slice())
        .ok()?;
    Some(make_vote::<Ed25519Scheme>(data, sig))
}

fn make_vote_multisig<V: Variant>(
    data: &VoteData,
) -> Option<Nullify<bls12381_multisig::Scheme<PublicKey, V>>> {
    let sig = V::Signature::decode(data.signature_bytes.as_slice()).ok()?;
    Some(make_vote::<bls12381_multisig::Scheme<PublicKey, V>>(
        data, sig,
    ))
}

fn make_vote_threshold<V: Variant>(
    data: &VoteData,
) -> Option<Nullify<bls12381_threshold::Scheme<PublicKey, V>>> {
    let vote_sig = V::Signature::decode(data.signature_bytes.as_slice()).ok()?;
    let sig = bls12381_threshold::Signature {
        vote_signature: vote_sig,
        seed_signature: vote_sig,
    };
    Some(make_vote::<bls12381_threshold::Scheme<PublicKey, V>>(
        data, sig,
    ))
}

fn fuzz_map<S: Scheme, F>(participants: u8, operations: Vec<Operation>, make_vote: F)
where
    F: Fn(&VoteData) -> Option<Nullify<S>>,
{
    let mut map: AttributableMap<Nullify<S>> = AttributableMap::new(participants as usize);
    let mut inserted_signers = std::collections::HashSet::new();

    for op in operations.into_iter().take(MAX_OPERATIONS) {
        match op {
            Operation::Insert(data) => {
                let signer = data.signer;
                if let Some(nullify) = make_vote(&data) {
                    let result = map.insert(nullify);

                    let in_bounds = (signer as usize) < (participants as usize);
                    let already_inserted = inserted_signers.contains(&signer);

                    if in_bounds && !already_inserted {
                        assert!(result, "insert should succeed for new in-bounds signer");
                        inserted_signers.insert(signer);
                    } else {
                        assert!(!result, "insert should fail for out-of-bounds or duplicate");
                    }

                    assert_eq!(map.len(), inserted_signers.len());
                    assert_eq!(map.is_empty(), inserted_signers.is_empty());
                }
            }
            Operation::Get { signer } => {
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

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Ed25519 {
            participants,
            operations,
        } => fuzz_map::<Ed25519Scheme, _>(participants, operations, make_vote_ed25519),

        FuzzInput::Bls12381MultisigMinPk {
            participants,
            operations,
        } => fuzz_map::<Bls12381MultisigMinPk, _>(participants, operations, make_vote_multisig),

        FuzzInput::Bls12381MultisigMinSig {
            participants,
            operations,
        } => fuzz_map::<Bls12381MultisigMinSig, _>(participants, operations, make_vote_multisig),

        FuzzInput::Bls12381ThresholdMinPk {
            participants,
            operations,
        } => fuzz_map::<Bls12381ThresholdMinPk, _>(participants, operations, make_vote_threshold),

        FuzzInput::Bls12381ThresholdMinSig {
            participants,
            operations,
        } => fuzz_map::<Bls12381ThresholdMinSig, _>(participants, operations, make_vote_threshold),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
