#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{FixedSize, ReadExt};
use commonware_consensus::{
    simplex::{
        signing_scheme::{
            bls12381_multisig, bls12381_threshold, bls12381_threshold::Signature, ed25519,
        },
        types::{AttributableMap, Nullify, Vote},
    },
    types::Round,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519::{PublicKey, Signature as Ed25519Signature},
};
use libfuzzer_sys::fuzz_target;

const MAX_VOTES: usize = 64;

#[derive(Arbitrary, Debug)]
enum SchemeType {
    Ed25519,
    Bls12381MultisigMinPk,
    Bls12381MultisigMinSig,
    Bls12381ThresholdMinPk,
    Bls12381ThresholdMinSig,
}

#[derive(Arbitrary, Debug)]
struct VoteInput {
    signer: u32,
    epoch: u64,
    view: u64,
    signature_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scheme: SchemeType,
    participants: u8,
    votes: Vec<VoteInput>,
}

fn ed25519_signature_from_bytes(bytes: &[u8]) -> Option<Ed25519Signature> {
    if bytes.len() < Ed25519Signature::SIZE {
        return None;
    }
    let mut buf = &bytes[..Ed25519Signature::SIZE];
    Ed25519Signature::read(&mut buf).ok()
}

fn bls_signature_from_bytes<V: Variant>(bytes: &[u8]) -> Option<V::Signature> {
    if bytes.len() < V::Signature::SIZE {
        return None;
    }
    let mut buf = &bytes[..V::Signature::SIZE];
    V::Signature::read(&mut buf).ok()
}

fn fuzz_ed25519(participants: u8, votes: Vec<VoteInput>) {
    let mut map: AttributableMap<Nullify<ed25519::Scheme>> =
        AttributableMap::new(participants as usize);

    for vote_data in votes.into_iter().take(MAX_VOTES) {
        let Some(signature) = ed25519_signature_from_bytes(&vote_data.signature_bytes) else {
            continue;
        };

        let message_vote = Vote::<ed25519::Scheme> {
            signer: vote_data.signer,
            signature,
        };

        let nullify = Nullify::<ed25519::Scheme> {
            round: Round::new(vote_data.epoch, vote_data.view),
            vote: message_vote,
        };

        let _ = map.insert(nullify);
    }
}

fn fuzz_bls_multisig<V: Variant>(participants: u8, votes: Vec<VoteInput>) {
    let mut map: AttributableMap<Nullify<bls12381_multisig::Scheme<PublicKey, V>>> =
        AttributableMap::new(participants as usize);

    for vote_data in votes.into_iter().take(MAX_VOTES) {
        let Some(signature) = bls_signature_from_bytes::<V>(&vote_data.signature_bytes) else {
            continue;
        };

        let message_vote = Vote::<bls12381_multisig::Scheme<PublicKey, V>> {
            signer: vote_data.signer,
            signature,
        };

        let nullify = Nullify::<bls12381_multisig::Scheme<PublicKey, V>> {
            round: Round::new(vote_data.epoch, vote_data.view),
            vote: message_vote,
        };

        let _ = map.insert(nullify);
    }
}

fn fuzz_bls_threshold<V: Variant>(participants: u8, votes: Vec<VoteInput>) {
    let mut map: AttributableMap<Nullify<bls12381_threshold::Scheme<PublicKey, V>>> =
        AttributableMap::new(participants as usize);

    for vote_data in votes.into_iter().take(MAX_VOTES) {
        let Some(vote_sig) = bls_signature_from_bytes::<V>(&vote_data.signature_bytes) else {
            continue;
        };
        // Use the same signature for both vote and seed for fuzzing
        let signature = Signature::<V> {
            vote_signature: vote_sig,
            seed_signature: vote_sig,
        };

        let message_vote = Vote::<bls12381_threshold::Scheme<PublicKey, V>> {
            signer: vote_data.signer,
            signature,
        };

        let nullify = Nullify::<bls12381_threshold::Scheme<PublicKey, V>> {
            round: Round::new(vote_data.epoch, vote_data.view),
            vote: message_vote,
        };

        let _ = map.insert(nullify);
    }
}

fn fuzz(input: FuzzInput) {
    let votes = input.votes;

    match input.scheme {
        SchemeType::Ed25519 => fuzz_ed25519(input.participants, votes),
        SchemeType::Bls12381MultisigMinPk => fuzz_bls_multisig::<MinPk>(input.participants, votes),
        SchemeType::Bls12381MultisigMinSig => {
            fuzz_bls_multisig::<MinSig>(input.participants, votes)
        }
        SchemeType::Bls12381ThresholdMinPk => {
            fuzz_bls_threshold::<MinPk>(input.participants, votes)
        }
        SchemeType::Bls12381ThresholdMinSig => {
            fuzz_bls_threshold::<MinSig>(input.participants, votes)
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
