//! Scheme tests over a six-participant committee with real key material.

mod batch;
mod certificates;
mod material;
mod roster;
mod signing;

use super::*;
use crate::{
    multimmit::{
        config::Protocol,
        mocks::{Committee, keys},
        scheme::Subject,
        types::{
            Attestation, BlockRef, ChainId, ChainSet, Lqc, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, VoteContent, Vqc,
        },
    },
    types::{Attributable as _, Height, View},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _,
    bls12381::primitives::{
        ops::{self, aggregate},
        variant::{MinPk, MinSig, Variant},
    },
    certificate::Subject as _,
    ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
    sha256::Digest,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};

const PARTICIPANTS: u32 = 6;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST";
const SEED: u64 = 9;

/// Runs `test` for both BLS variants.
macro_rules! both_variants {
    ($name:ident, $test:ident) => {
        #[test]
        fn $name() {
            $test::<MinPk>();
            $test::<MinSig>();
        }
    };
}
use both_variants;

fn test_committee<V: Variant>() -> Committee<V> {
    Committee::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .build()
}

/// Returns a vote content in `view` that varies one chain's tip and declaration with `marker`;
/// marker zero endorses every genesis object and declares nothing.
fn varied<V: Variant>(
    committee: &Committee<V>,
    view: View,
    leader: Option<Digest>,
    final_: bool,
    marker: u64,
) -> VoteContent<Digest> {
    let chains = committee.codec().chains();
    let mut tips = committee.genesis().tips().to_vec();
    let mut declared = ChainSet::empty(chains);
    if marker > 0 {
        let chain = ChainId::new((marker % chains as u64) as u32);
        tips[chain.index()] = BlockRef::new(
            chain,
            Height::new(marker),
            Sha256::hash(&[&marker.to_be_bytes()]),
        );
        declared.insert(chain);
    }
    committee.content(view, leader, final_, committee.endorsement(declared, tips))
}

/// Signs every `(signer, content)` pair and returns the attested votes.
fn attest<V: Variant>(
    committee: &Committee<V>,
    contents: &[(Participant, VoteContent<Digest>)],
) -> Vec<(VoteContent<Digest>, Attestation<V>)> {
    contents
        .iter()
        .map(|(signer, content)| (content.clone(), committee.sign_vote(*signer, content)))
        .collect()
}

/// Returns the sum of each signer's signature over its content.
fn aggregate_of<V: Variant>(
    committee: &Committee<V>,
    contents: &[(Participant, VoteContent<Digest>)],
) -> aggregate::Signature<V> {
    let signatures: Vec<_> = attest(committee, contents)
        .iter()
        .map(|(_, attestation)| *attestation.signature().unwrap())
        .collect();
    aggregate::combine_signatures::<V, _>(commonware_utils::non_empty![@signatures.iter()])
}

/// Returns `n - f` final votes of `view` from the first participants with distinct contents.
fn mixed_finals<V: Variant>(
    committee: &Committee<V>,
    view: View,
) -> Vec<(Participant, VoteContent<Digest>)> {
    (0..committee.codec().view_quorum())
        .map(|index| {
            let leader = (index % 2 == 0).then(|| Sha256::hash(&[b"leader"]));
            (
                Participant::from_usize(index),
                varied(committee, view, leader, true, (index % 3) as u64),
            )
        })
        .collect()
}
