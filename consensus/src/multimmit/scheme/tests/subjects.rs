//! Signed subjects: messages, namespaces, and epochs.

use super::*;
use bytes::BytesMut;
use commonware_codec::Write as _;
use std::collections::HashSet;

fn codec() -> CodecConfig {
    CodecConfig::new(1, 1, PathLimits::new(1, 0)).unwrap()
}

fn body(round: Round, leader: &[u8], position: u32) -> VoteBody<Digest> {
    VoteBody::new(
        round,
        Sha256::hash(&[leader]),
        vec![Position::new(position)],
        vec![Extension::empty()],
        codec(),
    )
    .unwrap()
}

fn header(epoch: Epoch, chain: u32, height: u64, marker: &[u8]) -> TransactionBlockHeader<Digest> {
    TransactionBlockHeader::new(
        epoch,
        ChainId::new(chain),
        Height::new(height),
        Sha256::hash(&[b"parent", marker]),
        Sha256::hash(&[b"body", marker]),
    )
    .unwrap()
}

fn leader(round: Round, marker: &[u8]) -> LeaderBlock<Bls<MinSig>, Digest> {
    let chain = ChainId::new(0);
    LeaderBlock::new(
        round,
        CertificateId::new(Sha256::hash(&[b"parent vqc", marker])),
        Sha256::hash(&[b"history", marker]),
        vec![
            ChainProposal::new(
                chain,
                Anchor::Tip(BlockRef::new(
                    chain,
                    Height::zero(),
                    Sha256::hash(&[b"tip"]),
                )),
                vec![Sha256::hash(&[b"payload", marker])],
                1,
            )
            .unwrap(),
        ],
        codec(),
    )
    .unwrap()
}

#[test]
fn compact_subjects_use_epoch_view_prefix() {
    let round = Round::new(Epoch::new(7), View::new(11));
    let mut prefix = BytesMut::new();
    round.epoch().write(&mut prefix);
    round.view().write(&mut prefix);

    assert_eq!(
        OrdinarySubject::novote(round).message(),
        prefix.clone().freeze()
    );
    assert_eq!(
        super::super::NullifySubject::new(round).message(),
        prefix.freeze()
    );
}

#[test]
fn encoded_subjects_report_their_object_epoch() {
    let round = Round::new(Epoch::new(u64::MAX), View::new(11));
    let body = body(round, b"leader", 0);
    let header = header(Epoch::new(300), 0, 1, b"header");
    let leader = leader(round, b"leader");
    assert_eq!(OrdinarySubject::vote(&body).epoch(), round.epoch());
    assert_eq!(
        OrdinarySubject::leader_block(&leader).epoch(),
        round.epoch()
    );
    assert_eq!(
        OrdinarySubject::transaction_block(&header).epoch(),
        header.epoch()
    );
    assert_eq!(
        super::super::DaSubject::new(&header).epoch(),
        header.epoch()
    );
    assert_eq!(OrdinarySubject::novote(round).epoch(), round.epoch());
    assert_eq!(
        super::super::NullifySubject::new(round).epoch(),
        round.epoch()
    );

    // Each subject signs its object's canonical encoding.
    assert_eq!(OrdinarySubject::vote(&body).message(), body.encode());
    assert_eq!(
        OrdinarySubject::leader_block(&leader).message(),
        leader.encode()
    );
    assert_eq!(
        OrdinarySubject::transaction_block(&header).message(),
        header.encode()
    );
    assert_eq!(
        super::super::DaSubject::new(&header).message(),
        header.encode()
    );
}

#[test]
fn every_subject_kind_signs_under_its_own_namespace() {
    let derived = Namespace::new(b"base");
    let round = Round::new(Epoch::new(3), View::new(5));
    let header = header(Epoch::new(3), 0, 1, b"header");
    let namespaces = [
        (
            OrdinarySubject::transaction_block(&header).namespace(&derived),
            b"base_TRANSACTION_BLOCK".as_slice(),
        ),
        (
            OrdinarySubject::leader_block(&leader(round, b"leader")).namespace(&derived),
            b"base_LEADER_BLOCK",
        ),
        (
            OrdinarySubject::vote(&body(round, b"leader", 0)).namespace(&derived),
            b"base_VOTE",
        ),
        (
            OrdinarySubject::novote(round).namespace(&derived),
            b"base_NOVOTE",
        ),
        (
            super::super::DaSubject::new(&header).namespace(&derived),
            b"base_DA_VOTE",
        ),
        (
            super::super::NullifySubject::new(round).namespace(&derived),
            b"base_NULLIFY",
        ),
    ];
    let mut distinct = HashSet::new();
    for (namespace, expected) in namespaces {
        assert_eq!(namespace, expected);
        assert!(distinct.insert(namespace.to_vec()));
    }
    // Registration proofs sign under their own namespace, bound to the registering identity.
    assert_eq!(derived.registration(b"id"), b"base_PROOF_OF_KNOWLEDGEid");
    assert!(!distinct.contains(&derived.registration(b"")));
}

#[test]
fn one_participant_never_produces_two_chains() {
    // A producer signs one header per height of its chain, which bounds a participant to one
    // header per height only because no participant owns two chains.
    let duplicate = Parameters::new(
        Epoch::new(1),
        NAMESPACE,
        PARTICIPANTS as usize,
        vec![Participant::new(2), Participant::new(2)],
        PathLimits::new(2, 2),
    );
    assert!(duplicate.is_err());
}

#[test]
fn namespaces_derive_only_from_their_base() {
    let namespace = Namespace::new(NAMESPACE);
    assert_eq!(namespace, Namespace::new(NAMESPACE));
    for other in [
        &NAMESPACE[..NAMESPACE.len() - 1],
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_",
        b"",
    ] {
        assert_ne!(namespace, Namespace::new(other));
    }
}
