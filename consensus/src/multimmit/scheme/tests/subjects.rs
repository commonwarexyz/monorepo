//! Signed subjects: messages, namespaces, epochs, and synchronized periods.

use super::*;
use bytes::BytesMut;
use commonware_codec::Write as _;
use std::collections::{HashMap, HashSet};

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
    for prefix in [
        &derived.view_period,
        &derived.leader_period,
        &derived.height_period,
    ] {
        assert!(!distinct.contains(prefix));
    }
}

#[test]
fn ordinary_subjects_share_periods_only_across_one_signing_slot() {
    let namespace = Namespace::new(NAMESPACE);
    let round = Round::new(Epoch::new(3), View::new(5));
    let epoch = round.epoch();

    // A view's votes, for any leader and any path, and its novote share one period, because a
    // node takes one stance per view.
    let votes = [
        OrdinarySubject::vote(&body(round, b"leader", 0)),
        OrdinarySubject::vote(&body(round, b"leader", 1)),
        OrdinarySubject::vote(&body(round, b"other", 0)),
        OrdinarySubject::novote(round),
    ];
    for subject in &votes {
        assert_eq!(subject.period_kind(), Period::View(round));
        assert_eq!(subject.period(&namespace), votes[0].period(&namespace));
    }

    // Every leader block of one view shares the leader period, apart from the view's votes.
    let leaders = [
        OrdinarySubject::leader_block(&leader(round, b"one")),
        OrdinarySubject::leader_block(&leader(round, b"two")),
    ];
    for subject in &leaders {
        assert_eq!(subject.period_kind(), Period::Leader(round));
        assert_eq!(subject.period(&namespace), leaders[0].period(&namespace));
        assert_ne!(subject.period(&namespace), votes[0].period(&namespace));
    }

    // Headers at one height share a period across chains and contents, because each chain has
    // exactly one producer.
    let headers = [
        OrdinarySubject::transaction_block(&header(epoch, 0, 7, b"a")),
        OrdinarySubject::transaction_block(&header(epoch, 1, 7, b"a")),
        OrdinarySubject::transaction_block(&header(epoch, 1, 7, b"b")),
    ];
    for subject in &headers {
        assert_eq!(subject.period_kind(), Period::Height(epoch, Height::new(7)));
        assert_eq!(subject.period(&namespace), headers[0].period(&namespace));
    }
    assert_ne!(
        OrdinarySubject::transaction_block(&header(epoch, 0, 8, b"a")).period(&namespace),
        headers[0].period(&namespace)
    );
}

#[test]
fn distinct_signing_slots_never_share_a_period() {
    let namespace = Namespace::new(NAMESPACE);
    // Values on both sides of every varint width boundary, where a non-injective encoding would
    // first collide.
    let values = [
        0u64,
        1,
        2,
        127,
        128,
        255,
        256,
        16_383,
        16_384,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut seen: HashMap<Bytes, Period> = HashMap::new();
    for &first in &values {
        for &second in &values {
            let round = Round::new(Epoch::new(first), View::new(second));
            for period in [
                Period::View(round),
                Period::Leader(round),
                Period::Height(Epoch::new(first), Height::new(second)),
            ] {
                if let Some(previous) = seen.insert(period.encode(&namespace), period) {
                    panic!("{previous:?} and {period:?} share a period");
                }
            }
        }
    }
    // The same slot under another deployment is another period.
    let round = Round::new(Epoch::new(3), View::new(5));
    assert_ne!(
        Period::View(round).encode(&namespace),
        Period::View(round).encode(&Namespace::new(b"_COMMONWARE_CONSENSUS_MULTIMMIT_OTHER"))
    );
}

#[test]
fn one_participant_never_produces_two_chains() {
    // Headers at one height share a period across chains, which is sound only because no
    // participant owns two chains.
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
