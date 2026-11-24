use super::*;
use crate::marshal::end_to_end::{
    coding_disrupter::{
        AnswerKind, BACKFILL_POISON_ACTOR, BackfillPoison, EXTENDED_POISON_MASK, ExtendedPoison,
        ExtraDraw, MAX_HINT_AHEAD, MAX_HINT_DELAY, MAX_HINTS, PoisonRecords, Requested,
        answer_request, check_resolver_block_witness, extended_answer, poisoned_notarization,
    },
    coding_stack::CodingB,
};
use bytes::{Buf as _, Bytes};
use commonware_codec::{Encode as _, Read as _};
use commonware_coding::Config as CodingConfig;
use commonware_consensus::{
    Handoff, Heightable as _,
    marshal::{
        coding::types::coding_config_for_participants,
        mocks::harness::{BLOCKS_PER_EPOCH, GENESIS_CODING_CONFIG},
        resolver::handler::Key,
    },
    simplex::{
        ForwardPolicy,
        types::{Finalization, Notarization, Subject},
    },
    types::{Epocher as _, FixedEpocher, Height, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX, SimplexCertificateMock, byzantine, strategy::StrategyChoice, utils::Partition,
};
use commonware_cryptography::{Hasher as _, Sha256, certificate::Verifier as _};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::Payload as ResolverPayload;
use commonware_utils::FuzzRng;
use rand_core::Rng as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn poison_input(raw_bytes: Vec<u8>, required_containers: u64) -> MarshalDisrupterInput {
    let mut input = MarshalDisrupterInput {
        raw_bytes,
        required_containers,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        handoff: Handoff::Wait,
        height_offset: block_disrupter::HeightOffset::Zero,
        application: ApplicationChoice::AlwaysAccept,
        degraded_network: true,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        forwarding: ForwardPolicy::Disabled,
    };
    force_poison(&mut input);
    input
}

fn run(raw_bytes: Vec<u8>) -> CodingRun {
    byzantine::reset();
    run_coding_disrupter_observed::<SimplexCertificateMock>(poison_input(raw_bytes, 6), true, None)
}

fn assert_same_run(left: &CodingRun, right: &CodingRun) {
    assert_eq!(left.state, right.state);
    assert_eq!(left.end, right.end);
    assert_eq!(left.delivered, right.delivered);
    assert_eq!(left.blocked, right.blocked);
    assert_eq!(left.records.extended, right.records.extended);
    assert_eq!(left.records.draws, right.records.draws);
    assert_eq!(left.records.answers, right.records.answers);
    assert_eq!(left.records.embedded, right.records.embedded);
    assert_eq!(left.records.hints, right.records.hints);
    assert_eq!(left.records.resolver_blocks, right.records.resolver_blocks);
}

fn finalized_seeds() -> [(AnswerKind, &'static [u8]); 5] {
    [
        (AnswerKind::UndecodableFinalization, &[7]),
        (AnswerKind::OtherEpoch, &[1]),
        (AnswerKind::UndecodableBlock, &[]),
        (AnswerKind::OtherHeight, &[]),
        (AnswerKind::OtherDigest, &[3]),
    ]
}

fn decoded_embedded(records: PoisonRecords) -> BTreeSet<commonware_cryptography::sha256::Digest> {
    deterministic::Runner::default().start(|mut context| async move {
        let (_, _schemes) = SimplexCertificateMock::setup(
            &mut context,
            commonware_consensus_fuzz_core::NAMESPACE,
            NUM_VALIDATORS,
        );
        let mut embedded = BTreeSet::new();
        for answer in records.answers {
            let mut value = Bytes::from(answer.bytes);
            let block = match answer.kind {
                AnswerKind::PoisonedBlock => {
                    Some(CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).unwrap())
                }
                AnswerKind::PoisonedNotarization | AnswerKind::OtherRound => {
                    let _ = Notarization::<
                        SchemeOf<SimplexCertificateMock>,
                        CommitmentOf<SimplexCertificateMock>,
                    >::read_cfg(&mut value, &())
                    .unwrap();
                    let block =
                        CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).unwrap();
                    let _ = CodingConfig::read_cfg(&mut value, &()).unwrap();
                    Some(block)
                }
                AnswerKind::OtherEpoch | AnswerKind::OtherHeight | AnswerKind::OtherDigest => {
                    let _ = Finalization::<
                        SchemeOf<SimplexCertificateMock>,
                        CommitmentOf<SimplexCertificateMock>,
                    >::read_cfg(&mut value, &())
                    .unwrap();
                    Some(CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).unwrap())
                }
                AnswerKind::UndecodableNotarization
                | AnswerKind::BadPayload
                | AnswerKind::UndecodableFinalization
                | AnswerKind::UndecodableBlock => None,
            };
            if let Some(block) = block {
                assert_eq!(value.remaining(), 0, "kind={:?}", answer.kind);
                embedded.insert(block.digest());
            }
        }
        embedded
    })
}

#[test]
fn at_001_at_010_masked_mode_and_constants() {
    assert_eq!(MAX_HINTS, 2);
    assert_eq!(MAX_HINT_DELAY, Duration::from_secs(2));
    assert_eq!(MAX_HINT_AHEAD, 3);
    assert_eq!(EXTENDED_POISON_MASK, 0xA5);

    let draw = |bytes: &[u8], masked: bool| {
        let tape = if masked {
            bytes
                .iter()
                .map(|byte| byte ^ EXTENDED_POISON_MASK)
                .collect()
        } else {
            bytes.to_vec()
        };
        FuzzRng::new(tape).random_range(0..2u8)
    };

    assert_eq!(draw(&[], true), 1);
    assert_eq!(draw(&[0; 1024], true), 0);
    assert_eq!(draw(&[0xff; 1024], true), 0);
    let selected = (0..=u8::MAX)
        .filter(|byte| draw(&[*byte], true) == 1)
        .count();
    let equal_to_unmasked = (0..=u8::MAX)
        .filter(|byte| draw(&[*byte], true) == draw(&[*byte], false))
        .count();
    assert_eq!(selected, 136);
    assert_eq!(equal_to_unmasked, 132);

    let mut same_window_a = [0u8; 32];
    let mut same_window_b = [0u8; 32];
    same_window_a[..8].copy_from_slice(b"12345678");
    same_window_b[..8].copy_from_slice(b"12345678");
    same_window_a[8..].fill(0x11);
    same_window_b[8..].fill(0xee);
    assert_eq!(draw(&same_window_a, true), draw(&same_window_b, true));

    for raw in [vec![], vec![0], vec![1], vec![0; 1024], vec![0xff; 1024]] {
        crate::marshal::end_to_end::coding_disrupter::reset_records();
        let selected =
            crate::marshal::end_to_end::coding_disrupter::ExtendedPoison::select(&raw).is_some();
        assert_eq!(selected, draw(&raw, true) == 1, "raw={raw:?}");
    }
}

#[test]
fn at_002_at_032_false_mode_matches_the_frozen_run() {
    byzantine::reset();
    let result = run_coding_disrupter_observed::<SimplexCertificateMock>(
        poison_input(vec![2], 6),
        true,
        None,
    );
    assert_eq!(result.records.extended, Some(false));
    assert_eq!(result.state, "7632dc2a");
    assert_eq!(result.end, Duration::from_millis(36_268));
    assert_eq!(byzantine::count(BACKFILL_POISON_ACTOR), 1);
    assert_eq!(result.records.draws, vec![ExtraDraw::Mode(false)]);
    assert_eq!(result.records.answers.len(), 1);
    assert_eq!(
        result.records.answers[0].kind,
        AnswerKind::PoisonedNotarization
    );
    assert_eq!(
        result.records.answers[0].legacy_draw,
        BackfillPoison::ForgedDigest
    );
    assert!(result.records.answers[0].accepted);
    assert!(result.records.embedded.is_empty());
    assert!(result.records.hints.is_empty());
    assert!(result.records.resolver_blocks.is_empty());
    assert!(result.blocked.is_empty());

    let expected = [
        "700775a459c689d8efea29e107cf8dba7df55d8544f0e41a4a2d73e9d138af99",
        "ac6003a20604f92eeb7ca0294bdd304016aef29291d5e6c6682cf447f9eebd8b",
        "66e139086a550b61df3669a0d344b69035a370d7c836267801222202d1c1597a",
        "7ba349d57d46575a561dc6ca32b76c30d7d2ec68da7371e772816fcd8955ea9f",
        "9708f90f52840db75b530b60da220bb9875165ecbb92def5070d928d6bd9dd74",
        "5c642e33272479859b3a0de7112e7e824ea0111d6ce440a3d1303a9c6b22d6bf",
        "1a561eee41c46e6544d39d56f1804239a77797c34b37850d421ce7094d1a2f63",
    ];
    assert_eq!(result.delivered.len(), 3);
    for (node, delivered) in &result.delivered {
        assert!((1..=3).contains(node));
        assert_eq!(delivered.len(), expected.len());
        for (index, (height, digest)) in delivered.iter().enumerate() {
            assert_eq!(height.get(), index as u64);
            assert_eq!(digest.to_string(), expected[index]);
        }
    }

    let mut fault_rng = FuzzRng::new(vec![2]);
    let _ = FaultyConfig::new(&mut fault_rng, 0, TermLength::ONE);
    assert_eq!(sample_shards_mailbox_size(&mut fault_rng).get(), 9);
    assert_eq!(fault_rng.random_range(0..=MAX_ANCESTRY_DEPTH), 3);
    assert!(fault_rng.random_range(0..2u8) == 1);
}

#[test]
fn at_006_block_answer_is_mode_independent_and_takes_no_extra_draw() {
    deterministic::Runner::default().start(|mut context| async move {
        let (participants, schemes) = SimplexCertificateMock::setup(
            &mut context,
            commonware_consensus_fuzz_core::NAMESPACE,
            NUM_VALIDATORS,
        );
        let leader = participants[BYZANTINE_IDX].clone();
        let config = coding_config_for_participants(NUM_VALIDATORS as u16);
        let commitment = CommitmentOf::<SimplexCertificateMock>::from((
            Sha256::hash(&[b"at-006-block"]),
            Sha256::hash(&[b"at-006-root"]),
            Sha256::hash(&[b"at-006-context"]),
            config,
        ));

        crate::marshal::end_to_end::coding_disrupter::reset_records();
        let extended = ExtendedPoison::select(&[]).expect("empty input selects extended mode");
        let mut extended_rng = FuzzRng::new(vec![42]);
        let extended_answer = answer_request::<SimplexCertificateMock>(
            &schemes,
            &leader,
            &mut extended_rng,
            ResolverPayload::Request(Key::Block(commitment)),
            Some(&extended),
        )
        .unwrap();
        assert_eq!(
            crate::marshal::end_to_end::coding_disrupter::records().draws,
            vec![ExtraDraw::Mode(true)]
        );

        crate::marshal::end_to_end::coding_disrupter::reset_records();
        let mut legacy_rng = FuzzRng::new(vec![42]);
        let legacy_answer = answer_request::<SimplexCertificateMock>(
            &schemes,
            &leader,
            &mut legacy_rng,
            ResolverPayload::Request(Key::Block(commitment)),
            None,
        )
        .unwrap();
        assert_eq!(extended_answer, legacy_answer);
        assert_eq!(extended_answer.kind, AnswerKind::PoisonedBlock);
        assert_eq!(extended_answer.requested, Requested::Block);
        assert!(
            crate::marshal::end_to_end::coding_disrupter::records()
                .draws
                .is_empty()
        );
        assert_eq!(extended_rng.next_u64(), legacy_rng.next_u64());

        let mut bytes = Bytes::from(extended_answer.bytes);
        let block = CodingB::<SimplexCertificateMock>::read_cfg(&mut bytes, &()).unwrap();
        let _config = CodingConfig::read_cfg(&mut bytes, &()).unwrap();
        assert_eq!(bytes.remaining(), 0);
        assert_eq!(extended_answer.embedded, Some(block.digest()));
    });
}

#[test]
fn at_004_at_005_at_007_answer_shapes_and_certificates() {
    deterministic::Runner::default().start(|mut context| async move {
        let (participants, schemes) = SimplexCertificateMock::setup(
            &mut context,
            commonware_consensus_fuzz_core::NAMESPACE,
            NUM_VALIDATORS,
        );
        let leader = participants[BYZANTINE_IDX].clone();
        let scheme = &schemes[0];
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        let round = Round::new(commonware_consensus::types::Epoch::zero(), View::new(1));

        let (legacy, _) = poisoned_notarization::<SimplexCertificateMock>(
            &schemes,
            &leader,
            round,
            BackfillPoison::WrongBlock,
        )
        .unwrap();
        let mut legacy = Bytes::from(legacy);
        let notarization = Notarization::<
            SchemeOf<SimplexCertificateMock>,
            CommitmentOf<SimplexCertificateMock>,
        >::read_cfg(&mut legacy, &())
        .unwrap();
        assert_eq!(notarization.round(), round);
        assert!(scheme.verify_certificate(
            &mut context,
            Subject::Notarize {
                proposal: &notarization.proposal
            },
            &notarization.certificate,
            &Sequential,
        ));
        let _ = CodingB::<SimplexCertificateMock>::read_cfg(&mut legacy, &()).unwrap();
        let config = CodingConfig::read_cfg(&mut legacy, &()).unwrap();
        assert_eq!(
            config,
            commonware_consensus::marshal::coding::types::coding_config_for_participants(
                NUM_VALIDATORS as u16
            )
        );
        assert_eq!(legacy.remaining(), 0);

        for kind in AnswerKind::NOTARIZED {
            let (bytes, embedded) = extended_answer::<SimplexCertificateMock>(
                &schemes,
                &leader,
                &epocher,
                &Key::Notarized { round },
                kind,
                BackfillPoison::WrongBlock,
            )
            .unwrap();
            let mut value = Bytes::from(bytes.clone());
            if kind == AnswerKind::UndecodableNotarization {
                let expected = Sha256::hash(&[b"poison-notarization", round.encode().as_ref()]);
                assert_eq!(bytes, expected.as_ref());
                assert!(
                    Notarization::<
                        SchemeOf<SimplexCertificateMock>,
                        CommitmentOf<SimplexCertificateMock>,
                    >::read_cfg(&mut value, &())
                    .is_err()
                );
                assert!(embedded.is_none());
                continue;
            }
            let certificate = Notarization::<
                SchemeOf<SimplexCertificateMock>,
                CommitmentOf<SimplexCertificateMock>,
            >::read_cfg(&mut value, &())
            .unwrap();
            assert!(scheme.verify_certificate(
                &mut context,
                Subject::Notarize {
                    proposal: &certificate.proposal
                },
                &certificate.certificate,
                &Sequential,
            ));
            match kind {
                AnswerKind::OtherRound => {
                    assert_eq!(certificate.round().epoch(), round.epoch());
                    assert_eq!(certificate.round().view(), round.view().next());
                    let block =
                        CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).unwrap();
                    let config = CodingConfig::read_cfg(&mut value, &()).unwrap();
                    assert_eq!(config, certificate.proposal.payload.config());
                    assert_eq!(embedded, Some(block.digest()));
                }
                AnswerKind::BadPayload => {
                    assert_eq!(certificate.round(), round);
                    assert_eq!(certificate.proposal.payload.config(), GENESIS_CODING_CONFIG);
                    assert!(embedded.is_none());
                }
                _ => unreachable!(),
            }
            assert_eq!(value.remaining(), 0, "kind={kind:?}");
        }

        let height = Height::new(2);
        let epoch = epocher.containing(height).unwrap().epoch();
        for kind in AnswerKind::FINALIZED {
            let (bytes, embedded) = extended_answer::<SimplexCertificateMock>(
                &schemes,
                &leader,
                &epocher,
                &Key::Finalized { height },
                kind,
                BackfillPoison::WrongBlock,
            )
            .unwrap();
            let mut value = Bytes::from(bytes.clone());
            if kind == AnswerKind::UndecodableFinalization {
                let expected = Sha256::hash(&[
                    b"poison-finalization",
                    height.get().to_be_bytes().as_slice(),
                ]);
                assert_eq!(bytes, expected.as_ref());
                assert!(
                    Finalization::<
                        SchemeOf<SimplexCertificateMock>,
                        CommitmentOf<SimplexCertificateMock>,
                    >::read_cfg(&mut value, &())
                    .is_err()
                );
                assert!(embedded.is_none());
                continue;
            }
            let certificate = Finalization::<
                SchemeOf<SimplexCertificateMock>,
                CommitmentOf<SimplexCertificateMock>,
            >::read_cfg(&mut value, &())
            .unwrap();
            assert!(scheme.verify_certificate(
                &mut context,
                Subject::Finalize {
                    proposal: &certificate.proposal
                },
                &certificate.certificate,
                &Sequential,
            ));
            if kind == AnswerKind::OtherEpoch {
                assert_eq!(certificate.proposal.round.epoch(), epoch.next());
            } else {
                assert_eq!(certificate.proposal.round.epoch(), epoch);
            }
            if kind == AnswerKind::UndecodableBlock {
                assert!(CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).is_err());
                assert!(embedded.is_none());
                continue;
            }
            let block = CodingB::<SimplexCertificateMock>::read_cfg(&mut value, &()).unwrap();
            assert_eq!(value.remaining(), 0, "kind={kind:?}");
            assert_eq!(embedded, Some(block.digest()));
            match kind {
                AnswerKind::OtherEpoch => {
                    assert_eq!(block.height(), height);
                    assert_eq!(certificate.proposal.payload.block(), block.digest());
                }
                AnswerKind::OtherHeight => {
                    assert_eq!(block.height(), height.next());
                    assert_eq!(certificate.proposal.payload.block(), block.digest());
                }
                AnswerKind::OtherDigest => {
                    assert_eq!(block.height(), height);
                    assert_ne!(certificate.proposal.payload.block(), block.digest());
                }
                _ => unreachable!(),
            }
        }
    });
}

#[test]
fn at_008_claims_follow_the_frozen_decision_stream() {
    let result = run(vec![]);
    assert_eq!(result.records.extended, Some(true));
    assert_eq!(result.records.hints.len(), 3 * MAX_HINTS);
    let mut per_node = BTreeMap::new();
    for hint in &result.records.hints {
        assert!((1..=3).contains(&hint.node));
        assert!(hint.delay <= MAX_HINT_DELAY);
        assert!((1..=MAX_HINT_AHEAD).contains(&hint.ahead));
        *per_node.entry(hint.node).or_insert(0usize) += 1;
    }
    assert_eq!(per_node, BTreeMap::from([(1, 2), (2, 2), (3, 2)]));
    assert_eq!(
        result.records.draws,
        vec![
            ExtraDraw::Mode(true),
            ExtraDraw::Delay {
                node: 1,
                delay: Duration::from_millis(962)
            },
            ExtraDraw::Delay {
                node: 2,
                delay: Duration::from_millis(214)
            },
            ExtraDraw::Delay {
                node: 3,
                delay: Duration::from_millis(223)
            },
            ExtraDraw::Ahead { node: 2, ahead: 2 },
            ExtraDraw::Delay {
                node: 2,
                delay: Duration::from_millis(340)
            },
            ExtraDraw::Ahead { node: 3, ahead: 2 },
            ExtraDraw::Delay {
                node: 3,
                delay: Duration::from_millis(453)
            },
            ExtraDraw::Answer(AnswerKind::OtherHeight),
            ExtraDraw::Ahead { node: 2, ahead: 2 },
            ExtraDraw::Ahead { node: 3, ahead: 2 },
            ExtraDraw::Ahead { node: 1, ahead: 1 },
            ExtraDraw::Delay {
                node: 1,
                delay: Duration::from_millis(1_365)
            },
            ExtraDraw::Answer(AnswerKind::UndecodableBlock),
            ExtraDraw::Ahead { node: 1, ahead: 3 },
            ExtraDraw::Answer(AnswerKind::OtherDigest),
            ExtraDraw::Answer(AnswerKind::OtherHeight),
        ]
    );
}

#[test]
fn at_009_at_030_finalized_sends_and_resolver_witnesses() {
    for (kind, seed) in finalized_seeds() {
        let result = run(seed.to_vec());
        assert_eq!(result.records.extended, Some(true));
        check_resolver_block_witness(&result.records, kind);
        assert!(byzantine::count(kind.label().unwrap()) > 0, "kind={kind:?}");
        let accepted = result
            .records
            .answers
            .iter()
            .filter(|answer| answer.accepted)
            .count();
        assert_eq!(byzantine::count(BACKFILL_POISON_ACTOR), accepted as u64);
        for answer_kind in AnswerKind::NOTARIZED
            .into_iter()
            .chain(AnswerKind::FINALIZED)
        {
            let expected = result
                .records
                .answers
                .iter()
                .filter(|answer| answer.accepted && answer.kind == answer_kind)
                .count() as u64;
            assert_eq!(byzantine::count(answer_kind.label().unwrap()), expected);
        }
        assert!(
            result
                .records
                .answers
                .iter()
                .all(|answer| answer.requester.is_some())
        );
        assert!(
            result
                .records
                .answers
                .windows(2)
                .all(|pair| pair[0].at <= pair[1].at)
        );
        assert_eq!(
            decoded_embedded(result.records.clone()),
            result.records.embedded
        );
    }
}

#[test]
fn at_011_at_014_at_016_invariants_hold_on_finalized_seeds() {
    for (kind, seed) in finalized_seeds() {
        let result = run(seed.to_vec());
        check_resolver_block_witness(&result.records, kind);
        assert!(!result.records.embedded.is_empty(), "kind={kind:?}");
        assert!(
            result
                .delivered
                .iter()
                .any(|(_, blocks)| !blocks.is_empty())
        );
        for (blocker, blocked) in &result.blocked {
            assert!(matches!(blocker, Some(1..=3)));
            assert_eq!(*blocked, Some(BYZANTINE_IDX));
        }
        for (node, delivered) in &result.delivered {
            for (_, digest) in delivered {
                assert!(
                    !result.records.embedded.contains(digest),
                    "RF-9 violated: node{node} received embedded block {digest}"
                );
            }
        }
        if kind == AnswerKind::OtherDigest {
            assert!(result.records.answers.iter().any(|answer| {
                let Requested::Finalized(height) = answer.requested else {
                    return false;
                };
                answer.kind == kind
                    && result.records.hints.iter().any(|hint| {
                        hint.node == answer.requester.unwrap()
                            && hint.ahead == 1
                            && hint.processed + 1 == height.get()
                    })
            }));
        }
    }
}

#[test]
fn at_020_extended_run_is_deterministic() {
    let first = run(vec![]);
    let second = run(vec![]);
    assert_same_run(&first, &second);
}

#[test]
fn at_021_empty_and_short_inputs_run_complete_scenarios() {
    let empty = run(vec![]);
    assert_eq!(empty.records.extended, Some(true));
    assert_eq!(empty.records.hints.len(), 3 * MAX_HINTS);
    assert!(empty.delivered.iter().all(|(_, blocks)| blocks.len() >= 2));

    let short = run(vec![0]);
    assert_eq!(short.records.extended, Some(false));
    assert!(short.records.hints.is_empty());
    assert!(short.delivered.iter().all(|(_, blocks)| blocks.len() >= 2));
}

#[test]
fn at_031_malformed_notarized_kinds_are_sent() {
    let runs = [run(vec![37]), run(vec![48]), run(vec![49])];
    for kind in AnswerKind::NOTARIZED {
        assert!(
            runs.iter().any(|result| result
                .records
                .answers
                .iter()
                .any(|answer| answer.accepted && answer.kind == kind)),
            "kind={kind:?}"
        );
    }
}
