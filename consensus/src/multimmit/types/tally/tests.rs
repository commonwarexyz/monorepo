//! Compact tally encoding, reference selection, and validation tests.

use super::*;
use crate::{
    multimmit::{
        algebra::{FinalTips, VqcExtraction},
        mocks::Committee,
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, DigestedLeader, Lqc,
            PathLimits, ViewMessage, Vqc,
        },
    },
    types::{Epoch, Height, Round, View},
};
use bytes::{Buf as _, BytesMut};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use proptest::{collection::vec as prop_vec, prelude::*};

fn digest(marker: u64) -> sha256::Digest {
    Sha256::hash(&[&marker.to_be_bytes()])
}

fn config() -> CodecConfig {
    CodecConfig::new(6, 6, PathLimits::new(2, 1).unwrap()).unwrap()
}

fn leader() -> LeaderBlock<MinSig, sha256::Digest> {
    let config = config();
    let proposals = (0..config.chains())
        .map(|index| {
            let chain = ChainId::new(index as u32);
            ChainProposal::new(
                chain,
                Anchor::Tip(BlockRef::new(chain, Height::zero(), digest(index as u64))),
                vec![digest(100 + index as u64)],
                config.pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    LeaderBlock::new(
        Round::new(Epoch::new(3), View::new(4)),
        CertificateId::new(digest(201)),
        digest(202),
        proposals,
        config,
    )
    .unwrap()
}

proptest! {
    #[test]
    fn compact_tally_round_trips_every_exact_vote(
        positions in prop_vec(prop_vec(0u32..=1, 6), 6),
        extension_flags in prop_vec(prop_vec(any::<bool>(), 6), 6),
        count in 1usize..=6,
    ) {
        let config = config();
        let leader = leader();
        let votes = (0..count)
            .map(|signer| {
                let extensions = extension_flags[signer]
                    .iter()
                    .enumerate()
                    .map(|(chain, present)| {
                        let payloads = present.then(|| digest(1_000 + (signer * 6 + chain) as u64));
                        Extension::new(payloads.into_iter().collect(), config.extension_bound()).unwrap()
                    })
                    .collect();
                let body = VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(&leader),
                    positions[signer].iter().copied().map(Position::new).collect(),
                    extensions,
                    config)
                .unwrap();
                (Participant::from_usize(signer), body)
            })
            .collect::<Vec<_>>();
        let tally = Tally::from_votes(
            DigestedLeader::new::<Sha256>(&leader),
            votes.iter().cloned(),
            config)
        .unwrap();

        for (signer, expected) in &votes {
            prop_assert_eq!(
                tally.vote(DigestedLeader::new::<Sha256>(&leader), *signer, config).unwrap(),
                expected.clone(),
            );
        }
        let mut encoded = tally.encode();
        let decoded = Tally::decode_for_leader(&mut encoded, &leader, config).unwrap();
        prop_assert!(!encoded.has_remaining());
        prop_assert_eq!(decoded, tally);
    }
}

#[test]
fn reference_prefers_most_common_standard_vote_then_canonical_bytes() {
    let config = config();
    let leader = leader();
    let empty = vec![Extension::empty(); config.chains()];
    let mut carried = empty.clone();
    carried[0] = Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
    let positions = vec![Position::new(1); config.chains()];
    let votes = [empty, carried.clone(), carried.clone()]
        .into_iter()
        .enumerate()
        .map(|(signer, extensions)| {
            (
                Participant::from_usize(signer),
                VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(&leader),
                    positions.clone(),
                    extensions,
                    config,
                )
                .unwrap(),
            )
        });
    let tally = Tally::from_votes(DigestedLeader::new::<Sha256>(&leader), votes, config).unwrap();
    assert_eq!(tally.reference_extensions(), carried);
}

#[test]
fn reference_tie_breaks_by_canonical_bytes() {
    let config = CodecConfig::new(6, 6, PathLimits::new(2, 2).unwrap()).unwrap();
    let leader = leader();
    let positions = vec![Position::new(1); config.chains()];
    let mut short = vec![Extension::empty(); config.chains()];
    short[0] = Extension::new(vec![digest(900)], config.extension_bound()).unwrap();
    let mut long = vec![Extension::empty(); config.chains()];
    long[0] = Extension::new(vec![digest(1), digest(2)], config.extension_bound()).unwrap();
    let votes = [long, short.clone()]
        .into_iter()
        .enumerate()
        .map(|(signer, extensions)| {
            (
                Participant::from_usize(signer),
                VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(&leader),
                    positions.clone(),
                    extensions,
                    config,
                )
                .unwrap(),
            )
        });

    let tally = Tally::from_votes(DigestedLeader::new::<Sha256>(&leader), votes, config).unwrap();
    assert_eq!(tally.reference_extensions(), short);
}

#[test]
fn replacement_paths_are_shared_and_canonical() {
    let config = config();
    let leader = leader();
    let path = Extension::new(vec![digest(900)], config.extension_bound()).unwrap();
    let votes = (0..config.participants())
        .map(|signer| {
            let extensions = (0..config.chains())
                .map(|chain| {
                    if (chain + signer) % 3 == 0 {
                        path.clone()
                    } else {
                        Extension::empty()
                    }
                })
                .collect();
            (
                Participant::from_usize(signer),
                VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(&leader),
                    vec![Position::new(1); config.chains()],
                    extensions,
                    config,
                )
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        votes.clone(),
        config,
    )
    .unwrap();
    assert_eq!(tally.extension_paths(), std::slice::from_ref(&path));
    assert!(
        tally
            .deviations()
            .iter()
            .flat_map(|d| d.extensions())
            .filter(|d| d.extension() == Some(NonZeroUsize::MIN))
            .count()
            > 1
    );
    let reversed = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        votes.iter().rev().cloned(),
        config,
    )
    .unwrap();
    assert_eq!(tally.encode(), reversed.encode());
    let decoded = Tally::decode_for_leader(&mut tally.encode(), &leader, config).unwrap();
    for (signer, vote) in votes {
        assert_eq!(
            decoded
                .vote(DigestedLeader::new::<Sha256>(&leader), signer, config)
                .unwrap()
                .encode(),
            vote.encode()
        );
    }
    let mut duplicate = tally.clone();
    duplicate.extension_paths.push(path);
    let mut empty = tally.clone();
    empty.extension_paths[0] = Extension::empty();
    let mut unused = tally.clone();
    unused
        .extension_paths
        .push(Extension::new(vec![digest(901)], config.extension_bound()).unwrap());
    unused.extension_paths.sort();
    let mut invalid_index = tally.clone();
    invalid_index.deviations[0].extensions[0].extension = NonZeroUsize::new(2);
    let mut too_long = tally;
    too_long.extension_paths[0] = Extension::new(vec![digest(900), digest(901)], 2).unwrap();
    for malformed in [duplicate, empty, unused, invalid_index, too_long] {
        assert_eq!(malformed.validate(&leader, config), Err(Error::Transcript));
        assert!(Tally::decode_for_leader(&mut malformed.encode(), &leader, config).is_err());
    }
}

#[test]
fn decoding_rejects_noncanonical_extension_deviations() {
    let config = config();
    let leader = leader();
    let extension = Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(1); config.chains()],
        vec![extension; config.chains()],
        config,
    )
    .unwrap();
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        (0..3).map(|signer| (Participant::new(signer), body.clone())),
        config,
    )
    .unwrap();
    let clear = |chain| ExtensionDeviation::new(ChainId::new(chain), None);
    let path =
        |chain, index| ExtensionDeviation::new(ChainId::new(chain), NonZeroUsize::new(index));
    for replacements in [
        vec![],
        vec![clear(0), clear(0)],
        vec![clear(1), clear(0)],
        vec![clear(config.chains() as u32)],
        vec![clear(u32::MAX)],
        vec![path(0, 1)],
        vec![clear(0), path(1, 1)],
        vec![path(0, u32::MAX as usize)],
    ] {
        let mut malformed = tally.clone();
        malformed
            .deviations
            .push(Deviation::new(Participant::new(0), vec![], replacements));
        assert_eq!(malformed.validate(&leader, config), Err(Error::Transcript));
        assert!(Tally::decode_for_leader(&mut malformed.encode(), &leader, config).is_err());
    }

    let mut valid = tally;
    valid
        .deviations
        .push(Deviation::new(Participant::new(0), vec![], vec![clear(0)]));
    assert_eq!(
        Tally::decode_for_leader(&mut valid.encode(), &leader, config).unwrap(),
        valid
    );
    assert!(
        valid
            .vote(
                DigestedLeader::new::<Sha256>(&leader),
                Participant::new(0),
                config
            )
            .unwrap()
            .extensions()[0]
            .is_empty()
    );
}

#[test]
fn decoding_bounds_extension_deviation_counts_and_indices() {
    let config = config();
    let prefix = || {
        let mut bytes = BytesMut::new();
        Participant::new(0).write(&mut bytes);
        Vec::<PositionDeviation>::new().write(&mut bytes);
        bytes
    };
    let mut bytes = prefix();
    (config.chains() + 1).write(&mut bytes);
    assert!(matches!(
        Deviation::decode_with_paths(&mut bytes.freeze(), config, config.extension_bound()),
        Err(CodecError::InvalidLength(_))
    ));

    let mut bytes = prefix();
    1usize.write(&mut bytes);
    ChainId::new(0).write(&mut bytes);
    (config.extension_bound() + 1).write(&mut bytes);
    assert!(matches!(
        Deviation::decode_with_paths(&mut bytes.freeze(), config, config.extension_bound()),
        Err(CodecError::InvalidLength(_))
    ));
    let disabled = CodecConfig::new(6, 6, PathLimits::new(2, 0).unwrap()).unwrap();
    let mut bytes = prefix();
    1usize.write(&mut bytes);
    ChainId::new(0).write(&mut bytes);
    1usize.write(&mut bytes);
    assert!(matches!(
        Deviation::decode_with_paths(&mut bytes.freeze(), disabled, 0),
        Err(CodecError::InvalidLength(_))
    ));
}

fn certificate_extension_deviations<V: Variant>() {
    for chains in [6, 128] {
        let committee = Committee::<V>::builder(11, chains as u32)
            .namespace(b"_COMMONWARE_CONSENSUS_SPARSE_TALLY_TEST")
            .build();
        let config = committee.codec();
        let signed_leader = committee.leader_block(View::new(1));
        let leader = signed_leader.block();
        for changed in [0, 1, chains] {
            for (populated, clear) in [(false, false), (true, false), (true, true)] {
                let reference = (0..chains)
                    .map(|chain| {
                        if populated {
                            Extension::new(vec![digest(chain as u64)], 1).unwrap()
                        } else {
                            Extension::empty()
                        }
                    })
                    .collect::<Vec<_>>();
                let votes = (0..config.view_quorum())
                    .map(|signer| {
                        let mut extensions = reference.clone();
                        if signer >= config.view_quorum() - 2 {
                            for (chain, extension) in
                                extensions.iter_mut().enumerate().rev().take(changed)
                            {
                                *extension = if clear {
                                    Extension::empty()
                                } else {
                                    Extension::new(vec![digest(1000 + chain as u64)], 1).unwrap()
                                };
                            }
                        }
                        let body = VoteBody::for_leader(
                            DigestedLeader::new::<Sha256>(leader),
                            vec![Position::new(0); chains],
                            extensions,
                            config,
                        )
                        .unwrap();
                        committee.signers[signer].sign_vote(body).unwrap()
                    })
                    .collect::<Vec<_>>();
                let certificate = committee
                    .verifier
                    .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
                    .unwrap();
                let encoded = certificate.encode();
                assert_eq!(encoded.len(), certificate.encode_size());
                let decoded =
                    Lqc::<V, sha256::Digest>::decode_cfg(encoded.clone(), &config).unwrap();
                assert_eq!(decoded, certificate);
                assert!(
                    committee
                        .verifier
                        .verify_lqc::<_, Sha256, _>(&mut test_rng(), &decoded, &Sequential)
                        .is_some()
                );
                assert_eq!(decoded.tally().reference_extensions(), reference);
                if changed > 0 {
                    let mut altered = votes
                        .iter()
                        .map(|vote| (vote.signer(), vote.body().clone()))
                        .collect::<Vec<_>>();
                    let mut extensions = altered[0].1.extensions().to_vec();
                    extensions[0] = Extension::new(vec![digest(10_000)], 1).unwrap();
                    altered[0].1 = VoteBody::for_leader(
                        DigestedLeader::new::<Sha256>(leader),
                        altered[0].1.positions().to_vec(),
                        extensions,
                        config,
                    )
                    .unwrap();
                    let tampered =
                        Tally::from_votes(DigestedLeader::new::<Sha256>(leader), altered, config)
                            .unwrap();
                    let tampered = Lqc::new(
                        leader.clone(),
                        tampered,
                        decoded.signature().unwrap().clone(),
                        config,
                    )
                    .unwrap();
                    assert!(
                        committee
                            .verifier
                            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &tampered, &Sequential)
                            .is_none()
                    );
                }
                for vote in &votes {
                    let expanded = decoded
                        .tally()
                        .vote(DigestedLeader::new::<Sha256>(leader), vote.signer(), config)
                        .unwrap();
                    assert_eq!(expanded.encode(), vote.body().encode());
                }
                assert_eq!(
                    FinalTips::from_lqc::<Sha256, V>(&decoded, config).unwrap(),
                    FinalTips::from_pool::<Sha256, V, _>(
                        leader,
                        votes.iter().map(|vote| (vote.signer(), vote.body())),
                        config
                    )
                    .unwrap()
                );
                let messages = votes
                    .iter()
                    .cloned()
                    .map(ViewMessage::Vote)
                    .collect::<Vec<_>>();
                let vqc = committee
                    .verifier
                    .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
                    .unwrap();
                let decoded_vqc =
                    Vqc::<V, sha256::Digest>::decode_cfg(vqc.encode(), &config).unwrap();
                assert_eq!(decoded_vqc, vqc);
                assert!(
                    committee
                        .verifier
                        .verify_vqc::<_, Sha256, _>(&mut test_rng(), &decoded_vqc, &Sequential)
                        .is_some()
                );
                assert_eq!(
                    VqcExtraction::new::<Sha256, V>(&decoded_vqc, config)
                        .unwrap()
                        .into_parts()
                        .0,
                    VqcExtraction::from_votes::<Sha256, V>(
                        DigestedLeader::new::<Sha256>(leader),
                        votes.iter().map(|vote| (vote.signer(), vote.body())),
                        config
                    )
                    .unwrap()
                    .into_parts()
                    .0,
                );

                let tally = certificate.tally();
                assert!(
                    tally
                        .deviations()
                        .iter()
                        .all(|deviation| deviation.extensions().len() == changed)
                );
                let mut dense = BytesMut::new();
                tally.reference_extensions.write(&mut dense);
                tally.signers.write(&mut dense);
                tally.deviations.len().write(&mut dense);
                for deviation in &tally.deviations {
                    deviation.signer.write(&mut dense);
                    deviation.positions.write(&mut dense);
                    Some(
                        votes[usize::from(deviation.signer)]
                            .body()
                            .extensions()
                            .to_vec(),
                    )
                    .write(&mut dense);
                }
                let dense_size = encoded.len() - tally.encode_size() + dense.len();
                match changed {
                    0 => assert_eq!(encoded.len(), dense_size + 1),
                    1 => assert!(encoded.len() < dense_size),
                    _ if clear => assert_eq!(encoded.len(), dense_size + 2 * (chains - 1) + 1),
                    _ => assert!(encoded.len() < dense_size),
                }
                let bounds = config.encoded_bounds::<V, sha256::Digest>().unwrap();
                assert!(encoded.len() <= bounds.max_artifact_bytes());
                assert!(vqc.encode_size() <= bounds.max_artifact_bytes());
            }
        }
    }
}

#[test]
fn sparse_certificates_preserve_signatures_tips_and_measure_sizes() {
    certificate_extension_deviations::<MinPk>();
    certificate_extension_deviations::<MinSig>();
}

#[test]
fn certificate_decoding_matches_constructor_tally_validation() {
    let committee = Committee::<MinSig>::builder(6, 6)
        .namespace(b"_COMMONWARE_CONSENSUS_CERTIFICATE_TALLY_DECODE_TEST")
        .build();
    let config = committee.codec();
    let lqc = committee.lqc(View::new(1));
    let vqc = lqc.derive_vqc(config).unwrap();
    let leader = lqc.leader();
    let tally = lqc.tally();
    let mut cases = vec![tally.clone()];
    let mut wrong_length = tally.clone();
    wrong_length.reference_extensions.pop();
    cases.push(wrong_length);
    let mut wrong_participants = tally.clone();
    wrong_participants.signers = Signers::new(6, [Participant::new(0)]).unwrap();
    cases.push(wrong_participants);
    let mut invalid_position = tally.clone();
    invalid_position.deviations = vec![Deviation::new(
        Participant::new(0),
        vec![PositionDeviation::new(
            ChainId::new(0),
            Position::new(u32::MAX),
        )],
        Vec::new(),
    )];
    cases.push(invalid_position);
    let mut invalid_chain = tally.clone();
    invalid_chain.deviations = vec![Deviation::new(
        Participant::new(0),
        vec![PositionDeviation::new(ChainId::new(6), Position::new(0))],
        Vec::new(),
    )];
    cases.push(invalid_chain);
    let mut duplicate = tally.clone();
    let deviation = Deviation::new(Participant::new(0), Vec::new(), Vec::new());
    duplicate.deviations = vec![deviation.clone(), deviation];
    cases.push(duplicate);

    for (index, tally) in cases.into_iter().enumerate() {
        let lqc_result = Lqc::new(
            leader.clone(),
            tally.clone(),
            lqc.signature().unwrap().clone(),
            config,
        );
        let vqc_result = Vqc::new(
            leader.clone(),
            tally.clone(),
            vqc.novoters().clone(),
            Vec::new(),
            vqc.signature().unwrap().clone(),
            config,
        );
        assert_eq!(lqc_result.is_ok(), index == 0);
        assert_eq!(vqc_result.is_ok(), index == 0);
        let replace_tally = |encoded: bytes::Bytes| {
            let start = leader.encode_size();
            let end = start + lqc.tally().encode_size();
            let mut replaced = BytesMut::new();
            replaced.extend_from_slice(&encoded[..start]);
            tally.write(&mut replaced);
            replaced.extend_from_slice(&encoded[end..]);
            replaced.freeze()
        };
        assert_eq!(
            Lqc::<MinSig, sha256::Digest>::decode_cfg(replace_tally(lqc.encode()), &config).is_ok(),
            lqc_result.is_ok(),
        );
        assert_eq!(
            Vqc::<MinSig, sha256::Digest>::decode_cfg(replace_tally(vqc.encode()), &config).is_ok(),
            vqc_result.is_ok(),
        );
    }
}

#[test]
fn validation_rejects_noncanonical_reference() {
    let config = config();
    let leader = leader();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(1); config.chains()],
        vec![Extension::empty(); config.chains()],
        config,
    )
    .unwrap();
    let mut tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        [(Participant::new(0), body)],
        config,
    )
    .unwrap();
    tally.reference_extensions[0] =
        Extension::new(vec![digest(400)], config.extension_bound()).unwrap();
    tally.deviations.push(Deviation::new(
        Participant::new(0),
        Vec::new(),
        vec![ExtensionDeviation::new(ChainId::new(0), None)],
    ));
    assert_eq!(tally.validate(&leader, config), Err(Error::Transcript));
    let mut encoded = tally.encode();
    assert!(Tally::decode_for_leader(&mut encoded, &leader, config).is_err());
}

#[test]
fn validation_rejects_expanded_height_overflow() {
    let config = config();
    let proposals = (0..config.chains())
        .map(|index| {
            let chain = ChainId::new(index as u32);
            let height = if index == 0 {
                Height::new(u64::MAX)
            } else {
                Height::zero()
            };
            ChainProposal::new(
                chain,
                Anchor::<MinSig, _>::Tip(BlockRef::new(chain, height, digest(index as u64))),
                Vec::new(),
                config.pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        Round::new(Epoch::new(3), View::new(4)),
        CertificateId::new(digest(201)),
        digest(202),
        proposals,
        config,
    )
    .unwrap();
    let mut reference_extensions = vec![Extension::empty(); config.chains()];
    reference_extensions[0] = Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
    let tally = Tally {
        extension_paths: Vec::new(),
        reference_extensions,
        signers: Signers::new(
            config.participants().try_into().unwrap(),
            [Participant::new(0)],
        )
        .unwrap(),
        deviations: Vec::new(),
    };

    assert_eq!(tally.validate(&leader, config), Err(Error::Transcript));
    let mut encoded = tally.encode();
    assert!(Tally::decode_for_leader(&mut encoded, &leader, config).is_err());
}

#[test]
fn expanding_untrusted_tally_never_indexes_an_unchecked_chain() {
    let config = config();
    let leader = leader();
    let mut tally = Tally {
        extension_paths: Vec::new(),
        reference_extensions: vec![Extension::empty(); config.chains()],
        signers: Signers::new(
            config.participants().try_into().unwrap(),
            [Participant::new(0)],
        )
        .unwrap(),
        deviations: vec![Deviation::new(
            Participant::new(0),
            vec![PositionDeviation::new(
                ChainId::new(u32::MAX),
                Position::new(0),
            )],
            Vec::new(),
        )],
    };

    assert_eq!(
        tally.vote(
            DigestedLeader::new::<Sha256>(&leader),
            Participant::new(0),
            config
        ),
        Err(Error::Transcript)
    );
    tally.deviations[0].positions.clear();
    tally.deviations[0]
        .extensions
        .push(ExtensionDeviation::new(ChainId::new(u32::MAX), None));
    assert_eq!(
        tally.vote(
            DigestedLeader::new::<Sha256>(&leader),
            Participant::new(0),
            config
        ),
        Err(Error::Transcript)
    );
    tally.signers = Signers::new(
        (config.participants() + 1).try_into().unwrap(),
        [Participant::new(0)],
    )
    .unwrap();
    assert_eq!(
        tally.vote(
            DigestedLeader::new::<Sha256>(&leader),
            Participant::new(0),
            config
        ),
        Err(Error::Context)
    );
}

#[test]
fn conflicting_votes_share_their_ballot_and_bound_the_signer() {
    let config = config();
    let ballot = Ballot::new(
        digest(500),
        vec![Position::new(1); config.chains()],
        vec![Extension::empty(); config.chains()],
        config,
    )
    .unwrap();
    assert_eq!(
        ConflictingVote::new(
            Participant::from_usize(config.participants()),
            ballot.clone(),
            config,
        )
        .unwrap_err(),
        Error::Participants
    );
    let vote = ConflictingVote::new(Participant::new(0), ballot.clone(), config).unwrap();
    let body = vote
        .vote_body(Round::new(Epoch::new(3), View::new(4)))
        .unwrap();
    assert_eq!(body.ballot(), &ballot);
    assert!(core::ptr::eq(body.positions(), vote.positions()));
    assert!(core::ptr::eq(body.extensions(), vote.extensions()));
    assert_eq!(
        vote.vote_body(Round::new(Epoch::new(3), View::zero()))
            .unwrap_err(),
        Error::GenesisView
    );
    assert_eq!(
        ConflictingVote::<sha256::Digest>::decode_cfg(vote.encode(), &config).unwrap(),
        vote
    );
    let wider = CodecConfig::new(7, 6, PathLimits::new(2, 1).unwrap()).unwrap();
    let outsider = ConflictingVote::new(Participant::new(6), ballot, wider).unwrap();
    assert!(ConflictingVote::<sha256::Digest>::decode_cfg(outsider.encode(), &config).is_err());
}

#[test]
fn conflicting_votes_revalidate_their_ballot_against_the_config() {
    let config = config();
    let ballot = Ballot::new(
        digest(501),
        vec![Position::new(2); config.chains()],
        vec![Extension::new(vec![digest(502), digest(503)], 2).unwrap(); config.chains()],
        CodecConfig::new(6, 6, PathLimits::new(2, 2).unwrap()).unwrap(),
    )
    .unwrap();
    let signer = Participant::new(0);
    let fewer_chains = CodecConfig::new(6, 5, PathLimits::new(2, 2).unwrap()).unwrap();
    assert_eq!(
        ConflictingVote::new(signer, ballot.clone(), fewer_chains).unwrap_err(),
        Error::ChainCount
    );
    let shallower = CodecConfig::new(6, 6, PathLimits::new(1, 2).unwrap()).unwrap();
    assert_eq!(
        ConflictingVote::new(signer, ballot.clone(), shallower).unwrap_err(),
        Error::Position
    );
    // The test config admits depth 2 but extensions of at most one block.
    assert_eq!(
        ConflictingVote::new(signer, ballot, config).unwrap_err(),
        Error::ExtensionLength
    );
}
