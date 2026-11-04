//! Encodings of every artifact round-trip and stay within the codec bounds for every suite.

use super::*;
use core::fmt::Debug;

fn round_trip<T: Encode + Decode + PartialEq + Debug>(value: &T, cfg: &T::Cfg) -> usize {
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded.clone(), cfg).expect("canonical encoding decodes");
    assert_eq!(&decoded, value);
    assert_eq!(decoded.encode(), encoded, "re-encoding is canonical");
    // A truncated encoding never decodes.
    assert!(T::decode_cfg(encoded.slice(..encoded.len() - 1), cfg).is_err());
    encoded.len()
}

fn artifacts_round_trip_within_bounds<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let codec = fixture.codec;
    let bounds = codec
        .encoded_bounds::<S, Digest>()
        .expect("fixture bounds are representable");
    assert_eq!(
        codec.max_artifact_bytes::<S, Digest>().unwrap().get(),
        bounds.max_artifact_bytes()
    );
    let n = PARTICIPANTS;

    let header = fixture.header(0, 1);
    let transaction = fixture.signers[0]
        .sign_transaction_block(header.clone())
        .unwrap();
    let da_vote = fixture.signers[1].sign_da_vote(header.clone()).unwrap();
    let da_certificate = fixture.da_certificate(&header);
    let anchored = fixture.sign_leader(fixture.anchored_leader(2, da_certificate.clone()));
    let nullify = fixture.signers[2].sign_nullify(fixture.round).unwrap();
    let nullification = fixture.nullification(fixture.round);
    let novote = fixture.signers[3].sign_novote(fixture.round).unwrap();

    // The largest certificates this committee forms: every participant votes, each with its own
    // full path and extension on every chain.
    let leader = fixture.leader(3);
    let digested = DigestedLeader::new::<Sha256>(&leader);
    let votes = fixture
        .signers
        .iter()
        .enumerate()
        .map(|(index, signer)| {
            let positions = vec![Position::new(0); codec.chains()];
            let extensions = (0..codec.chains())
                .map(|chain| {
                    Extension::new(
                        (0..codec.extension_bound())
                            .map(|offset| {
                                digest(b"extension", (index * 100 + chain * 10 + offset) as u64)
                            })
                            .collect(),
                        codec.extension_bound(),
                    )
                    .unwrap()
                })
                .collect();
            signer
                .sign_vote(VoteBody::for_leader(digested, positions, extensions, codec).unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let messages = votes
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let vqc = fixture
        .verifier
        .assemble_vqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &messages, &Sequential)
        .unwrap();
    let lqc = fixture
        .verifier
        .assemble_lqc::<_, Sha256, _>(
            &mut test_rng(),
            leader,
            &votes[..codec.view_quorum()],
            &Sequential,
        )
        .unwrap();
    // A V-QC with abstentions and a conflicting vote.
    let other = fixture.leader(4);
    let mut mixed = fixture.quorum_votes(&fixture.leader(5))[..codec.designation_quorum()]
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    let index = mixed.len();
    mixed.push(ViewMessage::Vote(
        fixture.signers[index]
            .sign_vote(fixture.standard_body(&other))
            .unwrap(),
    ));
    mixed.push(ViewMessage::NoVote(
        fixture.signers[index + 1]
            .sign_novote(fixture.round)
            .unwrap(),
    ));
    let mixed_vqc = fixture
        .verifier
        .assemble_vqc::<_, Sha256, _>(&mut test_rng(), fixture.leader(5), &mixed, &Sequential)
        .unwrap();

    let data = [
        round_trip(&transaction, &()),
        round_trip(&da_vote, &()),
        round_trip(&da_certificate, &codec),
    ];
    let consensus = [
        round_trip(&anchored, &codec),
        round_trip(&votes[0], &codec),
        round_trip(&novote, &()),
        round_trip(&nullify, &()),
        round_trip(&ViewMessage::Vote(votes[1].clone()), &codec),
        round_trip(&ViewMessage::<S, Digest>::NoVote(novote.clone()), &codec),
    ];
    let certificates = [
        round_trip(&nullification, &codec),
        round_trip(&vqc, &codec),
        round_trip(&lqc, &codec),
        round_trip(&mixed_vqc, &codec),
    ];
    for size in data.iter().chain(&consensus).chain(&certificates) {
        assert!(*size <= bounds.max_artifact_bytes());
    }
    for size in data {
        assert!(size < bounds.max_data_frame_bytes());
    }
    for size in consensus {
        assert!(size < bounds.max_consensus_frame_bytes());
    }
    for size in certificates {
        assert!(size < bounds.max_certificate_frame_bytes());
    }
    assert!(
        round_trip(&vqc, &codec) + round_trip(&anchored, &codec)
            <= bounds.max_ingress_group_bytes()
    );

    // Each suite's certificates and aggregates stay within the bounds the codec relies on.
    assert!(
        da_certificate.certificate().encode_size() <= <S::Da as Verifier>::max_certificate_size(n)
    );
    assert!(
        nullification.certificate().encode_size()
            <= <S::Nullify as Verifier>::max_certificate_size(n)
    );
    for (certificate, terms) in [
        (vqc.signature(), n),
        (lqc.signature(), codec.view_quorum() as u32),
        (mixed_vqc.signature(), mixed.len() as u32),
    ] {
        assert!(
            certificate.encode_size() <= <S::Ordinary as Aggregator>::max_aggregate_size(terms)
        );
    }

    // Decoding under a smaller committee rejects every certificate that names more signers.
    let small = CodecConfig::new(codec.participants() - 1, codec.chains(), codec.limits()).unwrap();
    assert!(Vqc::<S, Digest>::decode_cfg(vqc.encode(), &small).is_err());
    assert!(Lqc::<S, Digest>::decode_cfg(lqc.encode(), &small).is_err());
}

#[test]
fn artifacts_round_trip_within_bounds_for_every_suite() {
    for_each_suite!(artifacts_round_trip_within_bounds);
}
