//! The shared committee fixture and assertions for the scheme tests.

use super::*;

pub(super) const PARTICIPANTS: u32 = 6;
pub(super) const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST";

/// Seeds the fixture committee's epoch, genesis, and key material.
pub(super) const SEED: u64 = 9;

/// A six-participant committee with one signer scheme per participant and a verifier.
pub(super) struct Fixture<V: Variant> {
    pub(super) codec: CodecConfig,
    pub(super) epoch_config: Protocol<Digest>,
    pub(super) roster: Roster<Ed25519PublicKey, V>,
    pub(super) da: Sharing<V>,
    pub(super) nullification: Sharing<V>,
    pub(super) round: Round,
    pub(super) tips: Vec<BlockRef<Digest>>,
    pub(super) signers: Vec<Scheme<Ed25519PublicKey, V>>,
    pub(super) verifier: Scheme<Ed25519PublicKey, V>,
}

impl<V: Variant> Fixture<V> {
    pub(super) fn new() -> Self {
        Self::with_producers((0..PARTICIPANTS).map(Participant::new).collect())
    }

    pub(super) fn with_producers(producers: Vec<Participant>) -> Self {
        let Committee {
            config,
            roster,
            da,
            nullification,
            signers,
            verifier,
            ..
        } = Committee::builder(SEED, PARTICIPANTS)
            .namespace(NAMESPACE)
            .producers(producers)
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        Self {
            codec: config.codec_config(),
            round: Round::new(config.epoch(), View::new(7)),
            tips: config.genesis().tips().to_vec(),
            epoch_config: config,
            roster,
            da,
            nullification,
            signers,
            verifier,
        }
    }

    pub(super) fn header(&self, chain: u32, marker: u64) -> TransactionBlockHeader<Digest> {
        TransactionBlockHeader::new(
            self.round.epoch(),
            ChainId::new(chain),
            Height::new(1),
            digest(b"parent", marker),
            digest(b"commitment", marker),
        )
        .unwrap()
    }

    pub(super) fn leader(&self, marker: u64) -> LeaderBlock<V, Digest> {
        let proposals = self
            .tips
            .iter()
            .enumerate()
            .map(|(index, tip)| {
                ChainProposal::new(
                    ChainId::new(index as u32),
                    Anchor::Tip(*tip),
                    vec![digest(b"proposal", marker * 100 + index as u64)],
                    self.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            self.round,
            CertificateId::new(digest(b"parent vqc", marker)),
            self.parent_history(marker).commitment::<Sha256>(),
            proposals,
            self.codec,
        )
        .unwrap()
    }

    pub(super) fn parent_history(&self, marker: u64) -> TipRecord<Digest> {
        TipRecord::at_tips(digest(b"history parent", marker), self.tips.clone()).unwrap()
    }

    pub(super) fn body(
        &self,
        leader: &LeaderBlock<V, Digest>,
        positions: Vec<u32>,
        extensions: Vec<Vec<Digest>>,
    ) -> VoteBody<Digest> {
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(leader),
            positions.into_iter().map(Position::new).collect(),
            extensions
                .into_iter()
                .map(|payloads| Extension::new(payloads, self.codec.extension_bound()).unwrap())
                .collect(),
            self.codec,
        )
        .unwrap()
    }

    pub(super) fn standard_body(&self, leader: &LeaderBlock<V, Digest>) -> VoteBody<Digest> {
        self.body(
            leader,
            vec![1; self.codec.chains()],
            vec![Vec::new(); self.codec.chains()],
        )
    }

    pub(super) fn certificate_verifier(&self) -> Scheme<Ed25519PublicKey, V> {
        Scheme::certificate_verifier(
            self.epoch_config.parameters(),
            self.roster.clone(),
            *self.da.public(),
            *self.nullification.public(),
        )
        .unwrap()
    }
}

pub(super) fn assert_expanded_artifacts<V: Variant>(
    verifier: &Scheme<Ed25519PublicKey, V>,
    artifacts: &[&Artifact<V, Digest>],
    known: &[&[Verified<'_, V, Digest>]],
    expected: &[bool],
) {
    let results = verifier.verify_artifacts_expanded::<_, Sha256, Digest>(
        &mut test_rng(),
        artifacts,
        known,
        &Sequential,
    );
    assert_eq!(results.len(), artifacts.len());
    for ((artifact, result), valid) in artifacts.iter().zip(results).zip(expected) {
        assert_eq!(result.is_ok(), *valid);
        let Ok(expansion) = result else {
            continue;
        };
        let (leader, tally) = match artifact {
            Artifact::Vqc(certificate) => (certificate.leader(), certificate.tally()),
            Artifact::Lqc(certificate) => (certificate.leader(), certificate.tally()),
            _ => {
                assert!(expansion.is_none());
                continue;
            }
        };
        let expansion = expansion.expect("certificate expansion");
        assert_eq!(expansion.leader, leader.digest::<Sha256>());
        let designated = tally
            .signers()
            .iter()
            .map(|signer| {
                (
                    signer,
                    tally
                        .vote(
                            DigestedLeader::with_digest(leader, leader.digest::<Sha256>()),
                            signer,
                            verifier.codec_config(),
                        )
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(expansion.designated, designated);
        let mut expected_votes = designated
            .into_iter()
            .map(|(signer, body)| VerifiedVote::new::<Sha256>(signer, body))
            .collect::<Vec<_>>();
        match artifact {
            Artifact::Vqc(certificate) => {
                let conflicts = certificate
                    .conflicting_votes()
                    .iter()
                    .map(|vote| (vote.signer(), vote.vote_body(leader.round()).unwrap()))
                    .collect::<Vec<_>>();
                assert_eq!(expansion.conflicting, conflicts);
                expected_votes.extend(
                    conflicts
                        .into_iter()
                        .map(|(signer, body)| VerifiedVote::new::<Sha256>(signer, body)),
                );
                let baseline =
                    validate_vqc::<Sha256, _, _>(certificate, verifier.codec_config()).unwrap();
                let mut validated = validate_vqc_with_votes::<Sha256, _, _>(
                    certificate,
                    verifier.codec_config(),
                    expansion,
                )
                .unwrap();
                assert_eq!(validated.take_votes(), expected_votes);
                assert_eq!(validated.into_parts(), baseline.into_parts());
            }
            Artifact::Lqc(certificate) => {
                assert!(expansion.conflicting.is_empty());
                let baseline =
                    FinalTips::from_lqc::<Sha256, _>(certificate, verifier.codec_config()).unwrap();
                let ValidatedLqc {
                    leader: digest,
                    tips,
                    votes,
                    derived,
                } = validate_lqc::<Sha256, _, _>(certificate, verifier.codec_config(), expansion)
                    .unwrap();
                assert_eq!(digest, leader.digest::<Sha256>());
                assert_eq!(tips, baseline);
                assert_eq!(votes, expected_votes);
                let vqc = certificate.derive_vqc(verifier.codec_config()).unwrap();
                let baseline = validate_vqc::<Sha256, _, _>(&vqc, verifier.codec_config()).unwrap();
                assert_eq!(derived.validated.into_parts(), baseline.into_parts());
                assert_eq!(derived.artifact_id, derived.artifact.arc().id::<Sha256>());
            }
            _ => unreachable!(),
        }
    }
}
