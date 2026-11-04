//! The shared committee fixture, forgeries, and assertions for the scheme tests.

use super::*;

pub(super) const PARTICIPANTS: u32 = 6;
pub(super) const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST";

/// Seeds the fixture committee's epoch, genesis, and key material.
pub(super) const SEED: u64 = 9;

/// A six-participant committee with one signer scheme per participant and a verifier.
pub(super) struct Fixture<S: Suite> {
    pub(super) codec: CodecConfig,
    pub(super) config: Protocol<Digest>,
    pub(super) round: Round,
    pub(super) tips: Vec<BlockRef<Digest>>,
    pub(super) signers: Vec<Generic<S>>,
    pub(super) verifier: Generic<S>,
}

impl<S: Suite> Fixture<S> {
    pub(super) fn new() -> Self {
        Self::with_producers((0..PARTICIPANTS).map(Participant::new).collect())
    }

    pub(super) fn with_producers(producers: Vec<Participant>) -> Self {
        Self::from_committee(
            Committee::<S>::builder(SEED, PARTICIPANTS)
                .namespace(NAMESPACE)
                .producers(producers)
                .limits(PathLimits::new(2, 2))
                .build(),
        )
    }

    pub(super) fn from_committee(committee: Committee<S>) -> Self {
        let Committee {
            config,
            signers,
            verifier,
            ..
        } = committee;
        Self {
            codec: config.codec_config(),
            round: Round::new(config.epoch(), View::new(7)),
            tips: config.genesis().tips().to_vec(),
            config,
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

    /// Returns a leader block for the fixture round whose chain `0` is anchored on
    /// `anchor` when given, and on its genesis tip otherwise.
    fn leader_with(
        &self,
        marker: u64,
        anchor: Option<DaCertificate<S, Digest>>,
    ) -> LeaderBlock<S, Digest> {
        let mut anchor = anchor;
        let proposals = self
            .tips
            .iter()
            .enumerate()
            .map(|(index, tip)| {
                let (anchor, payloads) = match (index, anchor.take()) {
                    (0, Some(certificate)) => (Anchor::Certificate(certificate), Vec::new()),
                    _ => (
                        Anchor::Tip(*tip),
                        vec![digest(b"proposal", marker * 100 + index as u64)],
                    ),
                };
                ChainProposal::new(
                    ChainId::new(index as u32),
                    anchor,
                    payloads,
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

    pub(super) fn leader(&self, marker: u64) -> LeaderBlock<S, Digest> {
        self.leader_with(marker, None)
    }

    /// Returns a leader block whose chain `0` anchors on `certificate`.
    pub(super) fn anchored_leader(
        &self,
        marker: u64,
        certificate: DaCertificate<S, Digest>,
    ) -> LeaderBlock<S, Digest> {
        self.leader_with(marker, Some(certificate))
    }

    pub(super) fn parent_history(&self, marker: u64) -> TipRecord<Digest> {
        TipRecord::at_tips(digest(b"history parent", marker), self.tips.clone()).unwrap()
    }

    /// Returns the index of the leader scheduled for `view`.
    pub(super) fn scheduled(&self, view: View) -> usize {
        self.config.leader(view).get() as usize
    }

    /// Returns `leader` signed by its scheduled leader.
    pub(super) fn sign_leader(
        &self,
        leader: LeaderBlock<S, Digest>,
    ) -> SignedLeaderBlock<S, Digest> {
        self.signers[self.scheduled(leader.view())]
            .sign_leader_block(leader)
            .unwrap()
    }

    pub(super) fn body(
        &self,
        leader: &LeaderBlock<S, Digest>,
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

    pub(super) fn standard_body(&self, leader: &LeaderBlock<S, Digest>) -> VoteBody<Digest> {
        let positions = leader
            .proposals()
            .iter()
            .map(|proposal| proposal.len() as u32)
            .collect();
        self.body(leader, positions, vec![Vec::new(); self.codec.chains()])
    }

    /// Returns every signer's DA vote over `header`.
    pub(super) fn da_votes(
        &self,
        header: &TransactionBlockHeader<Digest>,
    ) -> Vec<DaVote<S, Digest>> {
        self.signers
            .iter()
            .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
            .collect()
    }

    /// Returns the DA certificate the first DA quorum recovers over `header`.
    pub(super) fn da_certificate(
        &self,
        header: &TransactionBlockHeader<Digest>,
    ) -> DaCertificate<S, Digest> {
        let votes = self.da_votes(header);
        self.verifier
            .assemble_da_certificate(
                &mut test_rng(),
                &votes[..self.codec.da_quorum()],
                &Sequential,
            )
            .unwrap()
    }

    /// Returns every signer's nullify share for `round`.
    pub(super) fn nullifies(&self, round: Round) -> Vec<Nullify<S>> {
        self.signers
            .iter()
            .map(|signer| signer.sign_nullify(round).unwrap())
            .collect()
    }

    /// Returns the nullification the first `2f+1` shares recover for `round`.
    pub(super) fn nullification(&self, round: Round) -> Nullification<S> {
        let shares = self.nullifies(round);
        self.verifier
            .assemble_nullification(
                &mut test_rng(),
                &shares[..self.codec.nullification_quorum()],
                &Sequential,
            )
            .unwrap()
    }

    /// Returns the first `n-f` signers' standard votes for `leader`.
    pub(super) fn quorum_votes(&self, leader: &LeaderBlock<S, Digest>) -> Vec<Vote<S, Digest>> {
        (0..self.codec.view_quorum())
            .map(|index| {
                self.signers[index]
                    .sign_vote(self.standard_body(leader))
                    .unwrap()
            })
            .collect()
    }

    pub(super) fn lqc(&self, leader: &LeaderBlock<S, Digest>) -> Lqc<S, Digest> {
        self.verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut test_rng(),
                leader.clone(),
                &self.quorum_votes(leader),
                &Sequential,
            )
            .unwrap()
    }

    pub(super) fn vqc(&self, leader: &LeaderBlock<S, Digest>) -> Vqc<S, Digest> {
        let messages = self
            .quorum_votes(leader)
            .into_iter()
            .map(ViewMessage::Vote)
            .collect::<Vec<_>>();
        self.verifier
            .assemble_vqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &messages, &Sequential)
            .unwrap()
    }
}

/// Returns a signature whose encoding does not decode, or, for schemes whose every encoding
/// decodes, a signature by nobody.
pub(super) fn malformed<T: Read<Cfg = ()> + FixedSize>() -> Lazy<T> {
    Lazy::deferred(&mut Bytes::from(vec![0xFF; T::SIZE]), ())
}

/// Flips the last encoded byte of `value`, which lies in the trailing signature or aggregate of
/// every certificate, and decodes the result.
///
/// Signatures decode lazily, so the tampered value still decodes and fails only verification.
pub(super) fn corrupt_tail<T: Encode + Decode>(value: &T, cfg: &T::Cfg) -> T {
    let mut encoded = value.encode().to_vec();
    *encoded.last_mut().unwrap() ^= 0x01;
    T::decode_cfg(Bytes::from(encoded), cfg).expect("a tampered trailing signature still decodes")
}

/// Returns a verifier over the fixture's parameters with independently dealt key material.
pub(super) fn other_verifier<S: Suite>(fixture: &Fixture<S>, seed: u64) -> Generic<S> {
    let mut keys = (0..PARTICIPANTS)
        .map(|index| Ed25519PrivateKey::from_seed(seed * 1_000 + u64::from(index)))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.public_key());
    S::committee(&mut TestRng::new(seed), fixture.config.parameters(), &keys).1
}

/// Checks batch verdicts and, for every verified V-QC and L-QC, that its expanded votes match an
/// independent reconstruction.
pub(super) fn assert_expanded_artifacts<S: Suite>(
    verifier: &Generic<S>,
    artifacts: &[&Artifact<S, Digest>],
    known: &[&[Verified<'_, S, Digest>]],
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
