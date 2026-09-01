//! Structured certificate transcripts with real signatures and adversarial composition.

use crate::multimmit::{
    config::Limits,
    mocks::Committee,
    scheme::{Unverified, Verified},
    types::{Extension, LeaderBlock, Lqc, Position, ViewMessage, Vote, VoteBody, Vqc},
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use std::collections::BTreeSet;

thread_local! {
    static MIN_PK: Committee<MinPk> = Committee::new(914, 6, Limits::new(2, 2).unwrap());
    static MIN_SIG: Committee<MinSig> = Committee::new(914, 6, Limits::new(2, 2).unwrap());
}

pub(crate) fn exercise(input: &[u8]) {
    if input.first().copied().unwrap_or(0) & 1 == 0 {
        MIN_PK.with(|committee| campaign(committee, input));
    } else {
        MIN_SIG.with(|committee| campaign(committee, input));
    }
}

struct Schedule<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl Schedule<'_> {
    fn next(&mut self) -> usize {
        let value = self.input.get(self.cursor).copied().unwrap_or(0);
        self.cursor += 1;
        usize::from(value)
    }
}

// The oracle tracks generation facts, independently of compact tally reconstruction and
// signature verification. Identity, context, and designation are separate quorum conditions.
#[derive(Clone)]
struct Term<V: Variant> {
    message: ViewMessage<V, Digest>,
    identity: usize,
    designated: bool,
    same_round: bool,
    authentic: bool,
}

fn acceptable<V: Variant>(terms: &[Term<V>], quorum: usize, designation: usize, n: usize) -> bool {
    let identities: BTreeSet<_> = terms.iter().map(|term| term.identity).collect();
    (quorum..=n).contains(&terms.len())
        && identities.len() == terms.len()
        && terms.iter().filter(|term| term.designated).count() >= designation
        && terms.iter().all(|term| term.same_round && term.authentic)
}

fn body<V: Variant>(
    committee: &Committee<V>,
    leader: &LeaderBlock<V, Digest>,
    marker: usize,
) -> VoteBody<Digest> {
    let codec = committee.codec();
    let mut extensions = vec![Extension::empty(); codec.chains()];
    let chain = marker % codec.chains();
    let payloads = (0..marker % 3)
        .map(|offset| Sha256::hash(&[&marker.to_le_bytes(), &offset.to_le_bytes()]))
        .collect();
    extensions[chain] = Extension::new(payloads, codec.extension_bound()).unwrap();
    VoteBody::for_leader::<Sha256, V>(
        leader,
        vec![Position::new(0); codec.chains()],
        extensions,
        codec,
    )
    .unwrap()
}

const fn known<V: Variant>(message: &ViewMessage<V, Digest>) -> Verified<'_, V, Digest> {
    match message {
        ViewMessage::Vote(vote) => Verified::Vote(vote),
        ViewMessage::NoVote(vote) => Verified::NoVote(vote),
    }
}

fn campaign<V: Variant>(committee: &Committee<V>, input: &[u8]) {
    let codec = committee.codec();
    let mut schedule = Schedule { input, cursor: 1 };
    let rounds = 1 + schedule.next() % 3;
    let mut rng = TestRng::new(971);
    let mut parent = None;
    let mut previous = Vec::new();
    for step in 0..rounds {
        let view = 1 + step as u64;
        let signed = parent.as_ref().map_or_else(
            || committee.leader_block(view),
            |parent| committee.leader_block_with_parent(view, parent),
        );
        let leader = signed.block();
        let alternate = LeaderBlock::new(
            leader.round(),
            leader.parent(),
            Sha256::hash(&[b"alternate history", &view.to_le_bytes()]),
            leader.proposals().to_vec(),
            codec,
        )
        .unwrap();
        let count = codec.view_quorum()
            + schedule.next() % (codec.participants() - codec.view_quorum() + 1);
        let rotation = schedule.next() % codec.participants();
        let mut terms = Vec::new();
        for index in 0..count {
            let identity = (index + rotation) % codec.participants();
            let kind = if index < codec.designation_quorum() {
                0
            } else {
                schedule.next() % 3
            };
            let message = match kind {
                0 | 1 => ViewMessage::Vote(
                    committee.signers[identity]
                        .sign_vote(body(
                            committee,
                            if kind == 0 { leader } else { &alternate },
                            schedule.next(),
                        ))
                        .unwrap(),
                ),
                _ => ViewMessage::NoVote(committee.novote(identity, view)),
            };
            terms.push(Term {
                message,
                identity,
                designated: kind == 0,
                same_round: true,
                authentic: true,
            });
        }
        assert!(acceptable(
            &terms,
            codec.view_quorum(),
            codec.designation_quorum(),
            codec.participants(),
        ));
        let messages: Vec<_> = terms.iter().map(|term| term.message.clone()).collect();
        let vqc = committee
            .verifier
            .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
            .unwrap();
        assert!(
            committee
                .verifier
                .verify_vqc::<_, Sha256, _>(&mut rng, &vqc, &Sequential)
                .is_some()
        );

        // Every invocation includes both valid reorderings and invalid authority claims.
        for mutation in 0..7 {
            let mut hostile = terms.clone();
            let index = schedule.next() % hostile.len();
            match mutation {
                0 => hostile.rotate_left(index),
                1 => hostile.reverse(),
                2 => {
                    // Keep quorum size and designated support sufficient, isolating identity.
                    let last = hostile.len() - 1;
                    hostile[last] = hostile[index % codec.designation_quorum()].clone();
                }
                3 => {
                    hostile.truncate(codec.view_quorum() - 1);
                }
                4 => {
                    let index = codec.designation_quorum()
                        + index % (hostile.len() - codec.designation_quorum());
                    hostile[index].message =
                        ViewMessage::NoVote(committee.novote(hostile[index].identity, view + 100));
                    hostile[index].same_round = false;
                    hostile[index].designated = false;
                }
                5 => {
                    for term in &mut hostile {
                        term.message = ViewMessage::NoVote(committee.novote(term.identity, view));
                        term.designated = false;
                    }
                }
                _ => {
                    let wrong = committee.signers[hostile[index].identity]
                        .sign_vote(body(committee, &alternate, schedule.next()))
                        .unwrap();
                    hostile[index].message = ViewMessage::Vote(Vote::new(
                        body(committee, leader, schedule.next()),
                        wrong.attestation().clone(),
                    ));
                    hostile[index].designated = true;
                    hostile[index].authentic = false;
                }
            }
            let expected = acceptable(
                &hostile,
                codec.view_quorum(),
                codec.designation_quorum(),
                codec.participants(),
            );
            assert_eq!(
                expected,
                mutation < 2,
                "oracle sensitivity for mutation {mutation}"
            );
            let hostile_messages: Vec<_> = hostile.into_iter().map(|term| term.message).collect();
            let assembled = committee.verifier.assemble_vqc::<Sha256, _>(
                leader.clone(),
                &hostile_messages,
                &Sequential,
            );
            assert_eq!(assembled.is_ok(), expected, "V-QC mutation {mutation}");
            if let Ok(certificate) = assembled {
                assert_eq!(
                    certificate, vqc,
                    "message order changes the canonical certificate"
                );
            }
        }

        let votes: Vec<_> = (0..codec.view_quorum())
            .map(|index| {
                committee.signers[(index + rotation) % codec.participants()]
                    .sign_vote(body(committee, leader, schedule.next()))
                    .unwrap()
            })
            .collect();
        let lqc = committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
            .unwrap();
        let mut duplicate = votes.clone();
        duplicate[0] = duplicate[1].clone();
        assert!(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.clone(), &duplicate, &Sequential)
                .is_err()
        );
        assert!(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(alternate.clone(), &votes, &Sequential)
                .is_err()
        );

        // Substituting a valid group element from another round keeps the artifact structurally
        // valid while proving that cached terms cannot manufacture an aggregate signature.
        let donor = committee.vqc(view + 100);
        let forged_vqc = Vqc::new(
            leader.clone(),
            vqc.tally().clone(),
            vqc.novoters().clone(),
            vqc.conflicting_votes().to_vec(),
            donor.signature().unwrap().clone(),
            codec,
        )
        .unwrap();
        let forged_lqc = Lqc::new(
            leader.clone(),
            lqc.tally().clone(),
            donor.signature().unwrap().clone(),
            codec,
        )
        .unwrap();
        let context_vqc = Vqc::new(
            alternate.clone(),
            vqc.tally().clone(),
            vqc.novoters().clone(),
            vqc.conflicting_votes().to_vec(),
            vqc.signature().unwrap().clone(),
            codec,
        )
        .unwrap();
        let context_lqc = Lqc::new(
            alternate,
            lqc.tally().clone(),
            lqc.signature().unwrap().clone(),
            codec,
        )
        .unwrap();
        let artifacts = [
            Unverified::Vqc(&vqc),
            Unverified::Lqc(&lqc),
            Unverified::Vqc(&forged_vqc),
            Unverified::Lqc(&forged_lqc),
            Unverified::Vqc(&context_vqc),
            Unverified::Lqc(&context_lqc),
        ];
        let expected = [true, true, false, false, false, false];
        assert_eq!(
            committee
                .verifier
                .verify_artifacts::<_, Sha256, _>(&mut rng, &artifacts, &Sequential),
            expected
        );

        let mut authenticated = messages.clone();
        authenticated.extend(votes.into_iter().map(ViewMessage::Vote));
        authenticated.extend(previous.iter().cloned());
        for message in &authenticated {
            assert!(match message {
                ViewMessage::Vote(vote) => committee.verifier.verify_vote(vote),
                ViewMessage::NoVote(vote) => committee.verifier.verify_novote(vote),
            });
        }
        for cache_mode in 0..4 {
            let mut cache: Vec<_> = authenticated
                .iter()
                .enumerate()
                .filter(|(index, _)| cache_mode != 1 || index % 2 == 0)
                .map(|(_, message)| known(message))
                .collect();
            match cache_mode {
                0 => cache.clear(),
                2 => {
                    cache.reverse();
                }
                3 => {
                    cache.extend(authenticated.iter().map(known));
                }
                _ => {}
            }
            let caches = vec![cache.as_slice(); artifacts.len()];
            assert_eq!(
                committee
                    .verifier
                    .verify_artifacts_with_known::<_, Sha256, _>(
                        &mut rng,
                        &artifacts,
                        &caches,
                        &Sequential
                    ),
                expected,
                "cache mode {cache_mode}"
            );
        }
        previous = authenticated;
        parent = Some(vqc);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn structured_artifact_campaign() {
        for seed in 0u8..12 {
            let input: Vec<_> = (0u8..96)
                .map(|offset| seed.wrapping_add(offset.wrapping_mul(37)))
                .collect();
            super::exercise(&input);
        }
    }
}
