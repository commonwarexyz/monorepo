//! Structured certificate assembly and verification with real signatures and adversarial vote
//! mixes.

use crate::{
    multimmit::{
        mocks::Committee,
        scheme::bls12381::{SignatureVerification, Signed, Verdict},
        types::{Attestation, BlockRef, ChainId, ChainSet, Lqc, VoteContent, Vqc},
    },
    types::{Height, Participant, View},
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
    static MIN_PK: Committee<MinPk> = Committee::builder(914, 6).build();
    static MIN_SIG: Committee<MinSig> = Committee::builder(914, 6).build();
}

/// Runs one campaign driven by `input`.
pub(crate) fn exercise(input: &[u8]) {
    let mut schedule = Schedule {
        bytes: input,
        cursor: 0,
    };
    if schedule.next() & 1 == 0 {
        MIN_PK.with(|committee| campaign(committee, &mut schedule));
    } else {
        MIN_SIG.with(|committee| campaign(committee, &mut schedule));
    }
}

/// Reads input bytes in order, then zeros.
struct Schedule<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl Schedule<'_> {
    fn next(&mut self) -> usize {
        let byte = self.bytes.get(self.cursor).copied().unwrap_or(0);
        self.cursor += 1;
        usize::from(byte)
    }
}

/// One attested vote with the facts the oracle judges it by, tracked independently of tally
/// reconstruction and signature verification.
#[derive(Clone)]
struct Term {
    content: VoteContent<Digest>,
    attestation_signer: Participant,
    view: View,
    final_: bool,
    authentic: bool,
}

/// Returns whether `terms` must assemble into a certificate of `view`.
fn acceptable(terms: &[Term], view: View, quorum: usize, require_final: bool) -> bool {
    let signers: BTreeSet<_> = terms.iter().map(|term| term.attestation_signer).collect();
    terms.len() == quorum
        && signers.len() == terms.len()
        && terms
            .iter()
            .all(|term| term.view == view && term.authentic && (term.final_ || !require_final))
}

/// Returns a content in `view` that varies one chain's tip and declaration with `marker`.
fn content<V: Variant>(
    committee: &Committee<V>,
    view: View,
    leader: Option<Digest>,
    final_: bool,
    marker: usize,
) -> VoteContent<Digest> {
    let chains = committee.codec().chains();
    let chain = ChainId::new((marker % chains) as u32);
    let mut tips = committee.genesis().tips().to_vec();
    let height = (marker / chains) % 3;
    if height > 0 {
        tips[chain.index()] = BlockRef::new(
            chain,
            Height::new(height as u64),
            Sha256::hash(&[&marker.to_le_bytes()]),
        );
    }
    let declared = if marker % 2 == 1 {
        ChainSet::from_chains(chains, [chain]).expect("chain is in range")
    } else {
        ChainSet::empty(chains)
    };
    committee.content(view, leader, final_, committee.endorsement(declared, tips))
}

fn campaign<V: Variant>(committee: &Committee<V>, schedule: &mut Schedule<'_>) {
    let codec = committee.codec();
    let quorum = codec.view_quorum();
    let mut rng = TestRng::new(971);
    let view = View::new(1 + (schedule.next() % 3) as u64);
    let leader = committee.leader_block(view).block().clone();
    let digest = leader.digest::<Sha256>();
    let rotation = schedule.next() % codec.participants();

    let sign = |terms: &[Term]| -> Vec<(VoteContent<Digest>, Attestation<V>)> {
        terms
            .iter()
            .map(|term| {
                // An inauthentic attestation is the signer's signature over the same content in
                // another view.
                let signed = if term.authentic {
                    term.content.clone()
                } else {
                    committee.content(
                        View::new(term.view.get() + 100),
                        term.content.leader(),
                        term.content.is_final(),
                        term.content.endorsement().clone(),
                    )
                };
                let attestation = committee.sign_vote(term.attestation_signer, &signed);
                (term.content.clone(), attestation)
            })
            .collect()
    };
    let assemble_vqc = |terms: &[Term], rng: &mut TestRng| {
        committee.verifier.assemble_vqc(
            rng,
            committee.genesis().vqc(),
            &sign(terms),
            Vec::new(),
            SignatureVerification::Checked,
            &Sequential,
        )
    };
    let assemble_lqc = |terms: &[Term], rng: &mut TestRng| {
        committee.verifier.assemble_lqc::<_, Sha256, _>(
            rng,
            leader.clone(),
            &sign(terms),
            SignatureVerification::Checked,
            &Sequential,
        )
    };

    // Final votes of the view, a designated majority for the leader and the rest for none.
    let finals: Vec<_> = (0..quorum)
        .map(|index| {
            let target = (index < codec.designation_quorum()).then_some(digest);
            Term {
                content: content(committee, view, target, true, schedule.next()),
                attestation_signer: Participant::from_usize(
                    (index + rotation) % codec.participants(),
                ),
                view,
                final_: true,
                authentic: true,
            }
        })
        .collect();
    let vqc = assemble_vqc(&finals, &mut rng).expect("authentic finals assemble");
    assert!(committee.verifier.verify_vqc(&mut rng, &vqc, &Sequential));

    // Votes for the leader block, final or not.
    let votes: Vec<_> = (0..quorum)
        .map(|index| {
            let final_ = schedule.next().is_multiple_of(2);
            Term {
                content: content(committee, view, Some(digest), final_, schedule.next()),
                attestation_signer: Participant::from_usize(
                    (index + rotation) % codec.participants(),
                ),
                view,
                final_,
                authentic: true,
            }
        })
        .collect();
    let lqc = assemble_lqc(&votes, &mut rng).expect("authentic votes assemble");
    assert!(
        committee
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut rng, &lqc, &Sequential)
    );

    // Each mutation either keeps the transcript (reordering) or breaks exactly one condition.
    for mutation in 0..6 {
        for (terms, require_final) in [(&finals, true), (&votes, false)] {
            let mut hostile = terms.clone();
            let index = schedule.next() % hostile.len();
            match mutation {
                0 => hostile.rotate_left(index),
                1 => hostile.reverse(),
                2 => {
                    let other = (index + 1) % hostile.len();
                    hostile[index].attestation_signer = hostile[other].attestation_signer;
                }
                3 => {
                    hostile.truncate(quorum - 1);
                }
                4 => {
                    hostile[index].authentic = false;
                }
                _ => {
                    let term = &mut hostile[index];
                    term.final_ = !term.final_;
                    term.content = committee.content(
                        view,
                        term.content.leader(),
                        term.final_,
                        term.content.endorsement().clone(),
                    );
                    if !require_final {
                        // Finality is free in an L-QC, so move the vote to another view instead.
                        let shifted = View::new(view.get() + 1);
                        term.view = shifted;
                        term.content = committee.content(
                            shifted,
                            term.content.leader(),
                            term.final_,
                            term.content.endorsement().clone(),
                        );
                    }
                }
            }
            let expected = acceptable(&hostile, view, quorum, require_final);
            assert_eq!(
                expected,
                mutation < 2,
                "oracle sensitivity for mutation {mutation}"
            );
            if require_final {
                let assembled = assemble_vqc(&hostile, &mut rng);
                assert_eq!(assembled.is_ok(), expected, "V-QC mutation {mutation}");
                if let Ok(certificate) = assembled {
                    assert_eq!(certificate, vqc, "vote order changes the canonical V-QC");
                }
            } else {
                let assembled = assemble_lqc(&hostile, &mut rng);
                assert_eq!(assembled.is_ok(), expected, "L-QC mutation {mutation}");
                if let Ok(certificate) = assembled {
                    assert_eq!(certificate, lqc, "vote order changes the canonical L-QC");
                }
            }
        }
    }

    // A valid group element from another certificate keeps an artifact structurally valid but
    // never authenticates it, and a batch isolates the forgeries.
    let donor = committee.vqc(View::new(view.get() + 100));
    let donor = donor.signature().expect("donor signature decodes").clone();
    let forged_vqc = Vqc::new(
        vqc.round(),
        vqc.parent(),
        vqc.tally().clone(),
        donor.clone(),
        codec,
    )
    .expect("forged V-QC is structurally valid");
    let forged_lqc = Lqc::new(lqc.leader().clone(), lqc.tally().clone(), donor);
    let items = [
        Signed::Vqc(&vqc),
        Signed::Lqc(&lqc),
        Signed::Vqc(&forged_vqc),
        Signed::Lqc(&forged_lqc),
    ];
    let verdicts = committee
        .verifier
        .verify_batch::<_, Sha256, _>(&mut rng, &items, &Sequential);
    assert_eq!(verdicts[0], Verdict::Certificate(vqc.contents()));
    assert_eq!(verdicts[1], Verdict::Certificate(lqc.contents::<Sha256>()));
    assert_eq!(verdicts[2], Verdict::Invalid);
    assert_eq!(verdicts[3], Verdict::Invalid);
}

#[cfg(test)]
mod tests {
    #[test]
    fn structured_certificate_campaign() {
        for seed in 0u8..12 {
            let input: Vec<_> = (0u8..96)
                .map(|offset| seed.wrapping_add(offset.wrapping_mul(37)))
                .collect();
            super::exercise(&input);
        }
    }
}
