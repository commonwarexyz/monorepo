//! Execute one machine-issued verification job with the concrete Multimmit scheme.
//!
//! Every item joins one batched signature verification, so an invalid item cannot fail a valid
//! neighbor. A vote update is checked over the full content the machine rebuilt for it, which is
//! exactly the content the machine will count. Checks that need a certificate's parent chain
//! belong to the machine, which also rejects any completion whose generation, cardinality, or
//! ticket order does not match its job.

use crate::multimmit::{
    machine::{Verdict, VerificationCompletion, VerificationItem, VerifyJob},
    scheme::bls12381::{Scheme, Signed},
    types::Artifact,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// Executes `job` and returns one verdict per item, in item order.
pub(crate) fn verify<H, P, V>(
    job: &VerifyJob<V, H::Digest>,
    rng: &mut impl CryptoRng,
    scheme: &Scheme<P, V>,
    strategy: &impl Strategy,
) -> VerificationCompletion<H::Digest>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let items = job.items();
    let mut owners = Vec::with_capacity(items.len());
    let mut signed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if let Some(subject) = subject(item) {
            owners.push(index);
            signed.push(subject);
        }
    }
    let mut valid = vec![false; items.len()];
    let verdicts = scheme.verify_batch::<_, H, _>(rng, &signed, strategy);
    for (owner, verdict) in owners.into_iter().zip(verdicts) {
        valid[owner] = verdict.is_valid();
    }
    let verdicts = items
        .iter()
        .zip(valid)
        .map(|(item, valid)| Verdict::new(item.ticket(), valid))
        .collect();
    VerificationCompletion::new(job.issued(), verdicts)
}

/// Returns the signed subject of `item`, or `None` for a vote update without rebuilt content,
/// which has nothing its signature can be checked against.
fn subject<V: Variant, D: Digest>(item: &VerificationItem<V, D>) -> Option<Signed<'_, V, D>> {
    Some(match item.artifact() {
        Artifact::TransactionBlock(block) => Signed::TransactionBlock(block),
        Artifact::LeaderBlock(block) => Signed::LeaderBlock(block),
        Artifact::Update(update) => Signed::Vote {
            content: item.content()?,
            attestation: update.attestation(),
        },
        Artifact::Vqc(certificate) => Signed::Vqc(certificate),
        Artifact::Lqc(certificate) => Signed::Lqc(certificate),
        Artifact::Floor(floor) => Signed::Lqc(floor.lqc()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            machine::{Generation, Issued, JobId, Observation, VerificationTicket},
            mocks::Committee,
        },
        types::{Participant, View},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::sync::Arc;

    fn ticket(
        artifact: &Artifact<MinPk, Sha256Digest>,
        index: u32,
    ) -> VerificationTicket<Sha256Digest> {
        VerificationTicket::new(
            JobId::new(1),
            artifact.id::<Sha256>(),
            Observation::new(1, index),
        )
    }

    #[test]
    fn updates_verify_over_their_rebuilt_content() {
        let committee = Committee::<MinPk>::builder(11, 6).build();
        let endorsement = committee.genesis_endorsement();
        let content = committee.content(View::new(1), None, false, endorsement.clone());
        let other = committee.content(View::new(1), None, true, endorsement);
        let update = Arc::new(Artifact::Update(committee.update(
            Participant::new(0),
            &content,
            committee.genesis().tips(),
            1,
        )));
        let certificate = Arc::new(Artifact::Vqc(committee.vqc(View::new(1))));
        let items = vec![
            VerificationItem::update(ticket(&update, 0), Arc::clone(&update), Arc::new(content)),
            VerificationItem::update(ticket(&update, 1), Arc::clone(&update), Arc::new(other)),
            VerificationItem::new(ticket(&update, 2), Arc::clone(&update)),
            VerificationItem::new(ticket(&certificate, 3), certificate),
        ];
        let job = VerifyJob::new(Issued::new(JobId::new(1), Generation::new(0)), items);

        let completion =
            verify::<Sha256, _, _>(&job, &mut test_rng(), &committee.verifier, &Sequential);

        assert_eq!(completion.issued(), job.issued());
        let tickets = completion
            .verdicts()
            .iter()
            .map(|verdict| verdict.ticket())
            .collect::<Vec<_>>();
        let expected = job
            .items()
            .iter()
            .map(VerificationItem::ticket)
            .collect::<Vec<_>>();
        assert_eq!(tickets, expected);
        let valid = completion
            .verdicts()
            .iter()
            .map(|verdict| verdict.valid())
            .collect::<Vec<_>>();
        // Signed content, content the signer never signed, no rebuilt content, a certificate.
        assert_eq!(valid, [true, false, false, true]);
    }
}
