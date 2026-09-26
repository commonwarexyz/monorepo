//! Size limits for the messages [simplex](super) sends.

use super::scheme::Scheme;
use commonware_codec::{
    FixedSize,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_cryptography::Digest;
use commonware_p2p::Footprint;
use commonware_resolver::p2p::MAX_MESSAGE_OVERHEAD;
use commonware_utils::Widen;

/// Largest payloads simplex sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    vote: usize,
    response: usize,
}

impl Limits {
    /// Returns the limits for committees of at most `participants` under `S` with payload
    /// digest `D`.
    ///
    /// # Panics
    ///
    /// Panics if `S` cannot bound certificates for `participants` participants or a bound
    /// overflows `usize`.
    pub fn new<S: Scheme<D>, D: Digest>(participants: usize) -> Self {
        // Notarize and Finalize messages carry a proposal (round, parent view, and payload).
        // Nullify messages carry only a round (epoch and view), which is smaller.
        let proposal = D::SIZE.checked_add(3 * MAX_U64_VARINT_SIZE);

        // A vote is a tag, a proposal, and an attestation (signer and signature)
        let vote = proposal
            .and_then(|size| size.checked_add(u8::SIZE + MAX_U32_VARINT_SIZE))
            .and_then(|size| size.checked_add(S::Signature::SIZE))
            .expect("vote size overflow");

        // A certificate is a tag, a proposal, and a scheme certificate
        let signatures = S::certificate_max_size(participants)
            .expect("scheme cannot bound certificates for participants");
        let certificate = proposal
            .and_then(|size| size.checked_add(u8::SIZE))
            .and_then(|size| size.checked_add(signatures))
            .expect("certificate size overflow");

        // A resolver response is a certificate and resolver framing
        let response = certificate
            .checked_add(Widen::widen(MAX_MESSAGE_OVERHEAD))
            .expect("response size overflow");

        Self { vote, response }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.vote.max(self.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
                Nullify, Proposal, Vote,
            },
        },
        types::{Epoch, Participant, Round, View},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::{Attestation, mocks::Fixture},
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_LIMITS";

    /// Asserts that the widest message of each kind encodes to exactly its limit.
    fn check<S: Scheme<Sha256Digest>>(fixture: Fixture<S>) {
        let schemes = fixture.schemes;
        let limits = Limits::new::<S, Sha256Digest>(schemes.len());

        // Widen every varint
        let round = Round::new(Epoch::new(u64::MAX), View::new(u64::MAX));
        let proposal = Proposal::new(
            round,
            View::new(u64::MAX - 1),
            Sha256Digest::random(test_rng()),
        );
        let widest = |attestation: &Attestation<S>| Attestation::<S> {
            signer: Participant::new(u32::MAX),
            signature: attestation.signature.clone(),
        };

        // Sign with every participant
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        // The largest vote has the widest signer
        let votes = [
            Vote::Notarize(Notarize {
                proposal: proposal.clone(),
                attestation: widest(&notarizes[0].attestation),
            }),
            Vote::Nullify(Nullify {
                round,
                attestation: widest(&nullifies[0].attestation),
            }),
            Vote::Finalize(Finalize {
                proposal,
                attestation: widest(&finalizes[0].attestation),
            }),
        ];
        let sizes = votes.map(|vote| vote.encode().len());
        assert_eq!(sizes.into_iter().max(), Some(limits.vote));

        // The largest resolver response carries a certificate with every signer
        let certificates = [
            Certificate::Notarization(
                Notarization::from_notarizes(&schemes[0], non_empty![@&notarizes], &Sequential)
                    .unwrap(),
            ),
            Certificate::Nullification(
                Nullification::from_nullifies(&schemes[0], non_empty![@&nullifies], &Sequential)
                    .unwrap(),
            ),
            Certificate::Finalization(
                Finalization::from_finalizes(&schemes[0], non_empty![@&finalizes], &Sequential)
                    .unwrap(),
            ),
        ];
        let overhead: usize = Widen::widen(MAX_MESSAGE_OVERHEAD);
        let sizes = certificates.map(|certificate| certificate.encode().len() + overhead);
        assert_eq!(sizes.into_iter().max(), Some(limits.response));

        // Resolver responses dominate
        assert!(limits.vote < limits.response);
        assert_eq!(limits.footprint(), limits.response);
    }

    #[test]
    fn test_limits_ed25519() {
        for participants in [1, 4, 127, 128] {
            check(ed25519::fixture(&mut test_rng(), NAMESPACE, participants));
        }
    }

    #[test]
    #[should_panic(expected = "scheme cannot bound certificates for participants")]
    fn test_limits_unbounded_certificate() {
        Limits::new::<ed25519::Scheme, Sha256Digest>(Widen::<usize>::widen(u32::MAX) + 1);
    }
}
