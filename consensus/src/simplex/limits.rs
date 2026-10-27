//! Size limits for the payloads [simplex](super) sends.

use super::{
    scheme::Scheme,
    types::{Certificate, Vote},
};
use commonware_codec::{Footprint, MaxEncodeSize};
use commonware_cryptography::Digest;
use commonware_resolver::p2p::message_size;
use commonware_utils::sequence::U64;

/// Largest payloads simplex sends, as [message sizes](super#message-sizes) draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest vote, certificate, or resolver message, with every varint at its widest.
    message: usize,
}

impl Limits {
    /// Returns the limits for committees of at most `participants` under `S` with payload digest
    /// `D`.
    ///
    /// # Panics
    ///
    /// Panics if `S` cannot bound certificates for a committee of `participants`, if the widest
    /// certificate exceeds the `u32::MAX` bytes a resolver response carries, or if a bound
    /// overflows `usize`.
    pub fn new<S: Scheme<D>, D: Digest>(participants: usize) -> Self {
        // Vote and certificate payloads carry no framing. The resolver requests a certificate by
        // view and carries one as a response value.
        let certificate = Certificate::<S, D>::max_encode_size(participants)
            .expect("scheme must bound certificates for participants");
        let resolver =
            message_size::<U64>(certificate).expect("certificate must fit in a resolver response");
        Self {
            message: Vote::<S, D>::MAX_ENCODE_SIZE.max(certificate).max(resolver),
        }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{
                Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
                Nullify, Proposal, Vote,
            },
        },
        types::{Epoch, Participant, Round, View},
    };
    use commonware_codec::{Encode, MaxEncodeSize};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Attestation, mocks::Fixture},
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p::{MAX_RESPONSE_OVERHEAD, REQUEST_OVERHEAD};
    use commonware_utils::{Widen, non_empty, test_rng};

    /// Signing namespace for the votes and certificates these tests build.
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_SIMPLEX_LIMITS";

    /// Committee sizes for schemes whose certificates grow with the committee. Committees of 127
    /// and 128 sit on either side of the one-byte varint limit on a signature list's length.
    const PARTICIPANTS: [u32; 4] = [1, 4, 127, 128];

    /// Asserts that the widest message of each kind encodes to exactly its limit.
    fn check<S: Scheme<Sha256Digest>>(fixture: Fixture<S>) {
        let schemes = fixture.schemes;
        let limits = Limits::new::<S, Sha256Digest>(schemes.len());

        // Widen every varint.
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

        // Sign with every participant.
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

        // The largest vote has the widest signer.
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
        let vote = sizes.into_iter().max().unwrap();
        assert_eq!(vote, Vote::<S, Sha256Digest>::MAX_ENCODE_SIZE);

        // The largest certificate has every signer. A resolver response carrying it outsizes both
        // the largest vote and a request for the largest view, so it sets the footprint.
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
        let sizes = certificates.map(|certificate| certificate.encode().len());
        let certificate = sizes.into_iter().max().unwrap();
        assert_eq!(
            Some(certificate),
            Certificate::<S, Sha256Digest>::max_encode_size(schemes.len())
        );
        let request = U64::from(u64::MAX).encode().len() + REQUEST_OVERHEAD;
        let response = certificate + MAX_RESPONSE_OVERHEAD;
        assert!(vote < response && request < response);
        assert_eq!(limits.footprint(), response);
    }

    #[test]
    fn test_limits_ed25519() {
        for participants in PARTICIPANTS {
            check(ed25519::fixture(&mut test_rng(), NAMESPACE, participants));
        }
    }

    #[test]
    fn test_limits_secp256r1() {
        for participants in PARTICIPANTS {
            check(secp256r1::fixture(&mut test_rng(), NAMESPACE, participants));
        }
    }

    #[test]
    fn test_limits_bls12381_multisig() {
        for participants in PARTICIPANTS {
            check(bls12381_multisig::fixture::<MinPk, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
            check(bls12381_multisig::fixture::<MinSig, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
        }
    }

    #[test]
    fn test_limits_bls12381_threshold() {
        // A threshold certificate has one size for every committee.
        for participants in [4, 33] {
            check(bls12381_threshold::standard::fixture::<MinPk, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
            check(bls12381_threshold::standard::fixture::<MinSig, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
            check(bls12381_threshold::vrf::fixture::<MinPk, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
            check(bls12381_threshold::vrf::fixture::<MinSig, _>(
                &mut test_rng(),
                NAMESPACE,
                participants,
            ));
        }
    }

    #[test]
    #[should_panic(expected = "scheme must bound certificates for participants")]
    fn test_limits_unbounded_certificate() {
        Limits::new::<ed25519::Scheme, Sha256Digest>(Widen::<usize>::widen(u32::MAX) + 1);
    }
}
