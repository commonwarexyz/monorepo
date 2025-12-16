//! Ed25519 implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.

use crate::{
    simplex::{scheme::SeededScheme, types::Subject},
    types::Round,
};
use commonware_cryptography::impl_certificate_ed25519;

impl_certificate_ed25519!(Subject<'a, D>);

impl SeededScheme for Scheme {
    type Seed = ();

    fn seed(&self, _: Round, _: &Self::Certificate) -> Option<Self::Seed> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        simplex::{
            scheme::{ed25519, SeededScheme},
            types::Subject,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, Scheme as _},
        sha256::Digest as Sha256Digest,
    };
    use commonware_utils::quorum_from_slice;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_seed_returns_none() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 4);

        let quorum = quorum_from_slice(&schemes) as usize;

        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(
                    b"test",
                    Subject::Nullify {
                        round: Round::new(Epoch::new(1), View::new(1)),
                    },
                )
                .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble(attestations).unwrap();

        let round = Round::new(Epoch::new(1), View::new(1));
        assert!(schemes[0].seed(round, &certificate).is_none());
    }
}
