//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be
//! used by an external observer as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside an aggregated signature,
//! enabling secure per-validator activity tracking and conflict detection.

use crate::{
    scheme::impl_bls12381_multisig_scheme,
    simplex::{scheme::SeededScheme, types::Subject},
    types::Round,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};

impl_bls12381_multisig_scheme!(Subject<'a, D>);

impl<P: PublicKey, V: Variant + Send + Sync> SeededScheme for Scheme<P, V> {
    type Seed = ();

    fn seed(&self, _: Round, _: &Self::Certificate) -> Option<Self::Seed> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        scheme::Scheme as _,
        simplex::{
            mocks::fixtures::{bls12381_multisig, Fixture},
            scheme::SeededScheme,
            types::Subject,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig, Variant},
        sha256::Digest as Sha256Digest,
    };
    use commonware_utils::quorum_from_slice;
    use rand::{rngs::StdRng, SeedableRng};

    fn test_seed_returns_none<V: Variant + Send + Sync>() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = bls12381_multisig::<V, _>(&mut rng, 4);

        let quorum = quorum_from_slice(&schemes) as usize;

        // Create a certificate for testing
        let signatures: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign_vote::<Sha256Digest>(
                    b"test",
                    Subject::Nullify {
                        round: Round::new(Epoch::new(1), View::new(1)),
                    },
                )
                .unwrap()
            })
            .collect();

        let certificate = schemes[0].assemble_certificate(signatures).unwrap();

        let round = Round::new(Epoch::new(1), View::new(1));
        assert!(schemes[0].seed(round, &certificate).is_none());
    }

    #[test]
    fn test_seed_returns_none_variants() {
        test_seed_returns_none::<MinPk>();
        test_seed_returns_none::<MinSig>();
    }
}
