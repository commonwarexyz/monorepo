//! BLS12-381 threshold signature scheme for ordered broadcast.

use crate::signing_scheme::bls12381_threshold as raw;
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_utils::set::Ordered;

/// BLS12-381 threshold signature scheme for ordered broadcast.
#[derive(Clone, Debug)]
pub struct Bls12381Threshold<P: PublicKey, V: Variant> {
    /// Ordered set of participant public keys.
    pub participants: Ordered<P>,
    /// Raw BLS12-381 threshold implementation.
    pub raw: raw::Bls12381Threshold<V>,
}

impl<P: PublicKey, V: Variant> Bls12381Threshold<P, V> {
    /// Creates a new scheme with participants and the raw threshold implementation.
    pub fn new(participants: Ordered<P>, raw: raw::Bls12381Threshold<V>) -> Self {
        Self { participants, raw }
    }
}

use super::super::types::AckContext;

crate::impl_scheme_trait! {
    impl[P, V] Scheme for Bls12381Threshold<P, V>
    where [
        P: PublicKey,
        V: Variant + Send + Sync,
    ]
    {
        Context<'a, D> = [ AckContext<'a, P, D> ],
        PublicKey = P,
        Signature = V::Signature,
        Certificate = V::Signature,
        raw = raw,
        participants = participants,
        is_attributable = false,
        codec_config = (),
        codec_config_unbounded = (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ordered_broadcast::types::AckContext, signing_scheme::Scheme};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{group::Share, poly, variant::MinPk},
        },
        ed25519::{PrivateKey, PublicKey as EdPublicKey},
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _, PrivateKeyExt as _, Signer as _,
    };
    use commonware_utils::set::Ordered;
    use rand::SeedableRng;

    #[test]
    fn test_bls_threshold_sign_verify() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        // Create 5 validator identities
        let validators: Vec<EdPublicKey> = (0..5)
            .map(|_| PrivateKey::from_rng(&mut rng).public_key())
            .collect();

        // Create BLS threshold setup (3-of-5)
        let quorum = 3;
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut rng, None, 5, quorum);

        // Evaluate polynomial and get identity
        let evaluated = ops::evaluate_all::<MinPk>(&polynomial, 5);
        let identity = *poly::public::<MinPk>(&polynomial);

        // Create a chunk to sign
        let chunk = super::super::super::types::Chunk::new(
            validators[0].clone(),
            42,
            Sha256::hash(b"test payload"),
        );
        let epoch = 1;

        // Create context
        let ctx = AckContext {
            chunk: &chunk,
            epoch: &epoch,
        };

        // Sign with first 3 validators (each needs their own scheme instance)
        let mut votes = Vec::new();
        for i in 0..3 {
            let raw_scheme = raw::Bls12381Threshold::<MinPk>::new(
                identity.clone(),
                evaluated.clone(),
                shares[i].clone(),
                quorum,
            );
            let validator_scheme =
                Bls12381Threshold::new(Ordered::from_iter(validators.clone()), raw_scheme);

            if let Some(vote) = validator_scheme.sign_vote::<Sha256Digest>(b"test", ctx.clone()) {
                votes.push(vote);
            }
        }

        assert_eq!(votes.len(), 3);

        // Create a verifier scheme (without a local share, just for verification)
        let raw_scheme =
            raw::Bls12381Threshold::<MinPk>::new(identity, evaluated, shares[0].clone(), quorum);
        let scheme = Bls12381Threshold::new(Ordered::from_iter(validators), raw_scheme);

        // Assemble certificate
        let certificate = scheme
            .assemble_certificate(votes.iter().cloned())
            .expect("should assemble certificate");

        // Verify certificate
        assert!(scheme.verify_certificate::<_, Sha256Digest>(&mut rng, b"test", ctx, &certificate));
    }
}
