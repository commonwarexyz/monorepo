//! BLS12-381 threshold signature scheme for ordered broadcast.

use crate::{ordered_broadcast::types::AckContext, signing_scheme::impl_bls12381_threshold_scheme};

impl_bls12381_threshold_scheme!(AckContext<'a, P, D>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordered_broadcast::types::AckContext, signing_scheme::Scheme as SchemeTrait, types::Epoch,
    };
    use commonware_cryptography::{
        bls12381::{dkg, primitives::variant::MinPk},
        ed25519::{PrivateKey, PublicKey as EdPublicKey},
        sha256::Sha256,
        Hasher as _, PrivateKeyExt as _, Signer as _,
    };
    use commonware_utils::{
        ordered::{Quorum, Set},
        TryFromIterator, NZU32,
    };
    use rand::SeedableRng;

    #[test]
    fn test_bls_threshold_sign_verify() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        // Create 5 validator identities
        let validators: Vec<EdPublicKey> = (0..5)
            .map(|_| PrivateKey::from_rng(&mut rng).public_key())
            .collect();

        // Create BLS threshold setup (4-of-5)
        let (polynomial, shares) = dkg::deal_anonymous::<MinPk>(&mut rng, NZU32!(5));

        // Create a chunk to sign
        let chunk = super::super::super::types::Chunk::new(
            validators[0].clone(),
            42,
            Sha256::hash(b"test payload"),
        );
        let epoch = Epoch::new(1);

        // Create context
        let ctx = AckContext {
            chunk: &chunk,
            epoch,
        };

        // Sign with quorum-of-validators (each needs their own scheme instance)
        let quorum = Scheme::<EdPublicKey, MinPk>::new(
            Set::try_from_iter(validators.clone()).unwrap(),
            &polynomial,
            shares[0].clone(),
        )
        .participants()
        .quorum() as usize;
        let mut votes = Vec::new();
        for share in shares.iter().take(quorum) {
            let validator_scheme = Scheme::<EdPublicKey, MinPk>::new(
                Set::try_from_iter(validators.clone()).unwrap(),
                &polynomial,
                share.clone(),
            );

            if let Some(vote) = SchemeTrait::sign_vote(&validator_scheme, b"test", ctx.clone()) {
                votes.push(vote);
            }
        }

        assert_eq!(votes.len(), quorum);

        // Create a verifier scheme (without a local share, just for verification)
        let scheme = Scheme::<EdPublicKey, MinPk>::new(
            Set::try_from_iter(validators).unwrap(),
            &polynomial,
            shares[0].clone(),
        );

        // Assemble certificate
        let certificate = scheme
            .assemble_certificate(votes.iter().cloned())
            .expect("should assemble certificate");

        // Verify certificate
        assert!(SchemeTrait::verify_certificate(
            &scheme,
            &mut rng,
            b"test",
            ctx,
            &certificate
        ));
    }
}
