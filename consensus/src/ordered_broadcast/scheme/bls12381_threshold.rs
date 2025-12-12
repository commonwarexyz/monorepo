//! BLS12-381 threshold implementation of the [`Scheme`] trait for `ordered_broadcast`.
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures
//! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
//! any `t` valid partial signatures can be used to forge a partial signature for any other player,
//! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
//! (as it must be sent by said participant) but can't be used by an external observer.

use crate::{ordered_broadcast::types::AckContext, scheme::impl_bls12381_threshold_scheme};

impl_bls12381_threshold_scheme!(AckContext<'a, P, D>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordered_broadcast::types::AckContext, scheme::Scheme as SchemeTrait, types::Epoch,
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
        let quorum = Scheme::<EdPublicKey, MinPk>::signer(
            Set::try_from_iter(validators.clone()).unwrap(),
            &polynomial,
            shares[0].clone(),
        )
        .unwrap()
        .participants()
        .quorum() as usize;
        let mut votes = Vec::new();
        for share in shares.iter().take(quorum) {
            let validator_scheme = Scheme::<EdPublicKey, MinPk>::signer(
                Set::try_from_iter(validators.clone()).unwrap(),
                &polynomial,
                share.clone(),
            )
            .unwrap();

            if let Some(vote) = SchemeTrait::sign_vote(&validator_scheme, b"test", ctx.clone()) {
                votes.push(vote);
            }
        }

        assert_eq!(votes.len(), quorum);

        // Create a verifier scheme (without a local share, just for verification)
        let scheme = Scheme::<EdPublicKey, MinPk>::verifier(
            Set::try_from_iter(validators).unwrap(),
            &polynomial,
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
