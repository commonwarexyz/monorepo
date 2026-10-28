//! Checkpoint certificates from a Multimmit committee.
//!
//! [`aggregation`](crate::aggregation) certifies checkpoints of a deterministic execution over
//! Multimmit's finalized stream, such as the state roots it commits to. [`Scheme`] lets the same
//! committee that runs consensus certify them, with the threshold key it already holds: the
//! `2f + 1` nullification sharing of an `n = 5f + 1` committee.
//!
//! A checkpoint only needs every certifying quorum to contain an honest validator, because
//! honest validators compute the same digest. Any `2f + 1` validators include at least `f + 1`
//! honest ones, so a certified digest is one an honest validator computed, and a divergent
//! validator is outvoted as long as at most `f` are faulty.
//!
//! # Keys
//!
//! [`checkpoint`](crate::multimmit::scheme::bls12381_threshold::Scheme::checkpoint) derives the
//! checkpoint [`Scheme`] from a Multimmit scheme: a signer signs with its nullification share, and
//! a verifier needs only the committee's nullification sharing or identity.
//!
//! The nullification share also signs Multimmit's nullify messages. Aggregation signs under its
//! own suffix of the namespace it is given, which differs from Multimmit's nullify suffix, so a
//! checkpoint signature never verifies as a nullify share, nor the reverse, whatever the base
//! namespaces.
//!
//! # Caveats
//!
//! Aggregation signatures do not cover the epoch, so a checkpoint certificate verifies under
//! every epoch that shares its nullification identity. A reshare keeps that identity, so this is
//! every epoch of the deployment. A consumer derives the expected epoch and position range from
//! authenticated history and checks them with
//! [`Certificate::verify_for`](crate::aggregation::types::Certificate::verify_for).
//!
//! Because a quorum is only `2f + 1`, a bug that makes `f + 1` honest validators compute the
//! same wrong digest, together with `f` faulty ones, certifies that digest, where an `n - f`
//! quorum would need `3f + 1` of them.

use crate::aggregation::types::{Item, Namespace};
use commonware_cryptography::impl_certificate_bls12381_threshold;
use commonware_utils::faults::N5f1Nullification;

impl_certificate_bls12381_threshold!(&'a Item<D>, Namespace, N5f1Nullification);

impl<D: commonware_cryptography::Digest, P: commonware_cryptography::PublicKey, V>
    crate::aggregation::scheme::Scheme<D> for Scheme<P, V>
where
    V: commonware_cryptography::bls12381::primitives::variant::Variant,
{
    fn recovery_namespace(&self) -> crate::aggregation::types::RecoveryNamespace {
        self.generic.namespace().recovery_namespace()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::types::{Ack, Certificate},
        multimmit::{mocks::Committee, types::PathLimits},
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinPk};
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults as _, non_empty, test_rng};

    #[test]
    fn committee_nullification_keys_certify_checkpoints() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CHECKPOINT_TEST";
        let committee = Committee::<MinPk>::builder(7, 6)
            .limits(PathLimits::new(1, 0).unwrap())
            .build();
        let schemes = committee
            .signers
            .iter()
            .map(|signer| signer.checkpoint(NAMESPACE))
            .collect::<Vec<_>>();
        let item = Item {
            position: Height::new(9),
            digest: Sha256::hash(&[b"state root"]),
        };
        let acks = schemes
            .iter()
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect::<Vec<_>>();

        // Of six validators, 2f + 1 = 3 certify and two do not.
        let quorum = N5f1Nullification::quorum(schemes.len()) as usize;
        assert_eq!(quorum, 3);
        let below = &acks[..quorum - 1];
        assert!(
            Certificate::from_acks(&schemes[0], Epoch::zero(), non_empty![@below], &Sequential)
                .is_err()
        );
        let quorum = &acks[..quorum];
        let certificate =
            Certificate::from_acks(&schemes[0], Epoch::zero(), non_empty![@quorum], &Sequential)
                .unwrap();

        // A full verifier checks shares, and anyone with the nullification identity checks the
        // certificate, but only under the same namespace.
        let verifier = committee.verifier.checkpoint(NAMESPACE);
        assert!(acks[0].verify(&mut test_rng(), &verifier, &Sequential));
        assert!(certificate.verify_for(
            &mut test_rng(),
            &verifier,
            Epoch::zero(),
            Height::zero(),
            Height::new(100),
            &Sequential
        ));
        let identity = *committee.verifier.nullification_identity();
        let observer = Scheme::<_, MinPk>::certificate_verifier(NAMESPACE, identity);
        assert!(certificate.verify_for(
            &mut test_rng(),
            &observer,
            Epoch::zero(),
            Height::zero(),
            Height::new(100),
            &Sequential
        ));
        let other = Scheme::<_, MinPk>::certificate_verifier(b"other", identity);
        assert!(!certificate.verify_for(
            &mut test_rng(),
            &other,
            Epoch::zero(),
            Height::zero(),
            Height::new(100),
            &Sequential
        ));
    }
}
