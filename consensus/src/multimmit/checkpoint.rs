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
//! every epoch that reuses the same nullification key. And because a quorum is only `2f + 1`, a
//! bug that makes `f + 1` honest validators compute the same wrong digest, together with `f`
//! faulty ones, certifies that digest, where an `n - f` quorum would need `3f + 1` of them.

use crate::aggregation::types::{Item, Namespace};
use commonware_cryptography::impl_certificate_bls12381_threshold;
use commonware_utils::{Faults, N5f1};
use num_traits::ToPrimitive;

/// Multimmit's fault model with the nullification quorum: `n = 5f + 1` validators tolerate `f`
/// faults, and `2f + 1` of them certify.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NullificationQuorum;

impl Faults for NullificationQuorum {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        N5f1::max_faults(n)
    }

    fn quorum(n: impl ToPrimitive) -> u32 {
        N5f1::nullification_quorum(n)
    }
}

impl_certificate_bls12381_threshold!(&'a Item<D>, Namespace, NullificationQuorum);

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
    use commonware_utils::{non_empty, test_rng};

    #[test]
    fn quorum_is_two_faults_plus_one() {
        for (n, faults, quorum) in [(6, 1, 3), (11, 2, 5), (16, 3, 7), (50, 9, 19)] {
            assert_eq!(NullificationQuorum::max_faults(n), faults);
            assert_eq!(NullificationQuorum::quorum(n), quorum);
        }
    }

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
            height: Height::new(9),
            digest: Sha256::hash(&[b"state root"]),
        };
        let acks = schemes
            .iter()
            .map(|scheme| Ack::sign(scheme, Epoch::zero(), item.clone()).unwrap())
            .collect::<Vec<_>>();

        // Of six validators, 2f + 1 = 3 certify and two do not.
        let quorum = NullificationQuorum::quorum(schemes.len()) as usize;
        assert_eq!(quorum, 3);
        let below = &acks[..quorum - 1];
        assert!(Certificate::from_acks(&schemes[0], non_empty![@below], &Sequential).is_err());
        let quorum = &acks[..quorum];
        let certificate =
            Certificate::from_acks(&schemes[0], non_empty![@quorum], &Sequential).unwrap();

        // A full verifier checks shares, and anyone with the nullification identity checks the
        // certificate, but only under the same namespace.
        let verifier = committee.verifier.checkpoint(NAMESPACE);
        assert!(acks[0].verify(&mut test_rng(), &verifier, &Sequential));
        assert!(certificate.verify(&mut test_rng(), &verifier, &Sequential));
        let identity = *committee.verifier.nullification_identity();
        let observer = Scheme::<_, MinPk>::certificate_verifier(NAMESPACE, identity);
        assert!(certificate.verify(&mut test_rng(), &observer, &Sequential));
        let other = Scheme::<_, MinPk>::certificate_verifier(b"other", identity);
        assert!(!certificate.verify(&mut test_rng(), &other, &Sequential));
    }
}
