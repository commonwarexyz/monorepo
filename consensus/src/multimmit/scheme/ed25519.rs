//! Ed25519 keys for every role.
//!
//! Each participant's identity key signs for all three roles, each under its own namespace.
//! Aggregates and certificates list one signature per signer, so they grow linearly with the
//! committee but need no key registration proofs, trusted dealer, or pairing-friendly curve.
//! Ed25519 signatures are batch verified.

use super::{DaCertificateOf, Error, Generic};
use crate::multimmit::config::Parameters;
use commonware_cryptography::ed25519 as keys;
use commonware_utils::ordered::Set;
use std::sync::Arc;

/// Ed25519 ordinary keys over [`OrdinarySubject`](super::OrdinarySubject)s.
pub mod ordinary {
    use crate::multimmit::scheme::{Namespace, OrdinarySubject};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::N5f1;

    impl_certificate_ed25519!(OrdinarySubject, Namespace, N5f1);
}

/// Ed25519 data-availability certificates at `n-2f` or more, listing their signers.
pub mod da {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_ed25519;

    impl_certificate_ed25519!(DaSubject, Namespace, Available);
}

/// Ed25519 nullifications at `2f+1`.
pub mod nullify {
    use crate::multimmit::scheme::{Namespace, NullifySubject};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::faults::N5f1Nullification;

    impl_certificate_ed25519!(NullifySubject, Namespace, N5f1Nullification);
}

/// The Ed25519 suite.
///
/// Its DA certificates list their signers, so it can run payment chains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Scheme;

impl super::Scheme for Scheme {
    type PublicKey = keys::PublicKey;
    type Ordinary = ordinary::Scheme;
    type Da = da::Scheme;
    type Nullify = nullify::Scheme;

    fn da_certificate_config(participants: usize) -> usize {
        participants
    }

    fn nullification_config(participants: usize) -> usize {
        participants
    }

    fn da_signers(_: &da::Scheme, certificate: &DaCertificateOf<Self>) -> Option<usize> {
        Some(certificate.signers.count())
    }
}

impl Scheme {
    /// Creates a signer for the participant whose identity key is `private_key`.
    ///
    /// Fails when the key is not one of `participants` or the participants do not match the
    /// epoch configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        participants: Set<keys::PublicKey>,
        private_key: keys::PrivateKey,
    ) -> Result<Generic<Self>, Error> {
        let namespace = parameters.namespace();
        let ordinary =
            ordinary::Scheme::signer(namespace, participants.clone(), private_key.clone())
                .ok_or(Error::UnknownKey)?;
        let da = da::Scheme::signer(namespace, participants.clone(), private_key.clone())
            .ok_or(Error::UnknownKey)?;
        let nullify = nullify::Scheme::signer(namespace, participants, private_key)
            .ok_or(Error::UnknownKey)?;
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier for `participants`.
    pub fn verifier(
        parameters: &Arc<Parameters>,
        participants: Set<keys::PublicKey>,
    ) -> Result<Generic<Self>, Error> {
        let namespace = parameters.namespace();
        let ordinary = ordinary::Scheme::verifier(namespace, participants.clone());
        let da = da::Scheme::verifier(namespace, participants.clone());
        let nullify = nullify::Scheme::verifier(namespace, participants);
        Generic::new(parameters, ordinary, da, nullify)
    }
}
