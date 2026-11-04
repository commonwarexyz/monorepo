//! Ed25519 keys for every role.
//!
//! Each participant's identity key signs for all three roles, each under its own namespace.
//! Aggregates and certificates list one signature per signer, so they grow linearly with the
//! committee but need no key registration proofs, trusted dealer, or pairing-friendly curve.
//! Ed25519 signatures are batch verified.

use super::{Available, Binding, DaFaults, DaSubject, Error, Generic, Marker, RoleDigest};
use crate::multimmit::config::Parameters;
use commonware_cryptography::{
    certificate,
    ed25519::{self as keys, certificate::Certificate},
};
use commonware_utils::ordered::Set;
use core::{fmt, hash::Hash};
use std::sync::Arc;

/// Ed25519 ordinary keys over [`OrdinarySubject`](super::OrdinarySubject)s.
pub mod ordinary {
    use crate::multimmit::scheme::{Namespace, OrdinarySubject};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::N5f1;

    impl_certificate_ed25519!(OrdinarySubject, Namespace, N5f1);
}

/// Ed25519 data-availability certificates at the `n-2f` quorum of
/// [`DaQuorum::Available`](crate::multimmit::types::DaQuorum::Available).
pub mod da {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_ed25519;

    impl_certificate_ed25519!(DaSubject, Namespace, Available);
}

/// Ed25519 data-availability certificates at the `n-f` quorum of
/// [`DaQuorum::Binding`](crate::multimmit::types::DaQuorum::Binding).
pub mod da_binding {
    use crate::multimmit::scheme::{Binding, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_ed25519;

    impl_certificate_ed25519!(DaSubject, Namespace, Binding);
}

/// Ed25519 nullifications at `2f+1`.
pub mod nullify {
    use crate::multimmit::scheme::{Namespace, NullifySubject};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::faults::N5f1Nullification;

    impl_certificate_ed25519!(NullifySubject, Namespace, N5f1Nullification);
}

/// A data-availability fault model with an Ed25519 DA role.
///
/// Implemented by [`Available`] ([`da`]) and [`Binding`] ([`da_binding`]).
pub trait Quorum: DaFaults {
    /// The Ed25519 DA role at this quorum.
    type Da: for<'a> certificate::Scheme<
            PublicKey = keys::PublicKey,
            Faults = Self,
            Certificate = Certificate,
            Signature = keys::Signature,
            Subject<'a, RoleDigest> = DaSubject,
        >;

    /// Builds a DA signer, or `None` when `private_key` is not a participant.
    #[doc(hidden)]
    fn signer(
        namespace: &[u8],
        participants: Set<keys::PublicKey>,
        private_key: keys::PrivateKey,
    ) -> Option<Self::Da>;

    /// Builds a DA verifier.
    #[doc(hidden)]
    fn verifier(namespace: &[u8], participants: Set<keys::PublicKey>) -> Self::Da;
}

macro_rules! impl_quorum {
    ($faults:ty, $module:ident) => {
        impl Quorum for $faults {
            type Da = $module::Scheme;

            fn signer(
                namespace: &[u8],
                participants: Set<keys::PublicKey>,
                private_key: keys::PrivateKey,
            ) -> Option<Self::Da> {
                $module::Scheme::signer(namespace, participants, private_key)
            }

            fn verifier(namespace: &[u8], participants: Set<keys::PublicKey>) -> Self::Da {
                $module::Scheme::verifier(namespace, participants)
            }
        }
    };
}

impl_quorum!(Available, da);
impl_quorum!(Binding, da_binding);

/// The Ed25519 suite, with DA certificates at the quorum `Q`.
pub struct Scheme<Q = Available>(Marker<Q>);

impl<Q> Clone for Scheme<Q> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Q> Copy for Scheme<Q> {}

impl<Q> Default for Scheme<Q> {
    fn default() -> Self {
        Self(Marker::default())
    }
}

impl<Q> PartialEq for Scheme<Q> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<Q> Eq for Scheme<Q> {}

impl<Q> Hash for Scheme<Q> {
    fn hash<H: core::hash::Hasher>(&self, _: &mut H) {}
}

impl<Q> fmt::Debug for Scheme<Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ed25519::Scheme")
    }
}

impl<Q: Quorum> super::Scheme for Scheme<Q> {
    type PublicKey = keys::PublicKey;
    type DaFaults = Q;
    type Ordinary = ordinary::Scheme;
    type Da = Q::Da;
    type Nullify = nullify::Scheme;

    fn da_certificate_config(participants: usize) -> usize {
        participants
    }

    fn nullification_config(participants: usize) -> usize {
        participants
    }
}

impl<Q: Quorum> Scheme<Q> {
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
        let da = Q::signer(namespace, participants.clone(), private_key.clone())
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
        let da = Q::verifier(namespace, participants.clone());
        let nullify = nullify::Scheme::verifier(namespace, participants);
        Generic::new(parameters, ordinary, da, nullify)
    }
}
