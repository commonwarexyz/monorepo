//! Signing scheme implementations for `aggregation`.
//!
//! This module provides protocol-specific wrappers around the generic signing schemes
//! in [`commonware_cryptography::certificate`]. Each wrapper binds the scheme's subject type to
//! [`Item`], which represents the data being aggregated and signed.
//!
//! # Available Schemes
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`secp256r1`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification.
//!   Compact certificates while preserving attribution.
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Constant-size
//!   certificates regardless of committee size.

use super::types::{Item, RecoveryNamespace};
use commonware_cryptography::{Digest, certificate};

/// Marker trait for signing schemes compatible with `aggregation`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Item`] subject type while
/// retaining the certificate scheme's fault model. It is automatically implemented
/// for any compatible scheme.
pub trait Scheme<D: Digest>: for<'a> certificate::Scheme<Subject<'a, D> = &'a Item<D>> {
    /// Returns the recovery identity derived from this scheme's signing namespace.
    fn recovery_namespace(&self) -> RecoveryNamespace;
}

pub mod bls12381_multisig {
    //! BLS12-381 multi-signature implementation of the
    //! [`Scheme`](commonware_cryptography::certificate::Scheme) trait for `aggregation`.
    //!
    //! This scheme is attributable: certificates are compact while still preserving
    //! per-validator attribution.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_multisig;
    use commonware_utils::N3f1;

    impl_certificate_bls12381_multisig!(&'a Item<D>, Namespace, N3f1);

    impl<D: commonware_cryptography::Digest, P: commonware_cryptography::PublicKey, V>
        super::Scheme<D> for Scheme<P, V>
    where
        V: commonware_cryptography::bls12381::primitives::variant::Variant,
    {
        fn recovery_namespace(&self) -> crate::aggregation::types::RecoveryNamespace {
            self.generic.namespace().recovery_namespace()
        }
    }
}

pub mod bls12381_threshold {
    //! BLS12-381 threshold implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme)
    //! trait for `aggregation`.
    //!
    //! This scheme is non-attributable: partial signatures should not be exposed as
    //! third-party evidence.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_threshold;
    use commonware_utils::N3f1;

    impl_certificate_bls12381_threshold!(&'a Item<D>, Namespace, N3f1);

    impl<D: commonware_cryptography::Digest, P: commonware_cryptography::PublicKey, V>
        super::Scheme<D> for Scheme<P, V>
    where
        V: commonware_cryptography::bls12381::primitives::variant::Variant,
    {
        fn recovery_namespace(&self) -> crate::aggregation::types::RecoveryNamespace {
            self.generic.namespace().recovery_namespace()
        }
    }
}

pub mod ed25519 {
    //! Ed25519 implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme) trait
    //! for `aggregation`.
    //!
    //! This scheme is attributable: individual signatures can be safely exposed as
    //! evidence of liveness or faults.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_ed25519;
    use commonware_utils::N3f1;

    impl_certificate_ed25519!(&'a Item<D>, Namespace, N3f1);

    impl<D: commonware_cryptography::Digest> super::Scheme<D> for Scheme {
        fn recovery_namespace(&self) -> crate::aggregation::types::RecoveryNamespace {
            self.generic.namespace().recovery_namespace()
        }
    }
}

pub mod secp256r1 {
    //! Secp256r1 implementation of the [`Scheme`](commonware_cryptography::certificate::Scheme) trait
    //! for `aggregation`.
    //!
    //! This scheme is attributable: individual signatures can be safely exposed as
    //! evidence of liveness or faults.

    use crate::aggregation::types::{Item, Namespace};
    use commonware_cryptography::impl_certificate_secp256r1;
    use commonware_utils::N3f1;

    impl_certificate_secp256r1!(&'a Item<D>, Namespace, N3f1);

    impl<D: commonware_cryptography::Digest, P: commonware_cryptography::PublicKey> super::Scheme<D>
        for Scheme<P>
    {
        fn recovery_namespace(&self) -> crate::aggregation::types::RecoveryNamespace {
            self.generic.namespace().recovery_namespace()
        }
    }
}
