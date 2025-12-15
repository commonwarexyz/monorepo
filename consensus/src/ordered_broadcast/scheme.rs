//! Signing scheme implementations for `ordered_broadcast`.
//!
//! This module provides protocol-specific wrappers around the generic signing schemes
//! in [`crate::scheme`]. Each wrapper binds the scheme's subject type to
//! [`AckContext`], which is used for signing and verifying chunk acknowledgments.
//!
//! # Available Schemes
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly,
//!   no trusted setup required.
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification.
//!   Compact certificates while preserving attribution.
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Constant-size
//!   certificates regardless of committee size.

use super::types::AckContext;
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};

pub mod bls12381_multisig {
    //! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `ordered_broadcast`.
    //!
    //! [`Scheme`] is **attributable**: individual signatures can be
    //! used by an external observer as evidence of either liveness or of committing a fault.
    //! Certificates contain signer indices alongside an aggregated signature,
    //! enabling secure per-validator activity tracking and conflict detection.

    use crate::ordered_broadcast::types::AckContext;
    use commonware_cryptography::impl_bls12381_multisig_certificate;

    impl_bls12381_multisig_certificate!(AckContext<'a, P, D>);
}

pub mod bls12381_threshold {
    //! BLS12-381 threshold implementation of the [`Scheme`] trait for `ordered_broadcast`.
    //!
    //! [`Scheme`] is **non-attributable**: exposing partial signatures
    //! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
    //! any `t` valid partial signatures can be used to forge a partial signature for any other player,
    //! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
    //! (as it must be sent by said participant) but can't be used by an external observer.

    use crate::ordered_broadcast::types::AckContext;
    use commonware_cryptography::impl_bls12381_threshold_certificate;

    impl_bls12381_threshold_certificate!(AckContext<'a, P, D>);
}

pub mod ed25519 {
    //! Ed25519 implementation of the [`Scheme`] trait for `ordered_broadcast`.
    //!
    //! [`Scheme`] is **attributable**: individual signatures can be safely
    //! presented to some third party as evidence of either liveness or of committing a fault. Certificates
    //! contain signer indices alongside individual signatures, enabling secure
    //! per-validator activity tracking and fault detection.

    use crate::ordered_broadcast::types::AckContext;
    use commonware_cryptography::{ed25519, impl_ed25519_certificate};

    impl_ed25519_certificate!(AckContext<'a, ed25519::PublicKey, D>);
}

/// Marker trait for signing schemes compatible with `ordered_broadcast`.
///
/// This trait binds a [`Scheme`] to the [`AckContext`] subject type used by the
/// ordered broadcast protocol. It is automatically implemented for any scheme
/// whose subject type matches `AckContext<'a, P, D>`.
pub trait OrderedBroadcastScheme<P: PublicKey, D: Digest>:
    for<'a> Scheme<Subject<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}

impl<P: PublicKey, D: Digest, S> OrderedBroadcastScheme<P, D> for S where
    S: for<'a> Scheme<Subject<'a, D> = AckContext<'a, P, D>, PublicKey = P>
{
}
