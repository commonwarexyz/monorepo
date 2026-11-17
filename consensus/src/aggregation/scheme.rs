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

use super::types::Item;
use commonware_cryptography::{Digest, certificate};

/// Marker trait for signing schemes compatible with `aggregation`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Item`] subject type. It is automatically
/// implemented for any compatible scheme.
///
/// # Fault model
///
/// The scheme's fault model sets aggregation's thresholds: a quorum of acknowledgements certifies
/// an item, `max_faults + 1` validators reporting a tip make it safe to adopt, and
/// `max_faults + 1` signers of one epoch acknowledging another digest diverge a height (see
/// [Divergence](super#divergence)). The engine panics unless each epoch's committee of `n` has
/// `max_faults < quorum <= n - max_faults`, so a quorum contains an honest signer and honest
/// validators alone can certify.
///
/// A certified digest is then one an honest validator computed. If honest validators agree on
/// each height's digest, as for the state roots of a deterministic replicated execution, a
/// height has at most one certified digest even when quorums do not intersect in an honest
/// signer, such as `2f + 1` of `5f + 1`. With such a model, an honest automaton that returns
/// different digests for one height, including across restarts, may see two certified.
///
/// For [`bls12381_threshold`], the model also sets the degree of the group polynomial, so a DKG
/// over it needs `2 * max_faults < quorum` (see [`Faults::quorum`]).
///
/// [`Faults::quorum`]: commonware_utils::Faults::quorum
pub trait Scheme<D: Digest>: for<'a> certificate::Scheme<Subject<'a, D> = &'a Item<D>> {}

impl<D: Digest, S> Scheme<D> for S where S: for<'a> certificate::Scheme<Subject<'a, D> = &'a Item<D>>
{}

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
}
