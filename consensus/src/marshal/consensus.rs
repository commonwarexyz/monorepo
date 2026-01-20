//! Traits for abstracting over consensus protocols in marshal.
//!
//! This module provides traits that allow marshal to work with different consensus protocols
//! (e.g., simplex, minimmit) without being coupled to their specific type implementations.
//!
//! # Protocol Differences
//!
//! Different consensus protocols have different certificate types:
//! - **Simplex**: `Notarization` (M-quorum), `Finalization` (L-quorum)
//! - **Minimmit**: `MNotarization` (M-quorum), `Finalization` (L-quorum)
//!
//! These traits abstract over these differences, allowing marshal to handle certificates
//! generically.
//!
//! # Verification
//!
//! Certificate verification is handled through [`MarshalConsensus::verify_notarization`] and
//! [`MarshalConsensus::verify_finalization`] rather than methods on the certificate traits.
//! This design allows protocol implementations to add protocol-specific scheme bounds
//! (e.g., `simplex::scheme::Scheme<D>`) that can't be expressed generically.

use crate::types::Round;
use commonware_codec::{Decode, Encode, EncodeSize, Write};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;
use std::hash::Hash;

/// Trait for M-quorum certificates (Notarization in simplex, MNotarization in minimmit).
///
/// M-quorum certificates are formed when a threshold of validators have voted for a proposal.
/// In simplex this is 2f+1 (n-f), in minimmit this is 2f+1 (n-3f).
///
/// Verification is performed via [`MarshalConsensus::verify_notarization`] rather than a method
/// on this trait, to allow protocol-specific scheme bounds.
pub trait MarshalNotarization<S: Scheme, D: Digest>:
    Clone + Send + Sync + 'static + Write + EncodeSize + Encode + Decode + Eq + Hash
{
    /// Codec configuration type for decoding.
    type Cfg: Clone + Send + Sync + 'static;

    /// Returns the round associated with this certificate.
    fn round(&self) -> Round;

    /// Returns the payload (block commitment) from this certificate.
    fn payload(&self) -> D;

    /// Decodes the certificate from bytes using the given configuration.
    fn decode_cfg_notarization(
        bytes: impl AsRef<[u8]>,
        cfg: &<Self as MarshalNotarization<S, D>>::Cfg,
    ) -> Result<Self, commonware_codec::Error>;
}

/// Trait for L-quorum certificates (Finalization in both protocols).
///
/// L-quorum certificates are formed when a larger threshold of validators have voted,
/// confirming a block as finalized.
///
/// Verification is performed via [`MarshalConsensus::verify_finalization`] rather than a method
/// on this trait, to allow protocol-specific scheme bounds.
pub trait MarshalFinalization<S: Scheme, D: Digest>:
    Clone + Send + Sync + 'static + Write + EncodeSize + Encode + Decode + Eq + Hash
{
    /// Codec configuration type for decoding.
    type Cfg: Clone + Send + Sync + 'static;

    /// Returns the round associated with this certificate.
    fn round(&self) -> Round;

    /// Returns the view of the parent from this certificate's proposal.
    fn parent(&self) -> crate::types::View;

    /// Returns the payload (block commitment) from this certificate.
    fn payload(&self) -> D;

    /// Decodes the certificate from bytes using the given configuration.
    fn decode_cfg_finalization(
        bytes: impl AsRef<[u8]>,
        cfg: &<Self as MarshalFinalization<S, D>>::Cfg,
    ) -> Result<Self, commonware_codec::Error>;
}

/// Trait for extracting certificates from consensus activity.
///
/// Different protocols have different Activity enum variants. This trait allows
/// marshal to extract the relevant certificates (notarization/finalization) regardless
/// of the specific protocol being used.
pub trait MarshalActivity<C: MarshalConsensus>: Clone + Send + 'static {
    /// Attempts to extract an M-quorum certificate (notarization) from this activity.
    fn into_notarization(self) -> Option<C::Notarization>;

    /// Attempts to extract an L-quorum certificate (finalization) from this activity.
    fn into_finalization(self) -> Option<C::Finalization>;
}

/// Main trait for abstracting over consensus protocols.
///
/// This trait ties together all the protocol-specific types needed by marshal.
/// Implementations exist for both simplex and minimmit.
///
/// Verification methods are provided here rather than on the certificate traits to allow
/// implementations to add protocol-specific scheme bounds (e.g., `simplex::scheme::Scheme<D>`)
/// that can't be expressed in the generic trait bounds.
pub trait MarshalConsensus: Clone + Sized + Send + Sync + 'static {
    /// The signing scheme used by the protocol.
    type Scheme: Scheme;

    /// The digest type used for block commitments.
    type Digest: Digest;

    /// The M-quorum certificate type (Notarization for simplex, MNotarization for minimmit).
    ///
    /// The `Cfg` constraint ensures the codec configuration type from `MarshalNotarization`
    /// matches the `Read::Cfg` type, allowing archives to use the same config.
    type Notarization: MarshalNotarization<
        Self::Scheme,
        Self::Digest,
        Cfg = <Self::Notarization as commonware_codec::Read>::Cfg,
    >;

    /// The L-quorum certificate type (Finalization for both protocols).
    ///
    /// The `Cfg` constraint ensures the codec configuration type from `MarshalFinalization`
    /// matches the `Read::Cfg` type, allowing archives to use the same config.
    type Finalization: MarshalFinalization<
        Self::Scheme,
        Self::Digest,
        Cfg = <Self::Finalization as commonware_codec::Read>::Cfg,
    >;

    /// The activity enum type for receiving events from consensus.
    type Activity: MarshalActivity<Self>;

    /// Verifies a notarization certificate against the provided signing scheme.
    ///
    /// Returns `true` if the certificate is valid, `false` otherwise.
    fn verify_notarization<R: CryptoRngCore>(
        notarization: &Self::Notarization,
        rng: &mut R,
        scheme: &Self::Scheme,
        strategy: &impl Strategy,
    ) -> bool;

    /// Verifies a finalization certificate against the provided signing scheme.
    ///
    /// Returns `true` if the certificate is valid, `false` otherwise.
    fn verify_finalization<R: CryptoRngCore>(
        finalization: &Self::Finalization,
        rng: &mut R,
        scheme: &Self::Scheme,
        strategy: &impl Strategy,
    ) -> bool;
}
