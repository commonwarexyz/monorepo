//! Multimmit's signing, verification, and assembly over any [`Scheme`] suite.
//!
//! # Verification
//!
//! Every artifact decomposes into role checks after its structural checks: ordinary attestations
//! and aggregates, data-availability attestations and certificates, and nullify attestations and
//! nullifications. No signature is checked for an artifact that fails its structural checks.
//! Batch verification checks the ordinary checks of many artifacts with one
//! [`verify_aggregates`] call, the attestations of the other roles grouped by subject, and the
//! certificates of each role as one batch, and attributes every failure to the artifact that
//! contributed the failing check.
//!
//! [`verify_aggregates`]: commonware_cryptography::certificate::Aggregator::verify_aggregates

/// Declares a method public under the `mocks` feature, so benches and tests outside the crate
/// can drive it directly, and crate-private otherwise.
macro_rules! mocks_pub {
    ($(#[$meta:meta])* fn $($item:tt)*) => {
        #[cfg(any(test, feature = "mocks"))]
        $(#[$meta])*
        pub fn $($item)*

        #[cfg(not(any(test, feature = "mocks")))]
        $(#[$meta])*
        pub(crate) fn $($item)*
    };
}

mod assemble;
mod batch;
mod checks;
#[cfg(not(target_arch = "wasm32"))]
mod sign;
mod transcript;

use super::{DaFaults as _, Scheme};
use crate::{
    Epochable,
    multimmit::{
        config::Parameters,
        types::{ChainId, ChainLimits, CodecConfig, Error as TypesError, LeaderBlock, VoteBody},
    },
    types::Epoch,
};
#[cfg(any(test, feature = "mocks", not(target_arch = "wasm32")))]
pub use assemble::SignatureVerification;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use batch::CertificateVotes;
use commonware_cryptography::{
    Digest,
    certificate::{Membership, Scheme as _},
};
use commonware_utils::{Faults as _, Participant, ordered::Set};
use core::fmt;
use std::sync::Arc;

/// An error while constructing or verifying a Multimmit cryptographic artifact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The scheme has no local signing material.
    #[error("scheme is verifier-only")]
    VerifierOnly,
    /// The local key does not own the producer or leader role.
    #[error("unexpected signer")]
    Signer,
    /// A signature, aggregate, attestation, or certificate is invalid.
    #[error("invalid signature")]
    Signature,
    /// The supplied messages do not form the required certificate quorum.
    #[error("invalid quorum")]
    Quorum,
    /// A compact transcript does not reconstruct the supplied messages.
    #[error("invalid vote transcript")]
    Transcript,
    /// The object belongs to another epoch.
    #[error("epoch mismatch")]
    Context,
    /// The producer chain is outside the configured chain range.
    #[error("chain out of range")]
    Chain,
    /// A protocol object failed structural validation.
    #[error(transparent)]
    Types(#[from] TypesError),
    /// The roster was verified under another namespace.
    #[error("roster namespace mismatch")]
    Namespace,
    /// The roster does not have exactly one entry per committee participant.
    #[error("roster size does not match the committee")]
    Participants,
    /// Two roster entries share an identity or an ordinary key.
    #[error("duplicate roster entry")]
    DuplicateParticipant,
    /// An ordinary public key or its registration proof is invalid.
    #[error("invalid proof of knowledge")]
    ProofOfKnowledge,
    /// A threshold sharing has the wrong size or threshold, or a zero or repeated key.
    #[error("invalid threshold sharing")]
    Sharing,
    /// The DA and nullification sharings share a group identity.
    #[error("threshold roles share a group identity")]
    SharedIdentity,
    /// The ordinary key is not in the roster.
    #[error("ordinary key is not in the roster")]
    UnknownKey,
    /// A threshold share does not belong to the local participant or to its sharing.
    #[error("threshold share mismatch")]
    Share,
    /// The suite's data-availability quorum differs from the epoch's
    /// [`DaQuorum`](crate::multimmit::types::DaQuorum).
    #[error("suite DA quorum does not match the epoch")]
    DaQuorum,
    /// The role schemes do not agree on the local participant.
    #[error("role schemes disagree on the local participant")]
    Membership,
    /// The threshold roles hold no public sharing, so they cannot check or recover attestations.
    #[error("threshold sharings unavailable")]
    SharingUnavailable,
}

/// The outcome of an optimistic data-availability assembly that did not produce a certificate.
///
/// [`Self::InvalidShares`] carries the attribution pass's answer: every named signer
/// supplied an attestation that fails on its own.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum DaRecoveryError {
    /// The assembly could not be attempted against these attestations at all.
    #[error(transparent)]
    Scheme(#[from] Error),
    /// The assembled certificate is invalid, and exactly these signers supplied invalid
    /// attestations.
    #[error("invalid data-availability attestations")]
    InvalidShares(Vec<Participant>),
}

/// Multimmit's signing and verification for one epoch over the suite `S`.
///
/// A [`Generic`] holds one scheme per role (see [`Scheme`]) and the epoch [`Parameters`] it
/// checks every protocol object against. Each concrete suite provides constructors that verify
/// its key registration and build all three roles over one participant set, for example
/// [`bls12381::Scheme::signer`](super::bls12381::Scheme::signer).
///
/// A signer holds signing material for every role at one participant index; a verifier holds
/// none. Some roles also support verifying only certificates, which then cannot check or
/// assemble that role's attestations.
#[derive(Clone)]
pub struct Generic<S: Scheme> {
    parameters: Arc<Parameters>,
    ordinary: S::Ordinary,
    da: S::Da,
    nullify: S::Nullify,
    /// Whether the threshold roles can check and recover attestations. A certificate verifier
    /// holds only group identities: its DA votes and nullify shares fail their structural checks
    /// and their assembly fails, so no role scheme is asked for material it does not hold.
    attestations: bool,
}

impl<S: Scheme> fmt::Debug for Generic<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Generic")
            .field("suite", &S::default())
            .field("epoch", &self.parameters.epoch())
            .field("participants", &self.participants().len())
            .field("me", &self.me())
            .finish()
    }
}

impl<S: Scheme> Generic<S> {
    /// Combines one scheme per role into a Multimmit scheme for the epoch `parameters`.
    ///
    /// All roles must be constructed under `parameters`'s namespace over the same ordered
    /// participant set, which suite constructors guarantee. Fails when the ordinary participant
    /// set does not match the committee size, when the suite's data-availability quorum differs
    /// from the epoch's [`DaQuorum`](crate::multimmit::types::DaQuorum), or when the roles
    /// disagree on whether and where the local participant signs.
    pub fn new(
        parameters: &Arc<Parameters>,
        ordinary: S::Ordinary,
        da: S::Da,
        nullify: S::Nullify,
    ) -> Result<Self, Error> {
        let codec = parameters.codec_config();
        if S::DaFaults::QUORUM != codec.da_quorum_kind()
            || S::DaFaults::quorum(codec.participants()) as usize != codec.da_quorum()
        {
            return Err(Error::DaQuorum);
        }
        let participants = ordinary.participants().len();
        if participants == 0 || participants != codec.participants() {
            return Err(Error::Participants);
        }
        let signer = |membership: Option<Membership>| membership.and_then(|m| m.signer());
        let me = signer(ordinary.me());
        if signer(da.me()) != me || signer(nullify.me()) != me {
            return Err(Error::Membership);
        }
        Ok(Self {
            parameters: Arc::clone(parameters),
            ordinary,
            da,
            nullify,
            attestations: true,
        })
    }

    /// Returns this scheme with threshold roles that verify only complete certificates.
    ///
    /// Such roles cannot check or recover DA votes or nullify shares: those artifacts fail their
    /// structural checks (so [`Self::verify_da_vote`] and [`Self::verify_nullify`] return
    /// `false`), and assembling DA certificates or nullifications fails with
    /// [`Error::SharingUnavailable`] before any role scheme is called.
    pub(super) const fn certificates_only(mut self) -> Self {
        self.attestations = false;
        self
    }

    /// Returns this scheme bound to `parameters`, which must differ from its own only in their
    /// leader schedule.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn with_parameters(mut self, parameters: Arc<Parameters>) -> Self {
        debug_assert!(
            self.parameters.epoch() == parameters.epoch()
                && self.parameters.namespace() == parameters.namespace()
                && self.parameters.codec_config() == parameters.codec_config()
                && self.parameters.producers() == parameters.producers(),
            "only the leader schedule may change"
        );
        self.parameters = parameters;
        self
    }

    /// Returns the epoch parameters this scheme signs and verifies under.
    pub const fn parameters(&self) -> &Arc<Parameters> {
        &self.parameters
    }

    /// Returns the ordered identity-key committee.
    pub fn participants(&self) -> &Set<S::PublicKey> {
        self.ordinary.participants()
    }

    /// Returns this instance's participant index when it can sign.
    pub fn me(&self) -> Option<Participant> {
        self.ordinary
            .me()
            .and_then(|membership| membership.signer())
    }

    /// Returns the immutable decoding and quorum limits for this epoch.
    pub fn codec_config(&self) -> CodecConfig {
        self.parameters.codec_config()
    }

    /// Returns the ordinary role scheme.
    pub const fn ordinary(&self) -> &S::Ordinary {
        &self.ordinary
    }

    /// Returns the data-availability role scheme.
    pub const fn da(&self) -> &S::Da {
        &self.da
    }

    /// Returns the nullification role scheme.
    pub const fn nullify(&self) -> &S::Nullify {
        &self.nullify
    }

    fn ensure_epoch(&self, epoch: Epoch) -> Result<(), Error> {
        if epoch != self.parameters.epoch() {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Returns the epoch's per-chain path limits when chains differ, or `None` when every chain
    /// has the codec bounds.
    ///
    /// Leader blocks and vote bodies checked against the epoch's codec configuration are bounded
    /// by it, so with uniform limits that bound already holds each chain to its own. A V-QC's
    /// conflicting ballots are not checked against it and need the chain limits regardless.
    fn distinct_chain_limits(&self) -> Option<&ChainLimits> {
        let limits = self.parameters.chain_limits();
        (!limits.is_uniform()).then_some(limits)
    }

    /// Checks a leader block's epoch and structure, holding each chain to its own path limits.
    fn ensure_leader<D: Digest>(&self, leader: &LeaderBlock<S, D>) -> Result<(), Error> {
        self.ensure_epoch(leader.epoch())?;
        leader.validate(self.codec_config())?;
        if let Some(limits) = self.distinct_chain_limits() {
            leader.validate_chain_limits(limits)?;
        }
        Ok(())
    }

    /// Checks a vote body's epoch and structure, holding each chain to its own path limits.
    fn ensure_vote_body<D: Digest>(&self, body: &VoteBody<D>) -> Result<(), Error> {
        self.ensure_epoch(body.epoch())?;
        body.validate(self.codec_config())?;
        if let Some(limits) = self.distinct_chain_limits() {
            body.validate_chain_limits(limits)?;
        }
        Ok(())
    }

    /// Returns whether `chain` is one of the configured producer chains.
    fn chain_in_range(&self, chain: ChainId) -> bool {
        (chain.get() as usize) < self.codec_config().chains()
    }

    fn ensure_chain(&self, chain: ChainId) -> Result<(), Error> {
        if !self.chain_in_range(chain) {
            return Err(Error::Chain);
        }
        Ok(())
    }

    fn producer(&self, chain: ChainId) -> Result<Participant, Error> {
        self.parameters.producer(chain).ok_or(Error::Chain)
    }
}

impl<S: Scheme> Epochable for Generic<S> {
    fn epoch(&self) -> Epoch {
        self.parameters.epoch()
    }
}
