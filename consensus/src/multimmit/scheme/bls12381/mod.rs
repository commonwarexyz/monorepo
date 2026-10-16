//! BLS12-381 signatures and aggregate certificates.
//!
//! Every participant holds one ordinary BLS key, registered in a proof-of-possession checked
//! [`Roster`]. That key signs transaction-block headers, leader blocks, and vote contents. V-QCs
//! and L-QCs aggregate the ordinary vote signatures their tallies record.
//!
//! # Roles
//!
//! A [`Scheme`] is a signer (an ordinary key) or a verifier (keyless). Both verify everything.
//!
//! # Verification
//!
//! Every signed item decomposes into one pairing claim after its structural checks. Individual
//! verifiers check one claim, and [`Scheme::verify_batch`] checks the claims of many items as one
//! randomly scaled pairing product. A certificate's claim covers the vote content of each of its
//! signers; signers that signed the same content share one pairing, so a certificate whose voters
//! agree costs one pairing however many signers it has.

/// Declares a method public under the `mocks` feature, so benches and tests outside the crate
/// can drive it directly, and crate-private otherwise.
#[cfg(not(target_arch = "wasm32"))]
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
mod claims;
mod roster;
#[cfg(not(target_arch = "wasm32"))]
mod sign;
#[cfg(test)]
mod tests;

use super::Namespace;
use crate::{
    Epochable,
    multimmit::{
        config::Parameters,
        types::{ChainId, CodecConfig, Error as TypesError, VoteContent},
    },
    types::Epoch,
};
pub use assemble::SignatureVerification;
pub use batch::{Signed, Verdict};
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::{group::Private, ops, variant::Variant},
};
use commonware_utils::{
    Participant,
    ordered::{BiMap, Set},
};
use core::fmt;
pub use roster::Roster;
use std::sync::Arc;

/// The vote contents a certificate records, each with its signer, in signer order.
pub type Contents<D> = Vec<(Participant, VoteContent<D>)>;

/// An error while constructing or verifying a Multimmit cryptographic artifact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The scheme has no local signing key.
    #[error("scheme is verifier-only")]
    VerifierOnly,
    /// The local key does not own the producer or leader role.
    #[error("unexpected signer")]
    Signer,
    /// A signature or aggregate is malformed, zero, or invalid.
    #[error("invalid signature")]
    Signature,
    /// The supplied votes do not form the contents of one certificate.
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
    /// An ordinary public key or its proof of possession is invalid.
    #[error("invalid proof of possession")]
    ProofOfPossession,
    /// The ordinary key is not in the roster.
    #[error("ordinary key is not in the roster")]
    UnknownKey,
}

/// The local participant's ordinary key and its index in the roster.
#[derive(Clone)]
struct Signer {
    // Only signing reads the key, and signing is not built for wasm32.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    private: Private,
    participant: Participant,
}

/// Multimmit's concrete BLS12-381 scheme.
///
/// `V` may be either [`commonware_cryptography::bls12381::primitives::variant::MinPk`] or
/// [`commonware_cryptography::bls12381::primitives::variant::MinSig`]. The ordinary signing roster
/// is proof-of-possession checked by [`Roster`], which makes aggregating signatures from
/// distinct keys over one message safe against rogue keys.
#[derive(Clone)]
pub struct Scheme<P: PublicKey, V: Variant> {
    parameters: Arc<Parameters>,
    namespace: Namespace,
    participants: BiMap<P, V::Public>,
    signer: Option<Signer>,
}

impl<P: PublicKey, V: Variant> fmt::Debug for Scheme<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Scheme")
            .field("epoch", &self.parameters.epoch())
            .field("participants", &self.participants.len())
            .field("me", &self.me())
            .finish()
    }
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Creates a signer from the local participant's ordinary key.
    ///
    /// Fails when the roster does not match the epoch configuration or does not contain the key.
    pub fn signer(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        private: Private,
    ) -> Result<Self, Error> {
        validate_roster(parameters, &roster)?;
        let public = ops::compute_public::<V>(&private);
        let participant = roster
            .public_keys()
            .values()
            .iter()
            .enumerate()
            .find_map(|(index, registered)| {
                (registered == &public).then(|| Participant::from_usize(index))
            })
            .ok_or(Error::UnknownKey)?;
        Ok(Self::new(
            parameters,
            roster,
            Some(Signer {
                private,
                participant,
            }),
        ))
    }

    /// Creates a keyless verifier.
    ///
    /// Fails when the roster does not match the epoch configuration.
    pub fn verifier(parameters: &Arc<Parameters>, roster: Roster<P, V>) -> Result<Self, Error> {
        validate_roster(parameters, &roster)?;
        Ok(Self::new(parameters, roster, None))
    }

    fn new(parameters: &Arc<Parameters>, roster: Roster<P, V>, signer: Option<Signer>) -> Self {
        Self {
            parameters: Arc::clone(parameters),
            namespace: Namespace::new(parameters.namespace()),
            participants: roster.participants,
            signer,
        }
    }

    /// Returns the epoch parameters this scheme signs and verifies under.
    pub const fn parameters(&self) -> &Arc<Parameters> {
        &self.parameters
    }

    /// Returns the ordered identity-key committee.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the ordinary BLS public-key roster in identity-key order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
        &self.participants
    }

    /// Returns this instance's participant index when it can sign.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|signer| signer.participant)
    }

    /// Returns the immutable decoding and quorum limits for this epoch.
    pub fn codec_config(&self) -> CodecConfig {
        self.parameters.codec_config()
    }

    fn public(&self, participant: Participant) -> Option<&V::Public> {
        self.participants.value(usize::from(participant))
    }

    fn ensure_epoch(&self, epoch: Epoch) -> Result<(), Error> {
        if epoch != self.parameters.epoch() {
            return Err(Error::Context);
        }
        Ok(())
    }

    fn producer(&self, chain: ChainId) -> Result<Participant, Error> {
        self.parameters.producer(chain).ok_or(Error::Chain)
    }
}

impl<P: PublicKey, V: Variant> Epochable for Scheme<P, V> {
    fn epoch(&self) -> Epoch {
        self.parameters.epoch()
    }
}

/// Checks that `roster` was verified for the epoch's namespace and committee.
fn validate_roster<P: PublicKey, V: Variant>(
    parameters: &Parameters,
    roster: &Roster<P, V>,
) -> Result<(), Error> {
    if !roster.matches_namespace(parameters.namespace()) {
        return Err(Error::Namespace);
    }
    let participants = roster.public_keys();
    if participants.is_empty() || participants.len() != parameters.codec_config().participants() {
        return Err(Error::Participants);
    }
    Ok(())
}
