//! Cryptographic primitives tailored for distributed systems running in byzantine environments.

use bytes::Bytes;

mod utils;

pub mod ed25519;

/// Byte array representing an arbitrary public key.
pub type PublicKey = Bytes;
/// Byte array representing an arbitrary signature.
pub type Signature = Bytes;

/// Interface that commonware crates rely on for most cryptographic operations.
pub trait Scheme: Send + Sync + Clone + 'static {
    /// Returns the public key of the signer.
    fn me(&self) -> PublicKey;

    /// Verify that a public key is well-formatted.
    fn validate(public_key: &PublicKey) -> bool;

    /// Sign the given message.
    ///
    /// The message should not be hashed prior to calling this function. If a particular
    /// scheme requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// To protect against replay attacks, it is required to provide a namespace
    /// to prefix any message. This ensures that a signature meant for one context cannot be used
    /// unexpectedly in another (i.e. signing a message on the network layer can't accidentally
    /// spend funds on the execution layer).
    fn sign(&mut self, namespace: &[u8], message: &[u8]) -> Signature;

    /// Check that a signature is valid for the given message and public key.
    ///
    /// The message should not be hashed prior to calling this function. If a particular
    /// scheme requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// Because namespace is prepended to message before signing, the namespace provided here must
    /// match the namespace provided during signing.
    fn verify(
        namespace: &[u8],
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool;
}
