//! Cryptographic definitions required by commonware-p2p and select implementations
//! of different PKI schemes.

use bytes::Bytes;

pub mod ed25519;

/// Byte array representing an arbitrary public key.
pub type PublicKey = Bytes;
/// Byte array representing an arbitrary signature.
pub type Signature = Bytes;

/// Cryptographic operations required by commonware-p2p.
pub trait Crypto: Send + Sync + Clone + 'static {
    /// Returns the public key of the signer.
    fn me(&self) -> PublicKey;

    /// Verify that a public key is well-formatted.
    fn validate(public_key: &PublicKey) -> bool;

    /// Sign the given data.
    ///
    /// To protect against replay attacks, it is required to provide a namespace
    /// to prefix any data. This ensures that a signature meant for one context cannot be used
    /// unexpectedly in another (i.e. signing a message on the network layer can't accidentally
    /// spend funds on the execution layer).
    fn sign(&mut self, namespace: &[u8], data: &[u8]) -> Signature;

    /// Check that a signature is valid for the given data and public key.
    fn verify(namespace: &[u8], data: &[u8], public_key: &PublicKey, signature: &Signature)
        -> bool;
}
