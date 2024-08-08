//! Cryptographic definitions required by commonware-p2p and select implementations
//! of different PKI schemes.

use bytes::Bytes;

pub mod ed25519;

/// Byte array representing an arbitrary public key.
pub type PublicKey = Bytes;
/// Byte array representing an arbitrary signature.
pub type Signature = Bytes;

/// Cryptographic operations required by commonware-p2p.
///
/// # Warning
///
/// Although data provided to this implementation to be signed are expected to be
/// unique to commonware-p2p, it is strongly recommended to prefix any payloads
/// with a unique identifier to prevent replay attacks.
pub trait Crypto: Send + Sync + Clone + 'static {
    /// Returns the public key of the signer.
    fn me(&self) -> PublicKey;
    /// Sign the given data (usually an IP).
    fn sign(&mut self, data: Vec<u8>) -> Signature;
    /// Verify that a public key is well-formatted.
    fn validate(public_key: &PublicKey) -> bool;
    /// Check that a signature is valid for the given data and public key.
    fn verify(data: Vec<u8>, public_key: &PublicKey, signature: &Signature) -> bool;
}
