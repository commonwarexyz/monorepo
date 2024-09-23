//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Bytes;

pub mod bls12381;
pub mod ed25519;
pub mod utils;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sign_and_verify<C: Scheme>(mut signer: C) {
        let namespace = b"test_namespace";
        let message = b"test_message";
        let signature = signer.sign(namespace, message);

        let public_key = signer.me();
        assert!(C::verify(namespace, message, &public_key, &signature));
    }

    fn test_sign_and_verify_wrong_message<C: Scheme>(mut signer: C) {
        let namespace = b"test_namespace";
        let message = b"test_message";
        let wrong_message = b"wrong_message";
        let signature = signer.sign(namespace, message);

        let public_key = signer.me();
        assert!(!C::verify(
            namespace,
            wrong_message,
            &public_key,
            &signature
        ));
    }

    fn test_sign_and_verify_wrong_namespace<C: Scheme>(mut signer: C) {
        let namespace = b"test_namespace";
        let wrong_namespace = b"wrong_namespace";
        let message = b"test_message";
        let signature = signer.sign(namespace, message);

        let public_key = signer.me();
        assert!(!C::verify(
            wrong_namespace,
            message,
            &public_key,
            &signature
        ));
    }

    fn test_signature_determinism<C: Scheme>(mut signer_1: C, mut signer_2: C) {
        let namespace = b"test_namespace";
        let message = b"test_message";

        let signature_1 = signer_1.sign(namespace, message);
        let signature_2 = signer_2.sign(namespace, message);

        assert_eq!(signer_1.me(), signer_2.me());
        assert_eq!(signature_1, signature_2);
    }

    fn test_invalid_signature_length<C: Scheme>(mut signer: C) {
        let namespace = b"test_namespace";
        let message = b"test_message";
        let mut signature = signer.sign(namespace, message);
        signature.truncate(signature.len() - 1); // Invalidate the signature

        let public_key = signer.me();
        assert!(!C::verify(namespace, message, &public_key, &signature));
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let signer = ed25519::insecure_signer(0);
        test_sign_and_verify(signer);
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_message() {
        let signer = ed25519::insecure_signer(0);
        test_sign_and_verify_wrong_message(signer);
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_namespace() {
        let signer = ed25519::insecure_signer(0);
        test_sign_and_verify_wrong_namespace(signer);
    }

    #[test]
    fn test_ed25519_signature_determinism() {
        let signer_1 = ed25519::insecure_signer(0);
        let signer_2 = ed25519::insecure_signer(0);
        test_signature_determinism(signer_1, signer_2);
    }

    #[test]
    fn test_ed25519_invalid_signature_length() {
        let signer = ed25519::insecure_signer(0);
        test_invalid_signature_length(signer);
    }

    #[test]
    fn test_bls12381_sign_and_verify() {
        let signer = bls12381::insecure_signer(0);
        test_sign_and_verify(signer);
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_message() {
        let signer = bls12381::insecure_signer(0);
        test_sign_and_verify_wrong_message(signer);
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_namespace() {
        let signer = bls12381::insecure_signer(0);
        test_sign_and_verify_wrong_namespace(signer);
    }

    #[test]
    fn test_bls12381_signature_determinism() {
        let signer_1 = bls12381::insecure_signer(0);
        let signer_2 = bls12381::insecure_signer(0);
        test_signature_determinism(signer_1, signer_2);
    }

    #[test]
    fn test_bls12381_invalid_signature_length() {
        let signer = bls12381::insecure_signer(0);
        test_invalid_signature_length(signer);
    }
}
