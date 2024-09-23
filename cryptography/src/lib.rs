//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Bytes;
use rand::{CryptoRng, Rng};

pub mod bls12381;
pub mod ed25519;
pub mod utils;

/// Byte array representing an arbitrary private key.
pub type PrivateKey = Bytes;

/// Byte array representing an arbitrary public key.
pub type PublicKey = Bytes;

/// Byte array representing an arbitrary signature.
pub type Signature = Bytes;

/// Interface that commonware crates rely on for most cryptographic operations.
pub trait Scheme: Send + Sync + Clone + 'static {
    /// Returns a new instance of the scheme.
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    /// Returns a new instance of the scheme from a secret key.
    fn from(private_key: PrivateKey) -> Option<Self>;

    /// Returns a new instance of the scheme from a provided seed.
    ///
    /// # Warning
    ///
    /// This function is insecure and should only be used for examples
    /// and testing.
    fn from_seed(seed: u64) -> Self;

    /// Returns the serialized private key of the signer.
    fn private_key(&self) -> PrivateKey;

    /// Returns the serialized public key of the signer.
    fn public_key(&self) -> PublicKey;

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
    use bls12381::Bls12381;
    use ed25519::Ed25519;
    use rand::rngs::OsRng;

    fn test_validate<C: Scheme>() {
        let signer = C::new(&mut OsRng);
        let public_key = signer.public_key();
        assert!(C::validate(&public_key));
    }

    fn test_from_valid_private_key<C: Scheme>() {
        let signer = C::new(&mut OsRng);
        let private_key = signer.private_key();
        let public_key = signer.public_key();
        let signer = C::from(private_key).unwrap();
        assert_eq!(public_key, signer.public_key());
    }

    fn test_validate_invalid_public_key<C: Scheme>() {
        let public_key = PublicKey::from(vec![0; 1024]);
        assert!(!C::validate(&public_key));
    }

    fn test_sign_and_verify<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let signature = signer.sign(namespace, message);
        let public_key = signer.public_key();
        assert!(C::verify(namespace, message, &public_key, &signature));
    }

    fn test_sign_and_verify_wrong_message<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let wrong_message = b"wrong_message";
        let signature = signer.sign(namespace, message);
        let public_key = signer.public_key();
        assert!(!C::verify(
            namespace,
            wrong_message,
            &public_key,
            &signature
        ));
    }

    fn test_sign_and_verify_wrong_namespace<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace = b"test_namespace";
        let wrong_namespace = b"wrong_namespace";
        let message = b"test_message";
        let signature = signer.sign(namespace, message);
        let public_key = signer.public_key();
        assert!(!C::verify(
            wrong_namespace,
            message,
            &public_key,
            &signature
        ));
    }

    fn test_signature_determinism<C: Scheme>() {
        let mut signer_1 = C::from_seed(0);
        let mut signer_2 = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let signature_1 = signer_1.sign(namespace, message);
        let signature_2 = signer_2.sign(namespace, message);
        assert_eq!(signer_1.public_key(), signer_2.public_key());
        assert_eq!(signature_1, signature_2);
    }

    fn test_invalid_signature_length<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let mut signature = signer.sign(namespace, message);
        signature.truncate(signature.len() - 1); // Invalidate the signature
        let public_key = signer.public_key();
        assert!(!C::verify(namespace, message, &public_key, &signature));
    }

    #[test]
    fn test_ed25519_validate() {
        test_validate::<Ed25519>();
    }

    #[test]
    fn test_ed25519_validate_invalid_public_key() {
        test_validate_invalid_public_key::<Ed25519>();
    }

    #[test]
    fn test_ed25519_from_valid_private_key() {
        test_from_valid_private_key::<Ed25519>();
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        test_sign_and_verify::<Ed25519>();
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<Ed25519>();
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<Ed25519>();
    }

    #[test]
    fn test_ed25519_signature_determinism() {
        test_signature_determinism::<Ed25519>();
    }

    #[test]
    fn test_ed25519_invalid_signature_length() {
        test_invalid_signature_length::<Ed25519>();
    }

    #[test]
    fn test_bls12381_validate() {
        test_validate::<Bls12381>();
    }

    #[test]
    fn test_bls12381_validate_invalid_public_key() {
        test_validate_invalid_public_key::<Bls12381>();
    }

    #[test]
    fn test_bls12381_from_valid_private_key() {
        test_from_valid_private_key::<Bls12381>();
    }

    #[test]
    fn test_bls12381_sign_and_verify() {
        test_sign_and_verify::<Bls12381>();
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<Bls12381>();
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<Bls12381>();
    }

    #[test]
    fn test_bls12381_signature_determinism() {
        test_signature_determinism::<Bls12381>();
    }

    #[test]
    fn test_bls12381_invalid_signature_length() {
        test_invalid_signature_length::<Bls12381>();
    }
}
