//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Buf;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;
use thiserror::Error;

pub mod bls12381;
pub use bls12381::Bls12381;
pub mod ed25519;
pub use ed25519::Ed25519;
pub use ed25519::Ed25519Batch;
pub mod sha256;
pub use sha256::hash;
pub use sha256::Sha256;
pub mod secp256r1;
pub use secp256r1::Secp256r1;

/// Errors that can occur when interacting with cryptographic primitives.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid digest length")]
    InvalidDigestLength,
    #[error("invalid private key length")]
    InvalidPrivateKeyLength,
    #[error("invalid public key length")]
    InvalidPublicKeyLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid public key")]
    InvalidPublicKey,
}

/// Arbitrary object that can be represented as a byte array.
pub trait Octets:
    AsRef<[u8]>
    + for<'a> TryFrom<&'a [u8], Error = Error>
    + for<'a> TryFrom<&'a Vec<u8>, Error = Error>
    + TryFrom<Vec<u8>, Error = Error>
    + Deref<Target = [u8]>
    + Sized
    + Clone
    + Send
    + Sync
    + 'static
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Debug
    + Hash
{
    /// Attempts to read a digest from the provided buffer.
    fn read_from<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        // Check if there are enough bytes in the buffer to read a digest.
        let digest_len = size_of::<Self>();
        if buf.remaining() < digest_len {
            return Err(Error::InvalidDigestLength);
        }

        // If there are enough contiguous bytes in the buffer, use them directly.
        let chunk = buf.chunk();
        if chunk.len() >= digest_len {
            let digest = Self::try_from(&chunk[..digest_len])?;
            buf.advance(digest_len);
            return Ok(digest);
        }

        // Otherwise, copy the bytes into a temporary buffer.
        let mut temp = vec![0u8; digest_len];
        buf.copy_to_slice(&mut temp);
        Self::try_from(temp)
    }
}

/// Interface that commonware crates rely on for most cryptographic operations.
pub trait Scheme: Clone + Send + Sync + 'static {
    type PrivateKey: Octets;
    type PublicKey: Octets;
    type Signature: Octets;

    /// Returns a new instance of the scheme.
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self;

    /// Returns a new instance of the scheme from a secret key.
    fn from(private_key: Self::PrivateKey) -> Option<Self>;

    /// Returns a new instance of the scheme from a provided seed.
    ///
    /// # Warning
    ///
    /// This function is insecure and should only be used for examples
    /// and testing.
    fn from_seed(seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        Self::new(&mut rng)
    }

    /// Returns the serialized private key of the signer.
    fn private_key(&self) -> Self::PrivateKey;

    /// Returns the serialized public key of the signer.
    fn public_key(&self) -> Self::PublicKey;

    /// Sign the given message.
    ///
    /// The message should not be hashed prior to calling this function. If a particular scheme
    /// requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// A namespace should be used to prevent replay attacks. It will be prepended to the message so
    /// that a signature meant for one context cannot be used unexpectedly in another (i.e. signing
    /// a message on the network layer can't accidentally spend funds on the execution layer). See
    /// [union_unique](commonware_utils::union_unique) for details.
    fn sign(&mut self, namespace: Option<&[u8]>, message: &[u8]) -> Self::Signature;

    /// Check that a signature is valid for the given message and public key.
    ///
    /// The message should not be hashed prior to calling this function. If a particular
    /// scheme requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// Because namespace is prepended to message before signing, the namespace provided here must
    /// match the namespace provided during signing.
    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool;
}

/// Interface that commonware crates rely on for batched cryptographic operations.
pub trait BatchScheme {
    type PublicKey: Octets;
    type Signature: Octets;

    /// Create a new batch scheme.
    fn new() -> Self;

    /// Append item to the batch.
    ///
    /// The message should not be hashed prior to calling this function. If a particular scheme
    /// requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// A namespace should be used to prevent replay attacks. It will be prepended to the message so
    /// that a signature meant for one context cannot be used unexpectedly in another (i.e. signing
    /// a message on the network layer can't accidentally spend funds on the execution layer). See
    /// [union_unique](commonware_utils::union_unique) for details.
    fn add(
        &mut self,
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool;

    /// Verify all items added to the batch.
    ///
    /// Returns `true` if all items are valid, `false` otherwise.
    ///
    /// # Why Randomness?
    ///
    /// When performing batch verification, it is often important to add some randomness
    /// to prevent an attacker from constructing a malicious batch of signatures that pass
    /// batch verification but are invalid individually. Abstractly, think of this as
    /// there existing two valid signatures (`c_1` and `c_2`) and an attacker proposing
    /// (`c_1 + d` and `c_2 - d`).
    ///
    /// You can read more about this [here](https://ethresear.ch/t/security-of-bls-batch-verification/10748#the-importance-of-randomness-4).
    fn verify<R: RngCore + CryptoRng>(self, rng: &mut R) -> bool;
}

/// Interface that commonware crates rely on for hashing.
///
/// Hash functions in commonware primitives are not typically hardcoded
/// to a specific algorithm (e.g. SHA-256) because different hash functions
/// may work better with different cryptographic schemes, may be more efficient
/// to use in STARK/SNARK proofs, or provide different levels of security (with some
/// performance/size penalty).
///
/// This trait is required to implement the `Clone` trait because it is often
/// part of a struct that is cloned. In practice, implementations do not actually
/// clone the hasher state but users should not rely on this behavior and call `reset`
/// after cloning.
pub trait Hasher: Clone + Send + Sync + 'static {
    /// Byte array representing a hash digest.
    type Digest: Octets;

    /// Create a new hasher.
    fn new() -> Self;

    /// Append message to previously recorded data.
    fn update(&mut self, message: &[u8]);

    /// Hash all recorded data and reset the hasher
    /// to the initial state.
    fn finalize(&mut self) -> Self::Digest;

    /// Reset the hasher without generating a hash.
    ///
    /// This function does not need to be called after `finalize`.
    fn reset(&mut self);

    /// Generate a random digest.
    ///
    /// # Warning
    ///
    /// This function is typically used for testing and is not recommended
    /// for production use.
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self::Digest;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn test_validate<C: Scheme>() {
        let signer = C::new(&mut OsRng);
        let public_key = signer.public_key();
        assert!(C::PublicKey::try_from(public_key.as_ref()).is_ok());
    }

    fn test_from_valid_private_key<C: Scheme>() {
        let signer = C::new(&mut OsRng);
        let private_key = signer.private_key();
        let public_key = signer.public_key();
        let signer = C::from(private_key).unwrap();
        assert_eq!(public_key, signer.public_key());
    }

    fn test_validate_invalid_public_key<C: Scheme>() {
        let result = C::PublicKey::try_from(vec![0; 1024]);
        assert_eq!(result, Err(Error::InvalidPublicKeyLength));
    }

    fn test_sign_and_verify<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace = Some(&b"test_namespace"[..]);
        let message = b"test_message";
        let signature = signer.sign(namespace, message);
        let public_key = signer.public_key();
        assert!(C::verify(namespace, message, &public_key, &signature));
    }

    fn test_sign_and_verify_wrong_message<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let namespace: Option<&[u8]> = Some(&b"test_namespace"[..]);
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
        let namespace = Some(&b"test_namespace"[..]);
        let wrong_namespace = Some(&b"wrong_namespace"[..]);
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

    fn test_empty_vs_none_namespace<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let empty_namespace = Some(&b""[..]);
        let message = b"test_message";
        let signature = signer.sign(empty_namespace, message);
        let public_key = signer.public_key();
        assert!(C::verify(empty_namespace, message, &public_key, &signature));
        assert!(!C::verify(None, message, &public_key, &signature));
    }

    fn test_signature_determinism<C: Scheme>() {
        let mut signer_1 = C::from_seed(0);
        let mut signer_2 = C::from_seed(0);
        let namespace = Some(&b"test_namespace"[..]);
        let message = b"test_message";
        let signature_1 = signer_1.sign(namespace, message);
        let signature_2 = signer_2.sign(namespace, message);
        assert_eq!(signer_1.public_key(), signer_2.public_key());
        assert_eq!(signature_1, signature_2);
    }

    fn test_invalid_signature_publickey_pair<C: Scheme>() {
        let mut signer = C::from_seed(0);
        let signer_2 = C::from_seed(1);
        let namespace = Some(&b"test_namespace"[..]);
        let message = b"test_message";
        let signature = signer.sign(namespace, message);
        let public_key = signer_2.public_key();
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
    fn test_ed25519_empty_vs_none_namespace() {
        test_empty_vs_none_namespace::<Ed25519>();
    }

    #[test]
    fn test_ed25519_signature_determinism() {
        test_signature_determinism::<Ed25519>();
    }

    #[test]
    fn test_ed25519_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<Ed25519>();
    }

    #[test]
    fn test_ed25519_len() {
        assert_eq!(size_of::<<Ed25519 as Scheme>::PublicKey>(), 32);
        assert_eq!(size_of::<<Ed25519 as Scheme>::Signature>(), 64);
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
    fn test_bls12381_empty_vs_none_namespace() {
        test_empty_vs_none_namespace::<Bls12381>();
    }

    #[test]
    fn test_bls12381_signature_determinism() {
        test_signature_determinism::<Bls12381>();
    }

    #[test]
    fn test_bls12381_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<Bls12381>();
    }

    #[test]
    fn test_bls12381_len() {
        assert_eq!(size_of::<<Bls12381 as Scheme>::PublicKey>(), 48);
        assert_eq!(size_of::<<Bls12381 as Scheme>::Signature>(), 96);
    }

    #[test]
    fn test_secp256r1_validate() {
        test_validate::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_validate_invalid_public_key() {
        test_validate_invalid_public_key::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_from_valid_private_key() {
        test_from_valid_private_key::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_sign_and_verify() {
        test_sign_and_verify::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_empty_vs_none_namespace() {
        test_empty_vs_none_namespace::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_signature_determinism() {
        test_signature_determinism::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<Secp256r1>();
    }

    #[test]
    fn test_secp256r1_len() {
        assert_eq!(size_of::<<Secp256r1 as Scheme>::PublicKey>(), 33);
        assert_eq!(size_of::<<Secp256r1 as Scheme>::Signature>(), 64);
    }

    fn test_hasher_multiple_runs<H: Hasher>() {
        // Generate initial hash
        let mut hasher = H::new();
        hasher.update(b"hello world");
        let digest = hasher.finalize();
        assert!(H::Digest::try_from(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref().len(), size_of::<H::Digest>());

        // Reuse hasher without reset
        hasher.update(b"hello world");
        let digest_again = hasher.finalize();
        assert!(H::Digest::try_from(digest_again.as_ref()).is_ok());
        assert_eq!(digest, digest_again);

        // Reuse hasher with reset
        hasher.update(b"hello mars");
        hasher.reset();
        hasher.update(b"hello world");
        let digest_reset = hasher.finalize();
        assert!(H::Digest::try_from(digest_reset.as_ref()).is_ok());
        assert_eq!(digest, digest_reset);

        // Hash different data
        hasher.update(b"hello mars");
        let digest_mars = hasher.finalize();
        assert!(H::Digest::try_from(digest_mars.as_ref()).is_ok());
        assert_ne!(digest, digest_mars);
    }

    fn test_hasher_multiple_updates<H: Hasher>() {
        // Generate initial hash
        let mut hasher = H::new();
        hasher.update(b"hello");
        hasher.update(b" world");
        let digest = hasher.finalize();
        assert!(H::Digest::try_from(digest.as_ref()).is_ok());

        // Generate hash in oneshot
        let mut hasher = H::new();
        hasher.update(b"hello world");
        let digest_oneshot = hasher.finalize();
        assert!(H::Digest::try_from(digest_oneshot.as_ref()).is_ok());
        assert_eq!(digest, digest_oneshot);
    }

    fn test_hasher_empty_input<H: Hasher>() {
        let mut hasher = H::new();
        let digest = hasher.finalize();
        assert!(H::Digest::try_from(digest.as_ref()).is_ok());
    }

    fn test_hasher_large_input<H: Hasher>() {
        let mut hasher = H::new();
        let data = vec![1; 1024];
        hasher.update(&data);
        let digest = hasher.finalize();
        assert!(H::Digest::try_from(digest.as_ref()).is_ok());
    }

    #[test]
    fn test_sha256_hasher_multiple_runs() {
        test_hasher_multiple_runs::<Sha256>();
    }

    #[test]
    fn test_sha256_hasher_multiple_updates() {
        test_hasher_multiple_updates::<Sha256>();
    }

    #[test]
    fn test_sha256_hasher_empty_input() {
        test_hasher_empty_input::<Sha256>();
    }

    #[test]
    fn test_sha256_hasher_large_input() {
        test_hasher_large_input::<Sha256>();
    }
}
