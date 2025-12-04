//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Status
//!
//! `commonware-cryptography` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use commonware_codec::{Encode, ReadExt};
use commonware_utils::Array;
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;

pub mod bls12381;
pub mod ed25519;
pub mod sha256;
use rand_core::CryptoRngCore;
pub use sha256::{CoreSha256, Sha256};
pub mod blake3;
pub use blake3::{Blake3, CoreBlake3};
pub mod bloomfilter;
pub use bloomfilter::BloomFilter;
#[cfg(feature = "std")]
pub mod handshake;
pub mod lthash;
pub use lthash::LtHash;
pub mod secp256r1;
pub mod transcript;

/// Produces [Signature]s over messages that can be verified with a corresponding [PublicKey].
pub trait Signer: Send + Sync + Clone + 'static {
    /// The type of [Signature] produced by this [Signer].
    type Signature: Signature;

    /// The corresponding [PublicKey] type.
    type PublicKey: PublicKey<Signature = Self::Signature>;

    /// Returns the [PublicKey] corresponding to this [Signer].
    fn public_key(&self) -> Self::PublicKey;

    /// Sign a message with the given namespace.
    ///
    /// The message should not be hashed prior to calling this function. If a particular scheme
    /// requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// A namespace must be used to prevent cross-domain attacks (where a signature can be reused
    /// in a different context). It must be prepended to the message so that a signature meant for
    /// one context cannot be used unexpectedly in another (i.e. signing a message on the network
    /// layer can't accidentally spend funds on the execution layer). See
    /// [commonware_utils::union_unique] for details.
    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature;
}

/// A [Signer] that can be serialized/deserialized.
pub trait PrivateKey: Signer + Sized + ReadExt + Encode + PartialEq + Array {}

/// A [PrivateKey] that can be generated from a seed or RNG.
pub trait PrivateKeyExt: PrivateKey {
    /// Create a [PrivateKey] from a seed.
    ///
    /// # Warning
    ///
    /// This function is insecure and should only be used for examples
    /// and testing.
    fn from_seed(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Self::from_rng(&mut rng)
    }

    /// Create a fresh [PrivateKey] using the supplied RNG.
    fn from_rng<R: CryptoRngCore>(rng: &mut R) -> Self;
}

/// Verifies [Signature]s over messages.
pub trait Verifier {
    /// The type of [Signature] that this verifier can verify.
    type Signature: Signature;

    /// Verify that a [Signature] is a valid over a given message.
    ///
    /// The message should not be hashed prior to calling this function. If a particular
    /// scheme requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// Because namespace is prepended to message before signing, the namespace provided here must
    /// match the namespace provided during signing.
    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool;
}

/// A [PublicKey], able to verify [Signature]s.
pub trait PublicKey: Verifier + Sized + ReadExt + Encode + PartialEq + Array {}

/// A [Signature] over a message.
pub trait Signature: Sized + Clone + ReadExt + Encode + PartialEq + Array {}

/// An extension of [Signature] that supports public key recovery.
pub trait Recoverable: Signature {
    /// The type of [PublicKey] that can be recovered from this [Signature].
    type PublicKey: PublicKey<Signature = Self>;

    /// Recover the [PublicKey] of the signer that created this [Signature] over the given message.
    ///
    /// The message should not be hashed prior to calling this function. If a particular
    /// scheme requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// Like when verifying a signature, the namespace must match what was used during signing exactly.
    fn recover_signer(&self, namespace: &[u8], msg: &[u8]) -> Option<Self::PublicKey>;
}

/// Verifies whether all [Signature]s are correct or that some [Signature] is incorrect.
pub trait BatchVerifier<K: PublicKey> {
    /// Create a new batch verifier.
    fn new() -> Self;

    /// Append item to the batch.
    ///
    /// The message should not be hashed prior to calling this function. If a particular scheme
    /// requires a payload to be hashed before it is signed, it will be done internally.
    ///
    /// A namespace must be used to prevent replay attacks. It will be prepended to the message so
    /// that a signature meant for one context cannot be used unexpectedly in another (i.e. signing
    /// a message on the network layer can't accidentally spend funds on the execution layer). See
    /// [commonware_utils::union_unique] for details.
    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &K,
        signature: &K::Signature,
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
    fn verify<R: CryptoRngCore>(self, rng: &mut R) -> bool;
}

/// Specializes the [commonware_utils::Array] trait with the Copy trait for cryptographic digests
/// (which should be cheap to clone).
pub trait Digest: Array + Copy {
    /// Generate a random [Digest].
    ///
    /// # Warning
    ///
    /// This function is typically used for testing and is not recommended
    /// for production use.
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self;
}

/// An object that can be uniquely represented as a [Digest].
pub trait Digestible: Clone + Sized + Send + Sync + 'static {
    /// The type of digest produced by this object.
    type Digest: Digest;

    /// Returns a unique representation of the object as a [Digest].
    ///
    /// If many objects with [Digest]s are related (map to some higher-level
    /// group [Digest]), you should also implement [Committable].
    fn digest(&self) -> Self::Digest;
}

/// An object that can produce a commitment of itself.
pub trait Committable: Clone + Sized + Send + Sync + 'static {
    /// The type of commitment produced by this object.
    type Commitment: Digest;

    /// Returns the unique commitment of the object as a [Digest].
    ///
    /// For simple objects (like a block), this is often just the digest of the object
    /// itself. For more complex objects, however, this may represent some root or base
    /// of a proof structure (where many unique objects map to the same commitment).
    ///
    /// # Warning
    ///
    /// It must not be possible for two objects with the same [Digest] to map
    /// to different commitments. Primitives assume there is a one-to-one
    /// relation between digest and commitment and a one-to-many relation
    /// between commitment and digest.
    fn commitment(&self) -> Self::Commitment;
}

pub type DigestOf<H> = <H as Hasher>::Digest;

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
pub trait Hasher: Default + Clone + Send + Sync + 'static {
    /// Digest generated by the hasher.
    type Digest: Digest;

    /// The digest of an empty input.
    const EMPTY: Self::Digest;

    /// Create a new, empty hasher.
    fn new() -> Self {
        Self::default()
    }

    /// Append message to previously recorded data.
    fn update(&mut self, message: &[u8]) -> &mut Self;

    /// Hash all recorded data and reset the hasher
    /// to the initial state.
    fn finalize(&mut self) -> Self::Digest;

    /// Reset the hasher without generating a hash.
    ///
    /// This function does not need to be called after `finalize`.
    fn reset(&mut self) -> &mut Self;

    /// Hash a single message with a one-time-use hasher.
    fn hash(message: &[u8]) -> Self::Digest {
        Self::new().update(message).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};
    use rand::rngs::OsRng;

    fn test_validate<C: PrivateKeyExt>() {
        let private_key = C::from_rng(&mut OsRng);
        let public_key = private_key.public_key();
        assert!(C::PublicKey::decode(public_key.as_ref()).is_ok());
    }

    fn test_validate_invalid_public_key<C: Signer>() {
        let result = C::PublicKey::decode(vec![0; 1024].as_ref());
        assert!(result.is_err());
    }

    fn test_sign_and_verify<C: PrivateKeyExt>() {
        let private_key = C::from_seed(0);
        let namespace = &b"test_namespace"[..];
        let message = b"test_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(public_key.verify(namespace, message, &signature));
    }

    fn test_sign_and_verify_wrong_message<C: PrivateKeyExt>() {
        let private_key = C::from_seed(0);
        let namespace = &b"test_namespace"[..];
        let message = b"test_message";
        let wrong_message = b"wrong_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(!public_key.verify(namespace, wrong_message, &signature));
    }

    fn test_sign_and_verify_wrong_namespace<C: PrivateKeyExt>() {
        let private_key = C::from_seed(0);
        let namespace = &b"test_namespace"[..];
        let wrong_namespace = &b"wrong_namespace"[..];
        let message = b"test_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(!public_key.verify(wrong_namespace, message, &signature));
    }

    fn test_empty_namespace<C: PrivateKeyExt>() {
        let private_key = C::from_seed(0);
        let empty_namespace = &b""[..];
        let message = b"test_message";
        let signature = private_key.sign(empty_namespace, message);
        let public_key = private_key.public_key();
        assert!(public_key.verify(empty_namespace, message, &signature));
    }

    fn test_signature_determinism<C: PrivateKeyExt>() {
        let private_key_1 = C::from_seed(0);
        let private_key_2 = C::from_seed(0);
        let namespace = &b"test_namespace"[..];
        let message = b"test_message";
        let signature_1 = private_key_1.sign(namespace, message);
        let signature_2 = private_key_2.sign(namespace, message);
        assert_eq!(private_key_1.public_key(), private_key_2.public_key());
        assert_eq!(signature_1, signature_2);
    }

    fn test_invalid_signature_publickey_pair<C: PrivateKeyExt>() {
        let private_key = C::from_seed(0);
        let private_key_2 = C::from_seed(1);
        let namespace = &b"test_namespace"[..];
        let message = b"test_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key_2.public_key();
        assert!(!public_key.verify(namespace, message, &signature));
    }

    #[test]
    fn test_ed25519_validate() {
        test_validate::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_validate_invalid_public_key() {
        test_validate_invalid_public_key::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        test_sign_and_verify::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_empty_namespace() {
        test_empty_namespace::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_signature_determinism() {
        test_signature_determinism::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<ed25519::PrivateKey>();
    }

    #[test]
    fn test_ed25519_len() {
        assert_eq!(ed25519::PublicKey::SIZE, 32);
        assert_eq!(ed25519::Signature::SIZE, 64);
    }

    #[test]
    fn test_bls12381_validate() {
        test_validate::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_validate_invalid_public_key() {
        test_validate_invalid_public_key::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_sign_and_verify() {
        test_sign_and_verify::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_empty_namespace() {
        test_empty_namespace::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_signature_determinism() {
        test_signature_determinism::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<bls12381::PrivateKey>();
    }

    #[test]
    fn test_bls12381_len() {
        assert_eq!(bls12381::PublicKey::SIZE, 48);
        assert_eq!(bls12381::Signature::SIZE, 96);
    }

    #[test]
    fn test_secp256r1_standard_validate() {
        test_validate::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_validate_invalid_public_key() {
        test_validate_invalid_public_key::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_sign_and_verify() {
        test_sign_and_verify::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_empty_namespace() {
        test_empty_namespace::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_signature_determinism() {
        test_signature_determinism::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<secp256r1::standard::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_standard_len() {
        assert_eq!(secp256r1::standard::PublicKey::SIZE, 33);
        assert_eq!(secp256r1::standard::Signature::SIZE, 64);
    }

    #[test]
    fn test_secp256r1_recoverable_validate() {
        test_validate::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_validate_invalid_public_key() {
        test_validate_invalid_public_key::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_sign_and_verify() {
        test_sign_and_verify::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_empty_namespace() {
        test_empty_namespace::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_signature_determinism() {
        test_signature_determinism::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<secp256r1::recoverable::PrivateKey>();
    }

    #[test]
    fn test_secp256r1_recoverable_len() {
        assert_eq!(secp256r1::recoverable::PublicKey::SIZE, 33);
        assert_eq!(secp256r1::recoverable::Signature::SIZE, 65);
    }
    fn test_hasher_multiple_runs<H: Hasher>() {
        // Generate initial hash
        let mut hasher = H::new();
        hasher.update(b"hello world");
        let digest = hasher.finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref().len(), H::Digest::SIZE);

        // Reuse hasher without reset
        hasher.update(b"hello world");
        let digest_again = hasher.finalize();
        assert!(H::Digest::decode(digest_again.as_ref()).is_ok());
        assert_eq!(digest, digest_again);

        // Reuse hasher with reset
        hasher.update(b"hello mars");
        hasher.reset();
        hasher.update(b"hello world");
        let digest_reset = hasher.finalize();
        assert!(H::Digest::decode(digest_reset.as_ref()).is_ok());
        assert_eq!(digest, digest_reset);

        // Hash different data
        hasher.update(b"hello mars");
        let digest_mars = hasher.finalize();
        assert!(H::Digest::decode(digest_mars.as_ref()).is_ok());
        assert_ne!(digest, digest_mars);
    }

    fn test_hasher_multiple_updates<H: Hasher>() {
        // Generate initial hash
        let mut hasher = H::new();
        hasher.update(b"hello");
        hasher.update(b" world");
        let digest = hasher.finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());

        // Generate hash in oneshot
        let mut hasher = H::new();
        hasher.update(b"hello world");
        let digest_oneshot = hasher.finalize();
        assert!(H::Digest::decode(digest_oneshot.as_ref()).is_ok());
        assert_eq!(digest, digest_oneshot);
    }

    fn test_hasher_empty_input<H: Hasher>() {
        let mut hasher = H::new();
        let digest = hasher.finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
    }

    fn test_hasher_large_input<H: Hasher>() {
        let mut hasher = H::new();
        let data = vec![1; 1024];
        hasher.update(&data);
        let digest = hasher.finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
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
