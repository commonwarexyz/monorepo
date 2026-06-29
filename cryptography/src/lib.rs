//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Modules containing #[macro_export] macros must use verbose cfg.
// See rust-lang/rust#52234: macro-expanded macro_export macros cannot be referenced by absolute paths.
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
pub mod bls12381;
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
pub mod ed25519;
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // ALPHA
pub mod secp256r1;

commonware_macros::stability_scope!(ALPHA {
    #[cfg(feature = "std")]
    pub mod banderwagon;
    pub mod bloomfilter;
    pub use crate::bloomfilter::BloomFilter;

    pub mod lthash;
    pub use crate::lthash::LtHash;

    pub mod reed_solomon;

    pub mod zk;
});
commonware_macros::stability_scope!(BETA {
    use commonware_codec::{Encode, ReadExt};
    use commonware_math::algebra::Random;
    use commonware_parallel::Strategy;
    use commonware_utils::Array;
    use rand::SeedableRng as _;
    use rand_chacha::ChaCha20Rng;
    use rand_core::CryptoRngCore;

    pub mod secret;
    pub use crate::secret::Secret;

    pub mod certificate;
    pub mod transcript;

    pub mod sha256;
    pub use crate::sha256::{CoreSha256, Sha256};
    pub mod blake3;
    pub use crate::blake3::{Blake3, CoreBlake3};
    #[cfg(feature = "std")]
    pub mod crc32;
    #[cfg(feature = "std")]
    pub use crate::crc32::Crc32;

    #[cfg(feature = "std")]
    pub mod handshake;

    /// Produces [Signature]s over messages that can be verified with a corresponding [PublicKey].
    pub trait Signer: Random + Send + Sync + Clone + 'static {
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

        /// Create a [Signer] from a seed.
        ///
        /// # Warning
        ///
        /// This function is insecure and should only be used for examples
        /// and testing.
        fn from_seed(seed: u64) -> Self {
            Self::random(&mut ChaCha20Rng::seed_from_u64(seed))
        }
    }

    /// A [Signer] that can be serialized/deserialized.
    pub trait PrivateKey: Signer + Sized + ReadExt + Encode {}

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
    pub trait BatchVerifier {
        /// The type of public keys that this verifier can accept.
        type PublicKey: PublicKey;

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
            public_key: &Self::PublicKey,
            signature: &<Self::PublicKey as Verifier>::Signature,
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
        fn verify<R: CryptoRngCore>(self, rng: &mut R, strategy: &impl Strategy) -> bool;
    }

    /// Specializes the [commonware_utils::Array] trait with the Copy trait for cryptographic digests
    /// (which should be cheap to clone).
    ///
    /// # Warning
    ///
    /// This trait requires [`Random::random`], but generating a digest at random is
    /// typically reserved for testing, and not production use.
    pub trait Digest: Array + Copy + Random {
        /// An empty (all-zero) digest.
        const EMPTY: Self;
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

    /// In-progress hash state.
    ///
    /// If this value is dropped before [Pending::finalize] is called, the borrowed hasher is reset.
    #[must_use = "call finalize() to obtain the digest"]
    pub struct Pending<'a, H: Hasher> {
        hasher: &'a mut H,
        finalized: bool,
    }

    impl<H: Hasher> Pending<'_, H> {
        /// Append message to previously recorded data.
        #[inline]
        pub fn update(&mut self, message: &[u8]) -> &mut Self {
            assert!(!self.finalized, "pending hash already finalized");
            self.hasher.update_inner(message);
            self
        }

        /// Hash all recorded data and reset the hasher to the initial state.
        #[inline]
        pub fn finalize(mut self) -> H::Digest {
            assert!(!self.finalized, "pending hash already finalized");
            let digest = self.hasher.finalize_inner();
            self.finalized = true;
            digest
        }
    }

    impl<H: Hasher> Drop for Pending<'_, H> {
        fn drop(&mut self) {
            if !self.finalized {
                self.hasher.reset();
            }
        }
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
    /// clone the hasher state but users should not rely on this behavior.
    pub trait Hasher: Default + Clone + Send + Sync + 'static {
        /// Digest generated by the hasher.
        type Digest: Digest;

        /// Create a new, empty hasher.
        fn new() -> Self {
            Self::default()
        }

        /// Append message to a new hash.
        ///
        /// The returned [Pending] state holds a mutable reference to the hasher until it is
        /// finalized or dropped.
        #[inline]
        fn update(&mut self, message: &[u8]) -> Pending<'_, Self> {
            let mut pending = self.pending();
            pending.update(message);
            pending
        }

        /// Start a new empty hash.
        ///
        /// The returned [Pending] state holds a mutable reference to the hasher until it is
        /// finalized or dropped.
        #[inline]
        fn pending(&mut self) -> Pending<'_, Self> {
            Pending {
                hasher: self,
                finalized: false,
            }
        }

        /// Append message to the current hash state.
        #[doc(hidden)]
        fn update_inner(&mut self, message: &[u8]);

        /// Hash all recorded data and reset the hasher to the initial state.
        #[doc(hidden)]
        fn finalize_inner(&mut self) -> Self::Digest;

        /// Reset the hasher without generating a hash.
        ///
        /// This function does not need to be called after `finalize`.
        fn reset(&mut self) -> &mut Self;

        /// Hash a single message with a one-time-use hasher.
        fn hash(message: &[u8]) -> Self::Digest {
            Self::new().update(message).finalize()
        }
    }

    /// Extension methods for hashing encoded values and fixed preimages.
    pub trait CodecHasher: Hasher {
        /// Hash a sequence of byte slices as one contiguous message.
        ///
        /// The current hasher state is discarded before hashing, and the hasher is reset before
        /// returning.
        #[inline]
        fn hash_parts<'a>(&mut self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
            self.reset();
            let mut pending = self.pending();
            for part in parts {
                pending.update(part);
            }
            pending.finalize()
        }

        /// Hash an encoded value as one contiguous message.
        #[inline]
        fn hash_encoded<E: Encode>(&mut self, value: &E) -> Self::Digest {
            let encoded = value.encode();
            self.hash_parts([encoded.as_ref()])
        }

        /// Hash a byte prefix followed by an encoded value as one contiguous message.
        #[inline]
        fn hash_prefixed<E: Encode>(&mut self, prefix: &[u8], value: &E) -> Self::Digest {
            let encoded = value.encode();
            self.hash_parts([prefix, encoded.as_ref()])
        }

        /// Hash an empty message.
        #[doc(hidden)]
        #[inline]
        fn hash_empty(&mut self) -> Self::Digest {
            self.hash_parts(core::iter::empty::<&[u8]>())
        }

        /// Hash a `u32` followed by a digest.
        #[doc(hidden)]
        #[inline]
        fn hash_u32_digest(&mut self, prefix: u32, digest: &Self::Digest) -> Self::Digest {
            self.hash_parts([prefix.to_be_bytes().as_slice(), digest.as_ref()])
        }

        /// Hash two digests.
        #[doc(hidden)]
        #[inline]
        fn hash_digest_pair(
            &mut self,
            left: &Self::Digest,
            right: &Self::Digest,
        ) -> Self::Digest {
            self.hash_parts([left.as_ref(), right.as_ref()])
        }

        /// Hash a `u64` followed by two digests.
        #[doc(hidden)]
        #[inline]
        fn hash_u64_digest_pair(
            &mut self,
            prefix: u64,
            left: &Self::Digest,
            right: &Self::Digest,
        ) -> Self::Digest {
            self.hash_parts([prefix.to_be_bytes().as_slice(), left.as_ref(), right.as_ref()])
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_utils::test_rng;

    macro_rules! hasher {
        ($h:ty $(,)?) => {{
            let mut hasher = <$h>::new();
            hasher.pending().finalize()
        }};
        ($h:ty, $($part:expr),+ $(,)?) => {{
            let mut hasher = <$h>::new();
            let mut pending = hasher.pending();
            $(
                pending.update($part);
            )+
            pending.finalize()
        }};
    }

    fn test_validate<C: PrivateKey>() {
        let private_key = C::random(&mut test_rng());
        let public_key = private_key.public_key();
        assert!(C::PublicKey::decode(public_key.as_ref()).is_ok());
    }

    fn test_validate_invalid_public_key<C: Signer>() {
        let result = C::PublicKey::decode(vec![0; 1024].as_ref());
        assert!(result.is_err());
    }

    fn test_sign_and_verify<C: PrivateKey>() {
        let private_key = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(public_key.verify(namespace, message, &signature));
    }

    fn test_sign_and_verify_wrong_message<C: PrivateKey>() {
        let private_key = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let wrong_message = b"wrong_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(!public_key.verify(namespace, wrong_message, &signature));
    }

    fn test_sign_and_verify_wrong_namespace<C: PrivateKey>() {
        let private_key = C::from_seed(0);
        let namespace = b"test_namespace";
        let wrong_namespace = b"wrong_namespace";
        let message = b"test_message";
        let signature = private_key.sign(namespace, message);
        let public_key = private_key.public_key();
        assert!(!public_key.verify(wrong_namespace, message, &signature));
    }

    fn test_empty_namespace<C: PrivateKey>() {
        let private_key = C::from_seed(0);
        let empty_namespace = b"";
        let message = b"test_message";
        let signature = private_key.sign(empty_namespace, message);
        let public_key = private_key.public_key();
        assert!(public_key.verify(empty_namespace, message, &signature));
    }

    fn test_signature_determinism<C: PrivateKey>() {
        let private_key_1 = C::from_seed(0);
        let private_key_2 = C::from_seed(0);
        let namespace = b"test_namespace";
        let message = b"test_message";
        let signature_1 = private_key_1.sign(namespace, message);
        let signature_2 = private_key_2.sign(namespace, message);
        assert_eq!(private_key_1.public_key(), private_key_2.public_key());
        assert_eq!(signature_1, signature_2);
    }

    fn test_invalid_signature_publickey_pair<C: PrivateKey>() {
        let private_key = C::from_seed(0);
        let private_key_2 = C::from_seed(1);
        let namespace = b"test_namespace";
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
        let digest = hasher.update(b"hello world").finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref().len(), H::Digest::SIZE);

        // Reuse hasher without reset
        let digest_again = hasher.update(b"hello world").finalize();
        assert!(H::Digest::decode(digest_again.as_ref()).is_ok());
        assert_eq!(digest, digest_again);

        // Reuse hasher with reset
        drop(hasher.update(b"hello mars"));
        hasher.reset();
        let digest_reset = hasher.update(b"hello world").finalize();
        assert!(H::Digest::decode(digest_reset.as_ref()).is_ok());
        assert_eq!(digest, digest_reset);

        // Hash different data
        let digest_mars = hasher.update(b"hello mars").finalize();
        assert!(H::Digest::decode(digest_mars.as_ref()).is_ok());
        assert_ne!(digest, digest_mars);
    }

    fn test_hasher_multiple_updates<H: Hasher>() {
        // Generate initial hash
        let mut hasher = H::new();
        let mut pending = hasher.update(b"hello");
        pending.update(b" world");
        let digest = pending.finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());

        // Generate hash in oneshot
        let mut hasher = H::new();
        let digest_oneshot = hasher.update(b"hello world").finalize();
        assert!(H::Digest::decode(digest_oneshot.as_ref()).is_ok());
        assert_eq!(digest, digest_oneshot);
    }

    fn test_hasher_empty_input<H: Hasher>() {
        let mut hasher = H::new();
        let digest = hasher.pending().finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
    }

    fn test_hasher_large_input<H: Hasher>() {
        let mut hasher = H::new();
        let data = vec![1; 1024];
        let digest = hasher.update(&data).finalize();
        assert!(H::Digest::decode(digest.as_ref()).is_ok());
    }

    fn test_codec_hasher_manual_equivalence<H: CodecHasher>() {
        let mut hasher = H::new();
        let first = b"hello".as_slice();
        let second = b" world".as_slice();
        assert_eq!(
            hasher.hash_parts([first, second]),
            hasher!(H, first, second)
        );

        drop(hasher.update(b"discarded"));
        assert_eq!(
            hasher.hash_parts([first, second]),
            hasher!(H, first, second)
        );

        let value = (1u32, 2u64);
        let encoded = value.encode();
        assert_eq!(hasher.hash_encoded(&value), hasher!(H, encoded.as_ref()));

        let prefix = b"prefix";
        assert_eq!(
            hasher.hash_prefixed(prefix, &value),
            hasher!(H, prefix, encoded.as_ref())
        );

        assert_eq!(hasher.hash_empty(), hasher!(H));

        let left = H::hash(b"left");
        let right = H::hash(b"right");
        let prefix32 = 7u32.to_be_bytes();
        assert_eq!(
            hasher.hash_u32_digest(7, &left),
            hasher!(H, prefix32.as_slice(), left.as_ref())
        );
        assert_eq!(
            hasher.hash_digest_pair(&left, &right),
            hasher!(H, left.as_ref(), right.as_ref())
        );

        let prefix64 = 9u64.to_be_bytes();
        assert_eq!(
            hasher.hash_u64_digest_pair(9, &left, &right),
            hasher!(H, prefix64.as_slice(), left.as_ref(), right.as_ref())
        );
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

    #[test]
    fn test_sha256_codec_hasher_manual_equivalence() {
        test_codec_hasher_manual_equivalence::<Sha256>();
    }

    #[test]
    fn test_blake3_codec_hasher_manual_equivalence() {
        test_codec_hasher_manual_equivalence::<Blake3>();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_crc32_codec_hasher_manual_equivalence() {
        test_codec_hasher_manual_equivalence::<Crc32>();
    }
}
