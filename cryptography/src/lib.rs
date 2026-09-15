//! Generate keys, sign arbitrary messages, and deterministically verify signatures.
//!
//! # Randomness
//!
//! Cryptographic operations that accept an RNG require a cryptographically secure and
//! unpredictable source unless documented otherwise. A weak or predictable RNG may compromise
//! security.
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
#[cfg(all(
    feature = "bls12381",
    not(any(
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    ))
))] // BETA
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

    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;

    pub mod lthash;
    pub use crate::lthash::LtHash;

    pub mod reed_solomon;

    pub mod zk;
});
commonware_macros::stability_scope!(BETA {
    #[cfg(not(feature = "std"))]
    use alloc::{sync::Arc, vec::Vec};
    use commonware_codec::{Encode, ReadExt};
    use commonware_math::algebra::Random;
    use commonware_parallel::Strategy;
    use commonware_utils::Array;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, SeedableRng as _};
    #[cfg(feature = "std")]
    use std::{sync::Arc, vec::Vec};

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
            Self::random(ChaCha20Rng::seed_from_u64(seed))
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

        /// Create a new batch verifier with capacity for at least `capacity` items.
        ///
        /// The capacity is a hint: more than `capacity` items may be added, and
        /// implementations may ignore it.
        fn new(capacity: usize) -> Self;

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
        /// Returns `false` if no items were added or any item is invalid.
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
        fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> bool;
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

    impl<T: Digestible> Digestible for Arc<T> {
        type Digest = T::Digest;

        fn digest(&self) -> Self::Digest {
            self.as_ref().digest()
        }
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

    const HASH_BATCH_SIZE: usize = 16;

    #[inline]
    const fn message_work(len: usize) -> usize {
        len.saturating_add(1)
    }

    /// Split estimated work into ordered ranges while leaving at least one message
    /// for each remaining worker. Individual messages are never divided.
    fn hash_ranges<M: AsRef<[u8]>, W: Fn(usize) -> usize>(
        messages: &[M],
        parallelism: usize,
        work: &W,
    ) -> Vec<core::ops::Range<usize>> {
        let workers = parallelism.max(1).min(messages.len());
        let total = messages
            .iter()
            .fold(0u128, |sum, message| sum + work(message.as_ref().len()) as u128);
        let workers_u128 = workers as u128;
        let per_worker = total / workers_u128;
        let extra = total % workers_u128;
        let mut ranges = Vec::with_capacity(workers);
        let mut start = 0;
        let mut end = 0;
        let mut covered_work = 0u128;
        let mut target_work = 0u128;

        for worker in 0..workers - 1 {
            target_work += per_worker + u128::from((worker as u128) < extra);
            let remaining_workers = workers - worker - 1;
            let max_end = messages.len() - remaining_workers;
            loop {
                covered_work += work(messages[end].as_ref().len()) as u128;
                end += 1;
                if covered_work >= target_work || end == max_end {
                    break;
                }
            }
            ranges.push(start..end);
            start = end;
        }
        ranges.push(start..messages.len());
        ranges
    }

    fn hash_pairs_into<H: Hasher, M: AsRef<[u8]>>(messages: &[M], digests: &mut Vec<H::Digest>) {
        let (pairs, remainder) = messages.as_chunks::<2>();
        for pair in pairs {
            let (left, right) = H::hash_pair(&[pair[0].as_ref()], &[pair[1].as_ref()]);
            digests.push(left);
            digests.push(right);
        }
        if let [message] = remainder {
            digests.push(H::hash(&[message.as_ref()]));
        }
    }

    fn hash_span<H, M, F>(
        messages: &[M],
        hash_x16: &F,
        x16_minimum: Option<usize>,
    ) -> Vec<H::Digest>
    where
        H: Hasher,
        M: AsRef<[u8]>,
        F: for<'a> Fn([&'a [u8]; HASH_BATCH_SIZE]) -> Option<[H::Digest; HASH_BATCH_SIZE]>,
    {
        let mut digests = Vec::with_capacity(messages.len());
        let Some(minimum) = x16_minimum else {
            hash_pairs_into::<H, _>(messages, &mut digests);
            return digests;
        };

        for run in messages.chunk_by(|left, right| left.as_ref().len() == right.as_ref().len()) {
            for batch in run.chunks(HASH_BATCH_SIZE) {
                if batch.len() >= minimum {
                    // Spare lanes borrow the first input; only active lanes contribute output.
                    let mut inputs = [batch[0].as_ref(); HASH_BATCH_SIZE];
                    for (input, message) in inputs[1..].iter_mut().zip(&batch[1..]) {
                        *input = message.as_ref();
                    }
                    if let Some(batch_digests) = hash_x16(inputs) {
                        digests.extend_from_slice(&batch_digests[..batch.len()]);
                        continue;
                    }
                }
                hash_pairs_into::<H, _>(batch, &mut digests);
            }
        }
        digests
    }

    #[track_caller]
    fn hash_many_with<H, M, S, F, W>(
        messages: &[M],
        strategy: &S,
        hash_x16: F,
        x16_minimum: Option<usize>,
        message_work: W,
    ) -> Vec<H::Digest>
    where
        H: Hasher,
        M: AsRef<[u8]> + Sync,
        S: Strategy,
        F: for<'a> Fn([&'a [u8]; HASH_BATCH_SIZE]) -> Option<[H::Digest; HASH_BATCH_SIZE]>
            + Send
            + Sync,
        W: Fn(usize) -> usize + Sync,
    {
        if messages.is_empty() {
            return Vec::new();
        }

        let work = messages.iter().fold(0usize, |sum, message| {
            sum.saturating_add(message_work(message.as_ref().len()))
        });
        strategy.run(
            work,
            || hash_span::<H, _, _>(messages, &hash_x16, x16_minimum),
            || {
                let manual = strategy.manual();
                let ranges = hash_ranges(messages, manual.parallelism(), &message_work);
                manual
                    .map_collect_vec(ranges, |range| {
                        hash_span::<H, _, _>(&messages[range], &hash_x16, x16_minimum)
                    })
                    .into_iter()
                    .flatten()
                    .collect()
            },
        )
    }

    /// Interface that commonware crates rely on for hashing.
    ///
    /// Hash functions in commonware primitives are not typically hardcoded
    /// to a specific algorithm (e.g. SHA-256) because different hash functions
    /// may work better with different cryptographic schemes, may be more efficient
    /// to use in STARK/SNARK proofs, or provide different levels of security (with some
    /// performance/size penalty).
    ///
    /// Hashers are cheap to construct: callers that need a fresh hasher should
    /// create one with [`Default`] rather than duplicating an existing instance.
    pub trait Hasher: Default + Send + Sync + 'static {
        /// Digest generated by the hasher.
        type Digest: Digest;

        /// Hash the concatenation of `parts` in a single shot.
        ///
        /// This is the preferred entrypoint for hashing data that is fully
        /// available up-front. Implementations are free to specialize this for
        /// small, fixed-shape inputs (e.g. hashing a pair of digests) to avoid
        /// the overhead of the streaming machinery.
        fn hash(parts: &[&[u8]]) -> Self::Digest;

        /// Hash two messages, each given as a concatenation of parts, in a
        /// single shot.
        ///
        /// Must be equivalent to hashing each message with [`Hasher::hash`].
        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest);

        /// Hash multiple independent byte slices.
        ///
        /// Returns one digest per input in the same order. Inputs may be empty,
        /// differ in length, or overlap. Output position `i` is equivalent to
        /// `Self::hash(&[messages[i].as_ref()])`.
        /// Implementations may accelerate supported batches, and `strategy`
        /// selects between serial and parallel execution.
        #[track_caller]
        fn hash_many<M: AsRef<[u8]> + Sync>(
            messages: &[M],
            strategy: &impl Strategy,
        ) -> Vec<Self::Digest> {
            hash_many_with::<Self, _, _, _, _>(messages, strategy, |_| None, None, message_work)
        }

        /// Append `bytes` to the hasher's running state.
        fn update(&mut self, bytes: &[u8]) -> &mut Self;

        /// Consume the hasher, returning a freshly-reset hasher alongside the
        /// digest of everything written so far.
        fn finalize(self) -> (Self, Self::Digest);
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_parallel::{Rayon, Sequential, Strategy};
    use commonware_utils::{NZUsize, test_rng};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SINGLE_HASHES: AtomicUsize = AtomicUsize::new(0);
    static PAIRED_HASHES: AtomicUsize = AtomicUsize::new(0);
    static X16_HASHES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Default)]
    struct CountingHasher(Sha256);

    impl Hasher for CountingHasher {
        type Digest = <Sha256 as Hasher>::Digest;

        fn hash(parts: &[&[u8]]) -> Self::Digest {
            SINGLE_HASHES.fetch_add(1, Ordering::Relaxed);
            Sha256::hash(parts)
        }

        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            PAIRED_HASHES.fetch_add(1, Ordering::Relaxed);
            Sha256::hash_pair(left, right)
        }

        fn update(&mut self, bytes: &[u8]) -> &mut Self {
            self.0.update(bytes);
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            let (hasher, digest) = self.0.finalize();
            (Self(hasher), digest)
        }
    }

    fn reset_hash_counts() {
        SINGLE_HASHES.store(0, Ordering::Relaxed);
        PAIRED_HASHES.store(0, Ordering::Relaxed);
        X16_HASHES.store(0, Ordering::Relaxed);
    }

    fn simulated_hash_x16(
        batch: [&[u8]; HASH_BATCH_SIZE],
    ) -> Option<[<Sha256 as Hasher>::Digest; HASH_BATCH_SIZE]> {
        if batch.iter().any(|message| message.len() != batch[0].len()) {
            return None;
        }
        X16_HASHES.fetch_add(1, Ordering::Relaxed);
        Some(batch.map(|message| Sha256::hash(&[message])))
    }

    fn test_validate<C: PrivateKey>() {
        let private_key = C::random(test_rng());
        let public_key = private_key.public_key();
        assert!(C::PublicKey::decode(commonware_codec::Copying(public_key.as_ref())).is_ok());
    }

    fn test_validate_invalid_public_key<C: Signer>() {
        let result = C::PublicKey::decode(vec![0; 1024]);
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
    #[cfg(feature = "bls12381")]
    fn test_bls12381_validate() {
        test_validate::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_validate_invalid_public_key() {
        test_validate_invalid_public_key::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_sign_and_verify() {
        test_sign_and_verify::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_sign_and_verify_wrong_message() {
        test_sign_and_verify_wrong_message::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_sign_and_verify_wrong_namespace() {
        test_sign_and_verify_wrong_namespace::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_empty_namespace() {
        test_empty_namespace::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_signature_determinism() {
        test_signature_determinism::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
    fn test_bls12381_invalid_signature_publickey_pair() {
        test_invalid_signature_publickey_pair::<bls12381::PrivateKey>();
    }

    #[test]
    #[cfg(feature = "bls12381")]
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
        let mut hasher = H::default();
        hasher.update(b"hello world");
        let (hasher, digest) = hasher.finalize();
        assert!(H::Digest::decode(commonware_codec::Copying(digest.as_ref())).is_ok());
        assert_eq!(digest.as_ref().len(), H::Digest::SIZE);

        // Reuse the reset hasher returned by finalize
        let mut hasher = hasher;
        hasher.update(b"hello world");
        let (hasher, digest_again) = hasher.finalize();
        assert!(H::Digest::decode(commonware_codec::Copying(digest_again.as_ref())).is_ok());
        assert_eq!(digest, digest_again);

        // Hash via the one-shot API
        let digest_oneshot = H::hash(&[b"hello world"]);
        assert!(H::Digest::decode(commonware_codec::Copying(digest_oneshot.as_ref())).is_ok());
        assert_eq!(digest, digest_oneshot);

        // Hash different data
        let mut hasher = hasher;
        hasher.update(b"hello mars");
        let (_, digest_mars) = hasher.finalize();
        assert!(H::Digest::decode(commonware_codec::Copying(digest_mars.as_ref())).is_ok());
        assert_ne!(digest, digest_mars);
    }

    #[test]
    fn test_sha256_hasher_multiple_runs() {
        test_hasher_multiple_runs::<Sha256>();
    }

    #[test]
    fn hash_many_preserves_default_and_parallel_work_shapes() {
        let messages = (0..5)
            .map(|index| vec![index as u8; index + 1])
            .collect::<Vec<_>>();
        reset_hash_counts();
        let actual = CountingHasher::hash_many(&messages, &Sequential);
        let expected = messages
            .iter()
            .map(|message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(SINGLE_HASHES.load(Ordering::Relaxed), 1);
        assert_eq!(PAIRED_HASHES.load(Ordering::Relaxed), 2);
        assert_eq!(X16_HASHES.load(Ordering::Relaxed), 0);

        for (minimum, count) in [2, 7]
            .into_iter()
            .flat_map(|minimum| (0..=32).map(move |count| (minimum, count)))
        {
            let messages = (0..count)
                .map(|lane| vec![lane as u8; 128])
                .collect::<Vec<_>>();
            reset_hash_counts();
            let actual = hash_many_with::<CountingHasher, _, _, _, _>(
                &messages,
                &Sequential,
                simulated_hash_x16,
                Some(minimum),
                message_work,
            );
            let expected = messages
                .iter()
                .map(|message| Sha256::hash(&[message]))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
            let remainder = count % HASH_BATCH_SIZE;
            let wide = count / HASH_BATCH_SIZE + usize::from(remainder >= minimum);
            let narrow = if remainder < minimum { remainder } else { 0 };
            assert_eq!(
                X16_HASHES.load(Ordering::Relaxed),
                wide,
                "count={count}, minimum={minimum}",
            );
            assert_eq!(PAIRED_HASHES.load(Ordering::Relaxed), narrow / 2);
            assert_eq!(SINGLE_HASHES.load(Ordering::Relaxed), narrow % 2);
        }

        let messages = (0..18)
            .map(|index| vec![index as u8; 128])
            .collect::<Vec<_>>();
        reset_hash_counts();
        let actual = hash_many_with::<CountingHasher, _, _, _, _>(
            &messages,
            &Sequential,
            simulated_hash_x16,
            Some(7),
            message_work,
        );
        let expected = messages
            .iter()
            .map(|message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(SINGLE_HASHES.load(Ordering::Relaxed), 0);
        assert_eq!(PAIRED_HASHES.load(Ordering::Relaxed), 1);
        assert_eq!(X16_HASHES.load(Ordering::Relaxed), 1);

        let messages = (0..144)
            .map(|index| vec![index as u8; 128])
            .collect::<Vec<_>>();
        let ranges = hash_ranges(&messages, 8, &message_work);
        assert_eq!(
            ranges.iter().map(|range| range.len()).collect::<Vec<_>>(),
            vec![18; 8]
        );

        reset_hash_counts();
        let strategy = Rayon::new(NZUsize!(8)).unwrap().manual();
        let actual = hash_many_with::<CountingHasher, _, _, _, _>(
            &messages,
            &strategy,
            simulated_hash_x16,
            Some(7),
            message_work,
        );
        let expected = messages
            .iter()
            .map(|message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(SINGLE_HASHES.load(Ordering::Relaxed), 0);
        assert_eq!(PAIRED_HASHES.load(Ordering::Relaxed), 8);
        assert_eq!(X16_HASHES.load(Ordering::Relaxed), 8);

        for prefix in 0..=17 {
            let messages = (0..prefix)
                .map(|index| vec![index as u8; 32])
                .chain((0..16).map(|index| vec![(prefix + index) as u8; 128]))
                .collect::<Vec<_>>();
            reset_hash_counts();
            let actual = hash_many_with::<CountingHasher, _, _, _, _>(
                &messages,
                &Sequential,
                simulated_hash_x16,
                Some(7),
                message_work,
            );
            let expected = messages
                .iter()
                .map(|message| Sha256::hash(&[message]))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
            assert_eq!(
                X16_HASHES.load(Ordering::Relaxed),
                1 + prefix / HASH_BATCH_SIZE + usize::from(prefix % HASH_BATCH_SIZE >= 7),
                "prefix length {prefix}",
            );
        }
    }

    #[test]
    fn hash_ranges_cover_uneven_messages_in_order() {
        let messages = [vec![0; 1_000], vec![], vec![1], vec![2; 64], vec![3; 2]];
        for parallelism in 1..=8 {
            let ranges = hash_ranges(&messages, parallelism, &message_work);
            assert_eq!(ranges.len(), parallelism.min(messages.len()));
            assert!(ranges.iter().all(|range| !range.is_empty()));
            assert_eq!(ranges.first().unwrap().start, 0);
            assert_eq!(ranges.last().unwrap().end, messages.len());
            assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
        }
    }
}
