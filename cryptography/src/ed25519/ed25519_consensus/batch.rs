//! Performs batch Ed25519 signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!
//! In addition to these general tradeoffs, design flaws in Ed25519 specifically
//! mean that batched verification may not agree with individual verification.
//! Some signatures may verify as part of a batch but not on their own.
//! This problem is fixed by [ZIP215], a precise specification for edge cases
//! in Ed25519 signature validation that ensures that batch verification agrees
//! with individual verification in all cases.
//!
//! This crate implements ZIP215, so batch verification always agrees with
//! individual verification, but this is not guaranteed by other implementations.
//! **Be extremely careful when using Ed25519 in a consensus-critical context
//! like a blockchain.**
//!
//! This batch verification implementation is adaptive in the sense that it
//! detects multiple signatures created with the same verification key and
//! automatically coalesces terms in the final verification equation. In the
//! limiting case where all signatures in the batch are made with the same
//! verification key, coalesced batch verification runs twice as fast as ordinary
//! batch verification.
//!
//! ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
//!
//! This optimization doesn't help much when public keys are random,
//! but could be useful in proof-of-stake systems where signatures come from a
//! set of validators (provided that system uses the ZIP215 rules).
//!
//! # Example
//! ```
//! # use commonware_cryptography::ed25519::ed25519_consensus::*;
//! let mut batch = batch::Verifier::new();
//! for _ in 0..32 {
//!     let sk = SigningKey::new(rand::thread_rng());
//!     let vk = VerificationKey::from(&sk);
//!     let msg = b"BatchVerifyTest";
//!     let sig = sk.sign(&msg[..]);
//!     batch.queue(vk, sig, &msg[..]);
//! }
//! assert!(batch.verify(rand::thread_rng()).is_ok());
//! ```
//!
//! [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst

use super::{Error, Signature, VerificationKey, VerificationKeyBytes};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Sha512};
use std::{collections::HashMap, convert::TryFrom};

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

fn compute_k<M: AsRef<[u8]> + ?Sized>(vk_bytes: &[u8; 32], sig: &Signature, msg: &M) -> Scalar {
    Scalar::from_hash(
        Sha512::default()
            .chain(&sig.R_bytes[..])
            .chain(vk_bytes)
            .chain(msg),
    )
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[derive(Clone, Debug)]
pub struct Item {
    vk_bytes: VerificationKeyBytes,
    sig: Signature,
    k: Scalar,
}

impl<'msg, M: AsRef<[u8]> + ?Sized> From<(VerificationKeyBytes, Signature, &'msg M)> for Item {
    fn from(tup: (VerificationKeyBytes, Signature, &'msg M)) -> Self {
        let (vk_bytes, sig, msg) = tup;
        let k = compute_k(vk_bytes.as_bytes(), &sig, msg);
        Self { vk_bytes, sig, k }
    }
}

impl Item {
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing fallback
    /// logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](super::VerificationKey::verify), which requires
    /// borrowing the message data, the `Item` type is unlinked from the lifetime of
    /// the message.
    pub fn verify_single(self) -> Result<(), Error> {
        VerificationKey::try_from(self.vk_bytes)
            .and_then(|vk| vk.verify_prehashed(&self.sig, self.k))
    }
}

struct Entry {
    key: Option<VerificationKey>,
    signatures: Vec<(Scalar, Signature)>,
}

impl Entry {
    fn new() -> Self {
        Self {
            key: None,
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            signatures: Vec::with_capacity(1),
        }
    }
}

/// A batch verification context.
#[derive(Default)]
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: HashMap<VerificationKeyBytes, Entry>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a `(key, signature, message)` tuple for verification.
    pub fn queue<M: AsRef<[u8]> + ?Sized>(
        &mut self,
        key: VerificationKey,
        sig: Signature,
        msg: &M,
    ) {
        let item = Item {
            vk_bytes: VerificationKeyBytes::from(key),
            k: compute_k(key.as_bytes(), &sig, msg),
            sig,
        };
        self.queue_inner(item, Some(key));
    }

    /// Queue an item without a pre-decompressed verification key.
    ///
    /// This path only accepts [`Item`] values or tuples built from
    /// [`VerificationKeyBytes`].
    pub fn queue_raw<I: Into<Item>>(&mut self, item: I) {
        self.queue_inner(item.into(), None);
    }

    fn queue_inner(&mut self, item: Item, key: Option<VerificationKey>) {
        let Item { vk_bytes, sig, k } = item;
        let key = key.filter(|key| key.as_bytes() == vk_bytes.as_bytes());

        let entry = self.signatures.entry(vk_bytes).or_insert_with(Entry::new);

        if entry.key.is_none() {
            entry.key = key;
        }

        entry.signatures.push((k, sig));
        self.batch_size += 1;
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// # Warning
    ///
    /// Ed25519 has different verification rules for batched and non-batched
    /// verifications. This function does not have the same verification criteria
    /// as individual verification, which may reject some signatures this method
    /// accepts.
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        // The batch verification equation is
        //
        // [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
        //
        // where for each signature i,
        // - A_i is the verification key;
        // - R_i is the signature's R value;
        // - s_i is the signature's s value;
        // - k_i is the hash of the message and other data;
        // - z_i is a random 128-bit Scalar.
        //
        // Normally n signatures would require a multiscalar multiplication of
        // size 2*n + 1, together with 2*n point decompressions (to obtain A_i
        // and R_i). However, because we store batch entries in a HashMap
        // indexed by the verification key, we can "coalesce" all z_i * k_i
        // terms for each distinct verification key into a single coefficient.
        //
        // For n signatures from m verification keys, this approach instead
        // requires a multiscalar multiplication of size n + m + 1 together with
        // n + m point decompressions. When m = n, so all signatures are from
        // distinct verification keys, this is as efficient as the usual method.
        // However, when m = 1 and all signatures are from a single verification
        // key, this is nearly twice as fast.

        let m = self.signatures.len();

        let mut A_coeffs = Vec::with_capacity(m);
        let mut As = Vec::with_capacity(m);
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);
        let mut B_coeff = Scalar::ZERO;

        for (vk_bytes, entry) in self.signatures.iter() {
            let A = entry
                .key
                .map(|vk| -vk.minus_A)
                .or_else(|| CompressedEdwardsY(vk_bytes.0).decompress())
                .ok_or(Error::InvalidSignature)?;

            let mut A_coeff = Scalar::ZERO;

            for (k, sig) in entry.signatures.iter() {
                let R = CompressedEdwardsY(sig.R_bytes)
                    .decompress()
                    .ok_or(Error::InvalidSignature)?;
                let s = Scalar::from_canonical_bytes(sig.s_bytes)
                    .into_option()
                    .ok_or(Error::InvalidSignature)?;
                let z = Scalar::from(gen_u128(&mut rng));
                B_coeff -= z * s;
                Rs.push(R);
                R_coeffs.push(z);
                A_coeff += z * k;
            }

            As.push(A);
            A_coeffs.push(A_coeff);
        }

        use core::iter::once;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
        let check = EdwardsPoint::vartime_multiscalar_mul(
            once(&B_coeff).chain(A_coeffs.iter()).chain(R_coeffs.iter()),
            once(&B).chain(As.iter()).chain(Rs.iter()),
        );

        if check.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::ed25519_consensus::SigningKey;
    use commonware_utils::test_rng;
    use rstest::rstest;

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn verify_accepts_mixed_key_representations(#[case] queue_verification_key_first: bool) {
        let mut rng = test_rng();
        let mut batch = Verifier::new();
        let signer = SigningKey::new(&mut rng);
        let vk = signer.verification_key();
        let vk_bytes = VerificationKeyBytes::from(vk);

        let first_message = b"first";
        let second_message = b"second";
        let first_signature = signer.sign(first_message);
        let second_signature = signer.sign(second_message);

        if queue_verification_key_first {
            batch.queue(vk, first_signature, &first_message[..]);
            batch.queue_raw((vk_bytes, second_signature, &second_message[..]));
        } else {
            batch.queue_raw((vk_bytes, first_signature, &first_message[..]));
            batch.queue(vk, second_signature, &second_message[..]);
        }

        assert!(batch.verify(&mut rng).is_ok());
    }

    #[test]
    fn verify_accepts_raw_key_representations() {
        let mut rng = test_rng();
        let mut batch = Verifier::new();
        let signer = SigningKey::new(&mut rng);
        let vk_bytes = VerificationKeyBytes::from(signer.verification_key());

        let first_message = b"first";
        let second_message = b"second";
        let first_signature = signer.sign(first_message);
        let second_signature = signer.sign(second_message);

        batch.queue_raw((vk_bytes, first_signature, &first_message[..]));
        batch.queue_raw((vk_bytes, second_signature, &second_message[..]));

        assert!(batch.verify(&mut rng).is_ok());
    }

    #[test]
    fn verify_accepts_predecompressed_key_representations() {
        let mut rng = test_rng();
        let mut batch = Verifier::new();
        let signer = SigningKey::new(&mut rng);
        let vk = signer.verification_key();

        let first_message = b"first";
        let second_message = b"second";
        let first_signature = signer.sign(first_message);
        let second_signature = signer.sign(second_message);

        batch.queue(vk, first_signature, &first_message[..]);
        batch.queue(vk, second_signature, &second_message[..]);

        assert!(batch.verify(&mut rng).is_ok());
    }
}
