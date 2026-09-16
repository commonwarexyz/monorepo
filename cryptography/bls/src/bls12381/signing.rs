//! BLS signatures with public keys in G1 (MinPk) or G2 (MinSig).
//!
//! Callers supply the domain separation tag required by their BLS ciphersuite. Verification
//! consumes subgroup-checked group elements and rejects identity public keys and signatures.
//! Messages and domain tags are public inputs; hashing is variable time with respect to them.
//!
//! # Batch verification
//!
//! Batches must contain at least one signature. Per-signature input collections must have
//! equal lengths, and every public key and signature must be nonidentity. Duplicate entries
//! are accepted. Under the crate's [randomness requirement](crate#randomness), an invalid batch
//! is accepted with probability at most `2^-128`.

use crate::bls12381::{
    group::{EncodedScalar, G1, G2},
    scalar::Scalar,
};
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use core::fmt;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A nonzero BLS secret scalar.
///
/// Secret material is zeroized on drop. Its canonical 32-byte encoding is secret key material
/// and must be protected by the caller.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    scalar: Scalar,
}

impl SigningKey {
    /// Decodes a nonzero canonical big-endian scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let scalar = Zeroizing::new(Scalar::from_bytes(bytes)?);
        (!scalar.is_zero()).then_some(Self { scalar: *scalar })
    }

    /// Returns the canonical big-endian secret scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Samples a uniformly distributed nonzero secret scalar.
    pub fn random(mut rng: impl CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        loop {
            rng.fill_bytes(&mut bytes[..]);
            bytes[0] &= 0x7f;
            if let Some(key) = Self::from_bytes(&bytes) {
                return key;
            }
        }
    }

    /// Derives a key using the BLS HKDF-SHA256 KeyGen procedure used by `blst`.
    ///
    /// `ikm` must contain at least 32 bytes of secret, unpredictable input key material.
    /// `info` is an application-specific context string. Returns `None` when `ikm` is too short.
    pub fn key_gen(ikm: &[u8], info: &[u8]) -> Option<Self> {
        if ikm.len() < 32 {
            return None;
        }
        let mut salt: [u8; 32] = Sha256::digest(b"BLS-SIG-KEYGEN-SALT-").into();
        loop {
            let prk = hmac(&salt, &[ikm, &[0]]);
            let first = hmac(&prk, &[info, &[0, 48], &[1]]);
            let second = hmac(&prk, &[&first[..], info, &[0, 48], &[2]]);
            let mut wide = Zeroizing::new([0; 64]);
            wide[16..48].copy_from_slice(&first[..]);
            wide[48..].copy_from_slice(&second[..16]);
            let scalar = Zeroizing::new(Scalar::from_wide_bytes(&wide));
            if !scalar.is_zero() {
                return Some(Self { scalar: *scalar });
            }
            salt = Sha256::digest(salt).into();
        }
    }
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut block = Zeroizing::new([0; 64]);
    block[..32].copy_from_slice(key);
    for byte in block.iter_mut() {
        *byte ^= 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(&block[..]);
    for part in parts {
        inner.update(part);
    }
    let digest = Zeroizing::new(<[u8; 32]>::from(inner.finalize()));
    for byte in block.iter_mut() {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(&block[..]);
    outer.update(&digest[..]);
    Zeroizing::new(outer.finalize().into())
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl Write for SigningKey {
    fn write(&self, buf: &mut impl BufMut) {
        let bytes = Zeroizing::new(self.to_bytes());
        buf.put_slice(&bytes[..]);
    }
}

impl Read for SigningKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let bytes = Zeroizing::new(<[u8; 32]>::read_cfg(buf, &())?);
        Self::from_bytes(&bytes).ok_or(commonware_codec::Error::Invalid(
            "SigningKey",
            "Invalid secret scalar",
        ))
    }
}

impl FixedSize for SigningKey {
    const SIZE: usize = 32;
}

/// A structural or cryptographic batch-verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BatchError {
    /// No signatures were supplied.
    #[error("empty batch")]
    Empty,
    /// Public-key, message, and signature counts differ.
    #[error("batch input counts differ")]
    LengthMismatch,
    /// An original public key or signature is the identity.
    #[error("identity public key or signature")]
    Identity,
    /// The randomized aggregate pairing equation failed.
    #[error("batch signature equation failed")]
    InvalidSignature,
}

fn batch_coefficients(rng: &mut impl CryptoRng, count: usize) -> Vec<Scalar> {
    (0..count)
        .map(|_| {
            let mut bytes = Zeroizing::new([0; 32]);
            rng.fill_bytes(&mut bytes[16..]);
            Scalar::from_bytes(&bytes).expect("a 128-bit integer is below the scalar modulus")
        })
        .collect()
}

fn encoded_batch_coefficients(rng: &mut impl CryptoRng, count: usize) -> Vec<EncodedScalar> {
    (0..count)
        .map(|_| {
            let mut bytes = Zeroizing::new([0; 16]);
            rng.fill_bytes(&mut bytes[..]);
            EncodedScalar::from_batch_be_bytes(&bytes)
        })
        .collect()
}

fn validate_batch(
    count: usize,
    other_counts: &[usize],
    contains_identity: impl FnOnce() -> bool,
) -> Result<(), BatchError> {
    if other_counts.iter().any(|&other| other != count) {
        return Err(BatchError::LengthMismatch);
    }
    if count == 0 {
        return Err(BatchError::Empty);
    }
    if contains_identity() {
        return Err(BatchError::Identity);
    }
    Ok(())
}

fn prepare_batch(
    rng: &mut impl CryptoRng,
    count: usize,
    other_counts: &[usize],
    contains_identity: impl FnOnce() -> bool,
) -> Result<Vec<Scalar>, BatchError> {
    validate_batch(count, other_counts, contains_identity)?;
    Ok(batch_coefficients(rng, count))
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for SigningKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = Zeroizing::new(u.arbitrary()?);
        Self::from_bytes(&bytes).ok_or(arbitrary::Error::IncorrectFormat)
    }
}

/// BLS signatures in G2 with public keys in G1.
pub mod min_pk {
    use super::{BatchError, G1, G2, SigningKey, prepare_batch};
    use crate::bls12381::{hash::hash_to_g2, pairing::multi_pairing};
    use alloc::vec::Vec;
    use rand_core::CryptoRng;

    /// Derives the public key associated with this signing key.
    pub fn public_key(key: &SigningKey) -> G1 {
        G1::generator().mul(&key.scalar)
    }

    /// Signs a public message under the supplied ciphersuite domain separation tag.
    pub fn sign(key: &SigningKey, message: &[u8], dst: &[u8]) -> G2 {
        hash_to_g2(message, dst).mul(&key.scalar)
    }

    /// Verifies a signature, rejecting identity public keys and signatures.
    pub fn verify(public_key: &G1, message: &[u8], dst: &[u8], signature: &G2) -> bool {
        if public_key.is_identity() || signature.is_identity() {
            return false;
        }
        multi_pairing(&[
            (*public_key, hash_to_g2(message, dst)),
            (G1::generator().neg(), *signature),
        ])
        .is_identity()
    }

    /// Batch verifies signatures over independently selected messages.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify(
        rng: &mut impl CryptoRng,
        public_keys: &[G1],
        messages: &[&[u8]],
        dst: &[u8],
        signatures: &[G2],
    ) -> Result<(), BatchError> {
        let coefficients = prepare_batch(
            rng,
            public_keys.len(),
            &[messages.len(), signatures.len()],
            || public_keys.iter().any(G1::is_identity) || signatures.iter().any(G2::is_identity),
        )?;
        let aggregate_signature =
            G2::msm_vartime(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let mut pairs = Vec::with_capacity(public_keys.len() + 1);
        pairs.extend(public_keys.iter().zip(messages).zip(&coefficients).map(
            |((&public_key, &message), coefficient)| {
                (public_key.mul(coefficient), hash_to_g2(message, dst))
            },
        ));
        pairs.push((G1::generator().neg(), aggregate_signature));
        multi_pairing(&pairs)
            .is_identity()
            .then_some(())
            .ok_or(BatchError::InvalidSignature)
    }

    /// Batch verifies signatures by different keys over one message, hashing the message once.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify_same_message(
        rng: &mut impl CryptoRng,
        public_keys: &[G1],
        message: &[u8],
        dst: &[u8],
        signatures: &[G2],
    ) -> Result<(), BatchError> {
        let coefficients = prepare_batch(rng, public_keys.len(), &[signatures.len()], || {
            public_keys.iter().any(G1::is_identity) || signatures.iter().any(G2::is_identity)
        })?;
        let public_key =
            G1::msm_vartime(public_keys, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let signature =
            G2::msm_vartime(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        multi_pairing(&[
            (public_key, hash_to_g2(message, dst)),
            (G1::generator().neg(), signature),
        ])
        .is_identity()
        .then_some(())
        .ok_or(BatchError::InvalidSignature)
    }

    /// Batch verifies signatures by one key over different messages.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify_same_signer(
        rng: &mut impl CryptoRng,
        public_key: &G1,
        messages: &[&[u8]],
        dst: &[u8],
        signatures: &[G2],
    ) -> Result<(), BatchError> {
        let coefficients = prepare_batch(rng, messages.len(), &[signatures.len()], || {
            public_key.is_identity() || signatures.iter().any(G2::is_identity)
        })?;
        let hashes: Vec<_> = messages
            .iter()
            .map(|message| hash_to_g2(message, dst))
            .collect();
        let hash = G2::msm_vartime(&hashes, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let signature =
            G2::msm_vartime(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        multi_pairing(&[(*public_key, hash), (G1::generator().neg(), signature)])
            .is_identity()
            .then_some(())
            .ok_or(BatchError::InvalidSignature)
    }
}

/// BLS signatures in G1 with public keys in G2.
pub mod min_sig {
    use super::{
        BatchError, G1, G2, SigningKey, encoded_batch_coefficients, prepare_batch, validate_batch,
    };
    use crate::bls12381::{hash::hash_to_g1, pairing::multi_pairing};
    use alloc::vec::Vec;
    use rand_core::CryptoRng;

    /// Derives the public key associated with this signing key.
    pub fn public_key(key: &SigningKey) -> G2 {
        G2::generator().mul(&key.scalar)
    }

    /// Signs a public message under the supplied ciphersuite domain separation tag.
    pub fn sign(key: &SigningKey, message: &[u8], dst: &[u8]) -> G1 {
        hash_to_g1(message, dst).mul(&key.scalar)
    }

    /// Verifies a signature, rejecting identity public keys and signatures.
    pub fn verify(public_key: &G2, message: &[u8], dst: &[u8], signature: &G1) -> bool {
        if public_key.is_identity() || signature.is_identity() {
            return false;
        }
        multi_pairing(&[
            (hash_to_g1(message, dst), *public_key),
            (signature.neg(), G2::generator()),
        ])
        .is_identity()
    }

    /// Batch verifies signatures over independently selected messages.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify(
        rng: &mut impl CryptoRng,
        public_keys: &[G2],
        messages: &[&[u8]],
        dst: &[u8],
        signatures: &[G1],
    ) -> Result<(), BatchError> {
        let coefficients = prepare_batch(
            rng,
            public_keys.len(),
            &[messages.len(), signatures.len()],
            || public_keys.iter().any(G2::is_identity) || signatures.iter().any(G1::is_identity),
        )?;
        let aggregate_signature =
            G1::msm_vartime(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let mut pairs = Vec::with_capacity(public_keys.len() + 1);
        pairs.extend(public_keys.iter().zip(messages).zip(&coefficients).map(
            |((&public_key, &message), coefficient)| {
                (hash_to_g1(message, dst).mul(coefficient), public_key)
            },
        ));
        pairs.push((aggregate_signature.neg(), G2::generator()));
        multi_pairing(&pairs)
            .is_identity()
            .then_some(())
            .ok_or(BatchError::InvalidSignature)
    }

    /// Batch verifies signatures by different keys over one message, hashing the message once.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify_same_message(
        rng: &mut impl CryptoRng,
        public_keys: &[G2],
        message: &[u8],
        dst: &[u8],
        signatures: &[G1],
    ) -> Result<(), BatchError> {
        let coefficients = prepare_batch(rng, public_keys.len(), &[signatures.len()], || {
            public_keys.iter().any(G2::is_identity) || signatures.iter().any(G1::is_identity)
        })?;
        let public_key =
            G2::msm_vartime(public_keys, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let signature =
            G1::msm_vartime(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        multi_pairing(&[
            (hash_to_g1(message, dst), public_key),
            (signature.neg(), G2::generator()),
        ])
        .is_identity()
        .then_some(())
        .ok_or(BatchError::InvalidSignature)
    }

    /// Batch verifies signatures by one key over different messages.
    ///
    /// The [batch contract](crate::bls12381::signing#batch-verification) applies.
    pub fn batch_verify_same_signer(
        rng: &mut impl CryptoRng,
        public_key: &G2,
        messages: &[&[u8]],
        dst: &[u8],
        signatures: &[G1],
    ) -> Result<(), BatchError> {
        validate_batch(messages.len(), &[signatures.len()], || {
            public_key.is_identity() || signatures.iter().any(G1::is_identity)
        })?;
        let coefficients = encoded_batch_coefficients(rng, messages.len());
        let hashes: Vec<_> = messages
            .iter()
            .map(|message| hash_to_g1(message, dst))
            .collect();
        let hash =
            G1::msm_vartime_encoded(&hashes, &coefficients).ok_or(BatchError::LengthMismatch)?;
        let signature =
            G1::msm_vartime_encoded(signatures, &coefficients).ok_or(BatchError::LengthMismatch)?;
        multi_pairing(&[(hash, *public_key), (signature.neg(), G2::generator())])
            .is_identity()
            .then_some(())
            .ok_or(BatchError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BatchError, SigningKey, batch_coefficients, encoded_batch_coefficients, min_pk, min_sig,
    };
    use crate::bls12381::{
        group::{G1, G2},
        hash::hash_to_g1,
        pairing::multi_pairing,
    };
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::{ScriptedRng, test_rng};
    use rand_core::Rng;

    const MIN_PK_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const MIN_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    #[test]
    fn secret_key_boundaries() {
        assert!(SigningKey::from_bytes(&[0; 32]).is_none());
        assert!(SigningKey::from_bytes(&[0xff; 32]).is_none());
        assert!(SigningKey::key_gen(&[0; 31], b"").is_none());
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(SigningKey::from_bytes(&one).unwrap().to_bytes(), one);
        let key = SigningKey::random(test_rng());
        assert_eq!(
            SigningKey::from_bytes(&key.to_bytes()).unwrap().to_bytes(),
            key.to_bytes()
        );
        let encoded = key.encode();
        assert_eq!(
            SigningKey::decode(encoded.clone()).unwrap().to_bytes(),
            key.to_bytes()
        );
        for length in 0..32 {
            assert!(SigningKey::decode(encoded.slice(..length)).is_err());
        }
        let mut oversized = encoded.to_vec();
        oversized.push(0);
        assert!(SigningKey::decode(oversized).is_err());
    }

    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKey>();
        assert!(core::mem::needs_drop::<SigningKey>());
    }

    #[cfg(not(miri))]
    #[test]
    fn key_generation_matches_blst() {
        let mut rng = test_rng();
        for length in [32, 33, 48, 64, 65, 255, 256] {
            let mut ikm = vec![0; length];
            rng.fill_bytes(&mut ikm);
            for info in [b"".as_slice(), b"key context"] {
                let key = SigningKey::key_gen(&ikm, info).unwrap();
                let expected = blst::min_pk::SecretKey::key_gen(&ikm, info).unwrap();
                assert_eq!(key.to_bytes(), expected.to_bytes());
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn signatures_match_blst() {
        let key = SigningKey::key_gen(&[42; 32], b"").unwrap();
        let pk_reference = blst::min_pk::SecretKey::from_bytes(&key.to_bytes()).unwrap();
        let sig_reference = blst::min_sig::SecretKey::from_bytes(&key.to_bytes()).unwrap();
        let pk = min_pk::public_key(&key);
        let sig_pk = min_sig::public_key(&key);
        assert_eq!(pk.to_bytes(), pk_reference.sk_to_pk().to_bytes());
        assert_eq!(sig_pk.to_bytes(), sig_reference.sk_to_pk().to_bytes());

        for message in [b"".as_slice(), b"message", &[0xff; 64]] {
            let signature = min_pk::sign(&key, message, MIN_PK_DST);
            let sig_signature = min_sig::sign(&key, message, MIN_SIG_DST);
            assert_eq!(
                signature.to_bytes(),
                pk_reference.sign(message, MIN_PK_DST, b"").to_bytes()
            );
            assert_eq!(
                sig_signature.to_bytes(),
                sig_reference.sign(message, MIN_SIG_DST, b"").to_bytes()
            );
            assert!(min_pk::verify(&pk, message, MIN_PK_DST, &signature));
            assert!(min_sig::verify(
                &sig_pk,
                message,
                MIN_SIG_DST,
                &sig_signature
            ));

            // A valid signature binds the message, the key, and the ciphersuite domain.
            assert!(!min_pk::verify(&pk, b"other", MIN_PK_DST, &signature));
            assert!(!min_sig::verify(&sig_pk, message, b"other", &sig_signature));
            assert!(!min_pk::verify(&pk.neg(), message, MIN_PK_DST, &signature));
            assert!(!min_sig::verify(
                &sig_pk.neg(),
                message,
                MIN_SIG_DST,
                &sig_signature
            ));
        }
    }

    #[test]
    fn identity_keys_and_signatures_are_invalid() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        for (key, signature) in [
            (G1::identity(), g2),
            (g1, G2::identity()),
            (G1::identity(), G2::identity()),
        ] {
            assert!(!min_pk::verify(&key, b"", MIN_PK_DST, &signature));
            assert!(!min_sig::verify(&signature, b"", MIN_SIG_DST, &key));
        }
    }

    #[test]
    fn min_pk_batch_shapes_and_boundaries() {
        let keys: Vec<_> = (1u8..=3)
            .map(|byte| SigningKey::key_gen(&[byte; 32], b"").unwrap())
            .collect();
        let messages: [&[u8]; 3] = [b"one", b"two", b"three"];
        let public_keys: Vec<_> = keys.iter().map(min_pk::public_key).collect();
        let signatures: Vec<_> = keys
            .iter()
            .zip(messages)
            .map(|(key, message)| min_pk::sign(key, message, MIN_PK_DST))
            .collect();
        min_pk::batch_verify(
            &mut test_rng(),
            &public_keys,
            &messages,
            MIN_PK_DST,
            &signatures,
        )
        .unwrap();

        // Zero is one of the 2^128 valid challenges. Weighted identities remain algebraic inputs
        // to the raw pairing equation rather than passing through single-signature verification.
        min_pk::batch_verify(
            &mut ScriptedRng::new([0; 6]),
            &public_keys,
            &messages,
            MIN_PK_DST,
            &signatures,
        )
        .unwrap();

        let same_message = b"same";
        let same_message_signatures: Vec<_> = keys
            .iter()
            .map(|key| min_pk::sign(key, same_message, MIN_PK_DST))
            .collect();
        min_pk::batch_verify_same_message(
            &mut test_rng(),
            &public_keys,
            same_message,
            MIN_PK_DST,
            &same_message_signatures,
        )
        .unwrap();
        min_pk::batch_verify_same_message(
            &mut ScriptedRng::new([0; 6]),
            &public_keys,
            same_message,
            MIN_PK_DST,
            &same_message_signatures,
        )
        .unwrap();

        let signer = &keys[0];
        let signer_public = min_pk::public_key(signer);
        let signer_signatures: Vec<_> = messages
            .iter()
            .map(|message| min_pk::sign(signer, message, MIN_PK_DST))
            .collect();
        min_pk::batch_verify_same_signer(
            &mut test_rng(),
            &signer_public,
            &messages,
            MIN_PK_DST,
            &signer_signatures,
        )
        .unwrap();
        min_pk::batch_verify_same_signer(
            &mut ScriptedRng::new([0; 6]),
            &signer_public,
            &messages,
            MIN_PK_DST,
            &signer_signatures,
        )
        .unwrap();

        let mut corrupted = signatures.clone();
        corrupted[1] = corrupted[1].add(&G2::generator());
        assert_eq!(
            min_pk::batch_verify(
                &mut test_rng(),
                &public_keys,
                &messages,
                MIN_PK_DST,
                &corrupted,
            ),
            Err(BatchError::InvalidSignature),
        );
        let mut corrupted_same_message = same_message_signatures;
        corrupted_same_message[1] = corrupted_same_message[1].add(&G2::generator());
        assert_eq!(
            min_pk::batch_verify_same_message(
                &mut test_rng(),
                &public_keys,
                same_message,
                MIN_PK_DST,
                &corrupted_same_message,
            ),
            Err(BatchError::InvalidSignature),
        );
        assert_eq!(
            min_pk::batch_verify_same_signer(
                &mut test_rng(),
                &signer_public,
                &messages,
                b"wrong dst",
                &signer_signatures,
            ),
            Err(BatchError::InvalidSignature),
        );
        assert_eq!(
            min_pk::batch_verify(&mut test_rng(), &[], &[], MIN_PK_DST, &[]),
            Err(BatchError::Empty),
        );
        assert_eq!(
            min_pk::batch_verify(
                &mut test_rng(),
                &public_keys[..1],
                &messages[..2],
                MIN_PK_DST,
                &signatures[..1],
            ),
            Err(BatchError::LengthMismatch),
        );
        assert_eq!(
            min_pk::batch_verify(
                &mut ScriptedRng::new([]),
                &[G1::IDENTITY],
                &messages[..1],
                MIN_PK_DST,
                &signatures[..1],
            ),
            Err(BatchError::Identity),
        );
        assert_eq!(
            min_pk::batch_verify(
                &mut test_rng(),
                &public_keys[..1],
                &messages[..1],
                MIN_PK_DST,
                &[G2::IDENTITY],
            ),
            Err(BatchError::Identity),
        );
        min_pk::batch_verify(
            &mut test_rng(),
            &[public_keys[0], public_keys[0]],
            &[messages[0], messages[0]],
            MIN_PK_DST,
            &[signatures[0], signatures[0]],
        )
        .unwrap();
    }

    fn min_sig_fixture() -> (Vec<SigningKey>, [&'static [u8]; 3]) {
        let keys: Vec<_> = (4u8..=6)
            .map(|byte| SigningKey::key_gen(&[byte; 32], b"").unwrap())
            .collect();
        (keys, [b"one", b"two", b"three"])
    }

    #[test]
    fn min_sig_general_batch() {
        let (keys, messages) = min_sig_fixture();
        let public_keys: Vec<_> = keys.iter().map(min_sig::public_key).collect();
        let signatures: Vec<_> = keys
            .iter()
            .zip(messages)
            .map(|(key, message)| min_sig::sign(key, message, MIN_SIG_DST))
            .collect();
        min_sig::batch_verify(
            &mut test_rng(),
            &public_keys,
            &messages,
            MIN_SIG_DST,
            &signatures,
        )
        .unwrap();
        min_sig::batch_verify(
            &mut ScriptedRng::new([0; 6]),
            &public_keys,
            &messages,
            MIN_SIG_DST,
            &signatures,
        )
        .unwrap();

        let mut corrupted = signatures.clone();
        corrupted[1] = corrupted[1].add(&G1::generator());
        assert_eq!(
            min_sig::batch_verify(
                &mut test_rng(),
                &public_keys,
                &messages,
                MIN_SIG_DST,
                &corrupted,
            ),
            Err(BatchError::InvalidSignature),
        );
        min_sig::batch_verify(
            &mut test_rng(),
            &[public_keys[0], public_keys[0]],
            &[messages[0], messages[0]],
            MIN_SIG_DST,
            &[signatures[0], signatures[0]],
        )
        .unwrap();
    }

    #[test]
    fn min_sig_same_message_batch() {
        let (keys, _) = min_sig_fixture();
        let public_keys: Vec<_> = keys.iter().map(min_sig::public_key).collect();
        let same_message = b"same";
        let same_message_signatures: Vec<_> = keys
            .iter()
            .map(|key| min_sig::sign(key, same_message, MIN_SIG_DST))
            .collect();
        min_sig::batch_verify_same_message(
            &mut test_rng(),
            &public_keys,
            same_message,
            MIN_SIG_DST,
            &same_message_signatures,
        )
        .unwrap();
        min_sig::batch_verify_same_message(
            &mut ScriptedRng::new([0; 6]),
            &public_keys,
            same_message,
            MIN_SIG_DST,
            &same_message_signatures,
        )
        .unwrap();

        let mut corrupted = same_message_signatures;
        corrupted[1] = corrupted[1].add(&G1::generator());
        assert_eq!(
            min_sig::batch_verify_same_message(
                &mut test_rng(),
                &public_keys,
                same_message,
                MIN_SIG_DST,
                &corrupted,
            ),
            Err(BatchError::InvalidSignature),
        );
    }

    #[test]
    fn min_sig_same_signer_batch() {
        let (keys, messages) = min_sig_fixture();
        let signer = &keys[0];
        let signer_public = min_sig::public_key(signer);
        let signer_signatures: Vec<_> = messages
            .iter()
            .map(|message| min_sig::sign(signer, message, MIN_SIG_DST))
            .collect();
        min_sig::batch_verify_same_signer(
            &mut test_rng(),
            &signer_public,
            &messages,
            MIN_SIG_DST,
            &signer_signatures,
        )
        .unwrap();
        min_sig::batch_verify_same_signer(
            &mut ScriptedRng::new([0; 6]),
            &signer_public,
            &messages,
            MIN_SIG_DST,
            &signer_signatures,
        )
        .unwrap();
        min_sig::batch_verify_same_signer(
            &mut test_rng(),
            &signer_public,
            &[messages[0], messages[0]],
            MIN_SIG_DST,
            &[signer_signatures[0], signer_signatures[0]],
        )
        .unwrap();

        assert_eq!(
            min_sig::batch_verify_same_signer(
                &mut test_rng(),
                &signer_public,
                &messages,
                b"wrong dst",
                &signer_signatures,
            ),
            Err(BatchError::InvalidSignature),
        );
    }

    #[test]
    fn min_sig_same_signer_preserves_coefficients_and_equation() {
        let (keys, messages) = min_sig_fixture();
        let key = &keys[0];
        let public_key = min_sig::public_key(key);
        let hashes: Vec<_> = messages
            .iter()
            .map(|message| hash_to_g1(message, MIN_SIG_DST))
            .collect();
        let signatures: Vec<_> = messages
            .iter()
            .map(|message| min_sig::sign(key, message, MIN_SIG_DST))
            .collect();
        let mut corrupt = signatures.clone();
        corrupt[1] = corrupt[1].add(&G1::generator());
        const SENTINEL: u64 = 0x55aa;
        for samples in [
            [0; 6],
            [
                0x0123456789abcdef,
                0x1032547698badcfe,
                0,
                0,
                u64::MAX,
                u64::MAX,
            ],
            [u64::MAX; 6],
        ] {
            let rng = || ScriptedRng::new(samples.into_iter().chain([SENTINEL]));
            let mut scalar_rng = rng();
            let mut encoded_rng = rng();
            let scalars = batch_coefficients(&mut scalar_rng, messages.len());
            let encoded = encoded_batch_coefficients(&mut encoded_rng, messages.len());
            assert_eq!(scalar_rng.next_u64(), SENTINEL);
            assert_eq!(encoded_rng.next_u64(), SENTINEL);
            let hash = G1::msm_vartime(&hashes, &scalars).unwrap();
            assert_eq!(
                hash.to_bytes(),
                G1::msm_vartime_encoded(&hashes, &encoded)
                    .unwrap()
                    .to_bytes()
            );
            for signatures in [&signatures, &corrupt] {
                let signature = G1::msm_vartime(signatures, &scalars).unwrap();
                assert_eq!(
                    signature.to_bytes(),
                    G1::msm_vartime_encoded(signatures, &encoded)
                        .unwrap()
                        .to_bytes()
                );
                let expected =
                    multi_pairing(&[(hash, public_key), (signature.neg(), G2::generator())])
                        .is_identity()
                        .then_some(())
                        .ok_or(BatchError::InvalidSignature);
                let mut actual_rng = rng();
                assert_eq!(
                    min_sig::batch_verify_same_signer(
                        &mut actual_rng,
                        &public_key,
                        &messages,
                        MIN_SIG_DST,
                        signatures
                    ),
                    expected,
                );
                assert_eq!(actual_rng.next_u64(), SENTINEL);
            }
        }
    }

    #[test]
    fn min_sig_same_signer_rejects_before_rng() {
        let public_key = G2::generator();
        let messages: &[&[u8]] = &[b"one"];
        let signatures = [G1::generator()];
        for (key, messages, signatures, expected) in [
            (
                &G2::IDENTITY,
                &messages[..0],
                &signatures[..],
                BatchError::LengthMismatch,
            ),
            (
                &G2::IDENTITY,
                messages,
                &signatures[..0],
                BatchError::LengthMismatch,
            ),
            (
                &G2::IDENTITY,
                &messages[..0],
                &signatures[..0],
                BatchError::Empty,
            ),
            (
                &G2::IDENTITY,
                messages,
                &signatures[..],
                BatchError::Identity,
            ),
            (
                &public_key,
                messages,
                &[G1::IDENTITY][..],
                BatchError::Identity,
            ),
        ] {
            assert_eq!(
                min_sig::batch_verify_same_signer(
                    &mut ScriptedRng::new([]),
                    key,
                    messages,
                    MIN_SIG_DST,
                    signatures
                ),
                Err(expected),
            );
        }
    }

    #[test]
    fn min_sig_batch_rejects_structural_errors() {
        let key = SigningKey::key_gen(&[4; 32], b"").unwrap();
        let message = b"one".as_slice();
        let public_key = min_sig::public_key(&key);
        let signature = min_sig::sign(&key, message, MIN_SIG_DST);
        assert_eq!(
            min_sig::batch_verify(&mut test_rng(), &[], &[], MIN_SIG_DST, &[]),
            Err(BatchError::Empty),
        );
        assert_eq!(
            min_sig::batch_verify(
                &mut test_rng(),
                &[public_key],
                &[message, message],
                MIN_SIG_DST,
                &[signature],
            ),
            Err(BatchError::LengthMismatch),
        );
        assert_eq!(
            min_sig::batch_verify_same_message(
                &mut test_rng(),
                &[public_key],
                message,
                MIN_SIG_DST,
                &[],
            ),
            Err(BatchError::LengthMismatch),
        );
        assert_eq!(
            min_sig::batch_verify_same_signer(
                &mut test_rng(),
                &public_key,
                &[message],
                MIN_SIG_DST,
                &[],
            ),
            Err(BatchError::LengthMismatch),
        );
        assert_eq!(
            min_sig::batch_verify(
                &mut ScriptedRng::new([]),
                &[G2::IDENTITY],
                &[message],
                MIN_SIG_DST,
                &[signature],
            ),
            Err(BatchError::Identity),
        );
        assert_eq!(
            min_sig::batch_verify(
                &mut test_rng(),
                &[public_key],
                &[message],
                MIN_SIG_DST,
                &[G1::IDENTITY],
            ),
            Err(BatchError::Identity),
        );
    }

    #[test]
    fn min_pk_general_batch_pairing_chunk_boundaries() {
        let key = SigningKey::key_gen(&[7; 32], b"").unwrap();
        let min_pk_public = min_pk::public_key(&key);
        for count in [15, 16, 17] {
            let messages: Vec<_> = (0..count).map(|i| (i as u64).to_be_bytes()).collect();
            let message_refs: Vec<_> = messages.iter().map(|message| message.as_slice()).collect();
            let min_pk_signatures: Vec<_> = message_refs
                .iter()
                .map(|message| min_pk::sign(&key, message, MIN_PK_DST))
                .collect();
            min_pk::batch_verify(
                &mut test_rng(),
                &vec![min_pk_public; count],
                &message_refs,
                MIN_PK_DST,
                &min_pk_signatures,
            )
            .unwrap();
        }
    }

    #[test]
    fn min_sig_general_batch_pairing_chunk_boundaries() {
        let key = SigningKey::key_gen(&[7; 32], b"").unwrap();
        let min_sig_public = min_sig::public_key(&key);
        for count in [15, 16, 17] {
            let messages: Vec<_> = (0..count).map(|i| (i as u64).to_be_bytes()).collect();
            let message_refs: Vec<_> = messages.iter().map(|message| message.as_slice()).collect();
            let min_sig_signatures: Vec<_> = message_refs
                .iter()
                .map(|message| min_sig::sign(&key, message, MIN_SIG_DST))
                .collect();
            min_sig::batch_verify(
                &mut test_rng(),
                &vec![min_sig_public; count],
                &message_refs,
                MIN_SIG_DST,
                &min_sig_signatures,
            )
            .unwrap();
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::SigningKey;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<SigningKey> => 1024,
        }
    }
}
