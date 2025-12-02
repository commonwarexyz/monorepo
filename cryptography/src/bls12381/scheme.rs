//! BLS12-381 implementation of the [crate::Verifier] and [crate::Signer] traits.
//!
//! This implementation uses the `blst` crate for BLS12-381 operations. This
//! crate implements serialization according to the "ZCash BLS12-381" specification
//! (<https://github.com/supranational/blst/tree/master?tab=readme-ov-file#serialization-format>)
//! and hashes messages according to RFC 9380.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{bls12381, PrivateKey, PublicKey, Signature, PrivateKeyExt as _, Verifier as _, Signer as _};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = bls12381::PrivateKey::from_rng(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = &b"demo"[..];
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

use super::primitives::{
    group::{self, Scalar},
    ops,
    variant::{MinPk, Variant},
};
use crate::{Array, BatchVerifier, PrivateKeyExt, Signer as _};
#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, EncodeFixed, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_utils::{hex, union_unique, Span};
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    ops::Deref,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::borrow::Cow;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CURVE_NAME: &str = "bls12381";

/// BLS12-381 private key.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    raw: [u8; group::PRIVATE_KEY_LENGTH],
    key: group::Private,
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let key = group::Private::decode(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self { raw, key })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = group::PRIVATE_KEY_LENGTH;
}

impl Span for PrivateKey {}

impl Array for PrivateKey {}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PrivateKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<Scalar> for PrivateKey {
    fn from(key: Scalar) -> Self {
        let raw = key.encode_fixed();
        Self { raw, key }
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey::from(ops::compute_public::<MinPk>(&self.key))
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.sign_inner(Some(namespace), msg)
    }
}

impl PrivateKey {
    #[inline(always)]
    fn sign_inner(&self, namespace: Option<&[u8]>, message: &[u8]) -> Signature {
        ops::sign_message::<MinPk>(&self.key, namespace, message).into()
    }
}

impl PrivateKeyExt for PrivateKey {
    fn from_rng<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (private, _) = ops::keypair::<_, MinPk>(rng);
        let raw = private.encode_fixed();
        Self { raw, key: private }
    }
}

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        self.verify_inner(Some(namespace), msg, sig)
    }
}

impl PublicKey {
    #[inline(always)]
    fn verify_inner(
        &self,
        namespace: Option<&[u8]>,
        message: &[u8],
        signature: &Signature,
    ) -> bool {
        ops::verify_message::<MinPk>(&self.key, namespace, message, &signature.signature).is_ok()
    }
}

/// BLS12-381 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey {
    raw: [u8; <MinPk as Variant>::Public::SIZE],
    key: <MinPk as Variant>::Public,
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        private_key.public_key()
    }
}

impl AsRef<<MinPk as Variant>::Public> for PublicKey {
    fn as_ref(&self) -> &<MinPk as Variant>::Public {
        &self.key
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let key = <MinPk as Variant>::Public::decode(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self { raw, key })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = <MinPk as Variant>::Public::SIZE;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<<MinPk as Variant>::Public> for PublicKey {
    fn from(key: <MinPk as Variant>::Public) -> Self {
        let raw = key.encode_fixed();
        Self { raw, key }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// BLS12-381 signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; <MinPk as Variant>::Signature::SIZE],
    signature: <MinPk as Variant>::Signature,
}

impl crate::Signature for Signature {}

impl AsRef<<MinPk as Variant>::Signature> for Signature {
    fn as_ref(&self) -> &<MinPk as Variant>::Signature {
        &self.signature
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let signature = <MinPk as Variant>::Signature::decode(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self { raw, signature })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = <MinPk as Variant>::Signature::SIZE;
}

impl Span for Signature {}

impl Array for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for Signature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<<MinPk as Variant>::Signature> for Signature {
    fn from(signature: <MinPk as Variant>::Signature) -> Self {
        let raw = signature.encode_fixed();
        Self { raw, signature }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

/// BLS12-381 batch verifier.
pub struct Batch {
    publics: Vec<<MinPk as Variant>::Public>,
    hms: Vec<<MinPk as Variant>::Signature>,
    signatures: Vec<<MinPk as Variant>::Signature>,
}

impl Batch {
    #[inline(always)]
    fn add_inner(
        &mut self,
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        self.publics.push(public_key.key);
        let payload = match namespace {
            Some(namespace) => Cow::Owned(union_unique(namespace, message)),
            None => Cow::Borrowed(message),
        };
        let hm = ops::hash_message::<MinPk>(MinPk::MESSAGE, &payload);
        self.hms.push(hm);
        self.signatures.push(signature.signature);
        true
    }
}

impl BatchVerifier<PublicKey> for Batch {
    fn new() -> Self {
        Self {
            publics: Vec::new(),
            hms: Vec::new(),
            signatures: Vec::new(),
        }
    }

    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        self.add_inner(Some(namespace), message, public_key, signature)
    }

    fn verify<R: CryptoRngCore>(self, rng: &mut R) -> bool {
        MinPk::batch_verify(rng, &self.publics, &self.hms, &self.signatures).is_ok()
    }
}

/// Test vectors sourced from https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381;
    use commonware_codec::{DecodeExt, Encode};
    use rstest::rstest;

    #[test]
    fn test_codec_private_key() {
        let original =
            parse_private_key("0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
                .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), bls12381::PrivateKey::SIZE);
        let decoded = bls12381::PrivateKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let original =
            parse_public_key("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), PublicKey::SIZE);
        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_signature() {
        let original =
            parse_signature("0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), Signature::SIZE);
        let decoded = Signature::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[rstest]
    #[case(vector_sign_1())]
    #[case(vector_sign_2())]
    #[case(vector_sign_3())]
    #[case(vector_sign_4())]
    #[case(vector_sign_5())]
    #[case(vector_sign_6())]
    #[case(vector_sign_7())]
    #[case(vector_sign_8())]
    #[case(vector_sign_9())]
    fn test_sign(#[case] (private_key, message, expected): (PrivateKey, Vec<u8>, Signature)) {
        let signature = private_key.sign_inner(None, &message);
        assert_eq!(signature, expected);
    }

    #[test]
    fn test_sign_10() {
        let result =
            parse_private_key("0x0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
    }

    #[rstest]
    #[case(vector_verify_1())]
    #[case(vector_verify_2())]
    #[case(vector_verify_3())]
    #[case(vector_verify_4())]
    #[case(vector_verify_5())]
    #[case(vector_verify_6())]
    #[case(vector_verify_7())]
    #[case(vector_verify_8())]
    #[case(vector_verify_9())]
    #[case(vector_verify_10())]
    #[case(vector_verify_11())]
    #[case(vector_verify_12())]
    #[case(vector_verify_13())]
    #[case(vector_verify_14())]
    #[case(vector_verify_15())]
    #[case(vector_verify_16())]
    #[case(vector_verify_17())]
    #[case(vector_verify_18())]
    #[case(vector_verify_19())]
    #[case(vector_verify_20())]
    #[case(vector_verify_21())]
    #[case(vector_verify_22())]
    #[case(vector_verify_23())]
    #[case(vector_verify_24())]
    #[case(vector_verify_25())]
    #[case(vector_verify_26())]
    #[case(vector_verify_27())]
    #[case(vector_verify_28())]
    #[case(vector_verify_29())]
    fn test_verify(
        #[case] (public_key, message, signature, expected): (
            Result<PublicKey, CodecError>,
            Vec<u8>,
            Result<Signature, CodecError>,
            bool,
        ),
    ) {
        let mut batch = Batch::new();
        let expected = if !expected {
            public_key.is_err()
                || signature.is_err()
                || !public_key
                    .unwrap()
                    .verify_inner(None, &message, &signature.unwrap())
        } else {
            let public_key = public_key.unwrap();
            let signature = signature.unwrap();
            batch.add_inner(None, &message, &public_key, &signature);
            public_key.verify_inner(None, &message, &signature)
        };
        assert!(expected);
    }

    /// Parse `sign` vector from hex encoded data.
    fn parse_sign_vector(
        private_key: &str,
        msg: &str,
        signature: &str,
    ) -> (PrivateKey, Vec<u8>, Signature) {
        (
            parse_private_key(private_key).unwrap(),
            commonware_utils::from_hex_formatted(msg).unwrap(),
            parse_signature(signature).unwrap(),
        )
    }

    fn parse_private_key(private_key: &str) -> Result<PrivateKey, CodecError> {
        PrivateKey::decode(
            commonware_utils::from_hex_formatted(private_key)
                .unwrap()
                .as_ref(),
        )
    }
    fn parse_public_key(public_key: &str) -> Result<PublicKey, CodecError> {
        PublicKey::decode(
            commonware_utils::from_hex_formatted(public_key)
                .unwrap()
                .as_ref(),
        )
    }
    fn parse_signature(signature: &str) -> Result<Signature, CodecError> {
        Signature::decode(
            commonware_utils::from_hex_formatted(signature)
                .unwrap()
                .as_ref(),
        )
    }

    // sign_case_8cd3d4d0d9a5b265
    fn vector_sign_1() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"
        )
    }

    // sign_case_11b8c7cad5238946
    fn vector_sign_2() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9"
        )
    }

    // sign_case_84d45c9c7cca6b92
    fn vector_sign_3() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        )
    }

    // sign_case_142f678a8d05fcd1
    fn vector_sign_4() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe"
        )
    }

    // sign_case_37286e1a6d1f6eb3
    fn vector_sign_5() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
        )
    }

    // sign_case_7055381f640f2c1d
    fn vector_sign_6() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115"
        )
    }

    // sign_case_c82df61aa3ee60fb
    fn vector_sign_7() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
        )
    }

    // sign_case_d0e28d7e76eb6e9c
    fn vector_sign_8() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"
        )
    }

    // sign_case_f2ae1097e7d0e18b
    fn vector_sign_9() -> (PrivateKey, Vec<u8>, Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
        )
    }

    /// Parse `verify` vector from hex encoded data.
    fn parse_verify_vector(
        public_key: &str,
        msg: &str,
        signature: &str,
    ) -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
    ) {
        (
            parse_public_key(public_key),
            commonware_utils::from_hex_formatted(msg).unwrap(),
            parse_signature(signature),
        )
    }

    // verify_infinity_pubkey_and_infinity_signature
    fn vector_verify_1() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
                "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0x1212121212121212121212121212121212121212121212121212121212121212",
                "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_2ea479adf8c40300
    fn vector_verify_2() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_2f09d443ab8a3ac2
    fn vector_verify_3() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_6b3b17f6962a490c
    fn vector_verify_4() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_6eeb7c52dfd9baf0
    fn vector_verify_5() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_8761a0b7e920c323
    fn vector_verify_6() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b71ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_195246ee3bd3b6ec
    fn vector_verify_7() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_3208262581c8fc09
    fn vector_verify_8() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_d34885d766d5f705
    fn vector_verify_9() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075effffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_e8a50c445c855360
    fn vector_verify_10() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v= parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_valid_case_2ea479adf8c40300
    fn vector_verify_11() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v= parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_2f09d443ab8a3ac2
    fn vector_verify_12() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_6b3b17f6962a490c
    fn vector_verify_13() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_6eeb7c52dfd9baf0
    fn vector_verify_14() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_8761a0b7e920c323
    fn vector_verify_15() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_195246ee3bd3b6ec
    fn vector_verify_16() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_3208262581c8fc09
    fn vector_verify_17() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_d34885d766d5f705
    fn vector_verify_18() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_e8a50c445c855360
    fn vector_verify_19() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_wrong_pubkey_case_2ea479adf8c40300
    fn vector_verify_20() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_2f09d443ab8a3ac2
    fn vector_verify_21() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_6b3b17f6962a490c
    fn vector_verify_22() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_6eeb7c52dfd9baf0
    fn vector_verify_23() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_8761a0b7e920c323
    fn vector_verify_24() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_195246ee3bd3b6ec
    fn vector_verify_25() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_3208262581c8fc09
    fn vector_verify_26() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_d34885d766d5f705
    fn vector_verify_27() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_e8a50c445c855360
    fn vector_verify_28() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        );
        (v.0, v.1, v.2, false)
    }

    // verifycase_one_privkey_47117849458281be
    fn vector_verify_29() -> (
        Result<PublicKey, CodecError>,
        Vec<u8>,
        Result<Signature, CodecError>,
        bool,
    ) {
        let v= parse_verify_vector(
            "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            "0x1212121212121212121212121212121212121212121212121212121212121212",
            "0xa42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b4700829232052b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763",
        );
        (v.0, v.1, v.2, true)
    }
}
