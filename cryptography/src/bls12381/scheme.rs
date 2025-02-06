//! BLS12-381 implementation of the `Scheme` trait.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Bls12381, Scheme};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = Bls12381::new(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = Some(&b"demo"[..]);
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(Bls12381::verify(namespace, msg, &signer.public_key(), &signature));
//! ```

use super::primitives::{
    group::{self, Element, Scalar},
    ops,
};
use crate::{Array, Error, Scheme};
use commonware_utils::SizedSerialize;
use rand::{CryptoRng, Rng};
use std::{
    hash::{Hash, Hasher},
    ops::Deref,
};

/// BLS12-381 implementation of the `Scheme` trait.
///
/// This implementation uses the `blst` crate for BLS12-381 operations. This
/// crate implements serialization according to the "ZCash BLS12-381" specification
/// (<https://github.com/supranational/blst/tree/master?tab=readme-ov-file#serialization-format>) and
/// hashes messages according to RFC 9380.
#[derive(Clone)]
pub struct Bls12381 {
    private: group::Private,
    public: group::Public,
}

impl Scheme for Bls12381 {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let (private, public) = ops::keypair(r);
        Self { private, public }
    }

    fn from(private_key: PrivateKey) -> Option<Self> {
        let private = private_key.key;
        let mut public = group::Public::one();
        public.mul(&private);
        Some(Self { private, public })
    }

    fn private_key(&self) -> PrivateKey {
        PrivateKey::from(self.private)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public)
    }

    fn sign(&mut self, namespace: Option<&[u8]>, message: &[u8]) -> Signature {
        let signature = ops::sign_message(&self.private, namespace, message);
        Signature::from(signature)
    }

    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        ops::verify_message(&public_key.key, namespace, message, &signature.signature).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey {
    raw: [u8; group::PRIVATE_KEY_LENGTH],
    key: group::Private,
}

impl Array for PrivateKey {}

impl SizedSerialize for PrivateKey {
    const SERIALIZED_LEN: usize = group::PRIVATE_KEY_LENGTH;
}

impl Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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
        let raw: [u8; group::PRIVATE_KEY_LENGTH] = key.serialize().try_into().unwrap();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; group::PRIVATE_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPrivateKeyLength)?;
        let key = Scalar::deserialize(value).ok_or(Error::InvalidPrivateKey)?;
        Ok(Self { raw, key })
    }
}

impl TryFrom<&Vec<u8>> for PrivateKey {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    raw: [u8; group::PUBLIC_KEY_LENGTH],
    key: group::Public,
}

impl Array for PublicKey {}

impl SizedSerialize for PublicKey {
    const SERIALIZED_LEN: usize = group::PUBLIC_KEY_LENGTH;
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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

impl From<group::Public> for PublicKey {
    fn from(key: group::Public) -> Self {
        let raw = key.serialize().try_into().unwrap();
        Self { raw, key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; group::PUBLIC_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength)?;
        let key = group::Public::deserialize(value).ok_or(Error::InvalidPublicKey)?;
        Ok(Self { raw, key })
    }
}

impl TryFrom<&Vec<u8>> for PublicKey {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    raw: [u8; group::SIGNATURE_LENGTH],
    signature: group::Signature,
}

impl Array for Signature {}

impl SizedSerialize for Signature {
    const SERIALIZED_LEN: usize = group::SIGNATURE_LENGTH;
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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

impl From<group::Signature> for Signature {
    fn from(signature: group::Signature) -> Self {
        let raw = signature.serialize().try_into().unwrap();
        Self { raw, signature }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; group::SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength)?;
        let signature = group::Signature::deserialize(value).ok_or(Error::InvalidSignature)?;
        Ok(Self { raw, signature })
    }
}

impl TryFrom<&Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

/// Test vectors sourced from https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let cases = [
            vector_sign_1(),
            vector_sign_2(),
            vector_sign_3(),
            vector_sign_4(),
            vector_sign_5(),
            vector_sign_6(),
            vector_sign_7(),
            vector_sign_8(),
            vector_sign_9(),
        ];
        for (index, test) in cases.into_iter().enumerate() {
            let (private_key, message, expected) = test;
            let mut signer =
                <Bls12381 as Scheme>::from(private_key).expect("unable to deserialize private key");
            let signature = signer.sign(None, &message);
            assert_eq!(signature, expected, "vector_sign_{}", index + 1);
        }
    }

    #[test]
    fn test_sign_10() {
        let result =
            parse_private_key("0x0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify() {
        let cases = [
            vector_verify_1(),
            vector_verify_2(),
            vector_verify_3(),
            vector_verify_4(),
            vector_verify_5(),
            vector_verify_6(),
            vector_verify_7(),
            vector_verify_8(),
            vector_verify_9(),
            vector_verify_10(),
            vector_verify_11(),
            vector_verify_12(),
            vector_verify_13(),
            vector_verify_14(),
            vector_verify_15(),
            vector_verify_16(),
            vector_verify_17(),
            vector_verify_18(),
            vector_verify_19(),
            vector_verify_20(),
            vector_verify_21(),
            vector_verify_22(),
            vector_verify_23(),
            vector_verify_24(),
            vector_verify_25(),
            vector_verify_26(),
            vector_verify_27(),
            vector_verify_28(),
            vector_verify_29(),
        ];

        for (index, test) in cases.into_iter().enumerate() {
            let (public_key, message, signature, expected) = test;
            let expected = if !expected {
                public_key.is_err()
                    || signature.is_err()
                    || !Bls12381::verify(None, &message, &public_key.unwrap(), &signature.unwrap())
            } else {
                Bls12381::verify(None, &message, &public_key.unwrap(), &signature.unwrap())
            };
            assert!(expected, "vector_verify_{}", index + 1);
        }
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

    fn parse_private_key(private_key: &str) -> Result<PrivateKey, Error> {
        PrivateKey::try_from(commonware_utils::from_hex_formatted(private_key).unwrap())
    }
    fn parse_public_key(public_key: &str) -> Result<PublicKey, Error> {
        PublicKey::try_from(commonware_utils::from_hex_formatted(public_key).unwrap())
    }
    fn parse_signature(signature: &str) -> Result<Signature, Error> {
        Signature::try_from(commonware_utils::from_hex_formatted(signature).unwrap())
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
    ) -> (Result<PublicKey, Error>, Vec<u8>, Result<Signature, Error>) {
        (
            parse_public_key(public_key),
            commonware_utils::from_hex_formatted(msg).unwrap(),
            parse_signature(signature),
        )
    }

    // verify_infinity_pubkey_and_infinity_signature
    fn vector_verify_1() -> (
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
        Result<PublicKey, Error>,
        Vec<u8>,
        Result<Signature, Error>,
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
