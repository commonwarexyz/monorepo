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
use crate::{PrivateKey, PublicKey, Scheme, Signature};
use rand::{CryptoRng, Rng, SeedableRng};

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
    fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let (private, public) = ops::keypair(r);
        Self { private, public }
    }

    fn from(private_key: PrivateKey) -> Option<Self> {
        let private_key: [u8; group::PRIVATE_KEY_LENGTH] = match private_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return None,
        };
        let private = Scalar::deserialize(&private_key)?;
        let mut public = group::Public::one();
        public.mul(&private);
        Some(Self { private, public })
    }

    fn from_seed(seed: u64) -> Self {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        Self::new(&mut rng)
    }

    fn private_key(&self) -> PrivateKey {
        self.private.serialize().into()
    }

    fn public_key(&self) -> PublicKey {
        self.public.serialize().into()
    }

    fn sign(&mut self, namespace: Option<&[u8]>, message: &[u8]) -> Signature {
        let signature = ops::sign(&self.private, namespace, message);
        signature.serialize().into()
    }

    fn validate(public_key: &PublicKey) -> bool {
        group::Public::deserialize(public_key.as_ref()).is_some()
    }

    fn verify(
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        let public = match group::Public::deserialize(public_key.as_ref()) {
            Some(public) => public,
            None => return false,
        };
        let signature = match group::Signature::deserialize(signature.as_ref()) {
            Some(signature) => signature,
            None => return false,
        };
        ops::verify(&public, namespace, message, &signature).is_ok()
    }

    fn len() -> (usize, usize) {
        (group::G1_ELEMENT_BYTE_LENGTH, group::G2_ELEMENT_BYTE_LENGTH)
    }
}

#[cfg(test)]
mod tests {
    use super::{Bls12381, Scheme};
    use blst::min_pk::SecretKey;
    use core::str;
    use hex;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_bigint::BigUint;
    use serde::{Deserialize, Deserializer};
    use serde_json;
    use std::fs;

    use crate::PrivateKey;

    /// Strip the '0x' prefix.
    fn strip_prefix<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        Ok(hex_str.strip_prefix("0x").unwrap().to_string())
    }

    // Parse the hexadecimal string to a BigUint
    fn hex_to_int(hex_str: &str) -> BigUint {
        BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("Invalid hexadecimal string")
    }

    #[derive(Deserialize)]
    struct PrivateKeyMessage {
        #[serde(rename = "privkey", deserialize_with = "strip_prefix")]
        private_key: String,
        #[serde(deserialize_with = "strip_prefix")]
        message: String,
    }

    #[derive(Deserialize)]
    struct SigningVector {
        input: PrivateKeyMessage,
        #[serde(deserialize_with = "strip_prefix")]
        output: String,
    }

    fn load_sign_case_vector() -> SigningVector {
        let content = r#"{"input": {"privkey": "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138", "message": "0xabababababababababababababababababababababababababababababababab"}, "output": "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"}"#;
        serde_json::from_str(content).unwrap()
    }

    #[test]
    fn sign() {
        let signing_vector = load_sign_case_vector();
        let s = signing_vector.input.private_key;
        let big_int = hex_to_int(&s);
        let b = big_int.to_bytes_be();
        let private_key = PrivateKey::from(b);
        let mut bls = <Bls12381 as Scheme>::from(private_key).unwrap();
        let signature = bls.sign(None, &hex::decode(&signing_vector.input.message).unwrap());
        assert_eq!(signing_vector.output, hex::encode(signature));
    }
}
