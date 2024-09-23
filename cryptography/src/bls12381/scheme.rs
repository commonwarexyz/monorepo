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
//! let namespace = b"demo";
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
use crate::{utils::payload, PrivateKey, PublicKey, Scheme, Signature};
use rand::{CryptoRng, Rng, SeedableRng};

/// BLS12-381 implementation of the `Scheme` trait.
///
/// This implementation uses the `blst` crate for BLS12-381 operations. This
/// crate implments serialization according to the "ZCash BLS12-381" specification
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

    fn sign(&mut self, namespace: &[u8], message: &[u8]) -> Signature {
        let payload = payload(namespace, message);
        let signature = ops::sign(&self.private, &payload);
        signature.serialize().into()
    }

    fn validate(public_key: &PublicKey) -> bool {
        group::Public::deserialize(public_key.as_ref()).is_some()
    }

    fn verify(
        namespace: &[u8],
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
        let payload = payload(namespace, message);
        ops::verify(&public, &payload, &signature).is_ok()
    }
}
