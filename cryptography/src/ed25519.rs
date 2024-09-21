//! Ed25519 implementation of the Scheme trait.
//!
//! This implementation uses the `ed25519-consensus` crate to adhere to a strict
//! set of validation rules for Ed25519 signatures (which is necessary for
//! stability in a consensus context). You can read more about this
//! [here](https://hdevalence.ca/blog/2020-10-04-its-25519am).
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{ed25519::Ed25519, Scheme};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = Ed25519::new(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(Ed25519::verify(namespace, msg, &signer.me(), &signature));
//! ```

use crate::{utils::payload, PublicKey, Scheme, Signature};
use ed25519_consensus;
use rand::{CryptoRng, Rng, SeedableRng};

const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Ed25519 Signer.
#[derive(Clone)]
pub struct Ed25519 {
    signer: ed25519_consensus::SigningKey,
    verifier: PublicKey,
}

impl Ed25519 {
    /// Creates a new Ed25519 signer.
    pub fn new<R: CryptoRng + Rng>(r: &mut R) -> Self {
        let signer = ed25519_consensus::SigningKey::new(r);
        let verifier = signer.verification_key();
        Self {
            signer,
            verifier: verifier.to_bytes().to_vec().into(),
        }
    }

    /// Creates a new Ed25519 signer from a secret key.
    pub fn from(signer: [u8; SECRET_KEY_LENGTH]) -> Self {
        let signer = ed25519_consensus::SigningKey::from(signer);
        let verifier = signer.verification_key();
        Self {
            signer,
            verifier: verifier.to_bytes().to_vec().into(),
        }
    }
}

impl Scheme for Ed25519 {
    fn me(&self) -> PublicKey {
        self.verifier.clone()
    }

    fn sign(&mut self, namespace: &[u8], message: &[u8]) -> Signature {
        let payload = payload(namespace, message);
        self.signer.sign(&payload).to_bytes().to_vec().into()
    }

    fn validate(public_key: &PublicKey) -> bool {
        let public_key: [u8; PUBLIC_KEY_LENGTH] = match public_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };
        ed25519_consensus::VerificationKey::try_from(public_key).is_ok()
    }

    fn verify(
        namespace: &[u8],
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        let public_key: [u8; PUBLIC_KEY_LENGTH] = match public_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };
        let public_key = match ed25519_consensus::VerificationKey::try_from(public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature: [u8; SIGNATURE_LENGTH] = match signature.as_ref().try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let signature = ed25519_consensus::Signature::from(signature);
        let payload = payload(namespace, message);
        public_key.verify(&signature, &payload).is_ok()
    }
}

/// Creates a new Ed25519 signer with a secret key derived from the provided
/// seed.
///
/// # Warning
///
/// This function is intended for testing and demonstration purposes only.
/// It should never be used in production.
pub fn insecure_signer(seed: u64) -> Ed25519 {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut secret_key = [0u8; SECRET_KEY_LENGTH];
    rng.fill(&mut secret_key);
    Ed25519::from(secret_key)
}
