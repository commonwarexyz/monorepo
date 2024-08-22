//! Ed25519 implementation of the Crypto trait.
//!
//! This implementation uses the `ed25519-consensus` crate to adhere to a strict
//! set of validation rules for Ed25519 signatures (which is necessary for
//! stability in a consensus context).

use crate::{utils::payload, PublicKey, Scheme, Signature};
use ed25519_consensus;
use sha2::{Digest, Sha256};

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
    pub fn new(signer: ed25519_consensus::SigningKey) -> Self {
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
pub fn insecure_signer(seed: u16) -> Ed25519 {
    let secret_key: [u8; SECRET_KEY_LENGTH] = Sha256::digest(seed.to_be_bytes()).into();
    Ed25519::new(ed25519_consensus::SigningKey::from(secret_key))
}
