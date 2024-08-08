use crate::crypto;
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Ed25519 {
    signer: SigningKey,
    verifier: crypto::PublicKey,
}

impl Ed25519 {
    pub fn new(signer: SigningKey) -> Self {
        let verifier = signer.verifying_key();
        Self {
            signer,
            verifier: verifier.to_bytes().to_vec().into(),
        }
    }
}

impl crypto::Crypto for Ed25519 {
    fn me(&self) -> crypto::PublicKey {
        self.verifier.clone()
    }

    fn sign(&mut self, message: Vec<u8>) -> crypto::Signature {
        self.signer.sign(&message).to_bytes().to_vec().into()
    }

    fn validate(public_key: &crypto::PublicKey) -> bool {
        let public_key: &[u8; PUBLIC_KEY_LENGTH] = match public_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };
        VerifyingKey::from_bytes(public_key).is_ok()
    }

    fn verify(
        message: Vec<u8>,
        public_key: &crypto::PublicKey,
        signature: &crypto::Signature,
    ) -> bool {
        let public_key: &[u8; PUBLIC_KEY_LENGTH] = match public_key.as_ref().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };
        let public_key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature: &[u8; SIGNATURE_LENGTH] = match signature.as_ref().try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let signature = Signature::from(signature);
        public_key.verify(&message, &signature).is_ok()
    }
}

pub fn insecure_signer(peer: u16) -> Ed25519 {
    let secret_key: [u8; SECRET_KEY_LENGTH] = Sha256::digest(peer.to_be_bytes()).into();
    Ed25519::new(SigningKey::from(secret_key))
}
