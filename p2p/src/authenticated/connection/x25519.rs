use super::Error;
use bytes::Bytes;
use rand::{CryptoRng, Rng};
use x25519_dalek::{EphemeralSecret, PublicKey};

const PUBLIC_KEY_LENGTH: usize = 32;

pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralSecret {
    EphemeralSecret::random_from_rng(rng)
}

pub fn decode_public_key(public_key: &Bytes) -> Result<PublicKey, Error> {
    // Constuct a public key array from the data
    let public_key: [u8; PUBLIC_KEY_LENGTH] = match public_key.as_ref().try_into() {
        Ok(key) => key,
        Err(_) => return Err(Error::InvalidEphemeralPublicKey),
    };

    // Create the public key from the array
    Ok(PublicKey::from(public_key))
}

pub fn encode_public_key(public_key: PublicKey) -> Bytes {
    public_key.as_bytes().to_vec().into()
}
