use super::Error;
use bytes::Bytes;
use x25519_dalek::PublicKey;

const PUBLIC_KEY_LENGTH: usize = 32;

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
