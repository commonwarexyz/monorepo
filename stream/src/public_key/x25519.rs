use crate::Error;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_public_key() {
        let mut rng = rand::thread_rng();
        let secret = new(&mut rng);
        let public_key = PublicKey::from(&secret);

        let encoded = encode_public_key(public_key);
        let decoded = decode_public_key(&encoded).unwrap();

        assert_eq!(public_key, decoded);
    }

    #[test]
    fn invalid_public_key() {
        // Create a Bytes object that is too short
        let invalid_bytes = Bytes::from(vec![1, 2, 3]); // Length 3 instead of 32
        let result = decode_public_key(&invalid_bytes);
        assert!(matches!(result, Err(Error::InvalidEphemeralPublicKey)));

        // Create Bytes object that's too long
        let too_long_bytes = Bytes::from(vec![0u8; 33]); // Length 33
        let result = decode_public_key(&too_long_bytes);
        assert!(matches!(result, Err(Error::InvalidEphemeralPublicKey)));
    }
}
