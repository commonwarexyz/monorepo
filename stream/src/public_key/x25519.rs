use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Error as CodecError, SizedCodec};
use rand::{CryptoRng, Rng};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKey {
    inner: X25519PublicKey,
}

impl PublicKey {
    pub fn from_secret(secret: &EphemeralSecret) -> Self {
        PublicKey {
            inner: X25519PublicKey::from(secret),
        }
    }

    #[cfg(test)]
    pub fn from_bytes(array: [u8; 32]) -> Self {
        PublicKey {
            inner: X25519PublicKey::from(array),
        }
    }
}

impl AsRef<x25519_dalek::PublicKey> for PublicKey {
    fn as_ref(&self) -> &x25519_dalek::PublicKey {
        &self.inner
    }
}

impl Codec for PublicKey {
    fn write<B: BufMut>(&self, buf: &mut B) {
        self.inner.as_bytes().write(buf);
    }
    fn read<B: Buf>(buf: &mut B) -> Result<Self, CodecError> {
        let public_key = <[u8; Self::LEN_ENCODED]>::read(buf)?;
        Ok(PublicKey {
            inner: X25519PublicKey::from(public_key),
        })
    }
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }
}

impl SizedCodec for PublicKey {
    const LEN_ENCODED: usize = 32;
}

pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralSecret {
    EphemeralSecret::random_from_rng(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_runtime::deterministic::Executor;

    #[test]
    fn test_codec() {
        // Create a random public key
        let (_, mut context, _) = Executor::default();
        let mut buf = [0u8; PublicKey::LEN_ENCODED];
        context.fill(&mut buf);

        let original = PublicKey {
            inner: X25519PublicKey::from(buf),
        };
        let encoded = original.encode();
        assert_eq!(encoded.len(), PublicKey::LEN_ENCODED);
        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_decode_invalid() {
        // Create a Bytes object that is too short
        let invalid_bytes = Bytes::from(vec![1, 2, 3]); // Length 3 instead of 32
        let result = PublicKey::decode(invalid_bytes);
        assert!(result.is_err());

        // Create Bytes object that's too long
        let too_long_bytes = Bytes::from(vec![0u8; 33]); // Length 33
        let result = PublicKey::decode(too_long_bytes);
        assert!(result.is_err());
    }
}
