//! Operations over x25519 keys.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use rand::{CryptoRng, Rng};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// x25519 Public Key.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKey {
    inner: X25519PublicKey,
}

impl PublicKey {
    /// Derive a public key from a secret key.
    pub fn from_secret(secret: &EphemeralSecret) -> Self {
        PublicKey {
            inner: X25519PublicKey::from(secret),
        }
    }

    /// Parse a public key from a byte array.
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

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.as_bytes().write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let public_key = <[u8; Self::SIZE]>::read(buf)?;
        Ok(PublicKey {
            inner: X25519PublicKey::from(public_key),
        })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = 32;
}

/// Generate a new ephemeral secret for X25519 key exchange.
///
/// This creates a fresh ephemeral secret key that should be used for a single
/// key exchange and then discarded. The ephemeral nature provides forward secrecy.
pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralSecret {
    EphemeralSecret::random_from_rng(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_codec::{DecodeExt, Encode as _};
    use commonware_runtime::{deterministic, Runner};

    #[test]
    fn test_codec() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create a random public key
            let mut buf = [0u8; PublicKey::SIZE];
            context.fill(&mut buf);
            let original = PublicKey {
                inner: X25519PublicKey::from(buf),
            };
            // Encode and decode the public key
            let encoded = original.encode();
            assert_eq!(encoded.len(), PublicKey::SIZE);
            let decoded = PublicKey::decode(encoded).unwrap();
            assert_eq!(original, decoded);
        });
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
