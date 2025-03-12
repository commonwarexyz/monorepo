use commonware_codec::{Codec, Reader, Writer, Error, Result};
use commonware_cryptography::Scheme;
use commonware_utils::Array;
use x25519_dalek::PublicKey as X25519PublicKey;

// Implement Codec for types that implement Array
impl<T: Array> Codec for T {
    fn write(&self, writer: &mut impl Writer) {
        let bytes = self.deref();
        for &byte in bytes {
            writer.write_u8(byte);
        }
    }

    fn read(reader: &mut impl Reader) -> Result<Self> {
        let len = T::SERIALIZED_LEN;
        let mut buf = vec![0u8; len];
        for i in 0..len {
            buf[i] = reader.read_u8()?;
        }
        T::try_from(&buf[..]).map_err(|e| Error::InvalidData {
            message: e.to_string(),
            context: "array".to_string(),
        })
    }
}

// Implement Codec for x25519_dalek::PublicKey
impl Codec for X25519PublicKey {
    fn write(&self, writer: &mut impl Writer) {
        let bytes = self.as_bytes(); // Returns &[u8; 32]
        for &byte in bytes {
            writer.write_u8(byte);
        }
    }

    fn read(reader: &mut impl Reader) -> Result<Self> {
        let mut buf = [0u8; 32];
        for i in 0..32 {
            buf[i] = reader.read_u8()?;
        }
        Ok(X25519PublicKey::from(buf))
    }
}

/// Handshake message used to establish an authenticated connection
#[derive(Debug, Clone, PartialEq)]
pub struct Handshake<C: Scheme> {
    pub recipient_public_key: C::PublicKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub timestamp: u64,
    pub public_key: C::PublicKey,
    pub signature: C::Signature,
}

impl<C: Scheme> Codec for Handshake<C>
where
    C::PublicKey: Array,
    C::Signature: Array,
{
    fn encode(&self, writer: &mut impl Writer) {
        writer.write(&self.recipient_public_key);
        writer.write(&self.ephemeral_public_key);
        writer.write_u64(self.timestamp);
        writer.write(&self.public_key);
        writer.write(&self.signature);
    }

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let recipient_public_key = reader.read()?;
        let ephemeral_public_key = reader.read()?;
        let timestamp = reader.read_u64()?;
        let public_key = reader.read()?;
        let signature = reader.read()?;
        Ok(Self {
            recipient_public_key,
            ephemeral_public_key,
            timestamp,
            public_key,
            signature,
        })
    }
}
