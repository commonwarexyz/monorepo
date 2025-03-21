use bytes::Bytes;
use commonware_codec::{Codec, Error, Reader, Writer};
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

// Payload is the only allowed message format that can be sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload<C: Scheme> {
    /// Bit vector that represents the peers a peer knows about.
    ///
    /// Also used as a ping message to keep the connection alive.
    BitVec(BitVec),

    /// A vector of verifiable peer information.
    Peers(Vec<SignedPeerInfo<C>>),

    /// Arbitrary data sent between peers.
    Data(Data),
}

impl<C: Scheme> Codec for Payload<C> {
    fn write(&self, writer: &mut impl Writer) {
        match self {
            Payload::BitVec(bitvec) => {
                writer.write_u8(0);
                bitvec.write(writer);
            }
            Payload::Peers(peers) => {
                writer.write_u8(1);
                peers.write(writer);
            }
            Payload::Data(data) => {
                writer.write_u8(2);
                data.write(writer);
            }
        }
    }

    fn len_encoded(&self) -> usize {
        (match self {
            Payload::BitVec(bitvec) => bitvec.len_encoded(),
            Payload::Peers(peers) => peers.len_encoded(),
            Payload::Data(data) => data.len_encoded(),
        }) + 1
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let payload_type = reader.read_u8()?;
        match payload_type {
            0 => {
                let bitvec = BitVec::read(reader)?;
                Ok(Payload::BitVec(bitvec))
            }
            1 => {
                let peers = Vec::<SignedPeerInfo<C>>::read(reader)?;
                Ok(Payload::Peers(peers))
            }
            2 => {
                let data = Data::read(reader)?;
                Ok(Payload::Data(data))
            }
            _ => Err(Error::Invalid(
                "p2p::authenticated::Payload",
                "Invalid type",
            )),
        }
    }
}

/// BitVec is a bit vector that represents the peers a peer knows about at a given index.
///
/// A peer should respond with a `Peers` message if they know of any peers that the sender does not.
#[derive(Clone, Debug, PartialEq)]
pub struct BitVec {
    /// The index that the bit vector applies to.
    pub index: u64,

    /// The bit vector itself.
    pub bits: Vec<u8>,
}

impl Codec for BitVec {
    fn write(&self, writer: &mut impl Writer) {
        self.index.write(writer);
        self.bits.write(writer);
    }

    fn len_encoded(&self) -> usize {
        self.index.len_encoded() + self.bits.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let index = u64::read(reader)?;
        let bits = Vec::<u8>::read(reader)?;
        Ok(BitVec { index, bits })
    }
}

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedPeerInfo<C: Scheme> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: C::PublicKey,

    /// The peer's signature over the socket and timestamp.
    pub signature: C::Signature,
}

impl<C: Scheme> Codec for SignedPeerInfo<C> {
    fn write(&self, writer: &mut impl Writer) {
        self.socket.write(writer);
        self.timestamp.write(writer);
        self.public_key.write(writer);
        self.signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        self.socket.len_encoded()
            + self.timestamp.len_encoded()
            + self.public_key.len_encoded()
            + self.signature.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let socket = SocketAddr::read(reader)?;
        let timestamp = u64::read(reader)?;
        let public_key = C::PublicKey::read(reader)?;
        let signature = C::Signature::read(reader)?;
        Ok(SignedPeerInfo {
            socket,
            timestamp,
            public_key,
            signature,
        })
    }
}

// Data is an arbitrary message sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// A unique identifier for the channel the message is sent on.
    ///
    /// This is used to route the message to the correct handler.
    pub channel: u32,

    /// The payload of the message.
    pub message: Bytes,
}

impl Codec for Data {
    fn write(&self, writer: &mut impl Writer) {
        self.channel.write(writer);
        self.message.write(writer);
    }

    fn len_encoded(&self) -> usize {
        self.channel.len_encoded() + self.message.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let channel = u32::read(reader)?;
        let message = Bytes::read(reader)?;
        Ok(Data { channel, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Secp256r1;

    fn signed_peer_info() -> SignedPeerInfo<Secp256r1> {
        let mut rng = rand::thread_rng();
        let mut c = Secp256r1::new(&mut rng);
        SignedPeerInfo {
            socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
            timestamp: 1234567890,
            public_key: c.public_key(),
            signature: c.sign(None, &[1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn test_bitvec_codec() {
        let original = BitVec {
            index: 0,
            bits: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        let encoded = original.encode();
        let decoded = BitVec::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_signed_peer_info_codec() {
        let original = signed_peer_info();
        let encoded = original.encode();
        let decoded = SignedPeerInfo::<Secp256r1>::decode(encoded).unwrap();
        assert_eq!(original.socket, decoded.socket);
        assert_eq!(original.timestamp, decoded.timestamp);
        assert_eq!(original.public_key, decoded.public_key);
        assert_eq!(original.signature, decoded.signature);
    }

    #[test]
    fn test_data_codec() {
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
        };
        let encoded = original.encode();
        let decoded = Data::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_payload_codec() {
        // Test BitVec
        let original = BitVec {
            index: 0,
            bits: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        let encoded = Payload::<Secp256r1>::BitVec(original.clone()).encode();
        let decoded = match Payload::<Secp256r1>::decode(encoded) {
            Ok(Payload::<Secp256r1>::BitVec(b)) => b,
            _ => panic!(),
        };
        assert_eq!(original, decoded);

        // Test Peers
        let original = vec![signed_peer_info(), signed_peer_info()];
        let encoded = Payload::Peers(original.clone()).encode();
        let decoded = match Payload::<Secp256r1>::decode(encoded) {
            Ok(Payload::<Secp256r1>::Peers(p)) => p,
            _ => panic!(),
        };
        for (a, b) in original.iter().zip(decoded.iter()) {
            assert_eq!(a.socket, b.socket);
            assert_eq!(a.timestamp, b.timestamp);
            assert_eq!(a.public_key, b.public_key);
            assert_eq!(a.signature, b.signature);
        }

        // Test Data
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
        };
        let encoded = Payload::<Secp256r1>::Data(original.clone()).encode();
        let decoded = match Payload::<Secp256r1>::decode(encoded) {
            Ok(Payload::<Secp256r1>::Data(d)) => d,
            _ => panic!(),
        };
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_payload_decode_invalid_type() {
        let invalid_payload = vec![3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = Payload::<Secp256r1>::decode(invalid_payload);
        assert!(result.is_err());
    }
}
