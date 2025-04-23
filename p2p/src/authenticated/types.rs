use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    varint, Encode, EncodeSize, Error, RangeConfig, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::Verifier;
use commonware_utils::BitVec as UtilsBitVec;
use std::net::SocketAddr;

/// The maximum overhead (in bytes) when encoding a `message` into a [`Payload::Data`].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Payload enum value
/// - 5: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_PAYLOAD_DATA_OVERHEAD: usize = 1 + 5 + 5;

/// Configuration when deserializing messages.
///
/// This is used to limit the size of the messages received from peers.
#[derive(Clone)]
pub struct Config {
    /// The maximum number of peers that can be sent in a `Peers` message.
    pub max_peers: usize,

    /// The maximum number of bits that can be sent in a `BitVec` message.
    pub max_bitvec: usize,
}

/// Payload is the only allowed message format that can be sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload<C: Verifier> {
    /// Bit vector that represents the peers a peer knows about.
    ///
    /// Also used as a ping message to keep the connection alive.
    BitVec(BitVec),

    /// A vector of verifiable peer information.
    Peers(Vec<PeerInfo<C>>),

    /// Arbitrary data sent between peers.
    Data(Data),
}

impl<C: Verifier> EncodeSize for Payload<C> {
    fn encode_size(&self) -> usize {
        (match self {
            Payload::BitVec(bitvec) => bitvec.encode_size(),
            Payload::Peers(peers) => peers.encode_size(),
            Payload::Data(data) => data.encode_size(),
        }) + 1
    }
}

impl<C: Verifier> Write for Payload<C> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::BitVec(bitvec) => {
                0u8.write(buf);
                bitvec.write(buf);
            }
            Payload::Peers(peers) => {
                1u8.write(buf);
                peers.write(buf);
            }
            Payload::Data(data) => {
                2u8.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<C: Verifier> Read<Config> for Payload<C> {
    fn read_cfg(buf: &mut impl Buf, cfg: &Config) -> Result<Self, Error> {
        let payload_type = <u8>::read(buf)?;
        match payload_type {
            0 => {
                let bitvec = BitVec::read_cfg(buf, &cfg.max_bitvec)?;
                Ok(Payload::BitVec(bitvec))
            }
            1 => {
                let peers = Vec::<PeerInfo<C>>::read_range(buf, ..=cfg.max_peers)?;
                Ok(Payload::Peers(peers))
            }
            2 => {
                // Don't limit the size of the data to be read.
                // The max message size should already be limited by the p2p layer.
                let data = Data::read_cfg(buf, &(..))?;
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
    pub bits: UtilsBitVec,
}

impl EncodeSize for BitVec {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.bits.encode_size()
    }
}

impl Write for BitVec {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.bits.write(buf);
    }
}

impl Read<usize> for BitVec {
    fn read_cfg(buf: &mut impl Buf, max_bits: &usize) -> Result<Self, Error> {
        let index = u64::read(buf)?;
        let bits = UtilsBitVec::read_cfg(buf, &..=*max_bits)?;
        Ok(Self { index, bits })
    }
}

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerInfo<C: Verifier> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: C::PublicKey,

    /// The peer's signature over the socket and timestamp.
    pub signature: C::Signature,
}

impl<C: Verifier> PeerInfo<C> {
    /// Verify the signature of the peer info.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        C::verify(
            Some(namespace),
            &(self.socket, self.timestamp).encode(),
            &self.public_key,
            &self.signature,
        )
    }
}

impl<C: Verifier> EncodeSize for PeerInfo<C> {
    fn encode_size(&self) -> usize {
        self.socket.encode_size()
            + self.timestamp.encode_size()
            + self.public_key.encode_size()
            + self.signature.encode_size()
    }
}

impl<C: Verifier> Write for PeerInfo<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.socket.write(buf);
        self.timestamp.write(buf);
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<C: Verifier> Read for PeerInfo<C> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let socket = SocketAddr::read(buf)?;
        let timestamp = u64::read(buf)?;
        let public_key = C::PublicKey::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(PeerInfo {
            socket,
            timestamp,
            public_key,
            signature,
        })
    }
}

/// Data is an arbitrary message sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// A unique identifier for the channel the message is sent on.
    ///
    /// This is used to route the message to the correct handler.
    pub channel: u32,

    /// The payload of the message.
    pub message: Bytes,
}

impl EncodeSize for Data {
    fn encode_size(&self) -> usize {
        varint::size(self.channel) + self.message.encode_size()
    }
}

impl Write for Data {
    fn write(&self, buf: &mut impl BufMut) {
        varint::write(self.channel, buf);
        self.message.write(buf);
    }
}

impl<R: RangeConfig> Read<R> for Data {
    fn read_cfg(buf: &mut impl Buf, range: &R) -> Result<Self, Error> {
        let channel = varint::read::<u32>(buf)?;
        let message = Bytes::read_cfg(buf, range)?;
        Ok(Data { channel, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{Decode, DecodeRangeExt};
    use commonware_cryptography::{Secp256r1, Signer};

    fn signed_peer_info() -> PeerInfo<Secp256r1> {
        let mut rng = rand::thread_rng();
        let mut c = Secp256r1::new(&mut rng);
        PeerInfo {
            socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
            timestamp: 1234567890,
            public_key: c.public_key(),
            signature: c.sign(None, &[1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn test_bitvec_codec() {
        let original = BitVec {
            index: 1234,
            bits: UtilsBitVec::ones(71),
        };
        let decoded = BitVec::decode_cfg(original.encode(), &71).unwrap();
        assert_eq!(original, decoded);

        let too_short = BitVec::decode_cfg(original.encode(), &70);
        assert!(matches!(too_short, Err(Error::InvalidLength(71))));
    }

    #[test]
    fn test_signed_peer_info_codec() {
        let original = vec![signed_peer_info(), signed_peer_info(), signed_peer_info()];
        let encoded = original.encode();
        let decoded = Vec::<PeerInfo<Secp256r1>>::decode_range(encoded, 3..=3).unwrap();
        for (original, decoded) in original.iter().zip(decoded.iter()) {
            assert_eq!(original.socket, decoded.socket);
            assert_eq!(original.timestamp, decoded.timestamp);
            assert_eq!(original.public_key, decoded.public_key);
            assert_eq!(original.signature, decoded.signature);
        }

        let too_short = Vec::<PeerInfo<Secp256r1>>::decode_range(original.encode(), ..3);
        assert!(matches!(too_short, Err(Error::InvalidLength(3))));

        let too_long = Vec::<PeerInfo<Secp256r1>>::decode_range(original.encode(), 4..);
        assert!(matches!(too_long, Err(Error::InvalidLength(3))));
    }

    #[test]
    fn test_data_codec() {
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
        };
        let encoded = original.encode();
        let decoded = Data::decode_cfg(encoded, &(13..=13)).unwrap();
        assert_eq!(original, decoded);

        let too_short = Data::decode_cfg(original.encode(), &(0..13));
        assert!(matches!(too_short, Err(Error::InvalidLength(13))));

        let too_long = Data::decode_cfg(original.encode(), &(14..));
        assert!(matches!(too_long, Err(Error::InvalidLength(13))));
    }

    #[test]
    fn test_payload_codec() {
        // Config for the codec
        let cfg = Config {
            max_peers: 10,
            max_bitvec: 1024,
        };

        // Test BitVec
        let original = BitVec {
            index: 1234,
            bits: UtilsBitVec::ones(100),
        };
        let encoded: BytesMut = Payload::<Secp256r1>::BitVec(original.clone()).encode();
        let decoded = match Payload::<Secp256r1>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<Secp256r1>::BitVec(b)) => b,
            _ => panic!(),
        };
        assert_eq!(original, decoded);

        // Test Peers
        let original = vec![signed_peer_info(), signed_peer_info()];
        let encoded = Payload::Peers(original.clone()).encode();
        let decoded = match Payload::<Secp256r1>::decode_cfg(encoded, &cfg) {
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
        let decoded = match Payload::<Secp256r1>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<Secp256r1>::Data(d)) => d,
            _ => panic!(),
        };
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_payload_decode_invalid_type() {
        let cfg = Config {
            max_peers: 10,
            max_bitvec: 1024,
        };
        let invalid_payload = [3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = Payload::<Secp256r1>::decode_cfg(&invalid_payload[..], &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_payload_data_overhead() {
        let message = Bytes::from(vec![0; 1 << 29]);
        let message_len = message.len();
        let payload = Payload::<Secp256r1>::Data(Data {
            channel: u32::MAX,
            message,
        });
        assert_eq!(
            payload.encode_size(),
            message_len + MAX_PAYLOAD_DATA_OVERHEAD
        );
    }
}
