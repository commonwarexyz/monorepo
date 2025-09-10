use crate::authenticated::data::Data;
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{PublicKey, Signer};
use std::net::SocketAddr;

/// The maximum overhead (in bytes) when encoding a `message` into a [Payload::Data].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Payload enum value
/// - 5: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_PAYLOAD_DATA_OVERHEAD: usize = 1 + 5 + 5;

/// Prefix byte used to identify a [Payload] with variant BitVec.
const BIT_VEC_PREFIX: u8 = 0;
/// Prefix byte used to identify a [Payload] with variant Peers.
const PEERS_PREFIX: u8 = 1;
/// Prefix byte used to identify a [Payload] with variant Data.
const DATA_PREFIX: u8 = 2;

const BITMAP_CHUNK_SIZE: usize = 1;
type UtilsBitMap = commonware_utils::bitmap::BitMap<BITMAP_CHUNK_SIZE>;

/// Configuration when deserializing messages.
///
/// This is used to limit the size of the messages received from peers.
#[derive(Clone)]
pub struct Config {
    /// The maximum number of peers that can be sent in a `Peers` message.
    pub max_peers: usize,

    /// The maximum number of bits that can be sent in a `BitVec` message.
    pub max_bit_vec: usize,
}

/// Payload is the only allowed message format that can be sent between peers.
#[derive(Clone, Debug)]
pub enum Payload<C: PublicKey> {
    /// Bit vector that represents the peers a peer knows about.
    ///
    /// Also used as a ping message to keep the connection alive.
    BitVec(BitVec),

    /// A vector of verifiable peer information.
    Peers(Vec<PeerInfo<C>>),

    /// Arbitrary data sent between peers.
    Data(Data),
}

impl<C: PublicKey> EncodeSize for Payload<C> {
    fn encode_size(&self) -> usize {
        (match self {
            Payload::BitVec(bit_vec) => bit_vec.encode_size(),
            Payload::Peers(peers) => peers.encode_size(),
            Payload::Data(data) => data.encode_size(),
        }) + 1
    }
}

impl<C: PublicKey> Write for Payload<C> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::BitVec(bit_vec) => {
                BIT_VEC_PREFIX.write(buf);
                bit_vec.write(buf);
            }
            Payload::Peers(peers) => {
                PEERS_PREFIX.write(buf);
                peers.write(buf);
            }
            Payload::Data(data) => {
                DATA_PREFIX.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<C: PublicKey> Read for Payload<C> {
    type Cfg = Config;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let payload_type = <u8>::read(buf)?;
        match payload_type {
            BIT_VEC_PREFIX => {
                let bit_vec = BitVec::read_cfg(buf, &cfg.max_bit_vec)?;
                Ok(Payload::BitVec(bit_vec))
            }
            PEERS_PREFIX => {
                let peers = Vec::<PeerInfo<C>>::read_range(buf, ..=cfg.max_peers)?;
                Ok(Payload::Peers(peers))
            }
            DATA_PREFIX => {
                // Don't limit the size of the data to be read.
                // The max message size should already be limited by the p2p layer.
                let data = Data::read_cfg(buf, &(..).into())?;
                Ok(Payload::Data(data))
            }
            _ => Err(Error::Invalid(
                "p2p::authenticated::discovery::Payload",
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
    pub bits: UtilsBitMap,
}

impl EncodeSize for BitVec {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.bits.encode_size()
    }
}

impl Write for BitVec {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.bits.write(buf);
    }
}

impl Read for BitVec {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_bits: &usize) -> Result<Self, Error> {
        let index = UInt::read(buf)?.into();
        let bits = UtilsBitMap::read_cfg(buf, &(..=*max_bits).into())?;
        Ok(Self { index, bits })
    }
}

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug)]
pub struct PeerInfo<C: PublicKey> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp (epoch milliseconds) at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: C,

    /// The peer's signature over the socket and timestamp.
    pub signature: C::Signature,
}

impl<C: PublicKey> PeerInfo<C> {
    /// Verify the signature of the peer info.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        self.public_key.verify(
            Some(namespace),
            &(self.socket, self.timestamp).encode(),
            &self.signature,
        )
    }

    pub fn sign<Sk: Signer<PublicKey = C, Signature = C::Signature>>(
        signer: &Sk,
        namespace: &[u8],
        socket: SocketAddr,
        timestamp: u64,
    ) -> Self {
        let signature = signer.sign(Some(namespace), &(socket, timestamp).encode());
        PeerInfo {
            socket,
            timestamp,
            public_key: signer.public_key(),
            signature,
        }
    }
}

impl<C: PublicKey> EncodeSize for PeerInfo<C> {
    fn encode_size(&self) -> usize {
        self.socket.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.public_key.encode_size()
            + self.signature.encode_size()
    }
}

impl<C: PublicKey> Write for PeerInfo<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.socket.write(buf);
        UInt(self.timestamp).write(buf);
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<C: PublicKey> Read for PeerInfo<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let socket = SocketAddr::read(buf)?;
        let timestamp = UInt::read(buf)?.into();
        let public_key = C::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(PeerInfo {
            socket,
            timestamp,
            public_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use commonware_codec::{Decode, DecodeRangeExt};
    use commonware_cryptography::{secp256r1, PrivateKeyExt as _};

    fn signed_peer_info() -> PeerInfo<secp256r1::PublicKey> {
        let mut rng = rand::thread_rng();
        let c = secp256r1::PrivateKey::from_rng(&mut rng);
        PeerInfo {
            socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
            timestamp: 1234567890,
            public_key: c.public_key(),
            signature: c.sign(None, &[1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn test_bit_vec_codec() {
        let original = BitVec {
            index: 1234,
            bits: UtilsBitMap::ones(71),
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
        let decoded = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(encoded, 3..=3).unwrap();
        for (original, decoded) in original.iter().zip(decoded.iter()) {
            assert_eq!(original.socket, decoded.socket);
            assert_eq!(original.timestamp, decoded.timestamp);
            assert_eq!(original.public_key, decoded.public_key);
            assert_eq!(original.signature, decoded.signature);
        }

        let too_short = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(original.encode(), ..3);
        assert!(matches!(too_short, Err(Error::InvalidLength(3))));

        let too_long = Vec::<PeerInfo<secp256r1::PublicKey>>::decode_range(original.encode(), 4..);
        assert!(matches!(too_long, Err(Error::InvalidLength(3))));
    }

    #[test]
    fn test_payload_codec() {
        // Config for the codec
        let cfg = Config {
            max_peers: 10,
            max_bit_vec: 1024,
        };

        // Test BitVec
        let original = BitVec {
            index: 1234,
            bits: UtilsBitMap::ones(100),
        };
        let encoded: BytesMut = Payload::<secp256r1::PublicKey>::BitVec(original.clone()).encode();
        let decoded = match Payload::<secp256r1::PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<secp256r1::PublicKey>::BitVec(b)) => b,
            _ => panic!(),
        };
        assert_eq!(original, decoded);

        // Test Peers
        let original = vec![signed_peer_info(), signed_peer_info()];
        let encoded = Payload::Peers(original.clone()).encode();
        let decoded = match Payload::<secp256r1::PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<secp256r1::PublicKey>::Peers(p)) => p,
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
        let encoded = Payload::<secp256r1::PublicKey>::Data(original.clone()).encode();
        let decoded = match Payload::<secp256r1::PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<secp256r1::PublicKey>::Data(d)) => d,
            _ => panic!(),
        };
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_payload_decode_invalid_type() {
        let cfg = Config {
            max_peers: 10,
            max_bit_vec: 1024,
        };
        let invalid_payload = [3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = Payload::<secp256r1::PublicKey>::decode_cfg(&invalid_payload[..], &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_payload_data_overhead() {
        let message = Bytes::from(vec![0; 1 << 29]);
        let message_len = message.len();
        let payload = Payload::<secp256r1::PublicKey>::Data(Data {
            channel: u32::MAX,
            message,
        });
        assert_eq!(
            payload.encode_size(),
            message_len + MAX_PAYLOAD_DATA_OVERHEAD
        );
    }
}
