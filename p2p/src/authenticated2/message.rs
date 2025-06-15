use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    varint::UInt, Encode as _, EncodeSize, RangeCfg, Read, ReadExt as _, ReadRangeExt as _, Write,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_utils::BitVec as UtilsBitVec;
use std::net::SocketAddr;

/// The maximum overhead (in bytes) when encoding a `message` into a [`Message::Data`].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Message enum value
/// - 5: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_MESSAGE_DATA_OVERHEAD: usize = 1 + 5 + 5;

/// Prefix byte used to identify a [Message] with variant BitVec.
const BIT_VEC_PREFIX: u8 = 0;
/// Prefix byte used to identify a [Message] with variant Peers.
const PEERS_PREFIX: u8 = 1;
/// Prefix byte used to identify a [Message] with variant Data.
const DATA_PREFIX: u8 = 2;

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

/// Message is the only allowed message format that can be sent between peers.
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Bit vector that represents the peers a peer knows about.
    ///
    /// Also used as a ping message to keep the connection alive.
    BitVec(BitVec),

    /// A vector of verifiable peer information.
    Peers(Vec<PeerInfo<C>>),

    /// Arbitrary data sent between peers.
    Data(Data),
}

impl<C: PublicKey> EncodeSize for Message<C> {
    fn encode_size(&self) -> usize {
        (match self {
            Message::BitVec(bit_vec) => bit_vec.encode_size(),
            Message::Peers(peers) => peers.encode_size(),
            Message::Data(data) => data.encode_size(),
        }) + 1
    }
}

impl<C: PublicKey> Write for Message<C> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Message::BitVec(bit_vec) => {
                BIT_VEC_PREFIX.write(buf);
                bit_vec.write(buf);
            }
            Message::Peers(peers) => {
                PEERS_PREFIX.write(buf);
                peers.write(buf);
            }
            Message::Data(data) => {
                DATA_PREFIX.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<C: PublicKey> Read for Message<C> {
    type Cfg = Config;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let message_type = <u8>::read(buf)?;
        match message_type {
            BIT_VEC_PREFIX => {
                let bit_vec = BitVec::read_cfg(buf, &cfg.max_bit_vec)?;
                Ok(Message::BitVec(bit_vec))
            }
            PEERS_PREFIX => {
                let peers = Vec::<PeerInfo<C>>::read_range(buf, ..=cfg.max_peers)?;
                Ok(Message::Peers(peers))
            }
            DATA_PREFIX => {
                // Don't limit the size of the data to be read.
                // The max message size should already be limited by the p2p layer.
                let data = Data::read_cfg(buf, &(..).into())?;
                Ok(Message::Data(data))
            }
            _ => Err(commonware_codec::Error::Invalid(
                "p2p::authenticated::Message",
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

    fn read_cfg(buf: &mut impl Buf, max_bits: &usize) -> Result<Self, commonware_codec::Error> {
        let index = UInt::read(buf)?.into();
        let bits = UtilsBitVec::read_cfg(buf, &(..=*max_bits).into())?;
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

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
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
        UInt(self.channel).encode_size() + self.message.encode_size()
    }
}

impl Write for Data {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.channel).write(buf);
        self.message.write(buf);
    }
}

impl Read for Data {
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let channel = UInt::read(buf)?.into();
        let message = Bytes::read_cfg(buf, range)?;
        Ok(Data { channel, message })
    }
}
