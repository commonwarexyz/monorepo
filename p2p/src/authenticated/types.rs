use bytes::Bytes;
use commonware_codec::{Codec, Error, Reader, Writer};
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

// Payload is the only allowed message format that can be sent between peers.
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
#[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
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
