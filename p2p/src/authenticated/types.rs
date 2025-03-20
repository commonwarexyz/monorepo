use bytes::Bytes;
use commonware_codec::{Codec, Error, Reader, Writer};
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

// Payload is the only allowed message format that can be sent between peers.
pub enum Payload<C: Scheme> {
    BitVec(BitVec),

    // Peers is gossiped to peers periodically to
    // inform them of new peers that they can connect to.
    //
    // Peer will include their signed IP in this message.
    Peers(Vec<SignedPeerInfo<C>>),

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

// BitVec is a bit vector that represents the peers a peer
// knows about at a given index.
//
// A peer should respond with a Peers message
// if they know of any peers that the sender does not.
#[derive(Clone)]
pub struct BitVec {
    pub index: u64,
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

/// TODO
#[derive(Clone)]
pub struct PeerInfo {
    pub socket: SocketAddr,
    pub timestamp: u64,
}

impl Codec for PeerInfo {
    fn write(&self, writer: &mut impl Writer) {
        self.socket.write(writer);
        self.timestamp.write(writer);
    }

    fn len_encoded(&self) -> usize {
        self.socket.len_encoded() + self.timestamp.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let socket = SocketAddr::read(reader)?;
        let timestamp = u64::read(reader)?;
        Ok(PeerInfo { socket, timestamp })
    }
}

// Peer will send its signed IP to the recipient for gossip
// after the handshake has been established.
#[derive(Clone)]
pub struct SignedPeerInfo<C: Scheme> {
    pub info: PeerInfo,
    pub public_key: C::PublicKey,
    pub signature: C::Signature,
}

impl<C: Scheme> Codec for SignedPeerInfo<C> {
    fn write(&self, writer: &mut impl Writer) {
        self.info.write(writer);
        self.public_key.write(writer);
        self.signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        self.info.len_encoded() + self.public_key.len_encoded() + self.signature.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let info = PeerInfo::read(reader)?;
        let public_key = C::PublicKey::read(reader)?;
        let signature = C::Signature::read(reader)?;
        Ok(SignedPeerInfo {
            info,
            public_key,
            signature,
        })
    }
}

// Data is an arbitrary message sent between peers.
#[derive(Clone)]
pub struct Data {
    pub channel: u32,
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
