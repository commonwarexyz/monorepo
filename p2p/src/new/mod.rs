use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    varint::UInt, Decode as _, EncodeSize, RangeCfg, Read, ReadExt as _, ReadRangeExt as _, Write,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::Clock;
use tracing::info;

use crate::new::peer_info::PeerInfo;

mod peer;
mod peer_info;
mod tracker;

enum Event<P: PublicKey> {
    PeerConnected(P),
    PeerReady(P),
    PeerDisconnected(P),
    ReceivedMessage(P, Vec<u8>),
    SentMessage(P),
}

struct Network<P: PublicKey, E: Signer<PublicKey = P, Signature = P::Signature> + Clock> {
    codec_config: CodecConfig,
    tracker: tracker::Tracker<P, E>,
}

impl<P: PublicKey, E: Signer<PublicKey = P, Signature = P::Signature> + Clock> Network<P, E> {
    async fn run(mut self) -> Result<(), Error> {
        loop {
            // Handle incoming events
            match self.next_event().await {
                Event::PeerConnected(peer) => {}
                Event::PeerReady(peer) => {
                    println!("Peer ready: {:?}", peer);
                }
                Event::PeerDisconnected(peer) => {
                    println!("Peer disconnected: {:?}", peer);
                }
                Event::ReceivedMessage(peer, msg) => {
                    let msg: Payload<P> =
                        match Payload::decode_cfg(Bytes::from(msg), &self.codec_config) {
                            Ok(msg) => msg,
                            Err(err) => {
                                info!(?err, ?peer, "failed to decode message");
                                return Err(Error::DecodeFailed(err));
                            }
                        };
                    match msg {
                        Payload::BitVec(bit_vec) => {
                            println!("Received BitVec from {:?}: {:?}", peer, bit_vec);
                            // Handle BitVec logic here
                        }
                        Payload::Peers(peers) => {
                            println!("Received Peers from {:?}: {:?}", peer, peers);
                            // Handle Peers logic here
                        }
                        Payload::Data(data) => {
                            println!("Received Data from {:?}: {:?}", peer, data);
                            // Handle Data logic here
                        }
                    }
                }
                Event::SentMessage(peer) => {
                    println!("Sent message to {:?}", peer);
                }
            }
        }
    }

    async fn next_event(&mut self) -> Event<P> {
        todo!()
    }
}

#[derive(Debug)]
enum Error {
    DecodeFailed(commonware_codec::Error),
    ReceiveError,
    SendError,
}

/// Configuration when deserializing messages.
///
/// This is used to limit the size of the messages received from peers.
#[derive(Clone)]
pub struct CodecConfig {
    /// The maximum number of peers that can be sent in a `Peers` message.
    pub max_peers: usize,

    /// The maximum number of bits that can be sent in a `BitVec` message.
    pub max_bit_vec: usize,
}

/// The maximum overhead (in bytes) when encoding a `message` into a [`Payload::Data`].
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
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
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
            _ => Err(commonware_codec::Error::Invalid(
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
    pub bits: commonware_utils::BitVec,
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
        let bits = commonware_utils::BitVec::read_cfg(buf, &(..=*max_bits).into())?;
        Ok(Self { index, bits })
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
