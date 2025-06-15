use crate::authenticated2::{
    message::{Message, PeerInfo},
    set::Set,
};
use bytes::Bytes;
use commonware_codec::Decode;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Sink, Stream};
use commonware_stream::public_key::Connection;
use commonware_utils::SystemTimeExt as _;
use std::{collections::HashMap, net::SocketAddr};

mod message;
mod set;

pub struct Config {}

enum Peer<P: PublicKey, Si: Sink, St: Stream> {
    Myself(PeerInfo<P>),
    AddressUnknown(P),
    Disconnected(PeerInfo<P>),
    Connecting(PeerInfo<P>),
    Connected(PeerInfo<P>, Connection<Si, St>),
}

enum PeerStatus {}

struct Router {}

struct Spawner {}

struct Tracker {}

struct Directory {}

pub struct Network<Cl: Clock, P: PublicKey, Si: Sink, St: Stream> {
    clock: Cl,
    codec_cfg: message::Config,
    peer_set: Set<P>,
    peers: HashMap<P, Peer<P, Si, St>>,
    directory: Directory,
}

impl<Cl: Clock, P: PublicKey, Si: Sink, St: Stream> Network<Cl, P, Si, St> {
    fn process_event(&mut self, event: Event<P, Si, St>) -> Result<(), Error> {
        match event {
            Event::PeerConnected(peer_info, connection) => {
                self.handle_peer_connected(peer_info, connection)
            }
            Event::PeerDisconnected(peer_id) => self.handle_peer_disconnected(peer_id),
            Event::MessageReceived(peer_id, message) => {
                self.handle_message_received(peer_id, message)
            }
            Event::SendMessage(peer_id) => self.handle_send_message(peer_id),
        }
    }

    fn handle_peer_connected(
        &mut self,
        peer: PeerInfo<P>,
        connection: Connection<Si, St>,
    ) -> Result<(), Error> {
        let existing_peer = self
            .peers
            .get_mut(&peer.public_key)
            .ok_or(Error::PeerNotFound)?;
        *existing_peer = Peer::Connected(peer.clone(), connection);
        Ok(())
    }

    fn handle_peer_disconnected(&mut self, peer_id: P) -> Result<(), Error> {
        let peer = self.peers.remove(&peer_id).ok_or(Error::PeerNotFound)?;
        let peer = match peer {
            Peer::Connected(peer_info, ..) => Peer::Disconnected(peer_info),
            _ => {
                return Err(Error::PeerNotConnected);
            }
        };
        self.peers.insert(peer_id, peer);
        Ok(())
    }

    fn handle_message_received(&mut self, peer_id: P, message: Bytes) -> Result<(), Error> {
        // Parse message
        let Ok(msg): Result<message::Message<P>, _> = Message::decode_cfg(message, &self.codec_cfg)
        else {
            // TODO handle
            return Ok(());
        };
        match msg {
            Message::BitVec(bit_vec) => self.handle_bit_vec_message(peer_id, bit_vec),
            Message::Peers(peers) => self.handle_peers_message(peer_id, peers),
            Message::Data(data) => self.handle_data_message(peer_id, data),
        }
    }

    fn handle_bit_vec_message(
        &mut self,
        peer_id: P,
        bit_vec: message::BitVec,
    ) -> Result<(), Error> {
        let now = self.clock.current().epoch_millis();
        let peers: Vec<_> = bit_vec
            .bits
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                // We may have information signed over a timestamp greater than the current time,
                // but within our synchrony bound. Avoid sharing this information as it could get us
                // blocked by other peers due to clock skew. Consider timestamps earlier than the
                // current time to be safe enough to share.
                let peer = (!b).then_some(&self.peer_set[i])?;
                let peer = self.peers.get(peer)?;
                match peer {
                    Peer::Myself(peer_info) => {
                        if peer_info.timestamp <= now {
                            Some(peer_info.clone())
                        } else {
                            None
                        }
                    }
                    Peer::AddressUnknown(_) => todo!(),
                    Peer::Disconnected(peer_info) => {
                        if peer_info.timestamp <= now {
                            Some(peer_info.clone())
                        } else {
                            None
                        }
                    }
                    Peer::Connecting(peer_info) => {
                        if peer_info.timestamp <= now {
                            Some(peer_info.clone())
                        } else {
                            None
                        }
                    }
                    Peer::Connected(peer_info, _) => {
                        if peer_info.timestamp <= now {
                            Some(peer_info.clone())
                        } else {
                            // We could also consider the connection timestamp, but for simplicity,
                            // we just use the peer info timestamp.
                            None
                        }
                    }
                }
            })
            .collect();
        // TODO send peers to the peer
        Ok(())
    }

    fn handle_peers_message(
        &mut self,
        _peer_id: P,
        _peers: Vec<message::PeerInfo<P>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn handle_data_message(&mut self, _peer_id: P, _data: message::Data) -> Result<(), Error> {
        Ok(())
    }

    fn handle_send_message(&mut self, _peer_id: P) -> Result<(), Error> {
        Ok(())
    }
}

enum Event<P: PublicKey, Si: Sink, St: Stream> {
    PeerConnected(PeerInfo<P>, Connection<Si, St>),
    PeerDisconnected(P),
    MessageReceived(P, Bytes),
    SendMessage(P),
}

#[derive(Debug, Clone)]
enum Error {
    PeerMyself,
    PeerNotFound,
    PeerNotConnected,
    AlreadyConnected,
    ConnectionError,
    MessageError,
    TimeoutError,
}
