use crate::authenticated2::{
    message::{Message, PeerInfo},
    set::Set,
};
use bytes::Bytes;
use commonware_codec::Decode;
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::{Clock, Sink, Stream};
use commonware_stream::public_key::Connection;
use commonware_utils::SystemTimeExt as _;
use std::{collections::HashMap, net::SocketAddr, time::Duration};

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

pub struct Network<Cl: Clock, Sk: Signer, Si: Sink, St: Stream> {
    ip_namespace: Vec<u8>,
    my_sk: Sk,
    synchrony_bound: Duration,
    peer_gossip_max_count: usize,
    clock: Cl,
    codec_cfg: message::Config,
    peer_set: Set<Sk::PublicKey>,
    peers: HashMap<Sk::PublicKey, Peer<Sk::PublicKey, Si, St>>,
    directory: Directory,
}

impl<Cl: Clock, Sk: Signer, Si: Sink, St: Stream> Network<Cl, Sk, Si, St> {
    fn process_event(&mut self, event: Event<Sk::PublicKey, Si, St>) -> Result<(), Error> {
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
        peer: PeerInfo<Sk::PublicKey>,
        connection: Connection<Si, St>,
    ) -> Result<(), Error> {
        let existing_peer = self
            .peers
            .get_mut(&peer.public_key)
            .ok_or(Error::PeerNotFound)?;
        *existing_peer = Peer::Connected(peer.clone(), connection);
        Ok(())
    }

    fn handle_peer_disconnected(&mut self, peer_id: Sk::PublicKey) -> Result<(), Error> {
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

    fn handle_message_received(
        &mut self,
        peer_id: Sk::PublicKey,
        message: Bytes,
    ) -> Result<(), Error> {
        // Parse message
        let Ok(msg): Result<message::Message<Sk::PublicKey>, _> =
            Message::decode_cfg(message, &self.codec_cfg)
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
        peer_id: Sk::PublicKey,
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
        _peer_id: Sk::PublicKey,
        peers: Vec<message::PeerInfo<Sk::PublicKey>>,
    ) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        if peers.len() > self.peer_gossip_max_count {
            // TODO disconnect from the peer
            return Err(Error::TooManyPeers(peers.len()));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        let my_public_key = self.my_sk.public_key();
        let now = self.clock.current().epoch();
        for peer in &peers {
            // Check if IP is allowed
            // if !self.allow_private_ips && !ip::is_global(peer.socket.ip()) {
            //     return Err(Error::PrivateIPsNotAllowed(peer.socket.ip()));
            // }

            // Check if peer is us
            if peer.public_key == my_public_key {
                // TODO disconnect from the peer
                return Err(Error::PeersContainsMyself);
            }

            // If any timestamp is too far into the future, disconnect from the peer
            if Duration::from_millis(peer.timestamp) > now + self.synchrony_bound {
                // TODO disconnect from the peer
                return Err(Error::SynchronyBoundViolated);
            }

            // If any signature is invalid, disconnect from the peer
            if !peer.verify(&self.ip_namespace) {
                // TODO disconnect from the peer
                return Err(Error::InvalidSignature);
            }
        }

        for peer in peers {
            let peer_id = peer.public_key.clone();
            let Some(existing_peer) = self.peers.remove(&peer_id) else {
                // TODO disconnect from the peer
                return Err(Error::PeerNotFound);
            };

            match existing_peer {
                Peer::Myself(_) => {
                    // We should never receive a peer info for ourselves
                    // TODO disconnect from the peer
                    return Err(Error::PeerMyself);
                }
                Peer::AddressUnknown(_) => {
                    // If the peer was unknown, we can now add it as connected
                    self.peers.insert(peer_id, Peer::Disconnected(peer));
                }
                Peer::Disconnected(existing_peer) => {
                    // Only update the peer if the new peer info is more recent
                    let peer = if existing_peer.timestamp >= peer.timestamp {
                        Peer::Disconnected(existing_peer)
                    } else {
                        Peer::Disconnected(peer)
                    };
                    self.peers.insert(peer_id, peer);
                }
                Peer::Connecting(existing_peer) => {
                    let peer = if existing_peer.timestamp >= peer.timestamp {
                        Peer::Connecting(existing_peer)
                    } else {
                        // TODO notify connecting routine that address changed?
                        Peer::Connecting(peer)
                    };
                    self.peers.insert(peer_id, peer);
                }
                Peer::Connected(existing_peer, conn) => {
                    let peer = if existing_peer.timestamp >= peer.timestamp {
                        Peer::Connected(existing_peer, conn)
                    } else {
                        Peer::Connected(peer, conn)
                    };
                    self.peers.insert(peer_id, peer);
                }
            }
        }

        Ok(())
    }

    fn handle_data_message(
        &mut self,
        _peer_id: Sk::PublicKey,
        _data: message::Data,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn handle_send_message(&mut self, _peer_id: Sk::PublicKey) -> Result<(), Error> {
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
    PeersContainsMyself,
    InvalidSignature,
    SynchronyBoundViolated,
    AlreadyConnected,
    ConnectionError,
    MessageError,
    TimeoutError,
    TooManyPeers(usize),
}
