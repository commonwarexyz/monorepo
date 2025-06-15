use std::{collections::HashMap, os::unix::net::SocketAddr};

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::public_key::Connection;

pub struct Config {}

enum Peer<P: PublicKey, Si: Sink, St: Stream> {
    AddressUnknown(P),
    Disconnected(P, SocketAddr),
    Connecting(P, SocketAddr),
    Connected(P, SocketAddr, Connection<Si, St>),
}

enum PeerStatus {}

struct Router {}

struct Spawner {}

struct Tracker {}

pub struct Network<P: PublicKey, Si: Sink, St: Stream> {
    peers: HashMap<P, Peer<P, Si, St>>,
}

impl<P: PublicKey, Si: Sink, St: Stream> Network<P, Si, St> {
    fn process_event(&mut self, event: Event<P, Si, St>) -> Result<(), Error> {
        match event {
            Event::PeerConnected(peer_id, peer_addr, connection) => {
                self.handle_peer_connected(peer_id, peer_addr, connection)
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
        peer_id: P,
        peer_addr: SocketAddr,
        connection: Connection<Si, St>,
    ) -> Result<(), Error> {
        let peer = self
            .peers
            .entry(peer_id.clone())
            .or_insert(Peer::AddressUnknown(peer_id.clone()));
        match peer {
            Peer::Connected(..) => Err(Error::AlreadyConnected),
            _ => {
                *peer = Peer::Connected(peer_id, peer_addr, connection);
                Ok(())
            }
        }
    }

    fn handle_peer_disconnected(&mut self, peer_id: P) -> Result<(), Error> {
        // Error if peer doesn't exist
        let peer = self.peers.get_mut(&peer_id).ok_or(Error::PeerNotFound)?;
        match peer {
            Peer::Connected(_, addr, _) => {
                *peer = Peer::Disconnected(peer_id, addr.clone());
                Ok(())
            }
            _ => Err(Error::PeerNotFound),
        }
    }

    fn handle_message_received(&mut self, _peer_id: P, _message: Bytes) -> Result<(), Error> {
        Ok(())
    }

    fn handle_send_message(&mut self, _peer_id: P) -> Result<(), Error> {
        Ok(())
    }
}

enum Event<P: PublicKey, Si: Sink, St: Stream> {
    PeerConnected(P, SocketAddr, Connection<Si, St>),
    PeerDisconnected(P),
    MessageReceived(P, Bytes),
    SendMessage(P),
}

#[derive(Debug, Clone)]
enum Error {
    PeerNotFound,
    AlreadyConnected,
    ConnectionError,
    MessageError,
    TimeoutError,
}
