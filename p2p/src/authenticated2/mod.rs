use crate::authenticated2::{
    message::{Message, PeerInfo},
    set::Set,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode as _};
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_stream::{
    public_key::{Connection, Receiver, Sender},
    Receiver as _, Sender as _,
};
use commonware_utils::SystemTimeExt as _;
use futures::{channel::mpsc, SinkExt as _, StreamExt};
use std::{collections::HashMap, time::Duration};

mod message;
mod set;

pub struct Config {}

enum Peer<P: PublicKey> {
    Myself(PeerInfo<P>),
    AddressUnknown(P),
    Disconnected(PeerInfo<P>),
    Connecting(PeerInfo<P>),
    Connected(PeerInfo<P>, mpsc::Sender<Bytes>, mpsc::Receiver<(P, Bytes)>),
}

enum PeerStatus {}

struct Router {}

struct Tracker {}

struct Directory {}

async fn peer_receive_loop<P: PublicKey, St: Stream>(
    mut receiver: Receiver<St>,
    peer_id: P,
    mut tx: mpsc::Sender<(P, Bytes)>,
) -> Result<(), Error> {
    loop {
        // Read message
        let msg = receiver.receive().await.map_err(|_| Error::ReceiveError)?;

        // Send message to handler
        if tx.send((peer_id.clone(), msg)).await.is_err() {
            // TODO should this error?
            return Ok(());
        }
    }
}

async fn peer_send_loop<Si: Sink>(
    mut sender: Sender<Si>,
    mut rx: mpsc::Receiver<Bytes>,
) -> Result<(), Error> {
    loop {
        // Read message
        let Some(msg) = rx.next().await else {
            // If the receiver is closed, we stop sending messages
            // TODO should this error?
            return Ok(());
        };

        // Send message to handler
        sender.send(&msg).await.map_err(|_| Error::SendError)?;
    }
}

pub struct Network<C: Clock + Spawner, Sk: Signer, Si: Sink, St: Stream> {
    context: C,
    ip_namespace: Vec<u8>,
    my_sk: Sk,
    synchrony_bound: Duration,
    peer_gossip_max_count: usize,
    codec_cfg: message::Config,
    peer_set: Set<Sk::PublicKey>,
    peers: HashMap<Sk::PublicKey, Peer<Sk::PublicKey>>,
    directory: Directory,
    _phantom_si: std::marker::PhantomData<Si>,
    _phantom_st: std::marker::PhantomData<St>,
}

impl<C: Clock + Spawner, Sk: Signer, Si: Sink, St: Stream> Network<C, Sk, Si, St> {
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
        let (sender, receiver) = connection.split();

        let (receive_tx, receive_rx) = mpsc::channel(100);
        let peer_pub_key = peer.public_key.clone();
        self.context
            .clone()
            .spawn(move |_| peer_receive_loop(receiver, peer_pub_key, receive_tx));

        let (send_tx, send_rx) = mpsc::channel(100);
        self.context
            .clone()
            .spawn(move |_| peer_send_loop(sender, send_rx));

        *existing_peer = Peer::Connected(peer, send_tx, receive_rx);
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
            self.handle_peer_disconnected(peer_id);
            return Ok(());
        };
        match msg {
            Message::BitVec(bit_vec) => self.handle_bit_vec_message(peer_id, bit_vec),
            Message::Peers(peers) => {
                self.handle_peers_message(peer_id, peers);
                Ok(())
            }
            Message::Data(data) => self.handle_data_message(peer_id, data),
        }
    }

    fn handle_bit_vec_message(
        &mut self,
        peer_id: Sk::PublicKey,
        bit_vec: message::BitVec,
    ) -> Result<(), Error> {
        let now = self.context.current().epoch_millis();
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
                    Peer::Connected(peer_info, _, _) => {
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
        peer_id: Sk::PublicKey,
        peers: Vec<message::PeerInfo<Sk::PublicKey>>,
    ) {
        // Ensure there aren't too many peers sent
        if peers.len() > self.peer_gossip_max_count {
            self.handle_peer_disconnected(peer_id);
            return;
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        let my_public_key = self.my_sk.public_key();
        let now = self.context.current().epoch();
        for peer in &peers {
            // Check if IP is allowed
            // if !self.allow_private_ips && !ip::is_global(peer.socket.ip()) {
            //     return Err(Error::PrivateIPsNotAllowed(peer.socket.ip()));
            // }

            // Check if peer is us
            if peer.public_key == my_public_key {
                self.handle_peer_disconnected(peer_id);
                return;
            }

            // If any timestamp is too far into the future, disconnect from the peer
            if Duration::from_millis(peer.timestamp) > now + self.synchrony_bound {
                // TODO disconnect from the peer
                self.handle_peer_disconnected(peer_id);
                return;
            }

            // If any signature is invalid, disconnect from the peer
            if !peer.verify(&self.ip_namespace) {
                // TODO disconnect from the peer
                self.handle_peer_disconnected(peer_id);
                return;
            }
        }

        for peer in peers {
            let peer_id = peer.public_key.clone();
            let Some(existing_peer) = self.peers.remove(&peer_id) else {
                // TODO disconnect from the peer
                self.handle_peer_disconnected(peer_id);
                return;
            };

            match existing_peer {
                Peer::Myself(_) => {
                    // We should never receive a peer info for ourselves
                    // TODO disconnect from the peer
                    self.handle_peer_disconnected(peer_id);
                    return;
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
                Peer::Connected(existing_peer, sender, receiver) => {
                    let peer = if existing_peer.timestamp >= peer.timestamp {
                        Peer::Connected(existing_peer, sender, receiver)
                    } else {
                        Peer::Connected(peer, sender, receiver)
                    };
                    self.peers.insert(peer_id, peer);
                }
            }
        }
    }

    fn close_peer(&mut self, peer_id: Sk::PublicKey) {
        let peer = self.peers.remove(&peer_id).ok_or(Error::PeerNotFound)?;
        match peer {
            Peer::Connected(_, mut sender, mut receiver) => {
                // Close the sender and receiver
                sender.close();
                receiver.close();
            }
            _ => {}
        }
    }

    // async fn send_peers_message(
    //     &mut self,
    //     peer_id: Sk::PublicKey,
    //     peers: Vec<message::PeerInfo<Sk::PublicKey>>,
    // ) -> Result<(), Error> {
    //     let peer = self.peers.get(&peer_id).ok_or(Error::PeerNotFound)?;
    //     match peer {
    //         Peer::Connected(_, sender, _) => {
    //             let msg = Message::Peers(peers);
    //             let msg = msg.encode();
    //             sender
    //                 .send(&msg)
    //                 .await
    //                 .map_err(|_| Error::ConnectionError)?;

    //             Ok(())
    //         }
    //         _ => Err(Error::PeerNotConnected),
    //     }
    // }

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
    ReceiveError,
    ConnectionError,
    MessageError,
    SendError,
    TimeoutError,
    TooManyPeers(usize),
}
