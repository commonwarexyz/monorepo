use std::collections::HashMap;

use crate::authenticated::{
    tracker::directory::Directory,
    types::{self, PeerInfo},
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics, Network as RNetwork, Sink, SinkOf, Spawner, Stream, StreamOf,
};
use futures::{channel::mpsc, SinkExt};
use governor::clock::Clock as GClock;
use rand::{seq::SliceRandom as _, Rng};

enum Event<P: PublicKey> {
    IncomingConnection,
    ReadMessage(P, types::Payload<P>),
}

struct Tracker<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> {
    context: E,
    peer_gossip_max_count: usize,
    directory: Directory<E, P>,
    _phantom: std::marker::PhantomData<P>, // TODO remove
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> Tracker<E, P> {
    fn handle_bit_vec(&mut self, bit_vec: types::BitVec) -> Vec<PeerInfo<P>> {
        // TODO implement
        let Some(mut infos) = self.directory.infos(bit_vec) else {
            // TODO danlaine: can this happen?
            return vec![];
        };

        // Truncate to a random selection of peers if we have too many infos
        let max = self.peer_gossip_max_count;
        if infos.len() > max {
            infos.partial_shuffle(&mut self.context, max);
            infos.truncate(max);
        }

        infos
    }

    fn handle_peers(&mut self, peers: Vec<types::PeerInfo<P>>) {
        self.directory.update_peers(peers);
    }
}

struct Peer<P: PublicKey> {
    tx: mpsc::Sender<types::Payload<P>>,
}

struct Network<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> {
    channels: HashMap<u32, mpsc::Sender<Bytes>>,
    tracker: Tracker<E, P>,
    peers: HashMap<P, Peer<P>>,
    _phantom: std::marker::PhantomData<P>, // TODO remove
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> Network<E, P> {
    pub async fn run(mut self, rx: mpsc::Receiver<Vec<u8>>) {
        loop {
            // Wait for an event.
            let event = self.next_event().await;

            // Process the event.
            match event {
                Some(Event::IncomingConnection) => {
                    // Handle incoming connection.
                    // TODO implement
                }
                Some(Event::ReadMessage(peer, message)) => match message {
                    types::Payload::BitVec(bit_vec) => {
                        let peer_infos = self.tracker.handle_bit_vec(bit_vec);
                        if peer_infos.is_empty() {
                            // No peers to gossip to, skip.
                            continue;
                        }
                        let Some(peer) = self.peers.get_mut(&peer) else {
                            // Peer not found, skip.
                            continue;
                        };
                        peer.tx
                            .send(types::Payload::Peers(peer_infos))
                            .await
                            .expect("Failed to send peers to peer");
                    }
                    types::Payload::Peers(peers) => {
                        self.tracker.handle_peers(peers);
                    }
                    types::Payload::Data(data) => {
                        if let Some(tx) = self.channels.get_mut(&data.channel) {
                            tx.send(data.message).await.expect("Failed to send data");
                        }
                    }
                },
                None => {
                    // No more events, exit loop.
                    break;
                }
            }
        }
    }

    async fn next_event(&mut self) -> Option<Event<P>> {
        // TODO implement
        None
    }
}
