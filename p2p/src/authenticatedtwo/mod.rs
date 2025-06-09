use std::collections::{BTreeMap, HashMap};

use crate::authenticated::{
    tracker::directory::Directory,
    types::{self, PeerInfo},
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics, Network as RNetwork, Sink, SinkOf, Spawner, Stream, StreamOf,
};
use futures::{channel::mpsc, SinkExt, StreamExt as _};
use governor::clock::Clock as GClock;
use rand::{seq::SliceRandom as _, Rng};

enum Event<P: PublicKey, Si: Sink, St: Stream> {
    IncomingConnection { peer: P, sink: Si, stream: St },
    OutboundConnection { peer: P, sink: Si, stream: St },
    TryConnect,
    UpdateWantedPeers,
    SendPeers,
    PeerReady(P),
    PeerDisconnected(P),
    ReadMessage(P, types::Payload<P>),
}

struct Tracker<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> {
    context: E,
    peer_gossip_max_count: usize,
    directory: Directory<E, P>,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> Tracker<E, P> {
    fn handle_bit_vec(&mut self, bit_vec: types::BitVec) -> Vec<PeerInfo<P>> {
        let Some(mut peers) = self.directory.infos(bit_vec) else {
            // TODO danlaine: can this happen?
            return vec![];
        };

        // Truncate to a random selection of peers if we have too many infos
        let max = self.peer_gossip_max_count;
        if peers.len() > max {
            peers.partial_shuffle(&mut self.context, max);
            peers.truncate(max);
        }

        peers
    }

    fn handle_peers(&mut self, peers: Vec<types::PeerInfo<P>>) {
        self.directory.update_peers(peers);
    }
}

struct Peer<P: PublicKey> {
    tx: mpsc::Sender<types::Payload<P>>,
}

struct Network<E: RNetwork + Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> {
    context: E,
    events_rx: mpsc::Receiver<Event<P, SinkOf<E>, StreamOf<E>>>,
    channels: HashMap<u32, mpsc::Sender<Bytes>>,
    tracker: Tracker<E, P>,
    peers: HashMap<P, Peer<P>>,
    wanted_peers: Vec<P>,
    connections: BTreeMap<P, mpsc::Sender<types::Data>>,
}

impl<E: RNetwork + Spawner + Rng + Clock + GClock + RuntimeMetrics, P: PublicKey> Network<E, P> {
    pub async fn run(mut self, rx: mpsc::Receiver<Vec<u8>>) {
        loop {
            // Wait for an event.
            let Some(event) = self.events_rx.next().await else {
                break;
            };

            match event {
                Event::UpdateWantedPeers => {
                    self.wanted_peers = self.tracker.directory.dialable();
                }
                Event::TryConnect => {
                    while let Some(peer) = self.wanted_peers.pop() {
                        // TODO start task to try to dial peer
                    }
                }
                Event::IncomingConnection { peer, sink, stream } => {
                    if let Some(_) = self.tracker.directory.listen(&peer) {
                        continue;
                    }

                    // Create a new peer.
                    self.context
                        .with_label("peer")
                        .spawn(move |_context| async {
                            // TODO launch peer
                        });
                }
                Event::OutboundConnection { peer, sink, stream } => {
                    // TODO: check whether we should accept this connection
                    if self.peers.contains_key(&peer) {
                        // Peer already connected, skip.
                        continue;
                    }
                    // Create a new peer.
                    self.context
                        .with_label("peer")
                        .spawn(move |_context| async {
                            // TODO launch peer
                        });
                }
                Event::PeerReady(_peer) => {
                    // Peer is ready, we can now send messages to it.
                    // TODO: what do we need to do here?
                }
                Event::PeerDisconnected(_peer) => {
                    // Peer disconnected, remove it from the tracker and peers.
                    // TODO handle this
                }
                Event::ReadMessage(peer, message) => match message {
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
                _ => {
                    todo!()
                }
            }
        }
    }

    async fn next_event(&mut self) -> Option<Event<P, SinkOf<E>, StreamOf<E>>> {}
}
