use crate::Array;
use commonware_runtime::Spawner;
use futures::channel::mpsc;
use futures::StreamExt;
use std::sync::{Arc, Mutex};

/// Message type for coordinator updates
pub enum CoordinatorMsg<P> {
    /// Update the peers list
    UpdatePeers(Vec<P>),
}

/// A coordinator that can be used for testing
#[derive(Clone)]
pub struct Coordinator<P: Array> {
    /// The state of the coordinator
    state: Arc<Mutex<State<P>>>,
}

/// The state of the coordinator
struct State<P: Array> {
    peers: Vec<P>,
    peer_set_id: u64,
}

impl<P: Array> Coordinator<P> {
    /// Creates a new coordinator with the given initial peers
    pub fn new(initial_peers: Vec<P>) -> Self {
        let state = State {
            peers: initial_peers,
            peer_set_id: 0,
        };

        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Creates a channel for sending updates to this coordinator
    pub fn create_update_channel<E: Spawner>(&self, context: E) -> mpsc::Sender<CoordinatorMsg<P>> {
        let (sender, mut receiver) = mpsc::channel(8);
        let coordinator = self.clone();

        context.spawn(|_| async move {
            while let Some(msg) = receiver.next().await {
                match msg {
                    CoordinatorMsg::UpdatePeers(new_peers) => {
                        let mut state = coordinator.state.lock().unwrap();
                        state.peers = new_peers;
                        state.peer_set_id += 1;
                    }
                }
            }
        });

        sender
    }

    /// Updates the peers of the coordinator directly
    /// Note: Prefer using the update channel in multithreaded contexts
    pub fn set_peers(&self, new_peers: Vec<P>) {
        let mut state = self.state.lock().unwrap();
        state.peers = new_peers;
        state.peer_set_id += 1;
    }

    // Helper to get a cloned vector to support the trait implementation
    fn get_peers(&self) -> Vec<P> {
        let state = self.state.lock().unwrap();
        state.peers.clone()
    }
}

impl<P: Array> crate::p2p::Coordinator for Coordinator<P> {
    type PublicKey = P;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        // Still using the hack for testing purposes
        let peers = self.get_peers();
        Box::leak(Box::new(peers))
    }

    fn peer_set_id(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.peer_set_id
    }

    fn is_peer(&self, public_key: &Self::PublicKey) -> bool {
        let state = self.state.lock().unwrap();
        state.peers.contains(public_key)
    }
}
