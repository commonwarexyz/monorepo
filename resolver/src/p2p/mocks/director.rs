use crate::Array;
use std::sync::{Arc, Mutex};

pub struct Director<P: Array> {
    state: Arc<Mutex<State<P>>>,
}

struct State<P: Array> {
    peers: Vec<P>,
    peer_set_id: u64,
}

impl<P: Array> Director<P> {
    pub fn new(initial_peers: Vec<P>) -> Self {
        let state = State {
            peers: initial_peers,
            peer_set_id: 0,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn set_peers(&self, new_peers: Vec<P>) {
        let mut state = self.state.lock().unwrap();
        state.peers = new_peers;
        state.peer_set_id += 1;
    }

    // Helper to get a cloned vector as a workaround
    fn get_peers(&self) -> Vec<P> {
        let state = self.state.lock().unwrap();
        state.peers.clone()
    }
}

impl<P: Array> Clone for Director<P> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<P: Array> crate::p2p::Director for Director<P> {
    type PublicKey = P;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        // This is a hack: we leak a cloned vector to satisfy the trait.
        // Not recommended for production, only for testing.
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
