use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::{types::Context, Plan},
    types::{Epoch, Round},
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use commonware_cryptography::{
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256},
    Hasher,
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

const GENESIS_BYTES: &[u8] = b"genesis";

/// Shared state for the replay automaton.
///
/// Proposals are registered externally (by the replayer when processing
/// `Propose` actions) so that subsequent `verify` calls can find them.
#[derive(Default)]
struct Inner {
    known: HashSet<Sha256Digest>,
    /// Senders kept alive so that `propose()` receivers never resolve.
    /// Dropped together with the automaton at end of replay.
    parked_proposals: Vec<oneshot::Sender<Sha256Digest>>,
}

/// A replay-only automaton that replaces the mock application during model
/// replay. It stores proposal digests inserted by the replayer and uses
/// them to answer `verify` calls. `propose()` panics because the leader
/// path is handled via the `Proposed` voter hook.
#[derive(Clone)]
pub struct ReplayAutomaton {
    inner: Arc<Mutex<Inner>>,
}

impl ReplayAutomaton {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Register a proposal digest so that future `verify` calls succeed.
    pub fn register(&self, digest: Sha256Digest) {
        self.inner.lock().unwrap().known.insert(digest);
    }
}

impl Au for ReplayAutomaton {
    type Context = Context<Sha256Digest, PublicKey>;
    type Digest = Sha256Digest;

    async fn genesis(&mut self, epoch: Epoch) -> Sha256Digest {
        let mut hasher = Sha256::default();
        hasher.update(&(Bytes::from(GENESIS_BYTES), epoch).encode());
        let digest = hasher.finalize();
        self.inner.lock().unwrap().known.insert(digest);
        digest
    }

    async fn propose(
        &mut self,
        _context: Self::Context,
    ) -> oneshot::Receiver<Self::Digest> {
        // Return a receiver that never resolves. The leader path is driven
        // externally via the Proposed voter hook; the engine's internal
        // propose attempt must block indefinitely so it doesn't trigger a
        // timeout. We park the sender so it lives until the automaton is
        // dropped.
        let (tx, rx) = oneshot::channel();
        self.inner.lock().unwrap().parked_proposals.push(tx);
        rx
    }

    async fn verify(
        &mut self,
        _context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let known = self.inner.lock().unwrap().known.contains(&payload);
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(known);
        rx
    }
}

impl CAu for ReplayAutomaton {
    async fn certify(
        &mut self,
        _round: Round,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let result = (payload.as_ref().last().copied().unwrap_or(0) % 11) < 9;
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(result);
        rx
    }
}

impl Re for ReplayAutomaton {
    type Digest = Sha256Digest;
    type PublicKey = PublicKey;
    type Plan = Plan<PublicKey>;

    async fn broadcast(&mut self, _payload: Self::Digest, _plan: Plan<PublicKey>) {
        // No-op: replay doesn't need relay broadcast.
    }
}
