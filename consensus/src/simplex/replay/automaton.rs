//! Event-gated replay automaton.
//!
//! Unlike the honest mock [`Application`](crate::simplex::mocks::application::Application)
//! this automaton does **not** proactively produce proposals. Instead,
//! [`ReplayAutomaton::propose`] *parks* the oneshot sender keyed by the
//! proposed `(view, parent_view)`; the caller (the [`Replayer`](super::Replayer))
//! fires it via [`ReplayAutomaton::release`] when the matching
//! [`Event::Propose`](super::Event::Propose) arrives in the trace.
//!
//! Pre-arming is supported: if the driver reaches the `Propose` event
//! before the engine calls `propose()`, the digest is stashed in a
//! pending map and fires the next matching `propose()` call. This
//! removes the race we'd otherwise see when the engine races the driver.
//!
//! `verify()` succeeds whenever the payload has been registered (via
//! [`ReplayAutomaton::register`], called by the driver on every incoming
//! `Deliver` / `Propose` event so that the engine's normal verification
//! path always passes).
//!
//! `certify()` mirrors the honest `Certifier::Sometimes` policy from the
//! fuzz harness (`last_byte % 11 < 9`) so traces recorded there reproduce
//! identically.

use crate::{
    simplex::{types::Context, Plan},
    types::{Epoch, Round, View},
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256},
    Hasher,
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

const GENESIS_BYTES: &[u8] = b"genesis";

type ProposalKey = (View, View);

#[derive(Default)]
struct Inner {
    /// Digests registered via [`ReplayAutomaton::register`]; returning `true`
    /// from `verify`.
    known: HashSet<Sha256Digest>,
    /// Parked oneshot senders waiting for a matching `release`.
    parked: HashMap<ProposalKey, oneshot::Sender<Sha256Digest>>,
    /// Digests released before `propose()` was called for that key.
    pending: HashMap<ProposalKey, Sha256Digest>,
}

/// The replay automaton. Cloneable — same shared state.
#[derive(Clone)]
pub struct ReplayAutomaton {
    inner: Arc<Mutex<Inner>>,
}

impl Default for ReplayAutomaton {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayAutomaton {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Register `digest` so that a future `verify()` call succeeds for it.
    /// Idempotent.
    pub fn register(&self, digest: Sha256Digest) {
        self.inner.lock().unwrap().known.insert(digest);
    }

    /// Release a proposal digest for `(view, parent_view)`. Fires any
    /// parked `propose()` receiver for that key; otherwise stashes the
    /// digest to fire the next matching call.
    ///
    /// The digest is also registered so that `verify()` on a downstream
    /// node succeeds against the same payload.
    pub fn release(&self, view: View, parent_view: View, digest: Sha256Digest) {
        let key = (view, parent_view);
        let mut inner = self.inner.lock().unwrap();
        inner.known.insert(digest);
        if let Some(tx) = inner.parked.remove(&key) {
            tx.send_lossy(digest);
        } else {
            inner.pending.insert(key, digest);
        }
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

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let key: ProposalKey = (context.round.view(), context.parent.0);
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().unwrap();
        if let Some(digest) = inner.pending.remove(&key) {
            tx.send_lossy(digest);
        } else {
            inner.parked.insert(key, tx);
        }
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
        // Replay doesn't need relay broadcast. Block/digest dissemination
        // is irrelevant because we drive the engine with pre-signed votes.
    }
}
