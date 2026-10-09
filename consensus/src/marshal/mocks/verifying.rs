//! Mock verifying application for Marshaled wrapper tests.
//!
//! This module provides a generic mock application that implements the
//! `Application` trait, suitable for testing the `Marshaled` wrapper in
//! both standard and coding variants.

use crate::{
    CertifiableBlock, Epochable, Handoff,
    marshal::ancestry::{Ancestry, Parent},
};
use commonware_runtime::{deterministic, reschedule};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{future::pending, marker::PhantomData, sync::Arc};

/// A mock application that implements `Application` for testing.
///
/// This mock:
/// - Returns the configured block (if any) from `propose()`
/// - Returns a configurable result from `verify()`
/// - Rejects blocks matching an optional predicate in `verify()`
#[derive(Clone)]
pub struct MockVerifyingApp<B, S> {
    /// The block returned by `propose`. If `None`, `propose` returns `None`.
    pub propose_result: Option<B>,
    /// The result returned by `verify`.
    pub verify_result: bool,
    /// The decision `prepare` attaches to a built block. `Wait` declines without asking for
    /// the parent.
    handoff: Handoff<()>,
    /// Whether `prepare` asks the parent handle for its ancestry before building. When false,
    /// `prepare` returns `propose_result` under its decision without asking, and marshal must
    /// discard it.
    ask_parent: bool,
    /// Whether `prepare` returns `propose_result` under its decision even when the parent
    /// handle yields no ancestry, which marshal must discard.
    ignore_absence: bool,
    /// Whether `prepare` suspends once before building, so marshal drives it from a task
    /// instead of answering it on its first poll.
    suspend: bool,
    /// Shared by clones so that only the first proposal build waits on the gate.
    proposal_gate: Option<Arc<Mutex<Option<ProposalGate>>>>,
    /// Blocks for which `verify` returns false.
    pub reject: Option<fn(&B) -> bool>,
    _phantom: PhantomData<S>,
}

impl<B, S> MockVerifyingApp<B, S> {
    /// Create a new mock verifying application.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new mock verifying application with a fixed verify result.
    pub fn with_verify_result(verify_result: bool) -> Self {
        Self {
            verify_result,
            ..Self::default()
        }
    }

    /// Configure the block returned by `propose`.
    pub fn with_propose_result(mut self, block: B) -> Self {
        self.propose_result = Some(block);
        self
    }

    /// Configure the blocks for which `verify` returns false.
    pub fn with_reject(mut self, reject: fn(&B) -> bool) -> Self {
        self.reject = Some(reject);
        self
    }

    /// Configure the decision `prepare` attaches to a built block.
    pub const fn with_handoff(mut self, handoff: Handoff<()>) -> Self {
        self.handoff = handoff;
        self
    }

    /// Make `prepare` return `propose_result` without asking the parent handle.
    pub const fn without_parent(mut self) -> Self {
        self.ask_parent = false;
        self
    }

    /// Make `prepare` return `propose_result` even when the parent handle yields no ancestry.
    pub const fn ignoring_absence(mut self) -> Self {
        self.ignore_absence = true;
        self
    }

    /// Make `prepare` suspend once before building.
    pub const fn suspending(mut self) -> Self {
        self.suspend = true;
        self
    }

    /// Blocks the first proposal build until cancellation. Returns a receiver that
    /// signals when the build starts and one that errors when the build is cancelled.
    pub fn with_proposal_gate(mut self) -> (Self, oneshot::Receiver<()>, oneshot::Receiver<()>) {
        let (started, started_rx) = oneshot::channel();
        let (dropped, dropped_rx) = oneshot::channel();
        self.proposal_gate = Some(Arc::new(Mutex::new(Some(ProposalGate {
            started,
            dropped,
        }))));
        (self, started_rx, dropped_rx)
    }
}

struct ProposalGate {
    started: oneshot::Sender<()>,
    dropped: oneshot::Sender<()>,
}

impl<B, S> Default for MockVerifyingApp<B, S> {
    fn default() -> Self {
        Self {
            propose_result: None,
            verify_result: true,
            handoff: Handoff::Wait,
            ask_parent: true,
            ignore_absence: false,
            suspend: false,
            proposal_gate: None,
            reject: None,
            _phantom: PhantomData,
        }
    }
}

impl<B, S> crate::Application<deterministic::Context> for MockVerifyingApp<B, S>
where
    B: CertifiableBlock,
    B::Context: Epochable + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;
    type Input = ();

    async fn propose(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
    ) -> Option<Self::Block> {
        let gate = self
            .proposal_gate
            .as_ref()
            .and_then(|gate| gate.lock().take());
        if let Some(gate) = gate {
            // Cancelling this future drops the sender, which errors the receiver.
            let _dropped = gate.dropped;
            gate.started.send_lossy(());
            pending::<()>().await;
        }
        self.propose_result.clone()
    }

    async fn prepare(
        &mut self,
        context: (deterministic::Context, Self::Context),
        parent: impl Parent<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Self::Block> {
        if self.handoff.is_wait() {
            return Handoff::Wait;
        }
        let decision = self.handoff;
        if self.suspend {
            reschedule().await;
        }
        if !self.ask_parent {
            let block = self
                .propose_result
                .clone()
                .expect("unasked prepare needs a block");
            return decision.map(|()| block);
        }
        let Some(ancestry) = parent.ancestry().await else {
            if !self.ignore_absence {
                return Handoff::Wait;
            }
            let block = self
                .propose_result
                .clone()
                .expect("prepare ignoring an absent ancestry needs a block");
            return decision.map(|()| block);
        };
        self.propose(context, ancestry, input)
            .await
            .map_or(Handoff::Wait, |block| decision.map(|()| block))
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if let (Some(reject), Some(block)) = (self.reject, ancestry.peek())
            && reject(block)
        {
            return false;
        }
        self.verify_result
    }
}

/// A verifying mock application whose `verify()` signals `started` on entry and
/// blocks until `release` is received. Used to deterministically control when
/// the application verdict races with marshal shutdown.
#[derive(Clone)]
pub struct GatedVerifyingApp<B, S> {
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    _phantom: PhantomData<(B, S)>,
}

impl<B, S> GatedVerifyingApp<B, S> {
    /// Returns the gated app, a `started` receiver fired when `verify()` is entered,
    /// and a `release` sender that unblocks `verify()` once signaled.
    pub fn new() -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        (
            Self {
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                _phantom: PhantomData,
            },
            started_rx,
            release_tx,
        )
    }
}

impl<B, S> crate::Application<deterministic::Context> for GatedVerifyingApp<B, S>
where
    B: CertifiableBlock,
    B::Context: Epochable + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;
    type Input = ();

    async fn propose(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _input: Self::Input,
    ) -> Option<Self::Block> {
        None
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if let Some(started) = self.started.lock().take() {
            started.send_lossy(());
        }
        let release = self
            .release
            .lock()
            .take()
            .expect("release receiver missing");
        let _ = release.await;
        true
    }
}
