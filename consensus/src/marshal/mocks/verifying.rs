//! Mock verifying application for Marshaled wrapper tests.
//!
//! This module provides a generic mock application that implements both
//! `Application` and `VerifyingApplication` traits, suitable for testing
//! the `Marshaled` wrapper in both standard and coding variants.

use crate::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    types::Epoch, CertifiableBlock, Epochable,
};
use commonware_runtime::deterministic;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{marker::PhantomData, sync::Arc};

/// A mock application that implements `VerifyingApplication` for testing.
///
/// This mock:
/// - Returns the provided genesis block from `genesis()`
/// - Returns the configured block (if any) from `propose()`
/// - Returns a configurable result from `verify()`
#[derive(Clone)]
pub struct MockVerifyingApp<B, S, G = B> {
    /// The genesis block to return.
    pub genesis: G,
    /// The block returned by `propose`. If `None`, `propose` returns `None`.
    pub propose_result: Option<B>,
    /// The result returned by `verify`.
    pub verify_result: bool,
    _phantom: std::marker::PhantomData<S>,
}

impl<B, S, G> MockVerifyingApp<B, S, G> {
    /// Create a new mock verifying application with the given genesis block.
    pub fn new(genesis: G) -> Self {
        Self {
            genesis,
            propose_result: None,
            verify_result: true,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new mock verifying application with a fixed verify result.
    pub fn with_verify_result(genesis: G, verify_result: bool) -> Self {
        Self {
            genesis,
            propose_result: None,
            verify_result,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Configure the block returned by `propose`.
    pub fn with_propose_result(mut self, block: B) -> Self {
        self.propose_result = Some(block);
        self
    }
}

impl<B, S, G> crate::Application<deterministic::Context> for MockVerifyingApp<B, S, G>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
    G: Clone + Send + Sync + 'static,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;
    type Genesis = G;

    async fn genesis(&mut self, _epoch: Epoch) -> Self::Genesis {
        self.genesis.clone()
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: AncestorStream<A, Self::Block>,
    ) -> Option<Self::Block> {
        self.propose_result.clone()
    }
}

impl<B, S, G> crate::VerifyingApplication<deterministic::Context> for MockVerifyingApp<B, S, G>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
    G: Clone + Send + Sync + 'static,
{
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: AncestorStream<A, Self::Block>,
    ) -> bool {
        self.verify_result
    }
}

/// A verifying mock application whose `verify()` signals `started` on entry and
/// blocks until `release` is received. Used to deterministically control when
/// the application verdict races with marshal shutdown.
#[derive(Clone)]
pub struct GatedVerifyingApp<B, S, G = B> {
    genesis: G,
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    _phantom: PhantomData<(B, S)>,
}

impl<B, S, G> GatedVerifyingApp<B, S, G> {
    /// Returns the gated app, a `started` receiver fired when `verify()` is entered,
    /// and a `release` sender that unblocks `verify()` once signaled.
    pub fn new(genesis: G) -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        (
            Self {
                genesis,
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                _phantom: PhantomData,
            },
            started_rx,
            release_tx,
        )
    }
}

impl<B, S, G> crate::Application<deterministic::Context> for GatedVerifyingApp<B, S, G>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
    G: Clone + Send + Sync + 'static,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;
    type Genesis = G;

    async fn genesis(&mut self, _epoch: Epoch) -> Self::Genesis {
        self.genesis.clone()
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: AncestorStream<A, Self::Block>,
    ) -> Option<Self::Block> {
        None
    }
}

impl<B, S, G> crate::VerifyingApplication<deterministic::Context> for GatedVerifyingApp<B, S, G>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
    G: Clone + Send + Sync + 'static,
{
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: AncestorStream<A, Self::Block>,
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
