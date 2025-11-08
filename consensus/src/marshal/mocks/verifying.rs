//! Mock verifying application for Marshaled wrapper tests.
//!
//! This module provides a generic mock application that implements both
//! `Application` and `VerifyingApplication` traits, suitable for testing
//! the `Marshaled` wrapper in both standard and coding variants.

use crate::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    CertifiableBlock, Epochable,
};
use commonware_runtime::deterministic;

/// A mock application that implements `VerifyingApplication` for testing.
///
/// This mock:
/// - Returns the provided genesis block from `genesis()`
/// - Returns `None` from `propose()` (never proposes)
/// - Returns `true` from `verify()` (always accepts)
#[derive(Clone)]
pub struct MockVerifyingApp<B, S> {
    /// The genesis block to return.
    pub genesis: B,
    _phantom: std::marker::PhantomData<S>,
}

impl<B, S> MockVerifyingApp<B, S> {
    /// Create a new mock verifying application with the given genesis block.
    pub fn new(genesis: B) -> Self {
        Self {
            genesis,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B, S> crate::Application<deterministic::Context> for MockVerifyingApp<B, S>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
{
    type Block = B;
    type Context = B::Context;
    type SigningScheme = S;

    async fn genesis(&mut self) -> Self::Block {
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

impl<B, S> crate::VerifyingApplication<deterministic::Context> for MockVerifyingApp<B, S>
where
    B: CertifiableBlock + Clone + Send + Sync + 'static,
    B::Context: Epochable + Clone + Send + Sync + 'static,
    S: commonware_cryptography::certificate::Scheme + Clone + Send + Sync + 'static,
{
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: AncestorStream<A, Self::Block>,
    ) -> bool {
        true
    }
}
