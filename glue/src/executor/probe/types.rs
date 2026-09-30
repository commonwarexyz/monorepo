//! Checkpoints a probe serves and samples.

use commonware_consensus::{
    Block,
    aggregation::{scheme::Scheme, types::Certificate},
};
use std::sync::Arc;

/// A certified block of an executed chain, and where a node resumes marshal to execute after it.
#[derive(Clone, Debug)]
pub struct Checkpoint<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
{
    /// The certificate over the block's digest.
    pub certificate: Certificate<S, B::Digest>,
    /// The executed block the certificate names.
    pub block: Arc<B>,
    /// The floor its sender resumes marshal from at or below the block, if one is retained.
    /// Nothing checks a peer's floor before marshal installs it, so it may be anything.
    pub floor: Option<F>,
}

/// The newest checkpoint a sample of validators reported, and floors to resume marshal from.
#[derive(Clone, Debug)]
pub struct Sampled<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
{
    /// The certificate over the block's digest.
    pub certificate: Certificate<S, B::Digest>,
    /// The executed block the certificate names.
    pub block: Arc<B>,
    /// The floors the replies carried, newest round first.
    ///
    /// Each came from a different validator and is unverified: marshal verifies a floor when it
    /// installs it.
    pub floors: Vec<F>,
}
