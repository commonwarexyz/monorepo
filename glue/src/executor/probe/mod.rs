//! Find a checkpoint to state-sync from, and serve this node's checkpoint to peers.
//!
//! A node whose executor starts from a checkpoint needs a recent block the validators certified,
//! and a floor to resume its marshal from. It cannot trust any single peer to name them, so the
//! [`Probe`] asks every validator for its newest [`Checkpoint`] and adopts the highest valid one
//! among replies from `f + 1` distinct validators, where `f` is the number of faults the
//! checkpoint scheme tolerates. [`join`] drives a joining node through it.
//!
//! # Protocol
//!
//! A sample sends a request to every validator. Each validator answers with its newest
//! checkpoint: a certificate, the executed block it certifies, and a floor at or below that block.
//! A reply counts only if its sender is a validator, its certificate verifies, its block is the
//! one the certificate names at the checkpoint's height, and its floor's certificate verifies.
//! A peer that sends anything else is blocked, and at most one reply counts per peer. Once `f + 1`
//! validators have replied, the highest checkpoint is selected. If too few reply, the sample is
//! requested again after `retry_timeout`.
//!
//! # Why the sample is `f + 1`
//!
//! A certificate is self-certifying: any checkpoint that verifies names a block the validators
//! agreed on. A Byzantine peer can still replay an old one to drag a joining node far behind. At
//! most `f` of `f + 1` repliers are faulty, so the selected checkpoint is at least as recent as the
//! newest one an honest validator reported.
//!
//! # Floors
//!
//! A floor is finalized by a consensus certificate, which the probe checks with its
//! [`FloorVerifier`], and ranked by that certificate's round. The index a floor resumes
//! the stream after is known only once marshal installs it, as marshal may first fetch the block
//! the certificate names, and marshal authenticates whatever the certificate does not cover. A
//! sample therefore returns every reply's floor, newest first, and [`join`] installs the first
//! marshal accepts, then waits for a checkpoint at or above the index it resumes after.
//!
//! # Serving
//!
//! The probe answers requests with its [`Source`]'s newest checkpoint, such as the one
//! [`Checkpoints`] holds with the engine marshal's floor at or below it
//! ([`Local`]). A node without a certified checkpoint stays silent.

use super::Checkpoints;
use commonware_codec::Codec;
use commonware_consensus::{
    Block, Roundable,
    aggregation::{scheme::Scheme, types::Certificate},
    marshal::Floors,
    types::OutputIndex,
};
use commonware_runtime::Clock;
use std::{future::Future, sync::Arc, time::Duration};

mod actor;
pub use actor::{Config, Probe};
mod mailbox;
pub use mailbox::Mailbox;
mod wire;

#[cfg(test)]
mod tests;

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
    /// The floor its sender resumes marshal from at or below the block, if one is retained. Only
    /// the floor's certificate is checked, so a peer's floor may lie anywhere.
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
    /// Floors whose certificates verify, newest round first.
    ///
    /// Each came from a different validator. Marshal authenticates the rest of a floor when it
    /// installs it.
    pub floors: Vec<F>,
}

/// Verifies the consensus certificate of a floor a validator serves.
pub trait FloorVerifier<F>: Send + 'static {
    /// Returns whether `floor`'s certificate verifies.
    fn verify(&mut self, floor: &F) -> bool;
}

impl<F, C: FnMut(&F) -> bool + Send + 'static> FloorVerifier<F> for C {
    fn verify(&mut self, floor: &F) -> bool {
        self(floor)
    }
}

/// Where a [`Probe`] finds the checkpoint it serves.
pub trait Source: Send + Sync + 'static {
    /// The scheme that certifies checkpoints.
    type Scheme: Scheme<<Self::Block as commonware_cryptography::Digestible>::Digest>;
    /// The executed block.
    type Block: Block;
    /// Where a marshal resumes from.
    type Floor: Roundable + Codec + Clone + Send + Sync + 'static;

    /// Returns the newest checkpoint to serve, if any.
    fn newest(
        &self,
    ) -> impl Future<Output = Option<Checkpoint<Self::Scheme, Self::Block, Self::Floor>>> + Send;
}

/// Serves the newest checkpoint of the executed chain, with the engine marshal's floor at or
/// below it.
pub struct Local<S, B, M>
where
    S: Scheme<B::Digest>,
    B: Block,
{
    /// The executed chain's checkpoints.
    pub checkpoints: Checkpoints<S, B>,
    /// The engine's marshal.
    pub marshal: M,
}

impl<S, B, M> Clone for Local<S, B, M>
where
    S: Scheme<B::Digest>,
    B: Block,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            checkpoints: self.checkpoints.clone(),
            marshal: self.marshal.clone(),
        }
    }
}

impl<S, B, M> Source for Local<S, B, M>
where
    S: Scheme<B::Digest>,
    B: Block,
    M: Floors,
    M::Floor: Codec,
{
    type Scheme = S;
    type Block = B;
    type Floor = M::Floor;

    async fn newest(&self) -> Option<Checkpoint<S, B, M::Floor>> {
        let (certificate, block) = self.checkpoints.newest().await?;
        let floor = self
            .marshal
            .floor_at(OutputIndex::new(block.height().get()))
            .await
            .ok()
            .flatten()
            .map(|(_, floor)| floor);
        Some(Checkpoint {
            certificate,
            block,
            floor,
        })
    }
}

/// Resumes `marshal` from the newest floor the validators serve, then offers `chain` the block of
/// a newly sampled checkpoint every `resample`, until the chain has a base.
///
/// A checkpoint is offered only once it is at or above the index marshal resumes after, so that
/// no input after the base is missing. A chain that already has a state sync target or a base, as
/// after a restart, keeps marshal where it is and is only offered newer checkpoints. Returns once
/// the chain has a base, or the probe stopped.
pub async fn join<E, S, B, M>(
    context: E,
    probe: Mailbox<S, B, M::Floor>,
    marshal: M,
    chain: super::Mailbox<B>,
    resample: Duration,
) where
    E: Clock,
    S: Scheme<B::Digest>,
    B: Block,
    M: Floors,
{
    let mut installing = chain.awaits_floor().await;
    let mut floor = None;
    loop {
        let Some(sampled) = probe.sample().await else {
            return;
        };
        if installing {
            for candidate in sampled.floors {
                if let Ok(Some(index)) = marshal.install(candidate).await {
                    floor = Some(index);
                    installing = false;
                    break;
                }
            }
        }
        let above =
            floor.is_none_or(|index: OutputIndex| sampled.block.height().get() >= index.get());
        if !installing && above && !chain.sync_to(sampled.block).await {
            return;
        }
        context.sleep(resample).await;
    }
}
