//! Where a probe finds the checkpoint it serves.

use super::Checkpoint;
use crate::executor::Checkpoints;
use commonware_codec::Codec;
use commonware_consensus::{
    Block, Roundable,
    aggregation::scheme::Scheme,
    marshal::Floors,
    types::{Height, OutputIndex},
};
use commonware_cryptography::Digestible;
use std::{future::Future, num::NonZeroU64};

/// Where a [`Probe`](super::Probe) finds the checkpoint it serves.
pub trait Source: Clone + Send + Sync + 'static {
    /// The scheme that certifies checkpoints.
    type Scheme: Scheme<<Self::Block as Digestible>::Digest>;
    /// The executed block.
    type Block: Block;
    /// Where a marshal resumes from.
    type Floor: Roundable + Codec + Clone + Send + Sync + 'static;

    /// Returns the number of blocks per checkpoint: checkpoint `k` certifies the block at height
    /// `(k + 1) * interval - 1`.
    fn interval(&self) -> NonZeroU64;

    /// Returns the checkpoint height of the newest certified checkpoint, if any, without waiting.
    fn latest(&self) -> Option<Height>;

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

    fn interval(&self) -> NonZeroU64 {
        self.checkpoints.interval()
    }

    fn latest(&self) -> Option<Height> {
        self.checkpoints
            .latest()
            .map(|certificate| certificate.item.height)
    }

    async fn newest(&self) -> Option<Checkpoint<S, B, M::Floor>> {
        let (certificate, block) = self.checkpoints.latest_retained().await?;
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
