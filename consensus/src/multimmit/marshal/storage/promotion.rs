//! Asynchronous immutable storage for finalized producer-block bodies.
//!
//! The durable cursor binds each producer frontier to the marshal generation that established
//! it. Generation-tagged output metadata makes state-sync jumps explicit, so recovery can replay
//! later outputs without depending on an in-memory install notification.

use super::archive::{FinalizedArchive, Shared};
use crate::multimmit::{
    marshal::types::OutputIndex,
    types::{BlockRef, TransactionBlock},
};
use commonware_codec::{Codec, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Digestible, Hasher};
use commonware_storage::{Context, metadata::Metadata, translator::Translator};
use commonware_utils::sequence::Unit;
use std::sync::Arc;

/// Durable immutable-promotion progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct PromotionState<D: Digest> {
    through: Option<OutputIndex>,
    frontiers: Vec<BlockRef<D>>,
    generations: Vec<u64>,
}

impl<D: Digest> PromotionState<D> {
    pub(in crate::multimmit::marshal) const fn new(
        through: Option<OutputIndex>,
        frontiers: Vec<BlockRef<D>>,
        generations: Vec<u64>,
    ) -> Self {
        Self {
            through,
            frontiers,
            generations,
        }
    }

    pub(in crate::multimmit::marshal) const fn through(&self) -> Option<OutputIndex> {
        self.through
    }

    /// Merges an installed floor without regressing bodies promoted beyond it.
    fn install(
        &mut self,
        generation: u64,
        frontiers: Vec<BlockRef<D>>,
    ) -> Result<bool, &'static str> {
        if frontiers.len() != self.frontiers.len()
            || frontiers
                .iter()
                .zip(&self.frontiers)
                .any(|(next, current)| {
                    next.chain() != current.chain()
                        || (next.height() == current.height() && next != current)
                })
        {
            return Err("immutable promotion frontiers are not monotonic");
        }
        let mut changed = false;
        for (chain, frontier) in frontiers.into_iter().enumerate() {
            if frontier.height() > self.frontiers[chain].height() {
                self.frontiers[chain] = frontier;
                changed = true;
            }
            if generation > self.generations[chain] {
                self.generations[chain] = generation;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Applies one dense output. A newer generation authenticates a state-sync jump.
    fn extend(
        &mut self,
        reference: BlockRef<D>,
        parent: D,
        generation: u64,
    ) -> Result<(), &'static str> {
        let chain = reference.chain().get() as usize;
        let Some(current) = self.frontiers.get(chain).copied() else {
            return Err("immutable promotion block has an unknown producer chain");
        };
        let direct = current.height().next() == reference.height() && parent == current.digest();
        let installed_jump =
            generation > self.generations[chain] && reference.height() > current.height();
        if generation < self.generations[chain] || (!direct && !installed_jump) {
            return Err("immutable promotion block does not extend its producer frontier");
        }
        self.frontiers[chain] = reference;
        self.generations[chain] = generation;
        Ok(())
    }
}

impl<D: Digest> Read for PromotionState<D> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl bytes::Buf, chains: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            through: Option::<OutputIndex>::read(buf)?,
            frontiers: Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?,
            generations: Vec::<u64>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?,
        })
    }
}

impl<D: Digest> Write for PromotionState<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.through.write(buf);
        self.frontiers.write(buf);
        self.generations.write(buf);
    }
}

impl<D: Digest> EncodeSize for PromotionState<D> {
    fn encode_size(&self) -> usize {
        self.through.encode_size() + self.frontiers.encode_size() + self.generations.encode_size()
    }
}

pub(in crate::multimmit::marshal) type FinalBody<T, E, H, B> =
    FinalizedArchive<T, E, <H as Hasher>::Digest, Shared<TransactionBlock<H, B>>>;

/// One finalized body ready for immutable promotion.
pub(in crate::multimmit::marshal) struct PromotedBody<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub index: OutputIndex,
    pub reference: BlockRef<H::Digest>,
    pub block: Arc<TransactionBlock<H, B>>,
    pub generation: u64,
}

/// Exclusive immutable archive state owned by the promoter actor.
pub(in crate::multimmit::marshal) struct Store<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    bodies: Option<FinalBody<T, E, H, B>>,
    metadata: Option<Metadata<E, Unit, PromotionState<H::Digest>>>,
    state: PromotionState<H::Digest>,
}

impl<T, E, H, B> Store<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) fn new(
        bodies: FinalBody<T, E, H, B>,
        metadata: Metadata<E, Unit, PromotionState<H::Digest>>,
    ) -> Result<Self, &'static str> {
        let state = metadata
            .get(&Unit)
            .cloned()
            .ok_or("immutable promotion state is missing")?;
        if state.frontiers.is_empty() {
            return Err("immutable promotion state has no producer chains");
        }
        if state.frontiers.len() != state.generations.len()
            || state
                .frontiers
                .iter()
                .enumerate()
                .any(|(chain, frontier)| frontier.chain().get() as usize != chain)
        {
            return Err("immutable promotion state has invalid producer coordinates");
        }
        Ok(Self {
            bodies: Some(bodies),
            metadata: Some(metadata),
            state,
        })
    }

    pub(in crate::multimmit::marshal) const fn through(&self) -> Option<OutputIndex> {
        self.state.through()
    }

    /// Advances a state-sync floor without inventing archived output rows.
    ///
    /// The output cursor is unchanged. The caller may reclaim temporary bodies below the new
    /// frontiers only after this metadata update is durable.
    pub(in crate::multimmit::marshal) async fn advance_frontiers(
        &mut self,
        generation: u64,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Result<Vec<BlockRef<H::Digest>>, String> {
        let mut next = self.state.clone();
        if !next.install(generation, frontiers)? {
            return Ok(next.frontiers);
        }
        let metadata = self
            .metadata
            .take()
            .expect("promoter owns promotion metadata")
            .put_sync(Unit, next.clone())
            .await
            .map_err(|error| error.to_string())?;
        self.metadata = Some(metadata);
        self.state = next;
        Ok(self.state.frontiers.clone())
    }

    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, String> {
        self.bodies
            .as_ref()
            .expect("promoter owns immutable bodies")
            .get_by_key(&reference.digest())
            .await
            .map_err(|error| error.to_string())
            .map(|block| {
                block
                    .map(Shared::into_inner)
                    .filter(|block| block.reference() == reference)
            })
    }

    pub(in crate::multimmit::marshal) async fn block_by_digest(
        &self,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, String> {
        self.bodies
            .as_ref()
            .expect("promoter owns immutable bodies")
            .get_by_key(&digest)
            .await
            .map_err(|error| error.to_string())
            .map(|block| block.map(Shared::into_inner))
    }

    /// Promotes one dense output batch and advances cleanup only after body durability.
    pub(in crate::multimmit::marshal) async fn promote(
        &mut self,
        outputs: Vec<PromotedBody<H, B>>,
    ) -> Result<Vec<BlockRef<H::Digest>>, String> {
        if outputs.is_empty() {
            return Ok(self.state.frontiers.clone());
        }
        let first = self
            .state
            .through
            .map_or(Some(OutputIndex::ZERO), OutputIndex::next)
            .ok_or_else(|| "immutable output index exhausted".to_string())?;
        let mut bodies = self.bodies.take().expect("promoter owns immutable bodies");
        let mut state = self.state.clone();
        for (offset, output) in outputs.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| "immutable promotion batch is too large".to_string())?;
            let expected = first
                .get()
                .checked_add(offset)
                .map(OutputIndex::new)
                .ok_or_else(|| "immutable output index exhausted".to_string())?;
            if output.index != expected || output.block.reference() != output.reference {
                return Err("immutable promotion batch is not dense and exact".into());
            }
            state.extend(
                output.reference,
                output.block.header().parent(),
                output.generation,
            )?;
            bodies = bodies
                .put(
                    output.index.get(),
                    output.reference.digest(),
                    Shared::new(Arc::clone(&output.block)),
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        self.bodies = Some(bodies.sync().await.map_err(|error| error.to_string())?);
        state.through = outputs.last().map(|output| output.index);
        let metadata = self
            .metadata
            .take()
            .expect("promoter owns promotion metadata")
            .put_sync(Unit, state.clone())
            .await
            .map_err(|error| error.to_string())?;
        self.metadata = Some(metadata);
        self.state = state;
        Ok(self.state.frontiers.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::{ChainId, Height};
    use commonware_cryptography::Sha256;

    type Sha256Digest = <Sha256 as Hasher>::Digest;

    fn reference(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[label]),
        )
    }

    #[test]
    fn generations_authorize_state_sync_jumps_without_regressing_frontiers() {
        let genesis = reference(0, 0, b"genesis");
        let mut state = PromotionState::new(None, vec![genesis], vec![0]);

        let first = reference(0, 1, b"first");
        state.extend(first, genesis.digest(), 0).unwrap();

        let jumped = reference(0, 5, b"jumped");
        state
            .extend(jumped, Sha256::hash(&[b"installed parent"]), 1)
            .unwrap();
        let continued = reference(0, 6, b"continued");
        state.extend(continued, jumped.digest(), 1).unwrap();

        let stale = reference(0, 7, b"stale");
        assert!(state.extend(stale, continued.digest(), 0).is_err());
        assert!(
            state
                .extend(stale, Sha256::hash(&[b"wrong parent"]), 1)
                .is_err()
        );

        assert!(!state.install(1, vec![jumped]).unwrap());
        assert_eq!(state.frontiers, vec![continued]);
        assert_eq!(state.generations, vec![1]);
    }
}
