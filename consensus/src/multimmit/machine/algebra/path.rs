//! Proposal and vote path reconstruction.

use super::Error;
use crate::{
    multimmit::types::{
        Anchor, BlockRef, ChainId, LeaderBlock, Position, TransactionBlockHeader, VoteBody,
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// Read-only parent lookup used by authenticated path reconstruction.
pub(crate) trait Ancestry<D: Digest> {
    /// Returns the immediate parent of `block`, if it is locally available.
    fn parent(&self, block: BlockRef<D>) -> Option<BlockRef<D>>;
}

/// A compact ancestry index for reconstructed proposal and vote paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathIndex<D: Digest> {
    parents: BTreeMap<BlockRef<D>, BlockRef<D>>,
}

impl<D: Digest> Default for PathIndex<D> {
    fn default() -> Self {
        Self {
            parents: BTreeMap::new(),
        }
    }
}

impl<D: Digest> PathIndex<D> {
    /// Adds one authenticated parent edge to the index.
    pub(crate) fn insert_parent(
        &mut self,
        child: BlockRef<D>,
        parent: BlockRef<D>,
    ) -> Result<(), Error> {
        if parent.chain() != child.chain()
            || parent.height().get().checked_add(1) != Some(child.height().get())
        {
            return Err(Error::Vote);
        }
        if self
            .parents
            .get(&child)
            .is_some_and(|existing| *existing != parent)
        {
            return Err(Error::ConflictingAncestry);
        }
        self.parents.entry(child).or_insert(parent);
        Ok(())
    }

    /// Adds one contiguous chain path to the index.
    pub(crate) fn insert(&mut self, path: &[BlockRef<D>]) -> Result<(), Error> {
        self.validate(path)?;
        for pair in path.windows(2) {
            self.insert_parent(pair[1], pair[0])?;
        }
        Ok(())
    }

    /// Checks whether one path can be added without mutating the index.
    pub(crate) fn validate(&self, path: &[BlockRef<D>]) -> Result<(), Error> {
        for pair in path.windows(2) {
            let parent = pair[0];
            let child = pair[1];
            if parent.chain() != child.chain()
                || parent.height().get().checked_add(1) != Some(child.height().get())
            {
                return Err(Error::Vote);
            }
            if self
                .parents
                .get(&child)
                .is_some_and(|existing| *existing != parent)
            {
                return Err(Error::ConflictingAncestry);
            }
        }
        Ok(())
    }

    /// Returns whether `descendant` extends or equals `ancestor` in this index.
    pub(crate) fn extends_or_equals(
        &self,
        ancestor: BlockRef<D>,
        descendant: BlockRef<D>,
    ) -> Result<bool, Error> {
        if ancestor.chain() != descendant.chain() || ancestor.height() > descendant.height() {
            return Ok(false);
        }
        let mut current = descendant;
        while current.height() > ancestor.height() {
            current = self.parent(current).ok_or(Error::Vote)?;
        }
        Ok(current == ancestor)
    }
}

impl<D: Digest> Ancestry<D> for PathIndex<D> {
    fn parent(&self, block: BlockRef<D>) -> Option<BlockRef<D>> {
        self.parents.get(&block).copied()
    }
}

/// Materialized proposal paths, including each proposal anchor at index zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProposalPaths<D: Digest> {
    chains: Vec<Vec<BlockRef<D>>>,
    anchor_parents: Vec<Option<(BlockRef<D>, BlockRef<D>)>>,
}

impl<D: Digest> ProposalPaths<D> {
    /// Reconstructs every block reference pinned by `leader`.
    pub(crate) fn new<H, V>(leader: &LeaderBlock<V, D>) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        let mut chains = Vec::with_capacity(leader.proposals().len());
        let mut anchor_parents = Vec::with_capacity(leader.proposals().len());
        for (index, proposal) in leader.proposals().iter().enumerate() {
            let chain = ChainId::new(
                u32::try_from(index).map_err(|_| Error::Chain(ChainId::new(u32::MAX)))?,
            );
            let anchor = proposal.anchor().block_ref::<H>();
            let parent = match proposal.anchor() {
                Anchor::Tip(_) => None,
                Anchor::Certificate(certificate) => {
                    let height = certificate
                        .header()
                        .height()
                        .get()
                        .checked_sub(1)
                        .ok_or(Error::Vote)?;
                    Some((
                        anchor,
                        BlockRef::new(chain, Height::new(height), certificate.header().parent()),
                    ))
                }
            };
            let mut path = Vec::with_capacity(proposal.len() + 1);
            path.push(anchor);
            append_payloads::<H, V, D>(leader, chain, &mut path, proposal.payloads())?;
            chains.push(path);
            anchor_parents.push(parent);
        }
        Ok(Self {
            chains,
            anchor_parents,
        })
    }

    /// Returns one proposal path from its anchor through its proposed tip.
    pub(crate) fn chain(&self, chain: ChainId) -> Result<&[BlockRef<D>], Error> {
        self.chains
            .get(chain.get() as usize)
            .map(Vec::as_slice)
            .ok_or(Error::Chain(chain))
    }

    /// Returns the proposal block at a proposal-relative position.
    pub(crate) fn block(&self, chain: ChainId, position: Position) -> Result<BlockRef<D>, Error> {
        self.chain(chain)?
            .get(position.get() as usize)
            .copied()
            .ok_or(Error::Vote)
    }

    /// Returns the number of producer chains.
    pub(crate) const fn len(&self) -> usize {
        self.chains.len()
    }

    /// Adds every reconstructed proposal edge to `index`.
    pub(crate) fn index(&self, index: &mut PathIndex<D>) -> Result<(), Error> {
        for (child, parent) in self.anchor_parents.iter().flatten() {
            index.insert_parent(*child, *parent)?;
        }
        for path in &self.chains {
            index.insert(path)?;
        }
        Ok(())
    }
}

/// Materialized endorsed paths for one complete vote.
///
/// Each chain starts at the proposal anchor, follows the reported proposal position, and then
/// follows the vote's extension. Keeping this representation beside an admitted vote lets pool
/// updates reuse reconstruction work across every extraction pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VotePaths<D: Digest> {
    chains: Vec<Vec<BlockRef<D>>>,
}

impl<D: Digest> VotePaths<D> {
    /// Reconstructs the paths authenticated by `vote`.
    pub(crate) fn new<H, V>(
        leader: &LeaderBlock<V, D>,
        leader_digest: D,
        proposals: &ProposalPaths<D>,
        vote: &VoteBody<D>,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        if !vote.valid_for_digest(leader, leader_digest)
            || proposals.len() != leader.proposals().len()
            || vote.positions().len() != proposals.len()
            || vote.extensions().len() != proposals.len()
        {
            return Err(Error::Vote);
        }

        let mut chains = Vec::with_capacity(proposals.len());
        for index in 0..proposals.len() {
            let chain = ChainId::new(u32::try_from(index).map_err(|_| Error::Vote)?);
            let position = vote.positions()[index];
            let proposal = proposals.chain(chain)?;
            let prefix_end = position.get() as usize;
            let prefix = proposal.get(..=prefix_end).ok_or(Error::Vote)?;
            let extension = vote.extensions().get(index).ok_or(Error::Vote)?;
            let mut path = Vec::with_capacity(prefix.len() + extension.len());
            path.extend_from_slice(prefix);
            append_payloads::<H, V, D>(leader, chain, &mut path, extension.payloads())?;
            chains.push(path);
        }
        Ok(Self { chains })
    }

    /// Returns the endorsed path on one producer chain.
    pub(crate) fn chain(&self, chain: ChainId) -> Result<&[BlockRef<D>], Error> {
        self.chains
            .get(chain.get() as usize)
            .map(Vec::as_slice)
            .ok_or(Error::Chain(chain))
    }

    /// Adds every reconstructed vote edge to `index`.
    pub(crate) fn index(&self, index: &mut PathIndex<D>) -> Result<(), Error> {
        for path in &self.chains {
            index.insert(path)?;
        }
        Ok(())
    }

    /// Checks every vote path against `index` without mutating it.
    pub(crate) fn validate_index(&self, index: &PathIndex<D>) -> Result<(), Error> {
        for path in &self.chains {
            index.validate(path)?;
        }
        Ok(())
    }
}

fn append_payloads<H, V, D>(
    leader: &LeaderBlock<V, D>,
    chain: ChainId,
    path: &mut Vec<BlockRef<D>>,
    payloads: &[D],
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    for payload in payloads {
        let parent = path.last().copied().ok_or(Error::Vote)?;
        let height = parent
            .height()
            .get()
            .checked_add(1)
            .ok_or(Error::HeightOverflow)?;
        let header = TransactionBlockHeader::new(
            leader.round().epoch(),
            chain,
            Height::new(height),
            parent.digest(),
            *payload,
        )
        .map_err(|_| Error::HeightOverflow)?;
        path.push(header.block_ref::<H>());
    }
    Ok(())
}
