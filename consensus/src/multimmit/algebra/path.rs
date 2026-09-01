//! Proposal and vote path reconstruction.

use super::Error;
use crate::{
    multimmit::types::{
        Anchor, BlockRef, ChainId, DigestedLeader, LeaderBlock, Position, SelectedCommitments,
        TransactionBlockHeader, VoteBody,
    },
    types::{Epoch, Height},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
};

#[cfg(test)]
std::thread_local! {
    static PARENT_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_parent_lookups() -> usize {
    PARENT_LOOKUPS.with(|lookups| lookups.replace(0))
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
    /// Selects known contiguous suffixes, including only edges present in this index.
    pub(crate) fn selected(
        &self,
        epoch: Epoch,
        tips: impl IntoIterator<Item = BlockRef<D>>,
    ) -> SelectedCommitments<D> {
        let mut tips = tips.into_iter().collect::<BTreeSet<_>>();
        let mut paths = Vec::new();
        while let Some(tip) = tips.pop_last() {
            let mut path = vec![tip];
            let mut child = tip;
            while let Some(parent) = self.parents.get(&child) {
                path.push(*parent);
                tips.remove(parent);
                child = *parent;
            }
            if path.len() > 1 {
                path.reverse();
                paths.push(Arc::from(path));
            }
        }
        SelectedCommitments::new(epoch, paths)
    }

    /// Adds one authenticated parent edge to the index.
    pub(crate) fn insert_parent(
        &mut self,
        child: BlockRef<D>,
        parent: BlockRef<D>,
    ) -> Result<(), Error> {
        check_edge(parent, child)?;
        match self.parents.entry(child) {
            Entry::Occupied(entry) if *entry.get() != parent => {
                return Err(Error::ConflictingAncestry);
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(parent);
            }
        }
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
            check_edge(parent, child)?;
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
    #[cfg(test)]
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
            PARENT_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
            current = self.parents.get(&current).copied().ok_or(Error::Vote)?;
        }
        Ok(current == ancestor)
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
        chain_path(&self.chains, chain)
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

/// Reconstructed vote extensions, each seeded with its endorsed proposal block.
///
/// The seed supplies the parent for the first extension edge. Proposal prefixes remain in
/// [`ProposalPaths`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VotePaths<D: Digest> {
    chains: Vec<Vec<BlockRef<D>>>,
}

impl<D: Digest> VotePaths<D> {
    /// Reconstructs the paths authenticated by `vote`.
    pub(crate) fn new<H, V>(
        leader: DigestedLeader<'_, V, D>,
        proposals: &ProposalPaths<D>,
        vote: &VoteBody<D>,
    ) -> Result<Self, Error>
    where
        H: Hasher<Digest = D>,
        V: Variant,
    {
        if !vote.valid_for(leader)
            || proposals.len() != leader.block().proposals().len()
            || vote.positions().len() != proposals.len()
            || vote.extensions().len() != proposals.len()
        {
            return Err(Error::Vote);
        }

        let mut chains = Vec::with_capacity(proposals.len());
        for index in 0..proposals.len() {
            let chain = ChainId::new(u32::try_from(index).map_err(|_| Error::Vote)?);
            let position = vote.positions()[index];
            let extension = vote.extensions().get(index).ok_or(Error::Vote)?;
            let mut path = Vec::with_capacity(1 + extension.len());
            path.push(proposals.block(chain, position)?);
            append_payloads::<H, V, D>(leader.block(), chain, &mut path, extension.payloads())?;
            chains.push(path);
        }
        Ok(Self { chains })
    }

    /// Returns one extension, including its endorsed proposal block at index zero.
    pub(crate) fn extension(&self, chain: ChainId) -> Result<&[BlockRef<D>], Error> {
        chain_path(&self.chains, chain)
    }

    /// Adds extension edges to an index containing the proposal paths.
    pub(crate) fn index_extensions(&self, index: &mut PathIndex<D>) -> Result<(), Error> {
        for path in &self.chains {
            index.insert(path)?;
        }
        Ok(())
    }

    /// Checks extension edges against an index containing the proposal paths without mutating it.
    pub(crate) fn validate_extensions(&self, index: &PathIndex<D>) -> Result<(), Error> {
        for path in &self.chains {
            index.validate(path)?;
        }
        Ok(())
    }
}

/// Checks that `child` is the next height on `parent`'s chain.
fn check_edge<D: Digest>(parent: BlockRef<D>, child: BlockRef<D>) -> Result<(), Error> {
    if parent.chain() != child.chain()
        || parent.height().get().checked_add(1) != Some(child.height().get())
    {
        return Err(Error::Vote);
    }
    Ok(())
}

/// Returns the path stored for `chain` in a per-chain path vector.
fn chain_path<D: Digest>(
    chains: &[Vec<BlockRef<D>>],
    chain: ChainId,
) -> Result<&[BlockRef<D>], Error> {
    chains
        .get(chain.index())
        .map(Vec::as_slice)
        .ok_or(Error::Chain(chain))
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
