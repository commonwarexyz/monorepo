//! Producer headers rebuilt from payload hashes.
//!
//! Vote updates and V-QCs name blocks above a known object by the body digests of the headers in
//! between. Because a header commits to its epoch, chain, height, parent digest, and body digest,
//! those digests and the starting object determine every header, and so the digest of the top.

use super::{Ancestry, Error};
use crate::{
    multimmit::types::{BlockRef, ChainId, TransactionBlockHeader},
    types::{Epoch, Height},
};
use commonware_cryptography::{Digest, Hasher};

/// Headers rebuilt above one starting object, lowest first.
///
/// Header `k` (from one) sits at `from.height + k` on `from`'s chain, commits to the `k`-th
/// payload hash, and names the header below it as its parent (`from` for the first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Path<D: Digest> {
    from: BlockRef<D>,
    headers: Vec<TransactionBlockHeader<D>>,
    refs: Vec<BlockRef<D>>,
}

impl<D: Digest> Path<D> {
    /// Rebuilds the headers of `epoch` above `from` committing to `payloads` in order.
    pub(crate) fn rebuild<H: Hasher<Digest = D>>(
        epoch: Epoch,
        from: BlockRef<D>,
        payloads: &[D],
    ) -> Result<Self, Error> {
        let mut headers = Vec::with_capacity(payloads.len());
        let mut refs = Vec::with_capacity(payloads.len());
        let mut parent = from;
        for payload in payloads {
            let height = parent
                .height()
                .get()
                .checked_add(1)
                .ok_or(Error::HeightOverflow)?;
            let header = TransactionBlockHeader::new(
                epoch,
                from.chain(),
                Height::new(height),
                parent.digest(),
                *payload,
            )?;
            parent = header.block_ref::<H>();
            headers.push(header);
            refs.push(parent);
        }
        Ok(Self {
            from,
            headers,
            refs,
        })
    }

    /// Rebuilds the headers above `from` and requires the top to be `target` (same chain,
    /// height, and digest).
    pub(crate) fn resolve<H: Hasher<Digest = D>>(
        epoch: Epoch,
        from: BlockRef<D>,
        payloads: &[D],
        target: &BlockRef<D>,
    ) -> Result<Self, Error> {
        let path = Self::rebuild::<H>(epoch, from, payloads)?;
        if path.top() != *target {
            return Err(Error::PathTarget);
        }
        Ok(path)
    }

    /// Returns the object the path starts above.
    pub(crate) const fn from(&self) -> BlockRef<D> {
        self.from
    }

    /// Returns the rebuilt headers, lowest first.
    #[cfg(test)]
    pub(crate) fn headers(&self) -> &[TransactionBlockHeader<D>] {
        &self.headers
    }

    /// Returns the references of the rebuilt headers, lowest first.
    #[cfg(test)]
    pub(crate) fn refs(&self) -> &[BlockRef<D>] {
        &self.refs
    }

    /// Returns every rebuilt header with its reference, lowest first.
    pub(crate) fn rebuilt(
        &self,
    ) -> impl Iterator<Item = (&TransactionBlockHeader<D>, &BlockRef<D>)> {
        self.headers.iter().zip(&self.refs)
    }

    /// Returns the highest rebuilt block, or `from` when the path is empty.
    pub(crate) fn top(&self) -> BlockRef<D> {
        self.refs.last().copied().unwrap_or(self.from)
    }

    /// Returns the path's block at `height`, including `from`.
    fn at(&self, height: Height) -> Option<BlockRef<D>> {
        let offset = height.get().checked_sub(self.from.height().get())?;
        match offset {
            0 => Some(self.from),
            offset => usize::try_from(offset - 1)
                .ok()
                .and_then(|index| self.refs.get(index).copied()),
        }
    }

    /// Returns whether `block` is one of the rebuilt blocks (`from` excluded).
    fn holds(&self, block: &BlockRef<D>) -> bool {
        block.height() > self.from.height() && self.at(block.height()) == Some(*block)
    }
}

/// Ancestry over a set of rebuilt paths.
///
/// A block is known when it lies on some path. The ancestor of a known block at a height down to
/// its path's `from` is read off that path; below it the walk continues from `from` when `from`
/// itself lies on another path, and ends otherwise. A header's digest commits to its parent, so
/// every path containing a block agrees on its ancestry.
///
/// Paths are indexed by chain: a lookup compares the block against its chain's paths at the
/// block's height, one comparison per path. The paths of one chain are the distinct forks a set
/// of votes resolves there, one in the common case, so lookups hash nothing and stay cheap even
/// when the paths hold many blocks.
#[derive(Clone, Debug)]
pub(crate) struct PathAncestry<D: Digest> {
    paths: Vec<Path<D>>,
    /// The position in `paths` of every path, ordered by chain and then position.
    chains: Vec<(ChainId, usize)>,
}

impl<D: Digest> PathAncestry<D> {
    /// Indexes `paths`.
    pub(crate) fn new(paths: Vec<Path<D>>) -> Self {
        let mut chains = paths
            .iter()
            .enumerate()
            .map(|(slot, path)| (path.from().chain(), slot))
            .collect::<Vec<_>>();
        chains.sort_unstable();
        Self { paths, chains }
    }

    /// Returns the indexed paths in the order given.
    pub(crate) fn paths(&self) -> &[Path<D>] {
        &self.paths
    }

    /// Returns the paths of `chain`, in the order given.
    fn on(&self, chain: ChainId) -> impl Iterator<Item = &Path<D>> + '_ {
        let start = self.chains.partition_point(|(other, _)| *other < chain);
        self.chains[start..]
            .iter()
            .take_while(move |(other, _)| *other == chain)
            .map(|(_, slot)| &self.paths[*slot])
    }

    /// Returns the first path, in the order given, that rebuilt `block`.
    fn holder(&self, block: &BlockRef<D>) -> Option<&Path<D>> {
        self.on(block.chain()).find(|path| path.holds(block))
    }

    /// Returns whether `block` was rebuilt by some path.
    pub(crate) fn contains(&self, block: &BlockRef<D>) -> bool {
        self.holder(block).is_some()
    }

    /// Returns how many paths rebuilt `block`.
    pub(crate) fn holders(&self, block: &BlockRef<D>) -> usize {
        self.on(block.chain())
            .filter(|path| path.holds(block))
            .count()
    }
}

impl<D: Digest> Ancestry<D> for PathAncestry<D> {
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>> {
        if height > tip.height() {
            return None;
        }
        let mut current = *tip;
        // Each step moves to a strictly lower `from`, so the walk visits each path at most once.
        loop {
            if current.height() == height {
                return Some(current);
            }
            let path = self.holder(&current)?;
            if height >= path.from().height() {
                return path.at(height);
            }
            current = path.from();
        }
    }
}
