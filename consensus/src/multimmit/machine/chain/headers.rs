//! The header store: the producer headers this node holds, per chain and height.
//!
//! A header enters signed by its producer (received from a peer or produced locally), rebuilt from
//! payload hashes that a vote or certificate names, or from the durable accepted path on restart.
//! Per chain the store keeps heights above its floor (the lowest retained base) and at most a fixed
//! number of distinct headers per height; the chain layer bounds the top. A full height evicts an
//! unreferenced header (neither accepted nor endorsed by anybody) together with its held
//! descendants before it refuses a new one. Acceptance and endorsement both reach every held
//! ancestor, so those descendants are unreferenced too. A producer-signed header gives way only to
//! another producer-signed one, so headers rebuilt from payload hashes, which anybody can mint,
//! never displace the producer's.
//!
//! Headers of any branch are held, not only the accepted path: a vote names the tips of its
//! sender's accepted path, which may be another branch of an equivocating producer's chain. A
//! header is linked when its held ancestry reaches an accepted header, the chain's origin (its
//! genesis object, or the finalized base this node anchored at), or the floor; only a linked header
//! resolves a vote's tip, because only then is the path below it known down to the window base. A
//! header held before its parent is linked once the gap is.
//!
//! Every entry carries the set of validators whose read votes endorse it, and the same set
//! partitioned by the lowest view tag through which each validator endorses it. A vote endorsing a
//! tip endorses every ancestor, so each entry's endorsers include those of its held children, each
//! at a tag no higher than the child's: marking walks down from the endorsed tip and stops at the
//! first entry that already holds the mark, and a header inserted below held children inherits
//! their endorsers. The chain layer reads the height quorum `h*` and adoption from the union, and
//! the pool counts the endorsements in a view from the tags at or below it.
//!
//! Ancestry is answered by height wherever a chain holds one header per height: the store tracks
//! the heights holding several, and between two heights holding one header each, a linked
//! header's ancestor is the one header held there. Only a range crossing a fork walks parents.

use crate::{
    multimmit::{
        algebra::Ancestry,
        machine::input::BlockValidity,
        types::{ArtifactId, BlockRef, ChainId, SignedTransactionBlock, TransactionBlockHeader},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::bitmap::BitMap;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A producer-signed copy of a held header.
#[derive(Clone, Debug)]
pub(crate) struct Signed<V: Variant, D: Digest> {
    /// The signed header.
    pub(crate) block: Arc<SignedTransactionBlock<V, D>>,
    /// The artifact-store entry holding the copy while it is buffered for acceptance.
    pub(crate) artifact: Option<ArtifactId<D>>,
}

/// One held header.
#[derive(Clone, Debug)]
pub(crate) struct HeaderEntry<V: Variant, D: Digest> {
    pub(crate) header: TransactionBlockHeader<D>,
    pub(crate) digest: D,
    /// The producer-signed copy, if one was received or produced.
    pub(crate) signed: Option<Signed<V, D>>,
    /// The application's verdict on the body, once a chain plane returned one.
    pub(crate) verdict: Option<BlockValidity>,
    /// The validators whose read votes endorse this header.
    pub(crate) endorsers: BitMap,
    /// The endorsers partitioned by the lowest tag of a read vote through which each endorses
    /// this header, in ascending tag order. Their union is `endorsers`.
    pub(crate) tagged: Vec<(View, BitMap)>,
    /// Whether this header is on the local accepted path.
    pub(crate) accepted: bool,
    /// Whether this header's held ancestry reaches an accepted header, the chain's origin, or the
    /// floor.
    pub(crate) linked: bool,
}

impl<V: Variant, D: Digest> HeaderEntry<V, D> {
    /// Returns an unaccepted entry for `header` with digest `digest` and no endorsers among
    /// `participants` validators.
    pub(crate) fn new(header: TransactionBlockHeader<D>, digest: D, participants: usize) -> Self {
        Self {
            header,
            digest,
            signed: None,
            verdict: None,
            endorsers: BitMap::zeroes(participants as u64),
            tagged: Vec::new(),
            accepted: false,
            linked: false,
        }
    }

    /// Returns the header's reference.
    pub(crate) const fn block(&self) -> BlockRef<D> {
        BlockRef::new(self.header.chain(), self.header.height(), self.digest)
    }

    /// Returns how many validators endorse the header.
    pub(crate) fn endorsements(&self) -> usize {
        self.endorsers.count_ones() as usize
    }

    /// Returns how many validators endorse the header through votes tagged `view` or earlier.
    pub(crate) fn endorsements_through(&self, view: View) -> usize {
        // The partitions are disjoint: each endorser sits in the partition of its lowest tag.
        self.tagged
            .iter()
            .take_while(|(tag, _)| *tag <= view)
            .map(|(_, endorsers)| endorsers.count_ones() as usize)
            .sum()
    }

    /// Records that validator `signer` endorses the header through a vote tagged `tag`, and
    /// returns whether the union or the signer's lowest tag changed.
    fn endorse(&mut self, signer: u64, tag: View) -> bool {
        let added = !self.endorsers.get(signer);
        self.endorsers.set(signer, true);
        if let Some(index) = self
            .tagged
            .iter()
            .position(|(_, endorsers)| endorsers.get(signer))
        {
            if self.tagged[index].0 <= tag {
                return added;
            }
            let endorsers = &mut self.tagged[index].1;
            endorsers.set(signer, false);
            if endorsers.count_ones() == 0 {
                self.tagged.remove(index);
            }
        }
        let index = self.tagged.partition_point(|(view, _)| *view < tag);
        match self.tagged.get_mut(index) {
            Some((view, endorsers)) if *view == tag => endorsers.set(signer, true),
            _ => {
                let mut endorsers = BitMap::zeroes(self.endorsers.len());
                endorsers.set(signer, true);
                self.tagged.insert(index, (tag, endorsers));
            }
        }
        true
    }

    /// Folds the tags at or below `view` into one partition tagged `view`.
    fn merge_tags_through(&mut self, view: View) {
        let merged = self.tagged.partition_point(|(tag, _)| *tag <= view);
        if merged == 0 {
            return;
        }
        let mut folded = self.tagged.drain(..merged);
        let (_, mut union) = folded.next().expect("one partition is merged");
        for (_, endorsers) in folded {
            union.or(&endorsers);
        }
        self.tagged.insert(0, (view, union));
    }
}

/// The endorsement thresholds the store reports crossings of.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Thresholds {
    /// Endorsers that place a header at the height quorum (`n - 2f`).
    pub(crate) quorum: usize,
    /// Endorsers that make an unaccepted header adoptable (`alpha`).
    pub(crate) adoption: usize,
    /// Endorsers that confirm a header to its producer's delay estimator (`n - f`).
    pub(crate) confirmation: usize,
}

/// The thresholds one marking pass crossed.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Marked {
    /// The greatest height of a header that reached the height quorum.
    pub(crate) quorum: Option<Height>,
    /// Whether an unaccepted header reached the adoption threshold.
    pub(crate) adoptable: bool,
    /// The greatest height of a header that reached the confirmation threshold.
    pub(crate) confirmed: Option<Height>,
}

/// The outcome of holding one more header.
#[derive(Clone, Debug)]
pub(crate) struct Inserted<D: Digest> {
    /// The artifact-store entries that held the signed copies of the headers evicted for it.
    pub(crate) evicted: Vec<ArtifactId<D>>,
    /// The thresholds the endorsements it inherited crossed.
    pub(crate) marked: Marked,
}

/// One chain's held headers.
struct ChainHeaders<V: Variant, D: Digest> {
    heights: BTreeMap<Height, Vec<HeaderEntry<V, D>>>,
    /// The heights holding more than one header.
    forks: BTreeSet<Height>,
    floor: Height,
    /// Advances whenever a header is added to or removed from `heights`.
    revision: u64,
}

/// The held headers of every chain.
pub(crate) struct HeaderStore<V: Variant, D: Digest> {
    chains: Vec<ChainHeaders<V, D>>,
    /// Per chain, the finalized block every held header must descend from.
    origin: Vec<BlockRef<D>>,
    participants: usize,
    per_height: usize,
    thresholds: Thresholds,
}

impl<V: Variant, D: Digest> HeaderStore<V, D> {
    /// Creates an empty store over the chains starting at `origin`, one block per chain, holding at
    /// most `per_height` headers per height and tracking endorsements by `participants` validators.
    pub(crate) fn new(
        origin: &[BlockRef<D>],
        participants: usize,
        per_height: usize,
        thresholds: Thresholds,
    ) -> Self {
        Self {
            chains: origin
                .iter()
                .map(|_| ChainHeaders {
                    heights: BTreeMap::new(),
                    forks: BTreeSet::new(),
                    floor: Height::zero(),
                    revision: 0,
                })
                .collect(),
            origin: origin.to_vec(),
            participants,
            per_height,
            thresholds,
        }
    }

    /// Returns the number of validators endorsements are tracked for.
    pub(crate) const fn participants(&self) -> usize {
        self.participants
    }

    /// Returns the height at or below which `chain` holds no header.
    pub(crate) fn floor(&self, chain: ChainId) -> Height {
        self.chains[chain.index()].floor
    }

    /// Returns the revision of `chain`'s held headers. It changes whenever a header of `chain` is
    /// held or dropped, so anything derived from walking that chain's ancestry stands while it is
    /// unchanged.
    pub(crate) fn revision(&self, chain: ChainId) -> u64 {
        self.chains[chain.index()].revision
    }

    /// Returns the held headers of `chain` at `height`, in insertion order.
    pub(crate) fn at(&self, chain: ChainId, height: Height) -> &[HeaderEntry<V, D>] {
        self.chains[chain.index()]
            .heights
            .get(&height)
            .map_or(&[], Vec::as_slice)
    }

    /// Returns the most headers `chain` holds at one height.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn widest(&self, chain: ChainId) -> usize {
        self.chains[chain.index()]
            .heights
            .values()
            .map(Vec::len)
            .max()
            .unwrap_or(0)
    }

    /// Returns the held header `block`.
    pub(crate) fn get(&self, block: &BlockRef<D>) -> Option<&HeaderEntry<V, D>> {
        self.at(block.chain(), block.height())
            .iter()
            .find(|entry| entry.digest == block.digest())
    }

    /// Returns the held header `block` for update.
    pub(crate) fn get_mut(&mut self, block: &BlockRef<D>) -> Option<&mut HeaderEntry<V, D>> {
        self.chains[block.chain().index()]
            .heights
            .get_mut(&block.height())?
            .iter_mut()
            .find(|entry| entry.digest == block.digest())
    }

    /// Returns whether `header`'s parent is held, is its chain's origin, or lies at or below the
    /// floor, where the accepted path is no longer held.
    pub(crate) fn links(&self, header: &TransactionBlockHeader<D>) -> bool {
        self.parent_linked(header) || self.get(&header.parent_ref()).is_some()
    }

    /// Returns whether `header`'s parent is the chain's origin, lies at or below the floor, or is a
    /// held linked header. A parent at or below the origin's height is linked only if it is the
    /// origin: every other block there lies off the finalized path.
    fn parent_linked(&self, header: &TransactionBlockHeader<D>) -> bool {
        let parent = header.parent_ref();
        let origin = self.origin[header.chain().index()];
        if parent.height() <= origin.height() {
            return parent == origin;
        }
        parent.height() <= self.floor(header.chain())
            || self.get(&parent).is_some_and(|held| held.linked)
    }

    /// Links `block`, held, and every held descendant its link reaches.
    fn link(&mut self, block: BlockRef<D>) {
        let chain = block.chain();
        let mut frontier = vec![block];
        while let Some(block) = frontier.pop() {
            let Some(entry) = self.get_mut(&block) else {
                continue;
            };
            if entry.linked {
                continue;
            }
            entry.linked = true;
            frontier.extend(
                self.at(chain, block.height().next())
                    .iter()
                    .filter(|child| child.header.parent() == block.digest())
                    .map(HeaderEntry::block),
            );
        }
    }

    /// Marks the held header `block` accepted, which links it and the held headers above it.
    pub(crate) fn accept(&mut self, block: &BlockRef<D>) {
        if let Some(entry) = self.get_mut(block) {
            entry.accepted = true;
            self.link(*block);
        }
    }

    /// Returns whether `entry` may be evicted for a new header, producer-signed when `signed`:
    /// nothing accepted it, nobody endorses it, and it is unsigned unless the new header is signed.
    fn evictable(entry: &HeaderEntry<V, D>, signed: bool) -> bool {
        !entry.accepted && entry.endorsers.count_ones() == 0 && (signed || entry.signed.is_none())
    }

    /// Returns the header a new one at a full height evicts, an unsigned one first, if any.
    fn victim(entries: &[HeaderEntry<V, D>], signed: bool) -> Option<BlockRef<D>> {
        entries
            .iter()
            .find(|entry| Self::evictable(entry, false))
            .or_else(|| entries.iter().find(|entry| Self::evictable(entry, signed)))
            .map(HeaderEntry::block)
    }

    /// Returns whether a new header, producer-signed when `signed`, fits at `chain`'s `height`,
    /// possibly by evicting one.
    pub(crate) fn has_room(&self, chain: ChainId, height: Height, signed: bool) -> bool {
        height > self.floor(chain) && {
            let entries = self.at(chain, height);
            entries.len() < self.per_height || Self::victim(entries, signed).is_some()
        }
    }

    /// Removes the held header `block` and its held descendants, and returns the artifact-store
    /// entries that held their signed copies.
    fn evict(&mut self, block: BlockRef<D>) -> Vec<ArtifactId<D>> {
        let ChainHeaders { heights, forks, .. } = &mut self.chains[block.chain().index()];
        let mut released = Vec::new();
        let mut doomed = vec![block.digest()];
        let mut height = block.height();
        while let Some(entries) = heights.get_mut(&height) {
            entries.retain(|entry| {
                let dropped = doomed.contains(&entry.digest);
                if dropped {
                    released.extend(entry.signed.as_ref().and_then(|signed| signed.artifact));
                }
                !dropped
            });
            if entries.len() < 2 {
                forks.remove(&height);
            }
            if entries.is_empty() {
                heights.remove(&height);
            }
            height = height.next();
            doomed = heights.get(&height).map_or_else(Vec::new, |children| {
                children
                    .iter()
                    .filter(|child| doomed.contains(&child.header.parent()))
                    .map(|child| child.digest)
                    .collect()
            });
            if doomed.is_empty() {
                break;
            }
        }
        released
    }

    /// Inserts `entry`, which must not be held, evicting an unreferenced header with its held
    /// descendants when its height is full. The inserted header inherits the endorsers of its held
    /// children.
    ///
    /// An accepted header is always held above the floor: the accepted path has one header per
    /// height, so it exceeds a full height by at most one. Returns `None` when the height lies
    /// at or below the floor, or when it is full of headers `entry` cannot evict and `entry` is
    /// not accepted.
    pub(crate) fn insert(&mut self, entry: HeaderEntry<V, D>) -> Option<Inserted<D>> {
        let block = entry.block();
        let chain = block.chain();
        let signed = entry.signed.is_some();
        let linked = entry.accepted || self.parent_linked(&entry.header);
        if block.height() <= self.floor(chain)
            || (!entry.accepted && !self.has_room(chain, block.height(), signed))
        {
            return None;
        }
        let held = self.at(chain, block.height());
        let victim = (held.len() >= self.per_height)
            .then(|| Self::victim(held, signed))
            .flatten();
        let evicted = victim.map_or_else(Vec::new, |victim| self.evict(victim));
        let headers = &mut self.chains[chain.index()];
        headers.revision += 1;
        let entries = headers.heights.entry(block.height()).or_default();
        entries.push(entry);
        if entries.len() > 1 {
            headers.forks.insert(block.height());
        }
        if linked {
            self.link(block);
        }

        // A child held before its parent carries endorsements the parent and its ancestors lack.
        let inherited = self
            .at(chain, block.height().next())
            .iter()
            .filter(|child| child.header.parent() == block.digest())
            .flat_map(|child| {
                child.tagged.iter().flat_map(|(tag, endorsers)| {
                    endorsers.ones_iter().map(move |signer| (signer, *tag))
                })
            })
            .collect::<Vec<_>>();
        let marked = if inherited.is_empty() {
            Marked::default()
        } else {
            self.mark(block, |entry| {
                inherited.iter().fold(false, |changed, (signer, tag)| {
                    entry.endorse(*signer, *tag) | changed
                })
            })
        };
        Some(Inserted { evicted, marked })
    }

    /// Records that `signer` endorses the held header `tip`, and so every held ancestor, through
    /// a vote tagged `tag`.
    pub(crate) fn endorse(&mut self, signer: Participant, tag: View, tip: BlockRef<D>) -> Marked {
        let bit = u64::from(signer.get());
        if bit >= self.participants as u64 {
            return Marked::default();
        }
        self.mark(tip, |entry| entry.endorse(bit, tag))
    }

    /// Applies `add` to `from` and then to its held ancestors, highest first, until it changes
    /// nothing, and reports the thresholds crossed.
    fn mark(
        &mut self,
        from: BlockRef<D>,
        mut add: impl FnMut(&mut HeaderEntry<V, D>) -> bool,
    ) -> Marked {
        let Thresholds {
            quorum,
            adoption,
            confirmation,
        } = self.thresholds;
        let mut marked = Marked::default();
        let mut current = from;
        while let Some(entry) = self.get_mut(&current) {
            let before = entry.endorsements();
            if !add(entry) {
                break;
            }
            let after = entry.endorsements();
            if before < quorum && after >= quorum && marked.quorum.is_none() {
                marked.quorum = Some(current.height());
            }
            if !entry.accepted && before < adoption && after >= adoption {
                marked.adoptable = true;
            }
            if before < confirmation && after >= confirmation && marked.confirmed.is_none() {
                marked.confirmed = Some(current.height());
            }
            current = entry.header.parent_ref();
        }
        marked
    }

    /// Folds every held header's endorsement tags at or below `view` into one partition, once no
    /// count reads a view at or below it.
    pub(crate) fn merge_tags_through(&mut self, view: View) {
        for entry in self
            .chains
            .iter_mut()
            .flat_map(|chain| chain.heights.values_mut())
            .flatten()
        {
            entry.merge_tags_through(view);
        }
    }

    /// Drops the signed copies of unaccepted headers of `chain` at or below `height`, which can
    /// no longer be accepted, and returns the artifact-store entries that held them.
    pub(crate) fn release_signed_through(
        &mut self,
        chain: ChainId,
        height: Height,
    ) -> Vec<ArtifactId<D>> {
        let mut released = Vec::new();
        for entries in self.chains[chain.index()]
            .heights
            .range_mut(..=height)
            .map(|(_, entries)| entries)
        {
            for entry in entries.iter_mut().filter(|entry| !entry.accepted) {
                if let Some(signed) = entry.signed.take() {
                    released.extend(signed.artifact);
                }
                entry.verdict = None;
            }
        }
        released
    }

    /// Raises `chain`'s floor to `floor`, dropping every header at or below it, and returns the
    /// artifact-store entries that held their signed copies, or `None` when the floor is already
    /// at or above `floor`.
    pub(crate) fn retain_above(
        &mut self,
        chain: ChainId,
        floor: Height,
    ) -> Option<Vec<ArtifactId<D>>> {
        let headers = &mut self.chains[chain.index()];
        if floor <= headers.floor {
            return None;
        }
        headers.floor = floor;
        headers.revision += 1;
        headers.forks = headers.forks.split_off(&floor.next());
        let kept = headers.heights.split_off(&floor.next());
        let dropped = core::mem::replace(&mut headers.heights, kept);
        // Headers just above the floor link through it.
        let above = self
            .at(chain, floor.next())
            .iter()
            .map(HeaderEntry::block)
            .collect::<Vec<_>>();
        for block in above {
            self.link(block);
        }
        Some(
            dropped
                .into_values()
                .flatten()
                .filter_map(|entry| entry.signed.and_then(|signed| signed.artifact))
                .collect(),
        )
    }
}

impl<V: Variant, D: Digest> Ancestry<D> for HeaderStore<V, D> {
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>> {
        if height >= tip.height() {
            return (height == tip.height()).then_some(*tip);
        }
        let chain = &self.chains[tip.chain().index()];
        // A linked header's ancestors above the floor are all held, so where every height up to
        // the tip holds one header, the header above `height` is the tip's ancestor there.
        if height >= chain.floor
            && chain
                .forks
                .range(height.next()..=tip.height())
                .next()
                .is_none()
            && self.get(tip).is_some_and(|entry| entry.linked)
        {
            let child = chain.heights.get(&height.next())?.first()?;
            return Some(child.header.parent_ref());
        }
        let mut current = *tip;
        while current.height() > height {
            current = self.get(&current)?.header.parent_ref();
        }
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::EpochGenesis, types::Epoch};
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_utils::TestRng;
    use rand::{RngExt as _, seq::SliceRandom as _};

    type Store = HeaderStore<MinPk, Sha256Digest>;

    const EPOCH: Epoch = Epoch::new(1);

    /// Walks parents from `tip` down to `height` through held headers.
    fn walk(
        store: &Store,
        tip: &BlockRef<Sha256Digest>,
        height: Height,
    ) -> Option<BlockRef<Sha256Digest>> {
        if height > tip.height() {
            return None;
        }
        let mut current = *tip;
        while current.height() > height {
            current = store.get(&current)?.header.parent_ref();
        }
        Some(current)
    }

    #[test]
    fn ancestry_by_height_matches_walking_parents() {
        let mut rng = TestRng::new(7);
        for _ in 0..64 {
            let origin = EpochGenesis::new::<Sha256>(EPOCH, 1)
                .unwrap()
                .tips()
                .to_vec();
            let thresholds = Thresholds {
                quorum: 3,
                adoption: 2,
                confirmation: 4,
            };
            let mut store = Store::new(&origin, 6, 3, thresholds);
            // A trunk with forks, held in a random order with a random accepted prefix.
            let mut headers = Vec::new();
            let mut trunk = vec![origin[0]];
            for height in 1..=24u64 {
                let parent = *trunk.last().unwrap();
                let header = TransactionBlockHeader::new(
                    EPOCH,
                    parent.chain(),
                    Height::new(height),
                    parent.digest(),
                    Sha256::hash(&[&height.to_le_bytes()]),
                )
                .unwrap();
                trunk.push(header.block_ref::<Sha256>());
                headers.push((header, true));
            }
            for fork in 0..rng.random_range(0..6u64) {
                let mut parent = trunk[rng.random_range(0..trunk.len() - 1)];
                for step in 0..rng.random_range(1..4u64) {
                    let header = TransactionBlockHeader::new(
                        EPOCH,
                        parent.chain(),
                        parent.height().next(),
                        parent.digest(),
                        Sha256::hash(&[&fork.to_le_bytes(), &step.to_le_bytes()]),
                    )
                    .unwrap();
                    parent = header.block_ref::<Sha256>();
                    headers.push((header, false));
                }
            }
            headers.shuffle(&mut rng);
            let accepted = rng.random_range(0..=24u64);
            for (header, on_trunk) in headers {
                let digest = header.digest::<Sha256>();
                let height = header.height().get();
                let mut entry = HeaderEntry::new(header, digest, 6);
                entry.accepted = on_trunk && height <= accepted;
                store.insert(entry);
                if rng.random_bool(0.05) {
                    store.retain_above(origin[0].chain(), Height::new(rng.random_range(0..8)));
                }
            }
            let held = (1..=26u64)
                .flat_map(|height| store.at(origin[0].chain(), Height::new(height)).to_vec())
                .map(|entry| entry.block())
                .collect::<Vec<_>>();
            for tip in &held {
                for height in 0..=tip.height().get() + 1 {
                    let height = Height::new(height);
                    assert_eq!(store.ancestor(tip, height), walk(&store, tip, height));
                }
            }
        }
    }
}
