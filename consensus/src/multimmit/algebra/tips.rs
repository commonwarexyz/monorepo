//! What a set of votes endorses within one view's window, chain by chain.
//!
//! Every function here reads one chain against a base object: the window of base `b` is the
//! heights `ht(b) + 1 ..= ht(b) + N`, where `N` is the window cap. A vote endorses a block when
//! the block is its tip on that chain or an ancestor of the tip, so within the window a tip
//! endorses exactly the blocks on its path between the base and its [`Reach::Top`]. Votes are
//! supplied as `(signer, tip)` pairs so a caller can stream them from whatever per-chain state it
//! keeps; the ancestry it passes must resolve the tips it supplies.

use super::{Ancestry, Error};
use crate::{
    multimmit::types::{BlockRef, ChainId, CodecConfig, VoteContent},
    types::{Height, Participant},
};
use commonware_cryptography::Digest;
#[cfg(any(test, feature = "mocks"))]
use std::collections::BTreeSet;

/// What a tip endorses in a base's window on the base's chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reach<D: Digest> {
    /// The tip endorses no block of the window: it lies at or below the base height, on another
    /// chain, or on a path that does not pass through the base.
    Outside,
    /// The tip endorses exactly the window blocks on the path from the base up to this block, its
    /// ancestor at the lower of its own height and the top of the window.
    Top(BlockRef<D>),
    /// The ancestry cannot relate the tip to the base.
    Unresolved,
}

/// Returns what `tip` endorses in the window of cap `cap` above `base`.
pub(crate) fn reach<D: Digest>(
    base: &BlockRef<D>,
    cap: u32,
    tip: &BlockRef<D>,
    ancestry: &impl Ancestry<D>,
) -> Reach<D> {
    if tip.chain() != base.chain() || tip.height() <= base.height() {
        return Reach::Outside;
    }
    match ancestry.ancestor(tip, base.height()) {
        None => return Reach::Unresolved,
        Some(anchor) if anchor != *base => return Reach::Outside,
        Some(_) => {}
    }
    let top = tip.height().min(window_end(base, cap));
    ancestry
        .ancestor(tip, top)
        .map_or(Reach::Unresolved, Reach::Top)
}

/// Returns the highest height of the window above `base`.
fn window_end<D: Digest>(base: &BlockRef<D>, cap: u32) -> Height {
    Height::new(base.height().get().saturating_add(u64::from(cap)))
}

/// Returns the highest window block above `base` that at least `quorum` distinct signers endorse,
/// or `base` when there is none.
///
/// A signer may appear more than once and endorses the union of its entries' paths. Endorsers of a
/// block endorse its ancestors, so the heights holding a qualifying block form a prefix of the
/// window and a binary search over them finds the top.
///
/// Votes mostly share their tops, so each probe resolves the ancestor of every distinct top once.
fn highest_endorsed<D: Digest>(
    base: &BlockRef<D>,
    quorum: usize,
    tops: &[(Participant, BlockRef<D>)],
    ancestry: &impl Ancestry<D>,
) -> BlockRef<D> {
    let mut sorted = tops.to_vec();
    sorted.sort_unstable_by_key(|(_, top)| *top);
    let mut distinct = Vec::<BlockRef<D>>::new();
    let mut entries = Vec::with_capacity(sorted.len());
    for (signer, top) in sorted {
        if distinct.last() != Some(&top) {
            distinct.push(top);
        }
        entries.push((signer, distinct.len() - 1));
    }
    let mut ancestors = Vec::with_capacity(distinct.len());
    let mut endorsed = Vec::with_capacity(entries.len());
    let mut qualified = |height: Height| -> Option<BlockRef<D>> {
        ancestors.clear();
        ancestors.extend(distinct.iter().map(|top| {
            if top.height() >= height {
                ancestry.ancestor(top, height)
            } else {
                None
            }
        }));
        endorsed.clear();
        endorsed.extend(
            entries
                .iter()
                .filter_map(|(signer, index)| Some((ancestors[*index]?, *signer))),
        );
        endorsed.sort_unstable();
        endorsed.dedup();
        endorsed
            .chunk_by(|left, right| left.0 == right.0)
            .find(|group| group.len() >= quorum)
            .map(|group| group[0].0)
    };

    let mut best = *base;
    let mut low = base.height().get();
    let mut high = tops
        .iter()
        .map(|(_, top)| top.height().get())
        .max()
        .unwrap_or(low);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        match qualified(Height::new(middle)) {
            Some(block) => {
                best = block;
                low = middle;
            }
            None => high = middle - 1,
        }
    }
    best
}

/// Collects the window tops of `tips` above `base`, and whether some tip could not be resolved.
///
/// Votes mostly share their tips, so each distinct tip is related to the base once.
fn window_tops<D: Digest>(
    base: &BlockRef<D>,
    cap: u32,
    tips: impl IntoIterator<Item = (Participant, BlockRef<D>)>,
    ancestry: &impl Ancestry<D>,
) -> (Vec<(Participant, BlockRef<D>)>, bool) {
    let mut tips = tips.into_iter().collect::<Vec<_>>();
    tips.sort_unstable_by_key(|(_, tip)| *tip);
    let mut tops = Vec::new();
    let mut unresolved = false;
    let mut last = None;
    for (signer, tip) in tips {
        let reached = match last {
            Some((known, reached)) if known == tip => reached,
            _ => reach(base, cap, &tip, ancestry),
        };
        last = Some((tip, reached));
        match reached {
            Reach::Outside => {}
            Reach::Top(top) => tops.push((signer, top)),
            Reach::Unresolved => unresolved = true,
        }
    }
    (tops, unresolved)
}

/// Checks that `vector` holds one object per chain of `config`, in chain order.
pub(super) fn ensure_vector<D: Digest>(
    vector: &[BlockRef<D>],
    config: CodecConfig,
) -> Result<(), Error> {
    if vector.len() != config.chains()
        || !config
            .chain_ids()
            .zip(vector)
            .all(|(chain, block)| block.chain() == chain)
    {
        return Err(Error::ChainOrder);
    }
    Ok(())
}

/// Computes `Tips(Q)` of the V-QC whose `n - f` recorded final votes are `contents` and whose
/// base (the parent's tips) is `base`.
///
/// On chain `i` the tip is the highest window block extending `base[i]` that at least `n - 3f`
/// recorded votes endorse, or `base[i]` when there is none. `ancestry` must resolve every
/// recorded tip above the base down to the base height (see [`super::validate_vqc`]); a tip it
/// cannot resolve endorses nothing.
pub(crate) fn tips<D: Digest>(
    base: &[BlockRef<D>],
    contents: &[(Participant, VoteContent<D>)],
    config: CodecConfig,
    ancestry: &impl Ancestry<D>,
) -> Result<Vec<BlockRef<D>>, Error> {
    ensure_vector(base, config)?;
    let cap = config.window().cap();
    Ok(base
        .iter()
        .map(|base| {
            let (tops, _) = window_tops(base, cap, chain_tips(base.chain(), contents), ancestry);
            highest_endorsed(base, config.tip_quorum(), &tops, ancestry)
        })
        .collect())
}

/// Computes the pool's final tip `b*` on `base`'s chain: the highest window block extending
/// `base` that at least `n - f` distinct processors endorse, or `base` when there is none.
///
/// `endorsements` holds the chain's tip of every vote in the pool (every read vote tagged with
/// the view or an earlier one); a processor with several votes endorses the union of their
/// paths. A tip `ancestry` cannot resolve endorses nothing, which can only lower `b*`.
#[cfg(any(test, feature = "mocks"))]
pub(crate) fn final_tip<D: Digest>(
    base: &BlockRef<D>,
    config: CodecConfig,
    endorsements: impl IntoIterator<Item = (Participant, BlockRef<D>)>,
    ancestry: &impl Ancestry<D>,
) -> BlockRef<D> {
    let (tops, _) = window_tops(base, config.window().cap(), endorsements, ancestry);
    highest_endorsed(base, config.view_quorum(), &tops, ancestry)
}

/// Returns whether `content` binds its sender on `chain`: it is final, declares `chain`, or its
/// tip there is capped (at least `N` above `base`, the chain's base). Before the base is
/// resolved, only finality and declaration bind.
pub(crate) fn binding<D: Digest>(
    content: &VoteContent<D>,
    chain: ChainId,
    base: Option<&BlockRef<D>>,
    cap: u32,
) -> bool {
    content.is_final()
        || content.declared().contains(chain)
        || base.is_some_and(|base| {
            content
                .tips()
                .get(chain.index())
                .is_some_and(|tip| tip.height() >= window_end(base, cap))
        })
}

/// The settledness counts of one chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Settledness {
    /// Processors with a binding vote tagged with the view, `phi`.
    pub(crate) bound: usize,
    /// Those whose first binding vote may endorse a window block strictly extending `b*`,
    /// `gamma`.
    pub(crate) beyond: usize,
    /// Whether `gamma + (n - phi) <= n - 4f - 1`.
    pub(crate) settled: bool,
}

/// Computes whether `base`'s chain is settled given the pool's final tip `final_tip` (`b*`).
///
/// `first_binding` holds, for every processor with a binding vote tagged with the view (see
/// [`binding`]), the chain's tip of the first such vote this processor read; only a signer's
/// first entry counts. A tip `ancestry` cannot resolve counts as endorsing beyond `b*`, which
/// can only withhold settledness.
///
/// [`Bindings`] maintains the same counts as first binding votes are read.
#[cfg(any(test, feature = "mocks"))]
pub(crate) fn settled<D: Digest>(
    base: &BlockRef<D>,
    final_tip: &BlockRef<D>,
    config: CodecConfig,
    first_binding: impl IntoIterator<Item = (Participant, BlockRef<D>)>,
    ancestry: &impl Ancestry<D>,
) -> Settledness {
    let cap = config.window().cap();
    let mut seen = BTreeSet::new();
    let mut beyond = 0;
    for (signer, tip) in first_binding {
        if !seen.insert(signer) {
            continue;
        }
        let extends = match reach(base, cap, &tip, ancestry) {
            Reach::Outside => false,
            Reach::Unresolved => true,
            Reach::Top(top) => {
                top.height() > final_tip.height()
                    && ancestry
                        .ancestor(&top, final_tip.height())
                        .is_none_or(|ancestor| ancestor == *final_tip)
            }
        };
        beyond += usize::from(extends);
    }
    let bound = seen.len();
    let unseen = config.participants().saturating_sub(bound);
    Settledness {
        bound,
        beyond,
        settled: beyond + unseen <= config.settled_bound(),
    }
}

/// The first binding votes of one chain in one view, tallied by what they reach in the window of
/// the view's base `beta_v`, so settledness is re-evaluated in time proportional to the distinct
/// reaches rather than to the signers.
///
/// Each processor's first binding vote is fixed once read, and so is what its tip reaches once the
/// ancestry relates it to the base, so each tip is classified once: votes reaching outside the
/// window count as bound only; votes reaching a window block are counted per block; tips the
/// ancestry cannot relate yet count as reaching beyond every `b*` until a retry resolves them.
/// [`Self::settledness`] then agrees with [`settled`] over the same first binding votes, given
/// one entry per processor.
#[derive(Clone, Debug)]
pub(crate) struct Bindings<D: Digest> {
    base: BlockRef<D>,
    cap: u32,
    bound: usize,
    tops: Vec<(BlockRef<D>, usize)>,
    unresolved: Vec<BlockRef<D>>,
}

impl<D: Digest> Bindings<D> {
    /// Creates an empty tally against `base` with window cap `cap`.
    pub(crate) const fn new(base: BlockRef<D>, cap: u32) -> Self {
        Self {
            base,
            cap,
            bound: 0,
            tops: Vec::new(),
            unresolved: Vec::new(),
        }
    }

    /// Records one processor's first binding tip.
    pub(crate) fn add(&mut self, tip: BlockRef<D>, ancestry: &impl Ancestry<D>) {
        self.bound += 1;
        self.classify(tip, ancestry);
    }

    fn classify(&mut self, tip: BlockRef<D>, ancestry: &impl Ancestry<D>) {
        match reach(&self.base, self.cap, &tip, ancestry) {
            Reach::Outside => {}
            Reach::Unresolved => self.unresolved.push(tip),
            Reach::Top(top) => match self.tops.iter_mut().find(|(block, _)| *block == top) {
                Some((_, count)) => *count += 1,
                None => self.tops.push((top, 1)),
            },
        }
    }

    /// Classifies again the tips the ancestry could not relate to the base, and returns whether
    /// any now resolves.
    pub(crate) fn retry(&mut self, ancestry: &impl Ancestry<D>) -> bool {
        let before = self.unresolved.len();
        for tip in core::mem::take(&mut self.unresolved) {
            self.classify(tip, ancestry);
        }
        self.unresolved.len() != before
    }

    /// Returns whether some tip awaits resolution.
    pub(crate) const fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// Returns the settledness counts given the pool's final tip `final_tip` (`b*`).
    pub(crate) fn settledness(
        &self,
        final_tip: &BlockRef<D>,
        config: CodecConfig,
        ancestry: &impl Ancestry<D>,
    ) -> Settledness {
        let beyond = self.unresolved.len()
            + self
                .tops
                .iter()
                .filter(|(top, _)| {
                    top.height() > final_tip.height()
                        && ancestry
                            .ancestor(top, final_tip.height())
                            .is_none_or(|ancestor| ancestor == *final_tip)
                })
                .map(|(_, count)| count)
                .sum::<usize>();
        let unseen = config.participants().saturating_sub(self.bound);
        Settledness {
            bound: self.bound,
            beyond,
            settled: beyond + unseen <= config.settled_bound(),
        }
    }
}

/// Computes `Det(G)` on `base`'s chain for the final votes `tips` (one per signer of `G`).
///
/// The chain is determined at `t` when `t` is `base` or a window block extending it that at
/// least `n - f` of the votes endorse, and no vote endorses a window block strictly extending
/// `t`; at most one `t` qualifies. With exactly `n - f` votes this holds iff every vote has the
/// same [`reach`]: all [`Reach::Outside`] (`t` is `base`) or all [`Reach::Top`] of `t`. Returns
/// `None` when the chain is undetermined or some tip cannot be resolved.
pub(crate) fn determined<D: Digest>(
    base: &BlockRef<D>,
    config: CodecConfig,
    tips: impl IntoIterator<Item = (Participant, BlockRef<D>)>,
    ancestry: &impl Ancestry<D>,
) -> Option<BlockRef<D>> {
    let (tops, unresolved) = window_tops(base, config.window().cap(), tips, ancestry);
    if unresolved {
        return None;
    }
    let target = highest_endorsed(base, config.view_quorum(), &tops, ancestry);
    let exceeded = tops.iter().any(|(_, top)| {
        top.height() > target.height()
            && ancestry
                .ancestor(top, target.height())
                .is_none_or(|ancestor| ancestor == target)
    });
    (!exceeded).then_some(target)
}

/// Computes `Det(G)` on every chain for the `n - f` final votes `contents` relative to the base
/// vector `base`, or `None` when some chain is undetermined.
pub(crate) fn det<D: Digest>(
    base: &[BlockRef<D>],
    contents: &[(Participant, VoteContent<D>)],
    config: CodecConfig,
    ancestry: &impl Ancestry<D>,
) -> Result<Option<Vec<BlockRef<D>>>, Error> {
    ensure_vector(base, config)?;
    Ok(base
        .iter()
        .map(|base| determined(base, config, chain_tips(base.chain(), contents), ancestry))
        .collect())
}

/// Returns every content's tip on `chain` with its signer.
fn chain_tips<D: Digest>(
    chain: ChainId,
    contents: &[(Participant, VoteContent<D>)],
) -> impl Iterator<Item = (Participant, BlockRef<D>)> + '_ {
    contents
        .iter()
        .filter_map(move |(signer, content)| Some((*signer, *content.tips().get(chain.index())?)))
}
