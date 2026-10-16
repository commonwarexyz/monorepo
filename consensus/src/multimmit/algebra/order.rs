//! The horizontal order in which resolved tips and pool sweeps place producer blocks.
//!
//! The coordinates above a base vector `B` are pairs `(o, i)` of an offset `o >= 1` and a chain
//! `i`; coordinate `(o, i)` names height `ht(B_i) + o` on chain `i`. The horizontal order visits
//! them offset first, then chain in ascending order. Both iterators yield coordinates and the tip
//! whose ancestor fills each one; the caller resolves the concrete block through its own ancestry.

use super::Error;
use crate::{
    multimmit::types::{BlockRef, ChainId},
    types::Height,
};
use commonware_cryptography::Digest;

/// One block placed in the order: the ancestor of `tip` at `height` on `chain`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Append<D: Digest> {
    pub(crate) chain: ChainId,
    pub(crate) height: Height,
    pub(crate) tip: BlockRef<D>,
}

/// One step of a pool sweep.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step<D: Digest> {
    /// Place a block.
    Append(Append<D>),
    /// Stop: the next coordinate belongs to an unsettled chain above its final tip.
    Halt,
}

/// Visits the coordinates above `from` in horizontal order, up to the greatest offset of `to` above
/// `from`.
#[derive(Clone, Debug)]
struct Coordinates<'a, D: Digest> {
    from: &'a [BlockRef<D>],
    last: u64,
    offset: u64,
    chain: usize,
}

impl<'a, D: Digest> Coordinates<'a, D> {
    /// Checks that `to` is one object per chain in chain order, at or above `from` on each.
    fn new(from: &'a [BlockRef<D>], to: &[BlockRef<D>]) -> Result<Self, Error> {
        if from.len() != to.len() {
            return Err(Error::ChainOrder);
        }
        let mut last = 0;
        for (index, (lower, upper)) in from.iter().zip(to).enumerate() {
            if lower.chain().index() != index || upper.chain() != lower.chain() {
                return Err(Error::ChainOrder);
            }
            let lead = upper
                .height()
                .get()
                .checked_sub(lower.height().get())
                .ok_or(Error::Regression(lower.chain()))?;
            last = last.max(lead);
        }
        Ok(Self {
            from,
            last,
            offset: 1,
            chain: 0,
        })
    }

    /// Returns the next coordinate as `(chain index, height)`; a height that overflows is `None`.
    fn next(&mut self) -> Option<(usize, Option<Height>)> {
        if self.offset > self.last || self.from.is_empty() {
            return None;
        }
        let chain = self.chain;
        let height = self.from[chain]
            .height()
            .get()
            .checked_add(self.offset)
            .map(Height::new);
        self.chain += 1;
        if self.chain == self.from.len() {
            self.chain = 0;
            self.offset += 1;
        }
        Some((chain, height))
    }
}

/// `Horiz(B, B')`: the blocks between `B` (exclusive) and `B'` (inclusive) in horizontal order.
///
/// At each coordinate whose height is at most `ht(B'_i)` it appends the ancestor of `B'_i` there,
/// up to the greatest offset at which some chain still has one.
#[derive(Clone, Debug)]
pub(crate) struct Horiz<'a, D: Digest> {
    coordinates: Coordinates<'a, D>,
    to: &'a [BlockRef<D>],
}

impl<'a, D: Digest> Horiz<'a, D> {
    /// Creates `Horiz(from, to)`; both vectors hold one object per chain in chain order, and
    /// `to` is at or above `from` on every chain (it must extend it; that is not checked here).
    pub(crate) fn new(from: &'a [BlockRef<D>], to: &'a [BlockRef<D>]) -> Result<Self, Error> {
        Ok(Self {
            coordinates: Coordinates::new(from, to)?,
            to,
        })
    }
}

impl<D: Digest> Iterator for Horiz<'_, D> {
    type Item = Append<D>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (chain, height) = self.coordinates.next()?;
            let tip = self.to[chain];
            if let Some(height) = height.filter(|height| *height <= tip.height()) {
                return Some(Append {
                    chain: tip.chain(),
                    height,
                    tip,
                });
            }
        }
    }
}

/// The emission sweep of an open view over base `beta`, pool final tips `b*`, and settledness.
///
/// The coordinates above `beta` are visited in horizontal order up to the greatest offset at which
/// some chain's height is at most `ht(b*_i)`. A coordinate at or below `b*_i` appends the ancestor
/// of `b*_i`; above it, a settled chain is skipped and an unsettled one halts the sweep.
#[derive(Clone, Debug)]
pub(crate) struct Sweep<'a, D: Digest> {
    coordinates: Coordinates<'a, D>,
    finals: &'a [BlockRef<D>],
    settled: &'a [bool],
    halted: bool,
}

impl<'a, D: Digest> Sweep<'a, D> {
    /// Creates the sweep; `finals` is at or above `base` on every chain (it must extend it; that is
    /// not checked here) and `settled` holds one flag per chain.
    pub(crate) fn new(
        base: &'a [BlockRef<D>],
        finals: &'a [BlockRef<D>],
        settled: &'a [bool],
    ) -> Result<Self, Error> {
        if settled.len() != base.len() {
            return Err(Error::ChainOrder);
        }
        Ok(Self {
            coordinates: Coordinates::new(base, finals)?,
            finals,
            settled,
            halted: false,
        })
    }
}

impl<D: Digest> Iterator for Sweep<'_, D> {
    type Item = Step<D>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.halted {
            return None;
        }
        loop {
            let (chain, height) = self.coordinates.next()?;
            let tip = self.finals[chain];
            if let Some(height) = height.filter(|height| *height <= tip.height()) {
                return Some(Step::Append(Append {
                    chain: tip.chain(),
                    height,
                    tip,
                }));
            }
            if !self.settled[chain] {
                self.halted = true;
                return Some(Step::Halt);
            }
        }
    }
}
