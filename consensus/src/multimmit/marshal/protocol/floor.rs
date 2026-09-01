//! Shape checks of a floor checkpoint against the ordering state it replaces.

use super::order::{self, HistoryState};
use crate::multimmit::types::{BlockRef, CodecConfig, Frontier, Lqc, TipRecord};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// A floor checkpoint does not match the ordering state it would replace.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// The floor's tip history is not the one its anchor commits to.
    #[error("floor history does not establish its ordered frontier")]
    History,
    /// The floor's ordered frontier is below the current one on some chain.
    #[error("floor ordered frontier regresses")]
    OrderedRegression,
    /// The floor's emitted frontier is below the current one on some chain.
    #[error("floor emitted frontier regresses")]
    EmittedRegression,
    /// The floor's emitted frontier is not where the anchor's final sweep ends.
    #[error("floor emitted frontier is not the anchor's final sweep")]
    Sweep,
    /// The floor's frontiers or final sweep are malformed.
    #[error(transparent)]
    Order(#[from] order::Error),
}

/// The frontiers a floor checkpoint establishes.
pub(crate) struct Frontiers<D: Digest> {
    /// Commitment of the floor's tip-history record.
    pub history: D,
    /// Ordered frontier: the tips of the floor's tip-history record.
    pub ordered: Vec<BlockRef<D>>,
    /// Final tips of the anchor's final sweep.
    pub target: Vec<BlockRef<D>>,
}

/// Checks a floor with anchor proof `anchor`, tip history `history` and emitted frontier
/// `emitted` against `state`.
///
/// The history must be the one the anchor commits to, neither frontier may regress, and
/// `emitted` must end the anchor's final sweep from the ordered frontier. The ancestry between
/// `emitted` and the returned target is left to the caller.
pub(crate) fn validate<H, V>(
    state: &HistoryState<H::Digest>,
    anchor: &Lqc<V, H::Digest>,
    history: &TipRecord<H::Digest>,
    emitted: &[BlockRef<H::Digest>],
    codec: CodecConfig,
) -> Result<Frontiers<H::Digest>, Error>
where
    H: Hasher,
    V: Variant,
{
    let commitment = history.commitment::<H>();
    if anchor.leader().history() != commitment {
        return Err(Error::History);
    }
    let ordered = history.tips().to_vec();
    let next_ordered = Frontier::new(ordered.clone()).map_err(order::Error::from)?;
    if !state.ordered_frontier().advances_to(&next_ordered) {
        return Err(Error::OrderedRegression);
    }
    let next_emitted = Frontier::new(emitted.to_vec()).map_err(order::Error::from)?;
    if !state.emitted_frontier().advances_to(&next_emitted) {
        return Err(Error::EmittedRegression);
    }

    let base = HistoryState::new(commitment, ordered.clone(), ordered.clone())?;
    let sweep = base
        .final_sweep::<H, V>(anchor, codec, &ordered)?
        .into_stream();
    let target = sweep.target().to_vec();
    let mut expected = ordered.clone();
    for slot in sweep {
        expected[slot.tip().chain().get() as usize] =
            BlockRef::new(slot.tip().chain(), slot.height(), slot.tip().digest());
    }
    for (((ordered, target), expected), emitted) in
        ordered.iter().zip(&target).zip(&expected).zip(emitted)
    {
        if expected.height() != emitted.height()
            || (emitted.height() == ordered.height() && emitted != ordered)
            || (emitted.height() == target.height() && emitted != target)
        {
            return Err(Error::Sweep);
        }
    }
    Ok(Frontiers {
        history: commitment,
        ordered,
        target,
    })
}
