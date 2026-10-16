//! Checks of a floor against the ordering state it replaces.

use super::order::{self, HistoryState};
use crate::{
    Viewable as _,
    multimmit::{
        algebra::{self, validate_floor},
        types::{CodecConfig, Frontier, HistoryRecord, Lqc},
    },
    types::{Epoch, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// A floor is malformed or does not advance the ordering state it would replace.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// The L-QC and opening do not form a finalization certificate of the epoch.
    #[error("floor is not a finalization certificate: {0}")]
    Certificate(#[from] algebra::Error),
    /// The floor resolves a view before the current one.
    #[error("floor view regresses")]
    ViewRegression,
    /// The floor commits to another history at the current view.
    #[error("floor history conflicts with the current history")]
    HistoryConflict,
    /// The opened tips are below the current ordered frontier on some chain.
    #[error("floor ordered frontier regresses")]
    OrderedRegression,
    /// The opened tips are below the current emitted frontier on some chain.
    #[error("floor emitted frontier regresses")]
    EmittedRegression,
    /// The opened tips do not form a frontier.
    #[error(transparent)]
    Order(#[from] order::Error),
}

/// Checks the floor `(lqc, opening)` of `epoch` against `state` and returns the view it resolves
/// and its resume index, the sum of the opened tips' heights.
///
/// The floor must be a well-formed finalization certificate (see [`validate_floor`]): an L-QC of
/// view `v` pins the tips of view `v - 1`, which `opening` opens. That view must not precede the
/// state's, and the opened tips must advance both the ordered and the emitted frontier. The
/// aggregate signature is left to the caller.
pub(crate) fn validate<H, V>(
    state: &HistoryState<H::Digest>,
    lqc: &Lqc<V, H::Digest>,
    opening: &HistoryRecord<H::Digest>,
    epoch: Epoch,
    codec: CodecConfig,
) -> Result<(View, u64), Error>
where
    H: Hasher,
    V: Variant,
{
    let index = validate_floor::<H, V>(lqc, opening, epoch, codec)?;
    let view = pinned_view(lqc);
    if view < state.view() {
        return Err(Error::ViewRegression);
    }
    if view == state.view() && lqc.leader().history() != state.history() {
        return Err(Error::HistoryConflict);
    }
    let tips = Frontier::new(opening.tips().to_vec()).map_err(order::Error::from)?;
    if !state.ordered_frontier().advances_to(&tips) {
        return Err(Error::OrderedRegression);
    }
    if !state.emitted_frontier().advances_to(&tips) {
        return Err(Error::EmittedRegression);
    }
    Ok((view, index))
}

/// Returns the view whose tips `lqc` pins: an L-QC of view `v` finalizes a leader block that
/// commits to the tips-history of view `v - 1`.
pub(crate) fn pinned_view<V: Variant, D: Digest>(lqc: &Lqc<V, D>) -> View {
    lqc.view()
        .previous()
        .expect("leader blocks belong to views above genesis")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Epochable as _,
        multimmit::{
            mocks::Committee,
            types::{BlockRef, ChainId},
        },
        types::{Height, Participant},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };

    struct Fixture {
        committee: Committee<MinPk>,
        /// The opening of view 3, two chains at heights 4 and 6.
        opening: HistoryRecord<Sha256Digest>,
    }

    impl Fixture {
        fn new() -> Self {
            let committee = Committee::<MinPk>::builder(7, 6)
                .producers(vec![Participant::new(0), Participant::new(1)])
                .build();
            let tips = vec![tip(0, 4, b"tip"), tip(1, 6, b"tip")];
            let opening = HistoryRecord::new(Sha256::hash(&[b"view 2"]), tips).unwrap();
            Self { committee, opening }
        }

        /// The L-QC of view 4, which pins view 3.
        fn lqc(&self) -> Lqc<MinPk, Sha256Digest> {
            self.committee.lqc_with(
                View::new(4),
                self.committee.genesis().vqc(),
                self.opening.commitment::<Sha256>(),
            )
        }

        fn state(
            &self,
            view: u64,
            history: Sha256Digest,
            ordered: &[u64],
            emitted: &[u64],
        ) -> HistoryState<Sha256Digest> {
            let refs = |heights: &[u64]| {
                heights
                    .iter()
                    .enumerate()
                    .map(|(chain, height)| tip(chain as u32, *height, b"tip"))
                    .collect()
            };
            HistoryState::new(View::new(view), history, refs(ordered), refs(emitted)).unwrap()
        }

        fn validate(&self, state: &HistoryState<Sha256Digest>) -> Result<(View, u64), Error> {
            let lqc = self.lqc();
            validate::<Sha256, MinPk>(
                state,
                &lqc,
                &self.opening,
                lqc.epoch(),
                self.committee.codec(),
            )
        }
    }

    fn tip(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[label, &chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    #[test]
    fn floor_resolves_the_view_before_its_lqc_at_the_sum_of_tip_heights() {
        let fixture = Fixture::new();
        let state = fixture.state(1, Sha256::hash(&[b"view 1"]), &[1, 2], &[2, 2]);
        assert_eq!(fixture.validate(&state), Ok((View::new(3), 10)));
        assert_eq!(pinned_view(&fixture.lqc()), View::new(3));

        // The view the floor resolves may equal the current one only with the same history.
        let current = fixture.state(3, fixture.opening.commitment::<Sha256>(), &[4, 6], &[4, 6]);
        assert_eq!(fixture.validate(&current), Ok((View::new(3), 10)));
        let conflicting = fixture.state(3, Sha256::hash(&[b"other"]), &[4, 6], &[4, 6]);
        assert_eq!(fixture.validate(&conflicting), Err(Error::HistoryConflict));
    }

    #[test]
    fn floor_rejects_a_mismatched_certificate() {
        let fixture = Fixture::new();
        let state = fixture.state(1, Sha256::hash(&[b"view 1"]), &[1, 2], &[1, 2]);
        let lqc = fixture.lqc();
        let other = HistoryRecord::new(
            fixture.opening.parent(),
            vec![tip(0, 4, b"other"), tip(1, 6, b"tip")],
        )
        .unwrap();
        assert!(matches!(
            validate::<Sha256, MinPk>(&state, &lqc, &other, lqc.epoch(), fixture.committee.codec()),
            Err(Error::Certificate(_))
        ));
        let epoch = lqc.epoch().next();
        assert!(matches!(
            validate::<Sha256, MinPk>(
                &state,
                &lqc,
                &fixture.opening,
                epoch,
                fixture.committee.codec()
            ),
            Err(Error::Certificate(_))
        ));
    }

    #[test]
    fn floor_never_regresses() {
        let fixture = Fixture::new();
        let history = Sha256::hash(&[b"later"]);
        assert_eq!(
            fixture.validate(&fixture.state(4, history, &[1, 2], &[1, 2])),
            Err(Error::ViewRegression)
        );
        assert_eq!(
            fixture.validate(&fixture.state(1, history, &[5, 2], &[5, 2])),
            Err(Error::OrderedRegression)
        );
        // A sweep emitted past the floor's tips.
        assert_eq!(
            fixture.validate(&fixture.state(1, history, &[1, 2], &[1, 7])),
            Err(Error::EmittedRegression)
        );
        // Another block at a floor tip's height.
        let conflict = HistoryState::new(
            View::new(1),
            history,
            vec![tip(0, 4, b"fork"), tip(1, 2, b"tip")],
            vec![tip(0, 4, b"fork"), tip(1, 2, b"tip")],
        )
        .unwrap();
        assert_eq!(fixture.validate(&conflict), Err(Error::OrderedRegression));
    }
}
