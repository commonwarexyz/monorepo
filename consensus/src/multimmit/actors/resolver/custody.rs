//! Retention rules for the view proofs the resolver serves.

use crate::{multimmit::types::ViewProof, types::View};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{borrow::Borrow, collections::BTreeMap, marker::PhantomData};

/// Retained view proofs: an L-QC floor covering every view at or below it, and the exit proofs of
/// individual views above it.
///
/// Three rules keep the set minimal:
/// 1. A higher L-QC floor evicts every exit at or below it.
/// 2. A V-QC beats a nullification at the same view.
/// 3. Pruning through a view removes the exits at or below it and refuses later ones.
///
/// `T` is the stored value, which borrows as its [`ViewProof`].
pub(super) struct Custody<V: Variant, D: Digest, T> {
    /// The highest retained L-QC.
    floor: Option<T>,
    /// Retained V-QCs and nullifications by view, all above `floor` and `pruned`.
    exits: BTreeMap<View, T>,
    /// The highest view pruned through.
    pruned: Option<View>,
    _proof: PhantomData<fn() -> ViewProof<V, D>>,
}

/// One retention change a [`Custody::drain`] forwards.
pub(super) enum Change<T> {
    /// Prune through this view.
    Prune(View),
    /// Retain this value.
    Retain(T),
}

impl<V: Variant, D: Digest, T: Borrow<ViewProof<V, D>>> Custody<V, D, T> {
    /// Returns a custody with nothing retained or pruned.
    pub(super) const fn empty() -> Self {
        Self {
            floor: None,
            exits: BTreeMap::new(),
            pruned: None,
            _proof: PhantomData,
        }
    }

    /// Retains `proof`, converted to `T`, if the rules keep it.
    pub(super) fn retain<P>(&mut self, proof: P)
    where
        P: Borrow<ViewProof<V, D>> + Into<T>,
    {
        let retained: &ViewProof<V, D> = proof.borrow();
        let view = retained.view();
        match retained {
            ViewProof::Lqc(_) => {
                if self
                    .floor
                    .as_ref()
                    .is_none_or(|floor| view > Self::proof_of(floor).view())
                {
                    self.exits.retain(|exit, _| *exit > view);
                    self.floor = Some(proof.into());
                }
            }
            ViewProof::Vqc(_) => {
                if self.accepts_exit(view) {
                    self.exits.insert(view, proof.into());
                }
            }
            ViewProof::Nullification(_) => {
                if self.accepts_exit(view)
                    && !matches!(
                        self.exits.get(&view).map(Self::proof_of),
                        Some(ViewProof::Vqc(_))
                    )
                {
                    self.exits.insert(view, proof.into());
                }
            }
        }
    }

    /// Forwards the prune point, then the floor, then the exits in view order, removing each
    /// change `push` accepts.
    ///
    /// Returns `false`, keeping the change `push` hands back and every later one, when `push`
    /// hands a change back.
    pub(super) fn drain(&mut self, mut push: impl FnMut(Change<T>) -> Option<Change<T>>) -> bool {
        if let Some(through) = self.pruned.take()
            && let Some(Change::Prune(through)) = push(Change::Prune(through))
        {
            self.pruned = Some(through);
            return false;
        }
        if let Some(floor) = self.floor.take()
            && let Some(Change::Retain(floor)) = push(Change::Retain(floor))
        {
            self.floor = Some(floor);
            return false;
        }
        while let Some((view, exit)) = self.exits.pop_first() {
            if let Some(Change::Retain(exit)) = push(Change::Retain(exit)) {
                self.exits.insert(view, exit);
                return false;
            }
        }
        true
    }

    /// Removes the exits at or below `through` and refuses later ones.
    pub(super) fn prune(&mut self, through: View) {
        if self.pruned.is_some_and(|pruned| through <= pruned) {
            return;
        }
        self.pruned = Some(through);
        self.exits.retain(|view, _| *view > through);
    }

    /// Returns whether an exit proof for `view` is above both the prune point and the floor.
    fn accepts_exit(&self, view: View) -> bool {
        self.pruned.is_none_or(|pruned| view > pruned)
            && self
                .floor
                .as_ref()
                .is_none_or(|floor| view > Self::proof_of(floor).view())
    }

    /// Returns the view proof a stored value holds.
    fn proof_of(value: &T) -> &ViewProof<V, D> {
        value.borrow()
    }

    /// Returns the retained value that resolves `view`: the floor when it covers `view`, else the
    /// exit of exactly `view`.
    pub(super) fn get(&self, view: View) -> Option<&T> {
        match &self.floor {
            Some(floor) if Self::proof_of(floor).view() >= view => Some(floor),
            _ => self.exits.get(&view),
        }
    }

    /// Returns the retained value that resolves `view`, mutably.
    pub(super) fn get_mut(&mut self, view: View) -> Option<&mut T> {
        match &mut self.floor {
            Some(floor) if Self::proof_of(floor).view() >= view => Some(floor),
            _ => self.exits.get_mut(&view),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::mocks::Committee;
    use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest as Sha256};

    type TestCustody = Custody<MinPk, Sha256, ViewProof<MinPk, Sha256>>;

    fn committee() -> Committee<MinPk> {
        Committee::builder(7, 6).build()
    }

    #[test]
    fn higher_floor_evicts_exits_at_or_below_it() {
        let committee = committee();
        let mut custody = TestCustody::empty();
        for view in 2..=5 {
            custody.retain(ViewProof::Vqc(Box::new(committee.vqc(View::new(view)))));
        }
        let floor = ViewProof::Lqc(Box::new(committee.lqc(View::new(4))));
        custody.retain(floor.clone());

        assert_eq!(
            custody.exits.keys().copied().collect::<Vec<_>>(),
            [View::new(5)]
        );
        assert_eq!(custody.get(View::new(1)), Some(&floor));
        assert_eq!(custody.get(View::new(4)), Some(&floor));
        assert!(matches!(custody.get(View::new(5)), Some(ViewProof::Vqc(_))));

        // A lower floor and exits it would cover are refused.
        custody.retain(ViewProof::Lqc(Box::new(committee.lqc(View::new(3)))));
        custody.retain(ViewProof::Vqc(Box::new(committee.vqc(View::new(4)))));
        assert_eq!(custody.floor.as_ref(), Some(&floor));
        assert_eq!(custody.exits.len(), 1);
    }

    #[test]
    fn vqc_beats_nullification_at_the_same_view() {
        let committee = committee();
        let mut custody = TestCustody::empty();
        let vqc = ViewProof::Vqc(Box::new(committee.vqc(View::new(2))));
        custody.retain(ViewProof::Nullification(Box::new(
            committee.nullification(View::new(2)),
        )));
        custody.retain(vqc.clone());
        assert_eq!(custody.get(View::new(2)), Some(&vqc));

        custody.retain(ViewProof::Nullification(Box::new(
            committee.nullification(View::new(2)),
        )));
        assert_eq!(custody.get(View::new(2)), Some(&vqc));

        // A nullification is kept where no V-QC is.
        custody.retain(ViewProof::Nullification(Box::new(
            committee.nullification(View::new(3)),
        )));
        assert!(matches!(
            custody.get(View::new(3)),
            Some(ViewProof::Nullification(_))
        ));
    }

    #[test]
    fn prune_removes_exits_through_its_view_and_keeps_the_floor() {
        let committee = committee();
        let mut custody = TestCustody::empty();
        let floor = ViewProof::Lqc(Box::new(committee.lqc(View::new(2))));
        custody.retain(floor.clone());
        for view in 3..=5 {
            custody.retain(ViewProof::Vqc(Box::new(committee.vqc(View::new(view)))));
        }

        custody.prune(View::new(4));
        assert_eq!(
            custody.exits.keys().copied().collect::<Vec<_>>(),
            [View::new(5)]
        );
        assert_eq!(custody.get(View::new(2)), Some(&floor));

        // Later exits at or below the prune point are refused; a lower prune changes nothing.
        custody.retain(ViewProof::Nullification(Box::new(
            committee.nullification(View::new(4)),
        )));
        custody.prune(View::new(3));
        assert_eq!(custody.pruned, Some(View::new(4)));
        assert_eq!(custody.exits.len(), 1);
    }
}
