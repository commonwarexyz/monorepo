//! Tracks M-notarizations and nullifications for Minimmit proposals.
//!
//! # Status
//!
//! Internal consensus module used by the Minimmit state machine.
//!
//! # Examples
//!
//! ```rust,ignore
//! use commonware_consensus::minimmit::ancestry::Ancestry;
//! use commonware_cryptography::sha256::Digest as Sha256Digest;
//!
//! let genesis = Sha256Digest::from([0u8; 32]);
//! let ancestry = Ancestry::<Scheme, Sha256Digest>::new(genesis);
//! ```

use crate::{
    minimmit::{
        scheme::Scheme,
        types::{Finalization, MNotarization, Nullification, Proposal},
    },
    types::View,
};
use commonware_cryptography::Digest;
use std::collections::BTreeMap;

const GENESIS_VIEW: View = View::zero();

/// Tracks ancestry proofs for proposals.
#[derive(Debug)]
pub struct Ancestry<S: Scheme<D>, D: Digest> {
    genesis: D,
    m_notarizations: BTreeMap<View, BTreeMap<D, MNotarization<S, D>>>,
    finalizations: BTreeMap<View, Finalization<S, D>>,
    nullifications: BTreeMap<View, Nullification<S>>,
}

impl<S: Scheme<D>, D: Digest> Ancestry<S, D> {
    /// Creates ancestry tracking seeded with the genesis payload.
    pub const fn new(genesis: D) -> Self {
        Self {
            genesis,
            m_notarizations: BTreeMap::new(),
            finalizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
        }
    }

    /// Returns the genesis payload digest.
    pub const fn genesis(&self) -> D {
        self.genesis
    }

    /// Adds an M-notarization, returning true if it was newly inserted.
    pub fn add_m_notarization(&mut self, notarization: MNotarization<S, D>) -> bool {
        let view = notarization.proposal.round.view();
        let digest = notarization.proposal.payload;
        let entry = self.m_notarizations.entry(view).or_default();
        if entry.contains_key(&digest) {
            return false;
        }
        entry.insert(digest, notarization);
        true
    }

    /// Adds a finalization, returning true if it was newly inserted.
    pub fn add_finalization(&mut self, finalization: Finalization<S, D>) -> bool {
        let view = finalization.proposal.round.view();
        if self.finalizations.contains_key(&view) {
            return false;
        }
        self.finalizations.insert(view, finalization);
        true
    }

    /// Adds a nullification, returning true if it was newly inserted.
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.round.view();
        if self.nullifications.contains_key(&view) {
            return false;
        }
        self.nullifications.insert(view, nullification);
        true
    }

    /// Returns the M-notarization for a given view and digest, if present.
    pub fn m_notarization(&self, view: View, digest: D) -> Option<&MNotarization<S, D>> {
        self.m_notarizations.get(&view).and_then(|m| m.get(&digest))
    }

    /// Returns any M-notarization for a given view, if present.
    pub fn any_m_notarization(&self, view: View) -> Option<&MNotarization<S, D>> {
        self.m_notarizations
            .get(&view)
            .and_then(|m| m.values().next())
    }

    /// Returns the finalization for a given view, if present.
    pub fn finalization(&self, view: View) -> Option<&Finalization<S, D>> {
        self.finalizations.get(&view)
    }

    /// Returns the nullification for a given view, if present.
    pub fn nullification(&self, view: View) -> Option<&Nullification<S>> {
        self.nullifications.get(&view)
    }

    /// Returns true if the view has a recorded nullification.
    pub fn is_nullified(&self, view: View) -> bool {
        self.nullifications.contains_key(&view)
    }

    /// Returns the selected parent for the given view, if available.
    pub fn select_parent(&self, current_view: View) -> Option<(View, D)> {
        if current_view == GENESIS_VIEW {
            return None;
        }
        let view = self.best_view_before(current_view)?;
        if !self.nullifications_between(view, current_view) {
            return None;
        }
        let payload = self.best_payload_for_view(view)?;
        Some((view, payload))
    }

    /// Returns the parent payload for a proposal if its ancestry is valid.
    ///
    /// This verifies that:
    /// 1. The proposal's parent view is less than the proposal's view
    /// 2. The parent view is at or after min_view
    /// 3. All views between parent and proposal are nullified
    /// 4. The claimed parent_payload exists in our ancestry (genesis, finalization, or M-notarization)
    pub fn parent_payload(&self, proposal: &Proposal<D>, min_view: View) -> Option<(View, D)> {
        let view = proposal.round.view();
        let parent = proposal.parent;
        let claimed_payload = proposal.parent_payload;

        if view <= parent {
            return None;
        }
        if parent < min_view {
            return None;
        }
        if !self.nullifications_between(parent, view) {
            return None;
        }

        // Verify the claimed parent payload exists in our ancestry
        if !self.has_payload_for_view(parent, claimed_payload) {
            return None;
        }

        Some((parent, claimed_payload))
    }

    /// Returns true if the proposal has valid ancestry.
    pub fn is_proposal_valid(&self, proposal: &Proposal<D>, min_view: View) -> bool {
        self.parent_payload(proposal, min_view).is_some()
    }

    /// Returns true if we have proof of the given payload at the given view.
    ///
    /// This checks (in order of precedence):
    /// 1. Genesis payload at view 0
    /// 2. Finalization at the view
    /// 3. M-notarization at the view with matching payload
    fn has_payload_for_view(&self, view: View, payload: D) -> bool {
        if view == GENESIS_VIEW {
            return payload == self.genesis;
        }
        if let Some(finalization) = self.finalizations.get(&view) {
            return finalization.proposal.payload == payload;
        }
        self.m_notarizations
            .get(&view)
            .is_some_and(|m| m.contains_key(&payload))
    }

    /// Drops stored proofs strictly before the provided view.
    pub fn prune_before(&mut self, view: View) {
        self.m_notarizations.retain(|v, _| *v >= view);
        self.finalizations.retain(|v, _| *v >= view);
        self.nullifications.retain(|v, _| *v >= view);
    }

    fn best_view_before(&self, current_view: View) -> Option<View> {
        let mut best = if current_view > GENESIS_VIEW {
            Some(GENESIS_VIEW)
        } else {
            None
        };

        if let Some(view) = self
            .m_notarizations
            .range(..current_view)
            .next_back()
            .map(|(v, _)| *v)
        {
            if best.is_none_or(|b| view > b) {
                best = Some(view);
            }
        }

        if let Some(view) = self
            .finalizations
            .range(..current_view)
            .next_back()
            .map(|(v, _)| *v)
        {
            if best.is_none_or(|b| view > b) {
                best = Some(view);
            }
        }

        best
    }

    fn nullifications_between(&self, parent: View, view: View) -> bool {
        let start = parent.next();
        View::range(start, view).all(|v| self.is_nullified(v))
    }

    fn best_payload_for_view(&self, view: View) -> Option<D> {
        if view == GENESIS_VIEW {
            return Some(self.genesis);
        }
        if let Some(finalization) = self.finalizations.get(&view) {
            return Some(finalization.proposal.payload);
        }
        self.m_notarizations
            .get(&view)
            .and_then(|m| m.keys().next().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            scheme::ed25519,
            types::{Notarize, Nullify},
        },
        types::{Epoch, Round as Rnd},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    type Scheme = ed25519::Scheme;

    fn m_notarization_fixture(
        schemes: &[Scheme],
        verifier: &Scheme,
        proposal: Proposal<Sha256Digest>,
    ) -> MNotarization<Scheme, Sha256Digest> {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        MNotarization::from_notarizes(verifier, notarizes.iter(), &Sequential)
            .expect("m-notarization")
    }

    fn nullification_fixture(
        schemes: &[Scheme],
        verifier: &Scheme,
        round: Rnd,
    ) -> Nullification<Scheme> {
        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        Nullification::from_nullifies(verifier, nullifies.iter(), &Sequential)
            .expect("nullification")
    }

    #[test]
    fn select_parent_prefers_highest_view_and_lowest_digest() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 6);

        let genesis = Sha256Digest::from([0u8; 32]);
        let mut ancestry = Ancestry::<Scheme, Sha256Digest>::new(genesis);

        let payload_v1 = Sha256Digest::from([1u8; 32]);
        let proposal_v1 = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis, // parent_payload = genesis
            payload_v1,
        );
        let proposal_v2_a = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(2)),
            View::new(1),
            payload_v1, // parent_payload = v1's payload
            Sha256Digest::from([1u8; 32]),
        );
        let proposal_v2_b = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(2)),
            View::new(1),
            payload_v1, // parent_payload = v1's payload
            Sha256Digest::from([2u8; 32]),
        );

        let m1 = m_notarization_fixture(&schemes, &verifier, proposal_v1);
        let m2_a = m_notarization_fixture(&schemes, &verifier, proposal_v2_a.clone());
        let m2_b = m_notarization_fixture(&schemes, &verifier, proposal_v2_b);

        assert!(ancestry.add_m_notarization(m1));
        assert!(ancestry.add_m_notarization(m2_a));
        assert!(ancestry.add_m_notarization(m2_b));

        let parent = ancestry.select_parent(View::new(3)).expect("parent");
        assert_eq!(parent.0, View::new(2));
        assert_eq!(parent.1, proposal_v2_a.payload);
    }

    #[test]
    fn parent_payload_requires_nullifications() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 6);

        let genesis = Sha256Digest::from([0u8; 32]);
        let mut ancestry = Ancestry::<Scheme, Sha256Digest>::new(genesis);

        let payload_v1 = Sha256Digest::from([9u8; 32]);
        let proposal_v1 = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis, // parent_payload = genesis
            payload_v1,
        );
        let m1 = m_notarization_fixture(&schemes, &verifier, proposal_v1.clone());
        assert!(ancestry.add_m_notarization(m1));

        let proposal_v3 = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(3)),
            View::new(1),
            payload_v1, // parent_payload = v1's payload
            Sha256Digest::from([10u8; 32]),
        );
        assert!(ancestry
            .parent_payload(&proposal_v3, GENESIS_VIEW)
            .is_none());

        let round_v2 = Rnd::new(Epoch::new(1), View::new(2));
        let nullification = nullification_fixture(&schemes, &verifier, round_v2);
        assert!(ancestry.add_nullification(nullification));

        let parent = ancestry
            .parent_payload(&proposal_v3, GENESIS_VIEW)
            .expect("parent payload");
        assert_eq!(parent.0, View::new(1));
        assert_eq!(parent.1, proposal_v1.payload);
    }

    #[test]
    fn select_parent_requires_contiguous_nullifications() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 6);

        let genesis = Sha256Digest::from([0u8; 32]);
        let mut ancestry = Ancestry::<Scheme, Sha256Digest>::new(genesis);

        let payload_v1 = Sha256Digest::from([12u8; 32]);
        let proposal_v1 = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis, // parent_payload = genesis
            payload_v1,
        );
        let m1 = m_notarization_fixture(&schemes, &verifier, proposal_v1.clone());
        assert!(ancestry.add_m_notarization(m1));

        let nullification_v3 =
            nullification_fixture(&schemes, &verifier, Rnd::new(Epoch::new(1), View::new(3)));
        assert!(ancestry.add_nullification(nullification_v3));

        assert!(
            ancestry.select_parent(View::new(4)).is_none(),
            "missing view 2 nullification should block parent selection"
        );

        let nullification_v2 =
            nullification_fixture(&schemes, &verifier, Rnd::new(Epoch::new(1), View::new(2)));
        assert!(ancestry.add_nullification(nullification_v2));

        let parent = ancestry.select_parent(View::new(4)).expect("parent");
        assert_eq!(parent.0, View::new(1));
        assert_eq!(parent.1, proposal_v1.payload);
    }

    #[test]
    fn prune_before_drops_old_entries() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 6);

        let genesis = Sha256Digest::from([0u8; 32]);
        let mut ancestry = Ancestry::<Scheme, Sha256Digest>::new(genesis);

        let payload_v1 = Sha256Digest::from([11u8; 32]);
        let proposal_v1 = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis, // parent_payload = genesis
            payload_v1,
        );
        let m1 = m_notarization_fixture(&schemes, &verifier, proposal_v1.clone());
        assert!(ancestry.add_m_notarization(m1));

        let round_v2 = Rnd::new(Epoch::new(1), View::new(2));
        let nullification = nullification_fixture(&schemes, &verifier, round_v2);
        assert!(ancestry.add_nullification(nullification));

        ancestry.prune_before(View::new(2));

        assert!(ancestry
            .m_notarization(View::new(1), proposal_v1.payload)
            .is_none());
        assert!(ancestry.is_nullified(View::new(2)));
    }

    /// Regression test: With the fix, validators with different M-notarization sets
    /// correctly handle parent payload disambiguation.
    ///
    /// Previously, `Proposal` only contained `parent: View` without `parent_payload: Digest`.
    /// This caused validators with different M-notarization sets to disagree on which
    /// parent a proposal built on.
    ///
    /// The fix adds `parent_payload: D` to the Proposal type. Now:
    /// - Proposals explicitly specify which parent payload they extend
    /// - Validators verify they have proof of the claimed parent
    /// - Validators without the claimed parent reject the proposal (don't vote)
    #[test]
    fn parent_payload_disambiguation_with_multiple_m_notarizations() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 6);

        let genesis = Sha256Digest::from([0u8; 32]);

        // Create two M-notarizations at view 1 with different payloads
        let payload_x = Sha256Digest::from([0xFFu8; 32]);
        let payload_y = Sha256Digest::from([0x11u8; 32]);

        let proposal_v1_x = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis,
            payload_x,
        );
        let proposal_v1_y = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            genesis,
            payload_y,
        );

        let m_notarization_x = m_notarization_fixture(&schemes, &verifier, proposal_v1_x);
        let m_notarization_y = m_notarization_fixture(&schemes, &verifier, proposal_v1_y);

        // Validator A only has M-notarization for payload_x
        let mut ancestry_a = Ancestry::<Scheme, Sha256Digest>::new(genesis);
        assert!(ancestry_a.add_m_notarization(m_notarization_x.clone()));

        // Validator B has both M-notarizations
        let mut ancestry_b = Ancestry::<Scheme, Sha256Digest>::new(genesis);
        assert!(ancestry_b.add_m_notarization(m_notarization_x));
        assert!(ancestry_b.add_m_notarization(m_notarization_y.clone()));

        // Validator C only has M-notarization for payload_y
        let mut ancestry_c = Ancestry::<Scheme, Sha256Digest>::new(genesis);
        assert!(ancestry_c.add_m_notarization(m_notarization_y));

        // Proposer creates a proposal at view 2 explicitly building on payload_x
        let proposal_v2_on_x = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(2)),
            View::new(1),
            payload_x, // Explicitly claims to build on payload_x
            Sha256Digest::from([0xABu8; 32]),
        );

        // Validator A accepts: they have payload_x
        assert!(
            ancestry_a.is_proposal_valid(&proposal_v2_on_x, GENESIS_VIEW),
            "A should accept proposal building on X (they have X)"
        );
        let parent_a = ancestry_a
            .parent_payload(&proposal_v2_on_x, GENESIS_VIEW)
            .expect("parent for A");
        assert_eq!(parent_a.1, payload_x);

        // Validator B accepts: they have payload_x (among others)
        assert!(
            ancestry_b.is_proposal_valid(&proposal_v2_on_x, GENESIS_VIEW),
            "B should accept proposal building on X (they have X)"
        );
        let parent_b = ancestry_b
            .parent_payload(&proposal_v2_on_x, GENESIS_VIEW)
            .expect("parent for B");
        assert_eq!(parent_b.1, payload_x);

        // Validator C rejects: they don't have payload_x
        assert!(
            !ancestry_c.is_proposal_valid(&proposal_v2_on_x, GENESIS_VIEW),
            "C should reject proposal building on X (they don't have X)"
        );

        // All accepting validators agree on the parent
        assert_eq!(
            parent_a.1, parent_b.1,
            "Validators who accept must agree on parent"
        );

        // Now test a proposal building on payload_y
        let proposal_v2_on_y = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(2)),
            View::new(1),
            payload_y, // Explicitly claims to build on payload_y
            Sha256Digest::from([0xCDu8; 32]),
        );

        // Validator A rejects: they don't have payload_y
        assert!(
            !ancestry_a.is_proposal_valid(&proposal_v2_on_y, GENESIS_VIEW),
            "A should reject proposal building on Y (they don't have Y)"
        );

        // Validators B and C accept: they both have payload_y
        assert!(
            ancestry_b.is_proposal_valid(&proposal_v2_on_y, GENESIS_VIEW),
            "B should accept proposal building on Y"
        );
        assert!(
            ancestry_c.is_proposal_valid(&proposal_v2_on_y, GENESIS_VIEW),
            "C should accept proposal building on Y"
        );
    }
}
