//! Claims on artifacts still awaiting verification, indexed by view and input cohort.

use crate::{
    Viewable,
    multimmit::{
        machine::{util::retire_prefix, verification::Observation},
        types::{Artifact, ArtifactId},
    },
    types::{Attributable, Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// What a claim reserves within its view.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ClaimKind {
    Proposal,
    ViewMessage(Participant),
    Nullify(Participant),
    Nullification,
    Vqc,
}

/// One view-state slot an unverified artifact may fill.
///
/// Claims order by view first, so retirement drains one prefix.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Claim {
    pub(super) view: View,
    pub(super) kind: ClaimKind,
}

impl Claim {
    /// Creates the claim on `kind` in `view`.
    pub(super) const fn new(view: View, kind: ClaimKind) -> Self {
        Self { view, kind }
    }

    /// Returns the slot `artifact` would fill, if it is view-scoped.
    pub(super) fn for_artifact<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Option<Self> {
        let (view, kind) = match artifact {
            Artifact::LeaderBlock(block) => (block.view(), ClaimKind::Proposal),
            Artifact::Vote(vote) => (vote.view(), ClaimKind::ViewMessage(vote.signer())),
            Artifact::NoVote(vote) => (vote.view(), ClaimKind::ViewMessage(vote.signer())),
            Artifact::Nullify(share) => (share.view(), ClaimKind::Nullify(share.signer())),
            Artifact::Nullification(certificate) => (certificate.view(), ClaimKind::Nullification),
            Artifact::Vqc(certificate) => (certificate.view(), ClaimKind::Vqc),
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Lqc(_) => return None,
        };
        Some(Self::new(view, kind))
    }
}

/// Pending claims counted by input cohort.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CohortSet(BTreeMap<u64, usize>);

impl CohortSet {
    fn insert(&mut self, cohort: u64) {
        *self.0.entry(cohort).or_default() += 1;
    }

    /// Removes one claim from `cohort` and returns whether the set is now empty.
    fn remove(&mut self, cohort: u64) -> bool {
        if let Some(count) = self.0.get_mut(&cohort) {
            *count -= 1;
            if *count == 0 {
                self.0.remove(&cohort);
            }
        }
        self.0.is_empty()
    }

    /// Returns the earliest cohort holding a claim.
    pub(super) fn first(&self) -> Option<u64> {
        self.0.first_key_value().map(|(cohort, _)| *cohort)
    }
}

/// Pending claims with the cohorts they occupy, per claim and per view for view messages and
/// nullify shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ClaimIndex<D: Digest> {
    by_claim: BTreeMap<Claim, BTreeMap<ArtifactId<D>, Observation>>,
    cohorts: BTreeMap<Claim, CohortSet>,
    message_cohorts: BTreeMap<View, CohortSet>,
    nullify_cohorts: BTreeMap<View, CohortSet>,
}

impl<D: Digest> Default for ClaimIndex<D> {
    fn default() -> Self {
        Self {
            by_claim: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            message_cohorts: BTreeMap::new(),
            nullify_cohorts: BTreeMap::new(),
        }
    }
}

impl<D: Digest> ClaimIndex<D> {
    /// Records `id` as claiming `claim` at `observation`, replacing its earlier observation.
    pub(super) fn insert(&mut self, claim: Claim, id: ArtifactId<D>, observation: Observation) {
        let previous = self
            .by_claim
            .entry(claim)
            .or_default()
            .insert(id, observation);
        if let Some(previous) = previous {
            self.remove_cohort(claim, previous.cohort());
        }
        self.cohorts
            .entry(claim)
            .or_default()
            .insert(observation.cohort());
        if let Some(aggregate) = self.aggregate_mut(claim) {
            aggregate.insert(observation.cohort());
        }
    }

    /// Removes the claim `id` holds on `claim`, if any.
    pub(super) fn remove(&mut self, claim: Claim, id: ArtifactId<D>) {
        let Some(claims) = self.by_claim.get_mut(&claim) else {
            return;
        };
        let Some(observation) = claims.remove(&id) else {
            return;
        };
        if claims.is_empty() {
            self.by_claim.remove(&claim);
        }
        self.remove_cohort(claim, observation.cohort());
    }

    /// Returns the earliest cohort with a pending claim on `claim`.
    pub(super) fn first_cohort(&self, claim: Claim) -> Option<u64> {
        self.cohorts.get(&claim).and_then(CohortSet::first)
    }

    /// Returns the earliest cohort with a pending view-message claim in `view`.
    pub(super) fn first_message_cohort(&self, view: View) -> Option<u64> {
        self.message_cohorts.get(&view).and_then(CohortSet::first)
    }

    /// Returns the earliest cohort with a pending nullify-share claim in `view`.
    pub(super) fn first_nullify_cohort(&self, view: View) -> Option<u64> {
        self.nullify_cohorts.get(&view).and_then(CohortSet::first)
    }

    /// Drops every claim at or below `floor`.
    pub(super) fn retire_through(&mut self, floor: View) {
        retire_prefix(&mut self.by_claim, |claim| claim.view <= floor);
        retire_prefix(&mut self.cohorts, |claim| claim.view <= floor);
        retire_prefix(&mut self.message_cohorts, |view| *view <= floor);
        retire_prefix(&mut self.nullify_cohorts, |view| *view <= floor);
    }

    fn aggregate_mut(&mut self, claim: Claim) -> Option<&mut CohortSet> {
        match claim.kind {
            ClaimKind::ViewMessage(_) => Some(self.message_cohorts.entry(claim.view).or_default()),
            ClaimKind::Nullify(_) => Some(self.nullify_cohorts.entry(claim.view).or_default()),
            ClaimKind::Proposal | ClaimKind::Nullification | ClaimKind::Vqc => None,
        }
    }

    fn remove_cohort(&mut self, claim: Claim, cohort: u64) {
        remove_from(&mut self.cohorts, claim, cohort);
        match claim.kind {
            ClaimKind::ViewMessage(_) => remove_from(&mut self.message_cohorts, claim.view, cohort),
            ClaimKind::Nullify(_) => remove_from(&mut self.nullify_cohorts, claim.view, cohort),
            ClaimKind::Proposal | ClaimKind::Nullification | ClaimKind::Vqc => {}
        }
    }
}

/// Removes one claim from the cohort set at `key` and drops the set once empty.
fn remove_from<K: Ord>(index: &mut BTreeMap<K, CohortSet>, key: K, cohort: u64) {
    if index
        .get_mut(&key)
        .is_some_and(|cohorts| cohorts.remove(cohort))
    {
        index.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    fn id(seed: u8) -> ArtifactId<Sha256Digest> {
        ArtifactId::new(Sha256::hash(&[&[seed]]))
    }

    #[test]
    fn claim_index_tracks_cohorts_per_claim_and_view() {
        let view = View::new(4);
        let message = Claim::new(view, ClaimKind::ViewMessage(Participant::new(1)));
        let other = Claim::new(view, ClaimKind::ViewMessage(Participant::new(2)));
        let proposal = Claim::new(view, ClaimKind::Proposal);
        let mut claims = ClaimIndex::default();
        claims.insert(message, id(0), Observation::new(9, 0));
        claims.insert(other, id(1), Observation::new(5, 0));
        claims.insert(proposal, id(2), Observation::new(3, 0));
        assert_eq!(claims.first_cohort(message), Some(9));
        assert_eq!(claims.first_message_cohort(view), Some(5));
        assert_eq!(claims.first_nullify_cohort(view), None);

        // Re-claiming moves the claim to its new cohort.
        claims.insert(message, id(0), Observation::new(2, 0));
        assert_eq!(claims.first_cohort(message), Some(2));
        assert_eq!(claims.first_message_cohort(view), Some(2));

        claims.remove(message, id(0));
        claims.remove(message, id(0));
        assert_eq!(claims.first_cohort(message), None);
        assert_eq!(claims.first_message_cohort(view), Some(5));
        claims.remove(other, id(1));
        assert_eq!(claims.first_message_cohort(view), None);
        assert!(claims.message_cohorts.is_empty());

        claims.retire_through(View::new(3));
        assert_eq!(claims.first_cohort(proposal), Some(3));
        claims.retire_through(view);
        assert!(claims.by_claim.is_empty() && claims.cohorts.is_empty());
    }
}
