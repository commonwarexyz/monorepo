use crate::{
    Viewable,
    simplex::{
        actors::Kind,
        types::{Certificate, Notarization},
    },
    types::{TermLength, View},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, certificate::Scheme};
use std::collections::{BTreeMap, BTreeSet};

/// Why a resolver fetch was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FetchReason {
    MissingNullification,
    CertificationFailed,
}

impl FetchReason {
    /// Returns the stable trace field value for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingNullification => "missing_nullification",
            Self::CertificationFailed => "certification_failed",
        }
    }
}

/// Side effects requested by resolver state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// Issue a resolver fetch for `view`.
    Fetch {
        /// The view to fetch.
        view: View,
        /// The view whose processing caused this fetch.
        cause: View,
        /// Why the fetch is needed.
        reason: FetchReason,
    },
    /// New evidence settles asks for `kind` at views in `start..=end`.
    Settled {
        /// The kind of the settled asks.
        kind: Kind,
        /// The first settled view.
        start: View,
        /// The last settled view.
        end: View,
    },
    /// A finalization settles every ask at or below this view.
    Finalized(View),
    /// Retire background asks at or below this floor.
    RetainAbove(View),
}

/// Certificates the resolver holds and serves, and the repair progress built
/// on them through the current view.
pub struct State {
    /// Number of views in each leader term.
    term_length: TermLength,
    /// Highest seen view.
    current_view: View,
    /// View of the highest certified notarization or finalization, which is
    /// the construction floor.
    floor: View,
    /// Lowest anchor that fetch scans still need to consider (see
    /// [Self::fetch_missing]). Anchors below this cursor have already been
    /// requested or are covered by a stored nullification. A floor raise
    /// landing mid-term pulls it back to just above the floor (see
    /// [Self::prune]).
    fetch_floor: View,
    /// View and encoding of the highest finalization. It settles every ask at
    /// or below its view, so it stays servable while a certified notarization
    /// at the same or a higher view holds the floor.
    finalization: Option<(View, Bytes)>,
    /// Encoded nullifications retained while they cover an unfinalized view.
    /// They survive floor raises so asks below the floor remain servable.
    nullifications: BTreeMap<View, Bytes>,
    /// Views whose notarization awaits certification. They settle exact-parent
    /// fetches.
    pending_notarizations: BTreeSet<View>,
    /// Encoded certified notarizations retained until finalization. They
    /// survive floor raises so exact parents remain servable.
    certified_notarizations: BTreeMap<View, Bytes>,
    /// Views whose notarization is permanently uncertifiable, retained until
    /// finalization. These tombstones preserve the verdict for delayed
    /// exact-parent asks.
    uncertifiable_notarizations: BTreeSet<View>,
}

impl State {
    /// Create a new instance of [State].
    pub const fn new(term_length: TermLength) -> Self {
        Self {
            term_length,
            current_view: View::zero(),
            floor: View::zero(),
            fetch_floor: View::zero(),
            finalization: None,
            nullifications: BTreeMap::new(),
            pending_notarizations: BTreeSet::new(),
            certified_notarizations: BTreeMap::new(),
            uncertifiable_notarizations: BTreeSet::new(),
        }
    }

    /// Returns the term length this state was built with.
    pub const fn term_length(&self) -> TermLength {
        self.term_length
    }

    /// Returns the highest finalized view, or zero if none is known.
    pub fn last_finalized(&self) -> View {
        self.finalization
            .as_ref()
            .map_or(View::zero(), |(view, _)| *view)
    }

    /// Records a certificate and returns the effects the resolver actor should
    /// apply.
    pub fn handle<S: Scheme, D: Digest>(&mut self, certificate: Certificate<S, D>) -> Vec<Effect> {
        let view = certificate.view();
        let term_length = self.term_length;
        let last_finalized = self.last_finalized();
        self.current_view = self.current_view.max(view);

        // Retain encoded certificates until finalization so a peer repairing
        // below the floor can still fetch them.
        let mut effects = Vec::new();
        match &certificate {
            Certificate::Nullification(_) => {
                let end = view.term_end(term_length);
                if end > last_finalized {
                    self.nullifications.insert(view, certificate.encode());
                    effects.push(Effect::Settled {
                        kind: Kind::Nullification,
                        start: view,
                        end,
                    });
                }
            }
            Certificate::Notarization(_) => {
                // A notarization becomes the floor only once certified (see
                // [Self::handle_certified]).
                if view > last_finalized && !self.uncertifiable_notarizations.contains(&view) {
                    if !self.certified_notarizations.contains_key(&view) {
                        self.pending_notarizations.insert(view);
                    }
                    effects.push(Effect::Settled {
                        kind: Kind::Notarization,
                        start: view,
                        end: view,
                    });
                }
            }
            Certificate::Finalization(_) => {
                // The highest finalization answers every ask at or below it.
                if view > last_finalized {
                    self.finalization = Some((view, certificate.encode()));
                }

                // Finalization is the global retirement boundary: a valid proposal
                // can no longer name ancestry at or below it, so nothing here can
                // still be asked for.
                let finalized = last_finalized.max(view);
                self.nullifications
                    .retain(|view, _| view.term_end(term_length) > finalized);
                self.pending_notarizations.retain(|view| *view > finalized);
                self.certified_notarizations
                    .retain(|view, _| *view > finalized);
                self.uncertifiable_notarizations
                    .retain(|view| *view > finalized);
                effects.push(Effect::Finalized(finalized));
                if view > self.floor {
                    self.floor = view;
                    effects.push(self.prune());
                }
            }
        }

        effects.extend(self.fetch_missing(view));
        effects
    }

    /// Records a certification verdict and returns the effects the resolver
    /// actor should apply.
    ///
    /// The verdict carries its notarization, so it may arrive before or after
    /// [Self::handle] records that notarization.
    pub fn handle_certified<S: Scheme, D: Digest>(
        &mut self,
        notarization: Notarization<S, D>,
        success: bool,
    ) -> Vec<Effect> {
        let view = notarization.view();
        let last_finalized = self.last_finalized();

        // Every verdict clears the pending view.
        self.pending_notarizations.remove(&view);
        let mut effects = Vec::new();
        if success {
            // Only successful notarizations above finalization become servable.
            if view > last_finalized {
                self.certified_notarizations
                    .insert(view, Certificate::Notarization(notarization).encode());
            }

            // Certification passed: raise the floor to the notarization. This
            // may occur before or after a nullification for the same view (and
            // should always be favored). A finalization at a higher view can
            // later supersede this floor.
            if view > self.floor {
                self.floor = view;
                effects.push(self.prune());
            }

            // Re-scan for missing nullifications: a floor raise landing
            // mid-term pulls the fetch cursor back (see [Self::prune]).
            effects.extend(self.fetch_missing(view));
        } else {
            // No copy of an uncertifiable notarization can certify anywhere, so
            // it is not an answer to an exact-parent request.
            self.certified_notarizations.remove(&view);
            if view > last_finalized {
                self.uncertifiable_notarizations.insert(view);
            }
            effects.push(Effect::Settled {
                kind: Kind::Notarization,
                start: view,
                end: view,
            });

            // Request a nullification for this view (if not already covered).
            // Existing fetches remain active when the failed notarization did
            // not satisfy their subscribers, so the resolver retries them.
            if self.needs_nullification(view) {
                effects.push(Effect::Fetch {
                    view,
                    cause: view,
                    reason: FetchReason::CertificationFailed,
                });
            }
        }
        effects
    }

    /// Returns whether local evidence has settled an ask for `kind` at `view`.
    ///
    /// Settled means there is nothing left to fetch: either the evidence is in
    /// hand, or no response could ever serve the ask. This decides whether to
    /// open a fetch and whether a delivery completed one. [Effect::Settled] and
    /// [Effect::Finalized] carry the same rule to the resolver, one piece of
    /// evidence at a time.
    ///
    /// A valid response does not imply this. The wire key names only a view, so a
    /// peer may answer a notarization request with a covering nullification: valid
    /// evidence the resolver records, but not what was asked for.
    pub fn settled(&self, view: View, kind: Kind) -> bool {
        // Finalization rules out any further need for the view. This is also
        // what settles an ask answered by a finalization, since the highest one
        // is retained independently of the construction floor.
        if view <= self.last_finalized() {
            return true;
        }
        match kind {
            Kind::Nullification => self.covering_nullification(view).is_some(),
            Kind::Notarization => {
                // Holding the notarization settles this, and so does a failed
                // verdict: certification judges the evidence itself, so no
                // other copy of it could pass either.
                self.pending_notarizations.contains(&view)
                    || self.certified_notarizations.contains_key(&view)
                    || self.uncertifiable_notarizations.contains(&view)
            }
        }
    }

    /// Returns whether every ask sharing the resolver key for `view` is settled.
    ///
    /// Ignoring a delivery retires the key, including subscribers that may not
    /// be present in the delivery, so demand for both kinds must be settled.
    pub fn key_settled(&self, view: View) -> bool {
        self.settled(view, Kind::Nullification) && self.settled(view, Kind::Notarization)
    }

    /// Returns whether the notarization at `view` failed certification.
    pub fn uncertifiable(&self, view: View) -> bool {
        self.uncertifiable_notarizations.contains(&view)
    }

    /// Selects the best certificate to serve for `view`.
    ///
    /// The highest finalization settles every ask at or below it. Otherwise
    /// an exact certified notarization is preferred to a covering
    /// nullification, matching proposal construction. If neither is retained,
    /// the current floor is served. Pending notarizations and notarizations
    /// that fail certification are never served.
    pub fn produce(&self, view: View) -> Option<Bytes> {
        // Prefer the retained finalization because a higher notarization does
        // not settle an older ancestry request.
        if let Some((finalized, finalization)) = &self.finalization
            && view <= *finalized
        {
            return Some(finalization.clone());
        }

        // Follow the proposal-parent hierarchy. An honest proposer builds on a
        // nullification only when it has no certified notarization to use.
        if let Some(notarization) = self.certified_notarizations.get(&view) {
            return Some(notarization.clone());
        }
        if let Some(nullification) = self.covering_nullification(view) {
            return Some(nullification.clone());
        }

        // Above retained finalization, the movable floor may still serve a
        // higher certified notarization.
        if view > self.floor {
            return None;
        }
        self.certified_notarizations.get(&self.floor).cloned()
    }

    /// Returns the stored nullification covering `view`, if any.
    ///
    /// A nullification covers the rest of its term, so it may be keyed at an
    /// earlier view than the one being served.
    fn covering_nullification(&self, view: View) -> Option<&Bytes> {
        self.nullifications
            .range(view.covering_range(self.term_length))
            .next_back()
            .map(|(_, nullification)| nullification)
    }

    /// Returns whether `view` still needs a covering nullification to make
    /// progress: it is above the floor and no stored nullification covers it.
    fn needs_nullification(&self, view: View) -> bool {
        view > self.floor && self.covering_nullification(view).is_none()
    }

    /// Return requests for any missing nullifications.
    ///
    /// Scans from the cursor (never below the floor), requesting each term's
    /// anchor and advancing the cursor past everything scanned. Requests
    /// stay pending in the resolver until answered or retained out (we must
    /// eventually receive a nullification at the anchor or a
    /// notarization/finalization at a higher view). See the
    /// [module docs](super) for the full strategy, including how mid-term
    /// floor raises pull the cursor back.
    fn fetch_missing(&mut self, cause: View) -> Vec<Effect> {
        let mut effects = Vec::new();
        let mut cursor = self.fetch_floor.max(self.floor.next());
        while cursor < self.current_view {
            if self.covering_nullification(cursor).is_none() {
                effects.push(Effect::Fetch {
                    view: cursor,
                    cause,
                    reason: FetchReason::MissingNullification,
                });
            }
            cursor = cursor.next_term_start(self.term_length);
        }
        self.fetch_floor = cursor;
        effects
    }

    /// Retires background requests that are not higher than the floor.
    fn prune(&mut self) -> Effect {
        // A floor inside a partially-fetched term strands the term's tail
        // (see the module docs). Pull the cursor back to just above the
        // floor so a later scan re-requests the tail (the cursor may exceed
        // the current view here, so an eager fetch could not).
        let next = self.floor.next();
        if !next.is_term_start(self.term_length) {
            self.fetch_floor = self.fetch_floor.min(next);
        }
        Effect::RetainAbove(self.floor)
    }
}

/// Read access to resolver state for the actor tests.
#[cfg(test)]
impl State {
    pub(super) const fn floor(&self) -> View {
        self.floor
    }

    pub(super) const fn nullifications(&self) -> &BTreeMap<View, Bytes> {
        &self.nullifications
    }

    pub(super) const fn pending_notarizations(&self) -> &BTreeSet<View> {
        &self.pending_notarizations
    }

    pub(super) const fn certified_notarizations(&self) -> &BTreeMap<View, Bytes> {
        &self.certified_notarizations
    }

    pub(super) const fn uncertifiable_notarizations(&self) -> &BTreeSet<View> {
        &self.uncertifiable_notarizations
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_helpers::*, *};
    use crate::{simplex::scheme::ed25519, types::Epoch};
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_utils::{NZU32, test_rng};

    const NAMESPACE: &[u8] = b"resolver-state";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;
    type TestCertificate = Certificate<TestScheme, Sha256Digest>;

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        (schemes, verifier)
    }

    fn nullification(view: u64) -> TestCertificate {
        let (schemes, verifier) = fixture();
        Certificate::Nullification(build_nullification(
            &schemes,
            &verifier,
            EPOCH,
            View::new(view),
        ))
    }

    fn notarization(view: u64) -> Notarization<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        build_notarization(&schemes, &verifier, EPOCH, View::new(view))
    }

    fn finalization(view: u64) -> TestCertificate {
        let (schemes, verifier) = fixture();
        Certificate::Finalization(build_finalization(
            &schemes,
            &verifier,
            EPOCH,
            View::new(view),
        ))
    }

    fn fetch(view: u64, cause: u64, reason: FetchReason) -> Effect {
        Effect::Fetch {
            view: View::new(view),
            cause: View::new(cause),
            reason,
        }
    }

    fn settled(kind: Kind, start: u64, end: u64) -> Effect {
        Effect::Settled {
            kind,
            start: View::new(start),
            end: View::new(end),
        }
    }

    /// Applies effects to the views of outstanding background (nullification)
    /// asks, as the resolver actor would.
    fn apply_effects(outstanding: &mut BTreeSet<View>, effects: &[Effect]) {
        for effect in effects {
            match *effect {
                Effect::Fetch { view, .. } => {
                    outstanding.insert(view);
                }
                Effect::Settled {
                    kind: Kind::Nullification,
                    start,
                    end,
                } => {
                    outstanding.retain(|view| !(start..=end).contains(view));
                }
                Effect::Settled {
                    kind: Kind::Notarization,
                    ..
                } => {}
                Effect::Finalized(floor) | Effect::RetainAbove(floor) => {
                    outstanding.retain(|view| *view > floor);
                }
            }
        }
    }

    fn outstanding_views(views: &BTreeSet<View>) -> Vec<u64> {
        views.iter().map(|view| view.get()).collect()
    }

    #[test]
    fn handle_nullification_requests_missing_views() {
        let mut state = State::new(TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        let effects = state.handle(nullification(4));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Nullification, 4, 4),
                fetch(1, 4, FetchReason::MissingNullification),
                fetch(2, 4, FetchReason::MissingNullification),
                fetch(3, 4, FetchReason::MissingNullification),
            ]
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(state.nullifications.contains_key(&View::new(4)));
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let effects = state.handle(nullification(2));
        assert_eq!(effects, vec![settled(Kind::Nullification, 2, 2)]);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(state.nullifications.contains_key(&View::new(2)));
        assert_eq!(outstanding_views(&outstanding), vec![1, 3]);

        let effects = state.handle(nullification(1));
        assert_eq!(effects, vec![settled(Kind::Nullification, 1, 1)]);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(state.nullifications.contains_key(&View::new(1)));
        assert_eq!(outstanding_views(&outstanding), vec![3]);
    }

    #[test]
    fn fetch_requests_only_term_anchor_nullifications() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.handle(nullification(14));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Nullification, 14, 15),
                fetch(1, 14, FetchReason::MissingNullification),
                fetch(6, 14, FetchReason::MissingNullification),
                fetch(11, 14, FetchReason::MissingNullification),
            ]
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        let effects = state.handle(nullification(1));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);

        let effects = state.handle(nullification(6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![11]);
    }

    #[test]
    fn same_term_nullification_covers_later_views_until_finalized() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let nullification_v2 = nullification(2);
        state.handle(nullification_v2.clone());
        assert_eq!(state.produce(View::new(2)), Some(nullification_v2.encode()));
        assert_eq!(state.produce(View::new(5)), Some(nullification_v2.encode()));
        assert!(state.covering_nullification(View::new(6)).is_none());

        state.handle(finalization(3));
        assert_eq!(state.nullifications.len(), 1);
        assert_eq!(state.produce(View::new(4)), Some(nullification_v2.encode()));

        state.handle(finalization(5));
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn nullification_below_floor_can_cover_unresolved_term_views() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.handle(finalization(3));
        apply_effects(&mut outstanding, &effects);

        let effects = state.handle(nullification(6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![4]);

        let nullification_v2 = nullification(2);
        let effects = state.handle(nullification_v2.clone());
        apply_effects(&mut outstanding, &effects);
        assert!(outstanding.is_empty());
        assert_eq!(state.produce(View::new(4)), Some(nullification_v2.encode()));
        assert_eq!(state.produce(View::new(5)), Some(nullification_v2.encode()));
    }

    #[test]
    fn nullification_admission_matches_pruning_boundary() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let effects = state.handle(finalization(3));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(3)),
                Effect::RetainAbove(View::new(3))
            ]
        );

        let effects = state.handle(nullification(2));
        assert_eq!(effects, vec![settled(Kind::Nullification, 2, 5)]);
        assert!(state.covering_nullification(View::new(4)).is_some());

        let effects = state.handle(finalization(5));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(5)),
                Effect::RetainAbove(View::new(5))
            ]
        );
        assert!(state.nullifications.is_empty());

        let effects = state.handle(nullification(2));
        assert!(effects.is_empty());
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn floor_prunes_outstanding_requests() {
        let mut state = State::new(TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        for view in 4..=6 {
            let effects = state.handle(nullification(view));
            apply_effects(&mut outstanding, &effects);
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let effects = state.handle(Certificate::Notarization(notarization(6)));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::zero());
        assert_eq!(state.nullifications.len(), 3);
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let effects = state.handle(finalization(6));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(6)),
                Effect::RetainAbove(View::new(6))
            ]
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::new(6));
        assert!(state.nullifications.is_empty());
        assert!(outstanding.is_empty());
    }

    /// The highest finalization is served at or below its view, then an exact
    /// certified notarization, then a covering nullification, then the floor.
    #[test]
    fn produce_serves_finalization_nullification_or_floor() {
        let mut state = State::new(TermLength::ONE);

        // A finalization is served at and below its view.
        let finalization_v3 = finalization(3);
        state.handle(finalization_v3.clone());
        for view in 1..=3 {
            assert_eq!(
                state.produce(View::new(view)),
                Some(finalization_v3.encode())
            );
        }

        // A nullification above the finalization is served for its view. One
        // below the finalization is not retained.
        let nullification_v4 = nullification(4);
        state.handle(nullification_v4.clone());
        state.handle(nullification(1));
        assert!(!state.nullifications.contains_key(&View::new(1)));
        assert_eq!(state.produce(View::new(1)), Some(finalization_v3.encode()));
        assert_eq!(state.produce(View::new(4)), Some(nullification_v4.encode()));
        assert_eq!(state.produce(View::new(5)), None);

        // A certified notarization becomes the floor. It is served for its own
        // view and for lower views that nothing else covers.
        let notarization_v6 = notarization(6);
        state.handle(Certificate::Notarization(notarization_v6.clone()));
        state.handle_certified(notarization_v6.clone(), true);
        let floor = TestCertificate::Notarization(notarization_v6).encode();
        assert_eq!(state.produce(View::new(4)), Some(nullification_v4.encode()));
        assert_eq!(state.produce(View::new(5)), Some(floor.clone()));
        assert_eq!(state.produce(View::new(6)), Some(floor));
        assert_eq!(state.produce(View::new(7)), None);

        // A stale lower finalization does not replace the served one.
        state.handle(finalization(2));
        assert_eq!(state.produce(View::new(2)), Some(finalization_v3.encode()));
    }

    /// A pending notarization is never served. Once it certifies, it is
    /// preferred to a coexisting nullification, matching proposal construction.
    #[test]
    fn produce_tracks_preferred_ancestry_when_certificates_coexist() {
        let mut state = State::new(TermLength::ONE);

        // Before the notarization certifies, a leader can only justify
        // skipping this view with its nullification.
        let nullification_v3 = nullification(3);
        state.handle(nullification_v3.clone());
        let notarization_v3 = notarization(3);
        state.handle(Certificate::Notarization(notarization_v3.clone()));
        assert_eq!(state.produce(View::new(3)), Some(nullification_v3.encode()));

        // If certification completes after that decision, serving the
        // certified notarization matches the leader's newly preferred ancestry.
        state.handle_certified(notarization_v3.clone(), true);
        assert_eq!(
            state.produce(View::new(3)),
            Some(TestCertificate::Notarization(notarization_v3).encode())
        );
    }

    #[test]
    fn certification_failure_re_requests_failed_view() {
        let mut state = State::new(TermLength::ONE);

        // Handling a notarization requests the missing nullifications below it
        let notarization_v5 = notarization(5);
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Notarization, 5, 5),
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );

        // Certification fails for view 5
        let effects = state.handle_certified(notarization_v5, false);

        // Only the failed view gets a new background request. Requests
        // answered by the failed notarization are retried by the resolver
        // engine.
        assert_eq!(
            effects,
            vec![
                settled(Kind::Notarization, 5, 5),
                fetch(5, 5, FetchReason::CertificationFailed)
            ]
        );
    }

    #[test]
    fn certification_success_sets_floor() {
        let mut state = State::new(TermLength::ONE);

        // Handling a notarization requests the missing nullifications below it
        let notarization_v5 = notarization(5);
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Notarization, 5, 5),
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );

        // Certification succeeds for view 5
        let effects = state.handle_certified(notarization_v5, true);

        // The certified notarization becomes the floor
        assert_eq!(state.floor, View::new(5));
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
    }

    #[test]
    fn certification_success_preserves_remaining_anchor_requests() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.handle(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // The notarization does not duplicate any outstanding anchor while
        // certification is pending.
        let notarization_v5 = notarization(5);
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(effects, vec![settled(Kind::Notarization, 5, 5)]);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // Certification raises the floor past anchor 1 and leaves the higher
        // anchor requests pending.
        let effects = state.handle_certified(notarization_v5, true);
        apply_effects(&mut outstanding, &effects);

        assert_eq!(state.floor, View::new(5));
        assert_eq!(state.current_view, View::new(14));
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);
    }

    #[test]
    fn certification_success_at_mid_term_floor_refetches_term_tail() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.handle(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // A mid-term notarization answers the request for anchor 1, but once
        // certified it only covers views 1..=3 of term [1, 5].
        let notarization_v3 = notarization(3);
        let effects = state.handle(Certificate::Notarization(notarization_v3.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // Certification raises the floor to 3 and prunes the anchor-1 request.
        // Views 4-5 still need a covering nullification, which only a request
        // at a view in [4, 5] can retrieve (the outstanding requests at 6 and
        // 11 accept nothing from term [1, 5]), so the fetch scan must resume
        // from just above the mid-term floor rather than from the cursor.
        let effects = state.handle_certified(notarization_v3, true);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::new(3));
        assert_eq!(outstanding_views(&outstanding), vec![4, 6, 11]);
    }

    #[test]
    fn mid_term_floor_at_current_view_refetches_term_tail_later() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        // A gossiped notarization at view 4 is the highest view seen: the
        // fetch scan requests anchor 1, and the cursor jumps past the
        // current view to the next term anchor.
        let notarization_v4 = notarization(4);
        let effects = state.handle(Certificate::Notarization(notarization_v4.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1]);

        // Certification raises the floor to 4 (the current view itself),
        // mid-term of [1, 5]. The anchor-1 request is pruned and no view
        // above the floor is below the current view yet, so nothing can be
        // fetched here.
        let effects = state.handle_certified(notarization_v4, true);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::new(4));
        assert!(outstanding_views(&outstanding).is_empty());

        // Once the current view grows, the scan must resume from just above
        // the mid-term floor: view 5 is only coverable by a nullification
        // from term [1, 5], which the requests at anchors 6 and 11 reject.
        let effects = state.handle(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![5, 6, 11]);
    }

    #[test]
    fn fetch_requests_each_anchor_once() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let effects = state.handle(nullification(14));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Nullification, 14, 15),
                fetch(1, 14, FetchReason::MissingNullification),
                fetch(6, 14, FetchReason::MissingNullification),
                fetch(11, 14, FetchReason::MissingNullification),
            ]
        );

        // A notarization satisfying the request for anchor 1 must not trigger
        // a re-request of anchor 1 while its certification is pending, no
        // matter how many times it is delivered.
        let notarization_v5 = Certificate::Notarization(notarization(5));
        for _ in 0..3 {
            let effects = state.handle(notarization_v5.clone());
            assert_eq!(
                effects,
                vec![settled(Kind::Notarization, 5, 5)],
                "anchor re-requested: {effects:?}"
            );
        }

        // A later certificate must only request newly-uncovered anchors, not
        // re-issue the outstanding ones (the p2p resolver owns retries).
        let effects = state.handle(nullification(20));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Nullification, 20, 20),
                fetch(16, 20, FetchReason::MissingNullification)
            ]
        );
    }

    #[test]
    fn certification_failure_skips_covered_re_requests() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        state.handle(nullification(14));
        let notarization_v5 = notarization(5);
        state.handle(Certificate::Notarization(notarization_v5.clone()));

        // A nullification at view 1 covers the whole term [1, 5], so the
        // failed view needs no re-request.
        state.handle(nullification(1));

        let effects = state.handle_certified(notarization_v5, false);
        assert_eq!(effects, vec![settled(Kind::Notarization, 5, 5)]);
    }

    /// A finalization at the view of a certified-notarization floor requests
    /// nothing new and is served for every view at or below it.
    #[test]
    fn finalization_at_certified_floor_serves_without_refetch() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        // A nullification at view 14 requests the missing term anchors below it.
        let effects = state.handle(nullification(14));
        apply_effects(&mut outstanding, &effects);

        // Certifying the mid-term notarization at view 3 raises the floor and
        // requests the term tail.
        let notarization_v3 = notarization(3);
        let effects = state.handle(Certificate::Notarization(notarization_v3.clone()));
        apply_effects(&mut outstanding, &effects);
        let effects = state.handle_certified(notarization_v3, true);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![4, 6, 11]);

        // A finalization at the floor view only retires asks at or below it.
        let finalization_v3 = finalization(3);
        let effects = state.handle(finalization_v3.clone());
        assert_eq!(effects, vec![Effect::Finalized(View::new(3))]);

        // A stale lower finalization requests nothing either, so the floor-view
        // finalization is served for every view at or below it.
        let effects = state.handle(finalization(2));
        assert_eq!(effects, vec![Effect::Finalized(View::new(3))]);
        for view in 1..=3 {
            assert_eq!(
                state.produce(View::new(view)),
                Some(finalization_v3.encode())
            );
        }
    }
}
