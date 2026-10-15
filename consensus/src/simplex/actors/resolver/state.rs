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

/// A change to resolver asks that follows from a recorded certificate or verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// A background fetch for the nullification covering `view`.
    Fetch {
        /// The view to fetch.
        view: View,
        /// The view whose processing caused this fetch.
        cause: View,
        /// Why the fetch is needed.
        reason: FetchReason,
    },
    /// Asks for `kind` at views in `start..=end` are settled.
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
    /// The floor rose to this view, ending background repair at or below it.
    Raised(View),
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
    /// [Self::fetch_missing]). Anchors below it have already been requested or
    /// are covered by a stored nullification. A floor raise landing mid-term
    /// pulls it back to just above the floor (see [Self::raise]).
    cursor: View,
    /// View and encoding of the highest finalization. It settles every ask at
    /// or below its view, so it stays servable while a certified notarization
    /// at the same or a higher view holds the floor.
    finalization: Option<(View, Bytes)>,
    /// Encoded nullifications retained while they cover an unfinalized view.
    nullifications: BTreeMap<View, Bytes>,
    /// Views whose notarization awaits certification. They settle exact-parent
    /// fetches.
    pending_notarizations: BTreeSet<View>,
    /// Encoded certified notarizations retained until finalization.
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
            cursor: View::zero(),
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
    fn last_finalized(&self) -> View {
        self.finalization
            .as_ref()
            .map_or(View::zero(), |(view, _)| *view)
    }

    /// Records a certificate and returns the effects the resolver actor should
    /// apply.
    pub fn updated<S: Scheme, D: Digest>(&mut self, certificate: Certificate<S, D>) -> Vec<Effect> {
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
                // [Self::certified]).
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
                    effects.push(self.raise(view));
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
    /// [Self::updated] records that notarization.
    pub fn certified<S: Scheme, D: Digest>(
        &mut self,
        notarization: Notarization<S, D>,
        success: bool,
    ) -> Vec<Effect> {
        let view = notarization.view();
        let last_finalized = self.last_finalized();

        // Every verdict clears the pending view and settles notarization asks
        // at it.
        self.pending_notarizations.remove(&view);
        let mut effects = vec![Effect::Settled {
            kind: Kind::Notarization,
            start: view,
            end: view,
        }];
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
                effects.push(self.raise(view));
            }

            // Re-scan for missing nullifications: a floor raise landing
            // mid-term pulls the fetch cursor back (see [Self::raise]).
            effects.extend(self.fetch_missing(view));
        } else {
            // No copy of a failed notarization can certify anywhere. Stop
            // serving it and record a tombstone that settles later asks at its
            // view.
            self.certified_notarizations.remove(&view);
            if view > last_finalized {
                self.uncertifiable_notarizations.insert(view);
            }

            // Request a nullification for this view if it is above the floor
            // and uncovered. Background fetches the notarization answered stay
            // open, since a notarization settles no nullification ask.
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
    /// [Effect::Finalized] carry the same rule to the resolver as each
    /// certificate or verdict is recorded.
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
    /// the floor is served for views at or below it. Pending notarizations and
    /// notarizations that fail certification are never served.
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

    /// Returns fetches for missing nullifications.
    ///
    /// Scans from the cursor (never at or below the floor), requesting each
    /// term's anchor and advancing the cursor past everything scanned. A
    /// request stays pending in the resolver until a covering nullification
    /// settles it or the floor reaches it. See the [module docs](super) for the
    /// full strategy, including how mid-term floor raises pull the cursor back.
    fn fetch_missing(&mut self, cause: View) -> Vec<Effect> {
        let mut effects = Vec::new();
        let mut anchor = self.cursor.max(self.floor.next());
        while anchor < self.current_view {
            if self.covering_nullification(anchor).is_none() {
                effects.push(Effect::Fetch {
                    view: anchor,
                    cause,
                    reason: FetchReason::MissingNullification,
                });
            }
            anchor = anchor.next_term_start(self.term_length);
        }
        self.cursor = anchor;
        effects
    }

    /// Raises the floor to `floor` and pulls the cursor back when the floor
    /// lands mid-term.
    fn raise(&mut self, floor: View) -> Effect {
        self.floor = floor;

        // A floor inside a partially-fetched term strands the term's tail
        // (see the module docs). Pull the cursor back to just above the
        // floor so a later scan re-requests the tail (the cursor may exceed
        // the current view here, so an eager fetch could not).
        let next = floor.next();
        if !next.is_term_start(self.term_length) {
            self.cursor = self.cursor.min(next);
        }
        Effect::Raised(floor)
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
                Effect::Finalized(floor) | Effect::Raised(floor) => {
                    outstanding.retain(|view| *view > floor);
                }
            }
        }
    }

    fn outstanding_views(views: &BTreeSet<View>) -> Vec<u64> {
        views.iter().map(|view| view.get()).collect()
    }

    #[test]
    fn nullification_requests_missing_views() {
        let mut state = State::new(TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        let effects = state.updated(nullification(4));
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

        let effects = state.updated(nullification(2));
        assert_eq!(effects, vec![settled(Kind::Nullification, 2, 2)]);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(state.nullifications.contains_key(&View::new(2)));
        assert_eq!(outstanding_views(&outstanding), vec![1, 3]);

        let effects = state.updated(nullification(1));
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

        let effects = state.updated(nullification(14));
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

        let effects = state.updated(nullification(1));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);

        let effects = state.updated(nullification(6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![11]);
    }

    #[test]
    fn same_term_nullification_covers_later_views_until_finalized() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let nullification_v2 = nullification(2);
        state.updated(nullification_v2.clone());
        assert_eq!(state.produce(View::new(2)), Some(nullification_v2.encode()));
        assert_eq!(state.produce(View::new(5)), Some(nullification_v2.encode()));
        assert!(state.covering_nullification(View::new(6)).is_none());

        state.updated(finalization(3));
        assert_eq!(state.nullifications.len(), 1);
        assert_eq!(state.produce(View::new(4)), Some(nullification_v2.encode()));

        state.updated(finalization(5));
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn nullification_below_floor_can_cover_unresolved_term_views() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.updated(finalization(3));
        apply_effects(&mut outstanding, &effects);

        let effects = state.updated(nullification(6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![4]);

        let nullification_v2 = nullification(2);
        let effects = state.updated(nullification_v2.clone());
        apply_effects(&mut outstanding, &effects);
        assert!(outstanding.is_empty());
        assert_eq!(state.produce(View::new(4)), Some(nullification_v2.encode()));
        assert_eq!(state.produce(View::new(5)), Some(nullification_v2.encode()));
    }

    #[test]
    fn nullification_admission_matches_pruning_boundary() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let effects = state.updated(finalization(3));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(3)),
                Effect::Raised(View::new(3))
            ]
        );

        let effects = state.updated(nullification(2));
        assert_eq!(effects, vec![settled(Kind::Nullification, 2, 5)]);
        assert!(state.covering_nullification(View::new(4)).is_some());

        let effects = state.updated(finalization(5));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(5)),
                Effect::Raised(View::new(5))
            ]
        );
        assert!(state.nullifications.is_empty());

        let effects = state.updated(nullification(2));
        assert!(effects.is_empty());
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn floor_retires_outstanding_requests() {
        let mut state = State::new(TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        for view in 4..=6 {
            let effects = state.updated(nullification(view));
            apply_effects(&mut outstanding, &effects);
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let effects = state.updated(Certificate::Notarization(notarization(6)));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::zero());
        assert_eq!(state.nullifications.len(), 3);
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let effects = state.updated(finalization(6));
        assert_eq!(
            effects,
            vec![
                Effect::Finalized(View::new(6)),
                Effect::Raised(View::new(6))
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
        state.updated(finalization_v3.clone());
        for view in 1..=3 {
            assert_eq!(
                state.produce(View::new(view)),
                Some(finalization_v3.encode())
            );
        }

        // A nullification above the finalization is served for its view. One
        // below the finalization is not retained.
        let nullification_v4 = nullification(4);
        state.updated(nullification_v4.clone());
        state.updated(nullification(1));
        assert!(!state.nullifications.contains_key(&View::new(1)));
        assert_eq!(state.produce(View::new(1)), Some(finalization_v3.encode()));
        assert_eq!(state.produce(View::new(4)), Some(nullification_v4.encode()));
        assert_eq!(state.produce(View::new(5)), None);

        // A certified notarization becomes the floor. It is served for its own
        // view and for lower views that nothing else covers.
        let notarization_v6 = notarization(6);
        state.updated(Certificate::Notarization(notarization_v6.clone()));
        state.certified(notarization_v6.clone(), true);
        let floor = TestCertificate::Notarization(notarization_v6).encode();
        assert_eq!(state.produce(View::new(4)), Some(nullification_v4.encode()));
        assert_eq!(state.produce(View::new(5)), Some(floor.clone()));
        assert_eq!(state.produce(View::new(6)), Some(floor));
        assert_eq!(state.produce(View::new(7)), None);

        // A stale lower finalization does not replace the served one.
        state.updated(finalization(2));
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
        state.updated(nullification_v3.clone());
        let notarization_v3 = notarization(3);
        state.updated(Certificate::Notarization(notarization_v3.clone()));
        assert_eq!(state.produce(View::new(3)), Some(nullification_v3.encode()));

        // If certification completes after that decision, serving the
        // certified notarization matches the leader's newly preferred ancestry.
        state.certified(notarization_v3.clone(), true);
        assert_eq!(
            state.produce(View::new(3)),
            Some(TestCertificate::Notarization(notarization_v3).encode())
        );
    }

    /// A verdict carries its notarization, so recording the notarization and
    /// its verdict leaves the same state in either order.
    #[test]
    fn verdict_and_notarization_commute() {
        let notarization_v7 = notarization(7);
        for success in [true, false] {
            // Record the notarization, then its verdict.
            let mut first = State::new(TermLength::new(NZU32!(5)));
            let mut first_outstanding = BTreeSet::new();
            let effects = first.updated(Certificate::Notarization(notarization_v7.clone()));
            apply_effects(&mut first_outstanding, &effects);
            let effects = first.certified(notarization_v7.clone(), success);
            apply_effects(&mut first_outstanding, &effects);

            // Record the verdict, then its notarization.
            let mut second = State::new(TermLength::new(NZU32!(5)));
            let mut second_outstanding = BTreeSet::new();
            let effects = second.certified(notarization_v7.clone(), success);
            apply_effects(&mut second_outstanding, &effects);
            let effects = second.updated(Certificate::Notarization(notarization_v7.clone()));
            apply_effects(&mut second_outstanding, &effects);

            // Both orders leave the same notarization sets, construction floor, and
            // fetches. Only a successful verdict makes the notarization
            // servable and the floor.
            assert_eq!(first.pending_notarizations, second.pending_notarizations);
            assert_eq!(
                first.certified_notarizations,
                second.certified_notarizations
            );
            assert_eq!(
                first.uncertifiable_notarizations,
                second.uncertifiable_notarizations
            );
            assert_eq!(first.floor, second.floor);
            assert_eq!(first_outstanding, second_outstanding);
            for probe in (1..=8).map(View::new) {
                assert_eq!(first.produce(probe), second.produce(probe));
            }
            assert_eq!(
                first.certified_notarizations.contains_key(&View::new(7)),
                success
            );
            assert_eq!(first.floor == View::new(7), success);
        }
    }

    /// Recording a certificate again opens no fetch and does not re-record a
    /// notarization that failed certification as pending, whatever arrived
    /// between the two copies.
    #[test]
    fn reapplied_certificates_emit_no_fetches() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let nullification_v20 = nullification(20);
        let notarization_v22 = notarization(22);
        let finalization_v23 = finalization(23);

        // Record each certificate once, with a failed verdict in between.
        state.updated(nullification_v20.clone());
        state.updated(Certificate::Notarization(notarization_v22.clone()));
        state.certified(notarization_v22.clone(), false);

        // Above finalization, copies open no fetch and the failed
        // notarization is not recorded again.
        assert_eq!(
            state.updated(nullification_v20.clone()),
            vec![settled(Kind::Nullification, 20, 20)]
        );
        assert!(
            state
                .updated(Certificate::Notarization(notarization_v22.clone()))
                .is_empty()
        );
        assert!(!state.pending_notarizations.contains(&View::new(22)));
        assert!(!state.certified_notarizations.contains_key(&View::new(22)));

        // After finalization prunes them, copies still open no fetch.
        state.updated(finalization_v23.clone());
        assert_eq!(
            state.updated(finalization_v23),
            vec![Effect::Finalized(View::new(23))]
        );
        assert!(state.updated(nullification_v20).is_empty());
        assert!(
            state
                .updated(Certificate::Notarization(notarization_v22))
                .is_empty()
        );
        assert!(state.nullifications.is_empty());
        assert!(state.pending_notarizations.is_empty());
    }

    /// A copy of a certified notarization settles its ask again without being
    /// recorded as pending, since no second verdict would ever clear it.
    #[test]
    fn certified_notarization_copy_is_not_pending() {
        let mut state = State::new(TermLength::ONE);
        let notarization_v3 = notarization(3);
        state.updated(Certificate::Notarization(notarization_v3.clone()));
        state.certified(notarization_v3.clone(), true);

        let effects = state.updated(Certificate::Notarization(notarization_v3));
        assert_eq!(effects, vec![settled(Kind::Notarization, 3, 3)]);
        assert!(state.pending_notarizations.is_empty());
    }

    /// A verdict that arrives after a covering finalization promotes nothing.
    #[test]
    fn late_verdict_after_finalization_promotes_nothing() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let notarization_v5 = notarization(5);
        state.updated(Certificate::Notarization(notarization_v5.clone()));
        assert!(state.pending_notarizations.contains(&View::new(5)));

        // A covering finalization prunes the view awaiting its verdict.
        state.updated(finalization(6));
        assert!(state.pending_notarizations.is_empty());

        // The late verdict finds nothing to promote: a notarization at or
        // below finalization never becomes servable.
        state.certified(notarization_v5, true);
        assert!(state.certified_notarizations.is_empty());
    }

    /// A finalization prunes every notarization at or below it and every
    /// nullification whose term ends at or below it.
    #[test]
    fn finalization_prunes_retained_certificates() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        // Retain a nullification and a notarization in each verdict state.
        state.updated(nullification(2));
        let (pending, certified, failed) = (notarization(6), notarization(7), notarization(8));
        for notarization in [&pending, &certified, &failed] {
            state.updated(Certificate::Notarization(notarization.clone()));
        }
        state.certified(certified, true);
        state.certified(failed, false);
        assert_eq!(state.nullifications.len(), 1);
        assert_eq!(state.pending_notarizations.len(), 1);
        assert_eq!(state.certified_notarizations.len(), 1);
        assert_eq!(state.uncertifiable_notarizations.len(), 1);

        // A finalization above all of them prunes them.
        state.updated(finalization(10));
        assert!(state.nullifications.is_empty());
        assert!(state.pending_notarizations.is_empty());
        assert!(state.certified_notarizations.is_empty());
        assert!(state.uncertifiable_notarizations.is_empty());
    }

    #[test]
    fn certification_failure_re_requests_failed_view() {
        let mut state = State::new(TermLength::ONE);

        // Handling a notarization requests the missing nullifications below it
        let notarization_v5 = notarization(5);
        let effects = state.updated(Certificate::Notarization(notarization_v5.clone()));
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
        let effects = state.certified(notarization_v5, false);

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
        let effects = state.updated(Certificate::Notarization(notarization_v5.clone()));
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
        let effects = state.certified(notarization_v5, true);

        // The certified notarization becomes the floor
        assert_eq!(state.floor, View::new(5));
        assert_eq!(
            effects,
            vec![
                settled(Kind::Notarization, 5, 5),
                Effect::Raised(View::new(5))
            ]
        );
    }

    #[test]
    fn certification_success_preserves_remaining_anchor_requests() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.updated(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // The notarization does not duplicate any outstanding anchor while
        // certification is pending.
        let notarization_v5 = notarization(5);
        let effects = state.updated(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(effects, vec![settled(Kind::Notarization, 5, 5)]);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // Certification raises the floor past anchor 1 and leaves the higher
        // anchor requests pending.
        let effects = state.certified(notarization_v5, true);
        apply_effects(&mut outstanding, &effects);

        assert_eq!(state.floor, View::new(5));
        assert_eq!(state.current_view, View::new(14));
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);
    }

    #[test]
    fn certification_success_at_mid_term_floor_refetches_term_tail() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let effects = state.updated(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // A mid-term notarization answers the request for anchor 1, but once
        // certified it only covers views 1..=3 of term [1, 5].
        let notarization_v3 = notarization(3);
        let effects = state.updated(Certificate::Notarization(notarization_v3.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // Certification raises the floor to 3 and retires the anchor-1 request.
        // Views 4-5 still need a covering nullification, which only a request
        // at a view in [4, 5] can retrieve (the outstanding requests at 6 and
        // 11 accept nothing from term [1, 5]), so the fetch scan must resume
        // from just above the mid-term floor rather than from the cursor.
        let effects = state.certified(notarization_v3, true);
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
        let effects = state.updated(Certificate::Notarization(notarization_v4.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1]);

        // Certification raises the floor to 4 (the current view itself),
        // mid-term of [1, 5]. The anchor-1 request is retired and no view
        // above the floor is below the current view yet, so nothing can be
        // fetched here.
        let effects = state.certified(notarization_v4, true);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.floor, View::new(4));
        assert!(outstanding_views(&outstanding).is_empty());

        // Once the current view grows, the scan must resume from just above
        // the mid-term floor: view 5 is only coverable by a nullification
        // from term [1, 5], which the requests at anchors 6 and 11 reject.
        let effects = state.updated(nullification(14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![5, 6, 11]);
    }

    #[test]
    fn fetch_requests_each_anchor_once() {
        let mut state = State::new(TermLength::new(NZU32!(5)));

        let effects = state.updated(nullification(14));
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
            let effects = state.updated(notarization_v5.clone());
            assert_eq!(
                effects,
                vec![settled(Kind::Notarization, 5, 5)],
                "anchor re-requested: {effects:?}"
            );
        }

        // A later certificate must only request newly-uncovered anchors, not
        // re-issue the outstanding ones (the p2p resolver owns retries).
        let effects = state.updated(nullification(20));
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

        state.updated(nullification(14));
        let notarization_v5 = notarization(5);
        state.updated(Certificate::Notarization(notarization_v5.clone()));

        // A nullification at view 1 covers the whole term [1, 5], so the
        // failed view needs no re-request.
        state.updated(nullification(1));

        let effects = state.certified(notarization_v5, false);
        assert_eq!(effects, vec![settled(Kind::Notarization, 5, 5)]);
    }

    /// A finalization at the view of a certified-notarization floor requests
    /// nothing new and is served for every view at or below it.
    #[test]
    fn finalization_at_certified_floor_serves_without_refetch() {
        let mut state = State::new(TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        // A nullification at view 14 requests the missing term anchors below it.
        let effects = state.updated(nullification(14));
        apply_effects(&mut outstanding, &effects);

        // Certifying the mid-term notarization at view 3 raises the floor and
        // requests the term tail.
        let notarization_v3 = notarization(3);
        let effects = state.updated(Certificate::Notarization(notarization_v3.clone()));
        apply_effects(&mut outstanding, &effects);
        let effects = state.certified(notarization_v3, true);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![4, 6, 11]);

        // A finalization at the floor view only retires asks at or below it.
        let finalization_v3 = finalization(3);
        let effects = state.updated(finalization_v3.clone());
        assert_eq!(effects, vec![Effect::Finalized(View::new(3))]);

        // A stale lower finalization requests nothing either, so the floor-view
        // finalization is served for every view at or below it.
        let effects = state.updated(finalization(2));
        assert_eq!(effects, vec![Effect::Finalized(View::new(3))]);
        for view in 1..=3 {
            assert_eq!(
                state.produce(View::new(view)),
                Some(finalization_v3.encode())
            );
        }
    }
}
