//! The resolver is responsible for ensuring that the voter has all the certificates it needs to
//! make progress. The voter is voting in a view and has a "floor" view which is the latest
//! certified (or finalized) view that it knows about. Thus, it either requires covering
//! nullification evidence for intermediate views, or a higher floor. It will request the required
//! nullifications from the resolver. Other nodes will either serve such nullifications, or higher floors.
//!
//! # Fetch Strategy
//!
//! A nullification covers the view it was created for and the rest of that view's term, and a
//! request only accepts nullifications from its own term (see [`crate::types::View::covers`]).
//! One request per term, at its lowest uncovered view (the term's "anchor"), is therefore
//! sufficient: whatever answers it covers the rest of the term, and a higher floor moots it. The
//! fetch scan requests each term's anchor and advances a cursor past everything it scanned:
//!
//! ```text
//! term:      [1  2  3  4  5] [6 . . . 10] [11 . . . 15]    current = 14
//! request:   [1]             [6]          [11]             cursor -> 16
//!
//! nullification@4 covers 4..=5:  only a request keyed in [4, 5] retrieves it
//! nullification@4 for request 6: rejected (wrong term)
//! ```
//!
//! Requests stay pending in the resolver until answered or retained out, so the cursor never
//! revisits scanned views on its own (a rescan re-issues fetches for requests that are still
//! pending, which the resolver engine deduplicates).
//!
//! # Proposal Ancestry
//!
//! Background repair cannot detect a split where one participant certified a notarization and
//! another holds a covering nullification for the same view: both consider that view complete.
//! A proposal exposes both the exact missing ancestry view and an elected leader that must hold
//! evidence for it. The voter therefore adds a targeted subscriber for the existing view key.
//! It uses the same certificate response format as background repair.
//! Resolver work is deduplicated by key: if an unrestricted background subscriber already exists
//! when a response is delivered, that shared fetch remains unrestricted rather than being narrowed
//! to the proposal leader, and delivery is treated as background repair. A background subscriber
//! added while a targeted-only response is being validated does not retroactively change that
//! delivery's classification or request an immediate re-gossip.
//!
//! The key does not identify a certificate kind. A producer deterministically serves its
//! certified or finalized floor when it covers the key, preferring that floor when a covering
//! nullification also exists; otherwise it serves the nullification. If the producer's floor
//! changed after it constructed the proposal, the response may align the next proposal instead
//! of repairing the current one.
//!
//! The peer-visible key remains kindless, but each local subscriber records whether it needs a
//! covering nullification or the named certified parent. A covering nullification removes
//! background demand and targeted nullification demand throughout its term while preserving
//! targeted parent demand. A terminal certification verdict removes targeted parent demand at
//! that exact view while preserving nullification demand: success supplies the parent, while
//! failure permanently rules it out and starts background nullification repair. A certified-floor
//! increase alone cannot identify either requirement and therefore does not remove targeted
//! subscribers. Finalization is the universal boundary: it removes every subscriber at or below
//! its view, and queued requests are pruned by their ancestry view so delayed proposal work cannot
//! recreate them. Resolved requirements are remembered locally until finalization makes their
//! range irrelevant, preventing an older queued request from resurrecting work after matching
//! evidence was processed.
//!
//! A valid response completes the subscribers to which the resolver delivered it even if its kind
//! does not satisfy an older proposal. It still communicates the producer's current deterministic
//! ancestry preference, and a later proposal can re-arm the view if necessary. Kind mismatch alone
//! is not a validation failure and does not fault the serving peer. Only malformed,
//! key-incompatible, or cryptographically invalid evidence, or a notarization whose application
//! certification terminates unsuccessfully, receives a failure verdict. Later proposals can also
//! add leaders to the target set while a request remains active. Targets are key-scoped, so a target
//! made obsolete by matching local evidence can remain attached while another subscriber keeps the
//! same key active. Consequently, distinct unsatisfied targeted keys and some obsolete targets can
//! accumulate while finalization is stalled; there is no independent bound on this local request
//! state. This lifetime avoids relying on elapsed time or proposal age for correctness.
//!
//! A valid response need not satisfy the triggering proposal. A late floor raise can make an
//! honest leader return a newly preferred notarization instead of the nullification used to build
//! its proposal, while a Byzantine leader can name an uncertified parent and return its preferred
//! nullification. The voter requests a particular view only once per round to avoid a response
//! loop. It votes only if the resulting ancestry is complete; a later proposal can arm another
//! request for the same view.
//!
//! This pull takes a request and response after the mismatch is detected, while broadcasting
//! conflicting evidence takes one message delay. When the fetch remains targeted, the extra delay
//! retrieves the leader's current preferred evidence without all-peer fanout. Repairing the
//! triggering proposal is opportunistic: the
//! response and application verification must both complete before its timer expires. If the
//! response is still outstanding at that point, the request remains active unless matching local
//! evidence or finalization retires it. If the response has completed, its evidence remains
//! available even though the fetch itself is done. Targeted-only delivery does not cause an
//! immediate certificate broadcast, although ordinary timeout-retry logic can later include the
//! certificate in a view-entry broadcast.
//!
//! # Mid-Term Floor Raises
//!
//! A floor raise landing inside a term (a certified notarization or a finalization at a mid-term
//! view) strands the term's tail: the anchor request is retained out with the floor, requests in
//! later terms reject this term's nullifications, and the cursor is already past it. Nothing
//! would ever re-request the tail, so a validator whose parent chain rests at the floor could
//! never validate proposals that skip it:
//!
//! ```text
//! floor raises to 3, mid-term of [1, 5]:
//!
//! term:      [1  2  3 |  4  5] [6 . . . 10] [11 . . . 15]
//!                     ^floor
//! request:    x          ??    [6]          [11]
//!            (retained out)    (reject term-1 evidence)
//! ```
//!
//! Pruning repairs this by pulling the cursor back to just above the floor, so a later scan
//! re-requests the tail. Anchors whose requests are still pending are re-issued along the way
//! and deduplicated by the engine, while anchors with a stored covering nullification are
//! skipped:
//!
//! ```text
//! pull-back: cursor = min(cursor, floor + 1) = 4
//!
//! next scan: fetch(4), then the later anchors: fetch(6), fetch(11)
//!                                              (still pending: deduplicated)
//!
//! term:      [1  2  3 |  4  5] [6 . . . 10] [11 . . . 15]
//! request:              [4]    [6]          [11]
//! ```
//!
//! With single-view terms every view is its own anchor, a floor raise can never land mid-term,
//! and the pull-back never fires.

mod actor;
mod ingress;
mod state;

use crate::types::{Epoch, TermLength};
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::MailboxMessage;
use std::{num::NonZeroUsize, time::Duration};

pub struct Config<S: Scheme, B: Blocker, T: Strategy> {
    pub scheme: S,

    pub blocker: B,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,
    pub fetch_concurrent: NonZeroUsize,
    pub fetch_timeout: Duration,
    pub term_length: TermLength,
}

/// Certificate builders shared by the resolver test modules.
#[cfg(test)]
mod test_helpers {
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_parallel::Sequential;

    type TestScheme = ed25519::Scheme;

    pub(super) fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(epoch, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes, &Sequential).expect("nullification quorum")
    }

    pub(super) fn build_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Notarization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, &votes, &Sequential).expect("notarization quorum")
    }

    pub(super) fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, &votes, &Sequential).expect("finalization quorum")
    }
}
