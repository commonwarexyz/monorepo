//! The resolver ensures that the voter has the certificates it needs to make progress. The voter
//! tracks a floor at its latest certified or finalized view. It needs either nullifications that
//! cover the intermediate views or evidence of a higher floor. The voter asks the resolver for
//! this evidence. Peers respond with covering nullifications or higher floors.
//!
//! # Fetch Strategy
//!
//! A nullification covers its own view and the rest of that view's term. A request only accepts
//! nullifications from its own term. See [`crate::types::View::covers`]. One request at the lowest
//! uncovered view is enough for each term. This view is the term's "anchor." Its answer covers the
//! rest of the term. A higher floor makes the request obsolete. The fetch scan requests each
//! term's anchor and advances a cursor past every view it scanned.
//!
//! ```text
//! term:      [1  2  3  4  5] [6 . . . 10] [11 . . . 15]    current = 14
//! request:   [1]             [6]          [11]             cursor -> 16
//!
//! nullification@4 covers 4..=5:  only a request keyed in [4, 5] retrieves it
//! nullification@4 for request 6: rejected (wrong term)
//! ```
//!
//! Requests stay pending until they are answered or removed by retention. The cursor does not
//! revisit scanned views on its own. A rescan reissues fetches for requests that remain pending.
//! The resolver engine deduplicates those fetches.
//!
//! # Proposal Ancestry
//!
//! Background repair cannot detect every certificate split. One participant may certify a
//! notarization while another holds a covering nullification for the same view. Both consider the
//! view complete. A proposal exposes the missing view and a leader that must hold useful evidence.
//! The voter adds a targeted purpose to the existing view key. The wire request and encoded
//! certificate response do not change. See [the Simplex overview](crate::simplex) for the protocol
//! rationale.
//!
//! The wire key does not identify a certificate kind. A producer serves its certified or finalized
//! floor when that floor covers the key. The floor takes priority when a nullification also exists.
//! Otherwise, the producer serves the covering nullification. A late floor change or Byzantine
//! proposal can produce a valid response that does not repair the triggering proposal. The voter
//! accepts this kind mismatch without faulting the peer. It reruns the full ancestry check before
//! voting.
//!
//! Malformed, key-incompatible, or cryptographically invalid evidence is rejected. A notarization
//! remains pending until application certification finishes. A terminal certification failure
//! produces a negative verdict. A pending verdict parks the fetch. The resolver sends no further
//! request for that view while validation is pending. Repair therefore waits for certification to
//! finish. A live [`CertifiableAutomaton`](crate::CertifiableAutomaton) must eventually return a
//! verdict unless finalization cancels the request. See the certification section of [the Simplex
//! overview](crate::simplex). Later proposal demand attaches to the same parked fetch. It does not
//! bypass the certification wait.
//!
//! Local fetch purposes govern retention. They do not affect response validity. A nullification
//! removes background and targeted-nullification demand throughout its term. A terminal
//! certification verdict removes targeted-parent demand at its exact view. A floor raise alone
//! removes only background demand. Finalization removes all demand at or below its view. Tombstones
//! prevent delayed mailbox work from recreating demand after matching evidence or finalization.
//!
//! Resolver work is deduplicated by key. A shared background subscriber keeps the fetch
//! unrestricted and follows the normal gossip path. Background demand that arrives during
//! validation does not reclassify a targeted-only delivery. Targeted-only delivery suppresses
//! immediate certificate gossip. Timeout retry may later include the certificate as view-entry
//! evidence.
//!
//! Unanswered targeted demand persists until matching evidence or finalization. It has no elapsed
//! time or proposal-age cutoff. Distinct keys can accumulate while finalization stalls. A target
//! for one key can remain while another subscriber keeps that key active. A targeted pull costs a
//! request and response instead of one broadcast delay. It avoids all-peer fanout. It rescues the
//! triggering proposal only if the response and application work finish before the proposal's
//! timer expires. Later proposals still benefit from evidence that arrives after the timer.
//!
//! # Mid-Term Floor Raises
//!
//! A floor raise inside a term strands the term's tail. The floor may come from a certified
//! notarization or a mid-term finalization. The anchor request is removed with the floor. Requests
//! in later terms reject this term's nullifications. The cursor is already past the tail. Nothing
//! would request it again. A validator whose parent chain rests at the floor could then fail to
//! validate proposals that skip it.
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
//! Pruning repairs this gap by pulling the cursor back to just above the floor. A later scan
//! requests the tail again. The scan also reissues requests for pending anchors. The resolver
//! engine deduplicates them. The scan skips anchors that already have a covering nullification.
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
//! With single-view terms, every view is its own anchor. A floor raise cannot land mid-term. The
//! pullback never runs.

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
