//! Bounds on the state that peer traffic can make an honest Simplex engine hold.
//!
//! A peer may send any number of signed votes for any view. The engine documents
//! how much of that it keeps: votes ahead of its view only inside the admission
//! window and the next-term lane (`Optimistic Validation` in
//! [commonware_consensus::simplex]), one vote of each kind per signer and view, and
//! rounds only from `view_retention` below the finalized tip. The checks here read
//! one engine's end-of-run state against those three bounds:
//!
//! - `C6-I1`: no recorded peer vote is beyond [`admission_bound`].
//! - `C6-I2`: no signer has two recorded votes of one kind for one view.
//! - `C6-I3`: the voter tracks at most [`retained_bound`] rounds.
//!
//! Bytes of memory, verification work and votes below the retention floor are not
//! checked. A run with a restarted engine is not measured: its gauges belong to
//! the last incarnation and its log to all of them.
//!
//! [`check`] counts every evaluation under the labels below in [`crate::reach`], so a
//! test can prove that a driver measured its engines.

use crate::{
    reach,
    simplex_audit::{Event, RecordedEvent},
};
use commonware_consensus::{
    Viewable,
    simplex::types::{Activity, Attributable},
    types::{Participant, TermLength, View, ViewDelta},
};
use commonware_cryptography::{Digest, certificate};
use std::{collections::BTreeSet, fmt};

/// Name suffix of the voter's gauge for the view it is in.
pub const CURRENT_VIEW: &str = "engine_voter_state_current_view";

/// Name suffix of the voter's gauge for the rounds it tracks.
pub const TRACKED_VIEWS: &str = "engine_voter_state_tracked_views";

/// The `view_retention` every engine of these harnesses is configured with.
pub const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);

/// [`reach`] label: one engine's gauges were read.
pub const MEASURED: &str = "state_bounds_measured";

/// [`reach`] label: `C6-I1` was evaluated for one engine.
pub const ADMISSION_CHECKED: &str = "state_bounds_admission_checked";

/// [`reach`] label: `C6-I2` was evaluated for one engine.
pub const UNIQUENESS_CHECKED: &str = "state_bounds_uniqueness_checked";

/// [`reach`] label: `C6-I3` was evaluated for one engine.
pub const RETENTION_CHECKED: &str = "state_bounds_retention_checked";

/// The metric label that tells one engine's gauges from another's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    label: &'static str,
    value: String,
}

impl Node {
    /// An engine whose context carries its validator's public key.
    pub fn public_key(key: &impl ToString) -> Self {
        Self {
            label: "public_key",
            value: key.to_string(),
        }
    }

    /// An engine whose context carries its participant index, as in a Twins run where
    /// two engines share one key.
    pub fn index(index: usize) -> Self {
        Self {
            label: "index",
            value: index.to_string(),
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=\"{}\"", self.label, self.value)
    }
}

/// Reads the gauge whose name ends in `suffix` for `node` from an encoded metrics
/// text.
///
/// # Panics
///
/// Panics with the gauge's name unless exactly one sample matches: a renamed metric
/// must fail every run instead of leaving the bounds unmeasured.
pub fn gauge(metrics: &str, suffix: &str, node: &Node) -> u64 {
    let label = node.to_string();
    let mut samples = metrics.lines().filter_map(|line| {
        let (series, value) = line.rsplit_once(' ')?;
        let (name, labels) = series.split_once('{')?;
        let labels = labels.strip_suffix('}')?;
        let named = name == suffix
            || name
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('_'));
        (named && labels.split(',').any(|pair| pair == label)).then_some(value)
    });
    let Some(value) = samples.next() else {
        panic!("gauge {suffix}{{{label}}} not found");
    };
    assert!(
        samples.next().is_none(),
        "gauge {suffix}{{{label}}} is ambiguous"
    );
    value
        .parse()
        .unwrap_or_else(|_| panic!("gauge {suffix}{{{label}}} has the value {value}"))
}

/// The last view of the term that holds `view`; genesis is its own term.
const fn term_end(view: u64, term_length: u64) -> u64 {
    if view == 0 {
        return 0;
    }
    ((view - 1) / term_length * term_length).saturating_add(term_length)
}

/// The highest view an engine at view `current` tracks a peer vote for: the first
/// view of the next term, then its lane of `min(max(lookahead, 1), term_length) + 1`
/// views.
///
/// It is the maximum of the admission rule at `current` and never decreases as
/// `current` grows, so it also bounds every vote admitted at an earlier view.
pub fn admission_bound(current: View, term_length: TermLength, lookahead: ViewDelta) -> View {
    let next_term_start = term_end(current.get(), term_length.get()).saturating_add(1);
    let lane = lookahead
        .get()
        .max(1)
        .min(term_length.get())
        .saturating_add(1);
    View::new(next_term_start.saturating_add(lane))
}

/// Kind of a vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VoteKind {
    Notarize,
    Nullify,
    Finalize,
}

/// One vote of a peer that an engine exported to its reporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerVote<D> {
    pub kind: VoteKind,
    pub view: View,
    pub signer: Participant,
    /// The payload voted for; `None` for a nullify.
    pub payload: Option<D>,
}

/// The peer-vote log of the engine of participant `me`: every notarize, nullify and
/// finalize vote in `events` that another participant signed, in export order.
pub fn peer_votes<S: certificate::Scheme, D: Digest>(
    events: &[RecordedEvent<S, D>],
    me: Participant,
) -> Vec<PeerVote<D>> {
    events
        .iter()
        .filter_map(|recorded| {
            let Event::Activity { activity, .. } = &recorded.event else {
                return None;
            };
            let (kind, signer, payload) = match activity {
                Activity::Notarize(vote) => (
                    VoteKind::Notarize,
                    vote.signer(),
                    Some(vote.proposal.payload),
                ),
                Activity::Nullify(vote) => (VoteKind::Nullify, vote.signer(), None),
                Activity::Finalize(vote) => (
                    VoteKind::Finalize,
                    vote.signer(),
                    Some(vote.proposal.payload),
                ),
                _ => return None,
            };
            (signer != me).then(|| PeerVote {
                kind,
                view: activity.view(),
                signer,
                payload,
            })
        })
        .collect()
}

/// The second-highest view among the finalization certificates in `events`; genesis
/// when there are fewer than two.
///
/// The voter prunes at the start of each loop iteration and handles one certificate
/// per iteration, so when it exports its newest finalization its last finished prune
/// used the one before.
pub fn second_finalization<S: certificate::Scheme, D: Digest>(
    events: &[RecordedEvent<S, D>],
) -> View {
    let views: BTreeSet<View> = events
        .iter()
        .filter_map(|recorded| match &recorded.event {
            Event::Activity {
                activity: Activity::Finalization(finalization),
                ..
            } => Some(finalization.view()),
            _ => None,
        })
        .collect();
    views.into_iter().rev().nth(1).unwrap_or(View::zero())
}

/// `C6-I1`: every vote in `votes` is at or below `bound`.
pub fn check_admission<D>(votes: &[PeerVote<D>], bound: View) -> Result<(), String> {
    match votes.iter().find(|vote| vote.view > bound) {
        Some(vote) => Err(format!(
            "C6-I1: a {:?} vote of participant {} for view {} was tracked beyond the admission bound {bound}",
            vote.kind,
            vote.signer.get(),
            vote.view,
        )),
        None => Ok(()),
    }
}

/// `C6-I2`: no two votes in `votes` share a signer, a kind and a view, whatever
/// their payloads.
pub fn check_uniqueness<D>(votes: &[PeerVote<D>]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    match votes
        .iter()
        .find(|vote| !seen.insert((vote.signer, vote.kind, vote.view)))
    {
        Some(vote) => Err(format!(
            "C6-I2: participant {} has two recorded {:?} votes for view {}",
            vote.signer.get(),
            vote.kind,
            vote.view,
        )),
        None => Ok(()),
    }
}

/// The most rounds a voter tracks: every view from [`VIEW_RETENTION`] below
/// `second_finalization` (view 1 at the lowest) up to `admission`.
pub fn retained_bound(admission: View, second_finalization: View) -> u64 {
    let floor = second_finalization
        .get()
        .saturating_sub(VIEW_RETENTION.get())
        .max(1);
    admission.get().saturating_sub(floor).saturating_add(1)
}

/// `C6-I3`: a voter at view `current` that exported `second_finalization` tracks at
/// most [`retained_bound`] rounds. Returns the bound.
pub fn check_retention(
    tracked: u64,
    current: View,
    term_length: TermLength,
    lookahead: ViewDelta,
    second_finalization: View,
) -> Result<u64, String> {
    let bound = retained_bound(
        admission_bound(current, term_length, lookahead),
        second_finalization,
    );
    if tracked > bound {
        return Err(format!(
            "C6-I3: the voter at view {current} tracks {tracked} rounds, above the bound {bound} \
             (second-highest finalization {second_finalization})"
        ));
    }
    Ok(bound)
}

/// What [`check`] measured for one engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement<D> {
    /// The voter's view.
    pub current: View,
    /// The rounds the voter tracks.
    pub tracked: u64,
    /// [`admission_bound`] at `current`.
    pub admission: View,
    /// [`second_finalization`] of the engine's log.
    pub second_finalization: View,
    /// The bound of `C6-I3`; `None` when it was not evaluated.
    pub retained: Option<u64>,
    /// The engine's peer-vote log.
    pub peer_votes: Vec<PeerVote<D>>,
}

/// Measures one engine that ran for the whole run and checks `C6-I1`, `C6-I2` and,
/// with `fault_model`, `C6-I3`.
///
/// `events` is the engine's audit history, `me` its participant, `lookahead` its
/// own optimistic lookahead. `C6-I3` needs `fault_model`, the configuration being
/// inside the fault tolerance: with more Byzantine signers a certificate for a far
/// view can be forged, and the voter tracks its round.
///
/// # Panics
///
/// Panics with the violated invariant's id first.
pub fn check<S: certificate::Scheme, D: Digest>(
    metrics: &str,
    node: &Node,
    events: &[RecordedEvent<S, D>],
    me: Participant,
    term_length: TermLength,
    lookahead: ViewDelta,
    fault_model: bool,
) -> Measurement<D> {
    let current = View::new(gauge(metrics, CURRENT_VIEW, node));
    let tracked = gauge(metrics, TRACKED_VIEWS, node);
    reach::record(MEASURED);
    let admission = admission_bound(current, term_length, lookahead);
    let peer_votes = peer_votes(events, me);
    let second_finalization = second_finalization(events);

    reach::record(ADMISSION_CHECKED);
    if let Err(violation) = check_admission(&peer_votes, admission) {
        panic!("{violation} ({node})");
    }
    reach::record(UNIQUENESS_CHECKED);
    if let Err(violation) = check_uniqueness(&peer_votes) {
        panic!("{violation} ({node})");
    }
    let retained = fault_model.then(|| {
        reach::record(RETENTION_CHECKED);
        check_retention(
            tracked,
            current,
            term_length,
            lookahead,
            second_finalization,
        )
        .unwrap_or_else(|violation| panic!("{violation} ({node})"))
    });

    Measurement {
        current,
        tracked,
        admission,
        second_finalization,
        retained,
        peer_votes,
    }
}
