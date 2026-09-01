//! Proposal selection, view-message collection, and view exits.
//!
//! [`ViewState`] keeps, for each retained view, this node's local choices (its slot), the verified
//! proposals, view messages, nullify shares, and certificates, and the proposal parents that later
//! views may build on.
//!
//! ```text
//!             proposal and vote passes      certificate assembly
//!             (sign proposal, vote, or      (V-QC or nullification
//!              timeout cutoff)               from settled records)
//!                      |                             |
//!                      v                             v
//! claim -> verify -> record -> settle -> scan -> certificate -> forward -> exit
//!                                                                     |
//!                                             retire below the floor <+
//! ```
//!
//! # Claims and cohorts
//!
//! An observed view-scoped artifact claims its slot (the proposal, one signer's view message or
//! nullify share, or the view's certificate) before it is verified, and the claim records the
//! input cohort the artifact arrived in. A verified record settles only once no claim from an
//! earlier cohort is still pending. Which message, certificate, or exit wins therefore depends on
//! arrival order, never on the order in which verifications complete.
//!
//! # Certificate assembly
//!
//! A certificate scan walks one view's settled messages and nullify shares, picks the best V-QC
//! transcript or a nullification share set, and issues at most one aggregation job per view.
//! Completing a job invalidates the view's scan before another candidate is chosen.
//!
//! # Forwarding and exits
//!
//! The earliest V-QC or nullification of each view, by cohort with a V-QC winning a tie, is
//! forwarded to peers once. A certificate for the current view exits it. When a V-QC exits a view
//! in which this validator can still vote, the exit carries the V-QC's leader so the node votes
//! for it before leaving (the rescue vote).
//!
//! # Proposal and vote passes
//!
//! A proposal or vote body covers every producer chain, so it is built by a resumable pass that
//! spends the machine budget; a producer header admitted mid-pass restarts it. When the view timer
//! fires, the slot freezes a timeout cutoff: the vote this node would still cast, or a plain
//! timeout.

mod certificate;
mod claims;
mod forward;
mod proposal;
mod slot;
mod state;
mod store;

pub(crate) use self::{
    certificate::{
        NullificationRecoveryCompletion, NullificationRecoveryJob, VqcAggregateCompletion,
        VqcAggregateJob,
    },
    proposal::TimeoutCutoff,
    slot::{ViewSlotSnapshot, ViewStance, ViewTransition},
    state::{RetireFloors, ViewError, ViewState, ViewTimer},
};
