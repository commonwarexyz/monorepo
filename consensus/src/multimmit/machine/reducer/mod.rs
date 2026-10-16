//! The [`Machine`](machine::Machine), its persistence pipeline bounds, and the resumable pass
//! the core hands it for each queued input.
//!
//! - `machine`: the `Machine` struct, construction, restore, and inspection.
//! - `step`: entry points: input steps, resumable passes, work polls, and replay.
//! - `observe`: admission, verification verdicts, and dependency waits.
//! - `completions`: completions of work the machine issued and timer deadlines.
//! - `persistence`: staging durable changes and the journal barrier pipeline.
//! - `components`: the protocol components and the hooks that hand them work.
//! - `store`, `ledger`: the retained artifact store and the durable ledger.

mod completions;
pub(super) mod components;
mod ledger;
pub(super) mod machine;
mod observe;
mod persistence;
mod step;
mod store;

use super::{
    artifact::IdentifiedArtifact,
    input::{Input, InputKind, Now},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// Emitted-but-unacknowledged barriers allowed before ordinary batches stop entering the journal
/// pipeline. The journal must flush by this limit to release the core's capacity.
pub(crate) const MAX_INFLIGHT_BARRIERS: usize = 4;

/// The most events one barrier may carry. The journal derives its record limits from this and
/// [`MAX_BATCH_BYTES`].
pub(crate) const MAX_BATCH_EVENTS: usize = 32;

/// The byte target that closes a barrier's batch. One indivisible event may exceed it, and the
/// journal's record limit leaves room for that event.
pub(crate) const MAX_BATCH_BYTES: usize = 1 << 20;

/// Total unacknowledged batches retained by the synchronous owner: the journal pipeline, one
/// coalescing batch, and one successor whose external release requires journal admission.
pub(crate) const MAX_STAGED_BARRIERS: usize = MAX_INFLIGHT_BARRIERS + 2;

/// One queued input, the clock reading at its admission, and its progress across core cycles.
///
/// An observation cohort resumes where the last budget ran out; every other input applies in one
/// unit.
pub(crate) struct InputPass<V: Variant, D: Digest> {
    pub(super) admitted: Now,
    pub(super) kind: PassKind<V, D>,
}

/// The unapplied remainder of one queued input.
pub(super) enum PassKind<V: Variant, D: Digest> {
    /// An input not yet applied; taken when it applies.
    Atomic(Option<Input<V, D>>),
    /// The artifacts of an observation cohort not yet observed, in observation order.
    Observe(std::vec::IntoIter<IdentifiedArtifact<V, D>>),
}

impl<V: Variant, D: Digest> InputPass<V, D> {
    /// Creates the pass of `input`, admitted at `admitted`.
    pub(crate) fn new(input: Input<V, D>, admitted: Now) -> Self {
        let kind = match input {
            Input::Observe(artifacts) => PassKind::Observe(artifacts.into_iter()),
            input => PassKind::Atomic(Some(input)),
        };
        Self { admitted, kind }
    }

    /// Returns the clock reading at the input's admission.
    pub(crate) const fn admitted(&self) -> Now {
        self.admitted
    }

    /// Returns whether the pass observes a cohort, whose units are artifacts.
    pub(crate) const fn observes(&self) -> bool {
        matches!(self.kind, PassKind::Observe(_))
    }

    /// Returns the kind of the input, or `None` for an atomic input that already applied.
    pub(crate) const fn input_kind(&self) -> Option<InputKind> {
        match &self.kind {
            PassKind::Atomic(input) => match input {
                Some(input) => Some(input.kind()),
                None => None,
            },
            PassKind::Observe(_) => Some(InputKind::Observe),
        }
    }

    /// Returns the input of an atomic pass that has not applied yet.
    #[cfg(test)]
    pub(crate) const fn pending_input(&self) -> Option<&Input<V, D>> {
        match &self.kind {
            PassKind::Atomic(input) => input.as_ref(),
            PassKind::Observe(_) => None,
        }
    }
}
