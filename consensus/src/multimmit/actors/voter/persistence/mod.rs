//! Owner of the voter's safety journal and checkpoint store.
//!
//! The voter core must remain available while storage appends, syncs, and snapshot writes are
//! pending. The persistence actor owns both stores, so only its task calls `append_persist`,
//! `start_sync`, `roll`, `prune`, or `store`.
//!
//! ```text
//! voter                             persistence actor
//!   |                                        |
//!   |-- Append(root, span, job) ------------>|-- append_persist(job)
//!   |                                        |-- start_sync(captured prefix)
//!   |-- Append(next job) ------------------->|       | appends continue behind the sync
//!   |                                        |<------+
//!   |<------------- Durable(span, job, ack) -| oldest first
//!   |                                        |
//!   |-- Checkpoint(cut) -------------------->|-- roll, then store the snapshot on a task
//!   |<------------------------------ Stored -|
//!   |<------------------------------ Pruned -|-- prune once no append is pending
//! ```
//!
//! Every result reaches the voter through one ordered [`Output`], so no acknowledgement
//! overtakes an earlier one and checkpoint progress keeps its place among them.
//!
//! A sync captures every append visible when it starts. Later appends continue while that sync
//! runs, but never borrow its durability. There is at most one sync. Once it completes, the actor
//! acknowledges exactly the captured prefix. Urgent records, a full append queue, a flush request,
//! and command closure demand durability. Before starting a demanded sync, the actor drains ready
//! commands so authorization and signature records can share it. Quiet reconstructible records
//! stay buffered until one of these demands arrives.
//!
//! A checkpoint rolls the journal to a fresh section before its snapshot is materialized, so every
//! earlier section is covered once the snapshot is durable. The prune waits until no append is
//! pending; the voter holds back authority-producing input until its appends drain.
//!
//! Any storage error is terminal: the actor reports it once as [`Output::Failed`] and stops.

mod actor;
mod hooks;
mod mailbox;
mod metrics;
#[cfg(test)]
mod test_gates;
#[cfg(test)]
mod tests;

pub(crate) use actor::{Actor, Config};
pub(crate) use hooks::{Hooks, NoHooks};
#[cfg(any(test, feature = "mocks"))]
pub(crate) use mailbox::Flusher;
pub(crate) use mailbox::{Admission, CheckpointOrigin, Durable, Error, Flushes, Mailbox, Output};
#[cfg(test)]
pub(crate) use test_gates::{JournalPoint, TestGates};

/// Builds an info span named `$name` that carries a checkpoint's origin fields.
macro_rules! checkpoint_span {
    ($parent:expr, $name:literal, $origin:expr) => {{
        let origin: $crate::multimmit::actors::voter::persistence::CheckpointOrigin = $origin;
        tracing::info_span!(
            parent: $parent,
            $name,
            epoch = commonware_runtime::telemetry::traces::TracedExt::traced(origin.epoch.get()),
            view = commonware_runtime::telemetry::traces::TracedExt::traced(origin.view.get()),
            cursor = commonware_runtime::telemetry::traces::TracedExt::traced(origin.cursor.get()),
            retired_views = commonware_runtime::telemetry::traces::TracedExt::traced(
                origin.retired_views.get()
            ),
        )
    }};
}
pub(crate) use checkpoint_span;
