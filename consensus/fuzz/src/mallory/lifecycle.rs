//! Mallory's managed-validator crash/restart mechanics.
//!
//! Mallory may fault the single faultable identity ([`crate::BYZANTINE_IDX`])
//! at the process level, not just over the network. This module owns the two
//! primitives the runner drives against a [`ManagedValidator`]:
//!
//! - [`crash_stop`]: abort and await BOTH task handles so the old incarnation can
//!   never send again, then mark it [`Crashed`](crate::ValidatorLifecycle::Crashed).
//!   Terminal within the run -- no re-registration, no rebuild.
//! - [`abort_tasks`]: the shared abort+await step, also the FIRST step of the
//!   runner's durable and amnesia restarts (so no second incarnation ever coexists
//!   with the first).
//! - [`amnesia_partition`]: the fresh (empty) storage partition an amnesia restart
//!   rebuilds on, derived from the bumped incarnation counter so it is deterministic
//!   and distinct from the durable partition.
//!
//! The restart ORCHESTRATION lives in [`crate::mallory::runner`] because it needs
//! the oracle, participants, receive-stack wrapping, and packet-fault cell; this
//! module owns only the abort mechanics, the fixed downtime, and the amnesia
//! partition name.

use crate::{simplex::Simplex, ManagedValidator};
use std::{fmt::Display, time::Duration};

/// The fixed downtime a durable or amnesia restart waits between abort and rejoin.
/// Uses deterministic runtime time (never the failed node's own stalled view), so a
/// replayed input reproduces the restart schedule.
pub(crate) const MALLORY_RESTART_DOWNTIME: Duration = Duration::from_secs(2);

/// The fresh (empty) storage partition an amnesia restart rebuilds on.
///
/// Derived from the restarted node's bumped incarnation counter (`generation`), so
/// it is deterministic under replay and always distinct from the durable partition
/// (`validator.to_string()`, which carries no `_gen` suffix) and from any prior
/// incarnation's partition. Building on this empty partition means the engine finds
/// no journaled storage to replay -- it has forgotten its prior durable state,
/// including signed votes (disk-loss / Byzantine amnesia).
pub(crate) fn amnesia_partition<PK: Display>(validator: &PK, generation: u32) -> String {
    format!("{validator}_gen{generation}")
}

/// Crash-stop the validator: abort and await both handles, then mark it crashed.
///
/// After this returns the old engine and application tasks are terminated and can
/// never send on the network again (the key safety property). Crash-stop is
/// terminal within the run; the runner ends the episode after enacting it.
pub(crate) async fn crash_stop<P: Simplex>(mv: &mut ManagedValidator<P>) {
    abort_tasks(mv).await;
    mv.mark_crashed();
}

/// Abort and await both the engine and application handles.
///
/// Aborting the engine handle cascades to every engine sub-task (the runtime
/// aborts a finished task's descendants), and awaiting each handle drives the
/// aborted task to termination -- so once this returns, no task of the aborted
/// incarnation is still schedulable. The runner calls this FIRST on a durable
/// restart, before re-registration, so a second incarnation never coexists with
/// the first.
pub(crate) async fn abort_tasks<P: Simplex>(mv: &mut ManagedValidator<P>) {
    if let Some(handle) = mv.take_engine_handle() {
        handle.abort();
        let _ = handle.await;
    }
    if let Some(handle) = mv.take_app_handle() {
        handle.abort();
        let _ = handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amnesia_partition_is_fresh_and_deterministic() {
        // The durable partition is the bare `validator.to_string()`; every amnesia
        // partition carries a `_gen{n}` suffix, so it never collides with the
        // durable one or with a different incarnation, and it is a pure function of
        // (validator, generation) so a replay reproduces it.
        let durable = "abcd".to_string();
        assert_eq!(amnesia_partition(&"abcd", 1), "abcd_gen1");
        assert_ne!(amnesia_partition(&"abcd", 1), durable);
        assert_ne!(amnesia_partition(&"abcd", 1), amnesia_partition(&"abcd", 2));
        assert_eq!(amnesia_partition(&"abcd", 1), amnesia_partition(&"abcd", 1));
    }
}
