//! Fatal-policy helper for awaiting durable syncs.
//!
//! A marshal write starts its fsync eagerly: the archive spawns the sync and returns a
//! [`Handle`] that only observes completion. The storage layer already makes those handles
//! safe to share and drop: every observer of a sync sees the same result, later operations
//! on the same store wait for (and re-surface the failure of) an in-flight sync, and a
//! duplicate put returns a handle that still covers the original write. What remains for
//! marshal is the failure policy: a sync failure is fatal to local storage state and must
//! never become a recoverable verdict.

use commonware_runtime::{Error, Handle};
use tracing::debug;

/// Result of a durable sync.
pub(crate) type SyncResult = Result<(), Error>;

/// Applies marshal's fatal policy to a durable-sync result.
///
/// Returns `true` once the sync is durable. A real sync failure panics (annotated with
/// `name`) rather than resolving: converting it into a `false` verdict would let consensus
/// treat lost local state as a live rejection. Returns `false` only when the runtime is
/// shutting down (the handle was closed or aborted before the sync resolved), so the caller
/// reports "not durable" and abandons the work.
pub(crate) fn observe_sync(result: SyncResult, name: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(Error::Closed | Error::Aborted) => {
            debug!(name, "runtime shutdown before sync completed");
            false
        }
        Err(e) => panic!("failed to sync {name}: {e}"),
    }
}

/// Awaits a durable-sync handle, applying marshal's fatal policy via [`observe_sync`].
pub(crate) async fn await_durable(handle: Handle<()>, name: &str) -> bool {
    observe_sync(handle.await, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};

    #[test]
    fn test_await_durable_resolves_true_on_success() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(await_durable(Handle::ready(Ok(())), "test").await);
        });
    }

    #[test]
    fn test_await_durable_reports_shutdown_as_not_durable() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(!await_durable(Handle::ready(Err(Error::Closed)), "test").await);
            assert!(!await_durable(Handle::ready(Err(Error::Aborted)), "test").await);
        });
    }

    #[test]
    #[should_panic(expected = "failed to sync test")]
    fn test_await_durable_panics_on_sync_failure() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let failure = Handle::ready(Err(Error::WriteFailed));
            let _ = await_durable(failure, "test").await;
        });
    }
}
