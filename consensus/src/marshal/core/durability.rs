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
use std::future::Future;
use tracing::debug;

/// Applies marshal's fatal policy when awaiting a durable-sync [`Handle`].
pub(crate) trait Durable {
    /// Resolves `true` once the sync is durable. A real sync failure panics (annotated
    /// with `name`) rather than resolving: converting it into a `false` verdict would let
    /// consensus treat lost local state as a live rejection. Resolves `false` only when
    /// the runtime is shutting down (the handle was closed or aborted before the sync
    /// resolved), so the caller reports "not durable" and abandons the work.
    fn durable(self, name: &'static str) -> impl Future<Output = bool> + Send;
}

impl Durable for Handle<()> {
    async fn durable(self, name: &'static str) -> bool {
        match self.await {
            Ok(()) => true,
            Err(Error::Closed | Error::Aborted) => {
                debug!(name, "runtime shutdown before sync completed");
                false
            }
            Err(e) => panic!("failed to sync {name}: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};

    #[test]
    fn test_durable_resolves_true_on_success() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(Handle::ready(Ok(())).durable("test").await);
        });
    }

    #[test]
    fn test_durable_reports_shutdown_as_not_durable() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(!Handle::ready(Err(Error::Closed)).durable("test").await);
            assert!(!Handle::ready(Err(Error::Aborted)).durable("test").await);
        });
    }

    #[test]
    #[should_panic(expected = "failed to sync test")]
    fn test_durable_panics_on_sync_failure() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let failure = Handle::<()>::ready(Err(Error::WriteFailed));
            let _ = failure.durable("test").await;
        });
    }
}
