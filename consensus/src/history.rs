//! Immutable commitments on a selected parent branch, resolved on demand.

use commonware_cryptography::Digest;
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use std::{future::Future, sync::Arc};

/// A shared handle to immutable selected parent commitments in forward order.
///
/// Complete history ends at the bound parent and begins at a finalized or genesis anchor.
/// Older history is available through canonical storage. A resident suffix exposed by
/// [`Self::peek`] may begin after that anchor.
///
/// Clones share one resolution and its result. Creating or cloning a handle does not poll
/// its resolver. The resolver future is polled only through [`Self::resolve`]. Dropping all
/// handles and resolution futures drops the resolver future and releases resources it owns.
/// Requests already submitted to shared services may continue under those services' lifetimes.
///
/// A resolved `None` means the selected history is permanently unavailable, for example
/// because its branch was replaced or consensus shut down. Temporary missing history must
/// keep the resolver pending. Resolving a handle never switches it to a replacement branch.
/// Unavailability does not establish payload invalidity: verification and certification
/// consumers must abstain or remain pending rather than reject the payload on this basis.
#[derive(Clone)]
pub struct History<D: Digest>(Inner<D>);

#[derive(Clone)]
enum Inner<D: Digest> {
    Ready(Arc<[D]>),
    Pending {
        resident: Arc<[D]>,
        resolver: Shared<BoxFuture<'static, Option<Arc<[D]>>>>,
    },
}

impl<D: Digest> History<D> {
    /// Creates a handle to commitments that are already resident.
    pub const fn ready(commitments: Arc<[D]>) -> Self {
        Self(Inner::Ready(commitments))
    }

    /// Creates a shared resolver that is first polled by [`Self::resolve`].
    ///
    /// The resolver must retain the selected branch's identity and return `None` only
    /// when that history can no longer become available. Work owned solely by this history
    /// must stop when all handles and resolution futures are dropped.
    pub fn new<F>(resolver: F) -> Self
    where
        F: Future<Output = Option<Arc<[D]>>> + Send + 'static,
    {
        Self::pending(Arc::from([]), resolver)
    }

    /// Creates a lazy shared resolver with an immediately available resident suffix.
    ///
    /// `resident` ends at the selected parent but may not reach the finalized or genesis
    /// anchor. The resolver completes the history to the current finalized anchor. It preserves
    /// overlapping commitments if finalization has advanced past part of the resident suffix.
    /// Callers compute the suffix's starting height from its length and the parent's height.
    /// Completion can extend the suffix backward or shorten it to a newer finalized anchor.
    ///
    /// The resolver has the same identity, unavailability, and cancellation requirements
    /// as [`Self::new`]. Neither construction nor [`Self::peek`] polls it.
    pub fn pending<F>(resident: Arc<[D]>, resolver: F) -> Self
    where
        F: Future<Output = Option<Arc<[D]>>> + Send + 'static,
    {
        Self(Inner::Pending {
            resident,
            resolver: resolver.boxed().shared(),
        })
    }

    /// Returns resident commitments without starting or polling resolution.
    ///
    /// Before resolution, returns the nonempty resident suffix supplied to [`Self::pending`],
    /// which may not reach the finalized anchor. After resolution, returns the complete
    /// history. Returns `None` when no suffix is resident or resolution ended without history.
    pub fn peek(&self) -> Option<&Arc<[D]>> {
        match &self.0 {
            Inner::Ready(commitments) => Some(commitments),
            Inner::Pending { resident, resolver } => resolver.peek().map_or_else(
                || (!resident.is_empty()).then_some(resident),
                |result| result.as_ref(),
            ),
        }
    }

    /// Resolves the selected history, sharing the result with all clones.
    ///
    /// `None` is terminal unavailability, never a temporary absence of dependencies.
    pub async fn resolve(self) -> Option<Arc<[D]>> {
        match self.0 {
            Inner::Ready(commitments) => Some(commitments),
            Inner::Pending { resolver, .. } => resolver.await,
        }
    }
}

impl<D: Digest> From<Arc<[D]>> for History<D> {
    fn from(commitments: Arc<[D]>) -> Self {
        Self::ready(commitments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::crc32::Digest;
    use futures::{channel::oneshot, future};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn commitments() -> Arc<[Digest]> {
        Arc::from([Digest::from(1), Digest::from(2)])
    }

    #[test]
    fn ready_and_from_preserve_resident_commitments() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<History<Digest>>();
        let selected = commitments();
        for history in [
            History::ready(selected.clone()),
            History::from(selected.clone()),
        ] {
            assert!(Arc::ptr_eq(history.peek().unwrap(), &selected));
            let resolved = history.resolve().now_or_never().unwrap().unwrap();
            assert!(Arc::ptr_eq(&resolved, &selected));
        }
    }

    #[test]
    fn lazy_first_poll_and_shared_resolution() {
        let executions = Arc::new(AtomicUsize::new(0));
        let started = executions.clone();
        let selected = commitments();
        let result = selected.clone();
        let (sender, receiver) = oneshot::channel();
        let history = History::new(async move {
            started.fetch_add(1, Ordering::SeqCst);
            receiver.await.unwrap();
            Some(result)
        });
        let other = history.clone();
        assert!(history.peek().is_none());
        assert!(other.peek().is_none());
        let mut first = Box::pin(history.clone().resolve());
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(first.as_mut().now_or_never().is_none());
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        let mut second = Box::pin(other.resolve());
        assert!(second.as_mut().now_or_never().is_none());
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        sender.send(()).unwrap();
        let resolved = first.now_or_never().unwrap().unwrap();
        assert!(Arc::ptr_eq(&resolved, &selected));
        assert!(Arc::ptr_eq(history.peek().unwrap(), &selected));
        assert!(Arc::ptr_eq(
            &second.now_or_never().unwrap().unwrap(),
            &selected
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unavailable_is_shared_and_terminal() {
        let executions = Arc::new(AtomicUsize::new(0));
        let started = executions.clone();
        let history = History::pending(commitments(), async move {
            started.fetch_add(1, Ordering::SeqCst);
            None
        });
        assert!(history.peek().is_some());
        assert!(history.clone().resolve().now_or_never().unwrap().is_none());
        assert!(history.peek().is_none());
        assert!(history.resolve().now_or_never().unwrap().is_none());
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resident_suffix_visible_before_poll_and_full_history_after_resolution() {
        let selected = commitments();
        let resident: Arc<[Digest]> = Arc::from([selected[1]]);
        let executions = Arc::new(AtomicUsize::new(0));
        let started = executions.clone();
        let full = selected.clone();
        let history = History::pending(resident.clone(), async move {
            started.fetch_add(1, Ordering::SeqCst);
            Some(full)
        });
        assert!(Arc::ptr_eq(history.peek().unwrap(), &resident));
        let resolving = history.clone().resolve();
        assert!(Arc::ptr_eq(history.peek().unwrap(), &resident));
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        let resolved = resolving.now_or_never().unwrap().unwrap();
        assert!(Arc::ptr_eq(&resolved, &selected));
        assert!(Arc::ptr_eq(history.peek().unwrap(), &selected));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unused_resolver_released_after_last_clone() {
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        let history = History::<Digest>::new(async move {
            future::pending::<()>().await;
            drop(resource);
            None
        });
        let other = history.clone();
        drop(history);
        assert!(weak.upgrade().is_some());
        drop(other);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn pending_resolver_released_after_last_owner() {
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        let history = History::<Digest>::new(async move {
            future::pending::<()>().await;
            drop(resource);
            None
        });
        let other = history.clone();
        let mut resolving = Box::pin(history.resolve());
        assert!(resolving.as_mut().now_or_never().is_none());
        drop(resolving);
        assert!(weak.upgrade().is_some());
        drop(other);
        assert!(weak.upgrade().is_none());
    }
}
