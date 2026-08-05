//! Coalesced payload durability for append-only atomic blobs.
//!
//! A frontier is credited only after a full-file data-synchronization operation completes. The
//! backend never stages a root that omits prefix bytes from CRC32C until that credit is visible.
//! Bytes after the credited frontier remain covered by the local-witness checksum, so recovery does
//! not depend on unsynchronized writes reaching disk in submission order. Rewind drains the
//! active driver and removes credit above the new tail before those physical offsets can be reused.

use super::atomic;
use crate::Error;
#[cfg(test)]
use commonware_utils::sync::Condvar;
use commonware_utils::sync::{AsyncMutex, AsyncOwnedMutexGuard, Mutex, MutexGuard};
use std::sync::Arc;

/// Shared state and payload-preflush coordination for one current V2 generation.
pub(super) struct Context {
    state: Arc<AsyncMutex<atomic::State>>,
    preflush: Arc<Preflush>,
}

impl Context {
    pub(super) fn new(state: atomic::State) -> std::io::Result<Arc<Self>> {
        let durable = state.raw_len()?;
        Ok(Arc::new(Self {
            state: Arc::new(AsyncMutex::new(state)),
            preflush: Arc::new(Preflush::new(durable)),
        }))
    }

    pub(super) async fn lock(self: &Arc<Self>) -> AsyncOwnedMutexGuard<atomic::State> {
        if let Ok(state) = self.state.clone().try_lock_owned() {
            return state;
        }
        self.state.clone().lock_owned().await
    }

    pub(super) const fn preflush(&self) -> &Arc<Preflush> {
        &self.preflush
    }
}

struct Inner {
    requested: u64,
    durable: u64,
    running: bool,
    failure: Option<Error>,
    waiters: Vec<commonware_utils::channel::oneshot::Sender<()>>,
}

/// Runtime-neutral coordination around a backend-owned durability worker.
///
/// The worker is started by the backend that transitions `running` from false to true. It may
/// coalesce newer requests into the current pass and reports completion through [`Self::complete`].
pub(super) struct Preflush {
    inner: Mutex<Inner>,
    #[cfg(test)]
    changed: Condvar,
}

/// Owns one active durability driver and poisons the generation if the driver disappears.
pub(super) struct Driver {
    preflush: Arc<Preflush>,
    armed: bool,
}

impl Driver {
    pub(super) fn complete(&mut self, target: u64, result: Result<(), Error>) -> Option<u64> {
        let next = self.preflush.complete(target, result);
        if next.is_none() {
            self.armed = false;
        }
        next
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if self.armed {
            self.preflush.fail(Error::Closed);
        }
    }
}

impl Preflush {
    #[allow(clippy::missing_const_for_fn)]
    fn new(durable: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                requested: durable,
                durable,
                running: false,
                failure: None,
                waiters: Vec::new(),
            }),
            #[cfg(test)]
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock()
    }

    fn notify(&self, inner: &mut Inner) {
        #[cfg(test)]
        self.changed.notify_all();
        for waiter in inner.waiters.drain(..) {
            let _ = waiter.send(());
        }
    }

    pub(super) fn driver(self: &Arc<Self>) -> Driver {
        Driver {
            preflush: self.clone(),
            armed: true,
        }
    }

    /// Request durability through `target`, returning the first worker target when one must start.
    pub(super) fn request(&self, target: u64) -> Result<Option<u64>, Error> {
        let mut inner = self.lock();
        if let Some(error) = &inner.failure {
            return Err(error.clone());
        }
        inner.requested = inner.requested.max(target);
        if inner.requested <= inner.durable || inner.running {
            return Ok(None);
        }
        inner.running = true;
        Ok(Some(inner.requested))
    }

    /// Finish one worker pass and return the next coalesced target, if any.
    pub(super) fn complete(&self, target: u64, result: Result<(), Error>) -> Option<u64> {
        let mut inner = self.lock();
        match result {
            Ok(()) => inner.durable = inner.durable.max(target),
            Err(error) => {
                inner.failure = Some(error);
                inner.running = false;
                self.notify(&mut inner);
                return None;
            }
        }
        let next = (inner.requested > inner.durable).then_some(inner.requested);
        if next.is_none() {
            inner.running = false;
        }
        self.notify(&mut inner);
        next
    }

    fn fail(&self, error: Error) {
        let mut inner = self.lock();
        inner.failure.get_or_insert(error);
        inner.running = false;
        self.notify(&mut inner);
    }

    /// Record durability established by the foreground publication barrier.
    pub(super) fn record_durable(&self, target: u64) {
        let mut inner = self.lock();
        inner.durable = inner.durable.max(target);
        let durable = inner.durable;
        inner.requested = inner.requested.max(durable);
        self.notify(&mut inner);
    }

    /// Forget durability credit above a tail that is about to be reused.
    ///
    /// Callers hold the blob state lock and wait for the active driver before resetting, so no
    /// append can request a new frontier between the drain and this reset.
    pub(super) fn reset_after_rewind(&self, target: u64) {
        let mut inner = self.lock();
        debug_assert!(!inner.running);
        inner.requested = target;
        inner.durable = target;
        self.notify(&mut inner);
    }

    pub(super) fn failure(&self) -> Option<Error> {
        self.lock().failure.clone()
    }

    #[cfg(test)]
    pub(super) fn requested(&self) -> u64 {
        self.lock().requested
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.lock().waiters.len()
    }

    #[cfg(test)]
    pub(super) fn wait_blocking(&self, target: u64) -> Result<(), Error> {
        let mut inner = self.lock();
        loop {
            if let Some(error) = &inner.failure {
                return Err(error.clone());
            }
            if inner.durable >= target {
                return Ok(());
            }
            self.changed.wait(&mut inner);
        }
    }

    #[cfg(test)]
    pub(super) fn wait_idle_blocking(&self) -> Result<(), Error> {
        let mut inner = self.lock();
        loop {
            if let Some(error) = &inner.failure {
                return Err(error.clone());
            }
            if !inner.running {
                return Ok(());
            }
            self.changed.wait(&mut inner);
        }
    }

    #[allow(dead_code)]
    pub(super) async fn wait(&self, target: u64) -> Result<(), Error> {
        loop {
            let receiver = {
                let mut inner = self.lock();
                if let Some(error) = &inner.failure {
                    return Err(error.clone());
                }
                if inner.durable >= target {
                    return Ok(());
                }
                inner.waiters.retain(|waiter| !waiter.is_closed());
                let (sender, receiver) = commonware_utils::channel::oneshot::channel();
                inner.waiters.push(sender);
                receiver
            };
            receiver.await.map_err(|_| Error::Closed)?;
        }
    }

    #[allow(dead_code)]
    pub(super) async fn wait_idle(&self) -> Result<(), Error> {
        loop {
            let receiver = {
                let mut inner = self.lock();
                if let Some(error) = &inner.failure {
                    return Err(error.clone());
                }
                if !inner.running {
                    return Ok(());
                }
                inner.waiters.retain(|waiter| !waiter.is_closed());
                let (sender, receiver) = commonware_utils::channel::oneshot::channel();
                inner.waiters.push(sender);
                receiver
            };
            receiver.await.map_err(|_| Error::Closed)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{pin_mut, poll};

    #[test]
    fn requests_are_coalesced_behind_one_worker() {
        let preflush = Preflush::new(10);
        assert_eq!(preflush.request(20).unwrap(), Some(20));
        assert_eq!(preflush.request(30).unwrap(), None);
        assert_eq!(preflush.complete(20, Ok(())), Some(30));
        assert_eq!(preflush.complete(30, Ok(())), None);
        preflush.wait_blocking(30).unwrap();
    }

    #[test]
    fn foreground_barrier_advances_durable_frontier() {
        let preflush = Preflush::new(10);
        preflush.record_durable(40);
        assert_eq!(preflush.request(40).unwrap(), None);
        assert_eq!(preflush.request(50).unwrap(), Some(50));
    }

    #[test]
    fn rewind_reset_removes_stale_durability_credit() {
        let preflush = Preflush::new(10);
        assert_eq!(preflush.request(40).unwrap(), Some(40));
        assert_eq!(preflush.complete(40, Ok(())), None);
        preflush.wait_idle_blocking().unwrap();
        preflush.reset_after_rewind(20);
        assert_eq!(preflush.request(30).unwrap(), Some(30));
    }

    #[test]
    fn dropped_driver_is_a_sticky_failure() {
        let preflush = Arc::new(Preflush::new(10));
        assert_eq!(preflush.request(20).unwrap(), Some(20));
        drop(preflush.driver());
        assert!(matches!(preflush.request(30), Err(Error::Closed)));
        assert!(matches!(preflush.wait_blocking(20), Err(Error::Closed)));
    }

    #[tokio::test]
    async fn failure_wakes_waiters_and_is_sticky() {
        let preflush = Arc::new(Preflush::new(10));
        assert_eq!(preflush.request(20).unwrap(), Some(20));
        let waiter = tokio::spawn({
            let preflush = preflush.clone();
            async move { preflush.wait(20).await }
        });
        preflush.complete(20, Err(Error::WriteFailed));
        assert!(matches!(waiter.await.unwrap(), Err(Error::WriteFailed)));
        assert!(matches!(preflush.request(30), Err(Error::WriteFailed)));
    }

    #[tokio::test]
    async fn canceled_waiters_are_pruned_while_a_driver_is_blocked() {
        let preflush = Preflush::new(10);
        assert_eq!(preflush.request(20).unwrap(), Some(20));

        for _ in 0..1_000 {
            let waiter = preflush.wait(20);
            pin_mut!(waiter);
            assert!(poll!(waiter.as_mut()).is_pending());
        }

        assert!(preflush.waiter_count() <= 1);
    }
}
