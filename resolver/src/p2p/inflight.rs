use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::histogram, Clock};
use commonware_utils::{
    futures::{AbortablePool, Aborter},
    Span,
};
use futures::future::Aborted;
use std::{collections::HashMap, future::Future};

/// A completed delivery to the consumer.
pub(super) struct Delivery<P: PublicKey, Key: Span> {
    pub(super) peer: P,
    pub(super) key: Key,
    pub(super) valid: bool,
}

/// Tracks per-key state for an in-flight fetch.
///
/// `delivery` is `Some` while the consumer is validating a response, and `None` while
/// the request is still pending in the fetcher.
struct Entry<E: Clock> {
    timer: histogram::Timer<E>,
    delivery: Option<Aborter>,
}

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<E: Clock, P: PublicKey, Key: Span> {
    /// Per-key entries tracking fetch duration timers and (when validating a response)
    /// the [Aborter] that cancels the in-flight consumer delivery.
    entries: HashMap<Key, Entry<E>>,

    /// Holds futures that resolve once the `Consumer` has validated fetched data.
    deliveries: AbortablePool<Delivery<P, Key>>,
}

impl<E: Clock, P: PublicKey, Key: Span> Default for Inflight<E, P, Key> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deliveries: AbortablePool::default(),
        }
    }
}

impl<E: Clock, P: PublicKey, Key: Span> Inflight<E, P, Key> {
    /// Returns true if there is an in-flight entry for the key.
    pub(super) fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Insert a new in-flight entry for the key.
    pub(super) fn insert(&mut self, key: Key, timer: histogram::Timer<E>) {
        self.entries.insert(
            key,
            Entry {
                timer,
                delivery: None,
            },
        );
    }

    /// Remove the in-flight entry for the key and cancel its duration timer (suppressing
    /// the recording). Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Key) -> bool {
        let Some(entry) = self.entries.remove(key) else {
            return false;
        };
        // Dropping `entry` aborts the in-flight delivery (if any).
        entry.timer.cancel();
        true
    }

    /// Mark the in-flight entry for the key as complete, recording its duration via the
    /// timer's drop. Panics if no entry exists for the key.
    pub(super) fn complete(&mut self, key: &Key) {
        self.entries.remove(key).expect("inflight entry");
    }

    /// Drop all in-flight entries without recording duration metrics.
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drop entries for which the predicate returns false. Cancels the timer
    /// for each dropped entry. Returns the count of dropped entries.
    pub(super) fn retain<F: FnMut(&Key) -> bool>(&mut self, mut predicate: F) -> usize {
        let removed: Vec<_> = self.entries.extract_if(|k, _| !predicate(k)).collect();
        let count = removed.len();
        for (_, entry) in removed {
            entry.timer.cancel();
        }
        count
    }

    /// Drop all entries, canceling each timer. Returns the count of dropped entries.
    pub(super) fn drain(&mut self) -> usize {
        let removed: Vec<_> = self.entries.drain().collect();
        let count = removed.len();
        for (_, entry) in removed {
            entry.timer.cancel();
        }
        count
    }

    /// Clear the delivery handle for an entry, leaving the entry in place.
    pub(super) fn clear_delivery(&mut self, key: &Key) {
        self.entries.get_mut(key).expect("inflight entry").delivery = None;
    }

    /// Begin a consumer delivery for the entry, attaching the abort handle.
    pub(super) fn start_delivery<F>(&mut self, key: &Key, fut: F)
    where
        F: Future<Output = Delivery<P, Key>> + Send + 'static,
    {
        let aborter = self.deliveries.push(fut);
        let entry = self.entries.get_mut(key).expect("inflight entry");
        assert!(entry.delivery.replace(aborter).is_none());
    }

    /// Returns a future that resolves to the next completed delivery, or [Aborted] if
    /// the delivery was canceled.
    pub(super) fn next_delivery(
        &mut self,
    ) -> impl Future<Output = Result<Delivery<P, Key>, Aborted>> + '_ {
        self.deliveries.next_completed()
    }
}
