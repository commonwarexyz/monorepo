//! Shared scheduling for active aggregation recovery.

use super::types::RecoveryKey;
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_macros::select_loop;
use commonware_resolver::Resolver;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};

/// Requests and cancels aggregation certificate recovery.
///
/// Implementations schedule logical recovery only. Recovered certificates must be delivered to
/// the matching [`super::Mailbox`] so the engine applies its authenticated epoch, range, and
/// signature checks.
pub trait Recoverer: Clone + Send + 'static {
    /// Requests `key` if it is not already requested.
    ///
    /// [`Unreliable::Rejected`] means the request was not admitted. Callers may retry it.
    fn fetch(&mut self, key: RecoveryKey) -> Unreliable<Feedback>;

    /// Cancels the exact admitted `key`.
    fn cancel(&mut self, key: RecoveryKey) -> Feedback;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::types::RecoveryNamespace,
        types::{Epoch, Height},
    };
    use commonware_resolver::Fetch;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::collections::BTreeSet;

    #[derive(Clone, Default)]
    struct MockResolver {
        state: Arc<Mutex<ResolverState>>,
    }

    #[derive(Default)]
    struct ResolverState {
        active: BTreeSet<RecoveryKey>,
        events: Vec<(bool, RecoveryKey)>,
        high_water: usize,
    }

    impl Resolver for MockResolver {
        type Key = RecoveryKey;
        type Subscriber = ();

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let key = fetch.into().key;
            let mut state = self.state.lock();
            state.active.insert(key);
            state.events.push((true, key));
            state.high_water = state.high_water.max(state.active.len());
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            for fetch in fetches {
                self.fetch(fetch);
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            let mut state = self.state.lock();
            let removed: Vec<_> = state
                .active
                .iter()
                .copied()
                .filter(|key| !predicate(key, &()))
                .collect();
            for key in removed {
                state.active.remove(&key);
                state.events.push((false, key));
            }
            Feedback::Ok
        }
    }

    fn key(epoch: u64, position: u64) -> RecoveryKey {
        RecoveryKey {
            namespace: RecoveryNamespace::derive(b"coordinator-test"),
            epoch: Epoch::new(epoch),
            position: Height::new(position),
        }
    }

    #[test]
    fn staged_admission_bounds_all_keys_and_rejected_fetches_are_retriable() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) =
                RecoveryCoordinator::staged(context.child("coordinator"), NZUsize!(2), NZUsize!(1));
            let keys: Vec<_> = (0..100).map(|position| key(1, position)).collect();

            assert!(recovery.fetch(keys[0]).accepted());
            assert!(recovery.fetch(keys[0]).accepted());
            assert!(recovery.fetch(keys[1]).accepted());
            for &key in &keys[2..] {
                assert_eq!(recovery.fetch(key), Unreliable::Rejected);
            }

            // Canceling one admitted key makes exactly one slot available before attachment.
            assert!(recovery.cancel(keys[0]).accepted());
            assert!(recovery.fetch(keys[2]).accepted());
            assert_eq!(recovery.fetch(keys[3]), Unreliable::Rejected);

            let handle = coordinator.attach(resolver).start();
            while state.lock().active.len() < 2 {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }

            {
                let state = state.lock();
                assert_eq!(state.high_water, 2);
                assert_eq!(state.active, BTreeSet::from([keys[1], keys[2]]));
                assert_eq!(state.events.len(), 2);
            }

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn coalesced_wakeups_preserve_dedup_and_exact_cancel() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) = RecoveryCoordinator::new(
                context.child("coordinator"),
                resolver,
                NZUsize!(1),
                NZUsize!(1),
            );
            let handle = coordinator.start();
            let requested = key(1, 0);

            assert!(recovery.fetch(requested).accepted());
            assert!(recovery.fetch(requested).accepted());
            while state.lock().events.is_empty() {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(recovery.cancel(requested).accepted());
            assert!(recovery.cancel(requested).accepted());
            assert!(recovery.fetch(requested).accepted());
            while state.lock().events.len() < 3 {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }

            assert_eq!(
                state.lock().events,
                vec![(true, requested), (false, requested), (true, requested)]
            );

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn pre_attachment_message_churn_has_bounded_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) =
                RecoveryCoordinator::staged(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let requested = key(1, 0);

            // A one-element ready queue and one optional overflow wake remain bounded regardless
            // of churn. Only the final admitted state needs to be reconciled after attachment.
            for _ in 0..10_000 {
                recovery.fetch(requested);
                recovery.cancel(requested);
            }
            recovery.fetch(requested);

            let handle = coordinator.attach(resolver).start();
            while state.lock().events.is_empty() {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(state.lock().events, vec![(true, requested)]);

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn runtime_shutdown_cancels_active_requests_with_live_handle() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) = RecoveryCoordinator::new(
                context.child("coordinator"),
                resolver,
                NZUsize!(1),
                NZUsize!(4),
            );
            let handle = coordinator.start();
            let requested = key(1, 0);
            assert!(recovery.fetch(requested).accepted());
            while state.lock().active.is_empty() {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");

            let state = state.lock();
            assert!(state.active.is_empty());
            assert_eq!(state.events, vec![(true, requested), (false, requested)]);
            drop(recovery);
        });
    }

    #[test]
    fn live_handles_are_closed_after_coordinator_shutdown() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) = RecoveryCoordinator::new(
                context.child("coordinator"),
                resolver,
                NZUsize!(1),
                NZUsize!(1),
            );
            let mut clone = recovery.clone();
            let handle = coordinator.start();

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");

            assert_eq!(recovery.fetch(key(1, 0)), Unreliable::new(Feedback::Closed));
            assert_eq!(recovery.cancel(key(1, 0)), Feedback::Closed);
            assert_eq!(clone.fetch(key(1, 1)), Unreliable::new(Feedback::Closed));
            assert_eq!(clone.cancel(key(1, 1)), Feedback::Closed);
            assert!(state.lock().events.is_empty());
        });
    }
}

#[derive(Clone, Copy)]
struct Wake;

#[derive(Default)]
struct WakeOverflow(Option<Wake>);

impl mailbox::Overflow<Wake> for WakeOverflow {
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Wake) -> Option<Wake>,
    {
        if let Some(wake) = self.0.take()
            && let Some(wake) = push(wake)
        {
            self.0 = Some(wake);
        }
    }
}

impl mailbox::Policy for Wake {
    type Overflow = WakeOverflow;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.0 = Some(message);
    }
}

#[derive(Default)]
struct Admission {
    // Tokens distinguish a cancellation followed by a new fetch of the same key.
    keys: BTreeMap<RecoveryKey, Arc<()>>,
    closed: bool,
}

/// Cloneable handle to a node-wide aggregation recovery coordinator.
pub struct Recovery {
    mailbox: mailbox::Sender<Wake>,
    admission: Arc<Mutex<Admission>>,
    cap: usize,
}

impl Clone for Recovery {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            admission: self.admission.clone(),
            cap: self.cap,
        }
    }
}

impl Recoverer for Recovery {
    fn fetch(&mut self, key: RecoveryKey) -> Unreliable<Feedback> {
        let mut admission = self.admission.lock();
        if admission.closed {
            return Unreliable::new(Feedback::Closed);
        }
        if admission.keys.contains_key(&key) {
            let feedback = self.mailbox.enqueue(Wake);
            if feedback == Feedback::Closed {
                admission.keys.remove(&key);
            }
            return Unreliable::new(feedback);
        }
        if admission.keys.len() >= self.cap {
            return Unreliable::rejected();
        }
        admission.keys.insert(key, Arc::new(()));
        let feedback = self.mailbox.enqueue(Wake);
        if feedback == Feedback::Closed {
            admission.keys.remove(&key);
        }
        Unreliable::new(feedback)
    }

    fn cancel(&mut self, key: RecoveryKey) -> Feedback {
        let mut admission = self.admission.lock();
        if admission.closed {
            return Feedback::Closed;
        }
        admission.keys.remove(&key);
        self.mailbox.enqueue(Wake)
    }
}

/// Actor that shares one logical outstanding recovery cap across engine scopes.
///
/// The cap is applied synchronously to every admitted key, including work waiting for the actor.
/// Excess distinct fetches return [`Unreliable::Rejected`] without being retained and can be
/// retried.
/// Actor wakeups are coalesced, so fetch and cancel churn cannot create unbounded mailbox overflow.
pub struct RecoveryCoordinator<E, R>
where
    E: Spawner + Metrics,
{
    context: ContextCell<E>,
    resolver: R,
    receiver: mailbox::Receiver<Wake>,
    admission: Arc<Mutex<Admission>>,
    active: BTreeMap<RecoveryKey, Arc<()>>,
}

impl<E, R> RecoveryCoordinator<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    /// Creates a coordinator and its cloneable handle.
    pub fn new(
        context: E,
        resolver: R,
        outstanding: NonZeroUsize,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Recovery) {
        let (coordinator, recovery) =
            RecoveryCoordinator::<E, ()>::staged(context, outstanding, mailbox_size);
        (coordinator.attach(resolver), recovery)
    }

    /// Starts the coordinator actor.
    pub fn start(self) -> Handle<()> {
        let mut this = self;
        spawn_cell!(this.context, this.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(_) = self.receiver.recv() else break => self.reconcile(),
        }
        let mut admission = self.admission.lock();
        admission.keys.clear();
        admission.closed = true;
        drop(admission);
        self.cancel_active();
    }

    fn reconcile(&mut self) {
        // Keep admission stable while stale requests are canceled and replacements are issued.
        // This preserves the cap across the resolver boundary, not only in the shared map.
        let admission = self.admission.lock();
        let canceled: Vec<_> = self
            .active
            .iter()
            .filter_map(|(key, token)| match admission.keys.get(key) {
                Some(admitted) if Arc::ptr_eq(token, admitted) => None,
                _ => Some(*key),
            })
            .collect();
        if !canceled.is_empty() {
            let canceled = BTreeSet::from_iter(canceled);
            self.resolver.retain(move |key, ()| !canceled.contains(key));
            self.active.retain(|key, token| {
                admission
                    .keys
                    .get(key)
                    .is_some_and(|admitted| Arc::ptr_eq(token, admitted))
            });
        }

        for (&key, token) in &admission.keys {
            if self.active.contains_key(&key) {
                continue;
            }
            if self.resolver.fetch(key).accepted() {
                self.active.insert(key, token.clone());
            }
        }
    }

    fn cancel_active(&mut self) {
        if self.active.is_empty() {
            return;
        }
        let active = std::mem::take(&mut self.active);
        self.resolver
            .retain(move |key, ()| !active.contains_key(key));
    }
}

impl<E> RecoveryCoordinator<E, ()>
where
    E: Spawner + Metrics,
{
    /// Creates a coordinator without a resolver and returns its cloneable handle.
    ///
    /// Requests may be submitted through the handle before [`Self::attach`] supplies the resolver.
    /// The configured outstanding limit still bounds all admitted requests before attachment. The
    /// attached coordinator must then be started to process them.
    pub fn staged(
        context: E,
        outstanding: NonZeroUsize,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Recovery) {
        let (mailbox, receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        let admission = Arc::new(Mutex::new(Admission::default()));
        let cap = outstanding.get();
        (
            Self {
                context: ContextCell::new(context),
                resolver: (),
                receiver,
                admission: admission.clone(),
                active: BTreeMap::new(),
            },
            Recovery {
                mailbox,
                admission,
                cap,
            },
        )
    }

    /// Attaches the resolver required to start the coordinator.
    pub fn attach<R>(self, resolver: R) -> RecoveryCoordinator<E, R>
    where
        R: Resolver<Key = RecoveryKey, Subscriber = ()>,
    {
        RecoveryCoordinator {
            context: self.context,
            resolver,
            receiver: self.receiver,
            admission: self.admission,
            active: self.active,
        }
    }
}
