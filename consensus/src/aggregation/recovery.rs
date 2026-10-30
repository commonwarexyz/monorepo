//! Shared scheduling and routing for active aggregation recovery.

use super::{
    CertificateOutcome, Mailbox,
    types::{RecoveryKey, RecoveryNamespace},
};
use crate::types::{Epoch, Height};
use bytes::Bytes;
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_macros::select_loop;
use commonware_resolver::{Delivery, Resolver};
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;

/// Registers an engine scope for certificate recovery.
pub trait Recoverer: Send + 'static {
    /// Requests recovery for the registered scope. Dropping it unregisters the scope.
    type Fetcher: Fetcher;

    /// Registers `mailbox` as the only destination for responses to `namespace` and `epoch`.
    ///
    /// The scope stays registered until the returned fetcher is dropped. Registering a scope that
    /// is already registered fails rather than replacing the live destination.
    fn register(
        &self,
        namespace: RecoveryNamespace,
        epoch: Epoch,
        mailbox: Mailbox,
    ) -> Result<Self::Fetcher, RegistrationError>;
}

/// Requests and cancels certificate recovery for one registered scope.
pub trait Fetcher: Send + 'static {
    /// Requests the certificate at `position` if it is not already requested.
    ///
    /// [`Unreliable::Rejected`] means the request was not admitted. Callers may retry it.
    fn fetch(&mut self, position: Height) -> Unreliable<Feedback>;

    /// Cancels the admitted request for `position`.
    fn cancel(&mut self, position: Height) -> Feedback;
}

/// Reason a scope could not be registered.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    /// Another live registration owns the scope.
    #[error("aggregation recovery scope is already registered")]
    AlreadyRegistered,
    /// The recovery coordinator has stopped.
    #[error("aggregation recovery coordinator is closed")]
    Closed,
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

type Scope = (RecoveryNamespace, Epoch);

struct Route {
    // Identifies the registration that owns this route.
    owner: Arc<()>,
    mailbox: Mailbox,
}

#[derive(Default)]
struct State {
    // Tokens distinguish a cancellation followed by a new fetch of the same key.
    keys: BTreeMap<RecoveryKey, Arc<()>>,
    routes: BTreeMap<Scope, Route>,
    closed: bool,
}

impl State {
    fn close(&mut self) {
        self.keys.clear();
        self.routes.clear();
        self.closed = true;
    }
}

/// Cloneable handle to a node-wide aggregation recovery coordinator.
#[derive(Clone)]
pub struct Recovery {
    wake: mailbox::Sender<Wake>,
    state: Arc<Mutex<State>>,
    cap: usize,
}

impl Recoverer for Recovery {
    type Fetcher = Registration;

    fn register(
        &self,
        namespace: RecoveryNamespace,
        epoch: Epoch,
        mailbox: Mailbox,
    ) -> Result<Registration, RegistrationError> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(RegistrationError::Closed);
        }
        let scope = (namespace, epoch);
        if state.routes.contains_key(&scope) {
            return Err(RegistrationError::AlreadyRegistered);
        }
        let owner = Arc::new(());
        state.routes.insert(
            scope,
            Route {
                owner: owner.clone(),
                mailbox,
            },
        );
        Ok(Registration {
            recovery: self.clone(),
            scope,
            owner,
        })
    }
}

/// Recovery registration for one engine scope.
///
/// Responses for the scope reach its mailbox while this value lives. Dropping it removes the
/// route and cancels every request for the scope.
pub struct Registration {
    recovery: Recovery,
    scope: Scope,
    owner: Arc<()>,
}

impl Registration {
    const fn key(&self, position: Height) -> RecoveryKey {
        RecoveryKey {
            namespace: self.scope.0,
            epoch: self.scope.1,
            position,
        }
    }
}

impl Fetcher for Registration {
    fn fetch(&mut self, position: Height) -> Unreliable<Feedback> {
        let key = self.key(position);
        let mut state = self.recovery.state.lock();
        if state.closed {
            return Unreliable::new(Feedback::Closed);
        }
        if !state.keys.contains_key(&key) {
            if state.keys.len() >= self.recovery.cap {
                return Unreliable::rejected();
            }
            state.keys.insert(key, Arc::new(()));
        }
        let feedback = self.recovery.wake.enqueue(Wake);
        if feedback == Feedback::Closed {
            state.keys.remove(&key);
        }
        Unreliable::new(feedback)
    }

    fn cancel(&mut self, position: Height) -> Feedback {
        let key = self.key(position);
        let mut state = self.recovery.state.lock();
        if state.closed {
            return Feedback::Closed;
        }
        state.keys.remove(&key);
        self.recovery.wake.enqueue(Wake)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self.recovery.state.lock();
        if !state
            .routes
            .get(&self.scope)
            .is_some_and(|route| Arc::ptr_eq(&route.owner, &self.owner))
        {
            return;
        }
        state.routes.remove(&self.scope);
        let admitted = state.keys.len();
        let scope = self.scope;
        state
            .keys
            .retain(|key, _| (key.namespace, key.epoch) != scope);
        if state.keys.len() != admitted {
            // A closed coordinator has no resolver requests left to cancel.
            let _ = self.recovery.wake.enqueue(Wake);
        }
    }
}

/// Resolver consumer that routes each response to the engine registered for its key.
///
/// A response for a scope with no registration is [`CertificateOutcome::Ignored`]. Requests are
/// admitted only while their scope is registered, and unregistering cancels them.
#[derive(Clone)]
pub struct Consumer {
    // Holds no coordinator wake sender, so a resolver that owns this consumer does not keep the
    // coordinator that owns the resolver running.
    state: Arc<Mutex<State>>,
}

impl commonware_resolver::Consumer for Consumer {
    type Key = RecoveryKey;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = CertificateOutcome;

    fn deliver(
        &mut self,
        delivery: Delivery<RecoveryKey, ()>,
        value: Bytes,
    ) -> oneshot::Receiver<CertificateOutcome> {
        let key = delivery.key;
        let mailbox = self
            .state
            .lock()
            .routes
            .get(&(key.namespace, key.epoch))
            .map(|route| route.mailbox.clone());
        if let Some(mailbox) = mailbox {
            return mailbox.deliver(key, value);
        }
        let (sender, receiver) = oneshot::channel();
        sender.send_lossy(CertificateOutcome::Ignored);
        receiver
    }
}

// Closes every handle when the coordinator stops or is dropped before starting.
struct Closer(Arc<Mutex<State>>);

impl Drop for Closer {
    fn drop(&mut self) {
        self.0.lock().close();
    }
}

/// Actor that shares one logical outstanding recovery cap across engine scopes and routes their
/// responses.
///
/// The cap is applied synchronously to every admitted key, including work waiting for the actor.
/// Excess distinct fetches return [`Unreliable::Rejected`] without being retained and can be
/// retried. Actor wakeups are coalesced, so fetch and cancel churn cannot create unbounded mailbox
/// overflow.
///
/// The coordinator stops once every [`Recovery`] and [`Registration`] is dropped, and it drops
/// its resolver. A node that serves certificates through that resolver must retain a handle.
pub struct RecoveryCoordinator<E: Spawner + Metrics> {
    context: ContextCell<E>,
    receiver: mailbox::Receiver<Wake>,
    state: Closer,
}

impl<E: Spawner + Metrics> RecoveryCoordinator<E> {
    /// Creates a coordinator, its cloneable handle, and the resolver consumer that routes
    /// responses to registered engines.
    ///
    /// Engines may register and request recovery before [`Self::start`]. The outstanding limit
    /// bounds requests before and after the coordinator starts.
    pub fn new(
        context: E,
        outstanding: NonZeroUsize,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Recovery, Consumer) {
        let (wake, receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        let state = Arc::new(Mutex::new(State::default()));
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                state: Closer(state.clone()),
            },
            Recovery {
                wake,
                state: state.clone(),
                cap: outstanding.get(),
            },
            Consumer { state },
        )
    }

    /// Starts the coordinator with the resolver configured with its [`Consumer`].
    pub fn start<R>(self, resolver: R) -> Handle<()>
    where
        R: Resolver<Key = RecoveryKey, Subscriber = ()>,
    {
        let Self {
            context,
            receiver,
            state,
        } = self;
        let mut actor = Actor {
            context,
            resolver,
            receiver,
            state,
            active: BTreeMap::new(),
        };
        spawn_cell!(actor.context, actor.run())
    }
}

struct Actor<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    context: ContextCell<E>,
    resolver: R,
    receiver: mailbox::Receiver<Wake>,
    state: Closer,
    active: BTreeMap<RecoveryKey, Arc<()>>,
}

impl<E, R> Actor<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(_) = self.receiver.recv() else break => {
                if !self.reconcile() {
                    break;
                }
            },
        }
    }

    /// Returns `false` if the resolver is closed.
    fn reconcile(&mut self) -> bool {
        // Keep admission stable while stale requests are canceled and replacements are issued.
        // This preserves the cap across the resolver boundary, not only in the shared map.
        let state = self.state.0.lock();
        let canceled: Vec<_> = self
            .active
            .iter()
            .filter_map(|(key, token)| match state.keys.get(key) {
                Some(admitted) if Arc::ptr_eq(token, admitted) => None,
                _ => Some(*key),
            })
            .collect();
        if !canceled.is_empty() {
            let canceled = BTreeSet::from_iter(canceled);
            self.resolver.retain(move |key, ()| !canceled.contains(key));
            self.active.retain(|key, token| {
                state
                    .keys
                    .get(key)
                    .is_some_and(|admitted| Arc::ptr_eq(token, admitted))
            });
        }

        for (&key, token) in &state.keys {
            if self.active.contains_key(&key) {
                continue;
            }
            if !self.resolver.fetch(key).accepted() {
                return false;
            }
            self.active.insert(key, token.clone());
        }
        true
    }
}

impl<E, R> Drop for Actor<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    // Runs on normal exit and abort.
    fn drop(&mut self) {
        self.state.0.lock().close();
        if self.active.is_empty() {
            return;
        }
        let active = std::mem::take(&mut self.active);
        self.resolver
            .retain(move |key, ()| !active.contains_key(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::engine::Request;
    use commonware_actor::mailbox::UnreliableReceiver;
    use commonware_resolver::{Consumer as _, Fetch, Outcome};
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct MockResolver {
        state: Arc<Mutex<ResolverState>>,
        // Mirrors a network resolver, which owns the consumer that routes its responses.
        _consumer: Option<Consumer>,
    }

    #[derive(Default)]
    struct ResolverState {
        active: BTreeSet<RecoveryKey>,
        events: Vec<(bool, RecoveryKey)>,
        high_water: usize,
        closed: bool,
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
            if state.closed {
                return Feedback::Closed;
            }
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

    fn namespace() -> RecoveryNamespace {
        RecoveryNamespace::derive(b"coordinator-test")
    }

    fn key(epoch: u64, position: u64) -> RecoveryKey {
        RecoveryKey {
            namespace: namespace(),
            epoch: Epoch::new(epoch),
            position: Height::new(position),
        }
    }

    fn mailbox(
        context: &deterministic::Context,
        label: &'static str,
    ) -> (Mailbox, UnreliableReceiver<Request>) {
        Mailbox::new(context.child(label), NZUsize!(4))
    }

    fn register(
        context: &deterministic::Context,
        recovery: &Recovery,
        epoch: u64,
    ) -> (Registration, UnreliableReceiver<Request>) {
        let (mailbox, receiver) = mailbox(context, "mailbox");
        let registration = recovery
            .register(namespace(), Epoch::new(epoch), mailbox)
            .unwrap();
        (registration, receiver)
    }

    fn delivery(key: RecoveryKey) -> Delivery<RecoveryKey, ()> {
        Delivery {
            key,
            subscribers: commonware_utils::vec::NonEmptyVec::new(((), tracing::Span::none())),
        }
    }

    async fn wait_events(
        context: &deterministic::Context,
        state: &Arc<Mutex<ResolverState>>,
        count: usize,
    ) {
        while state.lock().events.len() < count {
            context.sleep(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn admission_bounds_keys_before_start_and_rejected_fetches_are_retriable() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(2), NZUsize!(1));
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            let position = Height::new;

            assert!(registration.fetch(position(0)).accepted());
            assert!(registration.fetch(position(0)).accepted());
            assert!(registration.fetch(position(1)).accepted());
            for raw in 2..100 {
                assert_eq!(registration.fetch(position(raw)), Unreliable::Rejected);
            }

            // Canceling one admitted key makes exactly one slot available before start.
            assert!(registration.cancel(position(0)).accepted());
            assert!(registration.fetch(position(2)).accepted());
            assert_eq!(registration.fetch(position(3)), Unreliable::Rejected);

            let handle = coordinator.start(resolver);
            wait_events(&context, &state, 2).await;
            {
                let state = state.lock();
                assert_eq!(state.high_water, 2);
                assert_eq!(state.active, BTreeSet::from([key(1, 1), key(1, 2)]));
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
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let handle = coordinator.start(resolver);
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            let position = Height::new(0);

            assert!(registration.fetch(position).accepted());
            assert!(registration.fetch(position).accepted());
            wait_events(&context, &state, 1).await;
            assert!(registration.cancel(position).accepted());
            assert!(registration.cancel(position).accepted());
            assert!(registration.fetch(position).accepted());
            wait_events(&context, &state, 3).await;

            assert_eq!(
                state.lock().events,
                vec![(true, key(1, 0)), (false, key(1, 0)), (true, key(1, 0))]
            );

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn pre_start_message_churn_has_bounded_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            let position = Height::new(0);

            // A one-element ready queue and one optional overflow wake remain bounded regardless
            // of churn. Only the final admitted state needs to be reconciled after start.
            for _ in 0..10_000 {
                registration.fetch(position);
                registration.cancel(position);
            }
            registration.fetch(position);

            let handle = coordinator.start(resolver);
            wait_events(&context, &state, 1).await;
            assert_eq!(state.lock().events, vec![(true, key(1, 0))]);

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn duplicate_scope_is_rejected_until_its_registration_drops() {
        deterministic::Runner::default().start(|context| async move {
            let (_coordinator, recovery, mut consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(4), NZUsize!(4));
            let (first, mut first_receiver) = register(&context, &recovery, 1);

            // A live registration is never replaced, and responses still reach it.
            let (duplicate, _) = mailbox(&context, "duplicate");
            assert_eq!(
                recovery
                    .register(namespace(), Epoch::new(1), duplicate)
                    .err(),
                Some(RegistrationError::AlreadyRegistered)
            );
            let (other, _other_receiver) = mailbox(&context, "other");
            let _other = recovery
                .register(namespace(), Epoch::new(2), other)
                .unwrap();
            let _verdict = consumer.deliver(delivery(key(1, 0)), Bytes::new());
            assert_eq!(first_receiver.try_recv().unwrap().key, key(1, 0));

            drop(first);
            let mut verdict = consumer.deliver(delivery(key(1, 0)), Bytes::new());
            assert_eq!(verdict.try_recv().unwrap(), CertificateOutcome::Ignored);
            let (successor, mut successor_receiver) = mailbox(&context, "successor");
            let _successor = recovery
                .register(namespace(), Epoch::new(1), successor)
                .unwrap();
            let _verdict = consumer.deliver(delivery(key(1, 0)), Bytes::new());
            assert_eq!(successor_receiver.try_recv().unwrap().key, key(1, 0));
        });
    }

    #[test]
    fn dropping_registration_cancels_only_its_scope() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(2), NZUsize!(4));
            let handle = coordinator.start(resolver);
            let (mut first, _first_receiver) = register(&context, &recovery, 1);
            let (mut second, _second_receiver) = register(&context, &recovery, 2);
            assert!(first.fetch(Height::new(0)).accepted());
            assert!(second.fetch(Height::new(0)).accepted());
            assert_eq!(second.fetch(Height::new(1)), Unreliable::Rejected);
            wait_events(&context, &state, 2).await;

            // Dropping the first registration frees its slot for another scope.
            drop(first);
            assert!(second.fetch(Height::new(1)).accepted());
            wait_events(&context, &state, 4).await;
            assert_eq!(state.lock().active, BTreeSet::from([key(2, 0), key(2, 1)]));

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn successor_refetch_cancels_predecessor_request_first() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, mut consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(4));
            let handle = coordinator.start(resolver);
            let requested = key(1, 0);
            let (mut predecessor, predecessor_receiver) = register(&context, &recovery, 1);
            assert!(predecessor.fetch(requested.position).accepted());
            wait_events(&context, &state, 1).await;

            // A response is in flight to the predecessor when it stops.
            let mut stale = consumer.deliver(delivery(requested), Bytes::new());
            drop(predecessor);
            drop(predecessor_receiver);
            assert!(stale.try_recv().is_err());

            // The successor requests the same key before the coordinator observes the drop.
            let (mut successor, mut successor_receiver) = register(&context, &recovery, 1);
            assert!(successor.fetch(requested.position).accepted());
            wait_events(&context, &state, 3).await;

            // The predecessor's request is retained away before the successor's is issued, so
            // a network resolver discards a stale verdict instead of retiring the new request.
            assert_eq!(
                state.lock().events,
                vec![(true, requested), (false, requested), (true, requested)]
            );
            let _verdict = consumer.deliver(delivery(requested), Bytes::new());
            assert_eq!(successor_receiver.try_recv().unwrap().key, requested);

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");
        });
    }

    #[test]
    fn coordinator_stops_while_resolver_owns_consumer() {
        deterministic::Runner::default().start(|context| async move {
            let (coordinator, recovery, consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(4));
            let resolver = MockResolver {
                _consumer: Some(consumer),
                ..MockResolver::default()
            };
            let state = resolver.state.clone();
            let handle = coordinator.start(resolver);
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            assert!(registration.fetch(Height::new(0)).accepted());
            wait_events(&context, &state, 1).await;

            drop(registration);
            drop(recovery);
            handle.await.expect("recovery coordinator failed");
            assert!(state.lock().active.is_empty());
        });
    }

    #[test]
    fn runtime_shutdown_cancels_active_requests_with_live_handle() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(4));
            let handle = coordinator.start(resolver);
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            assert!(registration.fetch(Height::new(0)).accepted());
            wait_events(&context, &state, 1).await;

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");

            let state = state.lock();
            assert!(state.active.is_empty());
            assert_eq!(state.events, vec![(true, key(1, 0)), (false, key(1, 0))]);
        });
    }

    #[test]
    fn live_handles_are_closed_after_coordinator_shutdown() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, mut consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            let handle = coordinator.start(resolver);

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");

            assert_eq!(
                registration.fetch(Height::new(0)),
                Unreliable::new(Feedback::Closed)
            );
            assert_eq!(registration.cancel(Height::new(0)), Feedback::Closed);
            let (mailbox, _) = mailbox(&context, "late");
            assert_eq!(
                recovery.register(namespace(), Epoch::new(2), mailbox).err(),
                Some(RegistrationError::Closed)
            );
            let mut verdict = consumer.deliver(delivery(key(1, 0)), Bytes::new());
            assert_eq!(verdict.try_recv().unwrap(), CertificateOutcome::Ignored);
            assert!(state.lock().events.is_empty());
        });
    }

    #[test]
    fn abort_cancels_active_requests_and_closes_handles() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(4));
            let handle = coordinator.start(resolver);
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            assert!(registration.fetch(Height::new(0)).accepted());
            wait_events(&context, &state, 1).await;

            handle.abort();
            assert!(handle.await.is_err());

            assert!(state.lock().active.is_empty());
            assert_eq!(
                registration.fetch(Height::new(1)),
                Unreliable::new(Feedback::Closed)
            );
        });
    }

    #[test]
    fn unstarted_drop_closes_handles() {
        deterministic::Runner::default().start(|context| async move {
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let (mut registration, _receiver) = register(&context, &recovery, 1);
            assert!(registration.fetch(Height::new(0)).accepted());

            drop(coordinator);

            assert_eq!(
                registration.fetch(Height::new(1)),
                Unreliable::new(Feedback::Closed)
            );
            assert_eq!(registration.cancel(Height::new(0)), Feedback::Closed);
        });
    }

    #[test]
    fn closed_resolver_closes_handles() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            resolver.state.lock().closed = true;
            let (coordinator, recovery, _consumer) =
                RecoveryCoordinator::new(context.child("coordinator"), NZUsize!(1), NZUsize!(1));
            let handle = coordinator.start(resolver);
            let (mut registration, _receiver) = register(&context, &recovery, 1);

            // The first admitted key reaches the closed resolver and stops the coordinator.
            assert!(registration.fetch(Height::new(0)).accepted());
            handle.await.expect("recovery coordinator failed");
            assert_eq!(
                registration.fetch(Height::new(1)),
                Unreliable::new(Feedback::Closed)
            );
        });
    }

    #[test]
    fn certificate_outcomes_map_to_resolver_outcomes() {
        assert_eq!(
            Outcome::from(CertificateOutcome::Accepted),
            Outcome::Complete
        );
        assert_eq!(Outcome::from(CertificateOutcome::Ignored), Outcome::Ignored);
        assert_eq!(Outcome::from(CertificateOutcome::Invalid), Outcome::Invalid);
        assert_eq!(
            Outcome::from(CertificateOutcome::Backpressured),
            Outcome::Ambiguous
        );
    }
}
