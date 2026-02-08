//! Shared service loop primitive for actors.

use crate::{
    mailbox::{Mailbox, UnboundedMailbox},
    Actor,
};
use commonware_macros::select;
use commonware_runtime::{signal::Signal, ContextCell, Handle, Spawner};
use commonware_utils::channel::mpsc;
use std::{
    collections::BTreeMap,
    fmt,
    pin::{pin, Pin},
    task::{Context, Poll},
};
use thiserror::Error;
use tracing::{debug, error};

const DEFAULT_SINGLE_LANE: usize = 0;
const DEFAULT_MAILBOX_CAPACITY: usize = 64;

/// Returned when the same lane key is configured more than once.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("duplicate lane configured")]
pub struct DuplicateLaneError;

type SingleLaneBuildOutput<E, A> = (<A as Actor<E>>::Mailbox, ActorService<E, A, usize>);

type MultiLaneBuildOutput<E, A, L> = (Lanes<L, <A as Actor<E>>::Mailbox>, ActorService<E, A, L>);

/// Per-lane mailboxes returned by [`MultiLaneServiceBuilder::build`].
pub struct Lanes<L, M>
where
    L: Ord,
{
    mailboxes: BTreeMap<L, M>,
}

impl<L, M> Clone for Lanes<L, M>
where
    L: Ord + Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            mailboxes: self.mailboxes.clone(),
        }
    }
}

impl<L, M> fmt::Debug for Lanes<L, M>
where
    L: Ord + fmt::Debug,
    M: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lanes")
            .field("mailboxes", &self.mailboxes)
            .finish()
    }
}

impl<L, M> Lanes<L, M>
where
    L: Ord,
{
    /// Returns the number of lanes.
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Returns `true` if there are no lanes.
    pub fn is_empty(&self) -> bool {
        self.mailboxes.is_empty()
    }
}

impl<L, M> Lanes<L, M>
where
    L: Ord,
    M: Clone,
{
    /// Returns the mailbox for `lane`.
    pub fn lane(&self, lane: &L) -> Option<M> {
        self.mailboxes.get(lane).cloned()
    }

    /// Consume and return all lane mailboxes.
    pub fn into_inner(self) -> BTreeMap<L, M> {
        self.mailboxes
    }
}

impl<L, M> IntoIterator for Lanes<L, M>
where
    L: Ord,
{
    type Item = (L, M);
    type IntoIter = std::collections::btree_map::IntoIter<L, M>;

    fn into_iter(self) -> Self::IntoIter {
        self.mailboxes.into_iter()
    }
}

/// Configures an actor service loop before lane type is selected.
///
/// Polling is biased and deterministic:
/// - shutdown is always checked first
/// - lane polling is declaration-order biased
/// - the actor-defined [`Actor::on_external`] future is polled after lanes
///
/// **Note:** Under sustained load, earlier lanes can starve later lanes
/// because the first ready lane is always selected.
///
/// # Behavioral Semantics
///
/// - At most one event is dispatched per iteration.
/// - Returning `Err` from [`Actor::on_ingress`] logs the error and exits
///   the loop **without** calling [`Actor::on_shutdown`].
/// - A lane closing (`None`) or [`Actor::on_external`] returning `None`
///   triggers [`Actor::on_shutdown`] before exiting.
///
/// For single-lane actors with mailbox ergonomics, use
/// [`ServiceBuilder::build`] or [`ServiceBuilder::build_with_capacity`].
///
/// Adding the first lane transitions this typestate to [`MultiLaneServiceBuilder`].
pub struct ServiceBuilder<A> {
    actor: A,
}

impl<A> ServiceBuilder<A> {
    /// Create a new service builder for `actor`.
    pub const fn new(actor: A) -> Self {
        Self { actor }
    }

    /// Add a bounded lane, transitioning to a [`MultiLaneServiceBuilder`].
    pub fn with_lane<L>(self, lane: L, capacity: usize) -> MultiLaneServiceBuilder<A, L>
    where
        L: Copy + Ord + Send + 'static,
    {
        MultiLaneServiceBuilder {
            actor: self.actor,
            lanes: vec![(lane, capacity)],
        }
    }

    /// Add an unbounded lane, transitioning to a [`MultiLaneUnboundedServiceBuilder`].
    pub fn with_unbounded_lane<L>(self, lane: L) -> MultiLaneUnboundedServiceBuilder<A, L>
    where
        L: Copy + Ord + Send + 'static,
    {
        MultiLaneUnboundedServiceBuilder {
            actor: self.actor,
            lanes: vec![lane],
        }
    }

    /// Build a single-lane service with the default mailbox capacity of 64.
    ///
    /// This is a convenience for simple actors that only need one lane.
    pub fn build<E>(self, context: E) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        self.build_with_capacity(context, DEFAULT_MAILBOX_CAPACITY)
    }

    /// Build a single-lane service with an unbounded mailbox.
    ///
    /// This is a convenience for actors whose callers must never block on enqueue
    /// (e.g., when messages are sent from `Drop` implementations).
    pub fn build_unbounded<E>(self, context: E) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<UnboundedMailbox<A::Ingress>>,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let mailbox = A::Mailbox::from(UnboundedMailbox::new(tx));
        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,

            lanes: vec![LaneReceiver {
                _lane: DEFAULT_SINGLE_LANE,
                receiver: LaneReceiverKind::Unbounded(rx),
            }],
            shutdown,
        };

        (mailbox, service)
    }

    /// Build a single-lane service with the provided mailbox capacity.
    pub fn build_with_capacity<E>(self, context: E, capacity: usize) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        let (tx, rx) = mpsc::channel(capacity);
        let mailbox = A::Mailbox::from(Mailbox::new(tx));
        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,

            lanes: vec![LaneReceiver {
                _lane: DEFAULT_SINGLE_LANE,
                receiver: LaneReceiverKind::Bounded(rx),
            }],
            shutdown,
        };

        (mailbox, service)
    }
}

/// Configures a multi-lane actor service loop with bounded lanes.
pub struct MultiLaneServiceBuilder<A, L>
where
    L: Copy + Ord + Send + 'static,
{
    actor: A,
    lanes: Vec<(L, usize)>,
}

impl<A, L> MultiLaneServiceBuilder<A, L>
where
    L: Copy + Ord + Send + 'static,
{
    /// Add another bounded lane.
    pub fn with_lane(mut self, lane: L, capacity: usize) -> Self {
        self.lanes.push((lane, capacity));
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added
    /// more than once.
    pub fn build<E>(self, context: E) -> Result<MultiLaneBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        let mut seen = std::collections::BTreeSet::new();
        for (lane, _) in &self.lanes {
            if !seen.insert(lane) {
                return Err(DuplicateLaneError);
            }
        }

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for (lane, capacity) in self.lanes {
            let (tx, rx) = mpsc::channel(capacity);
            mailboxes.insert(lane, A::Mailbox::from(Mailbox::new(tx)));
            receivers.push(LaneReceiver {
                _lane: lane,
                receiver: LaneReceiverKind::Bounded(rx),
            });
        }

        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,

            lanes: receivers,
            shutdown,
        };

        Ok((Lanes { mailboxes }, service))
    }
}

/// Configures a multi-lane actor service loop with unbounded lanes.
pub struct MultiLaneUnboundedServiceBuilder<A, L>
where
    L: Copy + Ord + Send + 'static,
{
    actor: A,
    lanes: Vec<L>,
}

impl<A, L> MultiLaneUnboundedServiceBuilder<A, L>
where
    L: Copy + Ord + Send + 'static,
{
    /// Add another unbounded lane.
    pub fn with_unbounded_lane(mut self, lane: L) -> Self {
        self.lanes.push(lane);
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added
    /// more than once.
    pub fn build<E>(self, context: E) -> Result<MultiLaneBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<UnboundedMailbox<A::Ingress>>,
    {
        let mut seen = std::collections::BTreeSet::new();
        for lane in &self.lanes {
            if !seen.insert(lane) {
                return Err(DuplicateLaneError);
            }
        }

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for lane in self.lanes {
            let (tx, rx) = mpsc::unbounded_channel();
            mailboxes.insert(lane, A::Mailbox::from(UnboundedMailbox::new(tx)));
            receivers.push(LaneReceiver {
                _lane: lane,
                receiver: LaneReceiverKind::Unbounded(rx),
            });
        }

        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,

            lanes: receivers,
            shutdown,
        };

        Ok((Lanes { mailboxes }, service))
    }
}

/// Receive half of a single lane.
///
/// Used by `poll_lanes` to iterate lanes in declaration order.
struct LaneReceiver<L, I> {
    _lane: L,
    receiver: LaneReceiverKind<I>,
}

/// Receive half of a lane channel, either bounded or unbounded.
enum LaneReceiverKind<I> {
    Bounded(mpsc::Receiver<I>),
    Unbounded(mpsc::UnboundedReceiver<I>),
}

impl<L, I> LaneReceiver<L, I> {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>> {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => Pin::new(rx).poll_recv(cx),
            LaneReceiverKind::Unbounded(rx) => Pin::new(rx).poll_recv(cx),
        }
    }
}

/// Framework-managed actor loop used by [`ServiceBuilder`].
pub struct ActorService<E, A, L>
where
    E: Spawner,
    A: Actor<E>,
    L: Copy + Ord + Send + 'static,
{
    context: ContextCell<E>,
    actor: A,
    lanes: Vec<LaneReceiver<L, A::Ingress>>,
    shutdown: Signal,
}

impl<E, A, L> ActorService<E, A, L>
where
    E: Spawner,
    A: Actor<E>,
    L: Copy + Ord + Send + 'static,
{
    /// Spawn the control loop, passing `init` data to [`Actor::on_startup`].
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start_with(mut self, init: A::Init) -> Handle<()> {
        let context = self.context.take();
        context.spawn(move |context| async move {
            self.context.restore(context);
            self.enter(init).await
        })
    }

    async fn enter(mut self, mut init: A::Init) {
        debug!(lanes = self.lanes.len(), "actor service started");
        self.actor
            .on_startup(self.context.as_present_mut(), &mut init)
            .await;

        loop {
            self.actor
                .preprocess(self.context.as_present_mut(), &mut init)
                .await;

            let event = {
                let mut external = pin!(self
                    .actor
                    .on_external(self.context.as_present_mut(), &mut init));
                recv_event(&mut self.shutdown, &mut self.lanes, external.as_mut()).await
            };

            match event {
                LoopEvent::Shutdown => {
                    debug!("shutdown signal received");
                    self.actor
                        .on_shutdown(self.context.as_present_mut(), &mut init)
                        .await;
                    debug!("actor service stopped");
                    return;
                }
                LoopEvent::Mailbox(message) | LoopEvent::External(message) => match message {
                    Some(message) => {
                        if let Err(err) = self
                            .actor
                            .on_ingress(self.context.as_present_mut(), &mut init, message)
                            .await
                        {
                            error!(%err, "actor failed");
                            return;
                        }
                    }
                    None => {
                        debug!("ingress source closed, shutting down actor");
                        self.actor
                            .on_shutdown(self.context.as_present_mut(), &mut init)
                            .await;
                        debug!("actor service stopped");
                        return;
                    }
                },
            };

            self.actor
                .postprocess(self.context.as_present_mut(), &mut init)
                .await;
        }
    }
}

impl<E, A, L> ActorService<E, A, L>
where
    E: Spawner,
    A: Actor<E, Init = ()>,
    L: Copy + Ord + Send + 'static,
{
    /// Spawn the control loop for actors whose [`Actor::Init`] is `()`.
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start(self) -> Handle<()> {
        self.start_with(())
    }
}

/// Poll all lanes in declaration order, returning the first ready message.
///
/// Returns `Ready(None)` if any lane is closed. Returns `Pending` when
/// no lane is ready or `lanes` is empty.
fn poll_lanes<L, I>(lanes: &mut [LaneReceiver<L, I>], cx: &mut Context<'_>) -> Poll<Option<I>>
where
    L: Copy + Send + 'static,
    I: Send + 'static,
{
    if lanes.is_empty() {
        return Poll::Pending;
    }

    for lane in lanes.iter_mut() {
        match lane.poll_recv(cx) {
            Poll::Ready(Some(message)) => {
                return Poll::Ready(Some(message));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }
    }

    Poll::Pending
}

/// Await the next event for the actor loop using biased `select!`.
///
/// Priority order: shutdown signal, lane messages, then the actor-defined
/// external future. At most one event is returned per call.
async fn recv_event<'a, L, I, F>(
    shutdown: &'a mut Signal,
    lanes: &'a mut [LaneReceiver<L, I>],
    mut external: Pin<&'a mut F>,
) -> LoopEvent<I>
where
    L: Copy + Send + 'static,
    I: Send + 'static,
    F: std::future::Future<Output = Option<I>> + Send,
{
    let mut lane_recv = pin!(futures::future::poll_fn(|cx: &mut Context<'_>| {
        poll_lanes(lanes, cx)
    }));

    select! {
        _ = &mut *shutdown => {
            LoopEvent::Shutdown
        },
        message = &mut lane_recv => {
            LoopEvent::Mailbox(message)
        },
        message = &mut external => {
            LoopEvent::External(message)
        },
    }
}

/// Events that drive the actor control loop.
enum LoopEvent<I>
where
    I: Send + 'static,
{
    /// Runtime shutdown signal observed.
    Shutdown,
    /// A message received from the actor's mailbox. `None` indicates at least one lane closed.
    Mailbox(Option<I>),
    /// A message received from the actor-defined external future.
    External(Option<I>),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ingress;
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::channel::{fallible::OneshotExt, mpsc};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    struct ExternalActor {
        n: u64,
    }

    ingress! {
        ExternalMailbox,

        pub tell TellMsg { n: u64 };
        pub ask AskMsg -> u64;
    }

    impl<E: Spawner + Clock> Actor<E> for ExternalActor {
        type Mailbox = ExternalMailbox;
        type Ingress = ExternalMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = mpsc::Receiver<u64>;

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                ExternalMailboxMessage::TellMsg { n } => {
                    self.n = n;
                }
                ExternalMailboxMessage::AskMsg { response } => {
                    response.send_lossy(self.n);
                }
            }
            Ok(())
        }

        async fn on_external(
            &mut self,
            context: &mut E,
            init: &mut Self::Init,
        ) -> Option<Self::Ingress> {
            select! {
                _ = context.sleep(Duration::from_secs(1)) => {
                    None
                },
                n = init.recv() => {
                    n.map(|n| ExternalMailboxMessage::TellMsg { n })
                },
            }
        }
    }

    #[test]
    fn test_actor_on_external() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = ExternalActor { n: 0 };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("actor_on_external"));

            // Start the actor with an external channel.
            let (other_tx, other_rx) = mpsc::channel(8);
            service.start_with(other_rx);

            mailbox.tell_msg(42).await.expect("tell failed");
            context.sleep(Duration::from_millis(5)).await;
            assert_eq!(mailbox.ask_msg().await.expect("ask failed"), 42);

            other_tx.send(100).await.expect("send failed");
            context.sleep(Duration::from_millis(5)).await;
            assert_eq!(mailbox.ask_msg().await.expect("ask failed"), 100);

            context.sleep(Duration::from_secs(2)).await;
            assert!(mailbox.ask_msg().await.is_err());
        });
    }

    struct CounterActor {
        counter: u64,
        started: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    }

    ingress! {
        CounterMailbox,

        pub tell Increment;
        pub ask GetCounter -> u64;
    }

    impl<E: Spawner> Actor<E> for CounterActor {
        type Mailbox = CounterMailbox;
        type Ingress = CounterMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn on_startup(&mut self, _context: &mut E, _init: &mut Self::Init) {
            self.started.store(true, Ordering::SeqCst);
        }

        async fn on_shutdown(&mut self, _context: &mut E, _init: &mut Self::Init) {
            self.shutdown.store(true, Ordering::SeqCst);
        }

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                CounterMailboxMessage::Increment => {}
                CounterMailboxMessage::GetCounter { response } => {
                    response.send_lossy(self.counter);
                }
            }
            Ok(())
        }

        async fn postprocess(&mut self, _context: &mut E, _init: &mut Self::Init) {
            self.counter += 1;
        }
    }

    #[test]
    fn test_counter_actor_lifecycle() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let started = Arc::new(AtomicBool::new(false));
            let shutdown = Arc::new(AtomicBool::new(false));

            let actor = CounterActor {
                counter: 0,
                started: started.clone(),
                shutdown: shutdown.clone(),
            };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("counter"));
            let handle = service.start();

            // Send 3 increments; postprocess increments counter after each message.
            mailbox.increment().await.expect("tell failed");
            mailbox.increment().await.expect("tell failed");
            mailbox.increment().await.expect("tell failed");

            // The ask round-trips through the actor, so on_startup has
            // definitely completed by the time we get the response.
            let val = mailbox.get_counter().await.expect("ask failed");
            assert_eq!(val, 3);
            assert!(started.load(Ordering::SeqCst));

            // Drop mailbox to close the lane; actor should call on_shutdown
            drop(mailbox);
            let _ = handle.await;
            assert!(shutdown.load(Ordering::SeqCst));
        });
    }

    struct PreprocessActor {
        preprocess_count: u64,
    }

    ingress! {
        PreprocessMailbox,

        pub tell Bump;
        pub ask GetPreprocessCount -> u64;
    }

    impl<E: Spawner> Actor<E> for PreprocessActor {
        type Mailbox = PreprocessMailbox;
        type Ingress = PreprocessMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn preprocess(&mut self, _context: &mut E, _init: &mut Self::Init) {
            self.preprocess_count += 1;
        }

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                PreprocessMailboxMessage::Bump => {}
                PreprocessMailboxMessage::GetPreprocessCount { response } => {
                    response.send_lossy(self.preprocess_count);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_preprocess_runs_each_iteration() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = PreprocessActor {
                preprocess_count: 0,
            };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("preprocess"));
            service.start();

            // Send 3 bumps; each triggers one loop iteration with preprocess.
            mailbox.bump().await.expect("tell failed");
            mailbox.bump().await.expect("tell failed");
            mailbox.bump().await.expect("tell failed");

            // The ask itself is a 4th iteration.
            let count = mailbox.get_preprocess_count().await.expect("ask failed");
            assert_eq!(count, 4);
        });
    }

    struct StopOnCommandActor {
        shutdown_called: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct PoisonError;

    impl std::fmt::Display for PoisonError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "poisoned")
        }
    }

    ingress! {
        StopMailbox,

        pub tell Normal;
        pub tell Poison;
        pub ask IsAlive -> bool;
    }

    impl<E: Spawner> Actor<E> for StopOnCommandActor {
        type Mailbox = StopMailbox;
        type Ingress = StopMailboxMessage;
        type Error = PoisonError;
        type Init = ();

        async fn on_shutdown(&mut self, _context: &mut E, _init: &mut Self::Init) {
            self.shutdown_called.store(true, Ordering::SeqCst);
        }

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                StopMailboxMessage::Normal => Ok(()),
                StopMailboxMessage::Poison => Err(PoisonError),
                StopMailboxMessage::IsAlive { response } => {
                    response.send_lossy(true);
                    Ok(())
                }
            }
        }
    }

    #[test]
    fn test_stop_on_error() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let shutdown_called = Arc::new(AtomicBool::new(false));
            let actor = StopOnCommandActor {
                shutdown_called: shutdown_called.clone(),
            };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("stop_on_cmd"));
            let handle = service.start();

            // Normal message works
            mailbox.normal().await.expect("tell failed");
            context.sleep(Duration::from_millis(1)).await;
            assert!(mailbox.is_alive().await.expect("ask failed"));

            // Poison message causes fatal exit
            mailbox.poison().await.expect("tell failed");
            let _ = handle.await;

            // on_shutdown must NOT have been called
            assert!(!shutdown_called.load(Ordering::SeqCst));
        });
    }

    struct UnboundedActor {
        sum: u64,
    }

    ingress! {
        unbounded UnboundedActorMailbox,

        pub tell AddVal { n: u64 };
        pub ask GetSum -> u64;
    }

    impl<E: Spawner> Actor<E> for UnboundedActor {
        type Mailbox = UnboundedActorMailbox;
        type Ingress = UnboundedActorMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                UnboundedActorMailboxMessage::AddVal { n } => {
                    self.sum += n;
                }
                UnboundedActorMailboxMessage::GetSum { response } => {
                    response.send_lossy(self.sum);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_unbounded_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = UnboundedActor { sum: 0 };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build_unbounded(context.with_label("unbounded"));
            service.start();

            // Sync tells (unbounded)
            mailbox.add_val(10).expect("tell failed");
            mailbox.add_val(20).expect("tell failed");
            mailbox.add_val(30).expect("tell failed");

            // Let them process
            context.sleep(Duration::from_millis(1)).await;
            let total = mailbox.get_sum().await.expect("ask failed");
            assert_eq!(total, 60);
        });
    }

    struct MultiLaneActor {
        log: Vec<&'static str>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Lane {
        Priority,
        Normal,
    }

    ingress! {
        MultiLaneMailbox,

        pub tell TagPriority;
        pub tell TagNormal;
        pub ask ReadLog -> Vec<&'static str>;
    }

    impl<E: Spawner> Actor<E> for MultiLaneActor {
        type Mailbox = MultiLaneMailbox;
        type Ingress = MultiLaneMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                MultiLaneMailboxMessage::TagPriority => self.log.push("priority"),
                MultiLaneMailboxMessage::TagNormal => self.log.push("normal"),
                MultiLaneMailboxMessage::ReadLog { response } => {
                    response.send_lossy(self.log.clone());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_multi_lane_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = MultiLaneActor { log: Vec::new() };

            // Priority lane declared first -- gets poll bias.
            let (lanes, service) = ServiceBuilder::new(actor)
                .with_lane(Lane::Priority, 8)
                .with_lane(Lane::Normal, 8)
                .build(context.with_label("multi_lane"))
                .expect("build failed");
            service.start();

            let mut priority = lanes.lane(&Lane::Priority).expect("missing priority lane");
            let mut normal = lanes.lane(&Lane::Normal).expect("missing normal lane");

            // Send to both lanes before actor can process.
            // Normal is sent first, but Priority lane has higher poll bias.
            normal.tag_normal().await.expect("tell normal failed");
            priority.tag_priority().await.expect("tell priority failed");

            // Let both process (each iteration handles one message)
            context.sleep(Duration::from_millis(5)).await;

            // Ask via the priority lane for the log
            let log = priority.read_log().await.expect("ask failed");

            // Priority lane is polled first due to declaration order
            assert_eq!(log, vec!["priority", "normal"]);
        });
    }

    #[test]
    fn test_duplicate_lane_error() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = MultiLaneActor { log: Vec::new() };
            let result = ServiceBuilder::new(actor)
                .with_lane(0u8, 8)
                .with_lane(0u8, 16)
                .build(context.with_label("dup_lane"));

            assert!(result.is_err());
        });
    }

    #[test]
    fn test_lane_closed_triggers_shutdown() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let shutdown_called = Arc::new(AtomicBool::new(false));
            let actor = StopOnCommandActor {
                shutdown_called: shutdown_called.clone(),
            };
            let (mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("lane_closed"));
            let handle = service.start();

            // Drop the only sender -- lane should close
            drop(mailbox);
            let _ = handle.await;

            // on_shutdown SHOULD have been called (lane closure, not error)
            assert!(shutdown_called.load(Ordering::SeqCst));
        });
    }

    // Exercises M1 (unit tell/ask with generic mailbox) and M2 (ask response
    // type referencing a generic not present in fields).
    trait Peer: Send + Clone + 'static {}
    impl Peer for String {}

    struct GenericActor<P: Peer> {
        peer: Option<P>,
    }

    ingress! {
        GenericMailbox<P: Peer>,

        // Unit tell with mailbox generic
        pub tell Ping;
        // Non-unit tell using generic in field
        pub tell Connect { peer: P };
        // Unit ask whose response type uses generic, but fields don't
        pub ask GetPeer -> Option<P>;
        // Non-unit ask whose response uses generic, fields don't
        pub ask GetPeerById { id: u64 } -> Option<P>;
        // Unit ask with mailbox generic, response doesn't use it
        pub ask IsConnected -> bool;
    }

    impl<E: Spawner, P: Peer> Actor<E> for GenericActor<P> {
        type Mailbox = GenericMailbox<P>;
        type Ingress = GenericMailboxMessage<P>;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                GenericMailboxMessage::Ping => {}
                GenericMailboxMessage::Connect { peer } => {
                    self.peer = Some(peer);
                }
                GenericMailboxMessage::GetPeer { response } => {
                    response.send_lossy(self.peer.clone());
                }
                GenericMailboxMessage::GetPeerById { id: _, response } => {
                    response.send_lossy(self.peer.clone());
                }
                GenericMailboxMessage::IsConnected { response } => {
                    response.send_lossy(self.peer.is_some());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_generic_mailbox_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor: GenericActor<String> = GenericActor { peer: None };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("generic"));
            service.start();

            // M1: unit tell with generic mailbox
            mailbox.ping().await.expect("ping failed");
            context.sleep(Duration::from_millis(1)).await;

            // Unit ask with generic mailbox
            assert!(!mailbox.is_connected().await.expect("ask failed"));

            // Non-unit tell using generic field
            mailbox
                .connect("alice".to_string())
                .await
                .expect("connect failed");
            context.sleep(Duration::from_millis(1)).await;

            // M2: ask with response type referencing generic
            let peer = mailbox.get_peer().await.expect("ask failed");
            assert_eq!(peer, Some("alice".to_string()));
        });
    }

    // Exercises the `subscribe` item kind: the generated method returns a
    // `oneshot::Receiver` without waiting for the actor to respond.
    struct SubscribeActor {
        pending: Option<commonware_utils::channel::oneshot::Sender<String>>,
    }

    ingress! {
        SubscribeMailbox,

        pub subscribe WaitForValue -> String;
        pub tell Resolve { value: String };
    }

    impl<E: Spawner> Actor<E> for SubscribeActor {
        type Mailbox = SubscribeMailbox;
        type Ingress = SubscribeMailboxMessage;
        type Error = std::convert::Infallible;
        type Init = ();

        async fn on_ingress(
            &mut self,
            _context: &mut E,
            _init: &mut Self::Init,
            message: Self::Ingress,
        ) -> Result<(), Self::Error> {
            match message {
                SubscribeMailboxMessage::WaitForValue { response } => {
                    self.pending = Some(response);
                }
                SubscribeMailboxMessage::Resolve { value } => {
                    if let Some(tx) = self.pending.take() {
                        tx.send_lossy(value);
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_subscribe_returns_receiver() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = SubscribeActor { pending: None };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("subscribe"));
            service.start();

            // subscribe returns a receiver immediately
            let rx = mailbox.wait_for_value().await;

            // Send the value that the actor will forward to the pending
            // subscriber
            mailbox
                .resolve("hello".to_string())
                .await
                .expect("resolve failed");

            // Now await the receiver
            let val = rx.await.expect("subscribe receiver failed");
            assert_eq!(val, "hello");
        });
    }

    // Exercises try_tell and ask_timeout generated methods (A1, A2).
    #[test]
    fn test_try_tell_and_ask_timeout() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor {
                counter: 0,
                started: Arc::new(AtomicBool::new(false)),
                shutdown: Arc::new(AtomicBool::new(false)),
            };
            let (mut mailbox, service) =
                ServiceBuilder::new(actor).build(context.with_label("try_ask"));
            service.start();

            // try_tell (non-blocking enqueue)
            mailbox.try_increment().expect("try_tell failed");
            context.sleep(Duration::from_millis(1)).await;
            let val = mailbox.get_counter().await.expect("ask failed");
            assert_eq!(val, 1);

            // ask_timeout with a generous deadline
            let val = mailbox
                .get_counter_timeout(context.sleep(Duration::from_secs(5)))
                .await
                .expect("ask_timeout failed");
            assert_eq!(val, 2); // postprocess increments again

            // ask_timeout that times out immediately
            // Send increment to fill the ask pipeline, then ask with
            // an already-resolved timeout.
            let err = mailbox
                .get_counter_timeout(futures::future::ready(()))
                .await
                .unwrap_err();
            assert_eq!(err, crate::mailbox::MailboxError::Timeout);
        });
    }
}
