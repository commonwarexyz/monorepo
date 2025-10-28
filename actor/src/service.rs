//! Shared service loop primitive for actors.

use crate::{
    mailbox::{Mailbox, UnboundedMailbox},
    source::{NoSources, SourceSet},
    Actor,
};
use commonware_runtime::{signal::Signal, ContextCell, Handle, Spawner};
use commonware_utils::channel::mpsc;
use std::{
    collections::BTreeMap,
    future::Future,
    marker::PhantomData,
    ops::ControlFlow,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tracing::debug;

const DEFAULT_SINGLE_LANE: usize = 0;
const DEFAULT_MAILBOX_CAPACITY: usize = 64;

/// Errors returned when building an [`ActorService`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceBuildError {
    /// The same lane key was configured more than once.
    #[error("duplicate lane configured")]
    DuplicateLaneConfigured,
}

type SingleLaneBuildOutput<E, A, S> = (
    Mailbox<<A as Actor<ContextCell<E>>>::Ingress>,
    ActorService<E, A, usize, S>,
);

type SingleUnboundedLaneBuildOutput<E, A, S> = (
    UnboundedMailbox<<A as Actor<ContextCell<E>>>::Ingress>,
    ActorService<E, A, usize, S>,
);

type MultiLaneBuildOutput<E, A, L, S> = (
    Lanes<L, <A as Actor<ContextCell<E>>>::Ingress>,
    ActorService<E, A, L, S>,
);

/// Mailboxes for a set of configured lanes.
///
/// Returned by [`MultiLaneServiceBuilder::build`] for lane-specific caller handles.
pub struct Lanes<L, I>
where
    L: Ord,
{
    bounded_mailboxes: BTreeMap<L, Mailbox<I>>,
    unbounded_mailboxes: BTreeMap<L, UnboundedMailbox<I>>,
}

impl<L, I> Lanes<L, I>
where
    L: Ord,
{
    /// Returns the mailbox for `lane`.
    pub fn lane(&self, lane: &L) -> Option<Mailbox<I>> {
        self.bounded_mailboxes.get(lane).cloned()
    }

    /// Returns the unbounded mailbox for `lane`.
    pub fn unbounded_lane(&self, lane: &L) -> Option<UnboundedMailbox<I>> {
        self.unbounded_mailboxes.get(lane).cloned()
    }

    /// Consume and return bounded lane mailboxes.
    pub fn into_inner(self) -> BTreeMap<L, Mailbox<I>> {
        self.bounded_mailboxes
    }

    /// Consume and return unbounded lane mailboxes.
    pub fn into_unbounded_inner(self) -> BTreeMap<L, UnboundedMailbox<I>> {
        self.unbounded_mailboxes
    }

    /// Consume and return both bounded and unbounded lane mailboxes.
    pub fn into_parts(self) -> (BTreeMap<L, Mailbox<I>>, BTreeMap<L, UnboundedMailbox<I>>) {
        (self.bounded_mailboxes, self.unbounded_mailboxes)
    }
}

#[derive(Clone, Copy)]
enum LaneCapacity {
    Bounded(usize),
    Unbounded,
}

/// Configures an actor service loop before lane type is selected.
///
/// Polling is biased and deterministic:
/// - shutdown is always checked first
/// - lane/source branch order is set by first call order of `with_lane` and `with_sources`
/// - lane and source internals each use declaration-order polling
///
/// # Behavioral Semantics
///
/// - At most one event is dispatched per iteration.
/// - Returning [`ControlFlow::Break`] exits the loop.
/// - If `drain_on_shutdown` is enabled, queued lane messages are drained on shutdown.
///
/// For single-lane actors with mailbox ergonomics, use
/// [`ServiceBuilder::build`] or [`ServiceBuilder::build_with_capacity`].
///
/// Adding the first lane transitions this typestate to [`MultiLaneServiceBuilder`].
pub struct ServiceBuilder<E, A, S = NoSources>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
{
    actor: A,
    poll_order: Vec<PollTarget>,
    sources: S,
    drain_on_shutdown: bool,
    _marker: PhantomData<E>,
}

/// Configures a multi-lane actor service loop after lane type selection.
pub struct MultiLaneServiceBuilder<E, A, L, S = NoSources>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
    L: Copy + Ord + Send + 'static,
{
    actor: A,
    lanes: Vec<(L, LaneCapacity)>,
    poll_order: Vec<PollTarget>,
    sources: S,
    drain_on_shutdown: bool,
    _marker: PhantomData<E>,
}

impl<E, A> ServiceBuilder<E, A, NoSources>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
{
    /// Create a new service builder for `actor`.
    pub const fn new(actor: A) -> Self {
        Self {
            actor,
            poll_order: Vec::new(),
            sources: NoSources,
            drain_on_shutdown: true,
            _marker: PhantomData,
        }
    }
}

impl<E, A, S> ServiceBuilder<E, A, S>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
    S: Send + 'static,
{
    /// Replace the source set used by the driver.
    ///
    /// Polling is builder-order biased. The first call to this method places source polling
    /// relative to lane polling.
    ///
    /// Sources can be composed statically with [`sources!`](crate::sources!). Source polling
    /// within a composed set is declaration-order biased.
    ///
    /// See [`crate::source::Source`] and [`crate::source::poll_fn`] for custom source guidance.
    pub fn with_sources<S2>(self, sources: S2) -> ServiceBuilder<E, A, S2>
    where
        S2: Send + 'static,
    {
        let mut poll_order = self.poll_order;
        if !poll_order.contains(&PollTarget::Sources) {
            poll_order.push(PollTarget::Sources);
        }

        ServiceBuilder {
            actor: self.actor,
            poll_order,
            sources,
            drain_on_shutdown: self.drain_on_shutdown,
            _marker: self._marker,
        }
    }

    /// Add a lane with a bounded capacity.
    ///
    /// Polling is builder-order biased. The first call to this method places lane polling
    /// relative to source polling.
    pub fn with_lane<L>(self, lane: L, capacity: usize) -> MultiLaneServiceBuilder<E, A, L, S>
    where
        L: Copy + Ord + Send + 'static,
    {
        self.with_capacity_lane(lane, LaneCapacity::Bounded(capacity))
    }

    /// Add an unbounded lane.
    ///
    /// Polling is builder-order biased. The first call to this method places lane polling
    /// relative to source polling.
    pub fn with_unbounded_lane<L>(self, lane: L) -> MultiLaneServiceBuilder<E, A, L, S>
    where
        L: Copy + Ord + Send + 'static,
    {
        self.with_capacity_lane(lane, LaneCapacity::Unbounded)
    }

    fn with_capacity_lane<L>(
        mut self,
        lane: L,
        capacity: LaneCapacity,
    ) -> MultiLaneServiceBuilder<E, A, L, S>
    where
        L: Copy + Ord + Send + 'static,
    {
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }
        MultiLaneServiceBuilder {
            actor: self.actor,
            lanes: vec![(lane, capacity)],
            poll_order: self.poll_order,
            sources: self.sources,
            drain_on_shutdown: self.drain_on_shutdown,
            _marker: self._marker,
        }
    }

    /// Configure whether the control loop drains outstanding messages once shutdown begins.
    pub const fn with_drain_on_shutdown(mut self, drain: bool) -> Self {
        self.drain_on_shutdown = drain;
        self
    }

    /// Build a single-lane service with default mailbox capacity.
    ///
    /// This is a convenience for simple actors that only need one lane.
    pub fn build(self, context: E) -> SingleLaneBuildOutput<E, A, S>
    where
        S: SourceSet<ContextCell<E>, A, A::Ingress>,
    {
        self.build_with_capacity(context, DEFAULT_MAILBOX_CAPACITY)
    }

    /// Build a single-lane service with an unbounded mailbox.
    ///
    /// This is a convenience for actors whose callers must never block on enqueue
    /// (e.g., when messages are sent from `Drop` implementations).
    pub fn build_unbounded(mut self, context: E) -> SingleUnboundedLaneBuildOutput<E, A, S>
    where
        S: SourceSet<ContextCell<E>, A, A::Ingress>,
    {
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let mailbox = UnboundedMailbox::new(tx);
        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,
            init: None,
            lanes: vec![LaneReceiver {
                lane: DEFAULT_SINGLE_LANE,
                receiver: LaneReceiverKind::Unbounded(rx),
                closed: false,
            }],
            poll_order: self.poll_order,
            sources: self.sources,
            drain_on_shutdown: self.drain_on_shutdown,
            shutdown,
        };

        (mailbox, service)
    }

    /// Build a single-lane service with the provided mailbox capacity.
    pub fn build_with_capacity(
        mut self,
        context: E,
        capacity: usize,
    ) -> SingleLaneBuildOutput<E, A, S>
    where
        S: SourceSet<ContextCell<E>, A, A::Ingress>,
    {
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }

        let (tx, rx) = mpsc::channel(capacity);
        let mailbox = Mailbox::new(tx);
        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,
            init: None,
            lanes: vec![LaneReceiver {
                lane: DEFAULT_SINGLE_LANE,
                receiver: LaneReceiverKind::Bounded(rx),
                closed: false,
            }],
            poll_order: self.poll_order,
            sources: self.sources,
            drain_on_shutdown: self.drain_on_shutdown,
            shutdown,
        };

        (mailbox, service)
    }
}

impl<E, A, L, S> MultiLaneServiceBuilder<E, A, L, S>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
    L: Copy + Ord + Send + 'static,
    S: Send + 'static,
{
    /// Replace the source set used by the driver.
    ///
    /// Polling is builder-order biased. The first call to this method places source polling
    /// relative to lane polling.
    pub fn with_sources<S2>(self, sources: S2) -> MultiLaneServiceBuilder<E, A, L, S2>
    where
        S2: Send + 'static,
    {
        let mut poll_order = self.poll_order;
        if !poll_order.contains(&PollTarget::Sources) {
            poll_order.push(PollTarget::Sources);
        }

        MultiLaneServiceBuilder {
            actor: self.actor,
            lanes: self.lanes,
            poll_order,
            sources,
            drain_on_shutdown: self.drain_on_shutdown,
            _marker: self._marker,
        }
    }

    /// Add a lane with a bounded capacity.
    ///
    /// Polling is builder-order biased. The first call to this method places lane polling
    /// relative to source polling.
    pub fn with_lane(mut self, lane: L, capacity: usize) -> Self {
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }
        self.lanes.push((lane, LaneCapacity::Bounded(capacity)));
        self
    }

    /// Add an unbounded lane.
    ///
    /// Polling is builder-order biased. The first call to this method places lane polling
    /// relative to source polling.
    pub fn with_unbounded_lane(mut self, lane: L) -> Self {
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }
        self.lanes.push((lane, LaneCapacity::Unbounded));
        self
    }

    /// Configure whether the control loop drains outstanding messages once shutdown begins.
    pub const fn with_drain_on_shutdown(mut self, drain: bool) -> Self {
        self.drain_on_shutdown = drain;
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceBuildError::DuplicateLaneConfigured`] when the same lane key is added
    /// more than once.
    pub fn build(
        mut self,
        context: E,
    ) -> Result<MultiLaneBuildOutput<E, A, L, S>, ServiceBuildError>
    where
        S: SourceSet<ContextCell<E>, A, A::Ingress>,
    {
        let mut bounded_mailboxes = BTreeMap::new();
        let mut unbounded_mailboxes = BTreeMap::new();
        let mut receivers = Vec::new();
        if !self.poll_order.contains(&PollTarget::Lanes) {
            self.poll_order.push(PollTarget::Lanes);
        }
        for (lane, capacity) in self.lanes {
            match capacity {
                LaneCapacity::Bounded(capacity) => {
                    let (tx, rx) = mpsc::channel(capacity);
                    let inserted = bounded_mailboxes.insert(lane, Mailbox::new(tx));
                    if inserted.is_some() || unbounded_mailboxes.contains_key(&lane) {
                        return Err(ServiceBuildError::DuplicateLaneConfigured);
                    }
                    receivers.push(LaneReceiver {
                        lane,
                        receiver: LaneReceiverKind::Bounded(rx),
                        closed: false,
                    });
                }
                LaneCapacity::Unbounded => {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let inserted = unbounded_mailboxes.insert(lane, UnboundedMailbox::new(tx));
                    if inserted.is_some() || bounded_mailboxes.contains_key(&lane) {
                        return Err(ServiceBuildError::DuplicateLaneConfigured);
                    }
                    receivers.push(LaneReceiver {
                        lane,
                        receiver: LaneReceiverKind::Unbounded(rx),
                        closed: false,
                    });
                }
            }
        }

        let shutdown = context.stopped();
        let service = ActorService {
            context: ContextCell::new(context),
            actor: self.actor,
            init: None,
            lanes: receivers,
            poll_order: self.poll_order,
            sources: self.sources,
            drain_on_shutdown: self.drain_on_shutdown,
            shutdown,
        };

        Ok((
            Lanes {
                bounded_mailboxes,
                unbounded_mailboxes,
            },
            service,
        ))
    }
}

struct LaneReceiver<L, I> {
    lane: L,
    receiver: LaneReceiverKind<I>,
    closed: bool,
}

enum LaneReceiverKind<I> {
    Bounded(mpsc::Receiver<I>),
    Unbounded(mpsc::UnboundedReceiver<I>),
}

impl<L, I> LaneReceiver<L, I> {
    fn close(&mut self) {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => rx.close(),
            LaneReceiverKind::Unbounded(rx) => rx.close(),
        }
    }

    fn try_recv(&mut self) -> Result<I, mpsc::error::TryRecvError> {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => rx.try_recv(),
            LaneReceiverKind::Unbounded(rx) => rx.try_recv(),
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<I>> {
        match &mut self.receiver {
            LaneReceiverKind::Bounded(rx) => Pin::new(rx).poll_recv(cx),
            LaneReceiverKind::Unbounded(rx) => Pin::new(rx).poll_recv(cx),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PollTarget {
    Lanes,
    Sources,
}

/// Framework-managed actor loop used by [`ServiceBuilder`].
pub struct ActorService<E, A, L, S = NoSources>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
    L: Copy + Ord + Send + 'static,
{
    context: ContextCell<E>,
    actor: A,
    init: Option<A::Init>,
    lanes: Vec<LaneReceiver<L, A::Ingress>>,
    poll_order: Vec<PollTarget>,
    sources: S,
    drain_on_shutdown: bool,
    shutdown: Signal,
}

impl<E, A, L, S> ActorService<E, A, L, S>
where
    E: Spawner,
    A: Actor<ContextCell<E>>,
    L: Copy + Ord + Send + 'static,
    S: SourceSet<ContextCell<E>, A, A::Ingress>,
{
    /// Spawn the control loop for actors whose [`Actor::Init`] is `()`.
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start(self) -> Handle<()>
    where
        A: Actor<ContextCell<E>, Init = ()>,
    {
        self.start_with(())
    }

    /// Spawn the control loop, passing `init` data to [`Actor::on_startup`].
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start_with(mut self, init: A::Init) -> Handle<()> {
        self.init = Some(init);
        let context = self.context.take();
        context.spawn(move |context| async move {
            self.context.restore(context);
            self.enter().await
        })
    }

    async fn enter(mut self) {
        debug!(
            lanes = self.lanes.len(),
            poll_targets = self.poll_order.len(),
            drain_on_shutdown = self.drain_on_shutdown,
            "actor service started"
        );
        let init = self.init.take().expect("init must be set before enter");
        self.actor.on_startup(&self.context, init).await;

        loop {
            self.actor.preprocess(&self.context).await;

            let event = recv_event(
                &mut self.shutdown,
                &mut self.lanes,
                &mut self.sources,
                &mut self.actor,
                &self.context,
                &self.poll_order,
            )
            .await;

            let flow = match event {
                LoopEvent::Shutdown => {
                    if self.drain_on_shutdown {
                        debug!("shutdown signal received. draining queued messages and shutting down actor");
                        for lane in &mut self.lanes {
                            lane.close();
                        }
                        while let Some((_, message)) = try_recv_from_lanes(&mut self.lanes) {
                            if let ControlFlow::Break(_) =
                                self.actor.on_ingress(&self.context, message).await
                            {
                                break;
                            }
                        }
                    } else {
                        debug!("shutdown signal received, shutting down actor");
                    }
                    ControlFlow::Break(())
                }
                LoopEvent::Mailbox(message) => match message {
                    Some(message) => {
                        let flow = self.actor.on_ingress(&self.context, message).await;
                        if let ControlFlow::Break(_) = flow {
                            debug!("actor requested shutdown from mailbox ingress");
                        }
                        flow
                    }
                    None => {
                        debug!("lane closed, shutting down actor");
                        ControlFlow::Break(())
                    }
                },
                LoopEvent::Source(message) => match message {
                    Some(message) => {
                        let flow = self.actor.on_ingress(&self.context, message).await;
                        if let ControlFlow::Break(_) = flow {
                            debug!("actor requested shutdown from source ingress");
                        }
                        flow
                    }
                    None => {
                        debug!("source closed, shutting down actor");
                        ControlFlow::Break(())
                    }
                },
            };

            if let ControlFlow::Break(_) = flow {
                break;
            }

            self.actor.postprocess(&self.context).await;
        }

        self.actor.on_shutdown(&self.context).await;
        debug!("actor service stopped");
    }
}

fn poll_sources<E, A, I, S>(
    sources: &mut S,
    actor: &mut A,
    context: &E,
    cx: &mut Context<'_>,
) -> Poll<Option<I>>
where
    S: SourceSet<E, A, I>,
{
    sources.poll_next(actor, context, cx)
}

fn try_recv_from_lanes<L, I>(lanes: &mut [LaneReceiver<L, I>]) -> Option<(L, I)>
where
    L: Copy,
{
    if lanes.is_empty() {
        return None;
    }

    for lane in lanes.iter_mut() {
        if lane.closed {
            continue;
        }
        match lane.try_recv() {
            Ok(message) => {
                return Some((lane.lane, message));
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => {
                lane.closed = true;
            }
        }
    }
    None
}

fn poll_lanes<L, I>(lanes: &mut [LaneReceiver<L, I>], cx: &mut Context<'_>) -> Poll<Option<(L, I)>>
where
    L: Copy + Send + 'static,
    I: Send + 'static,
{
    if lanes.is_empty() {
        return Poll::Ready(None);
    }

    for lane in lanes.iter_mut() {
        if lane.closed {
            continue;
        }
        match lane.poll_recv(cx) {
            Poll::Ready(Some(message)) => {
                return Poll::Ready(Some((lane.lane, message)));
            }
            Poll::Ready(None) => {
                lane.closed = true;
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }
    }

    Poll::Pending
}

fn recv_event<'a, E, A, L, I, S>(
    shutdown: &'a mut Signal,
    lanes: &'a mut [LaneReceiver<L, I>],
    sources: &'a mut S,
    actor: &'a mut A,
    context: &'a E,
    poll_order: &'a [PollTarget],
) -> impl std::future::Future<Output = LoopEvent<I>> + 'a
where
    L: Copy + Send + 'static,
    I: Send + 'static,
    S: SourceSet<E, A, I>,
{
    futures::future::poll_fn(move |cx: &mut Context<'_>| {
        if Pin::new(&mut *shutdown).poll(cx).is_ready() {
            return Poll::Ready(LoopEvent::Shutdown);
        }

        for target in poll_order {
            match target {
                PollTarget::Lanes => match poll_lanes(lanes, cx) {
                    Poll::Ready(message) => {
                        return Poll::Ready(LoopEvent::Mailbox(
                            message.map(|(_, ingress)| ingress),
                        ));
                    }
                    Poll::Pending => {}
                },
                PollTarget::Sources => match poll_sources(sources, actor, context, cx) {
                    Poll::Ready(message) => return Poll::Ready(LoopEvent::Source(message)),
                    Poll::Pending => {}
                },
            }
        }

        Poll::Pending
    })
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
    /// A message received from registered sources.
    Source(Option<I>),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{dispatch, ingress, mailbox::MailboxError, source, sources, Request, Tell};
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::{
        channel::{mpsc, oneshot},
        futures::{AbortablePool, Aborter},
    };
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Lane {
        Control,
        High,
        Low,
    }

    fn assert_source_set<E, A, I, S: SourceSet<E, A, I>>(_source: &S) {}

    ingress! {
        StressMailbox,

        tell Add { value: u64 };
        ask Total -> u64;
        ask Stop -> u64;
    }

    #[derive(Default)]
    struct StressActor {
        total: u64,
    }

    impl<E> Actor<E> for StressActor
    where
        E: Spawner,
    {
        type Ingress = StressMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                StressMailboxMessage::Add { value } => {
                    self.total += value;
                },
                StressMailboxMessage::Total { response } => {
                    let _ = response.send(self.total);
                },
                StressMailboxMessage::Stop { response } => {
                    let _ = response.send(self.total);
                    ControlFlow::Break(())
                },
            })
        }
    }

    ingress! {
        CounterMailbox,

        tell Increment { amount: usize };
        ask Get -> usize;
        ask Fail -> Result<(), &'static str>;
    }

    #[derive(Default, Debug, Clone)]
    struct CounterActor {
        count: usize,
    }

    impl<E> Actor<E> for CounterActor
    where
        E: Spawner,
    {
        type Ingress = CounterMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                CounterMailboxMessage::Increment { amount } => {
                    self.count += amount;
                },
                CounterMailboxMessage::Get { response } => {
                    let _ = response.send(self.count);
                },
                CounterMailboxMessage::Fail { response } => {
                    let _ = response.send(Err("fatal"));
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn test_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (mut mailbox, control) =
                ServiceBuilder::new(actor).build(context.with_label("counter"));
            control.start();

            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 0);

            mailbox.tell(Increment { amount: 5 }).await.unwrap();
            mailbox.tell(Increment { amount: 5 }).await.unwrap();

            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 10);

            context.stop(0, None).await.unwrap();
            assert_eq!(mailbox.ask(Get).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[test]
    fn ingress_can_stop_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (mut mailbox, control) =
                ServiceBuilder::new(actor).build(context.with_label("failing"));
            let handle = control.start();

            let reply = mailbox.ask(Fail).await.unwrap();
            assert_eq!(reply, Err("fatal"));

            let _ = handle.await;
            assert_eq!(mailbox.ask(Fail).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[test]
    fn unbounded_lane_can_drive_service() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_unbounded_lane(0usize)
                .build(context.with_label("unbounded"))
                .unwrap();
            let mut mailbox = lanes.unbounded_lane(&0usize).unwrap();
            let handle = control.start();

            mailbox.tell(Increment { amount: 3 }).unwrap();
            mailbox.tell(Increment { amount: 4 }).unwrap();
            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 7);

            context.stop(0, None).await.unwrap();
            let _ = handle.await;
            assert_eq!(mailbox.ask(Get).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[test]
    fn build_unbounded_creates_single_unbounded_lane() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (mut mailbox, control) =
                ServiceBuilder::new(actor).build_unbounded(context.with_label("build_unbounded"));
            let handle = control.start();

            mailbox.tell(Increment { amount: 3 }).unwrap();
            mailbox.tell(Increment { amount: 4 }).unwrap();
            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 7);

            context.stop(0, None).await.unwrap();
            let _ = handle.await;
            assert_eq!(mailbox.ask(Get).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[derive(Debug)]
    struct DualStreamActor {
        count: usize,
    }

    impl<E> Actor<E> for DualStreamActor
    where
        E: Spawner,
    {
        type Ingress = CounterMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                CounterMailboxMessage::Increment { amount } => {
                    self.count += amount;
                },
                CounterMailboxMessage::Get { response } => {
                    let _ = response.send(self.count);
                },
                CounterMailboxMessage::Fail { response } => {
                    let _ = response.send(Err("fatal"));
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn test_dual_stream_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (aux_tx, aux_rx) = mpsc::channel(16);

            let actor = DualStreamActor { count: 0 };
            let aux_source = source::recv(
                aux_rx,
                |_unit,
                 _actor: &mut DualStreamActor,
                 _context: &ContextCell<deterministic::Context>| {
                    CounterMailboxMessage::Increment { amount: 1 }
                },
            );
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(0usize, 16)
                .with_sources(aux_source)
                .build(context.with_label("counter"))
                .unwrap();
            let mut mailbox = lanes.lane(&0usize).unwrap();
            control.start();

            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 0);

            mailbox.tell(Increment { amount: 5 }).await.unwrap();
            let _ = aux_tx.send(()).await;
            mailbox.tell(Increment { amount: 5 }).await.unwrap();
            let _ = aux_tx.send(()).await;

            context.sleep(Duration::from_millis(10)).await;

            let value = mailbox.ask(Get).await.unwrap();
            assert_eq!(value, 12);

            context.stop(0, None).await.unwrap();
            assert_eq!(mailbox.ask(Get).await.unwrap_err(), MailboxError::Closed);
        });
    }

    ingress! {
        SequenceMailbox,

        tell Push { tag: &'static str };
        ask GetSequence -> Vec<&'static str>;
    }

    #[derive(Default)]
    struct SequenceActor {
        seen: Vec<&'static str>,
    }

    impl<E> Actor<E> for SequenceActor
    where
        E: Spawner,
    {
        type Ingress = SequenceMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                SequenceMailboxMessage::Push { tag } => {
                    self.seen.push(tag);
                },
                SequenceMailboxMessage::GetSequence { response } => {
                    let _ = response.send(self.seen.clone());
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn lane_priority_prefers_earlier_lane() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = SequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(Lane::High, 8)
                .with_lane(Lane::Low, 8)
                .with_lane(Lane::Control, 8)
                .build(context.with_label("strict_lanes"))
                .unwrap();

            let mut high = lanes.lane(&Lane::High).unwrap();
            let mut low = lanes.lane(&Lane::Low).unwrap();
            let mut ctl = lanes.lane(&Lane::Control).unwrap();

            low.tell(Push { tag: "low-1" }).await.unwrap();
            high.tell(Push { tag: "high-1" }).await.unwrap();

            let handle = control.start();
            let seen = ctl.ask(GetSequence).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen, vec!["high-1", "low-1"]);
        });
    }

    #[test]
    fn closing_any_lane_stops_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(0usize, 8)
                .with_lane(1usize, 8)
                .build(context.with_label("lane_close_shutdown"))
                .unwrap();

            let mut lane0 = lanes.lane(&0).unwrap();
            let lane1 = lanes.lane(&1).unwrap();
            drop(lanes);

            let handle = control.start();
            lane0.tell(Increment { amount: 1 }).await.unwrap();
            assert_eq!(lane0.ask(Get).await.unwrap(), 1);

            drop(lane1);
            context.sleep(Duration::from_millis(0)).await;

            let _ = handle.await;
            assert_eq!(lane0.ask(Get).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[test]
    fn lane_priority_bias_drains_high_before_low() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = SequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(Lane::High, 8)
                .with_lane(Lane::Low, 8)
                .with_lane(Lane::Control, 8)
                .build(context.with_label("priority_lanes"))
                .unwrap();

            let mut high = lanes.lane(&Lane::High).unwrap();
            let mut low = lanes.lane(&Lane::Low).unwrap();
            let mut ctl = lanes.lane(&Lane::Control).unwrap();

            high.tell(Push { tag: "high-1" }).await.unwrap();
            high.tell(Push { tag: "high-2" }).await.unwrap();
            low.tell(Push { tag: "low-1" }).await.unwrap();
            low.tell(Push { tag: "low-2" }).await.unwrap();

            let handle = control.start();
            context.sleep(Duration::from_millis(10)).await;
            let seen = ctl.ask(GetSequence).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen, vec!["high-1", "high-2", "low-1", "low-2"]);
        });
    }

    #[test]
    fn stress_many_concurrent_senders_single_lane() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = StressActor::default();
            let (mailbox, control) = ServiceBuilder::new(actor)
                .build_with_capacity(context.with_label("stress_single_lane"), 1024);

            let handle = control.start();

            let workers = 24u64;
            let per_worker = 200u64;
            let mut joins = Vec::new();

            for i in 0..workers {
                let mut sender = mailbox.clone();
                joins.push(
                    context
                        .with_label("sender")
                        .spawn(move |_context| async move {
                            for _ in 0..per_worker {
                                sender.tell(Add { value: i + 1 }).await.unwrap();
                            }
                        }),
                );
            }

            for join in joins {
                let _ = join.await;
            }

            let mut checker = mailbox.clone();
            let expected = (1..=workers).sum::<u64>() * per_worker;
            let total = checker.ask(Total).await.unwrap();
            assert_eq!(total, expected);

            let final_total = checker.ask(Stop).await.unwrap();
            assert_eq!(final_total, expected);
            let _ = handle.await;
            assert_eq!(checker.ask(Total).await.unwrap_err(), MailboxError::Closed);
        });
    }

    #[test]
    fn stress_multi_lane_priority_prefers_high_lane() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = SequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(Lane::High, 256)
                .with_lane(Lane::Low, 256)
                .with_lane(Lane::Control, 32)
                .build(context.with_label("stress_priority"))
                .unwrap();

            let mut high = lanes.lane(&Lane::High).unwrap();
            let mut low = lanes.lane(&Lane::Low).unwrap();
            let mut ctl = lanes.lane(&Lane::Control).unwrap();

            for i in 0..100 {
                high.tell(Push {
                    tag: if i % 2 == 0 { "high-even" } else { "high-odd" },
                })
                .await
                .unwrap();
                low.tell(Push {
                    tag: if i % 2 == 0 { "low-even" } else { "low-odd" },
                })
                .await
                .unwrap();
            }

            let handle = control.start();
            context.sleep(Duration::from_millis(25)).await;
            let seen = ctl.ask(GetSequence).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen.len(), 200);
            let high_seen = seen.iter().filter(|tag| tag.starts_with("high")).count();
            let low_seen = seen.iter().filter(|tag| tag.starts_with("low")).count();
            assert_eq!(high_seen, 100);
            assert_eq!(low_seen, 100);

            for tag in &seen[..100] {
                assert!(tag.starts_with("high"));
            }
            for tag in &seen[100..] {
                assert!(tag.starts_with("low"));
            }
        });
    }

    ingress! {
        SourceSeqMailbox,

        tell Mark { tag: &'static str };
        ask GetMarks -> Vec<&'static str>;
    }

    #[derive(Default)]
    struct SourceSequenceActor {
        seen: Vec<&'static str>,
    }

    impl<E> Actor<E> for SourceSequenceActor
    where
        E: Spawner,
    {
        type Ingress = SourceSeqMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                SourceSeqMailboxMessage::Mark { tag } => {
                    self.seen.push(tag);
                },
                SourceSeqMailboxMessage::GetMarks { response } => {
                    let _ = response.send(self.seen.clone());
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn source_declaration_order_prefers_earlier_source() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (tx_a, rx_a) = mpsc::channel::<()>(8);
            let (tx_b, rx_b) = mpsc::channel::<()>(8);

            let src_a = source::recv(
                rx_a,
                |_unit,
                 _actor: &mut SourceSequenceActor,
                 _context: &ContextCell<deterministic::Context>| {
                    SourceSeqMailboxMessage::Mark { tag: "a" }
                },
            );
            let src_b = source::recv(
                rx_b,
                |_unit,
                 _actor: &mut SourceSequenceActor,
                 _context: &ContextCell<deterministic::Context>| {
                    SourceSeqMailboxMessage::Mark { tag: "b" }
                },
            );

            let actor = SourceSequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(0usize, 8)
                .with_sources(sources!(src_a, src_b))
                .build(context.with_label("source_declaration_order"))
                .unwrap();

            let mut mailbox = lanes.lane(&0usize).unwrap();
            tx_a.send(()).await.unwrap();
            tx_a.send(()).await.unwrap();
            tx_b.send(()).await.unwrap();
            tx_b.send(()).await.unwrap();

            let handle = control.start();
            context.sleep(Duration::from_millis(5)).await;
            let seen = mailbox.ask(GetMarks).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen, vec!["a", "a", "b", "b"]);
        });
    }

    struct ExhaustingSource {
        polls: Arc<AtomicUsize>,
        stage: u8,
    }

    impl<E> source::Source<E, SourceSequenceActor, SourceSeqMailboxMessage> for ExhaustingSource {
        fn poll_next(
            &mut self,
            _actor: &mut SourceSequenceActor,
            _context: &E,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<SourceSeqMailboxMessage>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            match self.stage {
                0 => {
                    self.stage = 1;
                    Poll::Ready(Some(SourceSeqMailboxMessage::Mark { tag: "once" }))
                }
                1 => {
                    self.stage = 2;
                    Poll::Ready(None)
                }
                _ => Poll::Pending,
            }
        }
    }

    impl<E> source::SourceSet<E, SourceSequenceActor, SourceSeqMailboxMessage> for ExhaustingSource {
        fn poll_next(
            &mut self,
            actor: &mut SourceSequenceActor,
            context: &E,
            cx: &mut Context<'_>,
        ) -> Poll<Option<SourceSeqMailboxMessage>> {
            source::Source::poll_next(self, actor, context, cx)
        }
    }

    #[test]
    fn exhausted_source_stops_actor() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let polls = Arc::new(AtomicUsize::new(0));
            let source = ExhaustingSource {
                polls: polls.clone(),
                stage: 0,
            };

            let actor = SourceSequenceActor::default();
            let (mut mailbox, control) = ServiceBuilder::new(actor)
                .with_sources(source)
                .build_with_capacity(context.with_label("source_exhaustion"), 16);

            let handle = control.start();
            context.sleep(Duration::from_millis(5)).await;
            let seen = mailbox.ask(GetMarks).await;
            let _ = handle.await;

            assert!(seen.is_err());
            assert_eq!(polls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn builder_order_sources_before_lanes_prefers_source_events() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (tx_source, rx_source) = mpsc::channel::<()>(4);
            let source = source::recv(
                rx_source,
                |_unit,
                 _actor: &mut SourceSequenceActor,
                 _context: &ContextCell<deterministic::Context>| {
                    SourceSeqMailboxMessage::Mark { tag: "source" }
                },
            );

            let actor = SourceSequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_sources(source)
                .with_lane(0usize, 16)
                .build(context.with_label("source_before_lane"))
                .unwrap();
            let mut mailbox = lanes.lane(&0usize).unwrap();

            mailbox.tell(Mark { tag: "lane" }).await.unwrap();
            tx_source.send(()).await.unwrap();

            let handle = control.start();
            context.sleep(Duration::from_millis(5)).await;
            let seen = mailbox.ask(GetMarks).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen, vec!["source", "lane"]);
        });
    }

    #[test]
    fn builder_order_lanes_before_sources_prefers_lane_events() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (tx_source, rx_source) = mpsc::channel::<()>(4);
            let source = source::recv(
                rx_source,
                |_unit,
                 _actor: &mut SourceSequenceActor,
                 _context: &ContextCell<deterministic::Context>| {
                    SourceSeqMailboxMessage::Mark { tag: "source" }
                },
            );

            let actor = SourceSequenceActor::default();
            let (lanes, control) = ServiceBuilder::new(actor)
                .with_lane(0usize, 16)
                .with_sources(source)
                .build(context.with_label("lane_before_source"))
                .unwrap();
            let mut mailbox = lanes.lane(&0usize).unwrap();

            mailbox.tell(Mark { tag: "lane" }).await.unwrap();
            tx_source.send(()).await.unwrap();

            let handle = control.start();
            context.sleep(Duration::from_millis(5)).await;
            let seen = mailbox.ask(GetMarks).await.unwrap();
            let _ = handle.await;

            assert_eq!(seen, vec!["lane", "source"]);
        });
    }

    ingress! {
        AdapterMailbox,

        tell Input { value: u64 };
        tell Timer;
        tell FutureDone { value: u64 };
        tell ArmTimer { delay_ms: u64 };
        tell ArmFuture { receiver: oneshot::Receiver<u64> };
        ask Snapshot -> (u64, usize);
    }

    #[derive(Default)]
    struct AdapterActor {
        sum: u64,
        ticks: usize,
        deadline: Option<std::time::SystemTime>,
        pending: Option<oneshot::Receiver<u64>>,
    }

    impl<E> Actor<E> for AdapterActor
    where
        E: Spawner + commonware_runtime::Clock,
    {
        type Ingress = AdapterMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                AdapterMailboxMessage::Input { value } => {
                    self.sum += value;
                },
                AdapterMailboxMessage::Timer => {
                    self.ticks += 1;
                    self.deadline = None;
                },
                AdapterMailboxMessage::FutureDone { value } => {
                    self.sum += value;
                },
                AdapterMailboxMessage::ArmTimer { delay_ms } => {
                    self.deadline = Some(context.current() + Duration::from_millis(delay_ms));
                },
                AdapterMailboxMessage::ArmFuture { receiver } => {
                    self.pending = Some(receiver);
                },
                AdapterMailboxMessage::Snapshot { response } => {
                    let _ = response.send((self.sum, self.ticks));
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn built_in_sources_recv_deadline_and_option_future_work_together() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (tx_input, rx_input) = mpsc::channel::<u64>(8);

            let input_source = source::recv(
                rx_input,
                |value,
                 _actor: &mut AdapterActor,
                 _context: &ContextCell<deterministic::Context>| {
                    AdapterMailboxMessage::Input { value }
                },
            );
            let timer_source = source::deadline(
                |actor: &mut AdapterActor, _context: &ContextCell<deterministic::Context>| {
                    actor.deadline
                },
                |_actor: &mut AdapterActor, _context: &ContextCell<deterministic::Context>| {
                    AdapterMailboxMessage::Timer
                },
            );
            let future_source = source::option_future(
                |actor: &mut AdapterActor, _context: &ContextCell<deterministic::Context>| {
                    actor.pending.take()
                },
                |result: Result<u64, oneshot::error::RecvError>,
                 _actor: &mut AdapterActor,
                 _context: &ContextCell<deterministic::Context>| {
                    let value = result.unwrap_or_default();
                    AdapterMailboxMessage::FutureDone { value }
                },
            );

            let actor = AdapterActor::default();
            let (mut mailbox, control) = ServiceBuilder::new(actor)
                .with_sources(sources!(input_source, timer_source, future_source))
                .build_with_capacity(context.with_label("source_adapters"), 32);

            let (future_tx, future_rx) = oneshot::channel();
            let handle = control.start();

            mailbox.tell(ArmTimer { delay_ms: 2 }).await.unwrap();
            mailbox
                .tell(ArmFuture {
                    receiver: future_rx,
                })
                .await
                .unwrap();

            tx_input.send(5).await.unwrap();
            let _ = future_tx.send(7);

            context.sleep(Duration::from_millis(10)).await;
            let (sum, ticks) = mailbox.ask(Snapshot).await.unwrap();
            let _ = handle.await;

            assert_eq!(sum, 12);
            assert_eq!(ticks, 1);
        });
    }

    enum ManualIngress {
        Add { value: u64 },
        Read { response: oneshot::Sender<u64> },
        Stop,
    }

    struct ManualAdd {
        value: u64,
    }

    impl Tell<ManualIngress> for ManualAdd {
        fn into_ingress(self) -> ManualIngress {
            ManualIngress::Add { value: self.value }
        }
    }

    struct ManualRead;
    impl Request<ManualIngress> for ManualRead {
        type Response = u64;

        fn into_ingress(self, response: oneshot::Sender<Self::Response>) -> ManualIngress {
            ManualIngress::Read { response }
        }
    }

    struct ManualStop;
    impl Tell<ManualIngress> for ManualStop {
        fn into_ingress(self) -> ManualIngress {
            ManualIngress::Stop
        }
    }

    #[test]
    fn manual_loop_uses_same_protocol_and_mailbox_types() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (tx, mut rx) = mpsc::channel::<ManualIngress>(128);
            let mut mailbox = Mailbox::new(tx);

            let handle = context
                .with_label("manual_loop")
                .spawn(move |_context| async move {
                    let mut total = 0u64;
                    while let Some(message) = rx.recv().await {
                        match message {
                            ManualIngress::Add { value } => {
                                total += value;
                            }
                            ManualIngress::Read { response } => {
                                let _ = response.send(total);
                            }
                            ManualIngress::Stop => break,
                        }
                    }
                });

            mailbox.tell(ManualAdd { value: 5 }).await.unwrap();
            mailbox.tell(ManualAdd { value: 6 }).await.unwrap();
            assert_eq!(mailbox.ask(ManualRead).await.unwrap(), 11);

            mailbox.tell(ManualStop).await.unwrap();
            let _ = handle.await;
            assert_eq!(
                mailbox.ask(ManualRead).await.unwrap_err(),
                MailboxError::Closed
            );
        });
    }

    ingress! {
        PoolMailbox,

        tell PushWork { receiver: oneshot::Receiver<u64> };
        tell AbortLast;
        tell PoolDone { value: u64 };
        tell PoolAborted;
        ask PoolSnapshot -> (u64, usize);
    }

    #[derive(Default)]
    struct PoolActor {
        pool: AbortablePool<u64>,
        aborters: Vec<Aborter>,
        sum: u64,
        aborted: usize,
    }

    impl<E> Actor<E> for PoolActor
    where
        E: Spawner,
    {
        type Ingress = PoolMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                PoolMailboxMessage::PushWork { receiver } => {
                    let aborter = self.pool.push(async move { receiver.await.unwrap_or_default() });
                    self.aborters.push(aborter);
                },
                PoolMailboxMessage::AbortLast => {
                    self.aborters.pop();
                },
                PoolMailboxMessage::PoolDone { value } => {
                    self.sum += value;
                },
                PoolMailboxMessage::PoolAborted => {
                    self.aborted += 1;
                },
                PoolMailboxMessage::PoolSnapshot { response } => {
                    let _ = response.send((self.sum, self.aborted));
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn built_in_source_pool_next_emits_completion_and_abort() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let pool_source = source::pool_next(
                |actor: &mut PoolActor| &mut actor.pool,
                |result: Result<u64, futures::future::Aborted>,
                 _actor: &mut PoolActor,
                 _context: &ContextCell<deterministic::Context>| {
                    result.map_or_else(
                        |_| PoolMailboxMessage::PoolAborted,
                        |value| PoolMailboxMessage::PoolDone { value },
                    )
                },
            );
            assert_source_set::<
                ContextCell<deterministic::Context>,
                PoolActor,
                PoolMailboxMessage,
                _,
            >(&pool_source);

            let actor = PoolActor::default();
            let (mut mailbox, control) = ServiceBuilder::new(actor)
                .with_sources(pool_source)
                .build_with_capacity(context.with_label("pool_source"), 32);

            let (ok_tx, ok_rx) = oneshot::channel();
            let (_abort_tx, abort_rx) = oneshot::channel::<u64>();
            let handle = control.start();

            mailbox.tell(PushWork { receiver: ok_rx }).await.unwrap();
            mailbox.tell(PushWork { receiver: abort_rx }).await.unwrap();
            mailbox.tell(AbortLast).await.unwrap();

            let _ = ok_tx.send(11);

            context.sleep(Duration::from_millis(10)).await;
            let (sum, aborted) = mailbox.ask(PoolSnapshot).await.unwrap();
            let _ = handle.await;

            assert_eq!(sum, 11);
            assert_eq!(aborted, 1);
        });
    }

    ingress! {
        HandleMailbox,

        tell ArmHandle { handle: Handle<u64> };
        tell Done { output: Result<u64, commonware_runtime::Error> };
        ask HandleSnapshot -> u64;
    }

    #[derive(Default)]
    struct HandleActor {
        pending: Option<Handle<u64>>,
        sum: u64,
    }

    impl<E> Actor<E> for HandleActor
    where
        E: Spawner,
    {
        type Ingress = HandleMailboxMessage;
        type Init = ();

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                HandleMailboxMessage::ArmHandle { handle } => {
                    self.pending = Some(handle);
                },
                HandleMailboxMessage::Done { output } => {
                    if let Ok(value) = output {
                        self.sum += value;
                    }
                },
                HandleMailboxMessage::HandleSnapshot { response } => {
                    let _ = response.send(self.sum);
                    ControlFlow::Break(())
                },
            })
        }
    }

    #[test]
    fn built_in_source_handle_emits_task_completion() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let handle_source = source::handle(
                |actor: &mut HandleActor| &mut actor.pending,
                |output: Result<u64, commonware_runtime::Error>,
                 _actor: &mut HandleActor,
                 _context: &ContextCell<deterministic::Context>| {
                    HandleMailboxMessage::Done { output }
                },
            );
            assert_source_set::<
                ContextCell<deterministic::Context>,
                HandleActor,
                HandleMailboxMessage,
                _,
            >(&handle_source);

            let actor = HandleActor::default();
            let (mut mailbox, control) = ServiceBuilder::new(actor)
                .with_sources(handle_source)
                .build_with_capacity(context.with_label("handle_source"), 16);

            let worker = context.with_label("worker").spawn(|context| async move {
                context.sleep(Duration::from_millis(3)).await;
                9u64
            });

            let handle = control.start();
            mailbox.tell(ArmHandle { handle: worker }).await.unwrap();

            context.sleep(Duration::from_millis(10)).await;
            let sum = mailbox.ask(HandleSnapshot).await.unwrap();
            let _ = handle.await;

            assert_eq!(sum, 9);
        });
    }

    #[derive(Default)]
    struct LifecycleState {
        started: AtomicUsize,
        shutdown: AtomicUsize,
        processed: AtomicUsize,
    }

    ingress! {
        LifecycleMailbox,

        tell Work;
    }

    struct LifecycleActor {
        state: Arc<LifecycleState>,
        startup_gate: Option<oneshot::Receiver<()>>,
    }

    impl<E> Actor<E> for LifecycleActor
    where
        E: Spawner,
    {
        type Ingress = LifecycleMailboxMessage;
        type Init = ();

        async fn on_startup(&mut self, _context: &E, _init: Self::Init) {
            self.state.started.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = self.startup_gate.take() {
                let _ = gate.await;
            }
        }

        async fn on_ingress(&mut self, _context: &E, message: Self::Ingress) -> ControlFlow<()> {
            dispatch!(message, {
                LifecycleMailboxMessage::Work => {
                    self.state.processed.fetch_add(1, Ordering::SeqCst);
                },
            })
        }

        async fn on_shutdown(&mut self, _context: &E) {
            self.state.shutdown.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn run_driver_lifecycle(drain: bool) -> Arc<LifecycleState> {
        let state = Arc::new(LifecycleState::default());
        let actor_state = state.clone();
        let runner = deterministic::Runner::default();
        runner.start(move |context| async move {
            let (startup_tx, startup_rx) = oneshot::channel();
            let actor = LifecycleActor {
                state: actor_state,
                startup_gate: Some(startup_rx),
            };
            let (mut mailbox, control) = ServiceBuilder::new(actor)
                .with_drain_on_shutdown(drain)
                .build_with_capacity(context.with_label("driver_lifecycle"), 8);
            mailbox.tell(Work).await.unwrap();
            mailbox.tell(Work).await.unwrap();

            let handle = control.start();
            let stopper = context
                .with_label("driver_stopper")
                .spawn(|context| async move { context.stop(0, None).await.unwrap() });
            context.sleep(Duration::from_millis(0)).await;
            let _ = startup_tx.send(());
            let _ = stopper.await;
            drop(mailbox);
            let _ = handle.await;
        });
        state
    }

    fn run_manual_lifecycle(drain: bool) -> Arc<LifecycleState> {
        let state = Arc::new(LifecycleState::default());
        let task_state = state.clone();
        let runner = deterministic::Runner::default();
        runner.start(move |context| async move {
            let (tx, mut rx) = mpsc::channel::<LifecycleMailboxMessage>(8);
            let mut manual_mailbox = crate::mailbox::Mailbox::new(tx);
            let (startup_tx, startup_rx) = oneshot::channel();

            manual_mailbox.tell(Work).await.unwrap();
            manual_mailbox.tell(Work).await.unwrap();

            let state = task_state;
            let handle = context
                .with_label("manual_lifecycle")
                .spawn(move |context| async move {
                    state.started.fetch_add(1, Ordering::SeqCst);
                    let _ = startup_rx.await;
                    let mut stopped = context.stopped();
                    select! {
                        _ = &mut stopped => {
                            if drain {
                                rx.close();
                                while let Ok(_msg) = rx.try_recv() {
                                    state.processed.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        },
                        _ = rx.recv() => {
                            state.processed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    state.shutdown.fetch_add(1, Ordering::SeqCst);
                });

            let stopper = context
                .with_label("manual_stopper")
                .spawn(|context| async move { context.stop(0, None).await.unwrap() });
            context.sleep(Duration::from_millis(0)).await;
            let _ = startup_tx.send(());
            let _ = stopper.await;
            drop(manual_mailbox);
            let _ = handle.await;
        });
        state
    }

    fn lifecycle_parity_case(drain: bool) {
        let driver_state = run_driver_lifecycle(drain);
        let manual_state = run_manual_lifecycle(drain);

        assert_eq!(driver_state.started.load(Ordering::SeqCst), 1);
        assert_eq!(manual_state.started.load(Ordering::SeqCst), 1);
        assert_eq!(driver_state.shutdown.load(Ordering::SeqCst), 1);
        assert_eq!(manual_state.shutdown.load(Ordering::SeqCst), 1);

        let expected = if drain { 2 } else { 0 };
        assert_eq!(driver_state.processed.load(Ordering::SeqCst), expected);
        assert_eq!(manual_state.processed.load(Ordering::SeqCst), expected);
    }

    #[test]
    fn build_errors_on_duplicate_lane_configuration() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = CounterActor::default();
            let result = ServiceBuilder::new(actor)
                .with_lane(0usize, 8)
                .with_unbounded_lane(0usize)
                .build(context.with_label("build_duplicate_lanes"));
            assert!(matches!(
                result,
                Err(ServiceBuildError::DuplicateLaneConfigured)
            ));
        });
    }

    #[test]
    fn source_only_protocol_wrappers_are_constructible() {
        let _ = Mark { tag: "mark" }.into_ingress();
        let _ = Input { value: 1 }.into_ingress();
        let _ = Timer.into_ingress();
        let _ = FutureDone { value: 2 }.into_ingress();
        let _ = PoolDone { value: 3 }.into_ingress();
        let _ = PoolAborted.into_ingress();
        let _ = Done { output: Ok(4) }.into_ingress();
    }

    #[test]
    fn lifecycle_parity_driver_vs_manual_stop_no_drain() {
        lifecycle_parity_case(false);
    }

    #[test]
    fn lifecycle_parity_driver_vs_manual_stop_with_drain() {
        lifecycle_parity_case(true);
    }
}
