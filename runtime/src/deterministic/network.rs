//! Deterministic, node-addressed reliable-stream simulation.
//!
//! This transport is intentionally separate from the deterministic runtime's
//! socket transport. The socket transport preserves TCP and DNS compatibility;
//! this module provides topology and impairment control for protocol tests.

pub use crate::network::bandwidth::{
    AllocationError as BandwidthAllocationError, Flow as BandwidthFlow, Fraction, Rate,
    allocate as allocate_bandwidth, duration as bandwidth_duration, transfer as bandwidth_transfer,
};
use crate::{
    Acceptor, Clock, ConnectionInfo, Dialer, Error, IoBufs, PlatformSend, Supervisor,
    network::bandwidth,
};
use commonware_macros::select;
use commonware_utils::{channel::mpsc, sync::Mutex};
use futures::future::pending;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, SystemTime},
};

/// Default number of connections waiting at a listener.
const DEFAULT_ACCEPT_QUEUE: usize = 128;

/// Default number of bytes buffered in each stream direction.
const DEFAULT_STREAM_BUFFER: usize = 256 * 1024;

/// Cheap, opaque address of a simulated node.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Endpoint(u64);

impl Endpoint {
    /// Creates an endpoint from a test-controlled stable identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Transport-observed identity of a simulated node.
///
/// Origins are deliberately distinct from endpoints: an endpoint is dialable,
/// while an origin is metadata observed on an established connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Origin(u64);

impl Origin {
    /// Creates an origin from a test-controlled stable identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Behavior of an established reliable path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Behavior {
    /// Bytes traverse the path.
    #[default]
    Deliver,
    /// The connection fails on its next operation.
    Fail,
    /// Operations remain pending until canceled.
    Blackhole,
}

/// Directional link configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Link {
    /// Base one-way delay.
    pub latency: Duration,
    /// Deterministic per-operation delay in the inclusive range `0..=jitter`.
    pub jitter: Duration,
    /// Reliable-path failure behavior.
    pub behavior: Behavior,
}

impl Link {
    /// Creates a delivering link with fixed one-way latency.
    pub const fn new(latency: Duration) -> Self {
        Self {
            latency,
            jitter: Duration::ZERO,
            behavior: Behavior::Deliver,
        }
    }

    /// Adds deterministic jitter to the link.
    pub const fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// Sets reliable-path failure behavior.
    pub const fn with_behavior(mut self, behavior: Behavior) -> Self {
        self.behavior = behavior;
        self
    }
}

/// Resource limits for the simulated transport.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Maximum connections waiting to be accepted.
    pub accept_queue: NonZeroUsize,
    /// Maximum bytes buffered in either direction of a connection.
    pub stream_buffer: NonZeroUsize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            accept_queue: NonZeroUsize::new(DEFAULT_ACCEPT_QUEUE).unwrap(),
            stream_buffer: NonZeroUsize::new(DEFAULT_STREAM_BUFFER).unwrap(),
        }
    }
}

/// Stable counters describing simulated network activity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Successful listener bindings.
    pub binds: u64,
    /// Successful outbound connections.
    pub connections: u64,
    /// Send operations that delivered bytes to a stream buffer.
    pub deliveries: u64,
    /// Operations that failed because of topology or configured behavior.
    pub failures: u64,
    /// Operations that entered a blackhole.
    pub blackholes: u64,
    /// Bytes submitted to successful sends.
    pub bytes: u64,
}

#[derive(Clone)]
struct Registration {
    origin: Option<Origin>,
    online: bool,
    generation: u64,
}

#[derive(Clone, Copy, Default)]
struct Bandwidth {
    egress: Option<u64>,
    ingress: Option<u64>,
}

struct Binding<E: Clock> {
    generation: u64,
    sender: mpsc::Sender<Connection<E>>,
}

struct Transfer {
    from: Endpoint,
    to: Endpoint,
    delivered: bool,
    remaining: Fraction,
    rate: Rate,
}

struct ConnectionRecord {
    a: Endpoint,
    b: Endpoint,
    failure: Weak<Failure>,
}

struct ConnectionLease<E: Clock> {
    shared: Weak<Shared<E>>,
    id: u64,
}

impl<E: Clock> Drop for ConnectionLease<E> {
    fn drop(&mut self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        shared.state.lock().connections.remove(&self.id);
    }
}

struct State<E: Clock> {
    nodes: BTreeMap<Endpoint, Registration>,
    bandwidth: BTreeMap<Endpoint, Bandwidth>,
    links: BTreeMap<(Endpoint, Endpoint), Link>,
    partitions: BTreeSet<(Endpoint, Endpoint)>,
    listeners: BTreeMap<Endpoint, Binding<E>>,
    transfers: BTreeMap<u64, Transfer>,
    transfer_updated: Option<SystemTime>,
    transfer_epoch: u64,
    transfer_waiters: Vec<Waker>,
    connections: BTreeMap<u64, ConnectionRecord>,
    next_generation: u64,
    next_connection: u64,
    next_operation: u64,
    statistics: Statistics,
}

impl<E: Clock> Default for State<E> {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            bandwidth: BTreeMap::new(),
            links: BTreeMap::new(),
            partitions: BTreeSet::new(),
            listeners: BTreeMap::new(),
            transfers: BTreeMap::new(),
            transfer_updated: None,
            transfer_epoch: 0,
            transfer_waiters: Vec::new(),
            connections: BTreeMap::new(),
            next_generation: 0,
            next_connection: 0,
            next_operation: 0,
            statistics: Statistics::default(),
        }
    }
}

struct Shared<E: Clock> {
    config: Config,
    clock: Mutex<Option<E>>,
    state: Mutex<State<E>>,
}

#[derive(Default)]
struct Failure {
    failed: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl Failure {
    fn fail(&self) {
        if self.failed.swap(true, Ordering::Relaxed) {
            return;
        }
        for waiter in std::mem::take(&mut *self.waiters.lock()) {
            waiter.wake();
        }
    }

    fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    const fn wait(&self) -> FailureWait<'_> {
        FailureWait { failure: self }
    }
}

struct FailureWait<'a> {
    failure: &'a Failure,
}

impl Future for FailureWait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.failure.is_failed() {
            return Poll::Ready(());
        }
        let mut waiters = self.failure.waiters.lock();
        if self.failure.is_failed() {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|waiter| waiter.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

struct TransferChanged<'a, E: Clock> {
    shared: &'a Shared<E>,
    epoch: u64,
}

impl<E: Clock> Future for TransferChanged<'_, E> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut state = self.shared.state.lock();
        if state.transfer_epoch != self.epoch {
            return Poll::Ready(());
        }
        if !state
            .transfer_waiters
            .iter()
            .any(|waiter| waiter.will_wake(cx.waker()))
        {
            state.transfer_waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

fn wake_transfers<E: Clock>(state: &mut State<E>) -> Vec<Waker> {
    state.transfer_epoch = state.transfer_epoch.wrapping_add(1);
    std::mem::take(&mut state.transfer_waiters)
}

fn wake_all(waiters: Vec<Waker>) {
    for waiter in waiters {
        waiter.wake();
    }
}

fn advance_transfers<E: Clock>(state: &mut State<E>, now: SystemTime) {
    let Some(updated) = state.transfer_updated.replace(now) else {
        return;
    };
    let elapsed = now.duration_since(updated).unwrap_or_default();
    for transfer in state.transfers.values_mut() {
        transfer.remaining = bandwidth::transfer(transfer.rate, elapsed, transfer.remaining);
    }
}

fn rebalance_transfers<E: Clock>(state: &mut State<E>) {
    let flows: Vec<_> = state
        .transfers
        .iter()
        .map(|(id, transfer)| BandwidthFlow {
            id: *id,
            origin: transfer.from,
            recipient: transfer.to,
            delivered: transfer.delivered,
        })
        .collect();
    let rates = bandwidth::allocate(
        &flows,
        |endpoint| {
            state
                .bandwidth
                .get(endpoint)
                .and_then(|bandwidth| bandwidth.egress)
                .map(u128::from)
        },
        |endpoint| {
            state
                .bandwidth
                .get(endpoint)
                .and_then(|bandwidth| bandwidth.ingress)
                .map(u128::from)
        },
    )
    .expect("deterministic transfer identifiers are unique");
    for (id, transfer) in &mut state.transfers {
        transfer.rate = rates[id];
    }
}

fn fail_connections<E: Clock>(
    state: &mut State<E>,
    predicate: impl Fn(Endpoint, Endpoint) -> bool,
) -> Vec<Arc<Failure>> {
    let mut failures = Vec::new();
    state.connections.retain(|_, connection| {
        let Some(failure) = connection.failure.upgrade() else {
            return false;
        };
        if predicate(connection.a, connection.b) {
            failures.push(failure);
            return false;
        }
        true
    });
    failures
}

fn notify_failures(failures: Vec<Arc<Failure>>) {
    for failure in failures {
        failure.fail();
    }
}

/// Controller for node lifecycle, topology, and impairments.
pub struct Oracle<E: Clock> {
    shared: Arc<Shared<E>>,
}

impl<E: Clock> Clone for Oracle<E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<E: Clock> Oracle<E> {
    /// Creates an empty network.
    pub fn new(config: Config) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                clock: Mutex::new(None),
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Registers a node and returns a handle bound to its deterministic context.
    ///
    /// Registering an existing endpoint models a node restart: it replaces the origin, brings the
    /// node online, and invalidates handles, listeners, and connections from the prior instance.
    pub fn register(&self, context: E, endpoint: Endpoint, origin: Option<Origin>) -> Network<E>
    where
        E: Supervisor,
    {
        let mut clock = self.shared.clock.lock();
        if clock.is_none() {
            *clock = Some(context.child("network_oracle"));
        }
        drop(clock);
        let mut state = self.shared.state.lock();
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        let replaced = state
            .nodes
            .insert(
                endpoint,
                Registration {
                    origin,
                    online: true,
                    generation,
                },
            )
            .is_some();
        let failures = if replaced {
            state.listeners.remove(&endpoint);
            fail_connections(&mut state, |a, b| a == endpoint || b == endpoint)
        } else {
            Vec::new()
        };
        let waiters = wake_transfers(&mut state);
        drop(state);
        notify_failures(failures);
        wake_all(waiters);
        Network {
            context,
            endpoint,
            generation,
            shared: Arc::clone(&self.shared),
        }
    }

    /// Sets whether a node may establish or use connections.
    pub fn set_online(&self, endpoint: Endpoint, online: bool) -> Result<(), Error> {
        let mut state = self.shared.state.lock();
        let node = state
            .nodes
            .get_mut(&endpoint)
            .ok_or(Error::ConnectionFailed)?;
        node.online = online;
        let failures = if online {
            Vec::new()
        } else {
            fail_connections(&mut state, |a, b| a == endpoint || b == endpoint)
        };
        let waiters = wake_transfers(&mut state);
        drop(state);
        notify_failures(failures);
        wake_all(waiters);
        Ok(())
    }

    /// Adds or replaces one directional link.
    pub fn set_link(&self, from: Endpoint, to: Endpoint, link: Link) -> Result<(), Error> {
        let mut state = self.shared.state.lock();
        state.links.insert((from, to), link);
        let failures = if link.behavior == Behavior::Fail {
            fail_connections(&mut state, |a, b| {
                a == from && b == to || a == to && b == from
            })
        } else {
            Vec::new()
        };
        let waiters = wake_transfers(&mut state);
        drop(state);
        notify_failures(failures);
        wake_all(waiters);
        Ok(())
    }

    /// Removes a directional link. Future dials and sends fail.
    pub fn remove_link(&self, from: Endpoint, to: Endpoint) {
        let mut state = self.shared.state.lock();
        state.links.remove(&(from, to));
        let failures = fail_connections(&mut state, |a, b| {
            a == from && b == to || a == to && b == from
        });
        let waiters = wake_transfers(&mut state);
        drop(state);
        notify_failures(failures);
        wake_all(waiters);
    }

    /// Enables or disables a symmetric partition without discarding link settings.
    pub fn partition(&self, a: Endpoint, b: Endpoint, enabled: bool) {
        let mut state = self.shared.state.lock();
        for edge in [(a, b), (b, a)] {
            if enabled {
                state.partitions.insert(edge);
            } else {
                state.partitions.remove(&edge);
            }
        }
        let failures = if enabled {
            fail_connections(&mut state, |left, right| {
                left == a && right == b || left == b && right == a
            })
        } else {
            Vec::new()
        };
        let waiters = wake_transfers(&mut state);
        drop(state);
        notify_failures(failures);
        wake_all(waiters);
    }

    /// Sets per-node egress and ingress limits in bytes per second.
    ///
    /// `None` is unlimited. A zero limit blackholes affected operations.
    pub fn limit_bandwidth(
        &self,
        endpoint: Endpoint,
        egress: Option<u64>,
        ingress: Option<u64>,
    ) -> Result<(), Error> {
        let now = self.shared.clock.lock().as_ref().map(Clock::current);
        let mut state = self.shared.state.lock();
        if let Some(now) = now {
            advance_transfers(&mut state, now);
        }
        state
            .bandwidth
            .insert(endpoint, Bandwidth { egress, ingress });
        rebalance_transfers(&mut state);
        let waiters = wake_transfers(&mut state);
        drop(state);
        wake_all(waiters);
        Ok(())
    }

    /// Returns stable aggregate activity counters.
    pub fn statistics(&self) -> Statistics {
        self.shared.state.lock().statistics
    }
}

/// Node-local transport handle.
pub struct Network<E: Clock> {
    context: E,
    endpoint: Endpoint,
    generation: u64,
    shared: Arc<Shared<E>>,
}

impl<E: Clock> fmt::Debug for Network<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Network")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl<E: Clock> Network<E> {
    /// Returns this handle's endpoint.
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// Splits this node-local transport into independently owned handles.
    ///
    /// Both handles retain the same endpoint and shared topology. This is useful when a protocol
    /// accepts its dialer and acceptor as separate capabilities.
    pub fn split(self) -> (Self, Self)
    where
        E: Supervisor,
    {
        let other = Self {
            context: self.context.child("network_handle"),
            endpoint: self.endpoint,
            generation: self.generation,
            shared: Arc::clone(&self.shared),
        };
        (self, other)
    }
}

/// Established simulated reliable stream.
pub struct Connection<E: Clock> {
    sink: Sink<E>,
    stream: Stream<E>,
    origin: Option<Origin>,
}

impl<E: Clock> crate::Connection for Connection<E> {
    type Sink = Sink<E>;
    type Stream = Stream<E>;
    type Origin = Origin;

    fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
        (
            self.sink,
            self.stream,
            ConnectionInfo {
                origin: self.origin,
                transport: "deterministic",
            },
        )
    }
}

enum HalfState {
    Open,
    Active,
    Closed,
}

/// Write half of a simulated connection.
pub struct Sink<E: Clock> {
    context: E,
    shared: Arc<Shared<E>>,
    from: Endpoint,
    to: Endpoint,
    inner: crate::mocks::Sink,
    failure: Arc<Failure>,
    _lease: Arc<ConnectionLease<E>>,
    state: HalfState,
}

enum Route {
    Deliver(Duration),
    Fail,
    Blackhole,
}

struct TransferGuard<'a, E: Clock> {
    context: &'a E,
    shared: &'a Shared<E>,
    id: u64,
    active: bool,
}

impl<'a, E: Clock> TransferGuard<'a, E> {
    const fn new(context: &'a E, shared: &'a Shared<E>, id: u64) -> Self {
        Self {
            context,
            shared,
            id,
            active: true,
        }
    }

    const fn disarm(&mut self) {
        self.active = false;
    }
}

impl<E: Clock> Drop for TransferGuard<'_, E> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.shared.state.lock();
        advance_transfers(&mut state, self.context.current());
        state.transfers.remove(&self.id);
        rebalance_transfers(&mut state);
        let waiters = wake_transfers(&mut state);
        drop(state);
        wake_all(waiters);
    }
}

impl<E: Clock> Sink<E> {
    fn route(&self) -> Route {
        let mut state = self.shared.state.lock();
        let operation = state.next_operation;
        state.next_operation = state.next_operation.wrapping_add(1);

        let Some(from) = state.nodes.get(&self.from) else {
            state.statistics.failures += 1;
            return Route::Fail;
        };
        let Some(to) = state.nodes.get(&self.to) else {
            state.statistics.failures += 1;
            return Route::Fail;
        };
        if !from.online || !to.online || state.partitions.contains(&(self.from, self.to)) {
            state.statistics.failures += 1;
            return Route::Fail;
        }
        let Some(link) = state.links.get(&(self.from, self.to)).copied() else {
            state.statistics.failures += 1;
            return Route::Fail;
        };

        match link.behavior {
            Behavior::Fail => {
                state.statistics.failures += 1;
                return Route::Fail;
            }
            Behavior::Blackhole => {
                return Route::Blackhole;
            }
            Behavior::Deliver => {}
        }

        let jitter = deterministic_jitter(link.jitter, self.from, self.to, operation);
        Route::Deliver(link.latency.saturating_add(jitter))
    }

    fn record_blackhole(&self, recorded: &mut bool) {
        if *recorded {
            return;
        }
        self.shared.state.lock().statistics.blackholes += 1;
        *recorded = true;
    }

    async fn transmit(
        &self,
        len: usize,
        delivered: bool,
        blackhole_recorded: &mut bool,
    ) -> Result<(), Error> {
        let now = self.context.current();
        let (id, waiters) = {
            let mut state = self.shared.state.lock();
            advance_transfers(&mut state, now);
            let id = state.next_operation;
            state.next_operation = state.next_operation.wrapping_add(1);
            state.transfers.insert(
                id,
                Transfer {
                    from: self.from,
                    to: self.to,
                    delivered,
                    remaining: Fraction::from_integer(len as u128),
                    rate: Rate::Unlimited,
                },
            );
            rebalance_transfers(&mut state);
            let waiters = wake_transfers(&mut state);
            (id, waiters)
        };
        wake_all(waiters);
        let mut guard = TransferGuard::new(&self.context, &self.shared, id);

        loop {
            let now = self.context.current();
            let (remaining, rate, epoch, behavior, delivered) = {
                let mut state = self.shared.state.lock();
                advance_transfers(&mut state, now);
                let transfer = state
                    .transfers
                    .get(&id)
                    .expect("active transfer must remain registered");
                if transfer.remaining.is_zero() {
                    state.transfers.remove(&id);
                    rebalance_transfers(&mut state);
                    let waiters = wake_transfers(&mut state);
                    guard.disarm();
                    drop(state);
                    wake_all(waiters);
                    return Ok(());
                }
                let behavior = state
                    .links
                    .get(&(self.from, self.to))
                    .map_or(Behavior::Fail, |link| link.behavior);
                (
                    transfer.remaining,
                    transfer.rate,
                    state.transfer_epoch,
                    behavior,
                    transfer.delivered,
                )
            };

            let changed = TransferChanged {
                shared: &self.shared,
                epoch,
            };
            let duration = match behavior {
                Behavior::Deliver => bandwidth::duration(rate, remaining),
                Behavior::Blackhole if !delivered => bandwidth::duration(rate, remaining),
                Behavior::Blackhole => None,
                Behavior::Fail => return Err(Error::WriteFailed),
            };
            let Some(duration) = duration else {
                self.record_blackhole(blackhole_recorded);
                select! {
                    _ = self.failure.wait() => return Err(Error::WriteFailed),
                    _ = changed => continue,
                }
            };
            select! {
                _ = self.failure.wait() => return Err(Error::WriteFailed),
                _ = changed => continue,
                _ = self.context.sleep(duration) => {},
            }
        }
    }

    fn fail(&mut self) -> Result<(), Error> {
        self.failure.fail();
        self.inner.close();
        self.state = HalfState::Closed;
        Err(Error::WriteFailed)
    }

    async fn blackhole(&self, len: usize, recorded: &mut bool) -> Result<(), Error> {
        self.transmit(len, false, recorded).await?;
        self.record_blackhole(recorded);
        select! {
            _ = pending::<()>() => unreachable!(),
            _ = self.failure.wait() => Err(Error::WriteFailed),
        }
    }
}

impl<E: Clock> crate::Sink for Sink<E> {
    async fn send(&mut self, bufs: impl Into<IoBufs> + PlatformSend) -> Result<(), Error> {
        if matches!(self.state, HalfState::Active) {
            self.failure.fail();
            self.inner.close();
            self.state = HalfState::Closed;
            return Err(Error::Closed);
        }
        if matches!(self.state, HalfState::Closed) {
            return Err(Error::Closed);
        }
        if self.failure.is_failed() {
            return self.fail();
        }

        let bufs = bufs.into();
        let len = bufs.len();
        let route = self.route();
        let mut blackhole_recorded = false;
        self.state = HalfState::Active;

        match route {
            Route::Fail => return self.fail(),
            Route::Blackhole => {
                if self.blackhole(len, &mut blackhole_recorded).await.is_err() {
                    return self.fail();
                }
                unreachable!();
            }
            Route::Deliver(delay) => {
                select! {
                    _ = self.context.sleep(delay) => {},
                    _ = self.failure.wait() => return self.fail(),
                }
            }
        }

        // Dynamic topology changes are connection-fatal and are checked again
        // after simulated time advances.
        match self.route() {
            Route::Deliver(_) => {}
            Route::Fail => return self.fail(),
            Route::Blackhole => {
                if self.blackhole(len, &mut blackhole_recorded).await.is_err() {
                    return self.fail();
                }
                unreachable!();
            }
        }
        if self
            .transmit(len, true, &mut blackhole_recorded)
            .await
            .is_err()
        {
            return self.fail();
        }
        let sent = select! {
            result = self.inner.send(bufs) => result,
            _ = self.failure.wait() => return self.fail(),
        };
        if sent.is_err() || self.failure.is_failed() {
            return self.fail();
        }

        let mut state = self.shared.state.lock();
        state.statistics.deliveries += 1;
        state.statistics.bytes = state.statistics.bytes.saturating_add(len as u64);
        self.state = HalfState::Open;
        Ok(())
    }
}

/// Read half of a simulated connection.
pub struct Stream<E: Clock> {
    inner: crate::mocks::Stream,
    failure: Arc<Failure>,
    _lease: Arc<ConnectionLease<E>>,
    state: HalfState,
    _context: std::marker::PhantomData<E>,
}

impl<E: Clock> crate::Stream for Stream<E> {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if !matches!(self.state, HalfState::Open) || self.failure.is_failed() {
            self.state = HalfState::Closed;
            return Err(Error::Closed);
        }
        self.state = HalfState::Active;
        let result = select! {
            result = self.inner.recv(len) => result,
            _ = self.failure.wait() => {
                self.state = HalfState::Closed;
                return Err(Error::ReadFailed);
            },
        };
        match result {
            Ok(bufs) => {
                self.state = HalfState::Open;
                Ok(bufs)
            }
            Err(_) => {
                self.failure.fail();
                self.state = HalfState::Closed;
                Err(Error::ReadFailed)
            }
        }
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        self.inner.peek(max_len)
    }
}

/// Listener whose binding is released when dropped.
pub struct Listener<E: Clock> {
    endpoint: Endpoint,
    generation: u64,
    shared: Arc<Shared<E>>,
    _sender: mpsc::Sender<Connection<E>>,
    receiver: mpsc::Receiver<Connection<E>>,
}

impl<E: Clock> crate::Listener for Listener<E> {
    type Connection = Connection<E>;

    async fn accept(&mut self) -> Result<Self::Connection, Error> {
        self.receiver.recv().await.ok_or(Error::ReadFailed)
    }
}

impl<E: Clock> Drop for Listener<E> {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        if state
            .listeners
            .get(&self.endpoint)
            .is_some_and(|binding| binding.generation == self.generation)
        {
            state.listeners.remove(&self.endpoint);
        }
    }
}

impl<E: Clock> Acceptor for Network<E> {
    type Bind = Endpoint;
    type Connection = Connection<E>;
    type Listener = Listener<E>;

    async fn bind(&self, bind: &Endpoint) -> Result<Self::Listener, Error> {
        if *bind != self.endpoint {
            return Err(Error::BindFailed);
        }
        let mut state = self.shared.state.lock();
        if !state
            .nodes
            .get(bind)
            .is_some_and(|node| node.online && node.generation == self.generation)
            || state.listeners.contains_key(bind)
        {
            return Err(Error::BindFailed);
        }
        let (sender, receiver) = mpsc::channel(self.shared.config.accept_queue.get());
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        state.listeners.insert(
            *bind,
            Binding {
                generation,
                sender: sender.clone(),
            },
        );
        state.statistics.binds += 1;
        Ok(Listener {
            endpoint: *bind,
            generation,
            shared: Arc::clone(&self.shared),
            _sender: sender,
            receiver,
        })
    }
}

impl<E: Clock + Supervisor> Dialer for Network<E> {
    type Endpoint = Endpoint;
    type Connection = Connection<E>;

    fn supports(&self, _endpoint: &Endpoint) -> bool {
        true
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Self::Connection, Error> {
        let failure = Arc::new(Failure::default());
        let (sender, source_origin, remote_origin, remote_generation, connection_id) = {
            let mut state = self.shared.state.lock();
            let source = state
                .nodes
                .get(&self.endpoint)
                .ok_or(Error::ConnectionFailed)?;
            let target = state.nodes.get(endpoint).ok_or(Error::ConnectionFailed)?;
            if source.generation != self.generation
                || !source.online
                || !target.online
                || state.partitions.contains(&(self.endpoint, *endpoint))
                || !state.links.contains_key(&(self.endpoint, *endpoint))
            {
                return Err(Error::ConnectionFailed);
            }
            let binding = state
                .listeners
                .get(endpoint)
                .ok_or(Error::ConnectionFailed)?;
            let sender = binding.sender.clone();
            let source_origin = source.origin;
            let remote_origin = target.origin;
            let remote_generation = target.generation;
            let connection_id = state.next_connection;
            state.next_connection = state.next_connection.wrapping_add(1);
            state
                .connections
                .retain(|_, connection| connection.failure.upgrade().is_some());
            state.connections.insert(
                connection_id,
                ConnectionRecord {
                    a: self.endpoint,
                    b: *endpoint,
                    failure: Arc::downgrade(&failure),
                },
            );
            (
                sender,
                source_origin,
                remote_origin,
                remote_generation,
                connection_id,
            )
        };
        let lease = Arc::new(ConnectionLease {
            shared: Arc::downgrade(&self.shared),
            id: connection_id,
        });
        let (outgoing_sink, incoming_stream) =
            crate::mocks::Channel::init_with_buffer_size(self.shared.config.stream_buffer.get());
        let (incoming_sink, outgoing_stream) =
            crate::mocks::Channel::init_with_buffer_size(self.shared.config.stream_buffer.get());

        let outgoing = Connection {
            sink: Sink {
                context: self.context.child("outgoing_sink"),
                shared: Arc::clone(&self.shared),
                from: self.endpoint,
                to: *endpoint,
                inner: outgoing_sink,
                failure: Arc::clone(&failure),
                _lease: Arc::clone(&lease),
                state: HalfState::Open,
            },
            stream: Stream {
                inner: outgoing_stream,
                failure: Arc::clone(&failure),
                _lease: Arc::clone(&lease),
                state: HalfState::Open,
                _context: std::marker::PhantomData,
            },
            origin: remote_origin,
        };
        let incoming = Connection {
            sink: Sink {
                context: self.context.child("incoming_sink"),
                shared: Arc::clone(&self.shared),
                from: *endpoint,
                to: self.endpoint,
                inner: incoming_sink,
                failure: Arc::clone(&failure),
                _lease: Arc::clone(&lease),
                state: HalfState::Open,
            },
            stream: Stream {
                inner: incoming_stream,
                failure: Arc::clone(&failure),
                _lease: lease,
                state: HalfState::Open,
                _context: std::marker::PhantomData,
            },
            origin: source_origin,
        };

        sender
            .try_send(incoming)
            .map_err(|_| Error::ConnectionFailed)?;
        let mut state = self.shared.state.lock();
        let current_source = state.nodes.get(&self.endpoint);
        let current_target = state.nodes.get(endpoint);
        if failure.is_failed()
            || !current_source.is_some_and(|node| node.generation == self.generation)
            || !current_target.is_some_and(|node| node.generation == remote_generation)
        {
            return Err(Error::ConnectionFailed);
        }
        state.statistics.connections += 1;
        Ok(outgoing)
    }
}

fn deterministic_jitter(
    jitter: Duration,
    from: Endpoint,
    to: Endpoint,
    operation: u64,
) -> Duration {
    let upper = jitter.as_nanos();
    if upper == 0 {
        return Duration::ZERO;
    }
    let mut value = from.0 ^ to.0.rotate_left(21) ^ operation.rotate_left(43);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    let nanos = (value as u128) % upper.saturating_add(1);
    Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Connection as _, IoBuf, Listener as _, Runner, Scheduler as _, Sink as _, Stream as _,
        deterministic, reschedule,
    };
    use commonware_macros::select;
    use futures::{join, poll};

    const A: Endpoint = Endpoint::new(1);
    const B: Endpoint = Endpoint::new(2);

    fn setup(
        context: deterministic::Context,
    ) -> (
        Oracle<deterministic::Context>,
        Network<deterministic::Context>,
        Network<deterministic::Context>,
    ) {
        let oracle = Oracle::new(Config::default());
        let a = oracle.register(context.child("node_a"), A, Some(Origin::new(11)));
        let b = oracle.register(context, B, None);
        oracle.set_link(A, B, Link::default()).unwrap();
        oracle.set_link(B, A, Link::default()).unwrap();
        (oracle, a, b)
    }

    #[test]
    fn lifecycle_order_and_optional_origin() {
        deterministic::Runner::seeded(7).start(|context| async move {
            let (oracle, a, b) = setup(context);
            let mut listener = b.bind(&B).await.unwrap();
            let outgoing = a.dial(&B).await.unwrap();
            let incoming = listener.accept().await.unwrap();
            let (mut a_sink, mut a_stream, a_info) = outgoing.split();
            let (mut b_sink, mut b_stream, b_info) = incoming.split();
            assert_eq!(a_info.origin, None);
            assert_eq!(b_info.origin, Some(Origin::new(11)));

            a_sink.send(IoBuf::from(&b"one-two"[..])).await.unwrap();
            assert_eq!(b_stream.recv(3).await.unwrap().coalesce(), b"one");
            assert_eq!(b_stream.recv(4).await.unwrap().coalesce(), b"-two");
            b_sink.send(IoBuf::from(&b"reply"[..])).await.unwrap();
            assert_eq!(a_stream.recv(5).await.unwrap().coalesce(), b"reply");

            drop(listener);
            assert!(b.bind(&B).await.is_ok());
            assert_eq!(oracle.statistics().deliveries, 2);
            assert_eq!(oracle.statistics().bytes, 12);
        });
    }

    #[test]
    fn split_handles_share_one_node() {
        deterministic::Runner::seeded(14).start(|context| async move {
            let (_oracle, a, b) = setup(context);
            let (a_dialer, a_acceptor) = a.split();
            let mut a_listener = a_acceptor.bind(&A).await.unwrap();
            let mut b_listener = b.bind(&B).await.unwrap();

            let _to_a = b.dial(&A).await.unwrap();
            let _at_a = a_listener.accept().await.unwrap();
            let _to_b = a_dialer.dial(&B).await.unwrap();
            let _at_b = b_listener.accept().await.unwrap();
        });
    }

    #[test]
    fn reregistering_node_replaces_listener_and_connections() {
        deterministic::Runner::seeded(18).start(|context| async move {
            let (oracle, a, b) = setup(context.child("setup"));
            let mut old_listener = b.bind(&B).await.unwrap();
            let old_outgoing = a.dial(&B).await.unwrap();
            let old_incoming = old_listener.accept().await.unwrap();
            let (mut old_sink, mut old_stream, _) = old_outgoing.split();
            let (mut old_remote_sink, mut old_remote_stream, _) = old_incoming.split();

            let replacement = oracle.register(context.child("replacement"), B, None);
            let mut replacement_listener = replacement.bind(&B).await.unwrap();

            assert!(matches!(b.bind(&B).await, Err(Error::BindFailed)));
            assert!(matches!(b.dial(&A).await, Err(Error::ConnectionFailed)));
            assert!(matches!(
                old_sink.send(IoBuf::from(&b"stale"[..])).await,
                Err(Error::WriteFailed)
            ));
            assert!(matches!(old_stream.recv(1).await, Err(Error::Closed)));
            assert!(matches!(
                old_remote_sink.send(IoBuf::from(&b"stale"[..])).await,
                Err(Error::WriteFailed)
            ));
            assert!(matches!(
                old_remote_stream.recv(1).await,
                Err(Error::Closed)
            ));
            drop(old_listener);

            let new_outgoing = a.dial(&B).await.unwrap();
            let _new_incoming = replacement_listener.accept().await.unwrap();
            let (mut new_sink, _, _) = new_outgoing.split();
            new_sink.send(IoBuf::from(&b"fresh"[..])).await.unwrap();
        });
    }

    #[test]
    fn final_connection_owner_removes_record() {
        deterministic::Runner::seeded(15).start(|context| async move {
            let (oracle, a, b) = setup(context);
            let mut listener = b.bind(&B).await.unwrap();
            let mut connections = Vec::new();

            for _ in 0..32 {
                let outgoing = a.dial(&B).await.unwrap();
                let incoming = listener.accept().await.unwrap();
                connections.push((outgoing, incoming));
            }

            assert_eq!(oracle.shared.state.lock().connections.len(), 32);
            drop(connections);
            assert!(oracle.shared.state.lock().connections.is_empty());
        });
    }

    #[test]
    fn topology_and_bandwidth_can_be_configured_before_registration() {
        deterministic::Runner::seeded(17).start(|context| async move {
            let oracle = Oracle::new(Config::default());
            oracle.set_link(A, B, Link::default()).unwrap();
            oracle.set_link(B, A, Link::default()).unwrap();
            oracle.limit_bandwidth(A, Some(10), None).unwrap();

            let a = oracle.register(context.child("a"), A, Some(Origin::new(1)));
            let b = oracle.register(context.child("b"), B, Some(Origin::new(2)));
            let mut listener = b.bind(&B).await.unwrap();
            let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
            let _incoming = listener.accept().await.unwrap();

            let started = context.current();
            sink.send(IoBuf::from(vec![0; 10])).await.unwrap();
            assert_eq!(
                context.current().duration_since(started).unwrap(),
                Duration::from_secs(1)
            );
        });
    }

    #[test]
    fn dynamic_partition_is_connection_fatal() {
        deterministic::Runner::seeded(8).start(|context| async move {
            let (oracle, a, b) = setup(context);
            let mut listener = b.bind(&B).await.unwrap();
            let connection = a.dial(&B).await.unwrap();
            let _incoming = listener.accept().await.unwrap();
            let (mut sink, mut stream, _) = connection.split();

            oracle.partition(A, B, true);
            assert!(matches!(
                sink.send(IoBuf::from(&b"x"[..])).await,
                Err(Error::WriteFailed)
            ));
            assert!(matches!(
                sink.send(IoBuf::from(&b"y"[..])).await,
                Err(Error::Closed)
            ));
            assert!(matches!(stream.recv(1).await, Err(Error::Closed)));
            assert!(matches!(a.dial(&B).await, Err(Error::ConnectionFailed)));
        });
    }

    #[test]
    fn latency_jitter_and_bandwidth_are_deterministic() {
        fn run() -> (Duration, Statistics) {
            deterministic::Runner::seeded(9).start(|context| async move {
                let started = context.current();
                let (oracle, a, b) = setup(context.child("setup"));
                oracle
                    .set_link(
                        A,
                        B,
                        Link::new(Duration::from_millis(10)).with_jitter(Duration::from_millis(5)),
                    )
                    .unwrap();
                oracle.limit_bandwidth(A, Some(1_000), None).unwrap();
                let mut listener = b.bind(&B).await.unwrap();
                let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
                let _incoming = listener.accept().await.unwrap();
                sink.send(IoBuf::from(vec![0; 100])).await.unwrap();
                (
                    context.current().duration_since(started).unwrap(),
                    oracle.statistics(),
                )
            })
        }

        let first = run();
        let second = run();
        assert_eq!(first, second);
        assert!(first.0 >= Duration::from_millis(110));
        assert!(first.0 <= Duration::from_millis(115));
        assert_eq!(first.1.bytes, 100);
    }

    #[test]
    fn offline_and_directional_links() {
        deterministic::Runner::seeded(10).start(|context| async move {
            let (oracle, a, b) = setup(context);
            let _listener = b.bind(&B).await.unwrap();
            oracle.remove_link(A, B);
            assert!(matches!(a.dial(&B).await, Err(Error::ConnectionFailed)));
            oracle.set_link(A, B, Link::default()).unwrap();
            oracle.set_online(B, false).unwrap();
            assert!(matches!(a.dial(&B).await, Err(Error::ConnectionFailed)));
        });
    }

    #[test]
    fn canceled_blackhole_poisons_sink() {
        deterministic::Runner::seeded(11).start(|context| async move {
            let (oracle, a, b) = setup(context.child("setup"));
            oracle
                .set_link(
                    A,
                    B,
                    Link::default().with_behavior(Behavior::Blackhole),
                )
                .unwrap();
            let mut listener = b.bind(&B).await.unwrap();
            let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
            let (_, mut remote_stream, _) = listener.accept().await.unwrap().split();
            let mut receive = Box::pin(remote_stream.recv(1));
            assert!(poll!(&mut receive).is_pending());

            select! {
                result = sink.send(IoBuf::from(&b"lost"[..])) => panic!("blackhole completed: {result:?}"),
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert!(matches!(
                sink.send(IoBuf::from(&b"after-cancel"[..])).await,
                Err(Error::Closed)
            ));
            assert!(matches!(receive.await, Err(Error::ReadFailed)));
            assert_eq!(oracle.statistics().blackholes, 1);
        });
    }

    #[test]
    fn failure_interrupts_backpressured_send() {
        deterministic::Runner::seeded(19).start(|context| async move {
            let config = Config {
                stream_buffer: NonZeroUsize::new(1).unwrap(),
                ..Config::default()
            };
            let oracle = Oracle::new(config);
            let a = oracle.register(context.child("a"), A, Some(Origin::new(1)));
            let b = oracle.register(context.child("b"), B, Some(Origin::new(2)));
            oracle.set_link(A, B, Link::default()).unwrap();
            oracle.set_link(B, A, Link::default()).unwrap();
            let mut listener = b.bind(&B).await.unwrap();
            let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
            let (_, mut remote_stream, _) = listener.accept().await.unwrap().split();

            let mut receive = Box::pin(remote_stream.recv(8));
            assert!(poll!(&mut receive).is_pending());
            let mut send = Box::pin(sink.send(IoBuf::from(&b"blocked"[..])));
            assert!(poll!(&mut send).is_pending());
            oracle.partition(A, B, true);

            assert!(matches!(send.await, Err(Error::WriteFailed)));
            assert!(matches!(receive.await, Err(Error::ReadFailed)));
            assert_eq!(oracle.statistics().deliveries, 0);
        });
    }

    #[test]
    fn dynamic_blackhole_keeps_send_pending() {
        deterministic::Runner::seeded(20).start(|context| async move {
            let (oracle, a, b) = setup(context.child("setup"));
            oracle
                .set_link(A, B, Link::new(Duration::from_secs(1)))
                .unwrap();
            let mut listener = b.bind(&B).await.unwrap();
            let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
            let _incoming = listener.accept().await.unwrap();

            let send = context
                .child("send")
                .spawn(|_| async move { sink.send(IoBuf::from(&b"blocked"[..])).await });
            reschedule().await;
            oracle
                .set_link(A, B, Link::default().with_behavior(Behavior::Blackhole))
                .unwrap();

            select! {
                result = send => panic!("dynamic blackhole completed: {result:?}"),
                _ = context.sleep(Duration::from_secs(2)) => {},
            }
            assert_eq!(oracle.statistics().blackholes, 1);
        });
    }

    #[test]
    fn zero_bandwidth_records_one_blackhole() {
        deterministic::Runner::seeded(18).start(|context| async move {
            let (oracle, a, b) = setup(context.child("setup"));
            oracle.limit_bandwidth(A, Some(0), None).unwrap();
            let mut listener = b.bind(&B).await.unwrap();
            let (mut sink, _, _) = a.dial(&B).await.unwrap().split();
            let _incoming = listener.accept().await.unwrap();

            select! {
                result = sink.send(IoBuf::from(&b"blocked"[..])) => panic!("zero-bandwidth send completed: {result:?}"),
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert_eq!(oracle.statistics().blackholes, 1);
            assert!(matches!(
                sink.send(IoBuf::from(&b"after-cancel"[..])).await,
                Err(Error::Closed)
            ));
            assert_eq!(oracle.statistics().blackholes, 1);
        });
    }

    #[test]
    fn simultaneous_flows_share_egress() {
        deterministic::Runner::seeded(12).start(|context| async move {
            let oracle = Oracle::new(Config::default());
            let a = oracle.register(context.child("a"), A, Some(Origin::new(1)));
            let b = oracle.register(context.child("b"), B, Some(Origin::new(2)));
            let c_endpoint = Endpoint::new(3);
            let c = oracle.register(context.child("c"), c_endpoint, Some(Origin::new(3)));
            oracle.set_link(A, B, Link::default()).unwrap();
            oracle.set_link(B, A, Link::default()).unwrap();
            oracle.set_link(A, c_endpoint, Link::default()).unwrap();
            oracle.set_link(c_endpoint, A, Link::default()).unwrap();
            oracle.limit_bandwidth(A, Some(100), None).unwrap();

            let mut b_listener = b.bind(&B).await.unwrap();
            let mut c_listener = c.bind(&c_endpoint).await.unwrap();
            let (mut b_sink, _, _) = a.dial(&B).await.unwrap().split();
            let (mut c_sink, _, _) = a.dial(&c_endpoint).await.unwrap().split();
            let _b_incoming = b_listener.accept().await.unwrap();
            let _c_incoming = c_listener.accept().await.unwrap();

            let started = context.current();
            let (b_result, c_result) = join!(
                b_sink.send(IoBuf::from(vec![0; 100])),
                c_sink.send(IoBuf::from(vec![0; 100])),
            );
            b_result.unwrap();
            c_result.unwrap();
            assert_eq!(
                context.current().duration_since(started).unwrap(),
                Duration::from_secs(2)
            );
        });
    }

    #[test]
    fn blackholed_flow_consumes_egress_but_not_ingress() {
        deterministic::Runner::seeded(16).start(|context| async move {
            let oracle = Oracle::new(Config::default());
            let a = oracle.register(context.child("a"), A, Some(Origin::new(1)));
            let b = oracle.register(context.child("b"), B, Some(Origin::new(2)));
            let c_endpoint = Endpoint::new(3);
            let c = oracle.register(context.child("c"), c_endpoint, Some(Origin::new(3)));
            oracle
                .set_link(A, B, Link::default().with_behavior(Behavior::Blackhole))
                .unwrap();
            oracle.set_link(B, A, Link::default()).unwrap();
            oracle.set_link(A, c_endpoint, Link::default()).unwrap();
            oracle.set_link(c_endpoint, A, Link::default()).unwrap();
            oracle.limit_bandwidth(A, Some(10), None).unwrap();
            oracle.limit_bandwidth(B, None, Some(0)).unwrap();

            let mut b_listener = b.bind(&B).await.unwrap();
            let mut c_listener = c.bind(&c_endpoint).await.unwrap();
            let (mut blackholed_sink, _, _) = a.dial(&B).await.unwrap().split();
            let (mut delivered_sink, _, _) = a.dial(&c_endpoint).await.unwrap().split();
            let _b_incoming = b_listener.accept().await.unwrap();
            let _c_incoming = c_listener.accept().await.unwrap();

            let blackholed = context
                .child("blackholed")
                .spawn(|_| async move { blackholed_sink.send(IoBuf::from(vec![0; 10])).await });
            reschedule().await;

            let started = context.current();
            delivered_sink.send(IoBuf::from(vec![0; 10])).await.unwrap();
            assert_eq!(
                context.current().duration_since(started).unwrap(),
                Duration::from_secs(2)
            );
            assert!(oracle.shared.state.lock().transfers.is_empty());
            blackholed.abort();
        });
    }

    #[test]
    fn partition_wakes_pending_receive() {
        deterministic::Runner::seeded(13).start(|context| async move {
            let (oracle, a, b) = setup(context);
            let mut listener = b.bind(&B).await.unwrap();
            let connection = a.dial(&B).await.unwrap();
            let _incoming = listener.accept().await.unwrap();
            let (_sink, mut stream, _) = connection.split();

            let mut receive = Box::pin(stream.recv(1));
            assert!(poll!(&mut receive).is_pending());
            oracle.partition(A, B, true);
            assert!(matches!(receive.await, Err(Error::ReadFailed)));
        });
    }
}
