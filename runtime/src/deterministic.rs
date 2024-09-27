//! A deterministic runtime that randomly selects tasks to run based on a seed
//!
//! # Panics
//!
//! If any task panics, the runtime will panic (and shutdown).
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::{Executor, Config}};
//! use prometheus_client::{registry::Registry, metrics::{counter::Counter, family::Family, gauge::Gauge}};
//! use std::{sync::{Mutex, Arc}, time::Duration};
//!
//! let cfg = Config::default();
//! let (executor, runtime, auditor) = Executor::init(cfg);
//! executor.start(async move {
//!     println!("Parent started");
//!     let result = runtime.spawn(async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! println!("Auditor state: {}", auditor.state());
//! ```

use crate::metrics::Metrics;
use crate::{Clock, Error, Handle};
use bytes::Bytes;
use futures::{
    channel::mpsc,
    task::{waker_ref, ArcWake},
    SinkExt, StreamExt,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::registry::Registry;
use rand::{prelude::SliceRandom, rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{BinaryHeap, HashMap},
    future::Future,
    mem::replace,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::trace;

/// Range of ephemeral ports assigned to dialers.
const EPHEMERAL_PORT_RANGE: Range<u16> = 32768..61000;

/// Track the state of the runtime for determinism auditing.
pub struct Auditor {
    hash: Mutex<String>,
}

impl Auditor {
    fn new() -> Self {
        Self {
            hash: Mutex::new(String::new()),
        }
    }

    fn process_task(&self, task: u128) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"process_task");
        hasher.update(task.to_be_bytes());
        *hash = format!("{:x}", hasher.finalize());
    }

    fn bind(&self, address: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"bind");
        hasher.update(address.to_string().as_bytes());
        *hash = format!("{:x}", hasher.finalize());
    }

    fn dial(&self, dialer: SocketAddr, dialee: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"dial");
        hasher.update(dialer.to_string().as_bytes());
        hasher.update(dialee.to_string().as_bytes());
        *hash = format!("{:x}", hasher.finalize());
    }

    fn accept(&self, dialee: SocketAddr, dialer: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"accept");
        hasher.update(dialee.to_string().as_bytes());
        hasher.update(dialer.to_string().as_bytes());
        *hash = format!("{:x}", hasher.finalize());
    }

    fn send(&self, sender: SocketAddr, receiver: SocketAddr, message: Bytes) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"send");
        hasher.update(sender.to_string().as_bytes());
        hasher.update(receiver.to_string().as_bytes());
        hasher.update(&message);
        *hash = format!("{:x}", hasher.finalize());
    }

    fn recv(&self, receiver: SocketAddr, sender: SocketAddr, message: Bytes) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"recv");
        hasher.update(receiver.to_string().as_bytes());
        hasher.update(sender.to_string().as_bytes());
        hasher.update(&message);
        *hash = format!("{:x}", hasher.finalize());
    }

    fn rand(&self, method: String) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(hash.as_bytes());
        hasher.update(b"rand");
        hasher.update(method.as_bytes());
        *hash = format!("{:x}", hasher.finalize());
    }

    /// Generate a representation of the current state of the runtime.
    ///
    /// This can be used to ensure that logic running on top
    /// of the runtime is interacting deterministically.
    pub fn state(&self) -> String {
        self.hash.lock().unwrap().clone()
    }
}

struct Task {
    id: u128,
    tasks: Arc<Tasks>,

    root: bool,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,

    completed: Mutex<bool>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.tasks.enqueue(arc_self.clone());
    }
}

struct Tasks {
    counter: Mutex<u128>,
    queue: Mutex<Vec<Arc<Task>>>,
}

impl Tasks {
    fn register(
        arc_self: &Arc<Self>,
        root: bool,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let mut queue = arc_self.queue.lock().unwrap();
        let id = {
            let mut l = arc_self.counter.lock().unwrap();
            let old = *l;
            *l = l.checked_add(1).expect("task counter overflow");
            old
        };
        queue.push(Arc::new(Task {
            id,
            root,
            future: Mutex::new(future),
            tasks: arc_self.clone(),
            completed: Mutex::new(false),
        }));
    }

    fn enqueue(&self, task: Arc<Task>) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(task);
    }

    fn drain(&self) -> Vec<Arc<Task>> {
        let mut queue = self.queue.lock().unwrap();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

/// Configuration for the `deterministic` runtime.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Seed for the random number generator.
    pub seed: u64,

    /// The cycle duration determines how much time is advanced after each iteration of the event
    /// loop. This is useful to prevent starvation if some task never yields.
    pub cycle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::default())),
            seed: 42,
            cycle: Duration::from_millis(1),
        }
    }
}

/// Deterministic runtime that randomly selects tasks to run based on a seed.
pub struct Executor {
    cycle: Duration,
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    rng: Mutex<StdRng>,
    time: Mutex<SystemTime>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
}

impl Executor {
    /// Initialize a new `deterministic` runtime with the given seed and cycle duration.
    pub fn init(cfg: Config) -> (Runner, Context, Arc<Auditor>) {
        let metrics = Arc::new(Metrics::init(cfg.registry));
        let auditor = Arc::new(Auditor::new());
        let executor = Arc::new(Self {
            cycle: cfg.cycle,
            metrics: metrics.clone(),
            auditor: auditor.clone(),
            rng: Mutex::new(StdRng::seed_from_u64(cfg.seed)),
            time: Mutex::new(UNIX_EPOCH),
            tasks: Arc::new(Tasks {
                queue: Mutex::new(Vec::new()),
                counter: Mutex::new(0),
            }),
            sleeping: Mutex::new(BinaryHeap::new()),
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context {
                executor,
                networking: Arc::new(Networking::new(metrics, auditor.clone())),
            },
            auditor,
        )
    }
}
/// Implementation of [`crate::Runner`] for the `deterministic` runtime.
pub struct Runner {
    executor: Arc<Executor>,
}

impl crate::Runner for Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Add root task to the queue
        let output = Arc::new(Mutex::new(None));
        Tasks::register(
            &self.executor.tasks,
            true,
            Box::pin({
                let output = output.clone();
                async move {
                    *output.lock().unwrap() = Some(f.await);
                }
            }),
        );

        // Process tasks until root task completes or progress stalls
        let mut iter = 0;
        loop {
            // Snapshot available tasks
            let mut tasks = self.executor.tasks.drain();

            // Shuffle tasks
            {
                let mut rng = self.executor.rng.lock().unwrap();
                tasks.shuffle(&mut *rng);
            }

            // Run all snapshotted tasks
            //
            // This approach is more efficient than randomly selecting a task one-at-a-time
            // because it ensures we don't pull the same pending task multiple times in a row (without
            // processing a different task required for other tasks to make progress).
            trace!(iter, tasks = tasks.len(), "starting loop");
            for task in tasks {
                // Record task for auditing
                self.executor.auditor.process_task(task.id);

                // Check if task is already complete
                if *task.completed.lock().unwrap() {
                    trace!(id = task.id, "skipping already completed task");
                    continue;
                }
                trace!(id = task.id, "processing task");

                // Prepare task for polling
                let waker = waker_ref(&task);
                let mut context = task::Context::from_waker(&waker);
                let mut future = task.future.lock().unwrap();

                // Record task poll
                self.executor.metrics.record_task_poll();

                // Task is re-queued in its `wake_by_ref` implementation as soon as we poll here (regardless
                // of whether it is Pending/Ready).
                let pending = future.as_mut().poll(&mut context).is_pending();
                if pending {
                    trace!(id = task.id, "task is still pending");
                    continue;
                }

                // Mark task as completed
                *task.completed.lock().unwrap() = true;
                trace!(id = task.id, "task is complete");

                // Root task completed
                if task.root {
                    return output.lock().unwrap().take().unwrap();
                }
            }

            // Advance time by cycle
            //
            // This approach prevents starvation if some task never yields (to approximate this,
            // duration can be set to 1ns).
            let mut current;
            {
                let mut time = self.executor.time.lock().unwrap();
                *time += self.executor.cycle;
                current = *time;
            }
            trace!(
                now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                "time advanced",
            );

            // Skip time if there is nothing to do
            if self.executor.tasks.len() == 0 {
                let mut skip = None;
                {
                    let sleeping = self.executor.sleeping.lock().unwrap();
                    if let Some(next) = sleeping.peek() {
                        if next.time > current {
                            skip = Some(next.time);
                        }
                    }
                }
                if skip.is_some() {
                    {
                        let mut time = self.executor.time.lock().unwrap();
                        *time = skip.unwrap();
                        current = *time;
                    }
                    trace!(
                        now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        "time skipped",
                    );
                }
            }

            // Wake all sleeping tasks that are ready
            let mut to_wake = Vec::new();
            let mut remaining;
            {
                let mut sleeping = self.executor.sleeping.lock().unwrap();
                while let Some(next) = sleeping.peek() {
                    if next.time <= current {
                        let sleeper = sleeping.pop().unwrap();
                        to_wake.push(sleeper.waker);
                    } else {
                        break;
                    }
                }
                remaining = sleeping.len();
            }
            for waker in to_wake {
                waker.wake();
            }

            // Account for remaining tasks
            remaining += self.executor.tasks.len();

            // If there are no tasks to run and no tasks sleeping, the executor is stalled
            // and will never finish.
            if remaining == 0 {
                panic!("runtime stalled");
            }
            iter += 1;
        }
    }
}

/// Implementation of [`crate::Spawner`] and [`crate::Clock`]
/// for the `deterministic` runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
    networking: Arc<Networking>,
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (f, handle) = Handle::init(f, false);
        Tasks::register(&self.executor.tasks, false, Box::pin(f));
        self.executor.metrics.record_task_spawned();
        handle
    }
}

struct Sleeper {
    executor: Arc<Executor>,
    time: SystemTime,
    registered: bool,
}

struct Alarm {
    time: SystemTime,
    waker: Waker,
}

impl PartialEq for Alarm {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

impl Eq for Alarm {}

impl PartialOrd for Alarm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alarm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the ordering for min-heap
        other.time.cmp(&self.time)
    }
}

impl Future for Sleeper {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        {
            let current_time = *self.executor.time.lock().unwrap();
            if current_time >= self.time {
                return Poll::Ready(());
            }
        }
        if !self.registered {
            self.registered = true;
            self.executor.sleeping.lock().unwrap().push(Alarm {
                time: self.time,
                waker: cx.waker().clone(),
            });
        }
        Poll::Pending
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        *self.executor.time.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        let time = self
            .current()
            .checked_add(duration)
            .expect("overflow when setting wake time");
        Sleeper {
            executor: self.executor.clone(),

            time,
            registered: false,
        }
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        Sleeper {
            executor: self.executor.clone(),

            time: deadline,
            registered: false,
        }
    }
}

impl GClock for Context {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for Context {}

type Dialable = mpsc::UnboundedSender<(
    SocketAddr,
    mpsc::UnboundedSender<Bytes>,   // Dialee -> Dialer
    mpsc::UnboundedReceiver<Bytes>, // Dialer -> Dialee
)>;

/// Implementation of [`crate::Network`] for the `deterministic` runtime.
///
/// When a dialer connects to a dialee, the dialee is given a new ephemeral port
/// from the range `32768..61000`. To keep things simple, it is not possible to
/// bind to an ephemeral port. Likewise, if ports are not reused and when exhausted,
/// the runtime will panic.
struct Networking {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    ephemeral: Mutex<u16>,
    listeners: Mutex<HashMap<SocketAddr, Dialable>>,
}

impl Networking {
    fn new(metrics: Arc<Metrics>, auditor: Arc<Auditor>) -> Self {
        Self {
            metrics,
            auditor,
            ephemeral: Mutex::new(EPHEMERAL_PORT_RANGE.start),
            listeners: Mutex::new(HashMap::new()),
        }
    }

    fn bind(&self, socket: SocketAddr) -> Result<Listener, Error> {
        self.auditor.bind(socket);

        // Ensure the port is not in the ephemeral range
        if EPHEMERAL_PORT_RANGE.contains(&socket.port()) {
            return Err(Error::BindFailed);
        }

        // Ensure the port is not already bound
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(&socket) {
            return Err(Error::BindFailed);
        }

        // Bind the socket
        let (sender, receiver) = mpsc::unbounded();
        listeners.insert(socket, sender.clone());
        Ok(Listener {
            auditor: self.auditor.clone(),
            address: socket,
            listener: receiver,
            metrics: self.metrics.clone(),
        })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        // Assign dialer a port from the ephemeral range
        let dialer = {
            let mut ephemeral = self.ephemeral.lock().unwrap();
            let dialer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *ephemeral);
            *ephemeral = ephemeral
                .checked_add(1)
                .expect("ephemeral port range exhausted");
            dialer
        };
        self.auditor.dial(dialer, socket);

        // Get dialee
        let mut sender = {
            let listeners = self.listeners.lock().unwrap();
            let sender = listeners.get(&socket).ok_or(Error::ConnectionFailed)?;
            sender.clone()
        };

        // Construct connection
        let (dialer_sender, dialer_receiver) = mpsc::unbounded();
        let (dialee_sender, dialee_receiver) = mpsc::unbounded();
        sender
            .send((dialer, dialer_sender, dialee_receiver))
            .await
            .map_err(|_| Error::ConnectionFailed)?;
        Ok((
            Sink {
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                sender: dialee_sender,
                metrics: self.metrics.clone(),
            },
            Stream {
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                receiver: dialer_receiver,
                metrics: self.metrics.clone(),
            },
        ))
    }
}

impl crate::Network<Listener, Sink, Stream> for Context {
    async fn bind(&self, socket: SocketAddr) -> Result<Listener, Error> {
        self.networking.bind(socket)
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        self.networking.dial(socket).await
    }
}

pub struct Listener {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(
        SocketAddr,
        mpsc::UnboundedSender<Bytes>,
        mpsc::UnboundedReceiver<Bytes>,
    )>,
}

impl crate::Listener<Sink, Stream> for Listener {
    async fn accept(&mut self) -> Result<(SocketAddr, Sink, Stream), Error> {
        let (socket, sender, receiver) = self.listener.next().await.ok_or(Error::ReadFailed)?;
        self.auditor.accept(self.address, socket);
        Ok((
            socket,
            Sink {
                metrics: self.metrics.clone(),
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                sender,
            },
            Stream {
                metrics: self.metrics.clone(),
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                receiver,
            },
        ))
    }
}

pub struct Sink {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    sender: mpsc::UnboundedSender<Bytes>,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: Bytes) -> Result<(), Error> {
        self.auditor.send(self.me, self.peer, msg.clone());
        self.metrics.record_bandwidth(self.me, self.peer, msg.len());
        self.sender.send(msg).await.map_err(|_| Error::WriteFailed)
    }
}

pub struct Stream {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl crate::Stream for Stream {
    async fn recv(&mut self) -> Result<Bytes, Error> {
        let msg = self.receiver.next().await.ok_or(Error::ReadFailed)?;
        self.auditor.recv(self.me, self.peer, msg.clone());
        self.metrics.record_bandwidth(self.peer, self.me, msg.len());
        Ok(msg)
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        self.executor.auditor.rand("next_u32".to_string());
        self.executor.rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.executor.auditor.rand("next_u64".to_string());
        self.executor.rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.executor.auditor.rand("fill_bytes".to_string());
        self.executor.rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.executor.auditor.rand("try_fill_bytes".to_string());
        self.executor.rng.lock().unwrap().try_fill_bytes(dest)
    }
}

impl CryptoRng for Context {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;
    use futures::task::noop_waker;
    use std::net::{IpAddr, Ipv4Addr};

    fn run_with_seed(seed: u64) -> (String, Vec<usize>) {
        let cfg = Config {
            seed,
            ..Default::default()
        };
        let (executor, runtime, auditor) = Executor::init(cfg);
        let messages = run_tasks(5, executor, runtime);
        (auditor.state(), messages)
    }

    #[test]
    fn test_same_seed_same_order() {
        // Generate initial outputs
        let mut outputs = Vec::new();
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            outputs.push(output);
        }

        // Ensure they match
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            assert_eq!(output, outputs[seed as usize]);
        }
    }

    #[test]
    fn test_different_seeds_different_order() {
        let output1 = run_with_seed(12345);
        let output2 = run_with_seed(54321);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_alarm_min_heap() {
        // Populate heap
        let now = SystemTime::now();
        let alarms = vec![
            Alarm {
                time: now + Duration::new(10, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(15, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
        ];
        let mut heap = BinaryHeap::new();
        for alarm in alarms {
            heap.push(alarm);
        }

        // Verify min-heap
        let mut sorted_times = Vec::new();
        while let Some(alarm) = heap.pop() {
            sorted_times.push(alarm.time);
        }
        assert_eq!(
            sorted_times,
            vec![
                now + Duration::new(5, 0),
                now + Duration::new(5, 0),
                now + Duration::new(10, 0),
                now + Duration::new(15, 0),
            ]
        );
    }
}
