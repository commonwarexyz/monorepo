use crate::{signal, Error, Handle, SinkOf, StreamOf};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::registry::Metric;
use rand::{CryptoRng, RngCore};
use std::{
    future::Future,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

const MISSING_CONTEXT: &str = "runtime context missing";
const DUPLICATE_CONTEXT: &str = "runtime context already present";

/// Spawn a task using a [`Cell`] by taking its context, executing the provided
/// async block, and restoring the context before the block completes.
///
/// The macro uses the context's default spawn configuration (supervised, shared executor with
/// `blocking == false`). If you need to mark the task as blocking or request a dedicated thread,
/// take the context via [`Cell::take`] and call the appropriate [`crate::Spawner`] methods before spawning.
#[macro_export]
macro_rules! spawn_cell {
    ($cell:expr, $body:expr $(,)?) => {{
        let __commonware_context = $cell.take();
        __commonware_context.spawn(move |context| async move {
            $cell.restore(context);
            $body
        })
    }};
}

/// A wrapper around context that allows it to be taken and returned without requiring
/// all interactions to unwrap (as with `Option<C>`).
// TODO(#1833): Remove `Clone`
#[derive(Clone, Debug)]
pub enum Cell<C> {
    /// A context available for use.
    Present(C),
    /// The context has been taken elsewhere.
    Missing,
}

impl<C> Cell<C> {
    /// Create a new slot containing `context`.
    pub const fn new(context: C) -> Self {
        Self::Present(context)
    }

    /// Remove the context from the slot, panicking if it is missing.
    pub fn take(&mut self) -> C {
        match std::mem::replace(self, Self::Missing) {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }

    /// Return a context to the slot, panicking if one is already present.
    pub fn restore(&mut self, context: C) {
        match self {
            Self::Present(_) => panic!("{}", DUPLICATE_CONTEXT),
            Self::Missing => {
                *self = Self::Present(context);
            }
        }
    }

    /// Consume the slot, returning the context and panicking if it is missing.
    pub fn into(self) -> C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }
}

impl<C> AsRef<C> for Cell<C> {
    fn as_ref(&self) -> &C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }
}

impl<C> AsMut<C> for Cell<C> {
    fn as_mut(&mut self) -> &mut C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }
}

impl<C> crate::Spawner for Cell<C>
where
    C: crate::Spawner,
{
    fn dedicated(self) -> Self {
        Self::Present(self.into().dedicated())
    }

    fn shared(self, blocking: bool) -> Self {
        Self::Present(self.into().shared(blocking))
    }

    fn instrumented(self) -> Self {
        Self::Present(self.into().instrumented())
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.into().spawn(move |context| f(Self::Present(context)))
    }

    fn stop(
        self,
        value: i32,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        self.into().stop(value, timeout)
    }

    fn stopped(&self) -> signal::Signal {
        self.as_ref().stopped()
    }
}

impl<C> crate::Metrics for Cell<C>
where
    C: crate::Metrics,
{
    fn label(&self) -> String {
        self.as_ref().label()
    }

    fn with_label(&self, label: &str) -> Self {
        Self::Present(self.as_ref().with_label(label))
    }

    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric) {
        self.as_ref().register(name, help, metric)
    }

    fn encode(&self) -> String {
        self.as_ref().encode()
    }
}

impl<C> crate::Clock for Cell<C>
where
    C: crate::Clock,
{
    fn current(&self) -> SystemTime {
        self.as_ref().current()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        self.as_ref().sleep(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        self.as_ref().sleep_until(deadline)
    }
}

#[cfg(feature = "external")]
impl<C> crate::Pacer for Cell<C>
where
    C: crate::Pacer,
{
    fn pace<'a, F, T>(&'a self, latency: Duration, future: F) -> impl Future<Output = T> + Send + 'a
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        self.as_ref().pace(latency, future)
    }
}

impl<C> crate::Network for Cell<C>
where
    C: crate::Network,
{
    type Listener = <C as crate::Network>::Listener;

    fn bind(
        &self,
        socket: SocketAddr,
    ) -> impl Future<Output = Result<Self::Listener, Error>> + Send {
        self.as_ref().bind(socket)
    }

    fn dial(
        &self,
        socket: SocketAddr,
    ) -> impl Future<Output = Result<(SinkOf<Self>, StreamOf<Self>), Error>> + Send {
        self.as_ref().dial(socket)
    }
}

impl<C> crate::Storage for Cell<C>
where
    C: crate::Storage,
{
    type Blob = <C as crate::Storage>::Blob;

    fn open(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl Future<Output = Result<(Self::Blob, u64), Error>> + Send {
        self.as_ref().open(partition, name)
    }

    fn remove(
        &self,
        partition: &str,
        name: Option<&[u8]>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        self.as_ref().remove(partition, name)
    }

    fn scan(&self, partition: &str) -> impl Future<Output = Result<Vec<Vec<u8>>, Error>> + Send {
        self.as_ref().scan(partition)
    }
}

impl<C> RngCore for Cell<C>
where
    C: RngCore,
{
    fn next_u32(&mut self) -> u32 {
        self.as_mut().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.as_mut().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.as_mut().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.as_mut().try_fill_bytes(dest)
    }
}

impl<C> CryptoRng for Cell<C> where C: CryptoRng {}

impl<C> GClock for Cell<C>
where
    C: GClock,
{
    type Instant = <C as GClock>::Instant;

    fn now(&self) -> Self::Instant {
        self.as_ref().now()
    }
}

impl<C> ReasonablyRealtime for Cell<C> where C: ReasonablyRealtime {}
