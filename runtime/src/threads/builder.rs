//! Creating runtime threads and placing work on them.

use super::{Local, admission::ThreadInner};
use crate::{Handle, Spawner, utils::supervision::Tree};
use std::{
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    ops::{Range, RangeInclusive},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};
use thiserror::Error;

/// One past the largest CPU id a [Cpus] stores (the size of the kernel's `cpu_set_t`).
const CPU_LIMIT: usize = 1024;

/// Number of 64-bit words in a [Cpus] bitset.
const CPU_WORDS: usize = CPU_LIMIT / 64;

/// A set of logical CPU ids, for [ThreadBuilder::pin].
///
/// Ids below 1024 (`CPU_SETSIZE`) are stored in a fixed bitset, so building a set never
/// allocates, whatever its range. A larger id is not stored. The set records the smallest such
/// id instead, and validation reports it as unavailable. [Cpus::iter] and [Cpus::len] cover the stored
/// ids only.
///
/// # Examples
///
/// ```
/// use commonware_runtime::Cpus;
///
/// let cpus = Cpus::from(2..=4);
/// assert_eq!(cpus.iter().collect::<Vec<_>>(), [2, 3, 4]);
/// assert_eq!(Cpus::from([0, 7]).len(), 2);
/// assert!(!Cpus::from(5000).is_empty());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cpus {
    /// Stored ids, one bit each.
    words: [u64; CPU_WORDS],
    /// The smallest requested id at or above 1024, which is not stored.
    beyond: Option<usize>,
}

impl Cpus {
    /// The empty set.
    const fn empty() -> Self {
        Self {
            words: [0; CPU_WORDS],
            beyond: None,
        }
    }

    /// Add `id`, or record it if it is too large to store.
    fn insert(&mut self, id: usize) {
        if id < CPU_LIMIT {
            self.words[id / 64] |= 1 << (id % 64);
        } else {
            self.record_beyond(id);
        }
    }

    /// Record `id`, at or above 1024, if it is the smallest such id requested.
    fn record_beyond(&mut self, id: usize) {
        self.beyond = Some(self.beyond.map_or(id, |beyond| beyond.min(id)));
    }

    /// Add every id from `start` to `last` inclusive, storing at most 1024 of them.
    fn insert_range(&mut self, start: usize, last: usize) {
        if start > last {
            return;
        }
        for id in start..=last.min(CPU_LIMIT - 1) {
            self.insert(id);
        }
        if last >= CPU_LIMIT {
            self.record_beyond(start.max(CPU_LIMIT));
        }
    }

    /// Whether `id` is stored.
    pub(crate) const fn contains(&self, id: usize) -> bool {
        id < CPU_LIMIT && self.words[id / 64] & (1 << (id % 64)) != 0
    }

    /// The smallest requested id at or above 1024, which is not stored.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) const fn beyond(&self) -> Option<usize> {
        self.beyond
    }

    /// The stored ids, in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..CPU_LIMIT).filter(|&id| self.contains(id))
    }

    /// The number of stored ids.
    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether no id was requested, so none is stored and none at or above 1024 was recorded.
    pub fn is_empty(&self) -> bool {
        self.beyond.is_none() && self.words.iter().all(|&word| word == 0)
    }

    /// The smallest requested id that `base` does not contain, including a recorded id at or
    /// above 1024.
    fn first_outside(&self, base: &Self) -> Option<usize> {
        self.iter().find(|&id| !base.contains(id)).or(self.beyond)
    }
}

impl From<usize> for Cpus {
    fn from(id: usize) -> Self {
        let mut cpus = Self::empty();
        cpus.insert(id);
        cpus
    }
}

impl From<&[usize]> for Cpus {
    fn from(ids: &[usize]) -> Self {
        let mut cpus = Self::empty();
        for &id in ids {
            cpus.insert(id);
        }
        cpus
    }
}

impl<const N: usize> From<[usize; N]> for Cpus {
    fn from(ids: [usize; N]) -> Self {
        Self::from(&ids[..])
    }
}

impl<const N: usize> From<&[usize; N]> for Cpus {
    fn from(ids: &[usize; N]) -> Self {
        Self::from(&ids[..])
    }
}

impl From<Vec<usize>> for Cpus {
    fn from(ids: Vec<usize>) -> Self {
        Self::from(&ids[..])
    }
}

impl From<&Vec<usize>> for Cpus {
    fn from(ids: &Vec<usize>) -> Self {
        Self::from(&ids[..])
    }
}

impl From<Range<usize>> for Cpus {
    fn from(range: Range<usize>) -> Self {
        let mut cpus = Self::empty();
        if range.start < range.end {
            cpus.insert_range(range.start, range.end - 1);
        }
        cpus
    }
}

impl From<RangeInclusive<usize>> for Cpus {
    fn from(range: RangeInclusive<usize>) -> Self {
        let mut cpus = Self::empty();
        if !range.is_empty() {
            let (start, last) = range.into_inner();
            cpus.insert_range(start, last);
        }
        cpus
    }
}

/// Check a pin request against the runner's base set. An empty request fails first with
/// `EmptyCpus`, then an unknown base set with `UnsupportedAffinity`, then the smallest
/// requested id outside the base set with `CpuUnavailable`.
pub(crate) fn validate(cpus: &Cpus, base: Option<&Cpus>) -> Result<(), ThreadError> {
    if cpus.is_empty() {
        return Err(ThreadError::EmptyCpus);
    }
    let Some(base) = base else {
        return Err(ThreadError::UnsupportedAffinity);
    };
    cpus.first_outside(base)
        .map_or(Ok(()), |id| Err(ThreadError::CpuUnavailable(id)))
}

/// Why a runtime thread could not be created.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum ThreadError {
    /// The runtime is shutting down, or the lineage of the context that would create the thread
    /// already ended.
    #[error(
        "thread creation rejected because the runtime is shutting down or the creating lineage ended"
    )]
    Closed,
    /// CPU affinity is unavailable on this platform, so the thread cannot be pinned.
    #[error("CPU affinity is unavailable on this platform")]
    UnsupportedAffinity,
    /// A requested CPU is not in the runner's CPU set: the CPUs of the thread that started a
    /// native runner, or the configured set of the deterministic runtime.
    #[error("CPU {0} is not in the runner's CPU set")]
    CpuUnavailable(usize),
    /// [ThreadBuilder::pin] was given no CPU.
    #[error("no CPUs requested")]
    EmptyCpus,
    /// The operating system refused to create the thread.
    #[error("failed to spawn the thread: {0}")]
    Spawn(Arc<std::io::Error>),
}

/// A runtime thread, created through [Spawner::thread].
///
/// A handle names the thread for [Spawner::on] and [Spawner::spawn_on]. Holding one does not
/// keep the thread alive. The thread lives as long as the supervision node of the context that
/// created it, and work sent to a closed thread resolves [crate::Error::Closed]. Handles are
/// cheap to clone and can be sent anywhere. Two handles are equal when they name the same
/// thread of the same runner.
#[derive(Clone)]
pub struct Thread {
    /// The thread's shared state.
    inner: Arc<ThreadInner>,
}

impl Thread {
    /// Wrap a thread's shared state.
    pub(crate) const fn new(inner: Arc<ThreadInner>) -> Self {
        Self { inner }
    }

    /// The thread's shared state.
    pub(crate) const fn inner(&self) -> &Arc<ThreadInner> {
        &self.inner
    }

    /// The label of the context that created the thread.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// The CPUs requested with [ThreadBuilder::pin], if any. The kernel may further restrict
    /// the thread's effective mask.
    pub fn cpus(&self) -> Option<&Cpus> {
        self.inner.cpus()
    }
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thread")
            .field("name", &self.inner.name())
            .field("runner", &self.inner.runner())
            .field("id", &self.inner.id())
            .field("cpus", &self.inner.cpus())
            .finish()
    }
}

impl PartialEq for Thread {
    fn eq(&self, other: &Self) -> bool {
        self.inner.runner() == other.inner.runner() && self.inner.id() == other.inner.id()
    }
}

impl Eq for Thread {}

impl Hash for Thread {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.runner().hash(state);
        self.inner.id().hash(state);
    }
}

/// Creates runtime threads for a [ThreadBuilder].
pub(crate) trait ThreadRuntime: Send + Sync {
    /// Validate `cpus`, check admission, register the thread at `node` and start it. The
    /// thread occupies `node` from then on, and is named after `name`.
    fn create_thread(
        self: Arc<Self>,
        node: Arc<Tree>,
        name: &str,
        cpus: Option<Cpus>,
    ) -> Result<Thread, ThreadError>;
}

/// Configures a runtime thread, returned by [Spawner::thread].
///
/// The thread occupies the supervision node of the context consumed by [Spawner::thread] and
/// lives as long as that node, until the context's lineage finishes or is aborted, or the
/// runtime shuts down. A thread started by [ThreadBuilder::spawn] also closes when its root task
/// ends.
#[must_use = "a thread builder creates nothing until build, attach or spawn"]
pub struct ThreadBuilder<C> {
    /// The context handed to the thread's work, at a fresh child of `node`.
    context: C,
    /// The node the thread will occupy.
    node: Arc<Tree>,
    /// The label of the consumed context.
    name: String,
    /// CPUs requested with [ThreadBuilder::pin].
    cpus: Option<Cpus>,
    /// The runtime that creates the thread, without keeping it alive.
    host: Weak<dyn ThreadRuntime>,
}

impl<C> ThreadBuilder<C> {
    /// A builder for a thread occupying `node`, handing out `context`.
    pub(crate) fn new(
        context: C,
        node: Arc<Tree>,
        name: String,
        host: Weak<dyn ThreadRuntime>,
    ) -> Self {
        Self {
            context,
            node,
            name,
            cpus: None,
            host,
        }
    }

    /// Rewrap the context this builder produces.
    ///
    /// This exists for implementing [Spawner] on a wrapper context that delegates to an inner
    /// one. The wrapper's [Spawner::thread] maps the inner builder back to the wrapper type.
    ///
    /// ```ignore
    /// fn thread(self) -> ThreadBuilder<Self> {
    ///     let state = self.state;
    ///     self.inner.thread().map(move |inner| Self { inner, state })
    /// }
    /// ```
    pub fn map<D>(self, f: impl FnOnce(C) -> D) -> ThreadBuilder<D> {
        let Self {
            context,
            node,
            name,
            cpus,
            host,
        } = self;
        ThreadBuilder {
            context: f(context),
            node,
            name,
            cpus,
            host,
        }
    }
}

impl<C: Spawner> ThreadBuilder<C> {
    /// Pin the thread to these logical CPUs. A later call replaces an earlier one.
    ///
    /// Every CPU must be one the thread that started the runner was allowed to run on (on the
    /// deterministic runtime, one of `deterministic::Config::with_cpus`), or the finisher
    /// returns [ThreadError::CpuUnavailable]. An empty set returns [ThreadError::EmptyCpus], and
    /// platforms without CPU affinity return [ThreadError::UnsupportedAffinity] for any pin.
    ///
    /// Build strategies ([crate::Strategizer::strategy]) at wiring time, outside pinned threads,
    /// since a Rayon pool keeps the CPUs of the thread that builds it.
    pub fn pin(mut self, cpus: impl Into<Cpus>) -> Self {
        self.cpus = Some(cpus.into());
        self
    }

    /// Create the thread and return a handle for placing work on it, with [Spawner::on] or
    /// [Spawner::spawn_on].
    ///
    /// The thread lives as long as its creating lineage. Code that rebuilds a subsystem per
    /// epoch should create its thread inside a task that lives exactly as long as the subsystem,
    /// or use [ThreadBuilder::spawn].
    ///
    /// # Errors
    ///
    /// Returns the pin errors of [ThreadBuilder::pin] if a pin was requested, then
    /// [ThreadError::Closed] if the runtime is shutting down or the creating lineage already
    /// ended, and [ThreadError::Spawn] if the operating system refuses the thread. A failed
    /// finisher creates no thread and aborts nothing.
    pub fn build(self) -> Result<Thread, ThreadError> {
        let (thread, _context) = self.create()?;
        Ok(thread)
    }

    /// Create the thread and return a context placed on it, at a fresh child of the thread's
    /// node. Spawns from the context, and from the contexts derived from it, run on the thread.
    /// The tasks they start receive parked contexts, which spawn on the thread again through
    /// [Spawner::placed].
    ///
    /// Such a thread hosts only `Send` work. Nothing returns its [Thread], so
    /// [Spawner::spawn_on] cannot target it. It lives as long as its creating lineage, so code
    /// that rebuilds a subsystem per epoch should attach inside a task that lives exactly as long
    /// as the subsystem.
    ///
    /// # Errors
    ///
    /// See [ThreadBuilder::build].
    pub fn attach(self) -> Result<C, ThreadError> {
        let (thread, context) = self.create()?;
        Ok(context.on(&thread))
    }

    /// Create the thread and run `f` as its root task. The thread closes when the root task
    /// ends, and once the returned handle resolves, every later spawn toward the thread resolves
    /// [crate::Error::Closed].
    ///
    /// `f` runs on the new thread, and its future may be `!Send`. If the thread starts
    /// closing before the root is admitted, this still returns `Ok`, with a handle that
    /// resolves [crate::Error::Closed].
    ///
    /// # Errors
    ///
    /// See [ThreadBuilder::build]. On an error, `f` never runs and is dropped on the caller
    /// before this returns.
    pub fn spawn<F, Fut, T>(self, f: F) -> Result<Handle<T>, ThreadError>
    where
        F: FnOnce(Local<C>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let (thread, context) = self.create()?;
        let guard = RootGuard(thread.inner().clone());
        Ok(context.spawn_on(&thread, move |local| {
            let guard = guard;
            let future = Box::pin(f(local));
            Root {
                future,
                _guard: guard,
            }
        }))
    }

    /// Create the thread, returning it with the context to hand out.
    fn create(self) -> Result<(Thread, C), ThreadError> {
        let Self {
            context,
            node,
            name,
            cpus,
            host,
        } = self;
        let Some(host) = host.upgrade() else {
            return Err(ThreadError::Closed);
        };
        let thread = host.create_thread(node, &name, cpus)?;
        Ok((thread, context))
    }
}

/// Closes a thread's admission when its root task ends.
///
/// It travels with the root, first in its factory and then in its future, and every path that
/// ends the root drops it before the root's result is published or its sink is dropped. Its
/// drop moves admission from open to closing, then aborts the thread's node, so once the root's
/// handle resolves every new spawn toward the thread resolves [crate::Error::Closed]. Aborting
/// the node alone would not be such a barrier, because a concurrent abort may have taken the
/// node's aborter without running it yet.
pub(crate) struct RootGuard(Arc<ThreadInner>);

impl RootGuard {
    /// A guard closing `thread`.
    #[cfg(test)]
    pub(crate) const fn new(thread: Arc<ThreadInner>) -> Self {
        Self(thread)
    }
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        self.0.begin_close();
        if let Some(node) = self.0.node() {
            node.abort();
        }
    }
}

/// The root task of a thread: the user's future, followed by the guard that closes the thread.
///
/// Polling only forwards to the user's future and never drops it, so a destructor that panics
/// after the future completed is a disposal panic. The task wrapper drops the root, the future
/// before the guard, before it publishes the result.
struct Root<Fut> {
    /// The user's root future.
    future: Pin<Box<Fut>>,
    /// Closes the thread once the root is gone.
    _guard: RootGuard,
}

impl<Fut: Future> Future for Root<Fut> {
    type Output = Fut::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}
