//! Utility functions for interacting with any runtime.

use crate::metrics::{
    encoding::{
        text::{encode, encode_eof},
        EncodeMetric, MetricEncoder as PromMetricEncoder,
    },
    Metric, MetricType, Unit,
};
use commonware_utils::sync::{Condvar, Mutex};
use futures::task::ArcWake;
use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

commonware_macros::stability_mod!(BETA, pub mod buffer);
pub mod signal;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod thread;

mod handle;
pub use handle::Handle;
#[commonware_macros::stability(ALPHA)]
pub(crate) use handle::Panicked;
pub(crate) use handle::{Aborter, MetricHandle, Panicker};

mod cell;
pub use cell::Cell as ContextCell;

pub(crate) mod supervision;

/// The execution mode of a task.
#[derive(Copy, Clone, Debug)]
pub enum Execution {
    /// Task runs on a dedicated thread.
    Dedicated,
    /// Task runs on the shared executor. `true` marks short blocking work that should
    /// use the runtime's blocking-friendly pool.
    Shared(bool),
}

impl Default for Execution {
    fn default() -> Self {
        Self::Shared(false)
    }
}

/// Yield control back to the runtime.
pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

// Adapted from client_rust's internal descriptor encoder:
// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L218-L275
//
// Commonware needs a local copy because upstream keeps this helper internal
// while the runtime assembles metric samples independently.
fn encode_descriptor<W>(
    writer: &mut W,
    name: &str,
    help: &str,
    unit: Option<&Unit>,
    metric_type: MetricType,
) -> Result<(), std::fmt::Error>
where
    W: std::fmt::Write,
{
    writer.write_str("# HELP ")?;
    writer.write_str(name)?;
    if let Some(unit) = unit {
        writer.write_str("_")?;
        writer.write_str(unit.as_str())?;
    }
    writer.write_str(" ")?;
    writer.write_str(help)?;
    writer.write_str("\n# TYPE ")?;
    writer.write_str(name)?;
    if let Some(unit) = unit {
        writer.write_str("_")?;
        writer.write_str(unit.as_str())?;
    }
    writer.write_str(" ")?;
    writer.write_str(metric_type.as_str())?;
    writer.write_str("\n")?;

    if let Some(unit) = unit {
        writer.write_str("# UNIT ")?;
        writer.write_str(name)?;
        writer.write_str("_")?;
        writer.write_str(unit.as_str())?;
        writer.write_str(" ")?;
        writer.write_str(unit.as_str())?;
        writer.write_str("\n")?;
    }

    Ok(())
}

fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    err.downcast_ref::<&str>().map_or_else(
        || {
            err.downcast_ref::<String>()
                .map_or_else(|| format!("{err:?}"), |s| s.clone())
        },
        |s| s.to_string(),
    )
}

fn prefixed_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}_{name}")
    }
}

/// Synchronization primitive that enables a thread to block until a waker delivers a signal.
pub struct Blocker {
    /// Tracks whether a wake-up signal has been delivered (even if wait has not started yet).
    state: Mutex<bool>,
    /// Condvar used to park and resume the thread when the signal flips to true.
    cv: Condvar,
}

impl Blocker {
    /// Create a new [Blocker].
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(false),
            cv: Condvar::new(),
        })
    }

    /// Block the current thread until a waker delivers a signal.
    pub fn wait(&self) {
        // Use a loop to tolerate spurious wake-ups and only proceed once a real signal arrives.
        let mut signaled = self.state.lock();
        while !*signaled {
            self.cv.wait(&mut signaled);
        }

        // Reset the flag so subsequent waits park again until the next wake signal.
        *signaled = false;
    }
}

impl ArcWake for Blocker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // Mark as signaled (and release lock before notifying).
        {
            let mut signaled = arc_self.state.lock();
            *signaled = true;
        }

        // Notify a single waiter so the blocked thread re-checks the flag.
        arc_self.cv.notify_one();
    }
}

#[cfg(any(test, feature = "test-utils"))]
/// Count the number of running tasks whose name starts with the given prefix.
///
/// This function encodes metrics and counts tasks that are currently running
/// (have a value of 1) and whose name starts with the specified prefix.
///
/// This is useful for verifying that all child tasks under a given label hierarchy
/// have been properly shut down.
///
/// # Example
///
/// ```rust
/// use commonware_runtime::{Clock, Metrics, Runner, Spawner, deterministic};
/// use commonware_runtime::utils::count_running_tasks;
/// use std::time::Duration;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Spawn a task under a labeled context
///     let handle = context.with_label("worker").spawn(|ctx| async move {
///         ctx.sleep(Duration::from_secs(100)).await;
///     });
///
///     // Allow the task to start
///     context.sleep(Duration::from_millis(10)).await;
///
///     // Count running tasks with "worker" prefix
///     let count = count_running_tasks(&context, "worker");
///     assert!(count > 0, "worker task should be running");
///
///     // Abort the task
///     handle.abort();
///     let _ = handle.await;
///     context.sleep(Duration::from_millis(10)).await;
///
///     // Verify task is stopped
///     let count = count_running_tasks(&context, "worker");
///     assert_eq!(count, 0, "worker task should be stopped");
/// });
/// ```
pub fn count_running_tasks(metrics: &impl crate::Metrics, prefix: &str) -> usize {
    let encoded = metrics.encode();
    encoded
        .lines()
        .filter_map(|line| {
            if !line.starts_with("runtime_tasks_running{") || !line.contains("kind=\"Task\"") {
                return None;
            }
            let name = line.split("name=\"").nth(1)?.split('"').next()?;
            if !name.starts_with(prefix) {
                return None;
            }
            line.trim_end().rsplit(' ').next()?.parse::<usize>().ok()
        })
        .sum()
}

/// Validates that a label matches Prometheus metric name format: `[a-zA-Z][a-zA-Z0-9_]*`.
///
/// # Panics
///
/// Panics if the label is empty, starts with a non-alphabetic character,
/// or contains characters other than `[a-zA-Z0-9_]`.
pub fn validate_label(label: &str) {
    let mut chars = label.chars();
    assert!(
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()),
        "label must start with [a-zA-Z]: {label}"
    );
    assert!(
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "label must only contain [a-zA-Z0-9_]: {label}"
    );
}

/// Add an attribute to a sorted attribute list, maintaining sorted order via binary search.
///
/// Returns `true` if the key was new, `false` if it was a duplicate (value overwritten).
pub fn add_attribute(
    attributes: &mut Vec<(String, String)>,
    key: &str,
    value: impl std::fmt::Display,
) -> bool {
    let key_string = key.to_string();
    let value_string = value.to_string();

    match attributes.binary_search_by(|(k, _)| k.cmp(&key_string)) {
        Ok(pos) => {
            attributes[pos].1 = value_string;
            false
        }
        Err(pos) => {
            attributes.insert(pos, (key_string, value_string));
            true
        }
    }
}

trait RegistrationGuard: Send + Sync {}

impl<T: Send + Sync> RegistrationGuard for T {}

struct GuardHolder<G>(Mutex<G>);

/// A shared lifecycle token for a [`Registered`] metric handle.
///
/// When the last clone of the associated [`Registered`] handle is dropped, this
/// registration is dropped as well. Runtime-managed metrics use that drop to
/// unregister themselves from the runtime registry, while external callers may
/// attach any custom drop guard.
#[derive(Clone)]
pub struct Registration {
    inner: Arc<dyn RegistrationGuard>,
}

impl Registration {
    /// Create a registration that performs no action when dropped.
    pub fn detached() -> Self {
        Self::from_guard(())
    }

    /// Create a registration from a guard that should be dropped when the last
    /// associated [`Registered`] handle is dropped.
    ///
    /// This can be used by external `Metrics` implementations to run custom
    /// teardown or notification logic by providing a guard type that implements
    /// [`Drop`].
    pub fn from_guard<G>(guard: G) -> Self
    where
        G: Send + 'static,
    {
        Self {
            inner: Arc::new(GuardHolder(Mutex::new(guard))),
        }
    }

    fn from_inner(inner: Arc<dyn RegistrationGuard>) -> Self {
        Self { inner }
    }

    fn downgrade(&self) -> Weak<dyn RegistrationGuard> {
        Arc::downgrade(&self.inner)
    }
}

struct RuntimeRegistration {
    id: u64,
    registry: Weak<Mutex<Registry>>,
}

impl Drop for RuntimeRegistration {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        registry.lock().unregister(self.id);
    }
}

/// A metric handle whose lifetime controls registry exposure and attached cleanup.
#[must_use = "registered metrics are removed and attached cleanup runs when the returned handle is dropped"]
pub struct Registered<M> {
    metric: Arc<M>,
    registration: Registration,
}

impl<M> Clone for Registered<M> {
    fn clone(&self) -> Self {
        Self {
            metric: self.metric.clone(),
            registration: self.registration.clone(),
        }
    }
}

impl<M> Registered<M> {
    /// Create a detached metric handle that does not unregister from any runtime registry.
    ///
    /// This is intended for `Metrics` implementations outside `commonware-runtime`
    /// that need to return a [`Registered`] handle without exposing the metric in
    /// a runtime-managed registry. If you need custom drop behavior, use
    /// [`Registered::with_registration`].
    pub fn detached(metric: M) -> Self {
        Self::with_registration(metric, Registration::detached())
    }

    /// Create a metric handle with an explicit lifecycle registration.
    ///
    /// The provided [`Registration`] is dropped when the last clone of this
    /// handle is dropped.
    pub fn with_registration(metric: M, registration: Registration) -> Self {
        Self::from_parts(Arc::new(metric), registration)
    }

    pub(crate) const fn from_parts(metric: Arc<M>, registration: Registration) -> Self {
        Self {
            metric,
            registration,
        }
    }

    pub fn metric(&self) -> &M {
        self.metric.as_ref()
    }
}

#[cfg(target_has_atomic = "64")]
impl Registered<crate::metrics::raw::Gauge> {
    pub fn try_set<T: TryInto<i64>>(&self, value: T) -> Result<i64, T::Error> {
        crate::metrics::try_set(self.metric(), value)
    }

    pub fn try_set_max<T: TryInto<i64> + Copy>(&self, value: T) -> Result<i64, T::Error> {
        crate::metrics::try_set_max(self.metric(), value)
    }
}

#[cfg(not(target_has_atomic = "64"))]
impl Registered<crate::metrics::raw::Gauge> {
    pub fn try_set<T: TryInto<i32>>(&self, value: T) -> Result<i32, T::Error> {
        crate::metrics::try_set(self.metric(), value)
    }

    pub fn try_set_max<T: TryInto<i32> + Copy>(&self, value: T) -> Result<i32, T::Error> {
        crate::metrics::try_set_max(self.metric(), value)
    }
}

impl Registered<crate::metrics::raw::Histogram> {
    pub fn observe_between(&self, start: std::time::SystemTime, end: std::time::SystemTime) {
        crate::metrics::observe_between(self.metric(), start, end);
    }
}

impl<S, M, C> Registered<crate::metrics::raw::Family<S, M, C>>
where
    S: Clone + std::hash::Hash + Eq,
    C: crate::metrics::family::MetricConstructor<M>,
{
    pub fn get_or_create_by<Q>(&self, label_set: &Q) -> impl Deref<Target = M> + '_
    where
        for<'a> S: From<&'a Q>,
    {
        let label_set = S::from(label_set);
        self.get_or_create(&label_set)
    }

    pub fn remove_by<Q>(&self, label_set: &Q) -> bool
    where
        for<'a> S: From<&'a Q>,
    {
        let label_set = S::from(label_set);
        self.remove(&label_set)
    }
}

impl<M> Deref for Registered<M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.metric()
    }
}

impl<M: std::fmt::Debug> std::fmt::Debug for Registered<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("metric", self.metric())
            .finish_non_exhaustive()
    }
}

type MetricKey = (String, Vec<(Cow<'static, str>, Cow<'static, str>)>);
type SampleEncoder = dyn Fn(&mut String, &str, &[(Cow<'static, str>, Cow<'static, str>)]) -> Result<(), std::fmt::Error>
    + Send
    + Sync;

pub(crate) struct SharedMetric<M>(pub(crate) Arc<M>);

impl<M: std::fmt::Debug> std::fmt::Debug for SharedMetric<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<M: EncodeMetric> EncodeMetric for SharedMetric<M> {
    fn encode(&self, encoder: PromMetricEncoder<'_>) -> Result<(), std::fmt::Error> {
        self.0.encode(encoder)
    }

    fn metric_type(&self) -> MetricType {
        self.0.metric_type()
    }
}

fn create_sample_encoder<M>(metric: Arc<M>) -> Box<SampleEncoder>
where
    M: Metric,
{
    Box::new(move |samples, name, labels| {
        let mut registry = crate::metrics::registry::Registry::with_labels(labels.iter().cloned());
        registry.register(name, "", SharedMetric(metric.clone()));

        let mut encoded = String::new();
        encode(&mut encoded, &registry).expect("encoding temporary metric registry failed");
        for line in encoded.lines() {
            if line.starts_with('#') {
                continue;
            }
            samples.push_str(line);
            samples.push('\n');
        }
        Ok(())
    })
}

struct MetricEntry {
    family_name: String,
    attributes: Vec<(Cow<'static, str>, Cow<'static, str>)>,
    encode_samples: Box<SampleEncoder>,
    metric_any: Arc<dyn Any + Send + Sync>,
    registration: Option<Weak<dyn RegistrationGuard>>,
    family_index: usize,
}

#[derive(Debug)]
struct MetricFamily {
    help: String,
    metric_type: MetricType,
    descriptor: String,
    metric_ids: Vec<u64>,
}

/// Manages runtime-internal metrics plus user-registered metrics with explicit lifetimes.
///
/// Runtime internals are stored permanently in the same table as user metrics, but
/// registered with a fixed prefix. User metrics additionally get a drop-based
/// registration handle so they can be unregistered when the owning handle drops.
pub(crate) struct Registry {
    metrics: Vec<Option<MetricEntry>>,
    free_metric_ids: Vec<u64>,
    families: BTreeMap<String, MetricFamily>,
    keys: HashMap<MetricKey, u64>,
    next_metric_id: u64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
            free_metric_ids: Vec::new(),
            families: BTreeMap::new(),
            keys: HashMap::new(),
            next_metric_id: 0,
        }
    }

    pub fn sub_registry_with_prefix(&mut self, prefix: &str) -> MetricScope<'_> {
        validate_label(prefix);
        MetricScope {
            registry: self,
            prefix: prefix.to_string(),
        }
    }

    #[cfg(test)]
    pub const fn scope(&mut self) -> MetricScope<'_> {
        MetricScope {
            registry: self,
            prefix: String::new(),
        }
    }

    fn insert_metric<M>(
        &mut self,
        name: String,
        help: String,
        attributes: Vec<(Cow<'static, str>, Cow<'static, str>)>,
        metric: M,
    ) -> u64
    where
        M: Metric,
    {
        let metric = Arc::new(metric);
        let encode_samples = create_sample_encoder(metric.clone());
        // Match upstream prometheus-client's `Descriptor::new` normalization,
        // which unconditionally appends `.` to the help text.
        let help = help + ".";
        let metric_type = metric.metric_type();
        if let Some(family) = self.families.get(&name) {
            assert_eq!(
                family.help, help,
                "metric family `{}` registered with inconsistent help text",
                name
            );
            assert_eq!(
                family.metric_type.as_str(),
                metric_type.as_str(),
                "metric family `{}` registered with inconsistent metric type",
                name
            );
        }
        let key = (name.clone(), attributes.clone());
        if let Some(&existing_id) = self.keys.get(&key) {
            return existing_id;
        }
        let id = self.allocate_metric_id();
        self.keys.insert(key, id);
        let family = match self.families.entry(name.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut descriptor = String::new();
                encode_descriptor(&mut descriptor, &name, &help, None, metric_type)
                    .expect("encoding cached descriptor failed");
                entry.insert(MetricFamily {
                    help,
                    metric_type,
                    descriptor,
                    metric_ids: Vec::new(),
                })
            }
        };
        let family_index = family.metric_ids.len();
        family.metric_ids.push(id);
        self.metric_slot_mut(id).replace(MetricEntry {
            family_name: name,
            attributes,
            encode_samples,
            metric_any: metric,
            registration: None,
            family_index,
        });
        id
    }

    pub fn register<M>(
        &mut self,
        registry: Weak<Mutex<Self>>,
        name: String,
        help: String,
        attributes: Vec<(String, String)>,
        metric: Arc<M>,
    ) -> Registered<M>
    where
        M: Metric,
    {
        let attributes = attributes
            .into_iter()
            .map(|(k, v)| (Cow::Owned(k), Cow::Owned(v)))
            .collect::<Vec<_>>();
        // Match upstream prometheus-client's `Descriptor::new` normalization,
        // which unconditionally appends `.` to the help text.
        let help = help + ".";
        let metric_type = metric.metric_type();
        let encode_samples = create_sample_encoder(metric.clone());
        let key = (name.clone(), attributes.clone());
        if let Some(existing_id) = self.keys.get(&key).copied() {
            let entry = self.metric_ref(existing_id);
            if let Some(inner) = entry.registration.as_ref().and_then(Weak::upgrade) {
                if let Some(family) = self.families.get(&name) {
                    assert_eq!(
                        family.help, help,
                        "metric family `{}` registered with inconsistent help text",
                        name
                    );
                }
                let existing_metric = Arc::clone(&entry.metric_any)
                    .downcast::<M>()
                    .unwrap_or_else(|_| {
                        panic!(
                            "duplicate metric `{}` with attributes {:?} registered with different type",
                            key.0, key.1
                        )
                    });
                return Registered::from_parts(existing_metric, Registration::from_inner(inner));
            }
            // The existing entry's last handle is mid-drop: its Weak no longer
            // upgrades, but the pending `unregister` call has not yet run.
            // Detach the stale key so we can insert fresh; the in-flight
            // `unregister` will still clean up its own metric slot and skip the
            // key removal (see the id check in `unregister`).
            self.keys.remove(&key);
        }
        if let Some(family) = self.families.get(&name) {
            assert_eq!(
                family.help, help,
                "metric family `{}` registered with inconsistent help text",
                name
            );
            assert_eq!(
                family.metric_type.as_str(),
                metric_type.as_str(),
                "metric family `{}` registered with inconsistent metric type",
                name
            );
        }

        let id = self.allocate_metric_id();
        let registration = Registration::from_guard(RuntimeRegistration { id, registry });
        self.keys.insert(key, id);
        let family = match self.families.entry(name.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut descriptor = String::new();
                encode_descriptor(&mut descriptor, &name, &help, None, metric_type)
                    .expect("encoding cached descriptor failed");
                entry.insert(MetricFamily {
                    help,
                    metric_type,
                    descriptor,
                    metric_ids: Vec::new(),
                })
            }
        };
        let family_index = family.metric_ids.len();
        family.metric_ids.push(id);
        let metric_any: Arc<dyn Any + Send + Sync> = metric.clone();
        self.metric_slot_mut(id).replace(MetricEntry {
            family_name: name,
            attributes,
            encode_samples,
            metric_any,
            registration: Some(registration.downgrade()),
            family_index,
        });
        Registered::from_parts(metric, registration)
    }

    fn metric_index(id: u64) -> usize {
        usize::try_from(id).expect("metric id overflowed usize")
    }

    fn metric_slot_mut(&mut self, id: u64) -> &mut Option<MetricEntry> {
        let index = Self::metric_index(id);
        if index == self.metrics.len() {
            self.metrics.push(None);
        }
        &mut self.metrics[index]
    }

    fn metric_ref(&self, id: u64) -> &MetricEntry {
        self.metrics
            .get(Self::metric_index(id))
            .and_then(Option::as_ref)
            .expect("metric id missing from registry")
    }

    fn metric_mut(&mut self, id: u64) -> &mut MetricEntry {
        self.metrics
            .get_mut(Self::metric_index(id))
            .and_then(Option::as_mut)
            .expect("metric id missing from registry")
    }

    fn allocate_metric_id(&mut self) -> u64 {
        if let Some(id) = self.free_metric_ids.pop() {
            return id;
        }
        let id = self.next_metric_id;
        self.next_metric_id = self
            .next_metric_id
            .checked_add(1)
            .expect("metric id overflow");
        id
    }

    pub fn register_permanent(
        &mut self,
        name: String,
        help: String,
        attributes: Vec<(String, String)>,
        metric: impl Metric,
    ) {
        let attributes = attributes
            .into_iter()
            .map(|(k, v)| (Cow::Owned(k), Cow::Owned(v)))
            .collect::<Vec<_>>();
        self.insert_metric(name, help, attributes, metric);
    }

    pub fn unregister(&mut self, id: u64) {
        let Some(metric) = self
            .metrics
            .get_mut(Self::metric_index(id))
            .and_then(Option::take)
        else {
            return;
        };
        let MetricEntry {
            family_name,
            attributes,
            family_index,
            ..
        } = metric;
        let key = (family_name, attributes);
        // Only remove the key mapping if it still points to our id. A
        // concurrent re-registration may have replaced it after our Weak died
        // but before this unregister ran; in that case the new entry owns the
        // key mapping and we must leave it alone.
        if self.keys.get(&key).copied() == Some(id) {
            self.keys.remove(&key);
        }
        let (family_name, _) = key;
        let (swapped_metric_id, remove_family) = {
            let family = self
                .families
                .get_mut(&family_name)
                .expect("family missing during unregister");
            let removed = family.metric_ids.swap_remove(family_index);
            debug_assert_eq!(removed, id, "family index mismatch during unregister");
            let swapped = family.metric_ids.get(family_index).copied();
            (swapped, family.metric_ids.is_empty())
        };
        if let Some(swapped_metric_id) = swapped_metric_id {
            self.metric_mut(swapped_metric_id).family_index = family_index;
        }
        if remove_family {
            self.families.remove(&family_name);
        }
        self.free_metric_ids.push(id);
    }

    pub fn encode(&self) -> String {
        let mut output = String::new();
        let mut samples = String::new();
        for (name, family) in &self.families {
            samples.clear();
            for metric_id in &family.metric_ids {
                let metric = self.metric_ref(*metric_id);
                (metric.encode_samples)(&mut samples, name, &metric.attributes)
                    .expect("encoding live metric samples failed");
            }
            // Suppress the HELP/TYPE descriptor when the family produced no
            // samples (e.g. a `Family<S, M>` with no child entries). Matches
            // upstream prometheus-client's empty-metric filtering.
            if samples.is_empty() {
                continue;
            }
            output.push_str(&family.descriptor);
            output.push_str(&samples);
        }

        encode_eof(&mut output).expect("encoding EOF failed");
        output
    }
}

pub(crate) struct MetricScope<'a> {
    registry: &'a mut Registry,
    prefix: String,
}

impl MetricScope<'_> {
    pub fn register(&mut self, name: &str, help: &str, metric: impl Metric) {
        validate_label(name);
        self.registry.register_permanent(
            prefixed_name(&self.prefix, name),
            help.to_string(),
            Vec::new(),
            metric,
        );
    }

    pub fn sub_registry_with_prefix(&mut self, prefix: &str) -> MetricScope<'_> {
        validate_label(prefix);
        MetricScope {
            registry: &mut *self.registry,
            prefix: prefixed_name(&self.prefix, prefix),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deterministic,
        metrics::raw::{Counter, Gauge, Histogram},
        Metrics, Runner, Spawner,
    };
    use commonware_macros::test_traced;
    use futures::{future, task::waker};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, TryRecvError},
    };

    #[test]
    fn test_blocker_waits_until_wake() {
        let blocker = Blocker::new();
        let started = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));

        let thread_blocker = blocker.clone();
        let thread_started = started.clone();
        let thread_completed = completed.clone();
        let handle = std::thread::spawn(move || {
            thread_started.store(true, Ordering::SeqCst);
            thread_blocker.wait();
            thread_completed.store(true, Ordering::SeqCst);
        });

        while !started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        assert!(!completed.load(Ordering::SeqCst));
        waker(blocker).wake();
        handle.join().unwrap();
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_blocker_handles_pre_wake() {
        let blocker = Blocker::new();
        waker(blocker.clone()).wake();

        let completed = Arc::new(AtomicBool::new(false));
        let thread_blocker = blocker;
        let thread_completed = completed.clone();
        std::thread::spawn(move || {
            thread_blocker.wait();
            thread_completed.store(true, Ordering::SeqCst);
        })
        .join()
        .unwrap();

        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_blocker_reusable_across_signals() {
        let blocker = Blocker::new();
        let completed = Arc::new(AtomicUsize::new(0));

        let thread_blocker = blocker.clone();
        let thread_completed = completed.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                thread_blocker.wait();
                thread_completed.fetch_add(1, Ordering::SeqCst);
            }
        });

        for expected in 1..=2 {
            waker(blocker.clone()).wake();
            while completed.load(Ordering::SeqCst) < expected {
                std::thread::yield_now();
            }
        }

        handle.join().unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 2);
    }

    #[test_traced]
    fn test_count_running_tasks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initially no tasks with "worker" prefix
            assert_eq!(
                count_running_tasks(&context, "worker"),
                0,
                "no worker tasks initially"
            );

            // Spawn a task under a labeled context that stays running
            let worker_ctx = context.with_label("worker");
            let handle1 = worker_ctx.clone().spawn(|_| async move {
                future::pending::<()>().await;
            });

            // Count running tasks with "worker" prefix
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 1, "worker task should be running");

            // Non-matching prefix should return 0
            assert_eq!(
                count_running_tasks(&context, "other"),
                0,
                "no tasks with 'other' prefix"
            );

            // Spawn a nested task (worker_child)
            let handle2 = worker_ctx.with_label("child").spawn(|_| async move {
                future::pending::<()>().await;
            });

            // Count should include both parent and nested tasks
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 2, "both worker and worker_child should be counted");

            // Abort parent task
            handle1.abort();
            let _ = handle1.await;

            // Only nested task remains
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 1, "only worker_child should remain");

            // Abort nested task
            handle2.abort();
            let _ = handle2.await;

            // All tasks stopped
            assert_eq!(
                count_running_tasks(&context, "worker"),
                0,
                "all worker tasks should be stopped"
            );
        });
    }

    #[test_traced]
    fn test_no_duplicate_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Register metrics under different labels (no duplicates)
            let c1 = Counter::<u64>::default();
            let _metric_a = context.with_label("a").register("test", "help", c1);
            let c2 = Counter::<u64>::default();
            let _metric_b = context.with_label("b").register("test", "help", c2);
        });
        // Test passes if runtime doesn't panic on shutdown
    }

    #[test_traced]
    fn test_duplicate_metrics_reuse_existing_handle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let c1 = Counter::<u64>::default();
            let metric_a = context.with_label("a").register("test", "help", c1);
            let c2 = Counter::<u64>::default();
            let metric_b = context.with_label("a").register("test", "help", c2);

            assert!(std::ptr::eq(metric_a.metric(), metric_b.metric()));

            metric_a.inc();
            metric_b.inc_by(2);
            let encoded = context.encode();
            assert!(encoded.contains("a_test_total 3"));
        });
    }

    #[test]
    #[should_panic(expected = "registered with different type")]
    fn test_duplicate_metrics_different_type_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let counter = Counter::<u64>::default();
            let _metric_a = context.with_label("a").register("test", "help", counter);
            let gauge = Gauge::<i64>::default();
            let _metric_b = context.with_label("a").register("test", "help", gauge);
        });
    }

    #[test]
    fn test_registered_detached_creates_detached_handle() {
        let registered = Registered::detached(Counter::<u64>::default());
        let clone = registered.clone();

        registered.inc_by(2);
        drop(registered);
        clone.inc();

        assert_eq!(clone.get(), 3);
    }

    #[test]
    fn test_registered_with_registration_notifies_on_last_drop() {
        struct NotifyOnDrop(mpsc::Sender<&'static str>);

        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send("dropped");
            }
        }

        let (tx, rx) = mpsc::channel();
        let registered = Registered::with_registration(
            Counter::<u64>::default(),
            Registration::from_guard(NotifyOnDrop(tx)),
        );
        let clone = registered.clone();

        drop(registered);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        drop(clone);
        assert_eq!(rx.recv().unwrap(), "dropped");
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
    }

    fn register_permanent_counter(registry: &mut Registry, name: &str, help: &str, value: u64) {
        let counter = Counter::<u64>::default();
        counter.inc_by(value);
        registry.register_permanent(name.to_string(), help.to_string(), Vec::new(), counter);
    }

    #[test]
    fn test_encode_is_deterministic() {
        let mut registry = Registry::default();
        register_permanent_counter(&mut registry, "beta", "beta counter", 2);
        register_permanent_counter(&mut registry, "alpha", "alpha counter", 1);
        let first = registry.encode();
        let second = registry.encode();
        assert_eq!(first, second);
        let alpha = first
            .find("# TYPE alpha")
            .expect("alpha family header present");
        let beta = first
            .find("# TYPE beta")
            .expect("beta family header present");
        assert!(alpha < beta, "families emitted in sorted order: {first}");
    }

    #[test]
    fn test_encode_emits_single_eof() {
        let mut registry = Registry::default();
        register_permanent_counter(&mut registry, "a", "help", 1);
        register_permanent_counter(&mut registry, "b", "help", 2);
        let encoded = registry.encode();
        assert_eq!(encoded.matches("# EOF").count(), 1);
        assert!(
            encoded.ends_with("# EOF\n"),
            "must terminate with EOF: {encoded}"
        );
    }

    #[test]
    fn test_encode_type_aware_suffixes() {
        let mut registry = Registry::default();
        register_permanent_counter(&mut registry, "requests", "request count", 3);
        let histogram = Histogram::new([0.1, 1.0, 10.0]);
        histogram.observe(0.5);
        registry.register_permanent(
            "latency".to_string(),
            "latency seconds".to_string(),
            Vec::new(),
            histogram,
        );
        let encoded = registry.encode();
        assert!(
            encoded.contains("requests_total 3"),
            "counter _total suffix: {encoded}"
        );
        assert!(
            encoded.contains("latency_bucket"),
            "histogram _bucket suffix: {encoded}"
        );
        assert!(
            encoded.contains("latency_sum"),
            "histogram _sum suffix: {encoded}"
        );
        assert!(
            encoded.contains("latency_count"),
            "histogram _count suffix: {encoded}"
        );
    }

    #[test]
    fn test_encode_shares_family_header_across_attributes() {
        let mut registry = Registry::default();
        let c1 = Counter::<u64>::default();
        c1.inc();
        registry.register_permanent(
            "votes".to_string(),
            "vote count".to_string(),
            vec![("epoch".to_string(), "1".to_string())],
            c1,
        );
        let c2 = Counter::<u64>::default();
        c2.inc_by(2);
        registry.register_permanent(
            "votes".to_string(),
            "vote count".to_string(),
            vec![("epoch".to_string(), "2".to_string())],
            c2,
        );
        let encoded = registry.encode();
        assert_eq!(
            encoded.matches("# HELP votes").count(),
            1,
            "single HELP: {encoded}"
        );
        assert_eq!(
            encoded.matches("# TYPE votes").count(),
            1,
            "single TYPE: {encoded}"
        );
        assert!(encoded.contains("votes_total{epoch=\"1\"} 1"));
        assert!(encoded.contains("votes_total{epoch=\"2\"} 2"));
    }

    #[test]
    fn test_encode_scope_registers_without_prefix() {
        let mut registry = Registry::default();
        {
            let mut scope = registry.scope();
            let counter = Counter::<u64>::default();
            counter.inc();
            scope.register("votes", "vote count", counter);
        }
        let encoded = registry.encode();
        assert!(
            encoded.contains("votes_total 1"),
            "no prefix applied: {encoded}"
        );
        assert!(
            encoded.starts_with("# HELP votes"),
            "family header at start: {encoded}"
        );
    }

    #[test]
    fn test_encode_suppresses_empty_family() {
        // A Family registered with no child entries should not emit its HELP/TYPE
        // descriptor on scrape. This matches upstream prometheus-client's
        // `encode_omit_empty` behavior.
        let mut registry = Registry::default();
        let empty_family = crate::metrics::raw::Family::<Vec<(String, String)>, Counter>::default();
        registry.register_permanent(
            "votes".to_string(),
            "vote count".to_string(),
            Vec::new(),
            empty_family,
        );
        register_permanent_counter(&mut registry, "ticks", "tick count", 1);
        let encoded = registry.encode();
        assert!(!encoded.contains("votes"), "empty family leaked: {encoded}");
        assert!(
            encoded.contains("ticks_total 1"),
            "populated metric missing: {encoded}"
        );
        assert_eq!(encoded.matches("# EOF").count(), 1);
    }

    #[test]
    fn test_encode_matches_upstream_registry() {
        // Byte-for-byte parity between our `Registry::encode` and upstream
        // prometheus-client's `registry::Registry::encode` on an equivalent
        // metric set. Covers HELP normalization (trailing `.`), TYPE lines,
        // counter `_total` suffix, histogram `_bucket`/`_sum`/`_count`, and
        // the single final `# EOF`. Our registry emits families in sorted
        // order (see `test_encode_is_deterministic`); upstream preserves
        // registration order. Register here in sorted order so the parity
        // assertion only flags real format divergences.
        let counter = Counter::<u64>::default();
        counter.inc_by(7);
        let gauge = Gauge::<i64>::default();
        gauge.set(-3);
        let histogram = Histogram::new([0.1, 1.0]);
        histogram.observe(0.5);

        let mut ours = Registry::default();
        ours.register_permanent(
            "latency".to_string(),
            "request latency seconds".to_string(),
            Vec::new(),
            histogram.clone(),
        );
        ours.register_permanent(
            "level".to_string(),
            "current level".to_string(),
            Vec::new(),
            gauge.clone(),
        );
        ours.register_permanent(
            "votes".to_string(),
            "number of votes".to_string(),
            Vec::new(),
            counter.clone(),
        );
        let ours_encoded = ours.encode();

        let mut theirs = crate::metrics::registry::Registry::default();
        theirs.register("latency", "request latency seconds", histogram);
        theirs.register("level", "current level", gauge);
        theirs.register("votes", "number of votes", counter);
        let mut theirs_encoded = String::new();
        crate::metrics::encoding::text::encode(&mut theirs_encoded, &theirs)
            .expect("upstream encode failed");

        assert_eq!(
            ours_encoded, theirs_encoded,
            "output diverged from upstream prometheus-client registry"
        );
    }

    #[test]
    fn test_register_drop_race_does_not_panic() {
        // Concurrently re-registers and drops the same metric key from multiple
        // threads. Before the fix, a register call could see the key present
        // with a Weak that no longer upgrades (last handle mid-drop), and panic
        // with "registration missing for live metric".
        let registry = Arc::new(Mutex::new(Registry::new()));
        let weak = Arc::downgrade(&registry);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let weak = weak.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        let handle = registry.lock().register(
                            weak.clone(),
                            "votes".to_string(),
                            "vote count".to_string(),
                            Vec::new(),
                            Arc::new(Counter::<u64>::default()),
                        );
                        drop(handle);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // Registry ends clean after the stress loop.
        let registry = registry.lock();
        assert!(
            registry.keys.is_empty(),
            "keys left behind: {:?}",
            registry.keys
        );
        assert!(
            registry.families.is_empty(),
            "families left behind: {:?}",
            registry.families
        );
    }
}
