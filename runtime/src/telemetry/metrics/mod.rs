//! Observability helpers for Prometheus-style metrics.
//!
//! This module owns all Prometheus-facing logic used by the runtime:
//! - Re-exports of the underlying `prometheus_client` types and derive macros.
//! - Ergonomic [`Registered`] handles that auto-unregister on drop.
//! - The runtime's [`Registry`] implementation that backs [`crate::Metrics::encode`].
//! - Helpers for label validation, attribute management, gauge/histogram ergonomics,
//!   and task introspection (`count_running_tasks`).

pub mod histogram;
pub mod status;
pub(crate) mod task;

/// Prefix for runtime metrics.
pub(crate) const METRICS_PREFIX: &str = "runtime";

pub use commonware_runtime_macros::{EncodeLabelSet, EncodeLabelValue, EncodeStruct};
pub use prometheus_client::{
    collector, encoding,
    encoding::{
        CounterValueEncoder, DescriptorEncoder, EncodeCounterValue, EncodeExemplarTime,
        EncodeExemplarValue, EncodeGaugeValue, EncodeLabel, EncodeLabelKey,
        EncodeLabelSet as EncodeLabelSetTrait, EncodeLabelValue as EncodeLabelValueTrait,
        EncodeMetric, ExemplarValueEncoder, GaugeValueEncoder, LabelEncoder, LabelKeyEncoder,
        LabelSetEncoder, LabelValueEncoder, MetricEncoder, NoLabelSet,
    },
    metrics::{MetricType, TypedMetric},
    registry,
    registry::Metric,
};

/// Underlying Prometheus metric types. Used when constructing a metric
/// to pass to [`crate::Metrics::register`].
pub mod raw {
    pub use prometheus_client::metrics::{
        counter::Counter,
        family::{self, Family},
        gauge::Gauge,
        histogram::Histogram,
    };
}

use commonware_utils::sync::Mutex;
use prometheus_client::encoding::{
    text::{encode, encode_eof},
    MetricEncoder as PromMetricEncoder,
};
use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    ops::Deref,
    sync::{atomic::Ordering, Arc, Weak},
};

/// Native integer width used by [`raw::Gauge`] on this target.
///
/// `i64` on platforms with 64-bit atomics, `i32` otherwise. Matches
/// `prometheus_client::metrics::gauge::Gauge`'s backing type.
#[cfg(target_has_atomic = "64")]
pub type GaugeValue = i64;
#[cfg(not(target_has_atomic = "64"))]
pub type GaugeValue = i32;

/// A registered counter metric.
pub type Counter = Registered<raw::Counter>;
/// A registered gauge metric.
pub type Gauge = Registered<raw::Gauge>;
/// A registered histogram metric.
pub type Histogram = Registered<raw::Histogram>;
/// A registered family of counters keyed by `L`.
pub type CounterFamily<L> = Registered<raw::Family<L, raw::Counter>>;
/// A registered family of gauges keyed by `L`.
pub type GaugeFamily<L> = Registered<raw::Family<L, raw::Gauge>>;

/// Convenience methods for Prometheus gauges.
pub trait GaugeExt {
    /// Set a gauge from a lossless integer conversion.
    fn try_set<T: TryInto<GaugeValue>>(&self, value: T) -> Result<GaugeValue, T::Error>;

    /// Atomically raise a gauge to at least the provided value.
    fn try_set_max<T: TryInto<GaugeValue> + Copy>(&self, value: T) -> Result<GaugeValue, T::Error>;
}

impl GaugeExt for raw::Gauge {
    fn try_set<T: TryInto<GaugeValue>>(&self, value: T) -> Result<GaugeValue, T::Error> {
        let value = value.try_into()?;
        Ok(self.set(value))
    }

    fn try_set_max<T: TryInto<GaugeValue> + Copy>(&self, value: T) -> Result<GaugeValue, T::Error> {
        let value = value.try_into()?;
        Ok(self.inner().fetch_max(value, Ordering::Relaxed))
    }
}

pub use histogram::HistogramExt;

/// One-line constructors for the common metric types.
///
/// ```ignore
/// use commonware_runtime::telemetry::metrics::MetricsExt;
/// let votes = context.counter("votes", "vote count");
/// ```
pub trait MetricsExt: crate::Metrics {
    /// Register a counter with the runtime.
    fn counter<N: Into<String>, H: Into<String>>(&self, name: N, help: H) -> Counter {
        self.register(name, help, raw::Counter::default())
    }

    /// Register a gauge with the runtime.
    fn gauge<N: Into<String>, H: Into<String>>(&self, name: N, help: H) -> Gauge {
        self.register(name, help, raw::Gauge::default())
    }

    /// Register a histogram with the runtime.
    fn histogram<N: Into<String>, H: Into<String>, I>(
        &self,
        name: N,
        help: H,
        buckets: I,
    ) -> Histogram
    where
        I: IntoIterator<Item = f64>,
    {
        self.register(name, help, raw::Histogram::new(buckets))
    }

    /// Register a metric family with the runtime.
    fn family<N, H, S, M>(&self, name: N, help: H) -> Registered<raw::Family<S, M>>
    where
        N: Into<String>,
        H: Into<String>,
        S: Clone + std::hash::Hash + Eq,
        M: Default,
        raw::Family<S, M>: Metric,
    {
        self.register(name, help, raw::Family::<S, M>::default())
    }
}

impl<T: crate::Metrics> MetricsExt for T {}

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
/// use commonware_runtime::{
///     deterministic, telemetry::metrics::count_running_tasks, Clock, Metrics, Runner, Spawner,
/// };
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
#[cfg(any(test, feature = "test-utils"))]
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

// Adapted from client_rust's internal descriptor encoder:
// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L218-L275
//
// Commonware needs a local copy because upstream keeps this helper internal
// while the runtime assembles metric samples independently. We only emit
// unit-less descriptors, so the `# UNIT` line is omitted.
fn encode_descriptor<W>(
    writer: &mut W,
    name: &str,
    help: &str,
    metric_type: MetricType,
) -> Result<(), std::fmt::Error>
where
    W: std::fmt::Write,
{
    writer.write_str("# HELP ")?;
    writer.write_str(name)?;
    writer.write_str(" ")?;
    writer.write_str(help)?;
    writer.write_str("\n# TYPE ")?;
    writer.write_str(name)?;
    writer.write_str(" ")?;
    writer.write_str(metric_type.as_str())?;
    writer.write_str("\n")?;
    Ok(())
}

pub(crate) fn prefixed_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}_{name}")
    }
}

/// Build a child context label by appending `label` to `prefix`, asserting that
/// `label` is valid and does not shadow the reserved runtime metric prefix.
pub(crate) fn child_label(prefix: &str, label: &str) -> String {
    validate_label(label);
    let name = prefixed_name(prefix, label);
    assert!(
        !name.starts_with(METRICS_PREFIX),
        "using runtime label is not allowed"
    );
    name
}

trait RegistrationGuard: Send + Sync {
    fn close(&self, _registration: &Arc<dyn RegistrationGuard>) {}
}

impl<G: Send + 'static> RegistrationGuard for GuardHolder<G> {}

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

    fn downgrade(&self) -> Weak<dyn RegistrationGuard> {
        Arc::downgrade(&self.inner)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.close(&self.inner);
        }
    }
}

struct RuntimeRegistration {
    id: u64,
    registry: Weak<Mutex<RegistryInner>>,
}

impl RegistrationGuard for RuntimeRegistration {
    fn close(&self, registration: &Arc<dyn RegistrationGuard>) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        registry
            .lock()
            .unregister_if_registration(self.id, registration);
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
        Self {
            metric: Arc::new(metric),
            registration,
        }
    }

    pub fn metric(&self) -> &M {
        self.metric.as_ref()
    }
}

impl<S, M, C> Registered<raw::Family<S, M, C>>
where
    S: Clone + std::hash::Hash + Eq,
    C: raw::family::MetricConstructor<M>,
{
    pub fn get_by<Q>(&self, label_set: &Q) -> Option<impl Deref<Target = M> + '_>
    where
        for<'a> S: From<&'a Q>,
    {
        let label_set = S::from(label_set);
        self.get(&label_set)
    }

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

type MetricAttributes = Vec<(Cow<'static, str>, Cow<'static, str>)>;
type MetricKey = (String, MetricAttributes);
type SampleEncoder = dyn Fn(&mut String, &str, &[(Cow<'static, str>, Cow<'static, str>)]) -> Result<(), std::fmt::Error>
    + Send
    + Sync;

struct PendingMetricEntry {
    family_name: String,
    attributes: MetricAttributes,
    encode_samples: Box<SampleEncoder>,
    metric_any: Arc<dyn Any + Send + Sync>,
    registration: Weak<dyn RegistrationGuard>,
}

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
        let mut registry = registry::Registry::with_labels(labels.iter().cloned());
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

fn owned_attributes(attributes: Vec<(String, String)>) -> MetricAttributes {
    attributes
        .into_iter()
        .map(|(k, v)| (Cow::Owned(k), Cow::Owned(v)))
        .collect()
}

fn normalize_help(help: String) -> String {
    help + "."
}

struct MetricEntry {
    family_name: String,
    attributes: MetricAttributes,
    encode_samples: Box<SampleEncoder>,
    metric_any: Arc<dyn Any + Send + Sync>,
    /// Weak handle to the lifecycle token owned by the outstanding [`Registered<_>`].
    registration: Weak<dyn RegistrationGuard>,
    family_index: usize,
}

#[derive(Debug)]
struct MetricFamily {
    help: String,
    metric_type: MetricType,
    descriptor: String,
    metric_ids: Vec<u64>,
}

/// Manages metrics with explicit lifetimes.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<RegistryInner>>,
}

struct RegistryInner {
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
            inner: Arc::new(Mutex::new(RegistryInner::new())),
        }
    }

    pub(crate) fn register<M>(
        &self,
        name: String,
        help: String,
        attributes: Vec<(String, String)>,
        metric: Arc<M>,
    ) -> Registered<M>
    where
        M: Metric,
    {
        let mut inner = self.inner.lock();
        inner.register(Arc::downgrade(&self.inner), name, help, attributes, metric)
    }

    pub fn unregister(&self, id: u64) {
        self.inner.lock().unregister(id);
    }

    pub fn encode(&self) -> String {
        self.inner.lock().encode()
    }
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            metrics: Vec::new(),
            free_metric_ids: Vec::new(),
            families: BTreeMap::new(),
            keys: HashMap::new(),
            next_metric_id: 0,
        }
    }

    fn register<M>(
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
        let attributes = owned_attributes(attributes);
        // Match upstream prometheus-client's `Descriptor::new` normalization,
        // which unconditionally appends `.` to the help text.
        let help = normalize_help(help);
        let metric_type = metric.metric_type();
        let encode_samples = create_sample_encoder(metric.clone());
        let key = (name.clone(), attributes.clone());
        if let Some(existing_id) = self.keys.get(&key).copied() {
            let entry = self.metric_ref(existing_id);
            if let Some(inner) = entry.registration.upgrade() {
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
                return Registered {
                    metric: existing_metric,
                    registration: Registration { inner },
                };
            }
            // The entry has no live registration owner. This should not happen
            // for runtime-managed registrations, which unregister before their
            // Weak stops upgrading, but removing the stale entry lets callers
            // recover if a registry is abandoned before its handles are dropped.
            self.drop_metric_entry(existing_id);
        }
        self.assert_family_matches(&name, &help, metric_type);

        let id = self.allocate_metric_id();
        let registration = Registration {
            inner: Arc::new(RuntimeRegistration { id, registry }),
        };
        let metric_any: Arc<dyn Any + Send + Sync> = metric.clone();
        self.insert_metric_entry(
            id,
            help,
            metric_type,
            PendingMetricEntry {
                family_name: name,
                attributes,
                encode_samples,
                metric_any,
                registration: registration.downgrade(),
            },
        );
        Registered {
            metric,
            registration,
        }
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

    fn assert_family_matches(&self, name: &str, help: &str, metric_type: MetricType) {
        if let Some(family) = self.families.get(name) {
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
    }

    fn insert_metric_entry(
        &mut self,
        id: u64,
        help: String,
        metric_type: MetricType,
        entry: PendingMetricEntry,
    ) {
        let PendingMetricEntry {
            family_name,
            attributes,
            encode_samples,
            metric_any,
            registration,
        } = entry;
        self.keys
            .insert((family_name.clone(), attributes.clone()), id);
        let family = match self.families.entry(family_name.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut descriptor = String::new();
                encode_descriptor(&mut descriptor, &family_name, &help, metric_type)
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
            family_name,
            attributes,
            encode_samples,
            metric_any,
            registration,
            family_index,
        });
    }

    pub fn unregister(&mut self, id: u64) {
        if self
            .metrics
            .get(Self::metric_index(id))
            .and_then(Option::as_ref)
            .is_none()
        {
            return;
        }
        self.drop_metric_entry(id);
    }

    fn unregister_if_registration(&mut self, id: u64, registration: &Arc<dyn RegistrationGuard>) {
        let Some(entry) = self
            .metrics
            .get(Self::metric_index(id))
            .and_then(Option::as_ref)
        else {
            return;
        };
        let registration_weak = Arc::downgrade(registration);
        if !entry.registration.ptr_eq(&registration_weak) {
            return;
        }
        if Arc::strong_count(registration) != 1 {
            return;
        }
        self.drop_metric_entry(id);
    }

    fn drop_metric_entry(&mut self, id: u64) {
        let metric = self
            .metrics
            .get_mut(Self::metric_index(id))
            .and_then(Option::take)
            .expect("metric id missing from registry");
        let MetricEntry {
            family_name,
            attributes,
            family_index,
            ..
        } = metric;
        let key = (family_name, attributes);
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
            assert_eq!(removed, id, "family index mismatch during unregister");
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

pub struct Scope {
    registry: Registry,
    prefix: String,
}

/// Shared registration surface accepted by runtime-owned constructors.
///
/// Both [`Registry`] (no prefix) and [`Scope`] (with prefix) implement
/// this, so a `fn new(registry: &mut impl Register)` can accept either
/// without the caller having to produce a scope first.
pub trait Register {
    /// Register a metric under this scope's prefix.
    fn register<M: Metric>(&mut self, name: &str, help: &str, metric: M) -> Registered<M>;

    /// Create a child scope by appending `prefix` to the current prefix.
    fn sub_registry(&mut self, prefix: &str) -> Scope;
}

impl Register for Registry {
    fn register<M: Metric>(&mut self, name: &str, help: &str, metric: M) -> Registered<M> {
        validate_label(name);
        Registry::register(
            self,
            name.to_string(),
            help.to_string(),
            Vec::new(),
            Arc::new(metric),
        )
    }

    fn sub_registry(&mut self, prefix: &str) -> Scope {
        validate_label(prefix);
        Scope {
            registry: self.clone(),
            prefix: prefix.to_string(),
        }
    }
}

impl Register for Scope {
    fn register<M: Metric>(&mut self, name: &str, help: &str, metric: M) -> Registered<M> {
        validate_label(name);
        let name = prefixed_name(&self.prefix, name);
        let help = help.to_string();
        let metric = Arc::new(metric);
        Registry::register(&self.registry, name, help, Vec::new(), metric)
    }

    fn sub_registry(&mut self, prefix: &str) -> Scope {
        validate_label(prefix);
        Scope {
            registry: self.registry.clone(),
            prefix: prefixed_name(&self.prefix, prefix),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Metrics, Runner, Spawner};
    use commonware_macros::test_traced;
    use futures::future;
    use std::sync::mpsc::{self, TryRecvError};

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
            let c1 = raw::Counter::<u64>::default();
            let _metric_a = context.with_label("a").register("test", "help", c1);
            let c2 = raw::Counter::<u64>::default();
            let _metric_b = context.with_label("b").register("test", "help", c2);
        });
        // Test passes if runtime doesn't panic on shutdown
    }

    #[test_traced]
    fn test_duplicate_metrics_reuse_existing_handle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let c1 = raw::Counter::<u64>::default();
            let metric_a = context.with_label("a").register("test", "help", c1);
            let c2 = raw::Counter::<u64>::default();
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
            let counter = raw::Counter::<u64>::default();
            let _metric_a = context.with_label("a").register("test", "help", counter);
            let gauge = raw::Gauge::<i64>::default();
            let _metric_b = context.with_label("a").register("test", "help", gauge);
        });
    }

    #[test]
    fn test_stale_registration_does_not_remove_reused_metric_id() {
        let registry = Registry::new();
        let key: MetricKey = ("votes".to_string(), Vec::new());

        let original = registry.register(
            key.0.clone(),
            "vote count".to_string(),
            Vec::new(),
            Arc::new(raw::Counter::<u64>::default()),
        );
        let original_id = {
            let registry = registry.inner.lock();
            *registry.keys.get(&key).expect("metric key missing")
        };
        let original_registration = {
            let registry = registry.inner.lock();
            registry
                .metric_ref(original_id)
                .registration
                .upgrade()
                .expect("registration missing")
        };

        registry.inner.lock().drop_metric_entry(original_id);
        drop(original);

        let replacement = registry.register(
            key.0.clone(),
            "vote count".to_string(),
            Vec::new(),
            Arc::new(raw::Counter::<u64>::default()),
        );
        replacement.inc_by(7);

        let replacement_id = {
            let registry = registry.inner.lock();
            *registry.keys.get(&key).expect("metric key missing")
        };
        assert_eq!(
            original_id, replacement_id,
            "replacement should safely reuse the freed metric id"
        );

        registry
            .inner
            .lock()
            .unregister_if_registration(original_id, &original_registration);

        let encoded = registry.encode();
        assert!(
            encoded.contains("votes_total 7"),
            "stale registration removed replacement metric: {encoded}"
        );

        registry.unregister(replacement_id);
        drop(replacement);
        let registry = registry.inner.lock();
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

    #[test]
    fn test_registered_detached_creates_detached_handle() {
        let registered = Registered::detached(raw::Counter::<u64>::default());
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
            raw::Counter::<u64>::default(),
            Registration::from_guard(NotifyOnDrop(tx)),
        );
        let clone = registered.clone();

        drop(registered);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        drop(clone);
        assert_eq!(rx.recv().unwrap(), "dropped");
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
    }

    fn register_counter(registry: &Registry, name: &str, help: &str, value: u64) -> Counter {
        let counter = raw::Counter::<u64>::default();
        counter.inc_by(value);
        registry.register(
            name.to_string(),
            help.to_string(),
            Vec::new(),
            Arc::new(counter),
        )
    }

    #[test]
    fn test_encode_is_deterministic() {
        let registry = Registry::default();
        let _beta = register_counter(&registry, "beta", "beta counter", 2);
        let _alpha = register_counter(&registry, "alpha", "alpha counter", 1);
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
        let registry = Registry::default();
        let _a = register_counter(&registry, "a", "help", 1);
        let _b = register_counter(&registry, "b", "help", 2);
        let encoded = registry.encode();
        assert_eq!(encoded.matches("# EOF").count(), 1);
        assert!(
            encoded.ends_with("# EOF\n"),
            "must terminate with EOF: {encoded}"
        );
    }

    #[test]
    fn test_encode_type_aware_suffixes() {
        let registry = Registry::default();
        let _requests = register_counter(&registry, "requests", "request count", 3);
        let histogram = raw::Histogram::new([0.1, 1.0, 10.0]);
        histogram.observe(0.5);
        let _histogram = registry.register(
            "latency".to_string(),
            "latency seconds".to_string(),
            Vec::new(),
            Arc::new(histogram),
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
        let registry = Registry::default();
        let c1 = raw::Counter::<u64>::default();
        c1.inc();
        let _c1 = registry.register(
            "votes".to_string(),
            "vote count".to_string(),
            vec![("epoch".to_string(), "1".to_string())],
            Arc::new(c1),
        );
        let c2 = raw::Counter::<u64>::default();
        c2.inc_by(2);
        let _c2 = registry.register(
            "votes".to_string(),
            "vote count".to_string(),
            vec![("epoch".to_string(), "2".to_string())],
            Arc::new(c2),
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
    fn test_encode_registers_without_prefix() {
        let registry = Registry::default();
        let _registered = register_counter(&registry, "votes", "vote count", 1);
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
        let registry = Registry::default();
        let empty_family = raw::Family::<Vec<(String, String)>, raw::Counter>::default();
        let _empty_family = registry.register(
            "votes".to_string(),
            "vote count".to_string(),
            Vec::new(),
            Arc::new(empty_family),
        );
        let _ticks = register_counter(&registry, "ticks", "tick count", 1);
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
        let counter = raw::Counter::<u64>::default();
        counter.inc_by(7);
        let gauge = raw::Gauge::<i64>::default();
        gauge.set(-3);
        let histogram = raw::Histogram::new([0.1, 1.0]);
        histogram.observe(0.5);

        let ours = Registry::default();
        let _latency = ours.register(
            "latency".to_string(),
            "request latency seconds".to_string(),
            Vec::new(),
            Arc::new(histogram.clone()),
        );
        let _level = ours.register(
            "level".to_string(),
            "current level".to_string(),
            Vec::new(),
            Arc::new(gauge.clone()),
        );
        let _votes = ours.register(
            "votes".to_string(),
            "number of votes".to_string(),
            Vec::new(),
            Arc::new(counter.clone()),
        );
        let ours_encoded = ours.encode();

        let mut theirs = registry::Registry::default();
        theirs.register("latency", "request latency seconds", histogram);
        theirs.register("level", "current level", gauge);
        theirs.register("votes", "number of votes", counter);
        let mut theirs_encoded = String::new();
        encode(&mut theirs_encoded, &theirs).expect("upstream encode failed");

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
        let registry = Registry::new();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let mut registry = registry.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        let handle = Register::register(
                            &mut registry,
                            "votes",
                            "vote count",
                            raw::Counter::<u64>::default(),
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
        let registry = registry.inner.lock();
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
