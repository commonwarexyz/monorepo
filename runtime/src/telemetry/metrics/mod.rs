//! Utility functions for metrics

pub mod histogram;
mod counter;
mod family;
mod gauge;
mod registration;
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

pub use counter::{Counter as RawCounter, CounterValue};
pub use family::{Family, FamilyValue};
pub use gauge::{Gauge as RawGauge, GaugeValue};
pub use histogram::HistogramExt;

/// Underlying metric types. Used when constructing a metric to pass to
/// [`crate::Metrics::register`].
pub mod raw {
    pub use super::{histogram::Histogram, Family, RawCounter as Counter, RawGauge as Gauge};
}

use commonware_utils::sync::Mutex;
use prometheus_client::encoding::{
    text::{encode_eof, encode_registry},
    MetricEncoder as PromMetricEncoder,
};
pub use registration::Registration;
use registration::{RegistrationGuard, RegistrationInner};
use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fmt::Write,
    ops::Deref,
    sync::{Arc, Weak},
};

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

/// One-line constructors for the common metric types.
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

// Adaptation of client_rust's internal descriptor encoder.
//
// Source:
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

/// Join a metric or label prefix with a child name using Prometheus' `_` separator.
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

struct RuntimeRegistration {
    id: u64,
    registry: Weak<Mutex<RegistryInner>>,
}

impl RegistrationGuard for RuntimeRegistration {
    fn registration_dropped(&self, registration: &Arc<RegistrationInner>) {
        // Keep the dropped claim counted until the registry lock is held. A
        // concurrent register can then either acquire this live registration or
        // wait for the entry to be removed.
        let Some(registry) = self.registry.upgrade() else {
            registration.release();
            return;
        };
        registry.lock().release_registration(self.id, registration);
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

impl<S, M> Registered<raw::Family<S, M>>
where
    S: Clone + std::hash::Hash + Eq + EncodeLabelSetTrait + Send + Sync + std::fmt::Debug + 'static,
    M: FamilyValue + Default + EncodeMetric,
{
    pub fn get_by<Q>(&self, label_set: &Q) -> Option<Arc<M>>
    where
        for<'a> S: From<&'a Q>,
    {
        let label_set = S::from(label_set);
        self.get(&label_set)
    }

    pub fn get_or_create_by<Q>(&self, label_set: &Q) -> Arc<M>
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
type SampleEncoder = dyn Fn(&mut String) -> Result<(), std::fmt::Error> + Send + Sync;

struct PendingMetricEntry {
    family_name: String,
    attributes: MetricAttributes,
    encode_samples: Box<SampleEncoder>,
    metric_any: Arc<dyn Any + Send + Sync>,
    registration: Weak<RegistrationInner>,
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

fn encode_label_suffix(attributes: &MetricAttributes) -> String {
    if attributes.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    output.push('{');
    for (i, (key, value)) in attributes.iter().enumerate() {
        if i != 0 {
            output.push(',');
        }
        output.push_str(key);
        output.push_str("=\"");
        output.push_str(value);
        output.push('"');
    }
    output.push('}');
    output
}

fn create_counter_encoder(
    name: String,
    attributes: &MetricAttributes,
    metric: Arc<raw::Counter>,
) -> Box<SampleEncoder> {
    let mut line_prefix = name;
    line_prefix.push_str("_total");
    line_prefix.push_str(&encode_label_suffix(attributes));
    line_prefix.push(' ');

    Box::new(move |samples| {
        samples.push_str(&line_prefix);
        write!(samples, "{}", metric.get())?;
        samples.push('\n');
        Ok(())
    })
}

fn create_gauge_encoder(
    name: String,
    attributes: &MetricAttributes,
    metric: Arc<raw::Gauge>,
) -> Box<SampleEncoder> {
    let mut line_prefix = name;
    line_prefix.push_str(&encode_label_suffix(attributes));
    line_prefix.push(' ');

    Box::new(move |samples| {
        samples.push_str(&line_prefix);
        write!(samples, "{}", metric.get())?;
        samples.push('\n');
        Ok(())
    })
}

// Adaptation of client_rust's text histogram encoder.
//
// Source:
// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L399-L466
//
// Histogram bucket bounds and registration labels are fixed after
// registration, so we cache their text prefixes once and only format the
// changing sample values during scrapes.
fn encode_histogram_bucket_label_suffix(base: &str, upper_bound: f64) -> String {
    let label = if upper_bound == f64::MAX {
        "+Inf".to_string()
    } else if upper_bound.fract() == 0.0 {
        format!("{upper_bound:.1}")
    } else {
        upper_bound.to_string()
    };
    let mut suffix = String::new();
    if base.is_empty() {
        suffix.push_str("{le=\"");
        suffix.push_str(&label);
        suffix.push_str("\"}");
    } else {
        suffix.push_str(&base[..base.len() - 1]);
        suffix.push_str(",le=\"");
        suffix.push_str(&label);
        suffix.push_str("\"}");
    }
    suffix
}

fn create_histogram_encoder(
    name: String,
    attributes: &MetricAttributes,
    histogram: Arc<raw::Histogram>,
) -> Box<SampleEncoder> {
    let label_suffix = encode_label_suffix(attributes);
    let mut sum_prefix = name.clone();
    sum_prefix.push_str("_sum");
    sum_prefix.push_str(&label_suffix);
    sum_prefix.push(' ');

    let mut count_prefix = name.clone();
    count_prefix.push_str("_count");
    count_prefix.push_str(&label_suffix);
    count_prefix.push(' ');

    let bucket_prefixes = histogram
        .bucket_bounds()
        .into_iter()
        .map(|upper_bound| {
            let mut prefix = name.clone();
            prefix.push_str("_bucket");
            prefix.push_str(&encode_histogram_bucket_label_suffix(&label_suffix, upper_bound));
            prefix.push(' ');
            prefix
        })
        .collect::<Vec<_>>();
    Box::new(move |samples| {
        histogram.encode_samples(&sum_prefix, &count_prefix, &bucket_prefixes, samples)
    })
}

fn create_family_encoder<S, M>(
    name: String,
    attributes: &MetricAttributes,
    family: Arc<raw::Family<S, M>>,
) -> Box<SampleEncoder>
where
    S: Clone
        + std::hash::Hash
        + Eq
        + EncodeLabelSetTrait
        + Send
        + Sync
        + std::fmt::Debug
        + 'static,
    M: FamilyValue + Default + EncodeMetric,
{
    let label_suffix = encode_label_suffix(attributes);
    Box::new(move |samples| family.encode_samples(&name, &label_suffix, samples))
}

// Fast path for native metrics.
//
// Source:
// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L314-L361
//
// `prometheus-client` keeps its text `MetricEncoder` constructor private, so
// generic metrics still use a temporary upstream registry below. Native
// counters, gauges, histograms, and supported families have simple, stable
// sample shapes, so we encode those lines directly and keep the generic path as
// a fallback.
fn create_sample_encoder<M>(
    name: String,
    attributes: MetricAttributes,
    metric: Arc<M>,
) -> Box<SampleEncoder>
where
    M: Metric,
{
    let metric_any: Arc<dyn Any + Send + Sync> = metric.clone();
    if let Ok(counter) = Arc::downcast::<raw::Counter>(metric_any.clone()) {
        return create_counter_encoder(name, &attributes, counter);
    }
    if let Ok(gauge) = Arc::downcast::<raw::Gauge>(metric_any) {
        return create_gauge_encoder(name, &attributes, gauge);
    }
    let metric_any: Arc<dyn Any + Send + Sync> = metric.clone();
    if let Ok(histogram) = Arc::downcast::<raw::Histogram>(metric_any) {
        return create_histogram_encoder(name, &attributes, histogram);
    }
    let metric_type = metric.metric_type();
    let mut descriptor = String::new();
    encode_descriptor(&mut descriptor, &name, ".", metric_type)
        .expect("encoding fallback descriptor failed");
    let descriptor_len = descriptor.len();

    Box::new(move |samples| {
        let mut registry = registry::Registry::with_labels(attributes.clone().into_iter());
        registry.register(name.as_str(), "", SharedMetric(metric.clone()));

        let mut encoded = String::new();
        encode_registry(&mut encoded, &registry).expect("encoding temporary metric registry failed");
        samples.push_str(&encoded[descriptor_len.min(encoded.len())..]);
        Ok(())
    })
}

fn owned_attributes(attributes: Vec<(String, String)>) -> MetricAttributes {
    attributes
        .into_iter()
        .map(|(k, v)| (Cow::Owned(k), Cow::Owned(v)))
        .collect()
}

// Match upstream prometheus-client's `Descriptor::new` normalization.
//
// Source:
// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/registry.rs#L340-L348
fn normalize_help(help: String) -> String {
    help + "."
}

struct MetricEntry {
    family_name: String,
    attributes: MetricAttributes,
    encode_samples: Box<SampleEncoder>,
    metric_any: Arc<dyn Any + Send + Sync>,
    /// Weak handle to the lifecycle token owned by the outstanding [`Registered<_>`].
    registration: Weak<RegistrationInner>,
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
    /// Dense metric storage indexed by stable metric id.
    metrics: Vec<Option<MetricEntry>>,
    /// Metric ids that can be reused after a metric is fully unregistered.
    free_metric_ids: Vec<u64>,
    /// Metric families keyed by family name, kept sorted for deterministic encoding.
    families: BTreeMap<String, MetricFamily>,
    /// Exact metric keys for duplicate registration detection.
    keys: HashMap<MetricKey, u64>,
    /// Monotonic id source used when there is no reusable metric slot.
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

    pub(crate) fn register_family<S, M>(
        &self,
        name: String,
        help: String,
        attributes: Vec<(String, String)>,
        family: Arc<raw::Family<S, M>>,
    ) -> Registered<raw::Family<S, M>>
    where
        S: Clone
            + std::hash::Hash
            + Eq
            + EncodeLabelSetTrait
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        M: FamilyValue + Default + EncodeMetric,
    {
        let mut inner = self.inner.lock();
        inner.register_family(Arc::downgrade(&self.inner), name, help, attributes, family)
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
        let help = normalize_help(help);
        let metric_type = metric.metric_type();
        let encode_samples =
            create_sample_encoder(name.clone(), attributes.clone(), metric.clone());
        let key = (name.clone(), attributes.clone());
        if let Some(existing_id) = self.keys.get(&key).copied() {
            let entry = self.metric_ref(existing_id);
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
            // Runtime registrations release under this same mutex, so a keyed
            // entry cannot have a closed lifecycle token.
            let registration = entry
                .registration
                .upgrade()
                .and_then(RegistrationInner::claim)
                .expect("metric key references closed registration");
            return Registered {
                metric: existing_metric,
                registration,
            };
        }
        self.assert_family_matches(&name, &help, metric_type);

        let id = self.allocate_metric_id();
        let registration =
            Registration::from_inner(RegistrationInner::new(RuntimeRegistration { id, registry }));
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

    fn register_family<S, M>(
        &mut self,
        registry: Weak<Mutex<Self>>,
        name: String,
        help: String,
        attributes: Vec<(String, String)>,
        family: Arc<raw::Family<S, M>>,
    ) -> Registered<raw::Family<S, M>>
    where
        S: Clone
            + std::hash::Hash
            + Eq
            + EncodeLabelSetTrait
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        M: FamilyValue + Default + EncodeMetric,
    {
        let attributes = owned_attributes(attributes);
        let help = normalize_help(help);
        let metric_type = family.metric_type();
        let encode_samples =
            create_family_encoder(name.clone(), &attributes, family.clone());
        let key = (name.clone(), attributes.clone());
        if let Some(existing_id) = self.keys.get(&key).copied() {
            let entry = self.metric_ref(existing_id);
            if let Some(family_meta) = self.families.get(&name) {
                assert_eq!(
                    family_meta.help, help,
                    "metric family `{}` registered with inconsistent help text",
                    name
                );
            }
            let existing_metric = Arc::clone(&entry.metric_any)
                .downcast::<raw::Family<S, M>>()
                .unwrap_or_else(|_| {
                    panic!(
                        "duplicate metric `{}` with attributes {:?} registered with different type",
                        key.0, key.1
                    )
                });
            let registration = entry
                .registration
                .upgrade()
                .and_then(RegistrationInner::claim)
                .expect("metric key references closed registration");
            return Registered {
                metric: existing_metric,
                registration,
            };
        }
        self.assert_family_matches(&name, &help, metric_type);

        let id = self.allocate_metric_id();
        let registration =
            Registration::from_inner(RegistrationInner::new(RuntimeRegistration { id, registry }));
        let metric_any: Arc<dyn Any + Send + Sync> = family.clone();
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
            metric: family,
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

    fn release_registration(&mut self, id: u64, registration: &Arc<RegistrationInner>) {
        let Some(entry) = self
            .metrics
            .get(Self::metric_index(id))
            .and_then(Option::as_ref)
        else {
            // The registry may already have explicitly removed this metric
            // while an older handle still owns a lifecycle claim.
            registration.release();
            return;
        };
        let registration_weak = Arc::downgrade(registration);
        if !entry.registration.ptr_eq(&registration_weak) {
            // The metric id has been reused for a newer registration. Release
            // only the stale claim and leave the replacement entry intact.
            registration.release();
            return;
        }
        // A duplicate register may have acquired this registration while the
        // dropping claim waited for the registry lock.
        if registration.release() {
            self.drop_metric_entry(id);
        }
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
        for family in self.families.values() {
            samples.clear();
            for metric_id in &family.metric_ids {
                let metric = self.metric_ref(*metric_id);
                (metric.encode_samples)(&mut samples).expect("encoding live metric samples failed");
            }
            // Suppress the HELP/TYPE descriptor when the family produced no
            // samples (e.g. a `Family<S, M>` with no child entries).
            //
            // Source:
            // https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L1283-L1298
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

pub(crate) struct Scope {
    registry: Registry,
    prefix: String,
}

pub(crate) trait Register {
    /// Register a metric under this scope's prefix.
    fn register<M: Metric>(&mut self, name: &str, help: &str, metric: M) -> Registered<M>;

    /// Register a native counter or gauge family under this scope's prefix.
    fn family<S, M>(&mut self, name: &str, help: &str) -> Registered<raw::Family<S, M>>
    where
        S: Clone
            + std::hash::Hash
            + Eq
            + EncodeLabelSetTrait
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        M: FamilyValue + Default + EncodeMetric;

    /// Create a child scope by appending `prefix` to the current prefix.
    fn sub_registry(&mut self, prefix: &str) -> Scope;
}

impl Register for Registry {
    fn register<M: Metric>(&mut self, name: &str, help: &str, metric: M) -> Registered<M> {
        validate_label(name);
        Self::register(
            self,
            name.to_string(),
            help.to_string(),
            Vec::new(),
            Arc::new(metric),
        )
    }

    fn family<S, M>(&mut self, name: &str, help: &str) -> Registered<raw::Family<S, M>>
    where
        S: Clone
            + std::hash::Hash
            + Eq
            + EncodeLabelSetTrait
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        M: FamilyValue + Default + EncodeMetric,
    {
        validate_label(name);
        let family = Family::<S, M>::default();
        Self::register_family(
            self,
            name.to_string(),
            help.to_string(),
            Vec::new(),
            Arc::new(family),
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

    fn family<S, M>(&mut self, name: &str, help: &str) -> Registered<raw::Family<S, M>>
    where
        S: Clone
            + std::hash::Hash
            + Eq
            + EncodeLabelSetTrait
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        M: FamilyValue + Default + EncodeMetric,
    {
        validate_label(name);
        let family = Family::<S, M>::default();
        Registry::register_family(
            &self.registry,
            prefixed_name(&self.prefix, name),
            help.to_string(),
            Vec::new(),
            Arc::new(family),
        )
    }

    fn sub_registry(&mut self, prefix: &str) -> Scope {
        validate_label(prefix);
        Self {
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
    use prometheus_client::encoding::text::encode;
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
    fn test_closed_registration_does_not_remove_reused_metric_id() {
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

        registry.inner.lock().drop_metric_entry(original_id);

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

        drop(original);

        let encoded = registry.encode();
        assert!(
            encoded.contains("votes_total 7"),
            "stale registration removed replacement metric: {encoded}"
        );

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
    fn test_duplicate_register_acquires_during_last_drop_window() {
        let registry = Registry::new();
        let key: MetricKey = ("votes".to_string(), Vec::new());

        let original = registry.register(
            key.0.clone(),
            "vote count".to_string(),
            Vec::new(),
            Arc::new(raw::Counter::<u64>::default()),
        );
        let original_metric = Arc::clone(&original.metric);
        let _original = std::mem::ManuallyDrop::new(original);
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

        // Simulate the final drop after it has decided to clean up but before
        // it obtains the registry lock. The dropped claim is still counted in
        // this window.
        let duplicate = registry.register(
            key.0.clone(),
            "vote count".to_string(),
            Vec::new(),
            Arc::new(raw::Counter::<u64>::default()),
        );
        assert!(Arc::ptr_eq(&original_metric, &duplicate.metric));

        registry
            .inner
            .lock()
            .release_registration(original_id, &original_registration);

        duplicate.inc_by(7);
        let encoded = registry.encode();
        assert!(
            encoded.contains("votes_total 7"),
            "last drop removed duplicate registration: {encoded}"
        );

        drop(duplicate);
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
    fn test_encode_native_counter_family() {
        let mut registry = Registry::default();
        let family: CounterFamily<Vec<(String, String)>> =
            Register::family(&mut registry, "votes", "vote count");
        family
            .get_or_create(&vec![("epoch".to_string(), "1".to_string())])
            .inc();
        family
            .get_or_create(&vec![("epoch".to_string(), "2".to_string())])
            .inc_by(2);

        let encoded = registry.encode();
        assert_eq!(
            encoded.matches("# HELP votes").count(),
            1,
            "single HELP: {encoded}"
        );
        assert!(encoded.contains("votes_total{epoch=\"1\"} 1"));
        assert!(encoded.contains("votes_total{epoch=\"2\"} 2"));
    }

    #[test]
    fn test_encode_native_counter_family_with_attributes() {
        let registry = Registry::default();
        let family = raw::Family::<Vec<(String, String)>, raw::Counter>::default();
        let family = registry.register_family(
            "votes".to_string(),
            "vote count".to_string(),
            vec![("region".to_string(), "us".to_string())],
            Arc::new(family),
        );
        family
            .get_or_create(&vec![("epoch".to_string(), "1".to_string())])
            .inc();

        let encoded = registry.encode();
        assert!(
            encoded.contains("votes_total{region=\"us\",epoch=\"1\"} 1"),
            "attributes and family labels should both be encoded: {encoded}"
        );
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
    fn test_encode_native_families_match_upstream_registry() {
        // Covers native family sample formatting, including registry labels
        // merged ahead of child labels.
        let levels = raw::Family::<Vec<(String, String)>, raw::Gauge>::default();
        levels
            .get_or_create(&vec![("queue".to_string(), "pending".to_string())])
            .set(4);
        let requests = raw::Family::<Vec<(String, String)>, raw::Counter>::default();
        requests
            .get_or_create(&vec![("method".to_string(), "GET".to_string())])
            .inc_by(3);
        requests
            .get_or_create(&vec![("method".to_string(), "POST".to_string())])
            .inc_by(5);

        let ours = Registry::default();
        let labels = vec![("region".to_string(), "us".to_string())];
        let _levels = ours.register_family(
            "levels".to_string(),
            "current queue depth".to_string(),
            labels.clone(),
            Arc::new(levels.clone()),
        );
        let _requests = ours.register_family(
            "requests".to_string(),
            "number of requests".to_string(),
            labels.clone(),
            Arc::new(requests.clone()),
        );
        let ours_encoded = ours.encode();

        let mut theirs = registry::Registry::with_labels(owned_attributes(labels).into_iter());
        theirs.register("levels", "current queue depth", levels);
        theirs.register("requests", "number of requests", requests);
        let mut theirs_encoded = String::new();
        encode(&mut theirs_encoded, &theirs).expect("upstream encode failed");

        assert_eq!(
            ours_encoded, theirs_encoded,
            "native family output diverged from upstream prometheus-client registry"
        );
    }

    #[test]
    fn test_shuffled_duplicate_drops_do_not_leave_registry_entries() {
        let registry = Registry::new();
        let mut handles = Vec::new();

        for _ in 0..8 {
            handles.push(registry.register(
                "votes".to_string(),
                "vote count".to_string(),
                Vec::new(),
                Arc::new(raw::Counter::<u64>::default()),
            ));
        }

        for index in [3, 0, 6, 1] {
            let _ = handles.swap_remove(index);
            handles.push(registry.register(
                "votes".to_string(),
                "vote count".to_string(),
                Vec::new(),
                Arc::new(raw::Counter::<u64>::default()),
            ));
        }

        drop(handles);
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
