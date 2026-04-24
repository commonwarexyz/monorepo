use super::raw;
use commonware_utils::sync::Mutex;
use prometheus_client::{
    encoding::{
        text::encode_registry, EncodeLabelSet as EncodeLabelSetTrait, EncodeMetric, MetricEncoder,
    },
    metrics::{MetricType, TypedMetric},
    registry,
};
use std::{collections::HashMap, fmt::Write, sync::Arc};

/// Metric value supported by native runtime families.
pub trait FamilyValue: Send + Sync + std::fmt::Debug + 'static {
    const TYPE: MetricType;
    const NAME_SUFFIX: &'static str;

    fn encode_value(&self, output: &mut String) -> Result<(), std::fmt::Error>;
}

impl FamilyValue for raw::Counter {
    const TYPE: MetricType = MetricType::Counter;
    const NAME_SUFFIX: &'static str = "_total";

    fn encode_value(&self, output: &mut String) -> Result<(), std::fmt::Error> {
        write!(output, "{}", self.get())
    }
}

impl FamilyValue for raw::Gauge {
    const TYPE: MetricType = MetricType::Gauge;
    const NAME_SUFFIX: &'static str = "";

    fn encode_value(&self, output: &mut String) -> Result<(), std::fmt::Error> {
        write!(output, "{}", self.get())
    }
}

struct FamilyEntry<S, M> {
    label_set: S,
    metric: Arc<M>,
    label_suffix: String,
}

struct FamilyInner<S, M> {
    entries: Vec<Option<FamilyEntry<S, M>>>,
    free: Vec<usize>,
    keys: HashMap<S, usize>,
}

impl<S, M> Default for FamilyInner<S, M> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            keys: HashMap::new(),
        }
    }
}

/// Native runtime family optimized for counter and gauge scrape encoding.
///
/// Sources:
/// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/metrics/family.rs#L102-L434
/// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L422-L560
///
/// This preserves upstream family semantics: a label set maps to one child
/// metric, missing children are created lazily, and generic `EncodeMetric`
/// still encodes through `MetricEncoder::encode_family`. It is not a direct
/// copy: upstream stores children in a `RwLock<HashMap<S, M>>` and returns read
/// guards, while this stores entries in a reusable slot table, returns `Arc<M>`,
/// caches the escaped label suffix at child creation, and exposes direct sample
/// encoding for supported native child metric types.
pub struct Family<S, M> {
    inner: Arc<Mutex<FamilyInner<S, M>>>,
}

impl<S, M> Clone for Family<S, M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, M> Default for Family<S, M> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FamilyInner::default())),
        }
    }
}

impl<S, M> std::fmt::Debug for Family<S, M>
where
    S: std::fmt::Debug,
    M: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Family").finish_non_exhaustive()
    }
}

impl<S, M> Family<S, M>
where
    S: Clone + std::hash::Hash + Eq + EncodeLabelSetTrait + Send + Sync + std::fmt::Debug + 'static,
    M: Default,
{
    /// Access a metric with the given label set, creating it if one does not yet exist.
    pub fn get_or_create(&self, label_set: &S) -> Arc<M> {
        let mut inner = self.inner.lock();
        if let Some(index) = inner.keys.get(label_set) {
            return inner.entries[*index]
                .as_ref()
                .expect("family key references missing entry")
                .metric
                .clone();
        }

        let index = inner.free.pop().unwrap_or(inner.entries.len());
        let entry = FamilyEntry {
            label_set: label_set.clone(),
            metric: Arc::new(M::default()),
            label_suffix: encode_family_label_suffix(label_set),
        };
        if index == inner.entries.len() {
            inner.entries.push(Some(entry));
        } else {
            inner.entries[index] = Some(entry);
        }
        inner.keys.insert(label_set.clone(), index);
        inner.entries[index]
            .as_ref()
            .expect("inserted family entry missing")
            .metric
            .clone()
    }

    /// Access a metric with the given label set, returning `None` if it does not exist.
    pub fn get(&self, label_set: &S) -> Option<Arc<M>> {
        let inner = self.inner.lock();
        let index = inner.keys.get(label_set)?;
        Some(
            inner.entries[*index]
                .as_ref()
                .expect("family key references missing entry")
                .metric
                .clone(),
        )
    }

    /// Remove a label set from the metric family.
    pub fn remove(&self, label_set: &S) -> bool {
        let mut inner = self.inner.lock();
        let Some(index) = inner.keys.remove(label_set) else {
            return false;
        };
        inner.entries[index]
            .take()
            .expect("family key references missing entry");
        inner.free.push(index);
        true
    }

    /// Clear all label sets from the metric family.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.entries.clear();
        inner.free.clear();
        inner.keys.clear();
    }

    /// Returns the number of metrics in this family.
    pub fn len(&self) -> usize {
        self.inner.lock().keys.len()
    }

    /// Returns `true` if the family contains no metrics.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().keys.is_empty()
    }
}

impl<S, M> Family<S, M>
where
    M: FamilyValue,
{
    pub(crate) fn encode_samples(
        &self,
        name: &str,
        base_label_suffix: &str,
        output: &mut String,
    ) -> Result<(), std::fmt::Error> {
        let inner = self.inner.lock();
        for entry in inner.entries.iter().flatten() {
            output.push_str(name);
            output.push_str(M::NAME_SUFFIX);
            encode_combined_label_suffix(output, base_label_suffix, &entry.label_suffix);
            output.push(' ');
            entry.metric.encode_value(output)?;
            output.push('\n');
        }
        Ok(())
    }
}

impl<S, M> TypedMetric for Family<S, M>
where
    M: FamilyValue,
{
    const TYPE: MetricType = M::TYPE;
}

impl<S, M> EncodeMetric for Family<S, M>
where
    S: Clone + std::hash::Hash + Eq + EncodeLabelSetTrait + Send + Sync + std::fmt::Debug + 'static,
    M: FamilyValue + EncodeMetric,
{
    fn encode(&self, mut encoder: MetricEncoder<'_>) -> Result<(), std::fmt::Error> {
        let inner = self.inner.lock();
        for entry in inner.entries.iter().flatten() {
            let encoder = encoder.encode_family(&entry.label_set)?;
            entry.metric.encode(encoder)?;
        }
        Ok(())
    }

    fn metric_type(&self) -> MetricType {
        M::TYPE
    }

    fn is_empty(&self) -> bool {
        self.inner.lock().keys.is_empty()
    }
}

fn encode_combined_label_suffix(output: &mut String, base: &str, child: &str) {
    match (base.is_empty(), child.is_empty()) {
        (true, true) => {}
        (true, false) => output.push_str(child),
        (false, true) => output.push_str(base),
        (false, false) => {
            output.push_str(&base[..base.len() - 1]);
            output.push(',');
            output.push_str(&child[1..]);
        }
    }
}

fn encode_family_label_suffix<S>(label_set: &S) -> String
where
    S: Clone + std::hash::Hash + Eq + EncodeLabelSetTrait + Send + Sync + std::fmt::Debug + 'static,
{
    // Source:
    // https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L422-L560
    //
    // Upstream exposes `EncodeLabelSet` but keeps the text label encoder
    // constructor internal. Use upstream once when a child is created to cache
    // the exact escaped suffix, then keep scrape encoding native.
    const NAME: &str = "commonware_label_suffix";
    let family = prometheus_client::metrics::family::Family::<S, raw::Counter>::default();
    family.get_or_create(label_set).inc();

    let mut registry = registry::Registry::default();
    registry.register(NAME, "", family);

    let mut encoded = String::new();
    encode_registry(&mut encoded, &registry).expect("encoding temporary label registry failed");

    let sample_prefix = format!("{NAME}_total");
    let sample = encoded
        .lines()
        .find_map(|line| line.strip_prefix(&sample_prefix))
        .expect("temporary label registry produced no sample");
    sample
        .rsplit_once(' ')
        .map(|(suffix, _)| suffix.to_string())
        .expect("temporary label sample missing value")
}
