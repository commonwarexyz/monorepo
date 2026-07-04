//! Shared test-only tracing subscriber that records span topology.
//!
//! Used by ingress and service tests to assert parentage and `follows_from`
//! edges without exposing a public API.

use commonware_utils::sync::Mutex;
use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    Event, Metadata, Subscriber,
};
use tracing_core::span::Current;

/// A span observed by [`TraceRecorder`].
#[derive(Clone, Debug)]
pub(crate) struct RecordedSpan {
    pub(crate) id: u64,
    pub(crate) name: &'static str,
    /// The resolved parent: explicit parents are taken from the span
    /// attributes, contextual parents from the enter/exit stack, and
    /// explicit roots record `None`.
    pub(crate) parent: Option<u64>,
    /// Span ids recorded via `Span::follows_from`.
    pub(crate) follows: Vec<u64>,
    /// Field values recorded at span creation, debug-formatted.
    pub(crate) fields: Vec<(&'static str, String)>,
    metadata: &'static Metadata<'static>,
}

impl RecordedSpan {
    /// Return the recorded value for `name`, panicking when absent.
    pub(crate) fn field(&self, name: &str) -> &str {
        self.fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("missing field {name}"))
    }
}

/// Captures span fields into debug-formatted strings.
///
/// `%value` and `?value` recordings both arrive through `record_debug`.
struct FieldCapture(Vec<(&'static str, String)>);

impl Visit for FieldCapture {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.push((field.name(), format!("{value:?}")));
    }
}

/// Shared state inspected by tests after a recorded run.
#[derive(Default)]
pub(crate) struct TraceState {
    next: AtomicU64,
    spans: Mutex<Vec<RecordedSpan>>,
    stack: Mutex<Vec<u64>>,
}

impl TraceState {
    /// Return the first recorded span with `name`, panicking when absent.
    pub(crate) fn span(&self, name: &str) -> RecordedSpan {
        self.spans
            .lock()
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("missing span {name}"))
            .clone()
    }

    /// Return every recorded span with `name`.
    pub(crate) fn spans_named(&self, name: &str) -> Vec<RecordedSpan> {
        self.spans
            .lock()
            .iter()
            .filter(|span| span.name == name)
            .cloned()
            .collect()
    }
}

/// Minimal [`Subscriber`] that records span creation, parentage, and
/// `follows_from` edges for assertions.
pub(crate) struct TraceRecorder {
    state: Arc<TraceState>,
}

impl TraceRecorder {
    pub(crate) fn new() -> (Self, Arc<TraceState>) {
        let state = Arc::new(TraceState::default());
        (
            Self {
                state: state.clone(),
            },
            state,
        )
    }
}

impl Subscriber for TraceRecorder {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let id = self.state.next.fetch_add(1, Ordering::SeqCst) + 1;
        let parent = if attrs.is_root() {
            None
        } else if attrs.is_contextual() {
            self.state.stack.lock().last().copied()
        } else {
            attrs.parent().map(|id| id.into_u64())
        };

        let mut fields = FieldCapture(Vec::new());
        attrs.record(&mut fields);

        self.state.spans.lock().push(RecordedSpan {
            id,
            name: attrs.metadata().name(),
            parent,
            follows: Vec::new(),
            fields: fields.0,
            metadata: attrs.metadata(),
        });
        Id::from_u64(id)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        let mut spans = self.state.spans.lock();
        let recorded = spans
            .iter_mut()
            .find(|recorded| recorded.id == span.into_u64())
            .expect("follows_from on unknown span");
        recorded.follows.push(follows.into_u64());
    }

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, span: &Id) {
        self.state.stack.lock().push(span.into_u64());
    }

    fn exit(&self, span: &Id) {
        let mut stack = self.state.stack.lock();
        if let Some(position) = stack.iter().rposition(|id| *id == span.into_u64()) {
            stack.remove(position);
        }
    }

    fn current_span(&self) -> Current {
        let stack = self.state.stack.lock();
        let Some(id) = stack.last().copied() else {
            return Current::none();
        };
        drop(stack);

        let spans = self.state.spans.lock();
        let recorded = spans
            .iter()
            .find(|span| span.id == id)
            .expect("current span was recorded");
        Current::new(Id::from_u64(id), recorded.metadata)
    }
}
