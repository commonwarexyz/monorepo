//! Helpers shared by in-crate Multimmit tests.

use crate::simplex::marshal::mocks::block::EmptyBlock;
use commonware_cryptography::Sha256;
use commonware_macros::select;
use commonware_runtime::{
    Clock,
    telemetry::{metrics::metric_sum, traces::collector::EventMetadata},
};
use commonware_utils::sync::Mutex;
use std::{
    fmt::Debug,
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

/// The application block body the marshal tests store and deliver.
pub(crate) type TestBody = EmptyBlock<Sha256>;

/// A span a [`SpanRecorder`] observed.
#[derive(Clone, Debug)]
pub(crate) struct RecordedSpan {
    /// The registry identifier, which the registry reuses once the span closes.
    pub(crate) id: u64,
    pub(crate) name: &'static str,
    pub(crate) parent: Option<u64>,
    pub(crate) parent_name: Option<&'static str>,
    /// Fields recorded at creation and by later `record` calls, rendered as strings.
    pub(crate) fields: EventMetadata,
    /// Names of the fields recorded as signed integers.
    pub(crate) signed: Vec<&'static str>,
    /// When the span opened and closed, on the recorder's clock.
    pub(crate) opened_at: usize,
    pub(crate) closed_at: Option<usize>,
}

impl RecordedSpan {
    /// Returns whether the span has closed.
    pub(crate) const fn closed(&self) -> bool {
        self.closed_at.is_some()
    }
}

/// An event a [`SpanRecorder`] observed.
#[derive(Clone, Debug)]
pub(crate) struct RecordedEvent {
    pub(crate) fields: EventMetadata,
    /// The outermost span of the event's scope, if it had one.
    pub(crate) root: Option<u64>,
    /// When the event was emitted, on the recorder's clock.
    pub(crate) at: usize,
}

#[derive(Default)]
struct Records {
    spans: Vec<RecordedSpan>,
    events: Vec<RecordedEvent>,
    links: Vec<(u64, u64)>,
    clock: usize,
}

impl Records {
    fn tick(&mut self) -> usize {
        let at = self.clock;
        self.clock += 1;
        at
    }

    fn open(&mut self, id: &Id) -> Option<&mut RecordedSpan> {
        let id = id.into_u64();
        self.spans
            .iter_mut()
            .rev()
            .find(|span| span.id == id && !span.closed())
    }
}

/// Visits fields into [`EventMetadata`], noting which were recorded as signed integers.
#[derive(Default)]
struct FieldVisitor {
    fields: EventMetadata,
    signed: Vec<&'static str>,
}

impl Visit for FieldVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.signed.push(field.name());
        self.fields.record_i64(field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.record_str(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.fields.record_debug(field, value);
    }
}

/// Records every span, event, and `follows_from` link for assertions after a traced run.
///
/// Spans and events share one clock that ticks when a span opens or closes and when an event is
/// emitted, so tests can order them.
#[derive(Clone, Default)]
pub(crate) struct SpanRecorder(Arc<Mutex<Records>>);

impl SpanRecorder {
    /// Runs `operation` with this recorder as the only layer of the default subscriber.
    pub(crate) fn capture<T>(&self, operation: impl FnOnce() -> T) -> T {
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(self.clone()),
            operation,
        )
    }

    /// Returns every recorded span, in creation order.
    pub(crate) fn spans(&self) -> Vec<RecordedSpan> {
        self.0.lock().spans.clone()
    }

    /// Returns every recorded span named `name`, in creation order.
    pub(crate) fn named(&self, name: &str) -> Vec<RecordedSpan> {
        self.0
            .lock()
            .spans
            .iter()
            .filter(|span| span.name == name)
            .cloned()
            .collect()
    }

    /// Returns the first recorded span named `name`.
    pub(crate) fn first(&self, name: &str) -> Option<RecordedSpan> {
        self.0
            .lock()
            .spans
            .iter()
            .find(|span| span.name == name)
            .cloned()
    }

    /// Returns the most recently created span named `name`.
    pub(crate) fn last(&self, name: &str) -> Option<RecordedSpan> {
        self.0
            .lock()
            .spans
            .iter()
            .rev()
            .find(|span| span.name == name)
            .cloned()
    }

    /// Returns every recorded event, in emission order.
    pub(crate) fn events(&self) -> Vec<RecordedEvent> {
        self.0.lock().events.clone()
    }

    /// Returns every `follows_from` link as `(span, cause)`, in recording order.
    pub(crate) fn links(&self) -> Vec<(u64, u64)> {
        self.0.lock().links.clone()
    }
}

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for SpanRecorder {
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        attributes.record(&mut visitor);
        let parent = context.span(id).and_then(|span| span.parent());
        let parent_name = parent.as_ref().map(|parent| parent.name());
        let parent = parent.map(|parent| parent.id().into_u64());
        let mut records = self.0.lock();
        let opened_at = records.tick();
        records.spans.push(RecordedSpan {
            id: id.into_u64(),
            name: attributes.metadata().name(),
            parent,
            parent_name,
            fields: visitor.fields,
            signed: visitor.signed,
            opened_at,
            closed_at: None,
        });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);
        if let Some(span) = self.0.lock().open(id) {
            span.fields.fields.extend(visitor.fields.fields);
            span.signed.extend(visitor.signed);
        }
    }

    fn on_follows_from(&self, id: &Id, follows: &Id, _: Context<'_, S>) {
        self.0
            .lock()
            .links
            .push((id.into_u64(), follows.into_u64()));
    }

    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let root = context
            .event_scope(event)
            .and_then(|scope| scope.from_root().next())
            .map(|span| span.id().into_u64());
        let mut records = self.0.lock();
        let at = records.tick();
        records.events.push(RecordedEvent {
            fields: visitor.fields,
            root,
            at,
        });
    }

    fn on_close(&self, id: Id, _: Context<'_, S>) {
        let mut records = self.0.lock();
        let at = records.tick();
        if let Some(span) = records.open(&id) {
            span.closed_at = Some(at);
        }
    }
}

/// Sums every sample of `name` in `encoded` as an integer.
///
/// `name` may be the full metric name or its unprefixed suffix.
pub(crate) fn metric_total(encoded: &str, name: &str) -> u64 {
    metric_sum(encoded, name, &[]) as u64
}

/// Awaits `future`, panicking with `what` unless it resolves within `timeout`.
pub(crate) async fn expect_within<T>(
    context: &impl Clock,
    timeout: Duration,
    future: impl Future<Output = T>,
    what: &str,
) -> T {
    expect_before(context, context.current() + timeout, future, what).await
}

/// Awaits `future`, panicking with `what` unless it resolves before `deadline`.
pub(crate) async fn expect_before<T>(
    context: &impl Clock,
    deadline: SystemTime,
    future: impl Future<Output = T>,
    what: &str,
) -> T {
    select! {
        output = future => output,
        () = context.sleep_until(deadline) => panic!("{what}"),
    }
}
