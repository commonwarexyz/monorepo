//! In-memory [tracing_subscriber::Layer] to collect spans and events for testing purposes.

use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};
use tracing::{field, span, Event, Level, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

/// A [tracing] event with its content and associated fields.
#[derive(Default, Clone, Debug)]
pub struct EventMetadata {
    /// The message content of the event.
    pub content: String,
    /// The fields associated with the event.
    pub fields: Vec<(String, String)>,
}

impl EventMetadata {
    /// Returns `true` if the event has a field with the specified name and value.
    pub fn field_matches<F>(&self, index: usize, predicate: F) -> bool
    where
        F: Fn(&(String, String)) -> bool,
    {
        self.fields.get(index).is_some_and(predicate)
    }

    /// Returns `true` if the event has a field with the specified name and value.
    pub fn has_field_exact(&self, field_name: &str, field_value: &str) -> bool {
        self.fields
            .iter()
            .any(|(name, value)| name == field_name && value == field_value)
    }

    /// Returns `true` if the event has a field with the specified name and a value that contains
    /// the substring passed.
    pub fn has_field_contains(&self, field_name: &str, field_value: &str) -> bool {
        self.fields
            .iter()
            .any(|(name, value)| name == field_name && value.contains(field_value))
    }
}

impl field::Visit for EventMetadata {
    fn record_str(&mut self, field: &field::Field, value: &str) {
        if field.name() == "message" {
            self.content = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.content = rendered;
        } else {
            self.fields.push((field.name().to_string(), rendered));
        }
    }
}

/// A recorded event with its [Level], target, active spans, message, and fields.
#[derive(Debug, Clone)]
pub struct RecordedEvent {
    /// The [Level] of the event.
    pub level: Level,
    /// The target of the event.
    pub target: String,
    /// The spans active during the event, in innermost -> outermost order.
    pub spans: Vec<EventMetadata>,
    /// The [EventMetadata].
    pub metadata: EventMetadata,
}

impl RecordedEvent {
    /// Returns `true` if the span at the specified index matches the predicate.
    pub fn span_matches<F>(&self, index: usize, predicate: F) -> bool
    where
        F: Fn(&EventMetadata) -> bool,
    {
        self.spans.get(index).is_some_and(predicate)
    }

    /// Returns `true` if any span matches the predicate.
    pub fn has_span<F>(&self, predicate: F) -> bool
    where
        F: Fn(&EventMetadata) -> bool,
    {
        self.spans.iter().any(predicate)
    }
}

/// A collection of [RecordedEvent]s.
#[derive(Default, Debug, Clone)]
pub struct RecordedEvents(Vec<RecordedEvent>);

impl RecordedEvents {
    /// Returns `true` if the [RecordedEvent] at the specified index matches the predicate.
    pub fn event_matches<F>(&self, index: usize, predicate: F) -> bool
    where
        F: Fn(&RecordedEvent) -> bool,
    {
        self.0.get(index).is_some_and(predicate)
    }

    /// Returns `true` if any [RecordedEvent] matches the predicate.
    pub fn has_event<F>(&self, predicate: F) -> bool
    where
        F: Fn(&RecordedEvent) -> bool,
    {
        self.0.iter().any(predicate)
    }

    /// Returns `true` if any [RecordedEvent] contains the specified message.
    pub fn has_message_exact(&self, message: &str) -> bool {
        self.0.iter().any(|event| event.metadata.content == message)
    }

    /// Returns `true` if any [RecordedEvent] contains a message that contains the specified substring.
    pub fn has_message_contains(&self, substring: &str) -> bool {
        self.0
            .iter()
            .any(|event| event.metadata.content.contains(substring))
    }
}

impl Deref for RecordedEvents {
    type Target = Vec<RecordedEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RecordedEvents {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<RecordedEvent>> for RecordedEvents {
    fn from(events: Vec<RecordedEvent>) -> Self {
        Self(events)
    }
}

/// The storage for the collected traces.
#[derive(Debug, Default, Clone)]
pub struct TraceStorage(Arc<Mutex<RecordedEvents>>);

impl TraceStorage {
    /// Returns the [RecordedEvent]s that match the specified [Level].
    pub fn get_by_level(&self, level: Level) -> RecordedEvents {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| (event.level == level).then_some(event.clone()))
            .collect::<Vec<_>>()
            .into()
    }

    /// Returns all [RecordedEvent]s in the storage.
    pub fn get_all(&self) -> RecordedEvents {
        self.0.lock().unwrap().clone()
    }

    /// Returns if the storage is empty.
    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }
}

/// A subscriber layer for [tracing] that collects traces and their log levels.
#[derive(Debug, Default)]
pub struct CollectingLayer {
    /// The storage for the collected traces.
    pub storage: TraceStorage,
}

impl CollectingLayer {
    /// Creates a new collecting layer with the specified [TraceStorage].
    pub const fn new(storage: TraceStorage) -> Self {
        Self { storage }
    }
}

impl<S> Layer<S> for CollectingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut span_fields = EventMetadata::default();
            attrs.record(&mut span_fields);
            span.extensions_mut().insert(span_fields);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = *metadata.level();

        let mut event_meta = EventMetadata::default();
        event.record(&mut event_meta);

        let mut spans = Vec::new();
        if let Some(current) = ctx.lookup_current() {
            let mut current = Some(current);
            while let Some(span) = current {
                let metadata = span.metadata();
                let EventMetadata { fields, .. } = span
                    .extensions()
                    .get::<EventMetadata>()
                    .cloned()
                    .unwrap_or_default();

                spans.push(EventMetadata {
                    content: metadata.name().to_string(),
                    fields,
                });
                current = span.parent();
            }
        }

        let mut storage = self.storage.0.lock().unwrap();
        storage.push(RecordedEvent {
            level,
            target: metadata.target().to_string(),
            spans,
            metadata: event_meta,
        });
    }
}
