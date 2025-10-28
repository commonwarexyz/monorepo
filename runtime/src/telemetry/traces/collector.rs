//! In-memory [tracing_subscriber::Layer] to collect spans and events for testing purposes.

use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tracing::{field, span, Event, Level, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

/// An error that occurs when a trace assertion fails.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("Trace assertion error: {0}")]
pub struct TraceAssertionError(String);

impl From<String> for TraceAssertionError {
    fn from(value: String) -> Self {
        TraceAssertionError(value)
    }
}

/// A [tracing] event with its content and associated fields.
#[derive(Default, Clone, Debug)]
pub struct EventMetadata {
    /// The message content of the event.
    pub content: String,
    /// The fields associated with the event.
    pub fields: Vec<(String, String)>,
}

impl EventMetadata {
    /// Expects that the content of the event matches the string.
    pub fn expect_content_exact(&self, content: &str) -> Result<(), TraceAssertionError> {
        if self.content == content {
            Ok(())
        } else {
            Err(format!("Expected content '{content}', found '{}'", self.content).into())
        }
    }

    /// Expects that the content of the event contains the substring.
    pub fn expect_content_contains(&self, substring: &str) -> Result<(), TraceAssertionError> {
        if self.content.contains(substring) {
            Ok(())
        } else {
            Err(format!(
                "Expected content containing '{substring}', found '{}'",
                self.content
            )
            .into())
        }
    }

    /// Expects that there are `n` fields associated with the event.
    pub fn expect_field_count(&self, n: usize) -> Result<(), TraceAssertionError> {
        if self.fields.len() == n {
            Ok(())
        } else {
            Err(format!("Expected {n} fields, found {}", self.fields.len()).into())
        }
    }

    /// Expects that a given field at the specified index matches the predicate.
    pub fn expect_field_at_index<F>(
        &self,
        index: usize,
        predicate: F,
    ) -> Result<(), TraceAssertionError>
    where
        F: Fn(&(String, String)) -> Result<(), TraceAssertionError>,
    {
        match self.fields.get(index) {
            Some(field) => predicate(field),
            None => Err(format!("Missing field at index {index}").into()),
        }
    }

    /// Expects that the event has a field with exactly the specified name and value.
    pub fn expect_field_exact(
        &self,
        field_name: &str,
        field_value: &str,
    ) -> Result<(), TraceAssertionError> {
        let found = self
            .fields
            .iter()
            .any(|(name, value)| name == field_name && value == field_value);
        if found {
            Ok(())
        } else {
            Err(format!("Expected a field '{field_name}' with value '{field_value}'").into())
        }
    }

    /// Expects that the event has a field with the specified name and a value that contains
    /// the substring.
    pub fn expect_field_contains(
        &self,
        field_name: &str,
        field_value: &str,
    ) -> Result<(), TraceAssertionError> {
        let found = self
            .fields
            .iter()
            .any(|(name, value)| name == field_name && value.contains(field_value));
        if found {
            Ok(())
        } else {
            Err(format!("Expected a field '{field_name}' containing value '{field_value}'").into())
        }
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
    /// Expects that there are `n` spans active during the event.
    pub fn expect_span_count(&self, n: usize) -> Result<(), TraceAssertionError> {
        if self.spans.len() == n {
            Ok(())
        } else {
            Err(format!("Expected {n} active spans, found {}", self.spans.len()).into())
        }
    }

    /// Expects that the span at the specified index matches the predicate.
    pub fn expect_span_at_index<F>(
        &self,
        index: usize,
        predicate: F,
    ) -> Result<(), TraceAssertionError>
    where
        F: Fn(&EventMetadata) -> Result<(), TraceAssertionError>,
    {
        match self.spans.get(index) {
            Some(span) => predicate(span),
            None => Err(format!("Missing span at index {index}").into()),
        }
    }

    /// Expects that any span matches the predicate.
    pub fn expect_span<F>(&self, predicate: F) -> Result<(), TraceAssertionError>
    where
        F: Fn(&EventMetadata) -> bool,
    {
        if self.spans.iter().any(predicate) {
            Ok(())
        } else {
            Err("Missing span matching predicate".to_string().into())
        }
    }
}

/// A collection of [RecordedEvent]s.
#[derive(Default, Debug, Clone)]
pub struct RecordedEvents(Vec<RecordedEvent>);

impl RecordedEvents {
    /// Expects that the event at the specified index matches the predicate.
    pub fn expect_event_at_index<F>(
        &self,
        index: usize,
        predicate: F,
    ) -> Result<(), TraceAssertionError>
    where
        F: Fn(&RecordedEvent) -> Result<(), TraceAssertionError>,
    {
        match self.get(index) {
            Some(field) => predicate(field),
            None => Err(format!("Missing event at index {index}").into()),
        }
    }

    /// Expects that any [RecordedEvent] matches the predicate.
    pub fn expect_event<F>(&self, predicate: F) -> Result<(), TraceAssertionError>
    where
        F: Fn(&RecordedEvent) -> bool,
    {
        if self.iter().any(predicate) {
            Ok(())
        } else {
            Err("Missing event matching predicate".to_string().into())
        }
    }

    /// Expects that any [RecordedEvent] contains a message that exactly matches the specified string.
    pub fn expect_message_exact(&self, message: &str) -> Result<(), TraceAssertionError> {
        let found = self.iter().any(|event| event.metadata.content == message);
        if found {
            Ok(())
        } else {
            Err(format!("Missing message: '{message}'").into())
        }
    }

    /// Expects that any [RecordedEvent] contains a message that contains the specified substring.
    pub fn expect_message_contains(&self, substring: &str) -> Result<(), TraceAssertionError> {
        let found = self
            .iter()
            .any(|event| event.metadata.content.contains(substring));
        if found {
            Ok(())
        } else {
            Err(format!("Missing message containing: '{substring}'").into())
        }
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
pub struct CollectingLayer(TraceStorage);

impl CollectingLayer {
    /// Creates a new collecting layer with the specified [TraceStorage].
    pub const fn new(storage: TraceStorage) -> Self {
        Self(storage)
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

        let mut storage = self.0 .0.lock().unwrap();
        storage.push(RecordedEvent {
            level,
            target: metadata.target().to_string(),
            spans,
            metadata: event_meta,
        });
    }
}
