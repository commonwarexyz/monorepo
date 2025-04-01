//! Record the OTLP status of a span.

use opentelemetry::trace::Status;
use std::fmt::Debug;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Set the status of a span to `Ok`.
pub fn ok(span: &Span) {
    span.set_status(Status::Ok);
}

/// Set the status of a span to `Error`.
///
/// If `error` is provided, it will be recorded as an attribute on the span.
pub fn error(span: &Span, status: &str, error: Option<&dyn Debug>) {
    if let Some(error) = error {
        span.record("error", format!("{:?}", error));
    }
    span.set_status(Status::error(status.to_string()));
}
