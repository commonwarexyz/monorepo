use opentelemetry::trace::Status;
use std::fmt::Debug;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn ok(span: &Span) {
    span.set_status(Status::Ok);
}

pub fn error(span: &Span, description: &str) {
    span.set_status(Status::error(description.to_string()));
}

pub fn wrapped_error<E: Debug>(span: &Span, error: &E, description: &str) {
    span.record("error", format!("{:?}", error));
    span.set_status(Status::error(description.to_string()));
}
