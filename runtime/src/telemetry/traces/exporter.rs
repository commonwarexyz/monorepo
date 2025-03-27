//! Utilities to export traces to an OTLP endpoint.

use opentelemetry::{
    global,
    trace::{TraceError, TracerProvider},
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    trace::{BatchSpanProcessor, Sampler, SdkTracerProvider, Tracer},
    Resource,
};

/// Configuration for exporting traces to an OTLP endpoint.
pub struct Config {
    /// The OTLP endpoint to export traces to.
    pub endpoint: String,
    /// The service name to use for the traces.
    pub name: String,
    /// The sampling rate to use for the traces.
    pub rate: f64,
}

/// Export traces to an OTLP endpoint.
pub fn export(cfg: Config) -> Result<Tracer, TraceError> {
    // Create the OTLP HTTP exporter
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(cfg.endpoint)
        .build()?;

    // Configure the batch processor
    let batch_processor = BatchSpanProcessor::builder(exporter).build();

    // Define the resource with service name
    let resource = Resource::builder()
        .with_service_name(cfg.name.clone())
        .build();

    // Build the tracer provider
    let sampler = Sampler::TraceIdRatioBased(cfg.rate);
    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    // Create the tracer and set it globally
    let tracer = tracer_provider.tracer(cfg.name);
    global::set_tracer_provider(tracer_provider);
    Ok(tracer)
}
