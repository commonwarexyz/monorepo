//! Utilities to export traces to an OTLP endpoint.

use commonware_utils::Probability;
use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_otlp::{ExporterBuildError, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    trace::{BatchSpanProcessor, Sampler, SdkTracerProvider, Tracer},
};
use std::time::Duration;

/// Timeout for the OTLP HTTP exporter.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for exporting traces to an OTLP endpoint.
pub struct Config {
    /// The OTLP endpoint to export traces to.
    pub endpoint: String,
    /// The service name to use for the traces.
    pub name: String,
    /// The sampling rate to use for the traces.
    pub rate: Probability,
    /// Shared identity of a deployment or run, exported as resource `commonware.run_id`.
    ///
    /// Use the same value on every node in a run and a distinct value for overlapping runs.
    /// This does not affect trace identifiers or `service.name`. When absent, the resource
    /// attribute is omitted. TraceQL can filter it with `{ resource.commonware.run_id = "run-42" }`.
    pub run_id: Option<String>,
}

impl Config {
    fn resource(&self) -> Resource {
        let mut builder = Resource::builder_empty().with_service_name(self.name.clone());
        if let Some(run_id) = &self.run_id {
            builder = builder.with_attribute(KeyValue::new("commonware.run_id", run_id.clone()));
        }
        builder.build()
    }
}

/// Export traces to an OTLP endpoint.
pub fn export(cfg: Config) -> Result<Tracer, ExporterBuildError> {
    let resource = cfg.resource();
    // Create the OTLP HTTP exporter
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(cfg.endpoint)
        .with_timeout(TIMEOUT)
        .build()?;

    // Configure the batch processor
    let batch_processor = BatchSpanProcessor::builder(exporter).build();

    // Build the tracer provider
    let sampler = Sampler::TraceIdRatioBased(cfg.rate.as_f64());
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

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::{Key, Value};

    #[test]
    fn run_identity_is_optional_resource_metadata() {
        for run_id in [None, Some("run-42".to_owned()), Some("run-43".to_owned())] {
            let cfg = Config {
                endpoint: "http://localhost:4318/v1/traces".to_owned(),
                name: "node-7".to_owned(),
                rate: 1.0,
                run_id: run_id.clone(),
            };
            let resource = cfg.resource();
            assert_eq!(
                resource.get(&Key::new("service.name")),
                Some(Value::from("node-7"))
            );
            assert_eq!(
                resource.get(&Key::new("commonware.run_id")),
                run_id.map(Value::from)
            );
            assert_eq!(
                resource.iter().count(),
                if cfg.run_id.is_some() { 2 } else { 1 }
            );
        }
    }
}
