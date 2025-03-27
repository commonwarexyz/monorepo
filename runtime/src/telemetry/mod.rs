//! Utilities for collecting and reporting telemetry data.

use crate::tokio::Context;
use crate::Spawner;
use metrics::server;
use traces::exporter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

pub mod metrics;
pub mod traces;

pub fn init(
    context: Context,
    level: &str,
    metrics: Option<server::Config>,
    traces: Option<exporter::Config>,
) {
    // Create fmt layer for logging
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_line_number(true)
        .with_file(true);

    // Create a filter layer to set the maximum level to INFO
    let filter = tracing_subscriber::EnvFilter::new(level);

    // Expose metrics over HTTP
    if let Some(cfg) = metrics {
        context.spawn(move |context| async move { metrics::server::serve(context, cfg).await });
    }

    // Combine layers into a single subscriber
    if let Some(cfg) = traces {
        // Initialize tracing
        let tracer = traces::exporter::export(cfg).expect("Failed to initialize tracer");

        // Create OpenTelemetry layer for tracing
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        // Set the global subscriber
        let subscriber = Registry::default()
            .with(filter)
            .with(fmt_layer)
            .with(telemetry_layer);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    } else {
        // Set the global subscriber
        let subscriber = Registry::default().with(filter).with(fmt_layer);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    };
}
