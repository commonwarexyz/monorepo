//! Utilities for collecting and reporting telemetry data.

use super::{
    tracing::{export, Config},
    Context,
};
use crate::{telemetry::metrics, Metrics, Spawner, Storage};
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, Registry};

/// Initialize telemetry with the given configuration.
pub fn init<S: Storage>(
    context: Context<S>,
    level: Level,
    metrics: Option<SocketAddr>,
    traces: Option<Config>,
) {
    // Create fmt layer for logging
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE);

    // Create a filter layer to set the maximum level to INFO
    let filter = tracing_subscriber::EnvFilter::new(level.to_string());

    // Expose metrics over HTTP
    if let Some(cfg) = metrics {
        context
            .with_label("metrics")
            .spawn(move |context| async move { metrics::server::serve(context, cfg).await });
    }

    // Combine layers into a single subscriber
    if let Some(cfg) = traces {
        // Initialize tracing
        let tracer = export(cfg).expect("Failed to initialize tracer");

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
