//! Utilities for collecting and reporting telemetry data.

use super::{
    tracing::{export, Config},
    Context,
};
use crate::{Metrics, Network, Spawner};
use axum::{
    http::{header, Response, StatusCode},
    routing::get,
    serve, Extension, Router,
};
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, Registry};

/// Initialize telemetry with the given configuration.
pub fn init(context: Context, level: Level, metrics: Option<SocketAddr>, traces: Option<Config>) {
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
            .spawn(move |context| async move {
                // Create a listener for the metrics server
                let listener = context
                    .bind(cfg)
                    .await
                    .expect("Could not bind to metrics address");

                // Create a router for the metrics server
                let app = Router::new()
                    .route(
                        "/metrics",
                        get(|Extension(ctx): Extension<Context>| async move {
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                                .body(ctx.encode())
                                .expect("failed to create response")
                        }),
                    )
                    .layer(Extension(context));

                // Serve the metrics over HTTP
                //
                // `serve` will spawn its own tasks using `tokio`. These will not be tracked
                // like metrics spawned by `context`.
                serve(listener, app.into_make_service())
                    .await
                    .expect("Could not serve metrics");
            });
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
