//! Utilities for collecting and reporting telemetry data.

use super::{
    tracing::{export, Config},
    Context,
};
use crate::{Observer, Spawner, Supervisor};
use axum::{
    body::Body,
    http::{header, Response, StatusCode},
    routing::get,
    serve, Extension, Router,
};
use cfg_if::cfg_if;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, Layer, Registry};

/// Logging configuration.
pub struct Logging {
    /// The level of logging to use.
    pub level: Level,

    /// Whether to log in JSON format.
    ///
    /// This is useful for structured logging in server-based environments.
    /// If you are running things locally, it is recommended to use
    /// `json = false` to get a human-readable format.
    pub json: bool,
}

/// Initialize telemetry with the given configuration.
///
/// If `metrics` is provided, starts serving metrics at the given address at `/metrics`.
/// If `traces` is provided, enables OpenTelemetry trace export.
pub fn init(
    context: Context,
    logging: Logging,
    metrics: Option<SocketAddr>,
    traces: Option<Config>,
) {
    // Create a filter layer to set the maximum level to INFO
    let filter = tracing_subscriber::EnvFilter::new(logging.level.to_string());

    // Create fmt layer for logging
    let log_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE);

    // Set the format to JSON (if specified)
    let log_layer = if logging.json {
        log_layer.json().boxed()
    } else {
        log_layer.compact().boxed()
    };

    // Create OpenTelemetry layer for tracing
    let trace_layer = traces.map(|cfg| {
        let tracer = export(cfg).expect("Failed to initialize tracer");
        tracing_opentelemetry::layer().with_tracer(tracer)
    });

    // Create tracing registry.
    cfg_if! {
        if #[cfg(feature = "tokio-console")] {
            let console_layer = console_subscriber::spawn();
            let registry = Registry::default()
                .with(filter)
                .with(log_layer)
                .with(trace_layer)
                .with(console_layer);
        } else {
            let registry = Registry::default()
                .with(filter)
                .with(log_layer)
                .with(trace_layer);
        }
    }

    // Set the global subscriber
    tracing::subscriber::set_global_default(registry).expect("Failed to set subscriber");

    // Expose metrics over HTTP
    if let Some(cfg) = metrics {
        context.child("server").spawn(move |context| async move {
            // Create a tokio listener for the metrics server.
            //
            // We explicitly avoid using a runtime `Listener` because
            // it will track bandwidth used for metrics and apply a policy
            // for read/write timeouts fit for a p2p network.
            let listener = TcpListener::bind(cfg)
                .await
                .expect("Failed to bind metrics server");

            // Wrap the context in an Arc so axum's `Extension` (which
            // requires `Clone`) can share it across request handlers
            // without cloning the underlying context.
            let shared = Arc::new(context);

            // Create a router for the metrics server
            let app = Router::new()
                .route(
                    "/metrics",
                    get(|Extension(ctx): Extension<Arc<Context>>| async move {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body(Body::from(ctx.encode()))
                            .expect("Failed to create response")
                    }),
                )
                .layer(Extension(shared));

            // Serve the metrics over HTTP.
            //
            // `serve` will spawn its own tasks using `tokio::spawn` (and there is no way to specify
            // it to do otherwise). These tasks will not be tracked like metrics spawned using `Spawner`.
            serve(listener, app.into_make_service())
                .await
                .expect("Could not serve metrics");
        });
    }
}
