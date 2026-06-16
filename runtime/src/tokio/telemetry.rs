//! Utilities for collecting and reporting telemetry data.

use super::{
    tracing::{export, Config},
    Context,
};
use crate::{Metrics as _, Spawner, Supervisor as _};
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
use tracing_subscriber::{filter::filter_fn, layer::SubscriberExt, Layer, Registry};

/// Log configuration.
pub struct Logs {
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
/// If `traces` is provided, enables OpenTelemetry trace export. When `None`, span
/// callsites in the runtime-provided subscriber are disabled and only log events
/// are emitted (per [`Logs::level`]).
pub fn init(context: Context, logs: Logs, metrics: Option<SocketAddr>, traces: Option<Config>) {
    // Create fmt layer for logging
    let log_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true);

    // Set the format to JSON (if specified)
    let log_layer = if logs.json {
        log_layer.json().boxed()
    } else {
        log_layer.compact().boxed()
    };
    let log_layer = match &traces {
        None => log_layer
            .with_filter(filter_fn(move |metadata| {
                metadata.is_event() && *metadata.level() <= logs.level
            }))
            .boxed(),
        Some(_) => log_layer
            .with_filter(tracing_subscriber::EnvFilter::new(logs.level.to_string()))
            .boxed(),
    };

    // Create OpenTelemetry layer for tracing
    let trace_layer = traces.map(|cfg| {
        let tracer = export(cfg).expect("Failed to initialize tracer");
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(tracing_subscriber::EnvFilter::new(logs.level.to_string()))
    });

    // Create tracing registry.
    cfg_if! {
        if #[cfg(feature = "tokio-console")] {
            let console_layer = console_subscriber::spawn();
            let registry = Registry::default()
                .with(log_layer)
                .with(trace_layer)
                .with(console_layer);
        } else {
            let registry = Registry::default()
                .with(log_layer)
                .with(trace_layer);
        }
    }

    // Set the global subscriber
    tracing::subscriber::set_global_default(registry).expect("Failed to set subscriber");

    // Expose metrics over HTTP
    if let Some(cfg) = metrics {
        context.child("metrics").spawn(move |context| async move {
            // Create a tokio listener for the metrics server.
            //
            // We explicitly avoid using a runtime `Listener` because
            // it will track bandwidth used for metrics and apply a policy
            // for read/write timeouts fit for a p2p network.
            let listener = TcpListener::bind(cfg)
                .await
                .expect("Failed to bind metrics server");

            // Create a router for the metrics server
            let shared = Arc::new(context);
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
