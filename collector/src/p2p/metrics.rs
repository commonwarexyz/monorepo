use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Gauge, MetricsExt as _, status},
};

/// Metrics for the [Engine](super::Engine).
pub struct Metrics {
    /// Number of commitments being collected.
    pub outstanding: Gauge,
    /// Number of received requests the engine has not finished serving.
    pub serve_processing: Gauge,
    /// Number of sent requests by status. A request sent to at least one peer is a success and a
    /// request sent to none is dropped.
    pub send: status::Counter,
    /// Number of received responses by status. A collected response is a success, an ignored
    /// response is dropped, and a response that fails to decode is invalid.
    pub collect: status::Counter,
    /// Number of received requests by status. A request is a success when its response is sent,
    /// a failure when the handler declines it, dropped when its response cannot be sent, and
    /// invalid when it fails to decode.
    pub serve: status::Counter,
}

impl Metrics {
    /// Creates the engine's metrics and registers them with `context`.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            outstanding: context.gauge("outstanding", "Number of commitments being collected"),
            serve_processing: context.gauge(
                "serve_processing",
                "Number of received requests being processed",
            ),
            send: context.family("send", "Number of sent requests by status"),
            collect: context.family("collect", "Number of received responses by status"),
            serve: context.family("serve", "Number of received requests by status"),
        }
    }
}
