use crate::authenticated::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family};

/// Metrics for the [`Actor`](super::Actor)
#[derive(Default, Clone)]
pub struct Metrics {
    /// Number of messages sent per peer and channel
    pub sent_messages: Family<metrics::Message, Counter>,

    /// Number of messages received per peer and channel
    pub received_messages: Family<metrics::Message, Counter>,

    /// Number of rate limited messages per peer and channel
    pub rate_limited: Family<metrics::Message, Counter>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self::default();
        context.register(
            "messages_sent",
            "Number of messages sent per peer and channel",
            metrics.sent_messages.clone(),
        );
        context.register(
            "messages_received",
            "Number of messages received per peer and channel",
            metrics.received_messages.clone(),
        );
        context.register(
            "rate_limited_messages",
            "Number of rate limited messages per peer and channel",
            metrics.rate_limited.clone(),
        );
        metrics
    }
}
