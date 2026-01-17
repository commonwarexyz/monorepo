use crate::authenticated::discovery::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [super::Actor]
#[derive(Default)]
pub struct Metrics {
    /// The total number of unique peers in all peer sets being tracked.
    /// Includes bootstrappers, even if they are not in any peer set.
    /// Does not include self, despite having a record for it.
    pub tracked: Gauge,

    /// Blocked peers (value = expiry time as epoch millis).
    pub blocked: Family<metrics::Peer, Gauge>,

    /// The total number of outstanding reservations.
    pub reserved: Gauge,

    /// A count of the number of rate-limited connection events for each peer.
    pub limits: Family<metrics::Peer, Counter>,

    /// A count of the number of updates for each peer.
    pub updates: Family<metrics::Peer, Counter>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            tracked: context.get_or_register_default::<Gauge>(
                "tracked",
                "Total number of unique peers in all peer sets being tracked",
            ),
            blocked: context.get_or_register_default::<Family<metrics::Peer, Gauge>>(
                "blocked",
                "Blocked peers (value = expiry time as epoch millis)",
            ),
            reserved: context.get_or_register_default::<Gauge>(
                "reserved",
                "Total number of outstanding reservations",
            ),
            limits: context.get_or_register_default::<Family<metrics::Peer, Counter>>(
                "limits",
                "Count of the number of rate-limited connection events for each peer",
            ),
            updates: context.get_or_register_default::<Family<metrics::Peer, Counter>>(
                "updates",
                "Count of the number of updates for each peer",
            ),
        }
    }
}
