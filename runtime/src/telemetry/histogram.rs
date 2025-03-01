use prometheus_client::metrics::histogram::Histogram;
use std::time::SystemTime;

/// Holds constants for bucket sizes for histograms.
///
/// The bucket sizes are in seconds.
pub struct Buckets;

impl Buckets {
    /// For simple roundtrip requests to a peer.
    /// 
    /// These requests are expected to happen over a wide-area network, but not require extended
    /// calculation, retries, etc. Something like a ping/pong.
    pub const P2P: [f64; 12] = [
        0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
    ];

    /// For resolving items over a network.
    ///
    /// These tasks might require multiple hops, rounds, retries, etc. Something like coming to
    /// consensus or fetching a large amount of data from multiple peers.
    pub const NETWORK: [f64; 12] = [
        0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0,
    ];

    /// For resolving items locally.
    ///
    /// These tasks are expected to be fast and not require network access, but might require
    /// expensive computation, disk access, etc.
    pub const LOCAL: [f64; 12] = [
        3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0,
    ];
}

/// Extension trait for histograms.
pub trait HistogramExt {
    /// Observe the duration between two points in time, in seconds.
    ///
    /// If the clock goes backwards, the duration is 0.
    fn observe_between(&self, start: SystemTime, end: SystemTime);
}

impl HistogramExt for Histogram {
    fn observe_between(&self, start: SystemTime, end: SystemTime) {
        let duration = match end.duration_since(start) {
            Ok(duration) => duration.as_secs_f64(),
            Err(_) => 0.0, // Clock went backwards
        };
        self.observe(duration);
    }
}
