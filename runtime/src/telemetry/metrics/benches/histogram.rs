//! Histogram observation throughput.

use commonware_runtime::telemetry::metrics::raw::Histogram;
use criterion::Criterion;
use std::hint::black_box;

const OBSERVATIONS: usize = 1_024;
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Observes a fixed spread of latencies into one histogram.
pub fn bench(c: &mut Criterion) {
    let histogram = Histogram::new(BUCKETS);
    c.bench_function(
        &format!(
            "{}::metric_observation/observations={} buckets={}",
            module_path!(),
            OBSERVATIONS,
            BUCKETS.len(),
        ),
        |b| {
            b.iter(|| {
                for sample in 0..OBSERVATIONS {
                    histogram.observe(black_box((sample % 500) as f64 / 1_000.0));
                }
            });
        },
    );
}
