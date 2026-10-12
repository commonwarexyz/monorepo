//! Shared labels, buckets, and registration helpers for actor metrics.

use crate::multimmit::wire::Plane;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{CounterFamily, EncodeLabelSet, MetricsExt as _},
};

/// Stage latency buckets in seconds: 1ms steps to 10ms, 5ms to 100ms, 10ms to 250ms, tail to 30s.
pub(super) const STAGE_LATENCY: [f64; 58] = [
    0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.015, 0.02, 0.025, 0.03,
    0.035, 0.04, 0.045, 0.05, 0.055, 0.06, 0.065, 0.07, 0.075, 0.08, 0.085, 0.09, 0.095, 0.1, 0.11,
    0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.2, 0.21, 0.22, 0.23, 0.24, 0.25, 0.3, 0.35,
    0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 5.0, 10.0, 30.0,
];

/// Latency histogram buckets in seconds, with 1ms resolution through 10ms, 5ms resolution
/// through 1s, and a coarse tail through 30s.
///
/// Use these for WAN-scale consensus and payload-availability measurements. CPU and local
/// queue measurements can use smaller bucket sets to limit the number of exported series.
/// Applications that drive Multimmit can use them to report on the same scale.
pub const WAN_LATENCY: [f64; 213] = {
    let mut buckets = [0.0; 213];
    let mut index = 0;
    while index < 10 {
        buckets[index] = (index + 1) as f64 / 1_000.0;
        index += 1;
    }
    while index < 208 {
        buckets[index] = (15 + (index - 10) * 5) as f64 / 1_000.0;
        index += 1;
    }
    buckets[208] = 2.0;
    buckets[209] = 3.0;
    buckets[210] = 5.0;
    buckets[211] = 10.0;
    buckets[212] = 30.0;
    buckets
};

/// Power-of-two count buckets from zero to 256.
///
/// The zero bucket separates the healthy case (none) from any count at all.
pub(super) const COUNT_POW2_FROM_ZERO: [f64; 10] =
    [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0];

/// Power-of-two count buckets from one to 512.
pub(super) const COUNT_POW2_FROM_ONE: [f64; 10] =
    [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0];

/// Per-plane traffic label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct Traffic {
    pub(crate) plane: Plane,
}

impl From<Plane> for Traffic {
    fn from(plane: Plane) -> Self {
        Self { plane }
    }
}

/// Registers a counter family labelled by plane, exporting every plane from zero.
pub(super) fn plane_counter<E: Metrics>(
    context: &E,
    name: &'static str,
    help: &'static str,
) -> CounterFamily<Traffic> {
    let family = context.family(name, help);
    for plane in Plane::ALL {
        let _ = family.get_or_create(&Traffic::from(plane));
    }
    family
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wan_latency_resolution_and_tail() {
        assert!(WAN_LATENCY.windows(2).all(|pair| pair[0] < pair[1]));
        for millis in (1..=10).chain((15..=1_000).step_by(5)) {
            assert!(WAN_LATENCY.contains(&(f64::from(millis) / 1_000.0)));
        }
        assert_eq!(&WAN_LATENCY[208..], &[2.0, 3.0, 5.0, 10.0, 30.0]);
    }
}
