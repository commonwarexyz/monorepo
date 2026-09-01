//! Shared telemetry definitions for Multimmit and its application attachments.

/// Latency histogram buckets in seconds, with 1ms resolution through 10ms, 5ms resolution
/// through 1s, and a coarse tail through 30s.
///
/// Use these for WAN-scale consensus and payload-availability measurements. CPU and local
/// queue measurements can use smaller bucket sets to limit the number of exported series.
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
