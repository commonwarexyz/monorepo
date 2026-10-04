//! `reset_peak` starts a measurement window: a large earlier peak no longer
//! shows in `peak`, and growth after the reset does. (One test: the
//! counters are process-wide.)

use std::hint::black_box;

use sandblaster_memguard::{allocated, peak, reset_peak};

const MIB: usize = 1 << 20;

#[test]
fn reset_peak_starts_a_measurement_window() {
    // an earlier peak of 64 MiB, freed
    drop(black_box(vec![1u8; 64 * MIB]));
    let before = allocated();
    assert!(peak() >= before + 64 * MIB);
    // after the reset the peak is the current reservation, not the old peak
    reset_peak();
    assert!(peak() < before + 64 * MIB, "peak {} vs allocated {before}", peak());
    // and it records what comes after
    let v = black_box(vec![1u8; 8 * MIB]);
    assert!(peak() >= before + 8 * MIB);
    drop(v);
    assert!(peak() >= allocated());
}
