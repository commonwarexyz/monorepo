// The rows of the `mmr-smoke` probe (see `probes/README`).

fn cases() -> Vec<Box<dyn Case>> {
    // sizes up to MAX_NODES (2^63 - 1)
    vec![row!("mmr", mmr_to_nearest_size, inputs("mmr_to_nearest_size", vec![0, 1, 2, (1 << 63) - 1], |r| r.bits(63)), |&s| (s))]
}
