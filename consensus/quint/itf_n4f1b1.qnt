// -*- mode: Bluespec; -*-

/// Model instance for ITF trace generation with round-robin leaders.
/// Byzantine node is n0 (index 0), matching the Rust fuzz convention
/// where nodes 0..faults are Byzantine.
///
/// Leader schedule follows round-robin with epoch=0:
///   leader(v) = n(v % 4)
module itf_main {
    import automaton(
        CERTIFY_DOMAIN = Set("val_b0", "val_b1", "val_b2"),
    ) as app from "./automaton"
    import replica(
        N = 4,
        F = 1,
        Q = 3,
        CORRECT = Set("n1", "n2", "n3"),
        BYZANTINE = Set("n0"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 1.to(6),
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_PAYLOADS = Set(),
        ACTIVITY_TIMEOUT = 10
    ) as r from "./replica"

    pure val CERTIFY_ALL = r::Replicas.mapBy(_ => app::certify_always_true)

    // Round-robin leader map for epoch=0: leader(v) = n(v % 4)
    pure val RR_LEADERS = Map(
        0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3",
        4 -> "n0", 5 -> "n1", 6 -> "n2"
    )

    action init = r::initWithLeaderAndCertify(RR_LEADERS, CERTIFY_ALL)

    action step = r::step

    val safe_invariants = r::safe_invariants
}
