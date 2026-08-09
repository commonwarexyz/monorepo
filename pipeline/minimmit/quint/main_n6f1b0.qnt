// -*- mode: Bluespec; -*-

/// A small fault-free configuration intended for debugging, inspection, and model exploration.
///
/// Here, N is the total number of replicas in the system, and F is the maximum number of Byzantine
/// replicas the protocol is designed to tolerate while preserving its stated safety guarantees.
///
/// This instance has N = 6 and F = 1, but all 6 replicas are correct and no Byzantine behavior is enabled.
///
/// It is useful for inspecting normal protocol behavior and debugging the specification without adversarial actions.
module main {
    import replica(
        N = 6,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        BYZANTINE = Set(),
        TWINS = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inval_0", "inval_1"),
        VIEWS = 0.to(6),
  ) .* from "./replica"
}
