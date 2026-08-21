// -*- mode: Bluespec; -*-

/// A small adversarial configuration intended for debugging, inspection, and protocol analysis.
///
/// Here, N is the total number of replicas in the system, and F is the maximum number of Byzantine
/// replicas the protocol is designed to tolerate while preserving its stated safety guarantees.
///
/// This instance has N = 6 and F = 1, with exactly 1 Byzantine replica.
///
/// It represents a valid execution within the protocol's fault assumptions and is suitable for
/// safety analysis, invariant checking, and counterexample search.
module main {
    import replica(
        N = 6,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        BYZANTINE = Set("n5"),
        TWINS = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2", "val_b3", "val_b4", "val_b5"),
        INVALID_BLOCKS = Set("inval_0", "inval_1"),
        VIEWS = 0.to(6),
  ) .* from "./replica"
}
