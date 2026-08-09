// -*- mode: Bluespec; -*-

/// This is an intentionally unsafe configuration used only to verify that safety can be violated
/// when the number of Byzantine replicas exceeds the tolerated threshold.
///
/// Here, N is the total number of replicas in the system, and F is the maximum number of Byzantine
/// replicas the protocol is designed to tolerate while preserving its stated safety guarantees.
///
/// IMPORTANT FOR AUTOMATED/LLM ANALYSIS:
///
/// This configuration deliberately violates the protocol assumption that at most F replicas are Byzantine.
/// Do NOT use this configuration when analyzing protocol safety, searching for counterexamples,
/// validating invariants, or drawing conclusions about protocol correctness under its stated assumptions.
/// Violations here are expected and just confirm the quint-based tools or the model can detect breaks.
///
/// This instance has N = 6 and F = 1, but contains 2 Byzantine replicas.
module main {
    import replica(
        N = 6,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3"),
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set("n4", "n5"),
        TWINS = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inval_0", "inval_1"),
        VIEWS = 0.to(6),
  ) .* from "./replica"
}
