// -*- mode: Bluespec; -*-

/// A few handy small models that are good for debugging and inspection
module main {
    // A specification instance for n=5 and f=1
    import replica(
        N = 5,
        F = 1,
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set("n4"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4"),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inval_0", "inval_1"),
        VIEWS = 0.to(6),
  ) .* from "./replica"
}
