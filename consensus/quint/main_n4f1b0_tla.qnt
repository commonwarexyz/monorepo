// -*- mode: Bluespec; -*-

/// A few handy small models that are good for debugging and inspection
module main {
    // A specification instance for n=4 and f=0
    import replica(
        N = 4,
        F = 1,
        Q = 3,
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2", "val_b3", "val_b4", "val_b5", "val_b6", "val_b7", "val_b8", "val_b9", "val_b10"),
        INVALID_PAYLOADS = Set("inval_0", "inval_1"),
        VIEWS = 1.to(30),
        ACTIVITY_TIMEOUT = 10,
  ) .* from "./replica_tla"
}
