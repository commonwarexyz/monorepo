// -*- mode: Bluespec; -*-

/// A few handy small models that are good for debugging and inspection
module main {
    // A specification instance for n=6 and f=1
    import replica(
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        FAULTY = Set("n5"),
        WEIGHTS = Map("n0"->1, "n1"->1, "n2"->1, "n3"->1, "n4"->1, "n5"->1),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inval_0", "inval_1"),
        VIEWS = 0.to(6),
  ) .* from "./replica"
}
