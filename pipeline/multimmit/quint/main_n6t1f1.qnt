// The full model at N = 6, T = 1, F = 1.
//
// N = 6, T = 1 is exactly N = 5T + 1, the tight case. Thresholds are
// D = N - 2T = 4, M = 2T + 1 = 3, L = N - T = 5, and the uniqueness
// argument has "exactly one of margin": two D-sets intersect in
// 2D - N = N - 4T = 2 >= T + 1 replicas, hence in a correct one.
//
//   quint typecheck main_n6t1f1.qnt
//   quint run --max-steps=20 --invariant=all_invariants main_n6t1f1.qnt
//   quint verify --invariant=agreement main_n6t1f1.qnt
//
// The witnesses (no_leader_block, no_vote, no_vqc, no_log) are meant to
// be violated: checking one as an invariant yields a run that reaches
// the corresponding state, which is how to see that the model is live
// before trusting that its invariants hold vacuously.

module main_n6t1f1 {
    import types.* from "./types"

    import consensus(
        N = 6,
        T = 1,
        F = 1,
        // n0..n4 are correct and own chains 1..5; n5 is byzantine and
        // owns chain 6, so chain 6 is the equivocating chain and n5
        // leads every view v with v % 6 == 5.
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        TWINS = Set(),
        BYZANTINE = Set("n5"),
        REPLICA_KEYS = Map(
            "n0" -> "n0", "n1" -> "n1", "n2" -> "n2",
            "n3" -> "n3", "n4" -> "n4", "n5" -> "n5"
        ),
        CHAIN_OF = Map(
            "n0" -> 1, "n1" -> 2, "n2" -> 3,
            "n3" -> 4, "n4" -> 5, "n5" -> 6
        ),
        PAYLOADS = Set(1, 2),
        MAX_HEIGHT = 2,
        VIEWS = 0.to(3),
        MAX_VQC_HASH = 4,
        PIPELINE_D = 2,
        EXT_E = 1
    ).* from "./consensus"
}
