// The full model at N = 7, T = 1, F = 1 -- one processor above the tight
// case.
//
// This instance sits in the ambiguous-designation regime. Two disjoint
// sets of M votes need 4T + 2 messages, which exceeds L = N - T exactly
// when N <= 5T + 1. At N = 7, T = 1 we have M = 3, L = 6 and 2M = 6 <= L,
// so a bare V-notarization may designate two proposals, and "the tips of
// a notarization" is not well defined on the message set alone.
//
// This is harmless in the protocol, because a V-QC always names a single
// designated proposal -- the leader block it contains -- and it is the
// V-QC's designation that every rule consults. It matters for anyone
// transcribing the invariants: any invariant stated over bare
// notarizations rather than over V-QCs should break here, which is the
// point of running it. Every invariant in consensus.qnt is stated over
// V-QCs, so all of them should hold.
//
//   quint run --max-steps=30 --invariant=all_invariants main_n7t1f1.qnt

module main_n7t1f1 {
    import types.* from "./types"

    import consensus(
        N = 7,
        T = 1,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        TWINS = Set(),
        BYZANTINE = Set("n6"),
        REPLICA_KEYS = Map(
            "n0" -> "n0", "n1" -> "n1", "n2" -> "n2", "n3" -> "n3",
            "n4" -> "n4", "n5" -> "n5", "n6" -> "n6"
        ),
        CHAIN_OF = Map(
            "n0" -> 1, "n1" -> 2, "n2" -> 3, "n3" -> 4,
            "n4" -> 5, "n5" -> 6, "n6" -> 7
        ),
        PAYLOADS = Set(1, 2),
        MAX_HEIGHT = 2,
        VIEWS = 0.to(3),
        MAX_VQC_HASH = 4,
        PIPELINE_D = 2,
        EXT_E = 1
    ).* from "./consensus"
}
