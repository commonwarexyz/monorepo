// The chain layer alone, at N = 6, T = 1, F = 1.
//
// A debugging instance: the chain layer never waits on consensus, so it
// is a closed state machine on its own and can be checked before any
// consensus rule exists. Use it to see that DA-certificates actually
// form, and that C1, C2 and C5 hold under an equivocating producer.
//
//   quint run --max-steps=12 --invariant=inv main_da_n6t1f1.qnt
//   quint run --max-steps=12 --invariant=some_cert_formed main_da_n6t1f1.qnt
//
// N = 6, T = 1 is exactly N = 5T + 1, where the uniqueness argument has
// "exactly one of margin": D = N - 2T = 4, and two D-sets intersect in
// 2D - N = N - 4T = 2 >= T + 1 replicas, hence in a correct one.

module main_da_n6t1f1 {
    import types.* from "./types"
    import blocks.* from "./blocks"

    import da(
        // n0..n4 are correct; n5 is byzantine and owns chain 6, so
        // chain 6 is the equivocating chain.
        DA_REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        DA_BYZANTINE = Set("n5"),
        DA_REPLICA_KEYS = Map(
            "n0" -> "n0", "n1" -> "n1", "n2" -> "n2",
            "n3" -> "n3", "n4" -> "n4", "n5" -> "n5"
        ),
        DA_CHAIN_OF = Map(
            "n0" -> 1, "n1" -> 2, "n2" -> 3,
            "n3" -> 4, "n4" -> 5, "n5" -> 6
        ),
        DA_PAYLOADS = Set(1, 2),
        DA_MAX_HEIGHT = 2,
        DA_PARAMS = { n: 6, t: 1, d: 2, e: 1 }
    ).* from "./da"

    action init = da_init
    action step = da_step

    val inv = da_invariants

    // Witnesses. Check these as invariants to see a counterexample that
    // is really a positive example: the run that reaches the state.
    val some_cert_formed = sent_da_cert == Set()
    val some_block_da_voted = da_voted.keys().forall(id => da_voted.get(id) == Set())
    val some_equivocation = {
        val certified = produced.filter(b => b.chain == 6)
        tuples(certified, certified).forall(((b1, b2)) => not(incompatible(b1, b2)))
    }
}
