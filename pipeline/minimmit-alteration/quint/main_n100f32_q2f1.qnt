// -*- mode: Bluespec; -*-

module main {
    import three_quorum_family(
        N = 100,
        F = 32,
        Q_OFFSET = 1,
    ).* from "./three_quorum_family"

    // q = 2f+1 fixes X2, but X1 still fails at f~1/3.
    val expected = all {
        one_third_bound,
        not(admissible),
        not(x1_safety),
        x2_safety,
        progress
    }
}
