// -*- mode: Bluespec; -*-

module main {
    import three_quorum_family(
        N = 100,
        F = 32,
        Q_OFFSET = 0,
    ).* from "./three_quorum_family"

    // This captures the proposed n=100, f~1/3, q=2f variant.
    val expected = all {
        one_third_bound,
        not(admissible),
        not(x1_safety),
        not(x2_safety)
    }
}
