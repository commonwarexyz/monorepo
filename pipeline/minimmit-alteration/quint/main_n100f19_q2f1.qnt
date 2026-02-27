// -*- mode: Bluespec; -*-

module main {
    import three_quorum_family(
        N = 100,
        F = 19,
        Q_OFFSET = 1,
    ).* from "./three_quorum_family"

    // A passing instance: n >= 5f+1 and q = 2f+1.
    val expected = all {
        admissible,
        one_fifth_bound,
        x1_safety,
        x2_safety,
        progress
    }
}
