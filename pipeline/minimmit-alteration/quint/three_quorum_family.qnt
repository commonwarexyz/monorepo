// -*- mode: Bluespec; -*-

module three_quorum_family {
    // Total participants.
    const N: int
    // Byzantine bound.
    const F: int
    // Nullification offset in q = 2F + offset.
    const Q_OFFSET: int

    // Candidate threshold family discussed in the design notes:
    // m = n - 3f, q = 2f + offset, l = n - f
    pure val M = N - 3 * F
    pure val Q = 2 * F + Q_OFFSET
    pure val L = N - F

    pure val basic_assumptions = all {
        N > 0,
        F >= 0,
        F < N
    }

    pure val thresholds_in_range = all {
        basic_assumptions,
        1 <= M,
        M <= N,
        1 <= Q,
        Q <= N,
        1 <= L,
        L <= N
    }

    // Minimmit-style quorum constraints adapted to three quorums.
    // X1-style safety: finalized block excludes conflicting notarization.
    pure val x1_safety = M + L >= N + F + 1
    // X2-style safety: finalized block excludes nullification.
    pure val x2_safety = Q >= N - L + F + 1
    // Progress: if no notarization forms, nullification is still reachable.
    pure val progress = Q <= N - F - M + 1

    pure val admissible = all {
        thresholds_in_range,
        x1_safety,
        x2_safety,
        progress
    }

    // Closed forms for this threshold family.
    pure val x1_reduced = x1_safety iff (N >= 5 * F + 1)
    pure val x2_reduced = x2_safety iff (Q_OFFSET >= 1)
    pure val progress_reduced = progress iff (Q_OFFSET <= 1)

    pure val one_third_bound = 3 * F < N
    pure val one_fifth_bound = 5 * F + 1 <= N

    // Consequences for the family:
    pure val admissible_implies_one_fifth = admissible implies one_fifth_bound
    pure val x2_and_progress_force_offset_one =
        all { x2_safety, progress } implies (Q_OFFSET == 1)

    // Trivial transition system so the properties can be checked with `quint verify`.
    var stable: bool

    action init = stable' = true

    action step = stable' = stable

    val all_invariants = all {
        x1_reduced,
        x2_reduced,
        progress_reduced,
        admissible_implies_one_fifth,
        x2_and_progress_force_offset_one
    }

    val safe = all_invariants
}
