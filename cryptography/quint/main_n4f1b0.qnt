// -*- mode: Bluespec; -*-

// Configuration: 4 participants, 1 fault tolerance, 0 Byzantine
// All participants are both dealers and players (standard DKG setup)
module main {
    import dkg(
        N = 4,
        F = 1,
        DEALERS = Set("p0", "p1", "p2", "p3"),
        PLAYERS = Set("p0", "p1", "p2", "p3"),
        CORRECT_DEALERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_DEALERS = Set(),
        CORRECT_PLAYERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_PLAYERS = Set(),
        // Evaluation points must be non-zero and distinct
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4),
        // Degree = quorum - 1 = 2*1 + 1 - 1 = 2
        DEGREE = 2,
        // Polynomials for correct dealers (degree 2)
        POLYNOMIALS = Set(List(1, 2, 3), List(4, 5, 6), List(7, 8, 9)),
        // Byzantine behavior parameters (not used when BYZANTINE_DEALERS is empty)
        BYZANTINE_COMMITMENTS = Set(List(1, 1, 1), List(0, 0, 0)),
        BYZANTINE_SHARES = Set(0, 1, 999),
    ).* from "./dkg"
}
