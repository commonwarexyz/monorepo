// -*- mode: Bluespec; -*-

// Configuration: 7 participants, 2 fault tolerance, 2 Byzantine dealers
module main {
    import dkg(
        N = 7,
        F = 2,
        DEALERS = Set("p0", "p1", "p2", "p3", "p4", "p5", "p6"),
        PLAYERS = Set("p0", "p1", "p2", "p3", "p4", "p5", "p6"),
        CORRECT_DEALERS = Set("p0", "p1", "p2", "p3", "p4"),
        BYZANTINE_DEALERS = Set("p5", "p6"),
        CORRECT_PLAYERS = Set("p0", "p1", "p2", "p3", "p4", "p5", "p6"),
        BYZANTINE_PLAYERS = Set(),
        // Evaluation points must be non-zero and distinct
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4, "p4" -> 5, "p5" -> 6, "p6" -> 7),
        // Degree = quorum - 1 = 2*2 + 1 - 1 = 4
        DEGREE = 4,
        // Polynomials for correct dealers (degree 4)
        POLYNOMIALS = Set(
            List(1, 2, 3, 4, 5),
            List(6, 7, 8, 9, 10),
            List(11, 12, 13, 14, 15)
        ),
        // Byzantine behavior parameters
        BYZANTINE_COMMITMENTS = Set(List(1, 1, 1, 1, 1), List(0, 0, 0, 0, 0)),
        BYZANTINE_SHARES = Set(0, 1, 999),
    ).* from "./dkg"
}
