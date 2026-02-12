// -*- mode: Bluespec; -*-

// Configuration: 4 participants, 1 fault tolerance, 1 Byzantine PLAYER
// This config tests share_secrecy violations where Byzantine player
// can strategically ack/not-ack to cause reveals for correct players
module main {
    import dkg(
        N = 4,
        F = 1,
        DEALERS = Set("p0", "p1", "p2", "p3"),
        PLAYERS = Set("p0", "p1", "p2", "p3"),
        CORRECT_DEALERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_DEALERS = Set(),
        CORRECT_PLAYERS = Set("p0", "p1", "p2"),
        BYZANTINE_PLAYERS = Set("p3"),
        // Evaluation points must be non-zero and distinct
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4),
        // Degree = quorum - 1 = 2*1 + 1 - 1 = 2
        DEGREE = 2,
    ).* from "./dkg"
}
