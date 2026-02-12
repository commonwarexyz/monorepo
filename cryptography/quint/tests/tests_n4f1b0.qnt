// -*- mode: Bluespec; -*-

// Tests for DKG with 4 participants, 1 fault tolerance, 0 Byzantine
module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import dkg(
        N = 4,
        F = 1,
        DEALERS = Set("p0", "p1", "p2", "p3"),
        PLAYERS = Set("p0", "p1", "p2", "p3"),
        CORRECT_DEALERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_DEALERS = Set(),
        CORRECT_PLAYERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_PLAYERS = Set(),
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4),
        DEGREE = 2,
    ).* from "../dkg"

    // Verify configuration
    run configTest = all {
        assert(quorum == 3),
        assert(max_reveals == 1),
        assert(required_dealers == 3),
        assumptions_valid,
    }

    // Test polynomial evaluation
    // p(x) = 1 + 2x + 3x^2
    run polyEvalTest = {
        val poly = List(1, 2, 3)
        all {
            // p(0) = 1
            assert(eval_poly(poly, 0) == 1),
            // p(1) = 1 + 2 + 3 = 6
            assert(eval_poly(poly, 1) == 6),
            // p(2) = 1 + 4 + 12 = 17
            assert(eval_poly(poly, 2) == 17),
        }
    }

    // Test share verification
    // c(x) = 5 + 3x + 2x^2
    run shareVerifyTest = {
        val commitment = List(5, 3, 2)
        all {
            // c(1) = 5 + 3 + 2 = 10
            assert(verify_share(commitment, 10, 1) == true),
            // c(2) = 5 + 6 + 8 = 19
            assert(verify_share(commitment, 19, 2) == true),
            // Wrong share should fail
            assert(verify_share(commitment, 999, 1) == false),
        }
    }

    // Test power function
    run powTest = all {
        assert(pow(2, 0) == 1),
        assert(pow(2, 1) == 2),
        assert(pow(2, 3) == 8),
        assert(pow(3, 2) == 9),
        assert(pow(5, 3) == 125),
    }

    // Test polynomial addition
    run addPolyTest = {
        val p1 = List(1, 2, 3)    // 1 + 2x + 3x^2
        val p2 = List(4, 5, 6)    // 4 + 5x + 6x^2
        val sum = add_poly(p1, p2)  // 5 + 7x + 9x^2
        all {
            assert(sum[0] == 5),
            assert(sum[1] == 7),
            assert(sum[2] == 9),
        }
    }
}
