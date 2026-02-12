// -*- mode: Bluespec; -*-

// Pure definitions for polynomial operations and quorum calculations
module defs {
    import types.* from "./types"

    // Fixed bounds for Apalache compatibility
    // MAX_DEGREE: maximum polynomial degree (set to support up to n=10)
    // MAX_EVAL_POINT: maximum evaluation point value
    pure val MAX_DEGREE = 5
    pure val MAX_POLY_LEN = 6  // MAX_DEGREE + 1
    pure val MAX_EXPONENT = 30 // MAX_DEGREE * MAX_EVAL_POINT (5 * 6)

    // Fixed index sets for bounded iteration
    pure val POLY_INDICES = Set(0, 1, 2, 3, 4, 5)
    pure val EXP_INDICES = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                               15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)

    // Integer power function using bounded fold
    pure def pow(base: int, exp: int): int = {
        if (exp <= 0) 1
        else EXP_INDICES.filter(i => i < exp).fold(1, (acc, _) => acc * base)
    }

    // Get coefficient at index, or 0 if out of bounds
    pure def coeff(poly: Polynomial, i: int): Scalar = {
        if (i < poly.length()) poly[i] else 0
    }

    // Evaluate polynomial at point x using bounded fold
    // p(x) = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
    pure def eval_poly(poly: Polynomial, x: Scalar): Scalar = {
        POLY_INDICES.filter(i => i < poly.length()).fold(0, (acc, i) =>
            acc + coeff(poly, i) * pow(x, i)
        )
    }

    // Get the degree of a polynomial (index of highest non-zero coefficient)
    pure def degree(poly: Polynomial): int = {
        poly.length() - 1
    }

    // Get the constant term (secret) of a polynomial
    pure def constant(poly: Polynomial): Scalar = {
        if (poly.length() > 0) poly[0] else 0
    }

    // Check if commitment matches share at evaluation point
    pure def verify_share(commitment: Commitment, share: Share, eval_point: Scalar): bool = {
        eval_poly(commitment, eval_point) == share
    }

    // Sum two polynomials (for combining dealer contributions)
    pure def add_poly(p1: Polynomial, p2: Polynomial): Polynomial = {
        val max_len = if (p1.length() > p2.length()) p1.length() else p2.length()
        POLY_INDICES.filter(i => i < max_len).fold(List(), (acc, i) =>
            acc.append(coeff(p1, i) + coeff(p2, i))
        )
    }

    // Sum multiple shares
    pure def sum_shares(shares: Set[Share]): Share = {
        shares.fold(0, (acc, s) => acc + s)
    }

    // Count reveals in a dealer result
    pure def count_reveals(result: DealerResult): int = {
        match result {
            | DealerOk(results) => results.keys().filter(p =>
                match results.get(p) {
                    | Reveal(_) => true
                    | Ack(_) => false
                }
            ).size()
            | TooManyReveals => 0  // Not applicable
        }
    }

    // Count reveals for a specific player across multiple dealer logs
    pure def count_reveals_for_player(
        player: ParticipantId,
        logs: ParticipantId -> DealerLog
    ): int = {
        logs.keys().filter(dealer => {
            match logs.get(dealer).result {
                | DealerOk(results) => match results.get(player) {
                    | Reveal(_) => true
                    | Ack(_) => false
                }
                | TooManyReveals => false
            }
        }).size()
    }

    // Check if a dealer log is valid (has valid structure)
    pure def is_valid_log(log: DealerLog, players: Set[ParticipantId]): bool = {
        match log.result {
            | DealerOk(results) => results.keys() == players
            | TooManyReveals => true
        }
    }
}
