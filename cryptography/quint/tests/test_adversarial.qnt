// -*- mode: Bluespec; -*-

// Test for proving share_secrecy violation is reachable under adversarial scheduling
module test_adversarial {
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
        POLYNOMIALS = Set(List(1, 2, 3), List(4, 5, 6), List(7, 8, 9)),
        BYZANTINE_COMMITMENTS = Set(List(1, 1, 1), List(0, 0, 0)),
        BYZANTINE_SHARES = Set(0, 1, 999),
    ).* from "../dkg"

    // Adversarial setup: all dealers finalize with p1,p2,p3 acks (revealing p0)
    // This creates the scenario where share_secrecy is violated because p0 is
    // revealed by more than F dealers (all 3 selected dealers reveal p0's share)
    action adversarial_setup: bool = {
        val selected_dealers = Set("p0", "p1", "p2")
        val acking_players = Set("p1", "p2", "p3")
        val poly = List(1, 2, 3)

        all {
            // Start from initial state
            round == 0,
            DEALERS.forall(d => is_dealer_idle(dealer_state.get(d))),

            // Set up acks from p1, p2, p3 for all selected dealers
            sent_acks' = selected_dealers.fold(Set(), (acc, d) =>
                acc.union(acking_players.map(p => { player: p, dealer: d }))
            ),

            // Create logs for selected dealers, all revealing p0
            sent_logs' = selected_dealers.map(d => {
                dealer: d,
                log: {
                    pub_msg: { commitment: poly },
                    result: DealerOk(PLAYERS.mapBy(p =>
                        if (p == "p0") Reveal({ share: eval_poly(poly, EVAL_POINTS.get(p)) })
                        else Ack({ player: p, dealer: d })
                    ))
                }
            }),

            // Dealers are finalized
            dealer_state' = DEALERS.mapBy(d =>
                if (d.in(selected_dealers)) DealerFinalized({
                    pub_msg: { commitment: poly },
                    result: DealerOk(PLAYERS.mapBy(p =>
                        if (p == "p0") Reveal({ share: eval_poly(poly, EVAL_POINTS.get(p)) })
                        else Ack({ player: p, dealer: d })
                    ))
                })
                else DealerIdle
            ),

            // Players ready to finalize
            player_state' = PLAYERS.mapBy(p =>
                if (p.in(CORRECT_PLAYERS)) PlayerReceiving({ received: Map() })
                else PlayerIdle
            ),

            // Set up pub messages
            sent_pub_msgs' = selected_dealers.map(d => {
                dealer: d,
                msg: { commitment: poly }
            }),

            // Set up priv messages
            sent_priv_msgs' = selected_dealers.fold(Set(), (acc, d) =>
                acc.union(PLAYERS.map(p => {
                    dealer: d,
                    player: p,
                    msg: { share: eval_poly(poly, EVAL_POINTS.get(p)) }
                }))
            ),

            round' = round,
            ghost_selected_dealers' = ghost_selected_dealers,
            ghost_finalized_players' = ghost_finalized_players,
            ghost_public_polys' = ghost_public_polys,
        }
    }

    // Step relation that includes adversarial_setup
    action step_with_adversarial = any {
        step,
        adversarial_setup,
    }

    // This should be violated when adversarial_setup is enabled
    // (reuses share_secrecy_violated_example from dkg module)
}
