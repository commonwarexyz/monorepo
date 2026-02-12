// -*- mode: Bluespec; -*-

// Tests for DKG with 4 participants, 1 fault tolerance, 1 Byzantine (p3)
module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import dkg(
        N = 4,
        F = 1,
        DEALERS = Set("p0", "p1", "p2", "p3"),
        PLAYERS = Set("p0", "p1", "p2", "p3"),
        CORRECT_DEALERS = Set("p0", "p1", "p2"),
        BYZANTINE_DEALERS = Set("p3"),
        CORRECT_PLAYERS = Set("p0", "p1", "p2"),
        BYZANTINE_PLAYERS = Set("p3"),
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4),
        DEGREE = 2,
    ).* from "../dkg"

    // Verify configuration with Byzantine participant
    run configTest = all {
        quorum == 3,
        max_reveals == 1,
        required_dealers == 3,
        BYZANTINE_DEALERS.size() == 1,
        assumptions_valid,
    }

    // Test: Byzantine dealer sends wrong share to a player
    // Correct player should reject the invalid share and not ack
    run byzantineWrongShareTest = {
        pure val poly_p0 = List(10, 1, 1)
        pure val poly_p1 = List(20, 2, 1)
        pure val poly_p2 = List(30, 3, 1)
        // Byzantine p3's commitment
        pure val commitment_p3 = List(40, 4, 1)

        init
            // Correct dealers start
            .then(dealer_start("p0", poly_p0))
            .then(dealer_start("p1", poly_p1))
            .then(dealer_start("p2", poly_p2))
            // Byzantine p3 sends a commitment
            .then(byzantine_send_pub_msg("p3", { commitment: commitment_p3 }))
            // Byzantine p3 sends WRONG share to p0 (doesn't match commitment)
            .then(byzantine_send_priv_msg("p3", "p0", { share: 999 }))
            // Byzantine p3 sends correct shares to p1, p2
            .then(byzantine_send_priv_msg("p3", "p1", { share: eval_poly(commitment_p3, 2) }))
            .then(byzantine_send_priv_msg("p3", "p2", { share: eval_poly(commitment_p3, 3) }))
            // Players start
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            // p0 tries to receive from p3 - should fail verification and not ack
            .then(player_try_receive("p0", "p3", commitment_p3, 999))
            .then(all {
                // p0 should NOT have acked p3
                assert(not(sent_acks.exists(ack => ack.player == "p0" and ack.dealer == "p3"))),
                unchanged_all,
            })
            // p1, p2 receive from p3 - should succeed
            .then(player_receive_from_dealer("p1", "p3", commitment_p3))
            .then(player_receive_from_dealer("p2", "p3", commitment_p3))
            .then(all {
                // p1, p2 should have acked p3
                assert(sent_acks.exists(ack => ack.player == "p1" and ack.dealer == "p3")),
                assert(sent_acks.exists(ack => ack.player == "p2" and ack.dealer == "p3")),
                unchanged_all,
            })
            .expect(safe)
    }

    // Test: Byzantine dealer withholds share from a player
    // Protocol should still work as long as quorum of correct dealers participate
    run byzantineWithholdShareTest = {
        pure val poly_p0 = List(10, 1, 1)
        pure val poly_p1 = List(20, 2, 1)
        pure val poly_p2 = List(30, 3, 1)

        init
            // Only correct dealers start (Byzantine p3 doesn't participate)
            .then(dealer_start("p0", poly_p0))
            .then(dealer_start("p1", poly_p1))
            .then(dealer_start("p2", poly_p2))
            // Players start
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            // All correct players receive from all correct dealers
            .then(player_receive_from_dealer("p0", "p0", poly_p0))
            .then(player_receive_from_dealer("p0", "p1", poly_p1))
            .then(player_receive_from_dealer("p0", "p2", poly_p2))
            .then(player_receive_from_dealer("p1", "p0", poly_p0))
            .then(player_receive_from_dealer("p1", "p1", poly_p1))
            .then(player_receive_from_dealer("p1", "p2", poly_p2))
            .then(player_receive_from_dealer("p2", "p0", poly_p0))
            .then(player_receive_from_dealer("p2", "p1", poly_p1))
            .then(player_receive_from_dealer("p2", "p2", poly_p2))
            // Dealers receive acks
            .then(dealer_receive_ack("p0", { player: "p0", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p1", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p2", dealer: "p0" }))
            .then(dealer_receive_ack("p1", { player: "p0", dealer: "p1" }))
            .then(dealer_receive_ack("p1", { player: "p1", dealer: "p1" }))
            .then(dealer_receive_ack("p1", { player: "p2", dealer: "p1" }))
            .then(dealer_receive_ack("p2", { player: "p0", dealer: "p2" }))
            .then(dealer_receive_ack("p2", { player: "p1", dealer: "p2" }))
            .then(dealer_receive_ack("p2", { player: "p2", dealer: "p2" }))
            // Dealers finalize
            .then(dealer_finalize("p0"))
            .then(dealer_finalize("p1"))
            .then(dealer_finalize("p2"))
            // Players finalize with only correct dealers (quorum = 3, we have 3)
            .then(player_finalize("p0", Set("p0", "p1", "p2")))
            .then(player_finalize("p1", Set("p0", "p1", "p2")))
            .then(player_finalize("p2", Set("p0", "p1", "p2")))
            .expect(safe)
            .then(all {
                // All correct players should have finalized
                assert(ghost_finalized_players == Set("p0", "p1", "p2")),
                // Combined secret from p0, p1, p2 = 10 + 20 + 30 = 60
                assert(constant(ghost_public_poly) == 60),
                unchanged_all,
            })
    }

    // Test: Byzantine player doesn't ack, causing reveal
    // But only 1 reveal <= max_reveals, so dealer can still finalize
    run byzantineNoAckTest = {
        pure val poly_p0 = List(10, 1, 1)

        init
            .then(dealer_start("p0", poly_p0))
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            // Correct players receive and ack
            .then(player_receive_from_dealer("p0", "p0", poly_p0))
            .then(player_receive_from_dealer("p1", "p0", poly_p0))
            .then(player_receive_from_dealer("p2", "p0", poly_p0))
            // Byzantine p3 doesn't ack (or we don't model their ack)
            // Dealer receives acks from correct players
            .then(dealer_receive_ack("p0", { player: "p0", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p1", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p2", dealer: "p0" }))
            // Dealer finalizes - should have 1 reveal (p3) which is <= max_reveals
            .then(dealer_finalize("p0"))
            .then(all {
                assert(match dealer_state.get("p0") {
                    | DealerFinalized(log) => match log.result {
                        | Ok(map) => and {
                            // p3's share should be revealed
                            match map.get("p3") { | Reveal(_) => true | _ => false },
                            // p0, p1, p2 should have acks
                            match map.get("p0") { | Ack(_) => true | _ => false },
                            match map.get("p1") { | Ack(_) => true | _ => false },
                            match map.get("p2") { | Ack(_) => true | _ => false },
                        }
                        | _ => false
                    }
                    | _ => false
                }),
                unchanged_all,
            })
            .expect(safe)
    }

    // Test: Share secrecy - if player has <= F reveals, their share is secret
    run shareSecrecyTest = {
        pure val poly_p0 = List(10, 1, 1)
        pure val poly_p1 = List(20, 2, 1)
        pure val poly_p2 = List(30, 3, 1)

        init
            .then(dealer_start("p0", poly_p0))
            .then(dealer_start("p1", poly_p1))
            .then(dealer_start("p2", poly_p2))
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            // p0 receives from all dealers
            .then(player_receive_from_dealer("p0", "p0", poly_p0))
            .then(player_receive_from_dealer("p0", "p1", poly_p1))
            .then(player_receive_from_dealer("p0", "p2", poly_p2))
            // p1 only receives from p0 (doesn't ack p1, p2)
            .then(player_receive_from_dealer("p1", "p0", poly_p0))
            // p2 receives from all dealers
            .then(player_receive_from_dealer("p2", "p0", poly_p0))
            .then(player_receive_from_dealer("p2", "p1", poly_p1))
            .then(player_receive_from_dealer("p2", "p2", poly_p2))
            // Dealers receive acks and finalize
            .then(dealer_receive_ack("p0", { player: "p0", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p1", dealer: "p0" }))
            .then(dealer_receive_ack("p0", { player: "p2", dealer: "p0" }))
            .then(dealer_receive_ack("p1", { player: "p0", dealer: "p1" }))
            .then(dealer_receive_ack("p1", { player: "p2", dealer: "p1" }))
            .then(dealer_receive_ack("p2", { player: "p0", dealer: "p2" }))
            .then(dealer_receive_ack("p2", { player: "p2", dealer: "p2" }))
            .then(dealer_finalize("p0"))
            .then(dealer_finalize("p1"))
            .then(dealer_finalize("p2"))
            .then(all {
                // p1 has 2 reveals (from p1 and p2's logs) which is > F=1
                // But p0 and p2 have 0 reveals each, so their shares are secret
                // The share_secrecy invariant should still hold for p0 and p2
                assert(match dealer_state.get("p1") {
                    | DealerFinalized(log) => match log.result {
                        | Ok(map) => match map.get("p1") { | Reveal(_) => true | _ => false }
                        | _ => false
                    }
                    | _ => false
                }),
                assert(match dealer_state.get("p2") {
                    | DealerFinalized(log) => match log.result {
                        | Ok(map) => match map.get("p1") { | Reveal(_) => true | _ => false }
                        | _ => false
                    }
                    | _ => false
                }),
                unchanged_all,
            })
            .expect(safe)
    }

    // Helper action: player receives from a specific dealer
    action player_receive_from_dealer(player: ParticipantId, dealer: ParticipantId, poly: Polynomial): bool = {
        val pub_msg = { commitment: poly }
        val priv_msg = { share: eval_poly(poly, EVAL_POINTS.get(player)) }
        player_receive_dealer_msg(player, dealer, pub_msg, priv_msg)
    }

    // Helper action: player tries to receive with specific messages (may fail verification)
    action player_try_receive(
        player: ParticipantId,
        dealer: ParticipantId,
        commitment: Commitment,
        share: Share
    ): bool = {
        val pub_msg = { commitment: commitment }
        val priv_msg = { share: share }
        player_receive_dealer_msg(player, dealer, pub_msg, priv_msg)
    }

    // Helper: keep all state unchanged
    action unchanged_all = all {
        round' = round,
        dealer_state' = dealer_state,
        player_state' = player_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_priv_msgs' = sent_priv_msgs,
        sent_acks' = sent_acks,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_poly' = ghost_public_poly,
    }
}
