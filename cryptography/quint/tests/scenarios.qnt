// -*- mode: Bluespec; -*-

// Explicit scenario tests using .then() chaining (minimmit pattern)
module scenarios {
    import types.* from "../types"
    import defs.* from "../defs"
    import dkg(
        N = 4,
        F = 1,
        DEALERS = Set("p0", "p1", "p2", "p3"),
        PLAYERS = Set("p0", "p1", "p2", "p3"),
        CORRECT_DEALERS = Set("p0", "p1", "p2"),
        BYZANTINE_DEALERS = Set("p3"),
        CORRECT_PLAYERS = Set("p0", "p1", "p2", "p3"),
        BYZANTINE_PLAYERS = Set(),
        EVAL_POINTS = Map("p0" -> 1, "p1" -> 2, "p2" -> 3, "p3" -> 4),
        DEGREE = 2,
        POLYNOMIALS = Set(List(1, 2, 3), List(4, 5, 6), List(7, 8, 9)),
        BYZANTINE_COMMITMENTS = Set(List(1, 1, 1), List(0, 0, 0)),
        BYZANTINE_SHARES = Set(0, 1, 999),
    ).* from "../dkg"

    // ─────────────────────────────────────────────────────────────────────────
    // Test helper actions (minimmit pattern)
    // ─────────────────────────────────────────────────────────────────────────

    // Helper: player receives share from dealer (computes correct share automatically)
    action player_receives_share(player: ParticipantId, dealer: ParticipantId, poly: Polynomial): bool =
        player_receive_dealer_msg(player, dealer,
            { commitment: poly },
            { share: eval_poly(poly, EVAL_POINTS.get(player)) })

    // Helper: dealer receives ACK from player
    action dealer_receives_ack(dealer: ParticipantId, player: ParticipantId): bool =
        dealer_receive_ack(dealer, { player: player, dealer: dealer })

    // Helper: dealer finalizes (timer expires)
    action dealer_finalizes(dealer: ParticipantId): bool =
        dealer_timer_expired(dealer)

    // Helper: unchanged for assertions between steps
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
        ghost_public_polys' = ghost_public_polys,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Happy Path - Synchronous execution
    // All dealers start, all players receive and ACK, dealers finalize with
    // all ACKs, players finalize. Share secrecy holds.
    // ─────────────────────────────────────────────────────────────────────────
    run happyPathTest = {
        val poly0 = List(1, 2, 3)
        val poly1 = List(4, 5, 6)
        val poly2 = List(7, 8, 9)

        init
            // Phase 1: All correct dealers start
            .then(dealer_start("p0", poly0))
            .then(dealer_start("p1", poly1))
            .then(dealer_start("p2", poly2))
            .expect(is_dealer_distributing(dealer_state.get("p0")))
            .expect(is_dealer_distributing(dealer_state.get("p1")))
            .expect(is_dealer_distributing(dealer_state.get("p2")))
            .expect(sent_pub_msgs.size() == 3)
            .expect(sent_priv_msgs.size() == 12)

            // Phase 2: All players start
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            .then(player_start("p3"))
            .expect(CORRECT_PLAYERS.forall(p => is_player_receiving(player_state.get(p))))

            // Phase 3: All players receive from all correct dealers
            .then(player_receives_share("p0", "p0", poly0))
            .then(player_receives_share("p0", "p1", poly1))
            .then(player_receives_share("p0", "p2", poly2))
            .then(player_receives_share("p1", "p0", poly0))
            .then(player_receives_share("p1", "p1", poly1))
            .then(player_receives_share("p1", "p2", poly2))
            .then(player_receives_share("p2", "p0", poly0))
            .then(player_receives_share("p2", "p1", poly1))
            .then(player_receives_share("p2", "p2", poly2))
            .then(player_receives_share("p3", "p0", poly0))
            .then(player_receives_share("p3", "p1", poly1))
            .then(player_receives_share("p3", "p2", poly2))
            .expect(sent_acks.size() == 12)

            // Phase 4: Dealers receive all ACKs
            .then(dealer_receives_ack("p0", "p0"))
            .then(dealer_receives_ack("p0", "p1"))
            .then(dealer_receives_ack("p0", "p2"))
            .then(dealer_receives_ack("p0", "p3"))
            .then(dealer_receives_ack("p1", "p0"))
            .then(dealer_receives_ack("p1", "p1"))
            .then(dealer_receives_ack("p1", "p2"))
            .then(dealer_receives_ack("p1", "p3"))
            .then(dealer_receives_ack("p2", "p0"))
            .then(dealer_receives_ack("p2", "p1"))
            .then(dealer_receives_ack("p2", "p2"))
            .then(dealer_receives_ack("p2", "p3"))
            .expect(get_distributing(dealer_state.get("p0")).acks_received == CORRECT_PLAYERS)
            .expect(get_distributing(dealer_state.get("p1")).acks_received == CORRECT_PLAYERS)
            .expect(get_distributing(dealer_state.get("p2")).acks_received == CORRECT_PLAYERS)

            // Phase 5: Dealer timers expire (finalize with all ACKs = no reveals)
            .then(dealer_finalizes("p0"))
            .then(dealer_finalizes("p1"))
            .then(dealer_finalizes("p2"))
            .expect(is_dealer_finalized(dealer_state.get("p0")))
            .expect(is_dealer_finalized(dealer_state.get("p1")))
            .expect(is_dealer_finalized(dealer_state.get("p2")))
            .expect(sent_logs.size() == 3)
            // No reveals for any player
            .expect(sent_logs.forall(entry => match entry.log.result {
                | DealerOk(results) => CORRECT_PLAYERS.forall(p =>
                    match results.get(p) { | Ack(_) => true | Reveal(_) => false }
                )
                | TooManyReveals => false
            }))

            // Phase 6: Players finalize
            .then(player_finalize("p0"))
            .expect(is_player_finalized(player_state.get("p0")))
            .expect(ghost_selected_dealers == Set("p0", "p1", "p2"))
            .expect(share_secrecy)

            .then(player_finalize("p1"))
            .then(player_finalize("p2"))
            .then(player_finalize("p3"))
            .expect(CORRECT_PLAYERS.forall(p => is_player_finalized(player_state.get(p))))
            .expect(safe)
            .expect(share_secrecy)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Async - One player slow, gets revealed by all dealers
    // p0 doesn't ACK before any dealer timer expires -> revealed by all 3
    // This violates share_secrecy (3 reveals > F=1)
    // ─────────────────────────────────────────────────────────────────────────
    run asyncSlowPlayerTest = {
        val poly0 = List(1, 2, 3)
        val poly1 = List(4, 5, 6)
        val poly2 = List(7, 8, 9)

        init
            // All dealers start
            .then(dealer_start("p0", poly0))
            .then(dealer_start("p1", poly1))
            .then(dealer_start("p2", poly2))

            // All players start
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            .then(player_start("p3"))

            // Only p1, p2, p3 receive and ACK (p0 is slow)
            .then(player_receives_share("p1", "p0", poly0))
            .then(player_receives_share("p1", "p1", poly1))
            .then(player_receives_share("p1", "p2", poly2))
            .then(player_receives_share("p2", "p0", poly0))
            .then(player_receives_share("p2", "p1", poly1))
            .then(player_receives_share("p2", "p2", poly2))
            .then(player_receives_share("p3", "p0", poly0))
            .then(player_receives_share("p3", "p1", poly1))
            .then(player_receives_share("p3", "p2", poly2))
            .expect(sent_acks.size() == 9)
            .expect(not({ player: "p0", dealer: "p0" }.in(sent_acks)))

            // Dealers receive ACKs from p1, p2, p3 only
            .then(dealer_receives_ack("p0", "p1"))
            .then(dealer_receives_ack("p0", "p2"))
            .then(dealer_receives_ack("p0", "p3"))
            .then(dealer_receives_ack("p1", "p1"))
            .then(dealer_receives_ack("p1", "p2"))
            .then(dealer_receives_ack("p1", "p3"))
            .then(dealer_receives_ack("p2", "p1"))
            .then(dealer_receives_ack("p2", "p2"))
            .then(dealer_receives_ack("p2", "p3"))

            // Dealer timers expire (p0 not in acks_received -> revealed)
            .then(dealer_finalizes("p0"))
            .then(dealer_finalizes("p1"))
            .then(dealer_finalizes("p2"))
            .expect(sent_logs.size() == 3)
            // Each log reveals p0
            .expect(sent_logs.forall(entry => match entry.log.result {
                | DealerOk(results) => match results.get("p0") {
                    | Reveal(_) => true
                    | Ack(_) => false
                }
                | TooManyReveals => false
            }))

            // p0 finally receives (but too late)
            .then(player_receives_share("p0", "p0", poly0))
            .then(player_receives_share("p0", "p1", poly1))
            .then(player_receives_share("p0", "p2", poly2))

            // Player finalize
            .then(player_finalize("p0"))
            .expect(is_player_finalized(player_state.get("p0")))
            .expect(ghost_selected_dealers == Set("p0", "p1", "p2"))
            // Share secrecy VIOLATED: p0 revealed by 3 dealers > F=1
            .expect(not(share_secrecy))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Bounded reveals - one player slow but within F limit
    // Dealer p0 receives 3 ACKs (p1, p2, p3) before timer, reveals only p0
    // Share secrecy holds (1 reveal = F)
    // ─────────────────────────────────────────────────────────────────────────
    run boundedRevealsTest = {
        val poly0 = List(1, 2, 3)
        val poly1 = List(4, 5, 6)
        val poly2 = List(7, 8, 9)

        init
            .then(dealer_start("p0", poly0))
            .then(dealer_start("p1", poly1))
            .then(dealer_start("p2", poly2))

            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            .then(player_start("p3"))

            // p1, p2, p3 receive and ACK all dealers first (p0 is slow)
            .then(player_receives_share("p1", "p0", poly0))
            .then(player_receives_share("p1", "p1", poly1))
            .then(player_receives_share("p1", "p2", poly2))
            .then(player_receives_share("p2", "p0", poly0))
            .then(player_receives_share("p2", "p1", poly1))
            .then(player_receives_share("p2", "p2", poly2))
            .then(player_receives_share("p3", "p0", poly0))
            .then(player_receives_share("p3", "p1", poly1))
            .then(player_receives_share("p3", "p2", poly2))

            // Dealer p0 receives ACKs from p1, p2, p3 (not p0)
            .then(dealer_receives_ack("p0", "p1"))
            .then(dealer_receives_ack("p0", "p2"))
            .then(dealer_receives_ack("p0", "p3"))

            // Dealer p0's timer expires with 3 ACKs -> reveals p0 only
            .then(dealer_finalizes("p0"))
            .expect(match dealer_state.get("p0") {
                | DealerFinalized(log) => match log.result {
                    | DealerOk(results) =>
                        match results.get("p0") { | Reveal(_) => true | Ack(_) => false } and
                        match results.get("p1") { | Ack(_) => true | Reveal(_) => false } and
                        match results.get("p2") { | Ack(_) => true | Reveal(_) => false } and
                        match results.get("p3") { | Ack(_) => true | Reveal(_) => false }
                    | TooManyReveals => false
                }
                | _ => false
            })

            // p0 finally receives (late)
            .then(player_receives_share("p0", "p0", poly0))
            .then(player_receives_share("p0", "p1", poly1))
            .then(player_receives_share("p0", "p2", poly2))

            // Dealers p1 and p2 receive all ACKs before timer
            .then(dealer_receives_ack("p1", "p0"))
            .then(dealer_receives_ack("p1", "p1"))
            .then(dealer_receives_ack("p1", "p2"))
            .then(dealer_receives_ack("p1", "p3"))
            .then(dealer_receives_ack("p2", "p0"))
            .then(dealer_receives_ack("p2", "p1"))
            .then(dealer_receives_ack("p2", "p2"))
            .then(dealer_receives_ack("p2", "p3"))

            .then(dealer_finalizes("p1"))
            .then(dealer_finalizes("p2"))
            // Dealers p1, p2 have all ACKs (no reveals)
            .expect(sent_logs.filter(e => e.dealer == "p1" or e.dealer == "p2").forall(entry =>
                match entry.log.result {
                    | DealerOk(results) => CORRECT_PLAYERS.forall(p =>
                        match results.get(p) { | Ack(_) => true | Reveal(_) => false }
                    )
                    | TooManyReveals => false
                }
            ))

            .then(player_finalize("p0"))
            .expect(is_player_finalized(player_state.get("p0")))
            // Share secrecy holds: p0 revealed by only 1 dealer (= F)
            .expect(share_secrecy)
            .expect(safe)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: TooManyReveals - dealer timer expires with < quorum ACKs
    // ─────────────────────────────────────────────────────────────────────────
    run tooManyRevealsTest = {
        val poly0 = List(1, 2, 3)

        init
            .then(dealer_start("p0", poly0))
            .then(player_start("p0"))
            .then(player_start("p1"))

            // Only p0 receives and ACKs
            .then(player_receives_share("p0", "p0", poly0))
            .then(dealer_receives_ack("p0", "p0"))

            // Timer expires with only 1 ACK (reveals p1, p2, p3 = 3 > F)
            .then(dealer_finalizes("p0"))
            .expect(match dealer_state.get("p0") {
                | DealerFinalized(log) => match log.result {
                    | TooManyReveals => true
                    | DealerOk(_) => false
                }
                | _ => false
            })
            .expect(bounded_reveals)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Byzantine dealer sends inconsistent log - gets rejected
    // ─────────────────────────────────────────────────────────────────────────
    run byzantineLogRejectedTest = {
        val poly0 = List(1, 2, 3)
        val poly1 = List(4, 5, 6)
        val poly2 = List(7, 8, 9)

        init
            // Correct dealers complete normally
            .then(dealer_start("p0", poly0))
            .then(dealer_start("p1", poly1))
            .then(dealer_start("p2", poly2))

            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            .then(player_start("p3"))

            // All players receive from correct dealers and ACK
            .then(player_receives_share("p0", "p0", poly0))
            .then(player_receives_share("p0", "p1", poly1))
            .then(player_receives_share("p0", "p2", poly2))
            .then(player_receives_share("p1", "p0", poly0))
            .then(player_receives_share("p1", "p1", poly1))
            .then(player_receives_share("p1", "p2", poly2))
            .then(player_receives_share("p2", "p0", poly0))
            .then(player_receives_share("p2", "p1", poly1))
            .then(player_receives_share("p2", "p2", poly2))
            .then(player_receives_share("p3", "p0", poly0))
            .then(player_receives_share("p3", "p1", poly1))
            .then(player_receives_share("p3", "p2", poly2))

            // Dealers receive all ACKs and finalize
            .then(dealer_receives_ack("p0", "p0"))
            .then(dealer_receives_ack("p0", "p1"))
            .then(dealer_receives_ack("p0", "p2"))
            .then(dealer_receives_ack("p0", "p3"))
            .then(dealer_receives_ack("p1", "p0"))
            .then(dealer_receives_ack("p1", "p1"))
            .then(dealer_receives_ack("p1", "p2"))
            .then(dealer_receives_ack("p1", "p3"))
            .then(dealer_receives_ack("p2", "p0"))
            .then(dealer_receives_ack("p2", "p1"))
            .then(dealer_receives_ack("p2", "p2"))
            .then(dealer_receives_ack("p2", "p3"))
            .then(dealer_finalizes("p0"))
            .then(dealer_finalizes("p1"))
            .then(dealer_finalizes("p2"))

            // Byzantine dealer p3 sends a FAKE log claiming all ACKs
            .then(byzantine_send_log("p3", {
                pub_msg: { commitment: List(1, 1, 1) },
                result: DealerOk(PLAYERS.mapBy(p => Ack({ player: p, dealer: "p3" })))
            }))
            .expect(sent_logs.size() == 4)
            // Byzantine log is NOT consistent (fake ACKs not in sent_acks)
            .expect(not(is_consistent_log("p3", sent_logs.filter(e => e.dealer == "p3").fold(
                { pub_msg: { commitment: List() }, result: TooManyReveals },
                (_, e) => e.log
            ))))

            .then(player_finalize("p0"))
            // Only 3 dealers selected (Byzantine p3 rejected)
            .expect(ghost_selected_dealers == Set("p0", "p1", "p2"))
            .expect(safe)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Output agreement - all players compute same public poly
    // ─────────────────────────────────────────────────────────────────────────
    run outputAgreementTest = {
        val poly0 = List(1, 2, 3)
        val poly1 = List(4, 5, 6)
        val poly2 = List(7, 8, 9)
        val expected_combined = add_poly(add_poly(poly0, poly1), poly2)

        init
            .then(dealer_start("p0", poly0))
            .then(dealer_start("p1", poly1))
            .then(dealer_start("p2", poly2))
            .then(player_start("p0"))
            .then(player_start("p1"))
            .then(player_start("p2"))
            .then(player_start("p3"))

            // All receive and ACK
            .then(player_receives_share("p0", "p0", poly0))
            .then(player_receives_share("p0", "p1", poly1))
            .then(player_receives_share("p0", "p2", poly2))
            .then(player_receives_share("p1", "p0", poly0))
            .then(player_receives_share("p1", "p1", poly1))
            .then(player_receives_share("p1", "p2", poly2))
            .then(player_receives_share("p2", "p0", poly0))
            .then(player_receives_share("p2", "p1", poly1))
            .then(player_receives_share("p2", "p2", poly2))
            .then(player_receives_share("p3", "p0", poly0))
            .then(player_receives_share("p3", "p1", poly1))
            .then(player_receives_share("p3", "p2", poly2))

            .then(dealer_receives_ack("p0", "p0"))
            .then(dealer_receives_ack("p0", "p1"))
            .then(dealer_receives_ack("p0", "p2"))
            .then(dealer_receives_ack("p0", "p3"))
            .then(dealer_receives_ack("p1", "p0"))
            .then(dealer_receives_ack("p1", "p1"))
            .then(dealer_receives_ack("p1", "p2"))
            .then(dealer_receives_ack("p1", "p3"))
            .then(dealer_receives_ack("p2", "p0"))
            .then(dealer_receives_ack("p2", "p1"))
            .then(dealer_receives_ack("p2", "p2"))
            .then(dealer_receives_ack("p2", "p3"))
            .then(dealer_finalizes("p0"))
            .then(dealer_finalizes("p1"))
            .then(dealer_finalizes("p2"))

            // All players finalize
            .then(player_finalize("p0"))
            .then(player_finalize("p1"))
            .then(player_finalize("p2"))
            .then(player_finalize("p3"))

            // All players computed the same public polynomial
            .expect(ghost_public_polys.get("p0") == expected_combined)
            .expect(ghost_public_polys.get("p1") == expected_combined)
            .expect(ghost_public_polys.get("p2") == expected_combined)
            .expect(ghost_public_polys.get("p3") == expected_combined)
            .expect(output_agreement)
    }
}
