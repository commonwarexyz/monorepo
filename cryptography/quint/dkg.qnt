// -*- mode: Bluespec; -*-

// Joint-Feldman Distributed Key Generation Protocol
//
// This module specifies the DKG protocol where multiple dealers run VSS instances
// in parallel. Each dealer generates a random polynomial, distributes commitments
// publicly and shares privately to players. The final shared secret is the sum
// of all selected dealers' contributions.
//
// ## Partial Synchrony Model
//
// This spec models partial synchrony following the minimmit pattern:
// - `timer_expired: bool` in DealerDistributing state tracks whether timer has fired
// - `dealer_timer_expired`: fires nondeterministically, finalizes dealer with current acks
// - `dealer_receive_ack`: can happen while timer_expired is false, does NOT affect timer
//
// The nondeterministic scheduler explores all interleavings:
// - "Synchrony": dealer_receive_ack actions happen before dealer_timer_expired
// - "Asynchrony": dealer_timer_expired fires before some/all acks are received
//
// Under synchrony: All correct ACKs arrive before timer -> share_secrecy holds
// Under async: Timer may expire before ACKs arrive -> share_secrecy may be violated
//
// This matches the Rust implementation's documented caveats (see dkg.rs lines 103-180).

module dkg {
    import types.* from "./types"
    import defs.* from "./defs"

    // ─────────────────────────────────────────────────────────────────────────
    // Configuration constants
    // ─────────────────────────────────────────────────────────────────────────

    const N: int
    const F: int
    const DEALERS: Set[ParticipantId]
    const PLAYERS: Set[ParticipantId]
    const CORRECT_DEALERS: Set[ParticipantId]
    const BYZANTINE_DEALERS: Set[ParticipantId]
    const CORRECT_PLAYERS: Set[ParticipantId]
    const BYZANTINE_PLAYERS: Set[ParticipantId]
    const EVAL_POINTS: ParticipantId -> Scalar
    const DEGREE: int

    // Polynomials for correct dealers to choose from (must have correct degree)
    const POLYNOMIALS: Set[Polynomial]

    // Byzantine behavior parameters
    const BYZANTINE_COMMITMENTS: Set[Commitment]
    const BYZANTINE_SHARES: Set[Share]

    // ─────────────────────────────────────────────────────────────────────────
    // Derived constants
    // ─────────────────────────────────────────────────────────────────────────

    pure val quorum = 2 * F + 1
    pure val max_reveals = F
    pure val required_dealers = quorum

    // ─────────────────────────────────────────────────────────────────────────
    // Dealer selection
    // ─────────────────────────────────────────────────────────────────────────

    // Check if a dealer's log has valid structure (degree, reveal count)
    pure def is_selectable_log(log: DealerLog): bool = {
        degree(log.pub_msg.commitment) == DEGREE and
        match log.result {
            | DealerOk(results) => count_reveals(DealerOk(results)) <= max_reveals
            | TooManyReveals => false
        }
    }

    // Check if a dealer's log is consistent with ground truth:
    // - ACK claims must have corresponding ACK in sent_acks
    // - Reveal shares must verify against the commitment
    // This models cryptographic verification without actual crypto.
    def is_consistent_log(dealer: ParticipantId, log: DealerLog): bool = {
        match log.result {
            | DealerOk(results) => PLAYERS.forall(p =>
                match results.get(p) {
                    // ACK claim: verify the ACK was actually sent
                    | Ack(_) => { player: p, dealer: dealer }.in(sent_acks)
                    // Reveal claim: verify the share matches the commitment
                    | Reveal(pm) => verify_share(log.pub_msg.commitment, pm.share, EVAL_POINTS.get(p))
                }
            )
            | TooManyReveals => true  // No specific claims to verify
        }
    }

    // Compute the set of valid dealers from sent logs
    // A dealer is valid if their log is both selectable AND consistent
    def valid_dealers(): Set[ParticipantId] = {
        sent_logs.filter(entry =>
            is_selectable_log(entry.log) and is_consistent_log(entry.dealer, entry.log)
        ).map(entry => entry.dealer)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State variables
    // ─────────────────────────────────────────────────────────────────────────

    var round: RoundNumber
    var dealer_state: ParticipantId -> DealerState
    var player_state: ParticipantId -> PlayerState
    var sent_pub_msgs: Set[{ dealer: ParticipantId, msg: DealerPubMsg }]
    var sent_priv_msgs: Set[{ dealer: ParticipantId, player: ParticipantId, msg: DealerPrivMsg }]
    var sent_acks: Set[PlayerAck]
    var sent_logs: Set[{ dealer: ParticipantId, log: DealerLog }]

    // Ghost variables for verification
    var ghost_selected_dealers: Set[ParticipantId]
    var ghost_finalized_players: Set[ParticipantId]
    var ghost_public_polys: ParticipantId -> Commitment

    // ─────────────────────────────────────────────────────────────────────────
    // Helper predicates for state checks
    // ─────────────────────────────────────────────────────────────────────────

    pure def is_dealer_idle(state: DealerState): bool =
        match state {
            | DealerIdle => true
            | _ => false
        }

    pure def is_dealer_distributing(state: DealerState): bool =
        match state {
            | DealerDistributing(_) => true
            | _ => false
        }

    pure def is_dealer_finalized(state: DealerState): bool =
        match state {
            | DealerFinalized(_) => true
            | _ => false
        }

    pure def is_player_idle(state: PlayerState): bool =
        match state {
            | PlayerIdle => true
            | _ => false
        }

    pure def is_player_receiving(state: PlayerState): bool =
        match state {
            | PlayerReceiving(_) => true
            | _ => false
        }

    pure def is_player_finalized(state: PlayerState): bool =
        match state {
            | PlayerFinalized(_) => true
            | _ => false
        }

    pure def is_player_failed(state: PlayerState): bool =
        match state {
            | PlayerFailed => true
            | _ => false
        }

    pure def is_player_terminal(state: PlayerState): bool =
        is_player_finalized(state) or is_player_failed(state)

    // Extract distributing state
    // Requires: is_dealer_distributing(state) == true
    pure def get_distributing(state: DealerState): {
        polynomial: Polynomial,
        pub_msg: DealerPubMsg,
        acks_received: Set[ParticipantId],
        timer_expired: bool
    } = match state {
            | DealerDistributing(s) => s
            | _ => { polynomial: List(), pub_msg: { commitment: List() }, acks_received: Set(), timer_expired: false }
        }

    // Extract receiving state
    // Requires: is_player_receiving(state) == true
    pure def get_receiving(state: PlayerState): {
        received: ParticipantId -> { pub_msg: DealerPubMsg, priv_msg: DealerPrivMsg }
    } = match state {
            | PlayerReceiving(s) => s
            | _ => { received: Map() }
        }

    // ─────────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────────

    action init = all {
        round' = 0,
        dealer_state' = DEALERS.mapBy(_ => DealerIdle),
        player_state' = PLAYERS.mapBy(_ => PlayerIdle),
        sent_pub_msgs' = Set(),
        sent_priv_msgs' = Set(),
        sent_acks' = Set(),
        sent_logs' = Set(),
        ghost_selected_dealers' = Set(),
        ghost_finalized_players' = Set(),
        ghost_public_polys' = Map(),
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dealer actions
    // ─────────────────────────────────────────────────────────────────────────

    action dealer_start(dealer: ParticipantId, polynomial: Polynomial): bool = {
        val pub_msg: DealerPubMsg = { commitment: polynomial }
        all {
            dealer.in(DEALERS),
            is_dealer_idle(dealer_state.get(dealer)),
            degree(polynomial) == DEGREE,

            dealer_state' = dealer_state.set(dealer, DealerDistributing({
                polynomial: polynomial,
                pub_msg: pub_msg,
                acks_received: Set(),
                timer_expired: false
            })),
            sent_pub_msgs' = sent_pub_msgs.union(Set({ dealer: dealer, msg: pub_msg })),
            sent_priv_msgs' = sent_priv_msgs.union(
                PLAYERS.map(p => {
                    dealer: dealer,
                    player: p,
                    msg: { share: eval_poly(polynomial, EVAL_POINTS.get(p)) }
                })
            ),
            round' = round,
            player_state' = player_state,
            sent_acks' = sent_acks,
            sent_logs' = sent_logs,
            ghost_selected_dealers' = ghost_selected_dealers,
            ghost_finalized_players' = ghost_finalized_players,
            ghost_public_polys' = ghost_public_polys,
        }
    }

    // Dealer receives an ack from a player
    // Following minimmit pattern: this does NOT affect timer_expired
    // The timer fires independently via dealer_timer_expired
    action dealer_receive_ack(dealer: ParticipantId, ack: PlayerAck): bool = all {
        dealer.in(DEALERS),
        ack.dealer == dealer,
        ack.in(sent_acks),
        is_dealer_distributing(dealer_state.get(dealer)),
        val state = get_distributing(dealer_state.get(dealer))
        all {
            not(state.timer_expired),  // Can only receive acks before timer expires
            dealer_state' = dealer_state.set(dealer, DealerDistributing({
                ...state,
                acks_received: state.acks_received.union(Set(ack.player))
            })),
            round' = round,
            player_state' = player_state,
            sent_pub_msgs' = sent_pub_msgs,
            sent_priv_msgs' = sent_priv_msgs,
            sent_acks' = sent_acks,
            sent_logs' = sent_logs,
            ghost_selected_dealers' = ghost_selected_dealers,
            ghost_finalized_players' = ghost_finalized_players,
            ghost_public_polys' = ghost_public_polys,
        }
    }

    // Helper: build the dealer log from current state
    pure def build_dealer_log(dealer: ParticipantId, state: {
        polynomial: Polynomial,
        pub_msg: DealerPubMsg,
        acks_received: Set[ParticipantId],
        timer_expired: bool
    }): DealerLog = {
        val results_map: ParticipantId -> AckOrReveal = PLAYERS.mapBy(p =>
            if (p.in(state.acks_received))
                Ack({ player: p, dealer: dealer })
            else
                Reveal({ share: eval_poly(state.polynomial, EVAL_POINTS.get(p)) })
        )
        val num_reveals = PLAYERS.filter(p => not(p.in(state.acks_received))).size()
        val result: DealerResult = if (num_reveals > max_reveals) TooManyReveals else DealerOk(results_map)
        { pub_msg: state.pub_msg, result: result }
    }

    // Timer expires - dealer finalizes with whatever acks they have
    // Following minimmit pattern: this is the ONLY way for a dealer to finalize
    // The nondeterministic scheduler determines when this fires relative to ack arrivals
    action dealer_timer_expired(dealer: ParticipantId): bool = all {
        dealer.in(CORRECT_DEALERS),
        is_dealer_distributing(dealer_state.get(dealer)),
        val state = get_distributing(dealer_state.get(dealer))
        val log = build_dealer_log(dealer, state)
        all {
            not(state.timer_expired),  // Timer hasn't already fired
            dealer_state' = dealer_state.set(dealer, DealerFinalized(log)),
            sent_logs' = sent_logs.union(Set({ dealer: dealer, log: log })),
            round' = round,
            player_state' = player_state,
            sent_pub_msgs' = sent_pub_msgs,
            sent_priv_msgs' = sent_priv_msgs,
            sent_acks' = sent_acks,
            ghost_selected_dealers' = ghost_selected_dealers,
            ghost_finalized_players' = ghost_finalized_players,
            ghost_public_polys' = ghost_public_polys,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Player actions
    // ─────────────────────────────────────────────────────────────────────────

    action player_start(player: ParticipantId): bool = all {
        player.in(PLAYERS),
        is_player_idle(player_state.get(player)),

        player_state' = player_state.set(player, PlayerReceiving({ received: Map() })),
        round' = round,
        dealer_state' = dealer_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_priv_msgs' = sent_priv_msgs,
        sent_acks' = sent_acks,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    action player_receive_dealer_msg(
        player: ParticipantId,
        dealer: ParticipantId,
        pub_msg: DealerPubMsg,
        priv_msg: DealerPrivMsg
    ): bool = all {
        player.in(CORRECT_PLAYERS),
        dealer.in(DEALERS),
        { dealer: dealer, msg: pub_msg }.in(sent_pub_msgs),
        { dealer: dealer, player: player, msg: priv_msg }.in(sent_priv_msgs),
        is_player_receiving(player_state.get(player)),
        val state = get_receiving(player_state.get(player))
        val not_already_received = not(dealer.in(state.received.keys()))
        val valid_degree = degree(pub_msg.commitment) == DEGREE
        val valid_share = verify_share(pub_msg.commitment, priv_msg.share, EVAL_POINTS.get(player))
        val is_valid = not_already_received and valid_degree and valid_share
        all {
            is_valid,

            player_state' = player_state.set(player, PlayerReceiving({
                received: state.received.put(dealer, { pub_msg: pub_msg, priv_msg: priv_msg })
            })),
            sent_acks' = sent_acks.union(Set({ player: player, dealer: dealer })),
            round' = round,
            dealer_state' = dealer_state,
            sent_pub_msgs' = sent_pub_msgs,
            sent_priv_msgs' = sent_priv_msgs,
            sent_logs' = sent_logs,
            ghost_selected_dealers' = ghost_selected_dealers,
            ghost_finalized_players' = ghost_finalized_players,
            ghost_public_polys' = ghost_public_polys,
        }
    }

    action player_finalize(player: ParticipantId): bool = all {
        player.in(CORRECT_PLAYERS),
        is_player_receiving(player_state.get(player)),
        // Select dealers with valid AND consistent logs
        val selected_dealers = sent_logs.filter(entry =>
            is_selectable_log(entry.log) and is_consistent_log(entry.dealer, entry.log)
        ).map(entry => entry.dealer)
        val state = get_receiving(player_state.get(player))
        val logs: ParticipantId -> DealerLog = selected_dealers.mapBy(d =>
            sent_logs.filter(entry => entry.dealer == d).fold(
                { pub_msg: { commitment: List() }, result: TooManyReveals },
                (_, entry) => entry.log
            )
        )
        val shares: Set[Share] = selected_dealers.map(d => {
            if (d.in(state.received.keys()))
                state.received.get(d).priv_msg.share
            else
                match logs.get(d).result {
                    | DealerOk(results) => match results.get(player) {
                        | Reveal(pm) => pm.share
                        | Ack(_) => 0
                    }
                    | TooManyReveals => 0
                }
        })
        val final_share = sum_shares(shares)
        val public_poly = selected_dealers.fold(List(), (acc, d) =>
            add_poly(acc, logs.get(d).pub_msg.commitment)
        )
        all {
            selected_dealers.size() >= required_dealers,
            player_state' = player_state.set(player, PlayerFinalized({ share: final_share })),
            ghost_selected_dealers' = selected_dealers,
            ghost_finalized_players' = ghost_finalized_players.union(Set(player)),
            ghost_public_polys' = ghost_public_polys.put(player, public_poly),
            round' = round,
            dealer_state' = dealer_state,
            sent_pub_msgs' = sent_pub_msgs,
            sent_priv_msgs' = sent_priv_msgs,
            sent_acks' = sent_acks,
            sent_logs' = sent_logs,
        }
    }

    // Player fails - cannot get enough dealer contributions
    // NOT included in step for partial synchrony (correct players always eventually ack)
    action player_fail(player: ParticipantId): bool = all {
        player.in(PLAYERS),
        is_player_receiving(player_state.get(player)),

        player_state' = player_state.set(player, PlayerFailed),
        round' = round,
        dealer_state' = dealer_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_priv_msgs' = sent_priv_msgs,
        sent_acks' = sent_acks,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Round progression
    // ─────────────────────────────────────────────────────────────────────────

    action advance_round: bool = all {
        CORRECT_DEALERS.forall(d => is_dealer_finalized(dealer_state.get(d))),
        CORRECT_PLAYERS.forall(p => is_player_terminal(player_state.get(p))),

        round' = round + 1,
        dealer_state' = DEALERS.mapBy(_ => DealerIdle),
        player_state' = PLAYERS.mapBy(_ => PlayerIdle),
        sent_pub_msgs' = Set(),
        sent_priv_msgs' = Set(),
        sent_acks' = Set(),
        sent_logs' = Set(),
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Byzantine behavior
    // ─────────────────────────────────────────────────────────────────────────

    action byzantine_send_pub_msg(dealer: ParticipantId, msg: DealerPubMsg): bool = all {
        dealer.in(BYZANTINE_DEALERS),
        sent_pub_msgs' = sent_pub_msgs.union(Set({ dealer: dealer, msg: msg })),
        round' = round,
        dealer_state' = dealer_state,
        player_state' = player_state,
        sent_priv_msgs' = sent_priv_msgs,
        sent_acks' = sent_acks,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    action byzantine_send_priv_msg(dealer: ParticipantId, player: ParticipantId, msg: DealerPrivMsg): bool = all {
        dealer.in(BYZANTINE_DEALERS),
        player.in(PLAYERS),
        sent_priv_msgs' = sent_priv_msgs.union(Set({ dealer: dealer, player: player, msg: msg })),
        round' = round,
        dealer_state' = dealer_state,
        player_state' = player_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_acks' = sent_acks,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    action byzantine_send_log(dealer: ParticipantId, log: DealerLog): bool = all {
        dealer.in(BYZANTINE_DEALERS),
        sent_logs' = sent_logs.union(Set({ dealer: dealer, log: log })),
        round' = round,
        dealer_state' = dealer_state,
        player_state' = player_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_priv_msgs' = sent_priv_msgs,
        sent_acks' = sent_acks,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    action byzantine_send_ack(player: ParticipantId, dealer: ParticipantId): bool = all {
        player.in(BYZANTINE_PLAYERS),
        dealer.in(DEALERS),
        sent_acks' = sent_acks.union(Set({ player: player, dealer: dealer })),
        round' = round,
        dealer_state' = dealer_state,
        player_state' = player_state,
        sent_pub_msgs' = sent_pub_msgs,
        sent_priv_msgs' = sent_priv_msgs,
        sent_logs' = sent_logs,
        ghost_selected_dealers' = ghost_selected_dealers,
        ghost_finalized_players' = ghost_finalized_players,
        ghost_public_polys' = ghost_public_polys,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step relation
    // ─────────────────────────────────────────────────────────────────────────

    action step = any {
        all {
            nondet dealer = oneOf(CORRECT_DEALERS)
            nondet poly = oneOf(POLYNOMIALS)
            dealer_start(dealer, poly)
        },
        all {
            // Pick ack first, then use ack.dealer to ensure matching
            nondet ack = oneOf(sent_acks)
            dealer_receive_ack(ack.dealer, ack)
        },
        all {
            // Timer expires - this is the ONLY way for correct dealers to finalize
            // The scheduler nondeterministically chooses when this happens
            nondet dealer = oneOf(CORRECT_DEALERS)
            dealer_timer_expired(dealer)
        },
        all {
            nondet player = oneOf(CORRECT_PLAYERS)
            player_start(player)
        },
        all {
            // Pick a correct player's priv_entry, then find matching pub_entry
            nondet priv_entry = oneOf(sent_priv_msgs.filter(e => e.player.in(CORRECT_PLAYERS)))
            nondet pub_entry = oneOf(sent_pub_msgs.filter(e => e.dealer == priv_entry.dealer))
            player_receive_dealer_msg(priv_entry.player, priv_entry.dealer, pub_entry.msg, priv_entry.msg)
        },
        all {
            nondet player = oneOf(CORRECT_PLAYERS)
            player_finalize(player)
        },
        // NOTE: player_fail is NOT included for CORRECT_PLAYERS in partial synchrony.
        // Correct players always eventually send ACKs. The async behavior is modeled by
        // dealer_timer_expired firing before dealer_receive_ack.
        advance_round,
        all {
            BYZANTINE_DEALERS.size() > 0,
            nondet dealer = oneOf(BYZANTINE_DEALERS)
            nondet commitment = oneOf(BYZANTINE_COMMITMENTS)
            byzantine_send_pub_msg(dealer, { commitment: commitment })
        },
        all {
            BYZANTINE_DEALERS.size() > 0,
            nondet dealer = oneOf(BYZANTINE_DEALERS)
            nondet player = oneOf(PLAYERS)
            nondet share = oneOf(BYZANTINE_SHARES)
            byzantine_send_priv_msg(dealer, player, { share: share })
        },
        all {
            BYZANTINE_PLAYERS.size() > 0,
            nondet player = oneOf(BYZANTINE_PLAYERS)
            nondet dealer = oneOf(DEALERS)
            byzantine_send_ack(player, dealer)
        },
        // Byzantine dealers can send arbitrary logs (will be rejected if inconsistent)
        all {
            BYZANTINE_DEALERS.size() > 0,
            nondet dealer = oneOf(BYZANTINE_DEALERS)
            nondet commitment = oneOf(BYZANTINE_COMMITMENTS)
            // Byzantine can claim arbitrary ACKs/Reveals - players will verify
            nondet results = oneOf(Set(
                // Claim everyone ACKed (might be false)
                PLAYERS.mapBy(p => Ack({ player: p, dealer: dealer })),
                // Claim everyone revealed (with potentially wrong shares)
                PLAYERS.mapBy(p => Reveal({ share: 0 }))
            ))
            byzantine_send_log(dealer, {
                pub_msg: { commitment: commitment },
                result: DealerOk(results)
            })
        },
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Invariants
    // ─────────────────────────────────────────────────────────────────────────

    val assumptions_valid = all {
        CORRECT_DEALERS.union(BYZANTINE_DEALERS) == DEALERS,
        CORRECT_PLAYERS.union(BYZANTINE_PLAYERS) == PLAYERS,
        CORRECT_DEALERS.intersect(BYZANTINE_DEALERS) == Set(),
        CORRECT_PLAYERS.intersect(BYZANTINE_PLAYERS) == Set(),
        BYZANTINE_DEALERS.size() <= F,
        BYZANTINE_PLAYERS.size() <= F,
        N >= 3 * F + 1,
    }

    val output_agreement = {
        val finalized = CORRECT_PLAYERS.filter(p => is_player_finalized(player_state.get(p)))
        val polys = finalized.map(p => ghost_public_polys.get(p))
        polys.size() <= 1  // All polynomials are equal (set collapses duplicates)
    }

    // share_secrecy: under asynchrony, this MAY be violated
    // Under synchrony (all acks arrive before timer), it holds
    val share_secrecy = CORRECT_PLAYERS.forall(player => {
        val reveals_for_player = ghost_selected_dealers.filter(d =>
            sent_logs.exists(entry =>
                entry.dealer == d and
                match entry.log.result {
                    | DealerOk(results) => match results.get(player) {
                        | Reveal(_) => true
                        | Ack(_) => false
                    }
                    | TooManyReveals => false
                }
            )
        )
        reveals_for_player.size() <= F
    })

    val round_progress = round >= 0

    val dealer_logs_valid = CORRECT_DEALERS.forall(d =>
        match dealer_state.get(d) {
            | DealerFinalized(log) => is_valid_log(log, PLAYERS)
            | _ => true
        }
    )

    val bounded_reveals = CORRECT_DEALERS.forall(d =>
        match dealer_state.get(d) {
            | DealerFinalized(log) => match log.result {
                | DealerOk(results) => count_reveals(DealerOk(results)) <= max_reveals
                | TooManyReveals => true
            }
            | _ => true
        }
    )

    val safe = all {
        assumptions_valid,
        output_agreement,
        dealer_logs_valid,
        bounded_reveals,
    }

    // Test examples - these should be VIOLATED to show the behavior exists
    val player_finalized_example = not(CORRECT_PLAYERS.exists(p => is_player_finalized(player_state.get(p))))

    val too_many_reveals_example = not(CORRECT_DEALERS.exists(d =>
        match dealer_state.get(d) {
            | DealerFinalized(log) => match log.result {
                | TooManyReveals => true
                | _ => false
            }
            | _ => false
        }
    ))

    val round_advanced_example = round < 1

    // This should be violated under async scheduling (timer fires before all acks)
    // See tests/test_adversarial.qnt for a test that proves this can be violated
    val share_secrecy_violated_example = share_secrecy
}
