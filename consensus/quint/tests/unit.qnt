module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import automaton(
        CERTIFY_DOMAIN = Set("val_b0", "val_b1"),
    ) as app from "../automaton"
    import replica(
        N = 4,
        F = 1,
        Q = 3,
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 1.to(4),
        VALID_PAYLOADS = Set("val_b0", "val_b1"),
        INVALID_PAYLOADS = Set(),
        ACTIVITY_TIMEOUT = 10
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    action unchanged_all = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = lastAction,
    }

    pure def committed(view: ViewNumber, parent: ViewNumber, payload: Payload): Proposal = {
        {
            view: view,
            parent: parent,
            payload: payload,
        }
    }

    action init_with_blocks(chains: ReplicaId -> List[Proposal]): bool = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3", 4 -> "n0"),
            CERTIFY_ALL_TRUE
        ).then(all {
            ghost_committed_blocks' = chains,
            sent_notarize_votes' = sent_notarize_votes,
            sent_nullify_votes' = sent_nullify_votes,
            sent_finalize_votes' = sent_finalize_votes,
            sent_certificates' = sent_certificates,
            store_notarize_votes' = store_notarize_votes,
            store_nullify_votes' = store_nullify_votes,
            store_finalize_votes' = store_finalize_votes,
            store_certificates' = store_certificates,
            leader' = leader,
            replica_state' = replica_state,
            certify_policy' = certify_policy,
            lastAction' = lastAction,
        })
    }

    run emptyAgreementTest =
        init_with_blocks(Map("n0" -> List(), "n1" -> List(), "n2" -> List(), "n3" -> List()))
        .then(all { assert(agreement), unchanged_all })

    run prefixOneTest =
        init_with_blocks(Map("n0" -> List(committed(1, 0, "val_b0")), "n1" -> List(), "n2" -> List(), "n3" -> List()))
        .then(all { assert(agreement), unchanged_all })

    run prefixMatchTest =
        init_with_blocks(Map("n0" -> List(committed(1, 0, "val_b0")), "n1" -> List(committed(1, 0, "val_b0")), "n2" -> List(), "n3" -> List()))
        .then(all { assert(agreement), unchanged_all })

    run prefixLongerTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n1" -> List(committed(1, 0, "val_b0")),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(agreement), unchanged_all })

    run disagreementTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0")),
            "n1" -> List(committed(1, 0, "val_b1")),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(not(agreement)), unchanged_all })

    run disagreementSecondBlockTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n1" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b0")),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(not(agreement)), unchanged_all })

    run allAgreeTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n1" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n2" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n3" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1"))
        ))
        .then(all { assert(agreement), unchanged_all })

    // Negative: three replicas disagree with each other.
    run threeWayDisagreementTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0")),
            "n1" -> List(committed(1, 0, "val_b1")),
            "n2" -> List(committed(1, 0, "val_b0")),
            "n3" -> List(committed(1, 0, "val_b1"))
        ))
        .then(all { assert(not(agreement)), unchanged_all })

    // Negative: longer chain diverges from shorter.
    run longerDivergesTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b1"), committed(2, 1, "val_b0")),
            "n1" -> List(committed(1, 0, "val_b0")),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(not(agreement)), unchanged_all })

    // Positive: committed_blocks_no_duplicates holds with distinct blocks.
    run noDuplicatesTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b1")),
            "n1" -> List(committed(1, 0, "val_b0")),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(committed_blocks_no_duplicates), unchanged_all })

    // Positive: the same payload can appear in multiple committed views.
    run duplicatePayloadDifferentViewsAllowedTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(2, 1, "val_b0")),
            "n1" -> List(),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(committed_blocks_no_duplicates), unchanged_all })

    // Negative: committed_blocks_no_duplicates fails with duplicate committed views.
    run duplicateBlocksTest =
        init_with_blocks(Map(
            "n0" -> List(committed(1, 0, "val_b0"), committed(1, 0, "val_b0")),
            "n1" -> List(),
            "n2" -> List(),
            "n3" -> List()
        ))
        .then(all { assert(not(committed_blocks_no_duplicates)), unchanged_all })
}
