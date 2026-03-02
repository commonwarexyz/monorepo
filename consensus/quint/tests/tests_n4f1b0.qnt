module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import automaton(
        CERTIFY_DOMAIN = Set("val_b0", "val_b1", "val_b2", "inv_b3"),
    ) as app from "../automaton"
    import replica(
        N = 4,
        F = 1,
        Q = 3,
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set(),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 0.to(6),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)
    pure val CERTIFY_FAIL_INV_B3_BLOCK = Map(
        EMPTY_BLOCK -> true,
        GENESIS_BLOCK -> true,
        "val_b0" -> true,
        "val_b1" -> true,
        "val_b2" -> true,
        "inv_b3" -> false
    )
    pure val CERTIFY_FAIL_INV_B3 = Replicas.mapBy(_ => CERTIFY_FAIL_INV_B3_BLOCK)

    run initTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(all {
                assert(replica_state.get("n0").view == FIRST_VIEW),
                assert(replica_state.get("n1").view == FIRST_VIEW),
                assert(replica_state.get("n2").view == FIRST_VIEW),
                assert(replica_state.get("n3").view == FIRST_VIEW),
                assert(replica_state.get("n0").last_finalized == GENESIS_VIEW),
                unchanged_all,
            })
    }

    run happyPathFinalizeTest = {
        val proposal = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(proposal))
            .then(on_proposal("n0", proposal))
            .then(on_proposal("n1", proposal))
            .then(on_proposal("n2", proposal))
            .then(on_proposal("n3", proposal))

            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "val_b0")),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_block(v) == "val_b0")),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })

            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "val_b0")),
                assert(replica_state.get("n0").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n0").length() == 1),
                assert(ghost_committed_blocks.get("n0")[0] == "val_b0"),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run certificationAlwaysTrueTriggersFinalizeTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "inv_b3")),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_block(v) == "inv_b3")),
                assert(not(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v)))),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run leaderNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n0"))
            .then(all {
                assert(store_vote.get("n1").exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(sent_vote.exists(v => vote_sig(v) == "n1" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(replica_state.get("n1").nullified == true),
                assert(replica_state.get("n1").leader_timeout_cancelled == true),
                assert(replica_state.get("n1").advance_timeout_cancelled == true),
                assert(replica_state.get("n1").view == FIRST_VIEW),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run localProposalFailureTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            // Force proposer failure with an invalid parent for view 1.
            .then(proposer_step("n0", "val_b0", "val_b1", GENESIS_VIEW))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(replica_state.get("n0").nullified == true),
                assert(replica_state.get("n0").leader_timeout_cancelled == true),
                assert(replica_state.get("n0").advance_timeout_cancelled == true),
                assert(replica_state.get("n0").propose_sent == false),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                assert(not(sent_proposal.exists(p => p.sig == "n0" and p.view == FIRST_VIEW))),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run runCertifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n0", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_FAIL_INV_B3
        )
            // Build notarization(inv_b3, 1) at n0; certification should fail.
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "inv_b3")),
                assert(replica_state.get("n0").certified.get(FIRST_VIEW) == EMPTY_BLOCK),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(not(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v)))),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            // Enter view 2 via nullification certificate for view 1.
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            // In view 2, n0 is leader but must refuse to build on uncertified inv_b3.
            .then(proposer_step("n0", "val_b0", "inv_b3", FIRST_VIEW))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == 2 and is_nullify(v))),
                assert(not(sent_proposal.exists(p => p.sig == "n0" and p.view == 2 and p.block_parent == "inv_b3" and p.view_parent == FIRST_VIEW))),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run localVerificationFailureTest = {
        val invalid_proposal = {
            block: "inv_b3",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(invalid_proposal))
            .then(on_proposal("n1", invalid_proposal))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n1" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(not(sent_vote.exists(v => vote_sig(v) == "n1" and vote_view(v) == FIRST_VIEW and is_notarize(v)))),
                assert(replica_state.get("n1").nullified == true),
                assert(replica_state.get("n1").leader_timeout_cancelled == true),
                assert(replica_state.get("n1").advance_timeout_cancelled == true),
                assert(replica_state.get("n1").view == FIRST_VIEW),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    action inject_proposal(proposal: Proposal): bool = all {
        sent_proposal' = sent_proposal.union(Set(proposal)),
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        parent_refs' = parent_refs,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
    }

    action inject_vote(vote: Vote): bool = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote.union(Set(vote)),
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        parent_refs' = parent_refs,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
    }

    action replica_receives_notarize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_notarize(id, view, block, Set(notarize(view, src, block)))

    action replica_receives_finalize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_finalize(id, view, block, Set(finalize(view, src, block)))

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: ReplicaId): bool =
        on_vote_nullify(id, view, Set(nullify(view, src)))

    action unchanged_all = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        parent_refs' = parent_refs,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
    }
}
