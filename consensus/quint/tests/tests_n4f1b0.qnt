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
        VIEWS = 1.to(6),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)
    pure val CERTIFY_FAIL_INV_B3_BLOCK = Map(
        GENESIS_BLOCK -> true,
        "val_b0" -> true,
        "val_b1" -> true,
        "val_b2" -> true,
        "inv_b3" -> false
    )
    pure val CERTIFY_FAIL_INV_B3 = Replicas.mapBy(_ => CERTIFY_FAIL_INV_B3_BLOCK)

    run initTest = {
        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
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

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
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
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == Some("val_b0"))),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_block(v) == Some("val_b0"))),
                assert(replica_state.get("n0").view == 3),
                unchanged_all,
            })

            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == Some("val_b0"))),
                assert(replica_state.get("n0").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n0").length() == 1),
                assert(ghost_committed_blocks.get("n0")[0] == "val_b0"),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run certificationAlwaysTrueTriggersFinalizeTest = {
        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == Some("inv_b3"))),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_block(v) == Some("inv_b3"))),
                assert(not(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v)))),
                assert(replica_state.get("n0").view == 3),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run leaderNullifyTest = {
        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
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
        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            // Force proposer failure with an invalid parent for FIRST_VIEW.
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
        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n1", 1 -> "n2", 2 -> "n3", 3 -> "n0", 4 -> "n1", 5 -> "n2", 6 -> "n3"),
            CERTIFY_FAIL_INV_B3
        )
            // Build notarization(inv_b3, FIRST_VIEW) at n0; certification should fail.
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == Some("inv_b3"))),
                assert(replica_state.get("n0").certified.get(FIRST_VIEW) == None),
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(not(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v)))),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            // Enter view 3 via nullification certificate for FIRST_VIEW.
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 3),
                unchanged_all,
            })
            // In view 3, n0 is leader but must refuse to build on uncertified inv_b3.
            .then(proposer_step("n0", "val_b0", "inv_b3", FIRST_VIEW))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == 3 and is_nullify(v))),
                assert(not(sent_proposal.exists(p => p.sig == "n0" and p.view == 3 and p.block_parent == "inv_b3" and p.view_parent == FIRST_VIEW))),
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

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
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
        lastAction' = "inject_proposal",
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
        lastAction' = "inject_vote",
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
        lastAction' = lastAction,
    }

    action replica_receives_notarize_quorum(id: ReplicaId, block: Block, view: ViewNumber, srcs: Set[ReplicaId]): bool =
        on_vote_notarize(id, view, block, srcs.map(src => notarize(view, src, block)))

    action replica_receives_finalize_quorum(id: ReplicaId, block: Block, view: ViewNumber, srcs: Set[ReplicaId]): bool =
        on_vote_finalize(id, view, block, srcs.map(src => finalize(view, src, block)))

    action replica_receives_nullify_quorum(id: ReplicaId, view: ViewNumber, srcs: Set[ReplicaId]): bool =
        on_vote_nullify(id, view, srcs.map(src => nullify(view, src)))

    // All correct replicas finalize two consecutive blocks.
    run allCorrectReplicasFinalizeTwoBlocksTest = {
        val proposal1 = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        val proposal2 = {
            block: "val_b1",
            view: 3,
            view_parent: FIRST_VIEW,
            block_parent: "val_b0",
            sig: sig_of("n1")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
        // View 2: n0 proposes val_b0 with genesis parent
        .then(inject_proposal(proposal1))
        .then(on_proposal("n0", proposal1))
        .then(on_proposal("n1", proposal1))
        .then(on_proposal("n2", proposal1))
        .then(on_proposal("n3", proposal1))
        // All replicas receive notarize quorum -> notarization, send finalize, advance to view 3
        .then(replica_receives_notarize_quorum("n0", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n1", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n2", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n3", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        // All replicas receive finalize quorum -> finalization, commit val_b0
        .then(replica_receives_finalize_quorum("n0", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n1", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n2", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n3", "val_b0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == "val_b0")),
            assert(CORRECT.forall(id => replica_state.get(id).view == 3)),
            unchanged_all,
        })
        // View 3: n1 proposes val_b1 with val_b0 as parent
        .then(inject_proposal(proposal2))
        .then(on_proposal("n0", proposal2))
        .then(on_proposal("n1", proposal2))
        .then(on_proposal("n2", proposal2))
        .then(on_proposal("n3", proposal2))
        .then(replica_receives_notarize_quorum("n0", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n1", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n2", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n3", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n0", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n1", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n2", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n3", "val_b1", 3, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 2)),
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == "val_b0")),
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[1] == "val_b1")),
            assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 3)),
            unchanged_all,
        })
        .expect(all_invariants)
    }

    // Views 2 and 3 timeout, then view 4 leader proposes and all replicas finalize.
    run timeoutViewsThenFinalizeTest = {
        val proposal = {
            block: "val_b0",
            view: 4,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n2")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
        // View 2: all replicas timeout
        .then(on_timeout("n0"))
        .then(on_timeout("n1"))
        .then(on_timeout("n2"))
        .then(on_timeout("n3"))
        .then(replica_receives_nullify_quorum("n0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n1", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n2", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n3", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).view == 3)),
            unchanged_all,
        })
        // View 3: all replicas timeout
        .then(on_timeout("n0"))
        .then(on_timeout("n1"))
        .then(on_timeout("n2"))
        .then(on_timeout("n3"))
        .then(replica_receives_nullify_quorum("n0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n1", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n2", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n3", 3, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).view == 4)),
            unchanged_all,
        })
        // View 4: n2 proposes val_b0 with genesis parent (views 1-3 all nullified)
        .then(inject_proposal(proposal))
        .then(on_proposal("n0", proposal))
        .then(on_proposal("n1", proposal))
        .then(on_proposal("n2", proposal))
        .then(on_proposal("n3", proposal))
        .then(replica_receives_notarize_quorum("n0", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n1", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n2", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n3", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n0", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n1", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n2", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n3", "val_b0", 4, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == "val_b0")),
            assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 4)),
            unchanged_all,
        })
        .expect(all_invariants)
    }

    // View 2 leader proposes block with wrong parent (not genesis), replicas nullify.
    // View 3 leader proposes correct block with genesis parent, all replicas finalize.
    run wrongParentNullifyThenCorrectFinalizeTest = {
        val bad_proposal = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: "val_b1",
            sig: sig_of("n0")
        }
        val correct_proposal = {
            block: "val_b0",
            view: 3,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n1")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
        // View 2: n0 proposes val_b0 with wrong parent (val_b1 instead of genesis)
        .then(inject_proposal(bad_proposal))
        .then(on_proposal("n0", bad_proposal))
        .then(on_proposal("n1", bad_proposal))
        .then(on_proposal("n2", bad_proposal))
        .then(on_proposal("n3", bad_proposal))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).nullified == true)),
            assert(CORRECT.forall(id => sent_vote.exists(v =>
                vote_sig(v) == id and vote_view(v) == FIRST_VIEW and is_nullify(v)))),
            unchanged_all,
        })
        // Nullify quorum -> advance to view 3
        .then(replica_receives_nullify_quorum("n0", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n1", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n2", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(replica_receives_nullify_quorum("n3", FIRST_VIEW, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).view == 3)),
            unchanged_all,
        })
        // View 3: n1 proposes val_b0 with correct genesis parent
        .then(inject_proposal(correct_proposal))
        .then(on_proposal("n0", correct_proposal))
        .then(on_proposal("n1", correct_proposal))
        .then(on_proposal("n2", correct_proposal))
        .then(on_proposal("n3", correct_proposal))
        .then(replica_receives_notarize_quorum("n0", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n1", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n2", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_notarize_quorum("n3", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n0", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n1", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n2", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(replica_receives_finalize_quorum("n3", "val_b0", 3, Set("n0", "n1", "n2")))
        .then(all {
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
            assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == "val_b0")),
            assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 3)),
            unchanged_all,
        })
        .expect(all_invariants)
    }

    // Replica n0 is very slow (always nullifies), but n1, n2, n3 finalize 2 blocks.
    run slowReplicaAlwaysNullifiesTest = {
        val proposal1 = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n1")
        }
        val proposal2 = {
            block: "val_b1",
            view: 3,
            view_parent: FIRST_VIEW,
            block_parent: "val_b0",
            sig: sig_of("n2")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n3", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        // View 2: n0 times out (slow), n1 is leader and proposes
        .then(on_timeout("n0"))
        .then(inject_proposal(proposal1))
        .then(on_proposal("n1", proposal1))
        .then(on_proposal("n2", proposal1))
        .then(on_proposal("n3", proposal1))
        // n1, n2, n3 receive notarize quorum -> notarization, finalize, advance to view 3
        .then(replica_receives_notarize_quorum("n1", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        .then(replica_receives_notarize_quorum("n2", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        .then(replica_receives_notarize_quorum("n3", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        // n1, n2, n3 receive finalize quorum -> finalization, commit val_b0
        .then(replica_receives_finalize_quorum("n1", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        .then(replica_receives_finalize_quorum("n2", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        .then(replica_receives_finalize_quorum("n3", "val_b0", FIRST_VIEW, Set("n1", "n2", "n3")))
        // n0 receives finalization cert to advance to view 3
        .then(on_certificate("n0", finalization(FIRST_VIEW, "val_b0", Set("n1", "n2", "n3"), "n1")))
        // View 3: n0 times out again (slow), n2 is leader and proposes
        .then(on_timeout("n0"))
        .then(inject_proposal(proposal2))
        .then(on_proposal("n1", proposal2))
        .then(on_proposal("n2", proposal2))
        .then(on_proposal("n3", proposal2))
        .then(replica_receives_notarize_quorum("n1", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(replica_receives_notarize_quorum("n2", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(replica_receives_notarize_quorum("n3", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(replica_receives_finalize_quorum("n1", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(replica_receives_finalize_quorum("n2", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(replica_receives_finalize_quorum("n3", "val_b1", 3, Set("n1", "n2", "n3")))
        .then(all {
            // n1, n2, n3 finalized 2 blocks
            assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id).length() == 2)),
            assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id)[0] == "val_b0")),
            assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id)[1] == "val_b1")),
            // n0 nullified both views
            assert(sent_vote.exists(v =>
                vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
            assert(sent_vote.exists(v =>
                vote_sig(v) == "n0" and vote_view(v) == 3 and is_nullify(v))),
            // n0 committed 1 block (from receiving finalization cert for view 2)
            assert(ghost_committed_blocks.get("n0").length() == 1),
            assert(ghost_committed_blocks.get("n0")[0] == "val_b0"),
            unchanged_all,
        })
        .expect(all_invariants)
    }
}
