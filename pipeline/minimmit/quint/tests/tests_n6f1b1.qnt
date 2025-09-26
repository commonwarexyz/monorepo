module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import replica(
        N = 6,
        F = 1,
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        BYZANTINE = Set("n5"),
        VIEWS = 0.to(8),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    run asuumptionsValidTest = all {
        L == 5,
        M == 3,
        assumptions_valid
    }

    run contradictionTest = {
        pure val proposal_from_n0 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        pure val proposal_from_n5_1 = {
            block: "val_b1",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n5")
        }
        pure val proposal_from_n5_2 = {
            block: "val_b2",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n5")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n1"))
            // === view 0 ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))
            .then(on_proposal("n3", proposal_from_n0))
            .then(on_proposal("n4", proposal_from_n0))
            // n0-n4 notarize 0 and move to view 1
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))
            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                unchanged_all,
            })

            // === view 1 ===
            // n5 proposes two blocks
            .then(inject_proposal(proposal_from_n5_1))
            .then(inject_proposal(proposal_from_n5_2))

            // n0, n1, n2 notarize proposal n5-1
            .then(on_proposal("n0", proposal_from_n5_1))
            .then(on_proposal("n1", proposal_from_n5_1))
            .then(on_proposal("n2", proposal_from_n5_1))

            // n3, n4, n5 notarize proposal n5-2
            .then(on_proposal("n3", proposal_from_n5_2))
            .then(on_proposal("n4", proposal_from_n5_2))
            .then(inject_vote({ view: proposal_from_n5_2.view, sig: sig_of("n5"), kind: NotarizeKind, block: proposal_from_n5_2.block }))

            .expect(all_invariants)

            // n0-n2 receive 2 votes each for b0
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, "n1"))


            .then(replica_receives_notarize_vote("n1", "val_b0", 1, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, "n1"))


            .then(replica_receives_notarize_vote("n2", "val_b0", 1, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, "n1"))


            // n0 receives 2 other votes for b1 and 1 nullify
            .then(replica_receives_nullify_vote("n0", 1, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n5"))

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n0").nullified == false),
                assert(is_contradicted(replica_state.get("n0"), 1, store_vote.get("n0")) == true),
                unchanged_all,
            })

            .then(on_nullify_by_contradiction("n0", 1))
            .expect(all_invariants)

            .then(all {
                assert(store_vote.get("n0").filter(v=>v.view==1).size() == 5),
                assert(replica_state.get("n0").nullified == true),
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
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
    }

    action inject_vote(vote: Vote): bool = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote.union(Set(vote)),
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
    }

     action replica_receives_notarize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_notarize(id, view, block,  Set(notarize(view, src, block)))

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: str): bool =
        on_vote_nullify(id, view, Set(nullify(view, src)))

    action unchanged_all = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
    }
}
