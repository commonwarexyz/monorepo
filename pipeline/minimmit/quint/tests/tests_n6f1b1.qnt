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

    // Regression test for the "commit skips its ancestors" defect.
    //
    // A replica enters the next view as soon as it sees M notarize votes, but it only
    // commits once it sees L of them. When `ghost_committed_blocks` was accumulated by
    // appending `cert.block`, a replica that saw view 0 as a notarization and then
    // finalized view 1 recorded ["val_b1"] while a peer that finalized view 0 recorded
    // ["val_b0"] -- two sequences of equal length differing at index 0, so `agreement`
    // failed. Now the chain is rebuilt from the stored certificates by walking forward
    // from genesis, so n3 cannot reach val_b1 without finalization(val_b0, 0) and
    // commits nothing instead.
    run agreementViolationTest = {
        pure val proposal_from_n0 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        pure val proposal_from_n1 = {
            block: "val_b1",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n1")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3", 4 -> "n4", 5 -> "n0"))
            // === view 0 ===
            // n0 proposes, n1 and n2 notarize it: a sub-quorum of M = 3 votes.
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))

            // n3 and n4 only ever see that sub-quorum. They assemble a notarization,
            // vote for it themselves, and enter view 1 without finalizing anything.
            .then(replica_receives_notarize_votes("n3", "val_b0", 0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n4", "val_b0", 0, Set("n0", "n1", "n2")))
            .then(all {
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n3").last_finalized == GENESIS_VIEW),
                assert(ghost_committed_blocks.get("n3") == List()),
                unchanged_all,
            })

            // n0 sees all L = 5 votes, finalizes view 0 and commits val_b0.
            .then(replica_receives_notarize_votes("n0", "val_b0", 0, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(ghost_committed_blocks.get("n0") == List("val_b0")),
                unchanged_all,
            })

            // n1 and n2 also advance on the sub-quorum only, so they never commit view 0.
            .then(replica_receives_notarize_votes("n1", "val_b0", 0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n2", "val_b0", 0, Set("n0", "n1", "n2")))

            // === view 1 ===
            // n1 proposes on top of the view-0 notarization, and all of n0-n4 notarize.
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .then(on_proposal("n3", proposal_from_n1))
            .then(on_proposal("n4", proposal_from_n1))
            .then(replica_receives_notarize_votes("n0", "val_b1", 1, Set("n1", "n3", "n4")))
            .then(on_proposal("n2", proposal_from_n1))

            // n3 sees all L = 5 votes for view 1 and finalizes it, but it holds only
            // notarization(val_b0, 0), so the walk from genesis cannot reach val_b1.
            .then(replica_receives_notarize_votes("n3", "val_b1", 1, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                assert(replica_state.get("n3").last_finalized == 1),
                assert(ghost_committed_blocks.get("n0") == List("val_b0")),
                assert(ghost_committed_blocks.get("n3") == List()),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Regression test for the "out-of-order commit at the top view" defect.
    //
    // `enter_new_view` gates all of its bookkeeping -- including the `last_finalized`
    // update -- behind `VIEWS.contains(cert.view + 1)`, so for a certificate on the top
    // view (8 here) the whole function is a no-op and `last_finalized` is never advanced.
    // When the commit was an append guarded by `cert.view > self.last_finalized`, that
    // stale watermark let n4 record view 8's block and then view 0's block after it.
    // The rebuilt chain does not consult `last_finalized` at all and derives its order
    // from parent links, so the defect can no longer reach `ghost_committed_blocks`.
    // (The stale watermark is still worth fixing on its own account: it also feeds
    // `on_proposal`'s `proposal.view_parent >= self.last_finalized` guard.)
    run outOfOrderCommitTest = {
        pure val proposal_from_n0 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        // view 8 is the top of VIEWS = 0.to(8)
        pure val proposal_at_top_view = {
            block: "val_b1",
            view: 8,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n0")
        }
        // assembled by n0 on the last rung of the nullification ladder
        pure val nullification_7 = {
            view: 7,
            block: DUMMY_BLOCK,
            signatures: Set("n0", "n1", "n5"),
            ghost_sender: "n0",
            kind: NullificationKind
        }
        // assembled and broadcast by n4 when it finalizes view 0, after view 8
        pure val finalization_0 = {
            view: 0,
            block: "val_b0",
            signatures: Set("n0", "n1", "n2", "n3", "n4"),
            ghost_sender: "n4",
            kind: FinalizationKind
        }

        // n5 leads views 1-7 and never proposes, so those views time out.
        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n5", 3 -> "n5", 4 -> "n5",
                           5 -> "n5", 6 -> "n5", 7 -> "n5", 8 -> "n0"))
            // === view 0: notarized by all of n0-n4, but nobody finalizes it yet ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))
            .then(on_proposal("n3", proposal_from_n0))
            .then(on_proposal("n4", proposal_from_n0))
            // n0 and n1 see only a sub-quorum of M = 3 votes, so they assemble a
            // notarization and enter view 1 without committing anything.
            .then(replica_receives_notarize_votes("n0", "val_b0", 0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n1", "val_b0", 0, Set("n0", "n1", "n2")))

            // === views 1-7 are nullified, walking n0 and n1 up to the top view ===
            .then(walkers_nullify_view(1))
            .then(walkers_nullify_view(2))
            .then(walkers_nullify_view(3))
            .then(walkers_nullify_view(4))
            .then(walkers_nullify_view(5))
            .then(walkers_nullify_view(6))
            .then(walkers_nullify_view(7))
            .then(all {
                assert(replica_state.get("n0").view == 8),
                assert(replica_state.get("n1").view == 8),
                assert(ghost_committed_blocks.get("n0") == List()),
                unchanged_all,
            })

            // === view 8, the top of VIEWS ===
            // n2, n3 and n4 jump straight from view 0 to view 8 on nullification(7).
            .then(on_certificate("n2", nullification_7))
            .then(on_certificate("n3", nullification_7))
            .then(on_certificate("n4", nullification_7))
            .then(proposer_step("n0", "val_b1", "val_b0", 0))
            .then(on_proposal("n1", proposal_at_top_view))
            .then(inject_vote(notarize(8, sig_of("n5"), "val_b1")))
            // n2 and n3 vote for the block on seeing notarization(val_b1, 8)
            .then(replica_receives_notarize_votes("n2", "val_b1", 8, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n3", "val_b1", 8, Set("n0", "n1", "n5")))

            // n4 sees all L = 5 votes and finalizes view 8. `enter_new_view` bails out
            // because view 9 is not in VIEWS, so n4.last_finalized is NOT advanced.
            .then(replica_receives_notarize_votes("n4", "val_b1", 8, Set("n0", "n1", "n5", "n2", "n3")))
            .then(all {
                // val_b1's parent is view 0, which n4 has not finalized, so the walk
                // from genesis cannot reach it and n4 commits nothing yet.
                assert(ghost_committed_blocks.get("n4") == List()),
                assert(replica_state.get("n4").last_finalized == GENESIS_VIEW),
                unchanged_all,
            })

            // n4 now finalizes the *earlier* view 0. The chain is rebuilt from scratch,
            // so val_b0 lands first; val_b1 still cannot follow it, because n4 is missing
            // nullifications for views 1-6 and the gap (0, 8) is not covered.
            .then(replica_receives_notarize_votes("n4", "val_b0", 0, Set("n0", "n1", "n2", "n3", "n4")))
            // n0 picks up that finalization certificate and commits val_b0 too.
            .then(on_certificate("n0", finalization_0))
            .then(all {
                assert(ghost_committed_blocks.get("n4") == List("val_b0")),
                assert(ghost_committed_blocks.get("n0") == List("val_b0")),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // One rung of the nullification ladder: the two walkers n0 and n1 time out, the
    // byzantine replica contributes the third nullify vote, and both walkers assemble
    // nullification(v) and enter view v + 1.
    action walkers_nullify_view(view: ViewNumber): bool =
        on_timer_expired("n0")
            .then(on_timer_expired("n1"))
            .then(inject_vote(nullify(view, sig_of("n5"))))
            .then(replica_receives_nullify_votes("n0", view, Set("n0", "n1", "n5")))
            .then(replica_receives_nullify_votes("n1", view, Set("n0", "n1", "n5")))

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

    action replica_receives_notarize_votes(id: ReplicaId, block: Block, view: ViewNumber, srcs: Set[ReplicaId]): bool =
        on_vote_notarize(id, view, block, srcs.map(src => notarize(view, src, block)))

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: str): bool =
        on_vote_nullify(id, view, Set(nullify(view, src)))

    action replica_receives_nullify_votes(id: ReplicaId, view: ViewNumber, srcs: Set[ReplicaId]): bool =
        on_vote_nullify(id, view, srcs.map(src => nullify(view, src)))

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
