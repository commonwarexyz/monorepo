module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import replica(
        CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        BYZANTINE = Set("n6"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5", "n6"->"n6"),
        N = 7,
        F = 1,
        VIEWS = 0.to(2),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    run asuumptionsValidTest = all {
        L == 6,
        M == 3,
        assumptions_valid
    }

    // This test reproduces the conditions for the following attack in the case of N = 7, F = 1, M = N-3*F=4, L = N - F=6. 
    // Note, that we use M = 2*F + 1 = 3. So this attack should not be possible, and this test checks exactly that.
    
    // Byzantine leader proposes block B to 3 honest replicas n0-n2,
    // and a conflicting block B' to the other 3 honest replicas n3-n6.
    //
    // All honest replicas receive a proposal before their timer expires,
    // so everyone notarizes something.
    //
    // Every honest replica has seen all 6 honest notarization votes,
    // split 3 vs 3.
    //
    // For any honest replica in the 3-group:
    // - Sees 3 votes for its own block (still < M = 4, so no notarization).
    // - Sees 3 conflicting votes (still < M = 4, so no “nullify by contradiction”).
    //
    //
    // The single Byzantine node stays silent.
    //
    // The result:
    // - No group reaches M=4 votes for any block.
    // - No one sees M=4 conflicting votes.
    // - Anyone who notarized is forbidden to nullify by timeout.
    //
    // ⇒ No proof(v) can be produced → progress stalls indefinitely.
    // ⇒ So M = 4 can break liveness.

    run livenessTest = {
        pure val proposal_from_n6_1 = { 
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n6")
        }
        pure val proposal_from_n6_2 = { 
            block: "val_b1",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n6")
        }

        initWithLeader(Map(0 -> "n6", 1 -> "n6", 2 -> "n6", 3 -> "n6", 4 -> "n6", 5 -> "n6"))
            // === view 0 ===
            
            // A faulty replica equivocates:
            .then(inject_proposal(proposal_from_n6_1))
            .then(inject_proposal(proposal_from_n6_2))

            // Partition 1 receives the proposal 1
            .then(on_proposal("n0", proposal_from_n6_1))
            .then(on_proposal("n1", proposal_from_n6_1))
            .then(on_proposal("n2", proposal_from_n6_1))

            // Partition 2 receives the proposal 1
            .then(on_proposal("n3", proposal_from_n6_2))
            .then(on_proposal("n4", proposal_from_n6_2))
            .then(on_proposal("n5", proposal_from_n6_2))
            
            
            // n0-n2 notarize 0 and move to view 1
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n3", "val_b1", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 0, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 0, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b1", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 0, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b1", 0, "n3"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 0, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 0, "n5"))

            
            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })

            .then(all {
                assert(store_vote.get("n0").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block == "val_b0").size() == 3),
                assert(store_vote.get("n3").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block == "val_b1").size() == 3),
                assert(store_vote.get("n0").filter(v=>v.view==0 and v.kind==NullifyKind).size() == 0),
                assert(replica_state.get("n0").nullified == false),
                assert(replica_state.get("n3").nullified == false),
                assert(replica_state.get("n0").notarized.get(0) == "val_b0"),
                assert(replica_state.get("n3").notarized.get(0) == "val_b1"),
                assert(is_contradicted(replica_state.get("n0"), 0, store_vote.get("n0")) == false),
                assert(is_contradicted(replica_state.get("n3"), 0, store_vote.get("n3")) == false),
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
