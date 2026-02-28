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
        CORRECT = Set("n0", "n1", "n2"),
        BYZANTINE = Set("n3"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 0.to(6),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    run invalidLeaderProposalTriggersNullifyTest = {
        val invalid_proposal = {
            block: "inv_b3",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n3")
        }

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n3", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(invalid_proposal))
            .then(on_proposal("n0", invalid_proposal))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(replica_state.get("n0").nullified == true),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run finalizationCertificateAdvancesViewTest = {
        val cert = finalization(FIRST_VIEW, "val_b0", Set("n0", "n1", "n2"), "n2")

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n1", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(on_certificate("n2", cert))
            .then(all {
                assert(store_certificate.get("n2").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "val_b0")),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n2").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n2").length() == 1),
                assert(ghost_committed_blocks.get("n2")[0] == "val_b0"),
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
        certify_policy' = certify_policy,
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
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
    }
}
