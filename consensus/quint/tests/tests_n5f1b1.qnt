module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import automaton(
        CERTIFY_DOMAIN = Set("val_b0", "val_b1", "val_b2", "inv_b3"),
    ) as app from "../automaton"
    import replica(
        CORRECT = Set("n0", "n1", "n2", "n3"),
        BYZANTINE = Set("n4"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4"->"n4"),
        N = 5,
        F = 1,
        VIEWS = 0.to(6),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    run notarizationCertificateTriggersFinalizeTest = {
        val cert = notarization(FIRST_VIEW, "val_b1", Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 4 -> "n3", 5 -> "n0", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(on_certificate("n3", cert))
            .then(all {
                assert(store_certificate.get("n3").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == "val_b1")),
                assert(sent_vote.exists(v => vote_sig(v) == "n3" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_block(v) == "val_b1")),
                assert(replica_state.get("n3").certified.get(FIRST_VIEW) == "val_b1"),
                assert(replica_state.get("n3").view == 2),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run timeoutBroadcastsNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3"),
            CERTIFY_ALL_TRUE
        )
            .then(on_timeout("n2"))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n2" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(replica_state.get("n2").nullified == true),
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
