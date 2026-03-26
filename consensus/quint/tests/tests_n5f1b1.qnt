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
        Q = 3,
        VIEWS = 1.to(6),
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_PAYLOADS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    run notarizationCertificateTriggersFinalizeTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
            sig: sig_of("n4")
        }
        val cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(proposal))
            .then(on_proposal("n0", proposal))
            .then(on_proposal("n1", proposal))
            .then(on_proposal("n2", proposal))
            .then(on_proposal("n3", proposal))
            .then(on_certificate("n3", cert))
            .then(all {
                assert(store_certificate.get("n3").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b1"))),
                assert(sent_vote.exists(v => vote_sig(v) == "n3" and vote_view(v) == FIRST_VIEW and is_finalize(v) and vote_payload(v) == Some("val_b1"))),
                assert(replica_state.get("n3").certified.get(FIRST_VIEW) == Some("val_b1")),
                assert(replica_state.get("n3").view == 2),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run timeoutBroadcastsNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
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
        lastAction' = "inject_proposal",
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
        lastAction' = "inject_vote",
    }

    action replica_receives_notarize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent, sig: sig_of(src) }
        on_vote_notarize(id, view, payload, Set(notarize(p, src)))
    }

    action replica_receives_finalize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent, sig: sig_of(src) }
        on_vote_finalize(id, view, payload, Set(finalize(p, src)))
    }

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
        lastAction' = lastAction,
    }
}
