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
        }
        val cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(on_certificate("n3", cert))
            .then(all {
                assert(store_certificates.get("n3").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b1"))),
                assert(sent_finalize_votes.exists(v => v.sig == "n3" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b1")),
                assert(replica_state.get("n3").certified.get(FIRST_VIEW) == Some("val_b1")),
                assert(replica_state.get("n3").view == 2),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run timeoutBroadcastsNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(on_timeout("n2"))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW)),
                assert(replica_state.get("n2").broadcast_nullify == true),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run invalidParentNotarizationCertificateDoesNotTriggerFinalizeTest = {
        val bad_proposal = {
            payload: "val_b1",
            view: 2,
            parent: 2,
        }
        val bad_cert = notarization(bad_proposal, Set("n0", "n1", "n4"), "n4")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(on_certificate("n3", bad_cert))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_notarization_cert(c)
                        and cert_proposal(c) == Some(bad_proposal)
                )),
                assert(not(sent_finalize_votes.exists(v =>
                    v.sig == "n3" and v.proposal == bad_proposal
                ))),
                assert(replica_state.get("n3").certified.get(2) == None),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    action send_proposal(sender: Signature, proposal: Proposal): bool = all {
        sent_proposal' = sent_proposal.union(Set((sender, proposal))),
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_proposal",
    }

    action replica_receives_notarize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent }
        on_notarize(id, { proposal: p, sig: src })
    }

    action replica_receives_finalize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent }
        on_finalize(id, Set({ proposal: p, sig: src }))
    }

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: ReplicaId): bool =
        on_nullify(id, view, Set({ view: view, sig: src }))

    action unchanged_all = all {
        sent_proposal' = sent_proposal,
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = lastAction,
    }
}
