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
        CORRECT = Set("n0", "n1", "n2"),
        BYZANTINE = Set("n3"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 1.to(6),
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_PAYLOADS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    run invalidLeaderProposalTriggersNullifyTest = {
        val invalid_proposal = {
            payload: "inv_b3",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n2", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n2", invalid_proposal.payload, invalid_proposal.parent))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW)),
                assert(replica_state.get("n0").nullified == true),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificates.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run finalizationCertificateAdvancesViewTest = {
        val proposal = {
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }
        // Cert assembled by n0 from finalize votes of n0, n1, and n3 (byzantine).
        val cert = finalization(proposal, Set("n0", "n1", "n3"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n0", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            // n0 sees notarize quorum -> notarization, certifies, sends finalize
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            // n1 sees notarize quorum -> notarization, certifies, sends finalize
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))
            // n3 (byzantine) also sent a finalize vote
            .then(send_finalize_vote({ proposal: proposal, sig: "n3" }))
            // n2 receives finalization cert from network (has not seen notarize quorum)
            .then(on_certificate("n2", cert))
            .then(all {
                assert(store_certificates.get("n2").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b0"))),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n2").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n2").length() == 1),
                assert(ghost_committed_blocks.get("n2")[0] == "val_b0"),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Byzantine n3 (leader) equivocates with two proposals having different parents.
    // A conflicting recovered certificate teaches the replica the equivocation.
    // This does NOT immediately trigger a nullify vote upon notarization.
    // Finalization is blocked by equivocation; the certification timeout handles nullification.
    run parentConflictDoesNotImmediatelyNullifyTest = {
        // Byzantine n3 sends two proposals: same (view, payload) but different parents.
        val proposal_1 = {
            payload: "val_b0",
            view: 1,
            parent: GENESIS_VIEW,
        }
        val proposal_a = {
            payload: "val_b1",
            view: 2,
            parent: 1,
        }
        val proposal_b = {
            payload: "val_b1",
            view: 2,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n1", 2 -> "n3", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(send_proposal("n1", proposal_1))
            .then(propose("n1", proposal_1.payload, proposal_1.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW,  "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW,  "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW,  "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW,  "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW,  "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))

            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW,  "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW,  "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))

            // All correct replicas see proposal A and notarize.
            .then(send_proposal("n3", proposal_a))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, 1, "n3"))

            // A recovered notarization for a conflicting proposal teaches n0
            // that the leader equivocated in view 2.
            .then(on_certificate("n0", notarization(proposal_b, Set("n0", "n1", "n3"), "n3")))

            // Byzantine n3 also sent a notarize vote.
            .then(send_notarize_vote({ proposal: proposal_a, sig: "n3" }))

            // n0 receives notarize quorum (n0, n1, n3) -> notarization forms.
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n1"))

            .then(all {
                assert(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_view(c) == 2
                    and cert_payload(c) == Some("val_b1"))),
                assert(replica_state.get("n0").leader_proposal.get(2) == Some(proposal_a)
                    or replica_state.get("n0").leader_proposal.get(2) == Some(proposal_b)),
                // n0 is still in the current view (waiting for timeout).
                assert(replica_state.get("n0").view == 2),
                assert(not(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == 2))),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run mixedParentNotarizeVotesDoNotFormCertificateTest = {
        val proposal_1 = {
            payload: "val_b0",
            view: 1,
            parent: GENESIS_VIEW,
        }
        val proposal_a = {
            payload: "val_b1",
            view: 2,
            parent: 1,
        }
        val proposal_b = {
            payload: "val_b1",
            view: 2,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n0", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n0", proposal_1.payload, proposal_1.parent))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(all {
                assert(replica_state.get("n0").view == 2),
                assert(replica_state.get("n0").last_finalized == 1),
                unchanged_all,
            })
            .then(propose("n0", proposal_a.payload, proposal_a.parent))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, 1, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, GENESIS_VIEW, "n3"))
            .then(all {
                assert(not(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_proposal(c) == Some(proposal_a)
                ))),
                assert(not(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_proposal(c) == Some(proposal_b)
                ))),
                assert(not(sent_finalize_votes.exists(v =>
                    v.sig == "n0" and v.proposal == proposal_a
                ))),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run mixedParentFinalizeVotesDoNotFormCertificateTest = {
        val proposal_1 = {
            payload: "val_b0",
            view: 1,
            parent: GENESIS_VIEW,
        }
        val proposal_a = {
            payload: "val_b1",
            view: 2,
            parent: 1,
        }
        val proposal_b = {
            payload: "val_b1",
            view: 2,
            parent: GENESIS_VIEW,
        }
        val notarization_a = notarization(proposal_a, Set("n0", "n1", "n3"), "n1")

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n0", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(send_proposal("n0", proposal_1))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(propose("n0", proposal_a.payload, proposal_a.parent))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, 1, "n0"))
            .then(send_notarize_vote({ proposal: proposal_a, sig: "n3" }))
            .then(on_certificate("n0", notarization_a))
            .then(on_certificate("n1", notarization_a))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, 1, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, GENESIS_VIEW, "n3"))
            .then(all {
                assert(not(store_certificates.get("n0").exists(c =>
                    is_finalization_cert(c) and cert_proposal(c) == Some(proposal_a)
                ))),
                assert(not(store_certificates.get("n0").exists(c =>
                    is_finalization_cert(c) and cert_proposal(c) == Some(proposal_b)
                ))),
                assert(replica_state.get("n0").last_finalized == 1),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run leaderProposalFiltersConflictingVotesTest = {
        val proposal_1 = {
            payload: "val_b0",
            view: 1,
            parent: GENESIS_VIEW,
        }
        val proposal_a = {
            payload: "val_b1",
            view: 2,
            parent: 1,
        }
        val proposal_b = {
            payload: "val_b1",
            view: 2,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n0", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n0", proposal_1.payload, proposal_1.parent))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(all {
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            .then(propose("n0", proposal_a.payload, proposal_a.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, GENESIS_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, GENESIS_VIEW, "n3"))
            .then(all {
                assert(replica_state.get("n0").leader_proposal.get(2) == Some(proposal_a)),
                assert(not(store_notarize_votes.get("n0").exists(v =>
                    v.sig == "n3" and v.proposal == proposal_b
                ))),
                assert(not(store_finalize_votes.get("n0").exists(v =>
                    v.sig == "n3" and v.proposal == proposal_b
                ))),
                unchanged_all,
            })
            .expect(all_invariants)
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

    action send_notarize_vote(vote: NotarizeVote): bool = all {
        sent_proposal' = sent_proposal,
        sent_notarize_votes' = sent_notarize_votes.union(Set(vote)),
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
        lastAction' = "inject_vote",
    }

    action send_finalize_vote(vote: FinalizeVote): bool = all {
        sent_proposal' = sent_proposal,
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes.union(Set(vote)),
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
        lastAction' = "inject_vote",
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
