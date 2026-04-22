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
        INVALID_PAYLOADS = Set("inv_b3"),
        ACTIVITY_TIMEOUT = 10
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    // This test injects an invalid leader vote directly to replicas. The
    // honest `propose` action only models successful proposals by correct
    // leaders, so invalid payloads must be introduced through `on_notarize`
    // helpers instead.
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
            // Deliver the leader's invalid notarize vote to each correct
            // replica, including the leader itself.
            .then(send_notarize_vote({ proposal: invalid_proposal, sig: "n2" }))
            .then(replica_receives_notarize_vote("n2", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n0", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW)),
                assert(sent_nullify_votes.exists(v => v.sig == "n1" and v.view == FIRST_VIEW)),
                assert(not(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW))),
                assert(broadcast_nullify("n0", FIRST_VIEW)),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n3" }))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n3"))
            .then(all {
                assert(store_certificates.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 2),
                unchanged_all,
            })
            .expect(test_invariants)
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
            .then(send_certificate(cert))
            .then(on_certificate("n2", cert))
            .then(all {
                assert(store_certificates.get("n2").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b0"))),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n2").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n2").length() == 1),
                assert(ghost_committed_blocks.get("n2")[0] == proposal),
                unchanged_all,
            })
            .expect(test_invariants)
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
            .then(send_notarize_vote({ proposal: proposal_a, sig: "n3" }))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, 1, "n3"))

            // A recovered notarization for a conflicting proposal teaches n0
            // that the leader equivocated in view 2.
            .then(send_certificate(notarization(proposal_b, Set("n0", "n1", "n3"), "n3")))
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
                // Certification succeeds (CERTIFY_ALL_TRUE) so n0 advances
                // to view 3, but equivocation blocks the finalize vote.
                assert(replica_state.get("n0").view == 3),
                assert(not(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == 2))),
                unchanged_all,
            })
            .expect(test_invariants)
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
            .then(send_notarize_vote({ proposal: proposal_b, sig: "n3" }))
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
            .expect(test_invariants)
    }

    run leaderProposalConflictIsStickyTest = {
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
            payload: "val_b2",
            view: 2,
            parent: 1,
        }
        val conflicting_cert_1 = notarization(proposal_b, Set("n0", "n1", "n3"), "n3")
        val conflicting_cert_2 = notarization(proposal_b, Set("n0", "n2", "n3"), "n3")

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n1", 2 -> "n3", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n1", proposal_1.payload, proposal_1.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(send_notarize_vote({ proposal: proposal_a, sig: "n3" }))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n3"))
            .then(send_certificate(conflicting_cert_1))
            .then(send_certificate(conflicting_cert_2))
            .then(on_certificate("n0", conflicting_cert_1))
            .then(on_certificate("n0", conflicting_cert_2))
            .then(all {
                // Certification succeeds but equivocation blocks finalize,
                // so replica advances to view 3 via enter_view.
                assert(replica_state.get("n0").view == 3),
                assert(not(sent_finalize_votes.exists(v =>
                    v.sig == "n0" and v.proposal.view == 2
                ))),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // When certification fails on notarization, the replica sends a nullify
    // vote but does NOT advance to the next view (no enter_view).
    //
    // PR #3543 adds a local auto-certify shortcut for locally built proposals,
    // which would mask a certify_policy rejection if the replica were the
    // leader. This test must therefore use a non-local proposal from the
    // rejecting replica's perspective: n1 is the leader of view 1 and
    // proposes; n0 only observes, so `locally_built["n0"][1] == false` and
    // the shortcut does not fire. n0's restrictive `CERTIFY_NO_FALSE` policy
    // then determines the outcome, exercising the original
    // certification-failure path.
    run certificationFailureDoesNotAdvanceViewTest = {
        val proposal_1 = {
            payload: "val_b0",
            view: 1,
            parent: GENESIS_VIEW,
        }
        // n0 rejects all payloads; other replicas certify normally.
        val CERTIFY_NO_FALSE = Replicas.mapBy(r =>
            if (r == "n0") Set()
            else app::certify_always_true
        )

        initWithLeaderAndCertify(
            // Leader of view 1 is n1, not n0, so the view-1 proposal is
            // non-local from n0's perspective.
            Map(0 -> "n2", 1 -> "n1", 2 -> "n0", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_NO_FALSE
        )
            .then(propose("n1", proposal_1.payload, proposal_1.parent))
            // n0 and n2 process the leader vote, casting their own notarize votes.
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            // n0 collects the remaining vote; the third vote forms the
            // notarization quorum and triggers notarize_effect on n0.
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(all {
                // Non-local on n0: shortcut must not apply.
                assert(replica_state.get("n0").locally_built.get(1) == false),
                // Certification failed: replica stays in view 1.
                assert(replica_state.get("n0").view == 1),
                // Nullify vote was sent.
                assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == 1)),
                // No finalize vote was sent.
                assert(not(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == 1))),
                // Certification recorded as failed.
                assert(replica_state.get("n0").certified.get(1) == Some(false)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run conflictingNotarizationCertificateIsNotDuplicateTest = {
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
            payload: "val_b2",
            view: 2,
            parent: 1,
        }
        val conflicting_cert = notarization(proposal_b, Set("n0", "n2", "n3"), "n3")

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n1", 2 -> "n3", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n1", proposal_1.payload, proposal_1.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 1, GENESIS_VIEW, "n2"))
            .then(send_notarize_vote({ proposal: proposal_a, sig: "n3" }))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, 1, "n1"))
            .then(send_certificate(conflicting_cert))
            .then(on_certificate("n0", conflicting_cert))
            .then(all {
                assert(replica_state.get("n0").leader_proposal_conflicted.get(2) == true),
                assert(replica_state.get("n0").leader_proposal.get(2) == Some(proposal_a)),
                assert(store_certificates.get("n0").filter(c =>
                    is_notarization_cert(c) and cert_view(c) == 2
                ).size() == 1),
                assert(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_proposal(c) == Some(proposal_a)
                )),
                assert(not(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_proposal(c) == Some(proposal_b)
                ))),
                unchanged_all,
            })
            .expect(test_invariants)
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
            .then(propose("n0", proposal_1.payload, proposal_1.parent))
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
            .then(send_certificate(notarization_a))
            .then(on_certificate("n0", notarization_a))
            .then(on_certificate("n1", notarization_a))
            .then(send_finalize_vote({ proposal: proposal_a, sig: "n1" }))
            .then(send_finalize_vote({ proposal: { payload: "val_b1", view: 2, parent: GENESIS_VIEW }, sig: "n3" }))
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
            .expect(test_invariants)
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
            .then(send_notarize_vote({ proposal: { payload: "val_b1", view: 2, parent: GENESIS_VIEW }, sig: "n3" }))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, GENESIS_VIEW, "n3"))
            .then(send_finalize_vote({ proposal: { payload: "val_b1", view: 2, parent: GENESIS_VIEW }, sig: "n3" }))
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
            .expect(test_invariants)
    }

    action send_proposal(sender: Signature, proposal: Proposal): bool = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_proposal",
    }

    action send_notarize_vote(vote: NotarizeVote): bool = all {
        sent_notarize_votes' = sent_notarize_votes.union(Set(vote)),
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = CORRECT.mapBy(id =>
            if (sig_of(id) == vote.sig) {
                record_local_proposal(replica_state.get(id), vote.proposal)
            } else {
                replica_state.get(id)
            }
        ),
        certify_policy' = certify_policy,
        lastAction' = "inject_vote",
    }

    action send_finalize_vote(vote: FinalizeVote): bool = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes.union(Set(vote)),
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_vote",
    }

    action send_nullify_vote(vote: NullifyVote): bool = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes.union(Set(vote)),
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_vote",
    }

    action send_certificate(cert: Certificate): bool = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates.union(Set(cert)),
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = CORRECT.mapBy(id =>
            if (sig_of(id) == cert_ghost_sender(cert)) {
                store_certificates.get(id).union(Set(cert))
            } else {
                store_certificates.get(id)
            }
        ),
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_cert",
    }

    action replica_receives_notarize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent }
        on_notarize(id, { proposal: p, sig: src })
    }

    action replica_receives_finalize_vote(id: ReplicaId, payload: Payload, view: ViewNumber, parent: ViewNumber, src: ReplicaId): bool = {
        val p: Proposal = { payload: payload, view: view, parent: parent }
        on_finalize(id, { proposal: p, sig: src })
    }

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: ReplicaId): bool =
        on_nullify(id, { view: view, sig: src })

    action unchanged_all = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates,
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = lastAction,
    }
}
