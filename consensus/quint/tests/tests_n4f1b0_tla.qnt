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
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2", "val_b3_part"),
        INVALID_PAYLOADS = Set("inv_b3"),
        ACTIVITY_TIMEOUT = 10
    ).* from "../replica_tla"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)
    pure val CERTIFY_FAIL_INV_B3_BLOCK = Set(GENESIS_PAYLOAD, "val_b0", "val_b1", "val_b2")
    pure val CERTIFY_FAIL_INV_B3 = Replicas.mapBy(_ => CERTIFY_FAIL_INV_B3_BLOCK)

    run initTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
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
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(propose("n0", proposal.payload, proposal.parent))
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))

        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))

        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))

        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))
        .then(all {
            assert(store_certificates.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b0"))),
            assert(store_certificates.get("n0").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_proposal(c) == Some(proposal)
            )),
            assert(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(sent_finalize_votes.exists(v => v.sig == "n1" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(sent_finalize_votes.exists(v => v.sig == "n2" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(sent_notarize_votes.exists(v => v.sig == "n0" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(sent_notarize_votes.exists(v => v.sig == "n1" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(sent_notarize_votes.exists(v => v.sig == "n2" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(replica_state.get("n0").view == 2),
            unchanged_all,
        })

        .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n0"))
        .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
        .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))
        .then(all {
            assert(store_certificates.get("n0").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b0"))),
            assert(store_certificates.get("n0").exists(c =>
                is_finalization_cert(c) and cert_view(c) == FIRST_VIEW and cert_proposal(c) == Some(proposal)
            )),
            assert(replica_state.get("n0").last_finalized == FIRST_VIEW),
            assert(ghost_committed_blocks.get("n0").length() == 1),
            assert(ghost_committed_blocks.get("n0")[0] == proposal),
            unchanged_all,
        })
    }

    run certificationAlwaysTrueTriggersFinalizeTest = {

        val proposal = {
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(propose("n0", proposal.payload, proposal.parent))
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))

        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n1"))
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW,  "n2"))
        .then(all {
            assert(store_certificates.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b0"))),
            assert(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b0")),
            assert(not(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW))),
            assert(replica_state.get("n0").view == 2),
            unchanged_all,
        })
    }

    run leaderNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n0" }))
        .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n0"))
        .then(all {
            assert(store_nullify_votes.get("n1").exists(v => v.sig == "n0" and v.view == FIRST_VIEW)),
            assert(sent_nullify_votes.exists(v => v.sig == "n1" and v.view == FIRST_VIEW)),
            assert(broadcast_nullify("n1", FIRST_VIEW)),
            assert(replica_state.get("n1").leader_timeout.get(FIRST_VIEW) == Some(true)),
            assert(replica_state.get("n1").certification_timeout.get(FIRST_VIEW) == Some(true)),
            assert(replica_state.get("n1").view == FIRST_VIEW),
            unchanged_all,
        })
    }

    // This test documents the current abstraction boundary of `propose`.
    // The model includes only the successful leader proposal path; it does
    // not model the "valid parent but propose(v, parent) = None" branch.
    // At FIRST_VIEW, choosing FIRST_VIEW itself as parent is invalid, so
    // the leader must neither emit a proposal nor nullify as a stand-in for
    // local proposal failure.
    run localProposalFailureTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(all {
            assert(is_none(parent_payload(replica_state.get("n0"), FIRST_VIEW, FIRST_VIEW, store_certificates.get("n0")))),
            assert(parent_payload(replica_state.get("n0"), FIRST_VIEW, GENESIS_VIEW, store_certificates.get("n0")) == Some(GENESIS_PAYLOAD)),
            assert(not(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW))),
            assert(not(broadcast_nullify("n0", FIRST_VIEW))),
            assert(replica_state.get("n0").leader_timeout.get(FIRST_VIEW) == Some(false)),
            assert(replica_state.get("n0").certification_timeout.get(FIRST_VIEW) == Some(false)),
            assert(replica_state.get("n0").proposal.get(FIRST_VIEW) == None),
            assert(replica_state.get("n0").view == FIRST_VIEW),
            assert(not(sent_notarize_votes.exists(v => v.sig == "n0" and v.proposal.view == FIRST_VIEW))),
            unchanged_all,
        })
    }

    // This test drives the "notarized but not certified" path.
    // View 1 reaches a notarization certificate for `val_b3_part`, but
    // `CERTIFY_FAIL_INV_B3` rejects that payload for certification, so replicas
    // broadcast nullify instead of finalizing it.
    // After n0 enters view 2 via the nullification certificate, the new leader
    // must not build on the uncertified view-1 block.
    run runCertifyTest = {
        val p = {
            payload: "val_b3_part",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        val vote0 = {
            proposal: p,
            sig: "n0"
        }

        val vote1 = {
            proposal: p,
            sig: "n1"
        }

        val vote2 = {
            proposal: p,
            sig: "n2"
        }

        val vote3 = {
            proposal: p,
            sig: "n3"
        }

        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_FAIL_INV_B3
        )
        .then(propose("n3", p.payload, p.parent))

        // Leader vote triggers proposal processing for each replica
        .then(on_notarize("n0", vote3))
        .then(on_notarize("n1", vote3))
        .then(on_notarize("n2", vote3))
        // Each replica receives 2 more votes to reach Q=3
        .then(on_notarize("n0", vote0))
        .then(on_notarize("n0", vote1))
        .then(on_notarize("n1", vote0))
        .then(on_notarize("n1", vote1))
        .then(on_notarize("n2", vote0))
        .then(on_notarize("n2", vote1))

        // All replicas see notarize quorum; certification fails -> all send nullify.
        .then(all {
            assert(store_certificates.get("n0").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b3_part"))),
            assert(replica_state.get("n0").certified.get(FIRST_VIEW) == Some(false)),
            assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW)),
            assert(sent_nullify_votes.exists(v => v.sig == "n1" and v.view == FIRST_VIEW)),
            assert(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW)),
            assert(not(sent_finalize_votes.exists(v => v.sig == "n0" and v.proposal.view == FIRST_VIEW))),
            assert(replica_state.get("n0").view == FIRST_VIEW),
            unchanged_all,
        })
        // Enter view 2 via nullification certificate for FIRST_VIEW.
        .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
        .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
        .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
        .then(all {
            assert(store_certificates.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
            assert(replica_state.get("n0").view == 2),
            unchanged_all,
        })
        // In view 2, n0 is leader, but FIRST_VIEW was nullified and never
        // certified, so it is not a valid parent anymore. The leader must
        // fall back to the latest valid certified ancestor, which is genesis.
        .then(all {
            assert(replica_state.get("n0").view == 2),
            assert(is_none(parent_payload(replica_state.get("n0"), 2, FIRST_VIEW, store_certificates.get("n0")))),
            assert(parent_payload(replica_state.get("n0"), 2, GENESIS_VIEW, store_certificates.get("n0")) == Some(GENESIS_PAYLOAD)),
            unchanged_all,
        })
        .then(propose("n0", "val_b0", GENESIS_VIEW))
        .then(all {
            assert(sent_notarize_votes.exists(v =>
                v.sig == "n0" and v.proposal.view == 2 and v.proposal.parent == GENESIS_VIEW and v.proposal.payload == "val_b0"
            )),
            assert(not(sent_notarize_votes.exists(v =>
                v.sig == "n0" and v.proposal.view == 2 and v.proposal.parent == FIRST_VIEW
            ))),
            assert(not(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == 2))),
            unchanged_all,
        })
    }

    run localVerificationFailureTest = {
        val invalid_proposal = {
            payload: "inv_b3",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(send_notarize_vote({ proposal: invalid_proposal, sig: "n0" }))
        .then(replica_receives_notarize_vote("n1", "inv_b3", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(all {
            assert(sent_nullify_votes.exists(v => v.sig == "n1" and v.view == FIRST_VIEW)),
            assert(not(sent_notarize_votes.exists(v => v.sig == "n1" and v.proposal.view == FIRST_VIEW))),
            assert(broadcast_nullify("n1", FIRST_VIEW)),
            assert(replica_state.get("n1").leader_timeout.get(FIRST_VIEW) == None),
            assert(replica_state.get("n1").certification_timeout.get(FIRST_VIEW) == None),
            assert(replica_state.get("n1").view == FIRST_VIEW),
            unchanged_all,
        })
    }

    // Receiving a notarization for a past view where certification fails must NOT
        // trigger a backfilled nullify vote. The Rust implementation restricts nullify
        // to the current view only (trigger_timeout and construct_nullify both reject
        // non-current views).
        run noBackfillNullifyForPastViewTest = {
            val proposal = {
                payload: "val_b3_part",
                view: FIRST_VIEW,
                parent: GENESIS_VIEW,
            }
            val cert = notarization(proposal, Set("n0", "n1", "n3"), "n0")

            initWithLeaderAndCertify(
                Map(0 -> "n1", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
                CERTIFY_FAIL_INV_B3
            )
            // View 1: n3 is leader; inject proposal for val_b3_part.
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n3"))

            // n0, n1, n2 form notarization; certification fails -> all send nullify(1).
            .then(replica_receives_notarize_vote("n0", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b3_part", FIRST_VIEW, GENESIS_VIEW, "n1"))

            // n3 (the leader) receives nullify quorum -> nullification cert -> view 2.
            // leader_nullify_trigger does not fire since n3 IS the leader; n3 sends no nullify.
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n2"))
            .then(all {
                assert(replica_state.get("n3").view == 2),
                assert(not(sent_nullify_votes.exists(v => v.sig == "n3" and v.view == FIRST_VIEW))),
                unchanged_all,
            })

            // n3 (now in view 2) receives the notarization cert for view 1.
            // Certification of val_b3_part fails, but n3 must NOT backfill
            // nullify(1) because view 1 is no longer n3's current view.
            .then(send_certificate(cert))
            .then(on_certificate("n3", cert))
            .then(all {
                // n3 stored the notarization for view 1...
                assert(store_certificates.get("n3").exists(c =>
                    is_notarization_cert(c) and cert_view(c) == FIRST_VIEW
                    and cert_payload(c) == Some("val_b3_part"))),
                // ...but did NOT send nullify for the past view.
                assert(not(sent_nullify_votes.exists(v => v.sig == "n3" and v.view == FIRST_VIEW))),
                assert(replica_state.get("n3").view == 2),
                unchanged_all,
            })
        }

        // All correct replicas finalize two consecutive blocks.
        run allCorrectReplicasFinalizeTwoBlocksTest = {
            val proposal1 = {
                payload: "val_b0",
                view: FIRST_VIEW,
                parent: GENESIS_VIEW,
            }
            val proposal2 = {
                payload: "val_b1",
                view: 2,
                parent: FIRST_VIEW,
            }

            initWithLeaderAndCertify(
                Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
                CERTIFY_ALL_TRUE
            )
            // View 1: n0 proposes val_b0 with genesis parent
            .then(propose("n0", proposal1.payload, proposal1.parent))

            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            // All replicas receive notarize quorum -> notarization, send finalize, advance to view 2
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            // All replicas receive finalize quorum -> finalization, commit val_b0
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == proposal1)),
                assert(CORRECT.forall(id => replica_state.get(id).view == 2)),
                unchanged_all,
            })
            // View 2: n1 proposes val_b1 with val_b0 as parent
            .then(propose("n1", proposal2.payload, proposal2.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 2)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == proposal1)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[1] == proposal2)),
                assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 2)),
                unchanged_all,
            })
        }

        // The same payload may be finalized in multiple views; the committed
        // chain should track proposals, not collapse them by payload string.
        run repeatedPayloadAcrossViewsFinalizeTest = {
            val proposal1 = {
                payload: "val_b0",
                view: FIRST_VIEW,
                parent: GENESIS_VIEW,
            }
            val proposal2 = {
                payload: "val_b0",
                view: 2,
                parent: FIRST_VIEW,
            }

            initWithLeaderAndCertify(
                Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
                CERTIFY_ALL_TRUE
            )
            .then(propose("n0", proposal1.payload, proposal1.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(propose("n1", proposal2.payload, proposal2.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, FIRST_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, FIRST_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 2)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == proposal1)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[1] == proposal2)),
                unchanged_all,
            })
        }

        // A later finalization must not appear in the committed chain until
        // the parent proposal is committed and any skipped views are nullified.
        run disconnectedFinalizationWaitsForParentAndNullificationTest = {
            val proposal1 = {
                payload: "val_b0",
                view: FIRST_VIEW,
                parent: GENESIS_VIEW,
            }
            val proposal3 = {
                payload: "val_b1",
                view: 3,
                parent: FIRST_VIEW,
            }
            val finalization1 = finalization(proposal1, Set("n0", "n1", "n2"), "n0")
            val finalization3 = finalization(proposal3, Set("n0", "n1", "n2"), "n0")
            val nullification2 = nullification(2, Set("n0", "n1", "n2"), "n0")

            initWithLeaderAndCertify(
                Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
                CERTIFY_ALL_TRUE
            )
            // n1 learns only the child finalization first, so the committed
            // prefix must stay empty even though last_finalized advances.
            .then(send_certificate(finalization3))
            .then(on_certificate("n1", finalization3))
            .then(all {
                assert(replica_state.get("n1").last_finalized == 3),
                assert(ghost_committed_blocks.get("n1").length() == 0),
                unchanged_all,
            })
            // Another replica that only knows the parent finalization still
            // agrees, because [] is a prefix of [proposal1].
            .then(send_certificate(finalization1))
            .then(on_certificate("n2", finalization1))
            .then(all {
                assert(replica_state.get("n2").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n2").length() == 1),
                assert(ghost_committed_blocks.get("n2")[0] == proposal1),
                unchanged_all,
            })
            // Once n1 learns the parent finalization, view 3 still cannot be
            // committed until view 2 is known nullified.
            .then(on_certificate("n1", finalization1))
            .then(all {
                assert(ghost_committed_blocks.get("n1").length() == 1),
                assert(ghost_committed_blocks.get("n1")[0] == proposal1),
                unchanged_all,
            })
            // Nullification of the skipped view unblocks the connected chain.
            .then(send_certificate(nullification2))
            .then(on_certificate("n1", nullification2))
            .then(all {
                assert(ghost_committed_blocks.get("n1").length() == 2),
                assert(ghost_committed_blocks.get("n1")[0] == proposal1),
                assert(ghost_committed_blocks.get("n1")[1] == proposal3),
                unchanged_all,
            })
        }

        // Views 1 and 2 timeout, then view 3 leader proposes and all replicas finalize.
        run timeoutViewsThenFinalizeTest = {
            val proposal = {
                payload: "val_b0",
                view: 3,
                parent: GENESIS_VIEW,
            }

            initWithLeaderAndCertify(
                Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
                CERTIFY_ALL_TRUE
            )
            // View 1: all replicas timeout
            .then(on_timeout("n0", LeaderTimeoutKind))
            .then(on_timeout("n1", LeaderTimeoutKind))
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(on_timeout("n3", LeaderTimeoutKind))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n2"))
            .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n1"))
            .then(all {
                assert(CORRECT.forall(id => replica_state.get(id).view == 2)),
                unchanged_all,
            })
            // View 2: all replicas timeout
            .then(on_timeout("n0", LeaderTimeoutKind))
            .then(on_timeout("n1", LeaderTimeoutKind))
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(on_timeout("n3", LeaderTimeoutKind))
            .then(replica_receives_nullify_vote("n0", 2, "n1"))
            .then(replica_receives_nullify_vote("n0", 2, "n2"))
            .then(replica_receives_nullify_vote("n1", 2, "n0"))
            .then(replica_receives_nullify_vote("n1", 2, "n2"))
            .then(replica_receives_nullify_vote("n2", 2, "n0"))
            .then(replica_receives_nullify_vote("n2", 2, "n1"))
            .then(replica_receives_nullify_vote("n3", 2, "n0"))
            .then(replica_receives_nullify_vote("n3", 2, "n1"))
            .then(all {
                assert(CORRECT.forall(id => replica_state.get(id).view == 3)),
                unchanged_all,
            })
            // View 3: n2 proposes val_b0 with genesis parent (views 1-2 all nullified)
            .then(propose("n2", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 3, GENESIS_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == proposal)),
                assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 3)),
                unchanged_all,
            })
        }

        // View 1 leader proposes a valid payload with an invalid parent, replicas nullify.
        // View 2 leader proposes correct payload with genesis parent, all replicas finalize.
        run wrongParentNullifyThenCorrectFinalizeTest = {
            val bad_proposal = {
                payload: "val_b0",
                view: 1,
                parent: FIRST_VIEW,
            }
            val correct_proposal = {
                payload: "val_b0",
                view: 2,
                parent: GENESIS_VIEW,
            }

            initWithLeaderAndCertify(
                Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
                CERTIFY_ALL_TRUE
            )
            // View 1: n0 proposes val_b0 with an invalid parent (equal to the proposal view).
            .then(send_notarize_vote({ proposal: bad_proposal, sig: "n0" }))
            .then(replica_receives_notarize_vote("n0", "val_b0", 1, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 1, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 1, FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 1, FIRST_VIEW, "n0"))
            .then(all {
                assert(not(broadcast_nullify("n0", FIRST_VIEW))),
                assert(Set("n1", "n2", "n3").forall(id => broadcast_nullify(id, FIRST_VIEW))),
                assert(not(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW))),
                assert(Set("n1", "n2", "n3").forall(id =>
                    sent_nullify_votes.exists(v => v.sig == id and v.view == FIRST_VIEW)
                )),
                unchanged_all,
            })
            // Nullify quorum -> advance to view 2
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n3"))
            .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n2"))
            .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n3"))
            .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n3"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => replica_state.get(id).view == 2)),
                unchanged_all,
            })
            // View 2: n1 proposes val_b0 with correct genesis parent
            .then(propose("n1", correct_proposal.payload, correct_proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n0", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n0"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", 2, GENESIS_VIEW, "n2"))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id).length() == 1)),
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id)[0] == correct_proposal)),
                assert(CORRECT.forall(id => replica_state.get(id).last_finalized == 2)),
                unchanged_all,
            })
        }

        // Replica n0 is very slow (always nullifies), but n1, n2, n3 finalize 2 payloads.
        run slowReplicaAlwaysNullifiesTest = {
            val proposal1 = {
                payload: "val_b0",
                view: FIRST_VIEW,
                parent: GENESIS_VIEW,
            }
            val proposal2 = {
                payload: "val_b1",
                view: 2,
                parent: FIRST_VIEW,
            }

            initWithLeaderAndCertify(
                Map(0 -> "n3", 1 -> "n1", 2 -> "n2", 3 -> "n3", 4 -> "n0", 5 -> "n1", 6 -> "n2"),
                CERTIFY_ALL_TRUE
            )
            // View 1: n0 times out (slow), n1 is leader and proposes
            .then(on_timeout("n0", LeaderTimeoutKind))
            .then(propose("n1", proposal1.payload, proposal1.parent))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            // n1, n2, n3 receive notarize quorum -> notarization, finalize, advance to view 2
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            // n1, n2, n3 receive finalize quorum -> finalization, commit val_b0
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
            // n0 receives finalization cert to advance to view 2
            .then(on_certificate("n0", finalization(proposal1, Set("n1", "n2", "n3"), "n1")))
            // View 2: n0 times out again (slow), n2 is leader and proposes
            .then(on_timeout("n0", LeaderTimeoutKind))
            .then(propose("n2", proposal2.payload, proposal2.parent))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n1", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n2", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n1"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n2"))
            .then(replica_receives_finalize_vote("n3", "val_b1", 2, FIRST_VIEW, "n3"))
            .then(all {
                // n1, n2, n3 finalized 2 payloads
                assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id).length() == 2)),
                assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id)[0] == proposal1)),
                assert(Set("n1", "n2", "n3").forall(id => ghost_committed_blocks.get(id)[1] == proposal2)),
                // n0 nullified both views
                assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == FIRST_VIEW)),
                assert(sent_nullify_votes.exists(v => v.sig == "n0" and v.view == 2)),
                // n0 committed 1 payload (from receiving finalization cert for view 1)
                assert(ghost_committed_blocks.get("n0").length() == 1),
                assert(ghost_committed_blocks.get("n0")[0] == proposal1),
                unchanged_all,
            })
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

    action send_certificate(cert: Certificate): bool = all {
        sent_notarize_votes' = sent_notarize_votes,
        sent_nullify_votes' = sent_nullify_votes,
        sent_finalize_votes' = sent_finalize_votes,
        sent_certificates' = sent_certificates.union(Set(cert)),
        store_notarize_votes' = store_notarize_votes,
        store_nullify_votes' = store_nullify_votes,
        store_finalize_votes' = store_finalize_votes,
        store_certificates' = store_certificates,
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

    // Leader vote arrives first: cert is formed on the 3rd vote with exactly
    // Q=3 signatures. The 4th vote does not change the stored cert.
    run notarizationCertHasQSignaturesLeaderFirstTest = {
        val proposal = {
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        // n0 proposes
        // n0 processes its own leader vote (proposal branch, stores vote)
        .then(propose("n0", proposal.payload, proposal.parent))
        // n0 receives n1 (2nd, aggregation, no cert yet)
        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
        // n0 receives n2 (3rd, aggregation, cert formed with {n0, n1, n2})
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        // n0 receives n3 (4th, aggregation, store keeps first cert)
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
        .then(all {
            assert(store_certificates.get("n0").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_proposal(c) == Some(proposal)
            )),
            assert(store_certificates.get("n0").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_signatures(c).size() == Q
            )),
            unchanged_all,
        })
    }

    // create_notarization uses all matching votes instead of exactly Q.
    // Leader vote arrives 3rd (proposal branch — no cert formed). The first
    // cert is formed on the 4th vote with all 4 signatures instead of Q=3.
    run notarizationCertHasQSignaturesLeaderLateTest = {
        val proposal = {
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n2", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        // n2 proposes
        .then(propose("n2", proposal.payload, proposal.parent))
        // n2 receives n1's vote (1st, aggregation, no cert)
        .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
        // n2 receives n3's vote (2nd, aggregation, no cert)
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n3"))
        // n2 receives its own leader vote (3rd, proposal branch — stores vote, no cert formed)
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        // n2 receives n0's vote (4th, aggregation — first cert formed with all 4 votes)
        .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        .then(replica_receives_notarize_vote("n2", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        .then(all {
            assert(store_certificates.get("n2").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_proposal(c) == Some(proposal)
            )),
            // BUG: cert has 4 signatures instead of Q=3
            assert(store_certificates.get("n2").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_signatures(c).size() == Q
            )),
            unchanged_all,
        })
    }

    // Leader (n2) != self (n3). Two aggregation votes arrive before the
    // leader's vote. The proposal branch adds both the leader vote and
    // own vote, so cert must still have exactly Q signatures.
    run notarizationCertHasQSignaturesLeaderDifferentTest = {
        val proposal = {
            payload: "val_b0",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n2", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n0", 6 -> "n1"),
            CERTIFY_ALL_TRUE
        )
        .then(send_notarize_vote({ proposal: proposal, sig: "n0" }))
        .then(send_notarize_vote({ proposal: proposal, sig: "n1" }))
        .then(send_notarize_vote({ proposal: proposal, sig: "n2" }))
        // n3 receives n0's vote (1st, aggregation, no cert)
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n0"))
        // n3 receives n1's vote (2nd, aggregation, no cert)
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n1"))
        // n3 receives n2's leader vote (proposal branch: adds leader + own = 4 votes total)
        .then(replica_receives_notarize_vote("n3", "val_b0", FIRST_VIEW, GENESIS_VIEW, "n2"))
        .then(all {
            assert(store_certificates.get("n3").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_proposal(c) == Some(proposal)
            )),
            assert(store_certificates.get("n3").exists(c =>
                is_notarization_cert(c) and cert_view(c) == FIRST_VIEW and cert_signatures(c).size() == Q
            )),
            unchanged_all,
        })
    }

    // Replica n0 never receives the leader's (n3) notarize vote before the
    // notarization cert arrives. Upon receiving the cert, n0 should self-vote
    // notarize (matching Rust construct_notarize round.rs:481-482). Then n3's
    // late vote arrives and is stored. Final store has all 4 signers.
    run lateLeaderNotarizeSelfVoteTest = {
        val proposal = {
            payload: "val_b0",
            view: 3,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n0", 2 -> "n1", 3 -> "n3", 4 -> "n0", 5 -> "n1", 6 -> "n2"),
            CERTIFY_ALL_TRUE
        )
        // Views 1-2: all replicas timeout and nullify
        .then(on_timeout("n0", LeaderTimeoutKind))
        .then(on_timeout("n1", LeaderTimeoutKind))
        .then(on_timeout("n2", LeaderTimeoutKind))
        .then(on_timeout("n3", LeaderTimeoutKind))
        .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
        .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
        .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n0"))
        .then(replica_receives_nullify_vote("n1", FIRST_VIEW, "n2"))
        .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n0"))
        .then(replica_receives_nullify_vote("n2", FIRST_VIEW, "n1"))
        .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n0"))
        .then(replica_receives_nullify_vote("n3", FIRST_VIEW, "n1"))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).view == 2)),
            unchanged_all,
        })
        .then(on_timeout("n0", LeaderTimeoutKind))
        .then(on_timeout("n1", LeaderTimeoutKind))
        .then(on_timeout("n2", LeaderTimeoutKind))
        .then(on_timeout("n3", LeaderTimeoutKind))
        .then(replica_receives_nullify_vote("n0", 2, "n1"))
        .then(replica_receives_nullify_vote("n0", 2, "n2"))
        .then(replica_receives_nullify_vote("n1", 2, "n0"))
        .then(replica_receives_nullify_vote("n1", 2, "n2"))
        .then(replica_receives_nullify_vote("n2", 2, "n0"))
        .then(replica_receives_nullify_vote("n2", 2, "n1"))
        .then(replica_receives_nullify_vote("n3", 2, "n0"))
        .then(replica_receives_nullify_vote("n3", 2, "n1"))
        .then(all {
            assert(CORRECT.forall(id => replica_state.get(id).view == 3)),
            unchanged_all,
        })
        // View 3: n3 proposes. n0 does NOT receive n3's vote directly yet.
        .then(propose("n3", proposal.payload, proposal.parent))
        // n1 and n2 receive leader vote from n3 (proposal path, they self-vote)
        .then(replica_receives_notarize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n3"))
        .then(replica_receives_notarize_vote("n2", "val_b0", 3, GENESIS_VIEW, "n3"))
        // n0 receives non-leader votes from n1, n2 (aggregation, no proposal yet)
        .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n1"))
        .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n2"))
        // n1 receives n2's vote -> notarization cert formed {n1, n2, n3} = Q
        .then(replica_receives_notarize_vote("n1", "val_b0", 3, GENESIS_VIEW, "n2"))
        // n0 receives notarization cert from n1 -> triggers self-vote
        .then(on_certificate("n0", notarization(proposal, Set("n1", "n2", "n3"), "n1")))
        .then(all {
            // n0 self-voted notarize for view 3 upon receiving the cert
            assert(sent_notarize_votes.exists(v => v.sig == "n0" and v.proposal.view == 3)),
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n0" and v.proposal.view == 3)),
            // n0 stored n1 and n2's votes from earlier aggregation
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n1" and v.proposal.view == 3)),
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n2" and v.proposal.view == 3)),
            unchanged_all,
        })
        // n3's late notarize arrives at n0
        .then(replica_receives_notarize_vote("n0", "val_b0", 3, GENESIS_VIEW, "n3"))
        .then(all {
            // All 4 signers in n0's store
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n0" and v.proposal.view == 3)),
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n1" and v.proposal.view == 3)),
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n2" and v.proposal.view == 3)),
            assert(store_notarize_votes.get("n0").exists(v => v.sig == "n3" and v.proposal.view == 3)),
            unchanged_all,
        })
    }

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
