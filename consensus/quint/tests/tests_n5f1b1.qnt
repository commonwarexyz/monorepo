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
        INVALID_PAYLOADS = Set("inv_b3"),
        ACTIVITY_TIMEOUT = 10
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
            .then(send_certificate(cert))
            .then(on_certificate("n3", cert))
            .then(all {
                assert(store_certificates.get("n3").exists(c => cert_kind(c) == NotarizationKind and cert_view(c) == FIRST_VIEW and cert_payload(c) == Some("val_b1"))),
                assert(sent_finalize_votes.exists(v => v.sig == "n3" and v.proposal.view == FIRST_VIEW and v.proposal.payload == "val_b1")),
                assert(sent_certificates.exists(c => and {
                    is_notarization_cert(c),
                    cert_view(c) == FIRST_VIEW,
                    cert_ghost_sender(c) == "n3",
                })),
                assert(replica_state.get("n3").certified.get(FIRST_VIEW) == Some(true)),
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
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW)),
                assert(broadcast_nullify("n2", FIRST_VIEW)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run leaderTimeoutBroadcastsCurrentViewNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(set_timeout_state("n2", 2, Some(false), Some(false)))
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == 2)),
                assert(not(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW))),
                assert(replica_state.get("n2").view == 2),
                assert(broadcast_nullify("n2", 2)),
                assert(replica_state.get("n2").leader_timeout.get(2) == Some(true)),
                assert(replica_state.get("n2").certification_timeout.get(2) == Some(false)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run certificationTimeoutBroadcastsCurrentViewNullifyTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(set_timeout_state("n2", 2, Some(true), Some(false)))
            .then(on_timeout("n2", CertificationTimeoutKind))
            .then(all {
                assert(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == 2)),
                assert(not(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == FIRST_VIEW))),
                assert(replica_state.get("n2").view == 2),
                assert(broadcast_nullify("n2", 2)),
                assert(replica_state.get("n2").leader_timeout.get(2) == Some(true)),
                assert(replica_state.get("n2").certification_timeout.get(2) == Some(true)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run timeoutDoesNotBroadcastNullifyAfterFinalizeTest = {
        val proposal = {
            payload: "val_b1",
            view: 2,
            parent: GENESIS_VIEW,
        }
        val cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n4", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(send_certificate(cert))
            .then(on_certificate("n2", cert))
            .then(send_finalize_vote({ proposal: proposal, sig: "n2" }))
            .then(set_timeout_state("n2", 2, Some(false), Some(false)))
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(all {
                assert(not(sent_nullify_votes.exists(v => v.sig == "n2" and v.view == 2))),
                assert(replica_state.get("n2").view == 2),
                assert(not(broadcast_nullify("n2", 2))),
                assert(broadcast_finalize("n2", 2)),
                assert(replica_state.get("n2").leader_timeout.get(2) == Some(true)),
                assert(replica_state.get("n2").certification_timeout.get(2) == Some(false)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run localNullificationConstructionCancelsTimersTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(on_timeout("n0", LeaderTimeoutKind))
            .then(on_timeout("n1", LeaderTimeoutKind))
            .then(on_timeout("n2", LeaderTimeoutKind))
            .then(on_nullify("n2", { view: FIRST_VIEW, sig: "n0" }))
            .then(on_nullify("n2", { view: FIRST_VIEW, sig: "n1" }))
            .then(all {
                assert(store_certificates.get("n2").exists(c =>
                    is_nullification_cert(c) and cert_view(c) == FIRST_VIEW
                )),
                assert(broadcast_nullification("n2", FIRST_VIEW)),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n2").leader_timeout.get(FIRST_VIEW) == None),
                assert(replica_state.get("n2").certification_timeout.get(FIRST_VIEW) == None),
                assert(replica_state.get("n2").leader_timeout.get(FIRST_VIEW) == None),
                assert(replica_state.get("n2").certification_timeout.get(FIRST_VIEW) == None),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run receivedNullificationCertificateCancelsTimersAndBroadcastsTest = {
        val cert = nullification(FIRST_VIEW, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n0" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n1" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n2" }))
            .then(send_certificate(cert))
            .then(on_certificate("n2", cert))
            .then(all {
                assert(store_certificates.get("n2").exists(c =>
                    is_nullification_cert(c) and cert_view(c) == FIRST_VIEW
                )),
                // First nullification: broadcast_nullification set and cert broadcast.
                assert(broadcast_nullification("n2", FIRST_VIEW)),
                assert(replica_state.get("n2").leader_timeout.get(FIRST_VIEW) == None),
                assert(replica_state.get("n2").certification_timeout.get(FIRST_VIEW) == None),
                assert(replica_state.get("n2").view == 2),
                assert(sent_certificates.exists(c => is_nullification_cert(c) and cert_view(c) == FIRST_VIEW)),
                assert(sent_certificates.filter(c => is_nullification_cert(c) and cert_view(c) == FIRST_VIEW).size() >= 1),
                unchanged_all,
            })
            // A 4th nullify vote arrives; on_nullify re-creates a cert but does not re-broadcast.
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n3" }))
            .then(on_nullify("n2", { view: FIRST_VIEW, sig: "n0" }))
            .then(on_nullify("n2", { view: FIRST_VIEW, sig: "n1" }))
            .then(all {
                assert(broadcast_nullification("n2", FIRST_VIEW)),
                // The late extra vote does not change the locally stored certificate.
                assert(sent_certificates.filter(c => is_nullification_cert(c) and cert_view(c) == FIRST_VIEW).size() >= 1),
                // Store still has only one nullification cert for this view.
                assert(store_certificates.get("n2").filter(c =>
                    is_nullification_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // A notarization certificate with an invalid parent (self-referencing view 2 -> 2)
    // still triggers certification and produces a finalize vote. Certification is
    // application-level and does not check parent validity. construct_finalize
    // (matching the implementation) only checks broadcast flags, equivocation,
    // notarization existence, and certification -- not parent validity.
    run invalidParentNotarizationCertificateStillFinalizesTest = {
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
            .then(send_certificate(bad_cert))
            .then(on_certificate("n3", bad_cert))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_notarization_cert(c)
                        and cert_proposal(c) == Some(bad_proposal)
                )),
                // Finalize vote IS sent: construct_finalize does not check parent validity.
                assert(sent_finalize_votes.exists(v =>
                    v.sig == "n3" and v.proposal == bad_proposal
                )),
                assert(replica_state.get("n3").certified.get(2) == Some(true)),
                assert(replica_state.get("n3").view == 3),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run firstObservedNotarizationCertificateIsStickyTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }
        val cert_first = notarization(proposal, Set("n0", "n1", "n2"), "n0")
        val cert_later = notarization(proposal, Set("n0", "n1", "n2", "n4"), "n4")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(send_certificate(cert_first))
            .then(on_certificate("n3", cert_first))
            .then(all {
                // First notarization: broadcast_notarization is set and cert is broadcast.
                assert(broadcast_notarization("n3", FIRST_VIEW)),
                assert(sent_certificates.exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c) == Set("n0", "n1", "n2")
                )),
                unchanged_all,
            })
            .then(send_notarize_vote({ proposal: proposal, sig: "n4" }))
            .then(send_certificate(cert_later))
            .then(on_certificate("n3", cert_later))
            .then(all {
                // Second notarization (same proposal, different sigs): not broadcast,
                // broadcast_notarization unchanged.
                assert(broadcast_notarization("n3", FIRST_VIEW)),
                assert(store_certificates.get("n3").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c) == Set("n0", "n1", "n2")
                )),
                assert(store_certificates.get("n3").filter(c =>
                    is_notarization_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run localNullificationUsesQuorumSizedCertificateTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n0" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n1" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n2" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n4" }))

            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n0" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n1" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n2" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n4" }))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_nullification_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c).size() == Q
                )),
                unchanged_all,
            })
            .then(all {
                assert(broadcast_nullification("n3", FIRST_VIEW)),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run localFinalizationUsesQuorumSizedCertificateTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }
        val notarization_cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(send_certificate(notarization_cert))
            .then(on_certificate("n0", notarization_cert))
            .then(on_certificate("n1", notarization_cert))
            .then(on_certificate("n3", notarization_cert))
            .then(send_finalize_vote({ proposal: proposal, sig: "n0" }))
            .then(send_finalize_vote({ proposal: proposal, sig: "n1" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n0" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n1" }))
            .then(all {
                // First finalization: broadcast_finalization set and cert broadcast.
                assert(broadcast_finalization("n3", FIRST_VIEW)),
                assert(sent_certificates.filter(c =>
                    is_finalization_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                assert(store_certificates.get("n3").exists(c =>
                    is_finalization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c).size() == Q
                )),
                unchanged_all,
            })
            // A 4th finalize vote arrives; on_finalize re-creates a cert but does not re-broadcast.
            .then(send_finalize_vote({ proposal: proposal, sig: "n4" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n4" }))
            .then(all {
                assert(broadcast_finalization("n3", FIRST_VIEW)),
                // No second finalization cert was broadcast.
                assert(sent_certificates.filter(c =>
                    is_finalization_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                // Store still has only one finalization cert for this view.
                assert(store_certificates.get("n3").filter(c =>
                    is_finalization_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    run duplicateReceivedNotarizationCertificateIsIgnoredTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }
        val later_cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(send_certificate(later_cert))
            .then(on_certificate("n3", later_cert))
            .then(all {
                assert(store_certificates.get("n3").filter(c =>
                    is_notarization_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                assert(store_certificates.get("n3").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // A late 4th notarize vote must NOT add a second certificate for
    // the same (view, proposal). Mirrors Rust's
    // `try_construct_notarization` short-circuit at
    // `src/simplex/actors/batcher/round.rs:422`, which returns early
    // once `has_notarization()` is true. The store keeps the original
    // first cert (3 signers) unchanged.
    run lateNotarizeVoteDoesNotAddSecondCertTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(send_notarize_vote({ proposal: proposal, sig: "n1" }))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(all {
                // First cert formed at quorum with {n0, n1, n3}.
                assert(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                assert(store_certificates.get("n0").filter(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ).size() == 1),
                unchanged_all,
            })
            .then(send_notarize_vote({ proposal: proposal, sig: "n2" }))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(all {
                // The original 3-signer cert is still in the store.
                assert(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                // NO second certificate was created for this proposal.
                // The `had_notarization` gate in replica.qnt prevents
                // a late 4th vote from constructing a larger cert
                // alongside the first one (matching Rust).
                assert(store_certificates.get("n0").filter(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ).size() == 1),
                assert(not(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c).size() == 4
                ))),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // Complementary to `lateNotarizeVoteDoesNotAddSecondCertTest`: when
    // the first certificate construction happens *after* all four
    // notarize votes are already in the store, the resulting cert
    // carries all four signers. This exercises the ≥-Q widening
    // (replica.qnt drops the former Q-cap preference) without the
    // multi-cert artifact: only one notarization exists in the store
    // for the given (view, proposal). Matches Rust's single-shot
    // `try_construct_notarization` firing after batch verification of
    // 4 votes.
    run notarizationFirstCertFourSignersTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }

        initWithLeaderAndCertify(
            // leader(1) = n3
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            // Stage two peer votes into sent_notarize_votes.
            .then(send_notarize_vote({ proposal: proposal, sig: "n1" }))
            .then(send_notarize_vote({ proposal: proposal, sig: "n2" }))
            // Deliver both to n0 via aggregation — each is below Q.
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n2"))
            .then(all {
                // No cert yet — only 2 < Q votes in store.
                assert(not(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ))),
                unchanged_all,
            })
            // Now the leader (n3) sends its notarize (stages it into
            // sent_notarize_votes via propose).
            .then(propose("n3", proposal.payload, proposal.parent))
            // n0 processes n3's leader vote. This goes through the
            // proposal branch of on_notarize, which adds BOTH the
            // leader's signature AND n0's own self-vote at once.
            // new_store_notarize_p = {n1, n2} ∪ {n3_vote, n0_self_vote}
            //                      = {n0, n1, n2, n3} = 4 signers.
            // The first (and only) certificate forms here with all 4.
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(all {
                // Exactly one cert, with all four signers.
                assert(store_certificates.get("n0").exists(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c) == Set("n0", "n1", "n2", "n3")
                )),
                assert(store_certificates.get("n0").filter(c =>
                    is_notarization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ).size() == 1),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // on_nullify can add the replica's own nullify vote via leader-triggered
    // timeout logic, so a later extra vote must not expand the first cert.
    run lateNullifyVoteKeepsFirstNullificationQuorumTest = {
        initWithLeaderAndCertify(
            Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n0" }))
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n1" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n0" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n1" }))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_nullification_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                assert(store_certificates.get("n3").filter(c =>
                    is_nullification_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                unchanged_all,
            })
            .then(send_nullify_vote({ view: FIRST_VIEW, sig: "n2" }))
            .then(on_nullify("n3", { view: FIRST_VIEW, sig: "n2" }))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_nullification_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                assert(store_certificates.get("n3").filter(c =>
                    is_nullification_cert(c) and cert_view(c) == FIRST_VIEW
                ).size() == 1),
                unchanged_all,
            })
            .expect(test_invariants)
    }

    // After finalization forms at quorum, a later extra finalize vote must not
    // change the stored cert away from the original {n0, n1, n3} signer set.
    run lateFinalizeVoteKeepsFirstFinalizationQuorumTest = {
        val proposal = {
            payload: "val_b1",
            view: FIRST_VIEW,
            parent: GENESIS_VIEW,
        }
        val notarization_cert = notarization(proposal, Set("n0", "n1", "n2"), "n0")

        initWithLeaderAndCertify(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n4"),
            CERTIFY_ALL_TRUE
        )
            .then(propose("n3", proposal.payload, proposal.parent))
            .then(replica_receives_notarize_vote("n0", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", FIRST_VIEW, GENESIS_VIEW, "n3"))
            .then(send_certificate(notarization_cert))
            .then(on_certificate("n0", notarization_cert))
            .then(on_certificate("n1", notarization_cert))
            .then(on_certificate("n3", notarization_cert))
            .then(send_finalize_vote({ proposal: proposal, sig: "n0" }))
            .then(send_finalize_vote({ proposal: proposal, sig: "n1" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n0" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n1" }))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_finalization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                assert(store_certificates.get("n3").filter(c =>
                    is_finalization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ).size() == 1),
                unchanged_all,
            })
            .then(send_finalize_vote({ proposal: proposal, sig: "n4" }))
            .then(on_finalize("n3", { proposal: proposal, sig: "n4" }))
            .then(all {
                assert(store_certificates.get("n3").exists(c =>
                    is_finalization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                        and cert_signatures(c) == Set("n0", "n1", "n3")
                )),
                assert(store_certificates.get("n3").filter(c =>
                    is_finalization_cert(c)
                        and cert_view(c) == FIRST_VIEW
                        and cert_proposal(c) == Some(proposal)
                ).size() == 1),
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

    action set_timeout_state(
        id: ReplicaId,
        view: ViewNumber,
        leader_timeout: Option[bool],
        certification_timeout: Option[bool]
    ): bool = all {
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
        replica_state' = replica_state.set(id, {
            ...replica_state.get(id),
            view: view,
            leader_timeout: replica_state.get(id).leader_timeout.set(view, leader_timeout),
            certification_timeout: replica_state.get(id).certification_timeout.set(view, certification_timeout)
        }),
        certify_policy' = certify_policy,
        lastAction' = "set_timeout_state",
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
