module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import replica(
        N = 6,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        BYZANTINE = Set("n5"),
        TWINS = Set(),
        VIEWS = 0.to(8),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2", "val_b3", "val_b4", "val_b5"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    run asuumptionsValidTest = all {
        L == 5,
        M == 3,
        assumptions_valid
    }

    // Finalization evidence combines a notarization certificate's signatures with raw votes: an
    // M = 3 notarization for a proposal plus 2 more raw notarize votes for it reach L = 5 and so
    // count as a finalization, even though neither the raw votes alone nor a full finalization
    // certificate is present. Pins `is_proposal_finalized_evidence` against a regression to
    // votes-only / full-certificate-only counting.
    run mixedEvidenceFinalizationTest = {
        pure val p = { block: "val_b0", view: 0, block_parent: GENESIS_BLOCK, view_parent: GENESIS_VIEW, sig: sig_of("n0") }
        pure val notar_p = notarization(p, Set("n0", "n1", "n2"), sig_of("n0"))   // an M = 3 notarization cert
        pure val extra_votes = Set(notarize(p, "n3"), notarize(p, "n4"))          // 2 additional raw votes
        all {
            // raw votes alone are a sub-quorum (2 < L): not a finalization
            not(is_proposal_finalized_votes(p, extra_votes)),
            // but the notarization's 3 signers plus the 2 raw votes reach L = 5: a finalization
            is_proposal_finalized_evidence(p, extra_votes, Set(notar_p)),
        }
    }

    // `on_certificate` accepts a finalization once its signature set reaches L. Two
    // threshold-sized finalizations for different blocks in the same view can therefore be
    // stored by different replicas, even though no corresponding votes were observed.
    //
    // This state is NOT reachable from `init` via `step`: both certificates name n0..n4,
    // and `byzantine_replica_step` draws `agg_sig` from the signatures of real votes united
    // with BYZANTINE, while a correct replica notarizes at most once per view -- so n0..n4
    // can never back both "val_b0" and "val_b1" in view 0. What the test pins down is that
    // `on_certificate` does not *preserve* the invariants when handed a certificate whose
    // signatures are not backed: safety here rests entirely on unforgeability, which
    // `certificates_are_backed` states explicitly. If a future change lets an unbacked
    // certificate reach a replica -- a sync or catch-up path, state transfer, an extra
    // adversary action -- these two steps are all it takes to break `validity`.
    run forgedFinalizationCertificatesViolateValidityTest = {
        pure val proposal_b0 = {
            block: "val_b0", view: 0,
            view_parent: GENESIS_VIEW, block_parent: GENESIS_BLOCK, sig: sig_of("n0")
        }
        pure val proposal_b1 = {
            block: "val_b1", view: 0,
            view_parent: GENESIS_VIEW, block_parent: GENESIS_BLOCK, sig: sig_of("n0")
        }
        pure val forged_finalization_b0 = notarization(
            proposal_b0,
            Set("n0", "n1", "n2", "n3", "n4"),
            sig_of("n5")
        )
        pure val forged_finalization_b1 = notarization(
            proposal_b1,
            Set("n0", "n1", "n2", "n3", "n4"),
            sig_of("n5")
        )

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3", 4 -> "n4", 5 -> "n0"))
            .expect(cert_kind(forged_finalization_b0) == FinalizationKind)
            .expect(cert_kind(forged_finalization_b1) == FinalizationKind)
            .then(on_certificate("n0", forged_finalization_b0))
            .then(on_certificate("n1", forged_finalization_b1))
            .then(all {
                assert(assumptions_valid),
                assert(forged_finalization_b0.in(store_certificate.get("n0"))),
                assert(forged_finalization_b1.in(store_certificate.get("n1"))),
                assert(certificates_are_valid_inv),
                // the certificates are well-shaped but their signatures are not backed:
                // only n0 and n1 ever voted, and only because `_process_certificate` made
                // them notarize the certificate's own proposal on accepting the forgery
                assert(not(certificates_are_backed)),
                assert(not(validity)),
                // n0 finalized val_b0 and n1 finalized val_b1 in the same view 0: two correct
                // replicas disagree on the finalized proposal
                assert(not(finalization_agreement)),
                assert(not(all_invariants)),
                unchanged_all,
            })
            .expect(not(certificates_are_backed))
            .expect(not(validity))
            .expect(not(finalization_agreement))
            .expect(not(all_invariants))
    }

    // The companion of the test above: when the same finalization is assembled from votes
    // that were really cast, `certificates_are_backed` holds. This is what pins the
    // invariant down -- without it the property could be satisfied by never forming a
    // certificate at all.
    run genuineFinalizationIsBackedTest = {
        pure val proposal_from_n0 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3",
                           4 -> "n4", 5 -> "n0", 6 -> "n1", 7 -> "n2", 8 -> "n3"))
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))
            .then(on_proposal("n3", proposal_from_n0))
            .then(on_proposal("n4", proposal_from_n0))
            // n0 assembles finalization(val_b0, 0) from the L = 5 votes it observed
            .then(replica_receives_notarize_votes("n0", proposal_from_n0, Set("n0","n1","n2","n3","n4")))
            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(store_certificate.get("n0").exists(c => and {
                    cert_kind(c) == FinalizationKind,
                    cert_view(c) == 0,
                    cert_proposal(c) == Some(proposal_from_n0),
                })),
                assert(certificates_are_backed),
                // a genuine, uniquely-backed finalization in view 0 satisfies finalization_agreement
                assert(finalization_agreement),
                assert(all_invariants),
                unchanged_all,
            })
            .expect(certificates_are_backed)
            .expect(finalization_agreement)
            .expect(all_invariants)
    }

    // Regression test: a byzantine proposal cannot un-commit or rewrite a finalized block.
    //
    // Regression test: a byzantine proposal cannot un-commit or rewrite a finalized block, even
    // when a later certificate-processing step rebuilds the committed chain afterwards.
    //
    // The committed chain is rebuilt from the stored certificates, not from `sent_proposal`, so a
    // stray proposal cannot move a committed block's parent link. And a Block commits to its
    // parent (`block_commits_to_parent`, minimmit.md 10), so the shadow below -- which reuses the
    // finalized block val_b0 with a different parent -- is a hash collision: it can never arise
    // via `step` (the proposal guards reject it). We force it into `sent_proposal` with
    // `inject_proposal` *before* n2's rebuild, to prove the rebuild ignores it: n2's chain grows,
    // nothing rolls back, and only `block_commits_to_parent` is falsified.
    run committedChainRollbackTest = {
        pure val proposal_0 = {
            block: "val_b0", view: 0,
            view_parent: GENESIS_VIEW, block_parent: GENESIS_BLOCK, sig: sig_of("n0")
        }
        pure val proposal_1 = {
            block: "val_b1", view: 1,
            view_parent: 0, block_parent: "val_b0", sig: sig_of("n1")
        }
        // n0's view-1 finalization certificate, delivered to n2 later to trigger a rebuild.
        pure val finalization_1 = notarization(proposal_1, Set("n0","n1","n2","n3","n4"), sig_of("n0"))
        // The byzantine "shadow" reuses the already finalized (val_b0, view 0) while claiming a
        // different parent -- a hash collision forbidden by `block_commits_to_parent`.
        pure val byz_shadow_of_view_0 = {
            block: "val_b0", view: 0,
            view_parent: 1, block_parent: "val_b1", sig: "n5"
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3",
                           4 -> "n4", 5 -> "n0", 6 -> "n1", 7 -> "n2", 8 -> "n3"))
            // === view 0: proposed, notarized by everyone, finalized by everyone ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_0))
            .then(on_proposal("n2", proposal_0))
            .then(on_proposal("n3", proposal_0))
            .then(on_proposal("n4", proposal_0))
            .then(replica_receives_notarize_votes("n0", proposal_0, Set("n0","n1","n2","n3","n4")))
            .then(replica_receives_notarize_votes("n1", proposal_0, Set("n0","n1","n2","n3","n4")))
            .then(replica_receives_notarize_votes("n2", proposal_0, Set("n0","n1","n2","n3","n4")))
            .then(replica_receives_notarize_votes("n3", proposal_0, Set("n0","n1","n2","n3","n4")))
            .then(replica_receives_notarize_votes("n4", proposal_0, Set("n0","n1","n2","n3","n4")))
            .then(all {
                assert(CORRECT.forall(id => ghost_committed_blocks.get(id) == List(proposal_0))),
                assert(all_invariants),
                unchanged_all,
            })

            // === view 1 runs normally; n0 is simply the first to finalize it ===
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .then(on_proposal("n0", proposal_1))
            .then(on_proposal("n2", proposal_1))
            .then(on_proposal("n3", proposal_1))
            .then(on_proposal("n4", proposal_1))
            .then(replica_receives_notarize_votes("n0", proposal_1, Set("n0","n1","n2","n3","n4")))
            .then(all {
                assert(replica_state.get("n0").last_finalized == 1),
                // n0 commits val_b1 and, by ancestor finalization, the val_b0 it builds on
                assert(ghost_committed_blocks.get("n0") == List(proposal_0, proposal_1)),
                // its peers, which processed no new certificate, still hold the prefix
                assert(ghost_committed_blocks.get("n2") == List(proposal_0)),
                assert(all_invariants),
                unchanged_all,
            })

            // === the byzantine shadow is injected BEFORE a later rebuild ===
            // reusing val_b0 with a different parent breaks the hash binding
            .then(inject_proposal(byz_shadow_of_view_0))
            // n2 now processes the view-1 finalization, which REBUILDS its committed chain while
            // the shadow sits in sent_proposal. The rebuild reads certificates, not sent_proposal,
            // so the shadow cannot un-commit or rewrite anything: n2's chain GROWS to [val_b0, val_b1].
            .then(on_certificate("n2", finalization_1))
            .then(all {
                assert(not(block_commits_to_parent)),
                // the later rebuild is unaffected by the shadow: n2 grew, n0 unchanged, no rollback
                assert(ghost_committed_blocks.get("n2") == List(proposal_0, proposal_1)),
                assert(ghost_committed_blocks.get("n0") == List(proposal_0, proposal_1)),
                unchanged_all,
            })
            .expect(not(block_commits_to_parent))
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
            .then(replica_receives_notarize_vote("n0", proposal_from_n0, "n0"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n0, "n1"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n0, "n2"))

            .then(replica_receives_notarize_vote("n1", proposal_from_n0, "n0"))
            .then(replica_receives_notarize_vote("n1", proposal_from_n0, "n1"))
            .then(replica_receives_notarize_vote("n1", proposal_from_n0, "n2"))

            .then(replica_receives_notarize_vote("n2", proposal_from_n0, "n0"))
            .then(replica_receives_notarize_vote("n2", proposal_from_n0, "n1"))
            .then(replica_receives_notarize_vote("n2", proposal_from_n0, "n2"))

            .then(replica_receives_notarize_vote("n3", proposal_from_n0, "n0"))
            .then(replica_receives_notarize_vote("n3", proposal_from_n0, "n1"))
            .then(replica_receives_notarize_vote("n3", proposal_from_n0, "n2"))

            .then(replica_receives_notarize_vote("n4", proposal_from_n0, "n0"))
            .then(replica_receives_notarize_vote("n4", proposal_from_n0, "n1"))
            .then(replica_receives_notarize_vote("n4", proposal_from_n0, "n2"))
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
            .then(inject_vote(notarize(proposal_from_n5_2, sig_of("n5"))))

            .expect(all_invariants)

            // n0 collects the conflicting evidence. Every vote below is one its signer
            // really broadcast above, which is what `step` would deliver: both
            // `on_vote_notarize` and `on_vote_nullify` are handed a subset of `sent_vote`.
            //
            // The evidence has to stay SPLIT across two shapes. Three notarize votes for one
            // proposal would reach M, assemble a notarization and carry n0 into view 2, and
            // 8.6 would never be needed. Two notarize votes for n5-2 (2 < M) plus one
            // nullify from the byzantine n5 -- free to send both for the same view -- give n0
            // exactly M = 3 distinct conflicting signers while no proof(1) exists yet. That
            // is the state 8.6 is for: n0 is locked on n5-1, can no longer reach L, and
            // nothing exists to move it to the next view.
            .then(inject_vote(nullify(1, sig_of("n5"))))
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_2, "n3"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_2, "n4"))
            .then(replica_receives_nullify_vote("n0", 1, "n5"))

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n0").nullified == false),
                assert(is_contradicted(replica_state.get("n0"), 1, store_vote.get("n0")) == true),
                unchanged_all,
            })

            .then(on_nullify_by_contradiction("n0", 1))
            .expect(all_invariants)

            .then(all {
                assert(store_vote.get("n0").filter(v => vote_view(v) == 1).size() == 3),
                assert(store_vote.get("n0").subseteq(sent_vote)),
                assert(replica_state.get("n0").nullified == true),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Agreement holds even when replicas finalize at different views.
    //
    // n0 finalizes view 0 and commits val_b0. n3 finalizes view 1 while holding
    // notarization(val_b0, 0), so by ancestor finalization (minimmit.md 8.4) it commits
    // [val_b0, val_b1]. n0's chain is a prefix of n3's, so `agreement` holds. (The earlier
    // "commit skips its ancestors" bug had n3 record ["val_b1"] alone, which broke `agreement`
    // against a peer holding ["val_b0"]; rebuilding the chain from certificates by walking a
    // finalized block's ancestry fixes that.)
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
            .then(replica_receives_notarize_votes("n3", proposal_from_n0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n4", proposal_from_n0, Set("n0", "n1", "n2")))
            .then(all {
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n3").last_finalized == GENESIS_VIEW),
                assert(ghost_committed_blocks.get("n3") == List()),
                unchanged_all,
            })

            // n0 sees all L = 5 votes, finalizes view 0 and commits val_b0.
            .then(replica_receives_notarize_votes("n0", proposal_from_n0, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(ghost_committed_blocks.get("n0") == List(proposal_from_n0)),
                unchanged_all,
            })

            // n1 and n2 also advance on the sub-quorum only, so they never commit view 0.
            .then(replica_receives_notarize_votes("n1", proposal_from_n0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n2", proposal_from_n0, Set("n0", "n1", "n2")))

            // === view 1 ===
            // n1 proposes on top of the view-0 notarization, and all of n0-n4 notarize.
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .then(on_proposal("n3", proposal_from_n1))
            .then(on_proposal("n4", proposal_from_n1))
            .then(replica_receives_notarize_votes("n0", proposal_from_n1, Set("n1", "n3", "n4")))
            .then(on_proposal("n2", proposal_from_n1))

            // n3 sees all L = 5 votes for view 1 and finalizes it. It also holds
            // notarization(val_b0, 0), so ancestor finalization commits both val_b0 and val_b1.
            .then(replica_receives_notarize_votes("n3", proposal_from_n1, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                assert(replica_state.get("n3").last_finalized == 1),
                // n0's [val_b0] is a prefix of n3's [val_b0, val_b1]: agreement holds
                assert(ghost_committed_blocks.get("n0") == List(proposal_from_n0)),
                assert(ghost_committed_blocks.get("n3") == List(proposal_from_n0, proposal_from_n1)),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Finalizing a proposal also finalizes all of its ancestors.
    run ancestorFinalizationMismatchTest = {
        pure val proposal_0: Proposal = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0"),
        }

        pure val proposal_1: Proposal = {
            block: "val_b1",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n1"),
        }

        pure val notarization_0 = notarization(
            proposal_0,
            Set(sig_of("n0"), sig_of("n1"), sig_of("n2")),
            sig_of("n0")
        )

        initWithLeader(Map(
            0 -> "n0",
            1 -> "n1",
            2 -> "n2",
            3 -> "n3",
            4 -> "n4",
            5 -> "n0"
        ))
        .expect(cert_kind(notarization_0) == NotarizationKind)
        // View 0: P0 receives exactly M = 3 notarize votes.
        .then(proposer_step(
            "n0",
            "val_b0",
            GENESIS_BLOCK,
            GENESIS_VIEW
        ))
        .then(on_proposal("n1", proposal_0))
        .then(on_proposal("n2", proposal_0))

        // The two remaining correct replicas nullify before learning P0.
        .then(on_timer_expired("n3"))
        .then(on_timer_expired("n4"))

        // n0 assembles only an M-certificate for P0.
        .then(replica_receives_notarize_votes(
            "n0",
            proposal_0,
            Set("n0", "n1", "n2")
        ))

        // Everyone enters view 1 using the P0 notarization.
        //
        // n1 and n2 already notarized P0. n3 and n4 already nullified
        // view 0. Consequently, delivery of the certificate generates no
        // additional P0 votes, and P0 remains unfinalized.
        .then(on_certificate("n1", notarization_0))
        .then(on_certificate("n2", notarization_0))
        .then(on_certificate("n3", notarization_0))
        .then(on_certificate("n4", notarization_0))

        .then(all {
            assert(replica_state.get("n0").view == 1),
            assert(replica_state.get("n1").view == 1),
            assert(replica_state.get("n2").view == 1),
            assert(replica_state.get("n3").view == 1),
            assert(replica_state.get("n4").view == 1),

            assert(not(is_proposal_finalized(
                Some(proposal_0),
                store_certificate.get("n0")
            ))),

            unchanged_all,
        })

        // View 1: all five correct replicas vote for child P1.
        .then(proposer_step(
            "n1",
            "val_b1",
            "val_b0",
            0
        ))
        .then(on_proposal("n0", proposal_1))
        .then(on_proposal("n2", proposal_1))
        .then(on_proposal("n3", proposal_1))
        .then(on_proposal("n4", proposal_1))

        // n0 observes L = 5 votes and finalizes P1.
        .then(replica_receives_notarize_votes(
            "n0",
            proposal_1,
            Set("n0", "n1", "n2", "n3", "n4")
        ))

        .then(all {
            assert(is_proposal_finalized(
                Some(proposal_1),
                store_certificate.get("n0")
            )),
            assert(not(is_proposal_finalized(
                Some(proposal_0),
                store_certificate.get("n0")
            ))),

            // P1's finalization also finalizes its ancestor P0 (minimmit.md 8.4): P0 carries
            // only a notarization, but rebuild_committed_chain walks through it, so n0 commits
            // [P0, P1].
            assert(replica_state.get("n0").last_finalized == 1),
            assert(ghost_committed_blocks.get("n0") == List(proposal_0, proposal_1)),

            assert(all_invariants),
            unchanged_all,
        })
        .expect(all_invariants)
    }


    // Regression test for the "out-of-order commit at the top view" defect.
    //
    // `enter_new_view` gates all of its bookkeeping -- including the `last_finalized`
    // update -- behind `VIEWS.contains(cert_view(cert) + 1)`, so for a certificate on the top
    // view (8 here) the whole function is a no-op and `last_finalized` is never advanced.
    // When the commit was an append guarded by `cert_view(cert) > self.last_finalized`, that
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
        pure val nullification_7 = nullification(
            7,
            Set("n0", "n1", "n5"),
            "n0"
        )
        // assembled and broadcast by n4 when it finalizes view 0, after view 8
        pure val finalization_0 = notarization(
            proposal_from_n0,
            Set("n0", "n1", "n2", "n3", "n4"),
            "n4"
        )

        // n5 leads views 1-7 and never proposes, so those views time out.
        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n5", 3 -> "n5", 4 -> "n5",
                           5 -> "n5", 6 -> "n5", 7 -> "n5", 8 -> "n0"))
            .expect(cert_kind(finalization_0) == FinalizationKind)
            // === view 0: notarized by all of n0-n4, but nobody finalizes it yet ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))
            .then(on_proposal("n3", proposal_from_n0))
            .then(on_proposal("n4", proposal_from_n0))
            // n0 and n1 see only a sub-quorum of M = 3 votes, so they assemble a
            // notarization and enter view 1 without committing anything.
            .then(replica_receives_notarize_votes("n0", proposal_from_n0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n1", proposal_from_n0, Set("n0", "n1", "n2")))

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
            .then(inject_vote(notarize(proposal_at_top_view, sig_of("n5"))))
            // n2 and n3 vote for the block on seeing notarization(val_b1, 8)
            .then(replica_receives_notarize_votes("n2", proposal_at_top_view, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n3", proposal_at_top_view, Set("n0", "n1", "n5")))

            // n4 sees all L = 5 votes and finalizes view 8. `enter_new_view` bails out
            // because view 9 is not in VIEWS, so n4.last_finalized is NOT advanced.
            .then(replica_receives_notarize_votes("n4", proposal_at_top_view, Set("n0", "n1", "n5", "n2", "n3")))
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
            .then(replica_receives_notarize_votes("n4", proposal_from_n0, Set("n0", "n1", "n2", "n3", "n4")))
            // n0 picks up that finalization certificate and commits val_b0 too.
            .then(on_certificate("n0", finalization_0))
            .then(all {
                assert(ghost_committed_blocks.get("n4") == List(proposal_from_n0)),
                assert(ghost_committed_blocks.get("n0") == List(proposal_from_n0)),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Regression test: `block_commits_to_parent` is what makes ancestor finalization safe by
    // ruling out a parent-equivocation attack.
    //
    // Ancestor finalization commits a finalized block's notarized ancestors (minimmit.md 8.4).
    // That is only sound because a Block is a hash-protected container that commits to its parent
    // (minimmit.md 10): the SAME block cannot be built on two different parents. Without that, a
    // byzantine leader could give block val_b2 two parents (val_b0 and val_b1); a finalized
    // descendant of val_b2 would then have an ambiguous ancestry and two correct replicas could
    // commit divergent chains ([val_b0, val_b2, ...] vs [val_b1, val_b2, ...]).
    //
    // `byzantine_replica_step` cannot produce this state -- its proposal guard enforces the
    // binding, so it can never bind val_b2 to a second parent. We build it here with
    // `inject_proposal`, which bypasses the guard, purely to show that `block_commits_to_parent`
    // detects it. This is the invariant `rebuild_committed_chain`'s ancestor walk relies on.
    run equivocatedAncestorTest = {
        // same block val_b2 at view 1, two different parents -- a hash collision
        pure val prop_x_via_a = { block: "val_b2", view: 1, block_parent: "val_b0", view_parent: 0, sig: sig_of("n5") }
        pure val prop_x_via_b = { block: "val_b2", view: 1, block_parent: "val_b1", view_parent: 0, sig: sig_of("n5") }

        initWithLeader(Map(0 -> "n5", 1 -> "n5", 2 -> "n0", 3 -> "n0",
                           4 -> "n0", 5 -> "n0", 6 -> "n0", 7 -> "n0", 8 -> "n0"))
            .then(all { assert(block_commits_to_parent), unchanged_all })   // holds initially
            .then(inject_proposal(prop_x_via_a))
            .then(all { assert(block_commits_to_parent), unchanged_all })   // one binding is fine
            // the second proposal binds the same block val_b2 to a different parent
            .then(inject_proposal(prop_x_via_b))
            .then(all {
                assert(prop_x_via_a.block == prop_x_via_b.block),
                assert(prop_x_via_a.block_parent != prop_x_via_b.block_parent),
                // the hash binding is broken -- exactly what a collision-resistant digest forbids
                assert(not(block_commits_to_parent)),
                unchanged_all,
            })
            .expect(not(block_commits_to_parent))
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

     action replica_receives_notarize_vote(id: ReplicaId, proposal: Proposal, src: ReplicaId): bool =
        on_vote_notarize(id, proposal,  Set(notarize(proposal, src)))

    action replica_receives_notarize_votes(id: ReplicaId, proposal: Proposal, srcs: Set[ReplicaId]): bool =
        on_vote_notarize(id, proposal, srcs.map(src => notarize(proposal, src)))

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
