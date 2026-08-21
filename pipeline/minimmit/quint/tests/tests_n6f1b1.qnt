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
                // no replica ever cast a notarize vote for these proposals, so the claimed
                // n0..n4 signatures have no corresponding votes
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

    // Regression test: contradiction causality must be enforced by the invariant layer, not
    // only by the transition guard.
    //
    // minimmit.md 8.6 permits notarize-then-nullify only after observing >= M distinct
    // conflicting replicas. `on_nullify_by_contradiction` checks this via `is_contradicted`,
    // but a guard is invisible to the invariants: `no_vote_equivocation_inv` accepts every
    // [notarize, nullify] sequence, and no property names the evidence. The unjustified state,
    // a nullify-after-notarize with NO conflicting evidence in the local store, is not
    // reachable via `step` precisely because of the guard, so no test can produce it through
    // the real action either; we force it with `force_unjustified_nullify`, which replays the
    // transition's effect while bypassing the guard, purely to show
    // `contradiction_nullify_is_justified` detects it (the same pattern as
    // `equivocatedAncestorTest`).
    run unjustifiedContradictionNullifyTest = {
        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n2", 3 -> "n3", 4 -> "n4", 5 -> "n0"))
            // n0 proposes, which counts as its notarize(val_b0, 0): ghost_sent_votes[0] = [Some]
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(all { assert(contradiction_nullify_is_justified), unchanged_all })
            // the forged 8.6: n0 nullifies view 0 with an empty vote store, zero conflicting
            // signatures, where the rule demands M = 3
            .then(force_unjustified_nullify("n0"))
            .then(all {
                // the sent sequence [notarize, nullify] is exactly the shape 8.6 legitimately
                // produces, so the equivocation invariant sees nothing wrong ...
                assert(no_vote_equivocation_inv),
                // ... but the causality invariant does: no evidence backs the nullify
                assert(not(contradiction_nullify_is_justified)),
                unchanged_all,
            })
            .expect(not(contradiction_nullify_is_justified))
            .expect(not(all_invariants))
    }

    // Replays the state change of `on_nullify_by_contradiction` WITHOUT its
    // `is_contradicted` guard. Test-only: `step` cannot produce this transition.
    action force_unjustified_nullify(id: ReplicaId): bool = all {
        val self = replica_state.get(id)
        all {
            sent_vote' = sent_vote.union(Set(nullify(self.view, sig_of(id)))),
            replica_state' = replica_state.set(id, {
                ...self,
                nullified: true,
                ghost_sent_votes: self.ghost_sent_votes.setBy(self.view, old => old.append(None))
            }),
            sent_proposal' = sent_proposal,
            sent_certificate' = sent_certificate,
            store_vote' = store_vote,
            store_certificate' = store_certificate,
            ghost_proposal' = ghost_proposal,
            ghost_committed_blocks' = ghost_committed_blocks,
            leader' = leader,
        }
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
            // All of n0-n4 notarize val_b0 by receiving the proposal, but n3 and n4 then observe
            // only the sub-quorum {n0, n1, n2} (M = 3, below the finalization quorum L).
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_from_n0))
            .then(on_proposal("n2", proposal_from_n0))
            .then(on_proposal("n3", proposal_from_n0))
            .then(on_proposal("n4", proposal_from_n0))

            // n3 and n4 assemble a notarization from that sub-quorum and enter view 1 without
            // finalizing anything.
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
            // n1 proposes on top of the view-0 notarization, and all of n0-n4 notarize by
            // receiving the proposal. n0 holds finalization(val_b0, 0), so `valid_parent` passes.
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .then(on_proposal("n0", proposal_from_n1))
            .then(on_proposal("n2", proposal_from_n1))
            .then(on_proposal("n3", proposal_from_n1))
            .then(on_proposal("n4", proposal_from_n1))

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
    // The committed chain is rebuilt from stored certificates and derives its order from parent
    // links, not from `last_finalized`, so a top-view finalization cannot commit out of order --
    // val_b1 (view 8) still cannot precede or follow val_b0 (view 0) unless the (0, 8) gap is
    // nullified. A finalization whose ancestry is locally incomplete is pending
    // (`pending_finalizations`) and does not advance `last_finalized`: the watermark tracks the
    // committed chain's tip, so it moves only when the ancestry is complete; here, when the
    // *earlier* view 0 is finalized while view 8 stays pending.
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
        // rungs of the nullification ladder (walkers n0, n1 + byzantine n5)
        pure val nullification_1 = nullification(1, Set("n0", "n1", "n5"), "n0")
        pure val nullification_2 = nullification(2, Set("n0", "n1", "n5"), "n0")
        pure val nullification_3 = nullification(3, Set("n0", "n1", "n5"), "n0")
        pure val nullification_4 = nullification(4, Set("n0", "n1", "n5"), "n0")
        pure val nullification_5 = nullification(5, Set("n0", "n1", "n5"), "n0")
        pure val nullification_6 = nullification(6, Set("n0", "n1", "n5"), "n0")
        // assembled by n0 on the last rung of the nullification ladder
        pure val nullification_7 = nullification(
            7,
            Set("n0", "n1", "n5"),
            "n0"
        )
        // the view-0 notarization for val_b0, assembled from the sub-quorum {n0, n1, n2}
        pure val notarization_0 = notarization(proposal_from_n0, Set("n0", "n1", "n2"), "n0")
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
            // n0 and n1 see only an M = 3 quorum of votes (below L), so they assemble a
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
            // n2 and n3 receive the full proof chain for val_b1's parent -- notarization(val_b0, 0)
            // and the nullifications for views 1..7 -- so `valid_parent` holds and they can notarize
            // val_b1 through the proposal path (n4 is deliberately left without it below).
            .then(on_certificate("n2", notarization_0))
            .then(on_certificate("n2", nullification_1))
            .then(on_certificate("n2", nullification_2))
            .then(on_certificate("n2", nullification_3))
            .then(on_certificate("n2", nullification_4))
            .then(on_certificate("n2", nullification_5))
            .then(on_certificate("n2", nullification_6))
            .then(on_certificate("n3", notarization_0))
            .then(on_certificate("n3", nullification_1))
            .then(on_certificate("n3", nullification_2))
            .then(on_certificate("n3", nullification_3))
            .then(on_certificate("n3", nullification_4))
            .then(on_certificate("n3", nullification_5))
            .then(on_certificate("n3", nullification_6))
            .then(on_proposal("n2", proposal_at_top_view))
            .then(on_proposal("n3", proposal_at_top_view))

            // n4 sees all L = 5 votes and stores a finalization for view 8. Its ancestry is
            // locally incomplete (the (0, 8) gap is not nullified in n4's store), so the
            // finalization is pending and `last_finalized` does not move.
            .then(replica_receives_notarize_votes("n4", proposal_at_top_view, Set("n0", "n1", "n5", "n2", "n3")))
            .then(all {
                // val_b1's parent is view 0, which n4 has not committed, and the (0, 8) gap is
                // not nullified in n4's store, so the walk from genesis cannot reach it: n4
                // commits nothing, the finalization is parked in `pending_finalizations`, and
                // the committed watermark stays at genesis.
                assert(ghost_committed_blocks.get("n4") == List()),
                assert(pending_finalizations(store_certificate.get("n4")) == Set(proposal_at_top_view)),
                assert(replica_state.get("n4").last_finalized == GENESIS_VIEW),
                unchanged_all,
            })

            // n4 now finalizes the *earlier* view 0. The chain is rebuilt from scratch,
            // so val_b0 lands first; val_b1 still cannot follow it, because n4 is missing
            // nullifications for views 1-6 and the gap (0, 8) is not covered; it stays
            // pending, and `last_finalized` advances only to the committed tip, view 0.
            .then(replica_receives_notarize_votes("n4", proposal_from_n0, Set("n0", "n1", "n2", "n3", "n4")))
            // n0 picks up that finalization certificate and commits val_b0 too.
            .then(on_certificate("n0", finalization_0))
            .then(all {
                assert(ghost_committed_blocks.get("n4") == List(proposal_from_n0)),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(pending_finalizations(store_certificate.get("n4")) == Set(proposal_at_top_view)),
                assert(ghost_committed_blocks.get("n0") == List(proposal_from_n0)),
                assert(replica_state.get("n0").last_finalized == 0),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Regression test for the pending-finalization semantics: a finalization whose ancestry
    // is locally incomplete must not vanish from the committed-state model.
    //
    // Two views, no forged messages: every step is a real protocol action and every vote a
    // replica receives was actually broadcast, so the whole trace is in-domain for `step`. A
    // replica (n4) that saw nothing of view 0 assembles a genuine L-quorum finalization for
    // the view-1 block from votes alone: `on_vote_notarize` checks only vote shape, no
    // ancestry, exactly like the real protocol, where a certificate is just an aggregation of
    // signatures. The L certificate for P1 does not certify P1's parent: the parent link
    // inside the proposal is a claim, and the proof of that claim (notarization(val_b0, 0))
    // is a separate certificate n4 does not hold. So n4 must NOT commit and, since
    // `last_finalized` is the committed watermark, must not advance it either. The
    // finalization is parked in `pending_finalizations`, waiting for backfill.
    //
    // Before this semantics landed, the trace ended with `last_finalized == 1`, an empty
    // committed chain, and `all_invariants` still true: the finalization was invisible to the
    // committed-state model, `agreement`'s prefix check was vacuous over the empty chain, and
    // no invariant related the stored L certificate to the chain. Now the state is honestly
    // described (pending, watermark unmoved) and pinned by `last_finalized_is_committed`,
    // `finalized_blocks_are_committed_or_pending`, and `pending_finalization_agreement`.
    run finalizationPendingUntilBackfillTest = {
        pure val proposal_0 = {
            block: "val_b0", view: 0,
            view_parent: GENESIS_VIEW, block_parent: GENESIS_BLOCK, sig: sig_of("n0")
        }
        pure val proposal_1 = {
            block: "val_b1", view: 1,
            view_parent: 0, block_parent: "val_b0", sig: sig_of("n1")
        }
        // assembled and broadcast by n0 from the M-subquorum {n0, n1, n2}
        pure val notarization_0 = notarization(proposal_0, Set("n0", "n1", "n2"), sig_of("n0"))

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n5", 3 -> "n5", 4 -> "n5",
                           5 -> "n5", 6 -> "n5", 7 -> "n5", 8 -> "n5"))
            // === view 0: P0 proposed and notarized by n0..n3; n4 sees none of it ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal_0))
            .then(on_proposal("n2", proposal_0))
            .then(on_proposal("n3", proposal_0))
            // n0 and n1 assemble notarization(P0, 0) from {n0, n1, n2} and enter view 1
            .then(replica_receives_notarize_votes("n0", proposal_0, Set("n0", "n1", "n2")))
            .then(replica_receives_notarize_votes("n1", proposal_0, Set("n0", "n1", "n2")))
            // n2 and n3 pick up the broadcast certificate and enter view 1 too
            .then(on_certificate("n2", notarization_0))
            .then(on_certificate("n3", notarization_0))

            // === view 1: P1 built on P0; the L-quorum forms ===
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .then(on_proposal("n0", proposal_1))
            .then(on_proposal("n2", proposal_1))
            .then(on_proposal("n3", proposal_1))
            // the byzantine replica contributes the fifth notarize vote
            .then(inject_vote(notarize(proposal_1, sig_of("n5"))))

            // n4, still in view 0 with an empty store, receives the L = 5 quorum for P1
            .then(replica_receives_notarize_votes("n4", proposal_1, Set("n0", "n1", "n2", "n3", "n5")))
            .then(all {
                // the finalization is genuine and stored ...
                assert(is_proposal_finalized(Some(proposal_1), store_certificate.get("n4"))),
                // ... but pending: P1's parent notarization is missing locally, so nothing
                // is committed and the committed watermark has not moved
                assert(pending_finalizations(store_certificate.get("n4")) == Set(proposal_1)),
                assert(ghost_committed_blocks.get("n4") == List()),
                assert(replica_state.get("n4").last_finalized == GENESIS_VIEW),
                // the state is fully accounted for: nothing disappeared, nothing objects
                assert(all_invariants),
                unchanged_all,
            })

            // === backfill: the missing parent notarization arrives ===
            .then(on_certificate("n4", notarization_0))
            .then(all {
                // the ancestry is now complete: the chain and the watermark advance
                // together, and the pending set drains; the finalization was never lost,
                // only waiting
                assert(ghost_committed_blocks.get("n4") == List(proposal_0, proposal_1)),
                assert(replica_state.get("n4").last_finalized == 1),
                assert(pending_finalizations(store_certificate.get("n4")) == Set()),
                assert(all_invariants),
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
