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
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
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
                // only n0 and n1 ever voted, and only because `_process_certificate` made
                // them notarize the certificate's own proposal on accepting the forgery
                assert(not(certificates_are_backed)),
                assert(not(validity)),
                assert(not(all_invariants)),
                unchanged_all,
            })
            .expect(not(certificates_are_backed))
            .expect(not(validity))
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
                assert(all_invariants),
                unchanged_all,
            })
            .expect(certificates_are_backed)
            .expect(all_invariants)
    }

    // Regression test for the "one byzantine proposal un-commits a finalized block" defect.
    //
    // The parent link of a committed block used to be derived from the global
    // `sent_proposal` by `claimed_view_parent`, which returned None as soon as two proposals
    // for the same (block, view) disagreed about `view_parent`. `byzantine_replica_step`
    // injects one proposal per step, choosing `view` and `view_parent` freely from VIEWS,
    // and nothing requires `view_parent < view`. A single such message aimed at an already
    // finalized (block, view) turned its link into None -- permanently, because
    // `sent_proposal` is never pruned. The committed chain is rebuilt from scratch whenever
    // a replica stores a new certificate, so the next certificate any replica processed
    // dropped every block it had committed, and no conjunct of `all_invariants` noticed:
    // `agreement` only asks that the shorter chain be a prefix of the longer one, and the
    // empty list is a prefix of everything.
    //
    // A certificate now carries the proposal it certifies, and `next_committable_cert` reads
    // the parent link off that proposal, so the link is decided when the block is proposed
    // and nothing outside the certificate can move it afterwards. The shadow below names an
    // already finalized block with a different parent, which makes it a *different*
    // proposal: no certificate names it, and `sent_proposal` is not consulted while
    // rebuilding at all, so the committed chain is untouched and keeps growing. This closes
    // the byzantine LEADER case as well -- a second leader-signed proposal for the same
    // (block, view) is likewise a different proposal, and votes for it never join the first
    // one's quorum.
    run committedChainRollbackTest = {
        pure val proposal_0 = {
            block: "val_b0", view: 0,
            view_parent: GENESIS_VIEW, block_parent: GENESIS_BLOCK, sig: sig_of("n0")
        }
        pure val proposal_1 = {
            block: "val_b1", view: 1,
            view_parent: 0, block_parent: "val_b0", sig: sig_of("n1")
        }
        // The byzantine shadow of the already finalized (val_b0, view 0), claiming a
        // different parent view. Every field is one byzantine_replica_step can produce:
        // view and view_parent in VIEWS, block and block_parent in AllBlocks, sig in BYZANTINE.
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

            // === the byzantine message that used to do the damage ===
            .then(inject_proposal(byz_shadow_of_view_0))
            .then(all {
                // the shadow is a different proposal from the finalized one, and no
                // certificate certifies it, so the committed chain cannot see it at all
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
                // the chain GROWS -- before the fix this rebuilt to List()
                assert(ghost_committed_blocks.get("n0") == List(proposal_0, proposal_1)),
                // its peers, which processed no new certificate, still hold the prefix
                assert(ghost_committed_blocks.get("n2") == List(proposal_0)),
                assert(all_invariants),
                unchanged_all,
            })
            .expect(all_invariants)
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

    // Regression test for the "commit skips its ancestors" defect.
    //
    // A replica enters the next view as soon as it sees M notarize votes, but it only
    // commits once it sees L of them. When `ghost_committed_blocks` was accumulated by
    // appending `cert.block`, a replica that saw view 0 as a notarization and then
    // finalized view 1 recorded ["val_b1"] while a peer that finalized view 0 recorded
    // ["val_b0"] -- two sequences of equal length differing at index 0, so `agreement`
    // failed. Now the chain is rebuilt from the stored certificates by walking forward
    // from genesis, so n3 cannot reach val_b1 without finalization(val_b0, 0) and
    // commits nothing instead.
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

            // n3 sees all L = 5 votes for view 1 and finalizes it, but it holds only
            // notarization(val_b0, 0), so the walk from genesis cannot reach val_b1.
            .then(replica_receives_notarize_votes("n3", proposal_from_n1, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                assert(replica_state.get("n3").last_finalized == 1),
                assert(ghost_committed_blocks.get("n0") == List(proposal_from_n0)),
                assert(ghost_committed_blocks.get("n3") == List()),
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

            // P1 is finalized, but rebuild_committed_chain cannot traverse
            // through P0 because P0 has only a notarization certificate.
            assert(replica_state.get("n0").last_finalized == 1),
            assert(ghost_committed_blocks.get("n0") == List(proposal_0, proposal_1)),

            // The mismatch is invisible to the encoded invariants.
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

    // Regression test: the conservative "commit only blocks with their own finalization" rule in
    // `rebuild_committed_chain` is REQUIRED for safety. Committing notarized-only ancestors -- a
    // naive reading of minimmit.md 8.4 "finalize c and all of its ancestors" -- would break
    // `agreement` in this model.
    //
    // A Block is a plain string and a child proposal's parent pointer is only
    // (block_parent, view_parent); it does NOT identify the parent's full proposal. So a
    // byzantine leader can equivocate a block's PARENT: two notarizations for the SAME block
    // val_b2 at view 1 with DIFFERENT parents (val_b0 vs val_b1), each backed by M = 3 votes
    // (2 honest that split on the view-0 parent, plus the byzantine key in both). A child Y at
    // view 2 built on val_b2@1 then finalizes with L = 5 notarize votes, but its ancestry BELOW
    // val_b2 is ambiguous: replica n0 (holding notarization(prop_x_via_a)) reconstructs
    // [val_b0, val_b2, val_b0] while n2 (holding notarization(prop_x_via_b)) reconstructs
    // [val_b1, val_b2, val_b0] -- divergent at index 0.
    //
    // The current model commits nothing here, because Y's parent val_b2@1 has no finalization of
    // its own (a finalization would pin the exact proposal via the L + M > N + F intersection).
    // This test pins that down: if `rebuild_committed_chain` is ever changed to finalize
    // notarized-only ancestors, the `ghost_committed_blocks == List()` / `all_invariants`
    // assertions fail, and `naive_ancestor_blocks` shows the concrete fork such a change causes.
    // (The real protocol avoids the ambiguity by using block digests, minimmit.md 10, so a block
    // commits to its parent; the model's plain-string blocks do not.)
    run equivocatedAncestorTest = {
        pure val prop_a0 = { block: "val_b0", view: 0, block_parent: GENESIS_BLOCK, view_parent: GENESIS_VIEW, sig: sig_of("n5") }
        pure val prop_b0 = { block: "val_b1", view: 0, block_parent: GENESIS_BLOCK, view_parent: GENESIS_VIEW, sig: sig_of("n5") }
        // same block val_b2 at view 1, two different parents (byzantine leader equivocates the parent)
        pure val prop_x_via_a = { block: "val_b2", view: 1, block_parent: "val_b0", view_parent: 0, sig: sig_of("n5") }
        pure val prop_x_via_b = { block: "val_b2", view: 1, block_parent: "val_b1", view_parent: 0, sig: sig_of("n5") }
        // finalized child at view 2, built on block val_b2@1
        pure val prop_y = { block: "val_b0", view: 2, block_parent: "val_b2", view_parent: 1, sig: sig_of("n0") }
        pure val notarization_a0 = notarization(prop_a0, Set("n0", "n1", "n5"), sig_of("n0"))
        pure val notarization_x_via_a = notarization(prop_x_via_a, Set("n0", "n1", "n5"), sig_of("n0"))

        initWithLeader(Map(0 -> "n5", 1 -> "n5", 2 -> "n0", 3 -> "n0",
                           4 -> "n0", 5 -> "n0", 6 -> "n0", 7 -> "n0", 8 -> "n0"))
            // === view 0: byzantine leader n5 broadcasts two different blocks ===
            .then(inject_proposal(prop_a0))
            .then(inject_proposal(prop_b0))
            .then(on_proposal("n0", prop_a0))
            .then(on_proposal("n1", prop_a0))
            .then(on_proposal("n2", prop_b0))
            .then(on_proposal("n3", prop_b0))
            .then(inject_vote(notarize(prop_a0, sig_of("n5"))))
            .then(inject_vote(notarize(prop_b0, sig_of("n5"))))
            // assemble the two view-0 notarizations; replicas enter view 1
            .then(replica_receives_notarize_votes("n0", prop_a0, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n1", prop_a0, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n2", prop_b0, Set("n2", "n3", "n5")))
            .then(replica_receives_notarize_votes("n3", prop_b0, Set("n2", "n3", "n5")))
            .then(on_certificate("n4", notarization_a0))   // n4 adopts a0 and enters view 1
            // === view 1: byzantine leader n5 broadcasts SAME block val_b2 with two parents ===
            .then(inject_proposal(prop_x_via_a))
            .then(inject_proposal(prop_x_via_b))
            .then(on_proposal("n0", prop_x_via_a))
            .then(on_proposal("n1", prop_x_via_a))
            .then(on_proposal("n2", prop_x_via_b))
            .then(on_proposal("n3", prop_x_via_b))
            .then(inject_vote(notarize(prop_x_via_a, sig_of("n5"))))
            .then(inject_vote(notarize(prop_x_via_b, sig_of("n5"))))
            .then(replica_receives_notarize_votes("n0", prop_x_via_a, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n1", prop_x_via_a, Set("n0", "n1", "n5")))
            .then(replica_receives_notarize_votes("n2", prop_x_via_b, Set("n2", "n3", "n5")))
            .then(replica_receives_notarize_votes("n3", prop_x_via_b, Set("n2", "n3", "n5")))
            .then(on_certificate("n4", notarization_x_via_a))   // n4 adopts x_via_a and enters view 2
            // === view 2: honest leader n0 proposes Y on val_b2@1; all five notarize -> finalize ===
            .then(proposer_step("n0", "val_b0", "val_b2", 1))
            .then(on_proposal("n1", prop_y))
            .then(on_proposal("n2", prop_y))
            .then(on_proposal("n3", prop_y))
            .then(on_proposal("n4", prop_y))
            .then(replica_receives_notarize_votes("n0", prop_y, Set("n0", "n1", "n2", "n3", "n4")))
            .then(replica_receives_notarize_votes("n2", prop_y, Set("n0", "n1", "n2", "n3", "n4")))
            .then(all {
                // Y is finalized at two correct replicas
                assert(is_proposal_finalized(Some(prop_y), store_certificate.get("n0"))),
                assert(is_proposal_finalized(Some(prop_y), store_certificate.get("n2"))),
                // they hold a notarization for the SAME block val_b2 at view 1, DIFFERENT parents
                assert(store_certificate.get("n0").exists(c => and {
                    cert_kind(c) == NotarizationKind, cert_view(c) == 1, cert_proposal(c) == Some(prop_x_via_a),
                })),
                assert(store_certificate.get("n2").exists(c => and {
                    cert_kind(c) == NotarizationKind, cert_view(c) == 1, cert_proposal(c) == Some(prop_x_via_b),
                })),
                // CURRENT (conservative) model commits nothing for either => agreement holds
                assert(ghost_committed_blocks.get("n0") == List()),
                assert(ghost_committed_blocks.get("n2") == List()),
                assert(all_invariants),
                // A naive 8.4 ancestor-walk WOULD fork the committed chain (divergent at index 0):
                assert(naive_ancestor_blocks(prop_y, store_certificate.get("n0")) == List("val_b0", "val_b2", "val_b0")),
                assert(naive_ancestor_blocks(prop_y, store_certificate.get("n2")) == List("val_b1", "val_b2", "val_b0")),
                unchanged_all,
            })
            .expect(all_invariants)
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

    // Hypothetical "finalize c and all of its ancestors" (minimmit.md 8.4), used ONLY by
    // `equivocatedAncestorTest` to show why it is unsafe here: walk down from a finalized
    // proposal following (block_parent, view_parent), taking any notarized/finalized proposal
    // for that (block, view). Because a block does not commit to its parent, this walk is
    // ambiguous under a parent-equivocating byzantine leader and can return different chains at
    // different replicas. Returns the committed blocks genesis-first. Not part of the model.
    def naive_ancestor_blocks(target: Proposal, certs: Set[Certificate]): List[Block] = {
        VIEWS.fold((target, List(target.block), false), (acc, _v) => {
            val cur = acc._1
            val blocks = acc._2
            val done = acc._3
            if (done) acc
            else if (cur.view_parent == GENESIS_VIEW and cur.block_parent == GENESIS_BLOCK)
                (cur, blocks, true)
            else {
                val parents = certs.filter(c => and {
                    cert_kind(c) == NotarizationKind or cert_kind(c) == FinalizationKind,
                    cert_view(c) == cur.view_parent,
                    cert_proposal(c).option_has(pp => pp.block == cur.block_parent),
                }).fold(Set(), (s, c) => match cert_proposal(c) { | Some(pp) => s.union(Set(pp)) | None => s })
                if (parents.size() >= 1) {
                    val parent = parents.fold(GENESIS_PROPOSAL, (_a, pp) => pp)
                    (parent, List(parent.block).concat(blocks), false)
                } else (cur, blocks, true)
            }
        })._2
    }
}
