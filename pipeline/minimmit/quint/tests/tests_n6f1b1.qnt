module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    pure val VAL_B0 = mkBlock("val_b0", 0)
    pure val VAL_B1 = mkBlock("val_b1", 1)
    pure val VAL_B2 = mkBlock("val_b2", 1)
    pure val BLOCK_B = mkBlock(VAL_B0.id, 1)
    pure val FAKE_PARENT = mkBlock(VAL_B1.id, 0)
    pure val JOIN_BLOCK = mkBlock(VAL_B0.id, 2)
    import replica(
        N = 6,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        TWINS = Set(),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        BYZANTINE = Set("n5"),
        VIEWS = 0.to(6),
        VALID_BLOCK_IDS = Set(VAL_B0.id, VAL_B1.id, VAL_B2.id),
        INVALID_BLOCK_IDS = Set("inval_0", "inval_1")
    ).* from "../replica"

    run asuumptionsValidTest = all {
        L == 5,
        M == 3,
        assumptions_valid
    }

    run contradictionTest = {
        pure val proposal_from_n0 = {
            block: VAL_B0,
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        pure val proposal_from_n5_1 = {
            block: VAL_B1,
            view: 1,
            view_parent: 0,
            block_parent: VAL_B0,
            sig: sig_of("n5")
        }
        pure val proposal_from_n5_2 = {
            block: VAL_B2,
            view: 1,
            view_parent: 0,
            block_parent: VAL_B0,
            sig: sig_of("n5")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n1"))
            // === view 0 ===
            .then(proposer_step("n0", VAL_B0.id, GENESIS_BLOCK, GENESIS_VIEW))
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

            // n0-n2 receive 2 votes each for b0
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_1, "n0"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_1, "n1"))


            .then(replica_receives_notarize_vote("n1", proposal_from_n5_1, "n0"))
            .then(replica_receives_notarize_vote("n1", proposal_from_n5_1, "n1"))


            .then(replica_receives_notarize_vote("n2", proposal_from_n5_1, "n0"))
            .then(replica_receives_notarize_vote("n2", proposal_from_n5_1, "n1"))


            // n0 receives 2 other votes for b1 and 1 nullify
            .then(replica_receives_nullify_vote("n0", 1, "n3"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_2, "n4"))
            .then(replica_receives_notarize_vote("n0", proposal_from_n5_2, "n5"))

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n0").nullified == false),
                assert(is_contradicted(replica_state.get("n0"), 1, store_vote.get("n0")) == true),
                unchanged_all,
            })

            .then(on_nullify_by_contradiction("n0", 1))
            .expect(all_invariants)

            .then(all {
                assert(store_vote.get("n0").filter(v=>vote_view(v)==1).size() == 5),
                assert(replica_state.get("n0").nullified == true),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    action inject_proposal(proposal: Proposal): bool = all {
        or {
            not(ghost_block_parent.keys().contains(proposal.block)),
            ghost_block_parent.get(proposal.block) == proposal.block_parent,
        },
        sent_proposal' = sent_proposal.union(Set(proposal)),
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        ghost_block_parent' = ghost_block_parent.put(proposal.block, proposal.block_parent),
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
        ghost_block_parent' = ghost_block_parent,
        leader' = leader,
        replica_state' = replica_state,
    }

     action replica_receives_notarize_vote(id: ReplicaId, p: Proposal, src: ReplicaId): bool =
        on_vote_notarize(id, p, Set(notarize(p, src)))

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: str): bool =
        on_vote_nullify(id, view, Set(nullify(view, src)))

    action unchanged_all = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        ghost_block_parent' = ghost_block_parent,
        leader' = leader,
        replica_state' = replica_state,
    }

    def proposal(
        proposer: ReplicaId,
        block: Block,
        view: ViewNumber,
        parent: Block,
        parentView: ViewNumber,
    ): Proposal = {
        {
            block: block,
            view: view,
            view_parent: parentView,
            block_parent: parent,
            sig: sig_of(proposer),
        }
    }

    def mkFinalization(
        sender: ReplicaId,
        p: Proposal,
    ): Certificate = {
        finalization(p, CORRECT, sender)
    }

    def mkNotarization(
        sender: ReplicaId,
        p: Proposal,
        signatures: Set[Signature],
    ): Certificate = {
        notarization(p, signatures, sender)
    }

    pure val ATTACK_PROPOSAL: Proposal = {
        view: 2,
        view_parent: 1,
        block: BLOCK_B,
        block_parent: FAKE_PARENT,
        sig: sig_of("n5"),
    }

    pure val ATTACK_CERTIFICATE: Certificate =
        notarization(ATTACK_PROPOSAL, Set(), "n5")

    // A deterministic branch of byzantine_replica_step: no votes, one
    // uncertified certificate, and the forged proposal used by this test.
    action injectAttackProposal = all {
        sent_proposal' = sent_proposal.union(Set(ATTACK_PROPOSAL)),
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate.union(Set(ATTACK_CERTIFICATE)),
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        ghost_block_parent' = ghost_block_parent.put(
            ATTACK_PROPOSAL.block, ATTACK_PROPOSAL.block_parent),
        leader' = leader,
        replica_state' = replica_state,
    }

    // Concrete choices from correct_replica_step. The membership checks are
    // the message-selection guards imposed by step.
    action receiveProposal(id: ReplicaId, p: Proposal): bool = all {
        p.in(sent_proposal),
        on_proposal(id, p),
    }

    action receiveAllNotarizeVotes(
        id: ReplicaId,
        p: Proposal,
    ): bool = {
        val votes = CORRECT.map(src => notarize(p, src))
        all {
            votes != Set(),
            votes.subseteq(sent_vote),
            on_vote_notarize(id, p, votes),
        }
    }

    action receiveNotarizeVotes(id: ReplicaId, p: Proposal, votes: Set[Vote]): bool = all {
        votes != Set(),
        votes.subseteq(sent_vote),
        on_vote_notarize(id, p, votes),
    }

    action receiveCertificate(id: ReplicaId, cert: Certificate): bool = all {
        cert.in(sent_certificate),
        on_certificate(id, cert),
    }

    action finalizeBlock0 = {
        val p = proposal("n1", VAL_B0, 0, GENESIS_BLOCK, GENESIS_VIEW)
        proposer_step("n1", VAL_B0.id, GENESIS_BLOCK, GENESIS_VIEW)
            .then(receiveProposal("n0", p))
            .then(receiveProposal("n2", p))
            .then(receiveProposal("n3", p))
            .then(receiveProposal("n4", p))
            .then(receiveAllNotarizeVotes("n0", p))
            .then(receiveCertificate("n1", mkFinalization("n0", p)))
            .then(receiveCertificate("n2", mkFinalization("n0", p)))
            .then(receiveCertificate("n3", mkFinalization("n0", p)))
            .then(receiveCertificate("n4", mkFinalization("n0", p)))
    }

    action finalizeBlockA = {
        val p = proposal("n2", VAL_B1, 1, VAL_B0, 0)
        proposer_step("n2", VAL_B1.id, VAL_B0, 0)
            .then(receiveProposal("n0", p))
            .then(receiveProposal("n1", p))
            .then(receiveProposal("n3", p))
            .then(receiveProposal("n4", p))
            .then(receiveAllNotarizeVotes("n0", p))
            .then(receiveCertificate("n1", mkFinalization("n0", p)))
            .then(receiveCertificate("n2", mkFinalization("n0", p)))
            .then(receiveCertificate("n3", mkFinalization("n0", p)))
            .then(receiveCertificate("n4", mkFinalization("n0", p)))
    }

    // Replay from the repository root with:
    //
    // quint test --backend=rust \
    //   --match=parentHeightCertificateTest tests/tests_n6f1b1.qnt
    //
    // The fixed leaders and injected Byzantine proposal reproduce the attack
    // without making the test depend on the evaluator's random seed.
    // The forged proposal reuses the certified block id at a different height.
    run parentHeightCertificateTest =
        initWithLeader(Map(
            0 -> "n1", 1 -> "n2", 2 -> "n5",
            3 -> "n0", 4 -> "n0", 5 -> "n0"))
            .then(injectAttackProposal)
            .then(finalizeBlock0)
            .then(finalizeBlockA)
            .expect(all {
                N == 6,
                F == 1,
                CORRECT == Set("n0", "n1", "n2", "n3", "n4"),
                BYZANTINE == Set("n5"),
                assumptions_valid,
                leader.get(0) == "n1",
                leader.get(1) == "n2",
                leader.get(2) == "n5",
                ATTACK_PROPOSAL.in(sent_proposal),
                VAL_B1.id == FAKE_PARENT.id,
                VAL_B1 != FAKE_PARENT,
                BLOCK_B.ghost_height == FAKE_PARENT.ghost_height + 1,
                VAL_B1.ghost_height == BLOCK_B.ghost_height,
                VAL_B1 != BLOCK_B,
                valid_parent(
                    2, 1, VAL_B1, store_certificate.get("n0")),
                not(valid_parent(
                    2, 1, FAKE_PARENT, store_certificate.get("n0"))),
                not(store_certificate.get("n0").exists(cert => and {
                    cert_view(cert) == 1,
                    cert_block(cert) == FAKE_PARENT,
                })),
                CORRECT.forall(id =>
                    not(ghost_proposal.get(id).contains(ATTACK_PROPOSAL))),
                not(sent_vote.exists(vote => and {
                    CORRECT.contains(vote_sig(vote)),
                    vote_view(vote) == 2,
                    vote_block(vote) == BLOCK_B,
                })),
                CORRECT.forall(id =>
                    ghost_committed_blocks.get(id) == Set(VAL_B0, VAL_B1)),
                agreement,
            })

    // A block has one globally fixed parent. Once the first proposal establishes
    // that relationship, a proposal reusing the block with another parent is
    // invalid and cannot collect votes.
    run blockParentUniquenessTest = {
        val proposal_a_v1 =
            proposal("n5", VAL_B1, 1, VAL_B0, 0)
        val proposal_b_v1 =
            proposal("n5", VAL_B2, 1, VAL_B0, 0)
        val cert_a_v1 =
            mkNotarization("n0", proposal_a_v1, Set("n0", "n1", "n5"))
        val cert_b_v1 =
            mkNotarization("n2", proposal_b_v1, Set("n2", "n3", "n4"))
        val proposal_join_via_a =
            proposal("n5", JOIN_BLOCK, 2, VAL_B1, 1)
        val proposal_join_via_b =
            proposal("n5", JOIN_BLOCK, 2, VAL_B2, 1)
        val proposal0 =
            proposal("n1", VAL_B0, 0, GENESIS_BLOCK, GENESIS_VIEW)
        val join_votes = Set(
            notarize(proposal_join_via_a, "n0"),
            notarize(proposal_join_via_a, "n1")
        )

        initWithLeader(Map(
            0 -> "n1", 1 -> "n5", 2 -> "n5",
            3 -> "n0", 4 -> "n0", 5 -> "n0"))
            .then(finalizeBlock0)

            // View 1: Byzantine leader creates two M-notarized parents.
            .then(inject_proposal(proposal_a_v1))
            .then(inject_proposal(proposal_b_v1))
            .then(receiveProposal("n0", proposal_a_v1))
            .then(receiveProposal("n1", proposal_a_v1))
            .then(receiveProposal("n2", proposal_b_v1))
            .then(receiveProposal("n3", proposal_b_v1))
            .then(receiveProposal("n4", proposal_b_v1))
            .then(inject_vote(notarize(proposal_a_v1, sig_of("n5"))))

            .then(replica_receives_notarize_vote("n0", proposal_a_v1, "n0"))
            .then(replica_receives_notarize_vote("n0", proposal_a_v1, "n1"))
            .then(replica_receives_notarize_vote("n0", proposal_a_v1, "n5"))
            .then(receiveCertificate("n1", cert_a_v1))

            .then(replica_receives_notarize_vote("n2", proposal_b_v1, "n2"))
            .then(replica_receives_notarize_vote("n2", proposal_b_v1, "n3"))
            .then(replica_receives_notarize_vote("n2", proposal_b_v1, "n4"))
            .then(receiveCertificate("n3", cert_b_v1))
            .then(receiveCertificate("n4", cert_b_v1))

            // View 2: establish VAL_B1 as the unique parent of JOIN_BLOCK.
            .then(inject_proposal(proposal_join_via_a))
            .then(receiveProposal("n0", proposal_join_via_a))
            .then(receiveProposal("n1", proposal_join_via_a))

            .expect(all {
                VAL_B1 != VAL_B2,
                VAL_B1.ghost_height == VAL_B2.ghost_height,
                JOIN_BLOCK.ghost_height == VAL_B1.ghost_height + 1,
                proposal_join_via_a.block == proposal_join_via_b.block,
                proposal_join_via_a.block_parent != proposal_join_via_b.block_parent,
                proposal_join_via_a.block_parent.ghost_height ==
                    proposal_join_via_b.block_parent.ghost_height,
                ghost_block_parent.keys().contains(JOIN_BLOCK),
                ghost_block_parent.get(JOIN_BLOCK) == VAL_B1,
                is_proposal_with_valid_parent_block(proposal_join_via_a),
                not(is_proposal_with_valid_parent_block(proposal_join_via_b)),
                proposal_join_via_a.in(sent_proposal),
                not(proposal_join_via_b.in(sent_proposal)),
                ghost_proposal.get("n0").contains(proposal_join_via_a),
                ghost_proposal.get("n1").contains(proposal_join_via_a),
                CORRECT.forall(id =>
                    not(ghost_proposal.get(id).contains(proposal_join_via_b))),
                join_votes.subseteq(sent_vote),
                join_votes.map(v => vote_sig(v)) == Set("n0", "n1"),
                select_notarize_votes_for_proposal(proposal_join_via_a, join_votes)
                    .map(v => vote_sig(v)) == Set("n0", "n1"),
                select_notarize_votes_for_proposal(proposal_join_via_b, join_votes) == Set(),
                not(is_view_finalized_votes(proposal_join_via_a, join_votes)),
                not(is_view_finalized_votes(proposal_join_via_b, join_votes)),
                CORRECT.forall(id =>
                    not(store_certificate.get(id).exists(cert => and {
                        cert_view(cert) == 2,
                        cert_kind(cert) == FinalizationKind,
                        cert_block(cert) == JOIN_BLOCK,
                    }))),
                CORRECT.forall(id =>
                    ghost_committed_blocks.get(id) == Set(proposal0.block)),
                validity,
                agreement,
                all_invariants,
            })
    }

    // Finalizing a proposal should also commit its ancestors. This trace
    // finalizes proposal_child while proposal_parent is only notarized.
    run ancestorCommitOnFinalizationTest = {
        val proposal0 =
            proposal("n1", VAL_B0, 0, GENESIS_BLOCK, GENESIS_VIEW)
        val proposal_parent =
            proposal("n5", VAL_B1, 1, VAL_B0, 0)
        val cert_parent =
            mkNotarization("n0", proposal_parent, Set("n0", "n1", "n5"))
        val proposal_child =
            proposal("n5", JOIN_BLOCK, 2, VAL_B1, 1)

        initWithLeader(Map(
            0 -> "n1", 1 -> "n5", 2 -> "n5",
            3 -> "n0", 4 -> "n0", 5 -> "n0"))
            .then(finalizeBlock0)

            // View 1: only M-notarize the parent, so it is a valid parent
            // for view 2 but is not itself finalized.
            .then(inject_proposal(proposal_parent))
            .then(receiveProposal("n0", proposal_parent))
            .then(receiveProposal("n1", proposal_parent))
            .then(inject_vote(notarize(proposal_parent, sig_of("n5"))))
            .then(replica_receives_notarize_vote("n0", proposal_parent, "n0"))
            .then(replica_receives_notarize_vote("n0", proposal_parent, "n1"))
            .then(replica_receives_notarize_vote("n0", proposal_parent, "n5"))

            // Share the parent notarization so every correct replica can
            // validate a child proposal in view 2.
            .then(receiveCertificate("n1", cert_parent))
            .then(receiveCertificate("n2", cert_parent))
            .then(receiveCertificate("n3", cert_parent))
            .then(receiveCertificate("n4", cert_parent))

            // View 2: finalize the child.
            .then(inject_proposal(proposal_child))
            .then(receiveProposal("n0", proposal_child))
            .then(receiveProposal("n1", proposal_child))
            .then(receiveProposal("n2", proposal_child))
            .then(receiveProposal("n3", proposal_child))
            .then(receiveProposal("n4", proposal_child))
            .then(receiveAllNotarizeVotes("n0", proposal_child))
            .then(receiveCertificate("n1", mkFinalization("n0", proposal_child)))
            .then(receiveCertificate("n2", mkFinalization("n0", proposal_child)))
            .then(receiveCertificate("n3", mkFinalization("n0", proposal_child)))
            .then(receiveCertificate("n4", mkFinalization("n0", proposal_child)))

            .expect(all {
                is_view_notarized(1, store_certificate.get("n0")),
                is_view_finalized(2, store_certificate.get("n0")),
                CORRECT.forall(id =>
                    ghost_committed_blocks.get(id).contains(proposal0.block)),
                CORRECT.forall(id =>
                    ghost_committed_blocks.get(id).contains(proposal_child.block)),
                CORRECT.forall(id =>
                    ghost_committed_blocks.get(id).contains(proposal_parent.block)),
                CORRECT.forall(id =>
                    Set(proposal0.block, proposal_parent.block, proposal_child.block)
                        == ghost_committed_blocks.get(id)),
                agreement,
                all_invariants,
            })
    }
}
