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
        REPLICA_LIST = ["n0", "n1", "n2", "n3"],
        VIEWS = 1.to(6),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    pure val CERTIFY_ALL_TRUE = Replicas.mapBy(_ => app::certify_always_true)

    run invalidLeaderProposalTriggersNullifyTest = {
        val invalid_proposal = {
            block: "inv_b3",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n3")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n1", 1 -> "n2", 2 -> "n3", 3 -> "n0", 4 -> "n1", 5 -> "n2", 6 -> "n3"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(invalid_proposal))
            .then(on_proposal("n0", invalid_proposal))
            .then(on_proposal("n1", invalid_proposal))
            .then(on_proposal("n2", invalid_proposal))
            .then(all {
                assert(sent_vote.exists(v => vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                assert(replica_state.get("n0").nullified == true),
                assert(replica_state.get("n0").view == FIRST_VIEW),
                unchanged_all,
            })
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n0"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n1"))
            .then(replica_receives_nullify_vote("n0", FIRST_VIEW, "n2"))
            .then(all {
                assert(store_certificate.get("n0").exists(c => cert_kind(c) == NullificationKind and cert_view(c) == FIRST_VIEW)),
                assert(replica_state.get("n0").view == 3),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    run finalizationCertificateAdvancesViewTest = {
        val proposal = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }
        // Cert assembled by n0 from finalize votes of n0, n1, and n3 (byzantine).
        val cert = finalization(FIRST_VIEW, "val_b0", Set("n0", "n1", "n3"), "n0")

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n2", 1 -> "n3", 2 -> "n0", 3 -> "n1", 4 -> "n2", 5 -> "n3", 6 -> "n0"),
            CERTIFY_ALL_TRUE
        )
            .then(inject_proposal(proposal))
            .then(on_proposal("n0", proposal))
            .then(on_proposal("n1", proposal))
            .then(on_proposal("n2", proposal))
            // n0 sees notarize quorum -> notarization, certifies, sends finalize
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n2"))
            // n1 sees notarize quorum -> notarization, certifies, sends finalize
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", FIRST_VIEW, "n2"))
            // n3 (byzantine) also sent a finalize vote
            .then(inject_vote(finalize(FIRST_VIEW, "n3", "val_b0")))
            // n2 receives finalization cert from network (has not seen notarize quorum)
            .then(on_certificate("n2", cert))
            .then(all {
                assert(store_certificate.get("n2").exists(c => cert_kind(c) == FinalizationKind and cert_view(c) == FIRST_VIEW and cert_block(c) == Some("val_b0"))),
                assert(replica_state.get("n2").view == 3),
                assert(replica_state.get("n2").last_finalized == FIRST_VIEW),
                assert(ghost_committed_blocks.get("n2").length() == 1),
                assert(ghost_committed_blocks.get("n2")[0] == "val_b0"),
                unchanged_all,
            })
            .expect(all_invariants)
    }

    // Byzantine n3 (leader) equivocates with two proposals having different parents.
    // Parent conflict does NOT immediately trigger a nullify vote upon notarization.
    // Finalization is blocked by equivocation; the certification timeout handles nullification.
    run parentConflictDoesNotImmediatelyNullifyTest = {
        // Byzantine n3 sends two proposals: same (view, block) but different parents.
        val proposal_a = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n3")
        }
        val proposal_b = {
            block: "val_b0",
            view: FIRST_VIEW,
            view_parent: GENESIS_VIEW,
            block_parent: "val_b1",
            sig: sig_of("n3")
        }

        initWithLeaderAndCertifyTimeout(
            Map(0 -> "n1", 1 -> "n2", 2 -> "n3", 3 -> "n0", 4 -> "n1", 5 -> "n2", 6 -> "n3"),
            CERTIFY_ALL_TRUE
        )
            // n0 and n1 see proposal A and notarize.
            .then(inject_proposal(proposal_a))
            .then(on_proposal("n0", proposal_a))
            .then(on_proposal("n1", proposal_a))

            // n2 sees equivocating proposal B -> nullifies (unique_parent is false).
            .then(inject_proposal(proposal_b))
            .then(on_proposal("n2", proposal_b))
            .then(all {
                assert(sent_vote.exists(v =>
                    vote_sig(v) == "n2" and vote_view(v) == FIRST_VIEW and is_nullify(v))),
                unchanged_all,
            })

            // Byzantine n3 also sent a notarize vote.
            .then(inject_vote(notarize(FIRST_VIEW, "n3", "val_b0")))

            // n0 receives notarize quorum (n0, n1, n3) -> notarization forms.
            // parent_conflicted is true but no immediate nullify with the fix.
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", FIRST_VIEW, "n3"))

            .then(all {
                assert(store_certificate.get("n0").exists(c =>
                    is_notarization_cert(c) and cert_view(c) == FIRST_VIEW
                    and cert_block(c) == Some("val_b0"))),
                // n0 did NOT send nullify despite parent conflict.
                assert(not(sent_vote.exists(v =>
                    vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_nullify(v)))),
                // n0 did NOT send finalize (blocked by parent conflict).
                assert(not(sent_vote.exists(v =>
                    vote_sig(v) == "n0" and vote_view(v) == FIRST_VIEW and is_finalize(v)))),
                // n0 is still in the current view (waiting for timeout).
                assert(replica_state.get("n0").view == FIRST_VIEW),
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
        parent_refs' = parent_refs,
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
        parent_refs' = parent_refs,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_vote",
    }

    action replica_receives_notarize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_notarize(id, view, block, Set(notarize(view, src, block)))

    action replica_receives_finalize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_finalize(id, view, block, Set(finalize(view, src, block)))

    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: ReplicaId): bool =
        on_vote_nullify(id, view, Set(nullify(view, src)))

    action unchanged_all = all {
        sent_proposal' = sent_proposal,
        sent_vote' = sent_vote,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        parent_refs' = parent_refs,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = lastAction,
    }
}
