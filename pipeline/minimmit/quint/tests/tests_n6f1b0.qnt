module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import replica(
        N = 6,
        F = 1,
        CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5"->"n5"),
        BYZANTINE = Set(),
        VIEWS = 0.to(5),
        VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
        INVALID_BLOCKS = Set("inv_b3")
    ).* from "../replica"

    run asuumptionsValidTest = all {
        L == 5,
        M == 3,
        assumptions_valid
    }

    // Simple init test
    run initTest = {
        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            .then(all {
                assert(replica_state.get("n0").view == 0),
                assert(replica_state.get("n1").view == 0),
                assert(replica_state.get("n2").view == 0),
                assert(replica_state.get("n3").view == 0),
                assert(replica_state.get("n4").view == 0),
                assert(replica_state.get("n5").view == 0),
                assert(leader.get(1) == "n0"),
                unchanged_all
            })}

    // Minimal test without init
    run minimalProposalTest = {
        // Manual state setup
        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
        .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
        .then(all {
            assert(sent_proposal.size() == 1),
            unchanged_all
        })
    }

    run happyPathTest = {
        val proposal = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // Leader n0 proposes in view 0
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then( all {
                assert(replica_state.get("n0").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)
            // All replicas process the proposal and vote for it (n0 already did!)
            .then(on_proposal("n1", proposal))
            .then( all {
                assert(replica_state.get("n1").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n2", proposal))
            .then( all {
                assert(replica_state.get("n2").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n3", proposal))
            .then( all {
                assert(replica_state.get("n3").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n4", proposal))
            .then( all {
                assert(replica_state.get("n4").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n5", proposal))
            .then( all {
                assert(replica_state.get("n5").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)

            // All replicas collect votes and notarize the block
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(all{
                assert(store_certificate.get("n0").size() == 0),
                assert(replica_state.get("n0").ghost_last_seen_notarization==-1),
                assert(replica_state.get("n0").view==0),
                assert(replica_state.get("n0").last_finalized==-1),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))
            .then(all{
                assert(replica_state.get("n0").view==1),
                assert(replica_state.get("n0").ghost_last_seen_notarization==0),
                assert(replica_state.get("n0").last_finalized==-1),
                assert(store_certificate.get("n0").size() == 1),
                assert(store_certificate.get("n1").size() == 0),
                assert(is_view_notarized(0, store_certificate.get("n0"))),
                assert(is_view_notarized_votes(0, store_vote.get("n0"), proposal.block)),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))
            .then(all{
                assert(store_certificate.get("n0").size() == 1),
                unchanged_all
            })
            
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))
            .then(all{
                assert(store_certificate.get("n0").size() == 2),
                assert(replica_state.get("n0").ghost_last_seen_notarization==0),
                assert(replica_state.get("n0").last_finalized==0),
                unchanged_all
            })

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n5"))

            .expect(select_votes(0, NotarizeKind, store_vote.get("n0")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n1")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n2")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n3")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n4")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n5")).size()==6)

            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0"))

            .expect(store_certificate.get("n0").size() == 2)
            .expect(store_certificate.get("n1").size() == 2)
            .expect(store_certificate.get("n2").size() == 2)
            .expect(store_certificate.get("n3").size() == 2)
            .expect(store_certificate.get("n4").size() == 2)
            .expect(store_certificate.get("n5").size() == 2)

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n1")))
            .expect(is_view_notarized(0, store_certificate.get("n2")))
            .expect(is_view_notarized(0, store_certificate.get("n3")))
            .expect(is_view_notarized(0, store_certificate.get("n4")))
            .expect(is_view_notarized(0, store_certificate.get("n5")))
            .expect(all_invariants)

            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })

            .then(all {
                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),
                unchanged_all,
            })
    }

    run n5NodeIsSlowAndGetFinalizationFirstTest = {
        val proposal = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        val cert_n0n1n2n3n4 = {
                view: 0,
                kind: FinalizationKind,
                block: "val_b0",
                signatures: Set("n0", "n1", "n2", "n3", "n4"),
                ghost_sender: sig_of("n0"),
            }

        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // Leader n0 proposes in view 0
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then( all {
                assert(replica_state.get("n0").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)
            // All replicas process the proposal and vote for it (n0 already did!)
            .then(on_proposal("n1", proposal))
            .then( all {
                assert(replica_state.get("n1").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n2", proposal))
            .then( all {
                assert(replica_state.get("n2").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n3", proposal))
            .then( all {
                assert(replica_state.get("n3").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n4", proposal))
            .then( all {
                assert(replica_state.get("n4").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n5", proposal))
            .then( all {
                assert(replica_state.get("n5").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)

            // All replicas collect votes and notarize the block
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(all{
                assert(store_certificate.get("n0").size() == 0),
                assert(replica_state.get("n0").ghost_last_seen_notarization==-1),
                assert(replica_state.get("n0").view==0),
                assert(replica_state.get("n0").last_finalized==-1),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))
            .then(all{
                assert(replica_state.get("n0").view==1),
                assert(replica_state.get("n0").ghost_last_seen_notarization==0),
                assert(replica_state.get("n0").last_finalized==-1),
                assert(store_certificate.get("n0").size() == 1),
                assert(store_certificate.get("n1").size() == 0),
                assert(is_view_notarized(0, store_certificate.get("n0"))),
                assert(is_view_notarized_votes(0, store_vote.get("n0"), proposal.block)),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))
            .then(all{
                assert(store_certificate.get("n0").size() == 1),
                unchanged_all
            })
            
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))
            .then(all{
                assert(store_certificate.get("n0").size() == 2),
                assert(replica_state.get("n0").ghost_last_seen_notarization==0),
                assert(replica_state.get("n0").last_finalized==0),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n5"))
            .then(all{
                assert(store_certificate.get("n0").size() == 2),
                assert(replica_state.get("n0").ghost_last_seen_notarization==0),
                assert(replica_state.get("n0").last_finalized==0),
                unchanged_all
            })

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))

            .then(all{
                assert(replica_state.get("n5").view==0),
                assert(replica_state.get("n5").ghost_last_seen_notarization==-1),
                assert(replica_state.get("n5").last_finalized==-1),
                assert(store_certificate.get("n5").size() == 0),
                assert(not(is_view_notarized(0, store_certificate.get("n5")))),
                assert(not(is_view_notarized_votes(0, store_vote.get("n5"), proposal.block))),
                unchanged_all
            })
            .then(replica_receives_certificate("n5", cert_n0n1n2n3n4))
            .then(all{
                assert(replica_state.get("n5").view==1),
                assert(replica_state.get("n5").ghost_last_seen_notarization==0),
                assert(replica_state.get("n5").last_finalized==0),
                assert(store_certificate.get("n5").size() == 1),
                assert(store_certificate.get("n5").filter(cert=> cert.kind==FinalizationKind).size() == 1),
                assert(is_view_notarized(0, store_certificate.get("n5"))),
                assert(is_view_finalized(0, store_certificate.get("n5"))),
                unchanged_all
            })
            
            .expect(select_votes(0, NotarizeKind, store_vote.get("n0")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n1")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n2")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n3")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n4")).size()==6)

            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0"))
            .expect(is_view_finalized(0, store_certificate.get("n5")))

            .expect(store_certificate.get("n0").size() == 2)
            .expect(store_certificate.get("n0").filter(cert => cert.kind==FinalizationKind).size() == 1)
            .expect(store_certificate.get("n0").filter(cert => cert.kind==NotarizationKind).size() == 1)
            
            .expect(store_certificate.get("n1").size() == 2)
            .expect(store_certificate.get("n1").filter(cert => cert.kind==FinalizationKind).size() == 1)
            .expect(store_certificate.get("n1").filter(cert => cert.kind==NotarizationKind).size() == 1)
            
            .expect(store_certificate.get("n2").size() == 2)
            .expect(store_certificate.get("n2").filter(cert => cert.kind==FinalizationKind).size() == 1)
            .expect(store_certificate.get("n2").filter(cert => cert.kind==NotarizationKind).size() == 1)
            
            .expect(store_certificate.get("n3").size() == 2)
            .expect(store_certificate.get("n3").filter(cert => cert.kind==FinalizationKind).size() == 1)
            .expect(store_certificate.get("n3").filter(cert => cert.kind==NotarizationKind).size() == 1)
            
            .expect(store_certificate.get("n4").size() == 2)
            .expect(store_certificate.get("n4").filter(cert => cert.kind==FinalizationKind).size() == 1)
            .expect(store_certificate.get("n4").filter(cert => cert.kind==NotarizationKind).size() == 1)
            
            .expect(store_certificate.get("n5").size() == 1)
            .expect(store_certificate.get("n4").filter(cert => cert.kind==FinalizationKind).size() == 1)

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n1")))
            .expect(is_view_notarized(0, store_certificate.get("n2")))
            .expect(is_view_notarized(0, store_certificate.get("n3")))
            .expect(is_view_notarized(0, store_certificate.get("n4")))
            .expect(is_view_notarized(0, store_certificate.get("n5")))

            .expect(is_view_finalized(0, store_certificate.get("n0")))
            .expect(is_view_finalized(0, store_certificate.get("n1")))
            .expect(is_view_finalized(0, store_certificate.get("n2")))
            .expect(is_view_finalized(0, store_certificate.get("n3")))
            .expect(is_view_finalized(0, store_certificate.get("n4")))
            .expect(is_view_finalized(0, store_certificate.get("n5")))

            .expect(all_invariants)

            .then(all {
                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").ghost_last_seen_notarization == 0),
                assert(replica_state.get("n1").ghost_last_seen_notarization == 0),
                assert(replica_state.get("n2").ghost_last_seen_notarization == 0),
                assert(replica_state.get("n3").ghost_last_seen_notarization == 0),
                assert(replica_state.get("n4").ghost_last_seen_notarization == 0),
                assert(replica_state.get("n5").ghost_last_seen_notarization == 0),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),
                unchanged_all,
            })

            .expect(all_invariants)
    }

    run happyPathWithNotarizationCertificatesTest = {
        val proposal = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        val n4_vote = {
            view: 0,
            block: "val_b0",
            sig: sig_of("n4"),
            kind: NotarizeKind
        }

        val n5_vote = {
            view: 0,
            block: "val_b0",
            sig: sig_of("n5"),
            kind: NotarizeKind
        }

        val cert_n0n1n2 = {
            view: 0,
            kind: NotarizationKind,
            block: "val_b0",
            signatures: Set("n0", "n1", "n2"),
            ghost_sender: sig_of("n0"),
        }


        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // Leader n0 proposes in view 0
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then( all {
                assert(replica_state.get("n0").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)
            // replicas n0-n4, but not n5 process the proposal and vote for it (n0 already did!)
            .then(on_proposal("n1", proposal))
            .then( all {
                assert(replica_state.get("n1").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n2", proposal))
            .then( all {
                assert(replica_state.get("n2").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n3", proposal))
            .then( all {
                assert(replica_state.get("n3").notarized.get(0)=="val_b0"),
                unchanged_all
            })

            
            .expect(all_invariants)

            // All replicas collect votes and notarize the block
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))


            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))

            .then(all{
                assert(not(sent_vote.contains(n4_vote))),
                assert(store_vote.get("n4").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block == "val_b0").size() == 0),
                assert(store_certificate.get("n4").size() == 0),
                unchanged_all
            })
            .then(replica_receives_certificate("n4", cert_n0n1n2))
            // since n4 did not vote for the block it must send it's vote now
            .then(all{
                assert(store_certificate.get("n4").size() == 1),
                assert(sent_vote.contains(n4_vote)),
                unchanged_all
            })


            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n1"))
            .then(all{
                assert(not(sent_vote.contains(n5_vote))),
                assert(store_vote.get("n5").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block == "val_b0").size() == 2),
                assert(store_certificate.get("n5").size() == 0),
                assert(not(is_view_notarized(0, store_certificate.get("n5")))),
                assert(replica_state.get("n5").ghost_sent_votes.get(0).length() == 0),
                assert(replica_state.get("n5").notarized.get(0) == EMPTY_BLOCK),
                assert(not(replica_state.get("n5").has_notarized())),
                assert(replica_state.get("n5").view == 0),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n2"))
            // n5 has votes and M-quorum. 
            // since n5 did not vote for the block it must send its vote now and add M-notarization (certificate)
            .then(all{
                assert(store_certificate.get("n5").size() == 1),
                assert(sent_vote.contains(n5_vote)),
                assert(replica_state.get("n5").ghost_sent_votes.get(0).length() == 1),
                assert(replica_state.get("n5").notarized.get(0) == "val_b0"),
                assert(replica_state.get("n5").view == 1),
                unchanged_all
            })
            // n5 receives another vote. It should be in new view now, so no votes for previous view or new certificates.
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n3"))
            .then(all{
                assert(store_certificate.get("n5").size() == 1),
                assert(is_view_notarized(0, store_certificate.get("n5"))),
                assert(replica_state.get("n5").ghost_sent_votes.get(0).length() == 1),
                assert(replica_state.get("n5").ghost_sent_votes.get(1).length() == 0),
                unchanged_all
            })
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n4"))
            .then(all{
                assert(store_certificate.get("n5").size() == 2),
                assert(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0")),
                assert(replica_state.get("n5").ghost_sent_votes.get(0).length() == 1),
                unchanged_all
            })

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n5"))

            .expect(select_votes(0, NotarizeKind, store_vote.get("n0")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n1")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n2")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n3")).size()==6)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n4")).size()==2)
            .expect(select_votes(0, NotarizeKind, store_vote.get("n5")).size()==6)

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))  
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))  
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))  
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))            
            .expect(select_votes(0, NotarizeKind, store_vote.get("n4")).size()==6)

            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0"))            

            .expect(store_certificate.get("n0").size() == 2)
            .expect(store_certificate.get("n1").size() == 2)
            .expect(store_certificate.get("n2").size() == 2)
            .expect(store_certificate.get("n3").size() == 2)
            .expect(store_certificate.get("n4").size() == 2)
            .expect(store_certificate.get("n5").size() == 2)

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n1")))
            .expect(is_view_notarized(0, store_certificate.get("n2")))
            .expect(is_view_notarized(0, store_certificate.get("n3")))
            .expect(is_view_notarized(0, store_certificate.get("n4")))
            .expect(is_view_notarized(0, store_certificate.get("n5")))
            .expect(all_invariants)

            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })

            .then(all {
                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),
                unchanged_all,
            })
            
    }

    run happyPathWithFinalizationTest = {
        val proposal = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        val n5_vote = {
            view: 0,
            block: "val_b0",
            sig: sig_of("n5"),
            kind: NotarizeKind
        }

        val notarization_n0n1n2 = {
            view: 0,
            kind: NotarizationKind,
            block: "val_b0",
            signatures: Set("n0", "n1", "n2"),
            ghost_sender: sig_of("n0"),
        }

        val finalization_n0n1n2n3n4 = {
            view: 0,
            kind: FinalizationKind,
            block: "val_b0",
            signatures: Set("n0", "n1", "n2", "n3", "n4"),
            ghost_sender: sig_of("n0"),
        }


        initWithLeader(Map(0 -> "n0", 1 -> "n0", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // Leader n0 proposes in view 0
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then( all {
                assert(replica_state.get("n0").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .expect(all_invariants)
            // replicas n0-n4, but not n5 process the proposal and vote for it (n0 already did!)
            .then(on_proposal("n1", proposal))
            .then( all {
                assert(replica_state.get("n1").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n2", proposal))
            .then( all {
                assert(replica_state.get("n2").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            .then(on_proposal("n3", proposal))
            .then( all {
                assert(replica_state.get("n3").notarized.get(0)=="val_b0"),
                unchanged_all
            })
            
            .expect(all_invariants)

            // All replicas collect votes and notarize the block
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))

            .then(all{
                assert(not(sent_vote.contains(n5_vote))),
                assert(store_vote.get("n5").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block == "val_b0").size() == 0),
                assert(store_certificate.get("n5").size() == 0),
                unchanged_all
            })
            .then(replica_receives_certificate("n5", notarization_n0n1n2))
    
            // since n4 did not vote for the block it must send it's vote now
            .then(all{
                assert(store_certificate.get("n5").size() == 1),
                assert(sent_vote.contains(n5_vote)),
                unchanged_all
            })

            .then(replica_receives_certificate("n5", finalization_n0n1n2n3n4))
            .then(all{
                assert(store_certificate.get("n5").size() == 2),
                assert(sent_vote.contains(n5_vote)),
                assert(replica_state.get("n5").ghost_sent_votes.get(0).length() == 1),
                assert(replica_state.get("n5").notarized.get(0) == "val_b0"),
                assert(replica_state.get("n5").view == 1),
                unchanged_all
            })
            
            .expect(store_certificate.get("n0").size() == 2)
            .expect(store_certificate.get("n1").size() == 2)
            .expect(store_certificate.get("n2").size() == 2)
            .expect(store_certificate.get("n3").size() == 2)
            .expect(store_certificate.get("n4").size() == 2)
            .expect(store_certificate.get("n5").size() == 2)

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n1")))
            .expect(is_view_notarized(0, store_certificate.get("n2")))
            .expect(is_view_notarized(0, store_certificate.get("n3")))
            .expect(is_view_notarized(0, store_certificate.get("n4")))
            .expect(is_view_notarized(0, store_certificate.get("n5")))
            .expect(all_invariants)

            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),
                unchanged_all,
            })

            .then(all {
                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })

            .then(all {
                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),
                unchanged_all,
            })
    }

    // Two blocks happy path test - commits blocks in views 1 and 2
    run twoBlocksTest = {
        val proposal1 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        val proposal2 = {
            block: "val_b1",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n1")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))

            // === FIRST BLOCK (VIEW 1) ===
            // Leader n0 proposes in view 1
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .expect(all_invariants)

            // All replicas process the proposal and vote for it (n0 did it already)
            .then(on_proposal("n1", proposal1))
            .then(on_proposal("n2", proposal1))
            .then(on_proposal("n3", proposal1))
            .then(on_proposal("n4", proposal1))
            .then(on_proposal("n5", proposal1))
            .expect(all_invariants)

            // All replicas collect votes for block 1
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n5"))

            // Verify first block is finalized and committed
            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0"))

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n1")))
            .expect(is_view_notarized(0, store_certificate.get("n2")))
            .expect(is_view_notarized(0, store_certificate.get("n3")))
            .expect(is_view_notarized(0, store_certificate.get("n4")))
            .expect(is_view_notarized(0, store_certificate.get("n5")))

            // Check first block is committed and replicas advance to view 1
            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),

                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),

                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),

                unchanged_all,
            })

            // === SECOND BLOCK (VIEW 1) ===
            // Leader n1 proposes in view 1
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .expect(all_invariants)

            // All replicas process the second proposal and vote for it (n1 already did!)
            .then(on_proposal("n0", proposal2))
            //.then(on_proposal("n1", proposal2))
            .then(on_proposal("n2", proposal2))
            .then(on_proposal("n3", proposal2))
            .then(on_proposal("n4", proposal2))
            .then(on_proposal("n5", proposal2))
            .expect(all_invariants)

            // All replicas collect votes for block 2
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n5"))

            // Verify second block is finalized and committed
            .expect(is_view_finalized_votes(1, store_vote.get("n0"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n1"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n2"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n3"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n4"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n5"), "val_b1"))

            .expect(is_view_notarized(1, store_certificate.get("n0")))
            .expect(is_view_notarized(1, store_certificate.get("n1")))
            .expect(is_view_notarized(1, store_certificate.get("n2")))
            .expect(is_view_notarized(1, store_certificate.get("n3")))
            .expect(is_view_notarized(1, store_certificate.get("n4")))
            .expect(is_view_notarized(1, store_certificate.get("n5")))

            // Check both blocks are committed and replicas advance to view 3
            .then(all {
                assert(replica_state.get("n0").last_finalized == 1),
                assert(replica_state.get("n1").last_finalized == 1),
                assert(replica_state.get("n2").last_finalized == 1),
                assert(replica_state.get("n3").last_finalized == 1),
                assert(replica_state.get("n4").last_finalized == 1),
                assert(replica_state.get("n5").last_finalized == 1),

                assert(replica_state.get("n0").view == 2),
                assert(replica_state.get("n1").view == 2),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n3").view == 2),
                assert(replica_state.get("n4").view == 2),
                assert(replica_state.get("n5").view == 2),

                // Both blocks should be in the committed chain
                assert(ghost_committed_blocks.get("n0") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0", "val_b1"]),

                unchanged_all,
            })
            .expect(all_invariants)

            // replicas can receive old votes
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n0"))
    }

    // Two blocks happy path test - but notarization and finalizations are processed in different views
    run twoBlocksDifferentViewsTest = {
        val proposal1 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        val proposal2 = {
            block: "val_b1",
            view: 1,
            view_parent: 0,
            block_parent: "val_b0",
            sig: sig_of("n1")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n1", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))

            // === FIRST BLOCK (VIEW 1) ===
            // Leader n0 proposes in view 1
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .expect(all_invariants)

            // All replicas process the proposal and vote for it (n0 did it already)
            .then(on_proposal("n1", proposal1))
            .then(on_proposal("n2", proposal1))
            .then(on_proposal("n3", proposal1))
            .then(on_proposal("n4", proposal1))
            .then(on_proposal("n5", proposal1))
            .expect(all_invariants)

            // All replicas collect semiquorum for block 1
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n3"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n4"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n5"))

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))

            .expect(not(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0")))
            .expect(not(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0")))
            .expect(not(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0")))
            .expect(not(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0")))
            .expect(not(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0")))
            .expect(not(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0")))

            .then(all {
                assert(replica_state.get("n0").last_finalized == GENESIS_VIEW),
                assert(replica_state.get("n1").last_finalized == GENESIS_VIEW),
                assert(replica_state.get("n2").last_finalized == GENESIS_VIEW),
                assert(replica_state.get("n3").last_finalized == GENESIS_VIEW),
                assert(replica_state.get("n4").last_finalized == GENESIS_VIEW),
                assert(replica_state.get("n5").last_finalized == GENESIS_VIEW),

                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),

                assert(ghost_committed_blocks.get("n0") == []),
                assert(ghost_committed_blocks.get("n1") == []),
                assert(ghost_committed_blocks.get("n2") == []),
                assert(ghost_committed_blocks.get("n3") == []),
                assert(ghost_committed_blocks.get("n4") == []),
                assert(ghost_committed_blocks.get("n5") == []),

                unchanged_all,
            })

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b0", 0, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b0", 0, "n2"))

            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n2"))
            .then(replica_receives_notarize_vote("n5", "val_b0", 0, "n3"))

            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))
            .expect(is_view_notarized(0, store_certificate.get("n0")))

            // Verify first block is finalized and committed
            .expect(is_view_finalized_votes(0, store_vote.get("n0"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n1"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n2"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n3"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n4"), "val_b0"))
            .expect(is_view_finalized_votes(0, store_vote.get("n5"), "val_b0"))

            // Check first block is committed and replicas advance to view 2
            .then(all {
                assert(replica_state.get("n0").last_finalized == 0),
                assert(replica_state.get("n1").last_finalized == 0),
                assert(replica_state.get("n2").last_finalized == 0),
                assert(replica_state.get("n3").last_finalized == 0),
                assert(replica_state.get("n4").last_finalized == 0),
                assert(replica_state.get("n5").last_finalized == 0),

                assert(replica_state.get("n0").view == 1),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),

                assert(ghost_committed_blocks.get("n0") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0"]),

                unchanged_all,
            })

            // === SECOND BLOCK (VIEW 1) ===
            // Leader n1 proposes in view 1
            .then(proposer_step("n1", "val_b1", "val_b0", 0))
            .expect(all_invariants)

            // All replicas process the second proposal and vote for it (n1 already did!)
            .then(on_proposal("n0", proposal2))
            .then(on_proposal("n2", proposal2))
            .then(on_proposal("n3", proposal2))
            .then(on_proposal("n4", proposal2))
            .then(on_proposal("n5", proposal2))
            .expect(all_invariants)

            // All replicas collect votes for block 2
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n0", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n1", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n2", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n3", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n4", "val_b1", 1, "n5"))

            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n0"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n1"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n2"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n3"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n4"))
            .then(replica_receives_notarize_vote("n5", "val_b1", 1, "n5"))

            // Verify second block is finalized and committed
            .expect(is_view_finalized_votes(1, store_vote.get("n0"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n1"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n2"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n3"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n4"), "val_b1"))
            .expect(is_view_finalized_votes(1, store_vote.get("n5"), "val_b1"))

            .expect(is_view_notarized(1, store_certificate.get("n0")))
            .expect(is_view_notarized(1, store_certificate.get("n1")))
            .expect(is_view_notarized(1, store_certificate.get("n2")))
            .expect(is_view_notarized(1, store_certificate.get("n3")))
            .expect(is_view_notarized(1, store_certificate.get("n4")))
            .expect(is_view_notarized(1, store_certificate.get("n5")))


            // Check both blocks are committed and replicas advance to view 3
            .then(all {
                assert(replica_state.get("n0").last_finalized == 1),
                assert(replica_state.get("n1").last_finalized == 1),
                assert(replica_state.get("n2").last_finalized == 1),
                assert(replica_state.get("n3").last_finalized == 1),
                assert(replica_state.get("n4").last_finalized == 1),
                assert(replica_state.get("n5").last_finalized == 1),

                assert(replica_state.get("n0").view == 2),
                assert(replica_state.get("n1").view == 2),
                assert(replica_state.get("n2").view == 2),
                assert(replica_state.get("n3").view == 2),
                assert(replica_state.get("n4").view == 2),
                assert(replica_state.get("n5").view == 2),

                // Both blocks should be in the committed chain
                assert(ghost_committed_blocks.get("n0") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n1") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n2") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n3") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n4") == ["val_b0", "val_b1"]),
                assert(ghost_committed_blocks.get("n5") == ["val_b0", "val_b1"]),

                unchanged_all,
            })

            .expect(all_invariants)
    }

    run timeoutTest = {
        // ----- first block (view 1) -----
        val proposal1 = {
            block: "val_b0",
            block_parent: GENESIS_BLOCK,
            view: 0,
            view_parent: GENESIS_VIEW,
            sig: sig_of("n0")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // === view 0 ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW)) // leader n0 proposes, view 0
            .expect(all_invariants)
            // n0 has sent notarize vote for its proposal in proposer_step, but all other replicas do not see it
            .then(on_timer_expired("n1"))
            .then(on_timer_expired("n2"))
            .then(on_timer_expired("n3"))
            .then(on_timer_expired("n4"))
            .then(on_timer_expired("n5"))
            .expect(all_invariants)

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))

            .then(replica_receives_nullify_vote("n1", 0, "n1"))
            .then(replica_receives_nullify_vote("n1", 0, "n2"))
            .then(replica_receives_nullify_vote("n1", 0, "n3"))
            .then(replica_receives_nullify_vote("n1", 0, "n4"))
            .then(replica_receives_nullify_vote("n1", 0, "n5"))

            .then(replica_receives_nullify_vote("n2", 0, "n1"))
            .then(replica_receives_nullify_vote("n2", 0, "n2"))
            .then(replica_receives_nullify_vote("n2", 0, "n3"))
            .then(replica_receives_nullify_vote("n2", 0, "n4"))
            .then(replica_receives_nullify_vote("n2", 0, "n5"))

            .then(replica_receives_nullify_vote("n3", 0, "n1"))
            .then(replica_receives_nullify_vote("n3", 0, "n2"))
            .then(replica_receives_nullify_vote("n3", 0, "n3"))
            .then(replica_receives_nullify_vote("n3", 0, "n4"))
            .then(replica_receives_nullify_vote("n3", 0, "n5"))

            .then(replica_receives_nullify_vote("n4", 0, "n1"))
            .then(replica_receives_nullify_vote("n4", 0, "n2"))
            .then(replica_receives_nullify_vote("n4", 0, "n3"))
            .then(replica_receives_nullify_vote("n4", 0, "n4"))
            .then(replica_receives_nullify_vote("n4", 0, "n5"))

            .then(replica_receives_nullify_vote("n5", 0, "n1"))
            .then(replica_receives_nullify_vote("n5", 0, "n2"))
            .then(replica_receives_nullify_vote("n5", 0, "n3"))
            .then(replica_receives_nullify_vote("n5", 0, "n4"))
            .then(replica_receives_nullify_vote("n5", 0, "n5"))

            .then(all {
                assert(replica_state.get("n0").view == 0),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })
            .expect(all_invariants)
            .then(all {
                assert(ghost_committed_blocks.get("n0") == []),
                assert(ghost_committed_blocks.get("n1") == []),
                assert(ghost_committed_blocks.get("n2") == []),
                assert(ghost_committed_blocks.get("n3") == []),
                assert(ghost_committed_blocks.get("n4") == []),
                assert(ghost_committed_blocks.get("n5") == []),
                unchanged_all,
            })
    }

    run nullificationTest = {
        // ----- first block (view 1) -----
        val proposal1 = {
            block: "val_b0",
            block_parent: GENESIS_BLOCK,
            view: 0,
            view_parent: GENESIS_VIEW,
            sig: sig_of("n0")
        }

        val nullification_n1n2n3 = {
            view: 0,
            kind: NullificationKind,
            block: DUMMY_BLOCK,
            signatures: Set("n1", "n2", "n3"),
            ghost_sender: sig_of("n1"),
        }

        val nullification_n2n3n4 = {
            view: 0,
            kind: NullificationKind,
            block: DUMMY_BLOCK,
            signatures: Set("n4", "n2", "n3"),
            ghost_sender: sig_of("n2"),
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n4"))
            // === view 0 ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW)) // leader n0 proposes, view 0
            .expect(all_invariants)
            // n0 has sent notarize vote for its proposal in proposer_step, but all other replicas do not see it
            .then(on_timer_expired("n1"))
            .then(on_timer_expired("n2"))
            .then(on_timer_expired("n3"))
            .then(on_timer_expired("n4"))
            .then(on_timer_expired("n5"))
            .expect(all_invariants)

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))

            .then(replica_receives_nullify_vote("n1", 0, "n1"))
            .then(replica_receives_nullify_vote("n1", 0, "n2"))
            .then(replica_receives_nullify_vote("n1", 0, "n3"))
            .then(replica_receives_nullify_vote("n1", 0, "n4"))
            

            .then(replica_receives_nullify_vote("n2", 0, "n1"))
            .then(replica_receives_nullify_vote("n2", 0, "n2"))
            .then(replica_receives_nullify_vote("n2", 0, "n3"))
            .then(replica_receives_nullify_vote("n2", 0, "n4"))
            

            .then(replica_receives_nullify_vote("n3", 0, "n1"))
            .then(replica_receives_nullify_vote("n3", 0, "n2"))
            .then(replica_receives_nullify_vote("n3", 0, "n3"))
            .then(replica_receives_nullify_vote("n3", 0, "n4"))

            .then(replica_receives_nullify_vote("n4", 0, "n1"))
            .then(replica_receives_nullify_vote("n4", 0, "n2"))
            .then(replica_receives_nullify_vote("n4", 0, "n3"))
            .then(replica_receives_nullify_vote("n4", 0, "n4"))
        
            .then(replica_receives_certificate("n5", nullification_n1n2n3))

            .then(all{
                assert(store_certificate.get("n5").size() == 1),
                unchanged_all
            })
            .then(all{
                assert(store_certificate.get("n5").size() == 1),
                unchanged_all
            }) 
            .then(all {
                assert(replica_state.get("n0").view == 0),
                assert(replica_state.get("n1").view == 1),
                assert(replica_state.get("n2").view == 1),
                assert(replica_state.get("n3").view == 1),
                assert(replica_state.get("n4").view == 1),
                assert(replica_state.get("n5").view == 1),
                unchanged_all,
            })
            .expect(all_invariants)
            .then(all {
                assert(ghost_committed_blocks.get("n0") == []),
                assert(ghost_committed_blocks.get("n1") == []),
                assert(ghost_committed_blocks.get("n2") == []),
                assert(ghost_committed_blocks.get("n3") == []),
                assert(ghost_committed_blocks.get("n4") == []),
                assert(ghost_committed_blocks.get("n5") == []),
                unchanged_all,
            })
    }

    run contradictionTest = {
        pure val proposal0 = {
            block: "val_b0",
            view: 0,
            view_parent: GENESIS_VIEW,
            block_parent: GENESIS_BLOCK,
            sig: sig_of("n0")
        }

        initWithLeader(Map(0 -> "n0", 1 -> "n5", 2 -> "n1", 3 -> "n2", 4 -> "n3", 5 -> "n1"))
            // === view 0 ===
            .then(proposer_step("n0", "val_b0", GENESIS_BLOCK, GENESIS_VIEW))
            .then(on_proposal("n1", proposal0))
            .then(on_proposal("n2", proposal0))

            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n0", "val_b0", 0, "n1"))

            .then(replica_receives_notarize_vote("n1", "val_b0", 0, "n0"))

            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n0"))
            .then(replica_receives_notarize_vote("n2", "val_b0", 0, "n1"))

            .then(on_timer_expired("n3"))
            .then(on_timer_expired("n4"))
            .then(on_timer_expired("n5"))

            .then(all {
                assert(replica_state.get("n0").view == 0),
                assert(replica_state.get("n1").view == 0),
                assert(replica_state.get("n2").view == 0),
                assert(replica_state.get("n3").view == 0),
                assert(replica_state.get("n4").view == 0),
                assert(replica_state.get("n5").view == 0),
                unchanged_all,
            })

            .expect(all_invariants)

            .then(replica_receives_nullify_vote("n0", 0, "n3"))
            .then(replica_receives_nullify_vote("n0", 0, "n4"))

            .then(all {
                assert(store_vote.get("n0").filter(v=>v.view==0 and v.kind==NotarizeKind and v.block != "val_b0").size() == 0),
                assert(store_vote.get("n0").filter(v=>v.view==0 and v.kind==NullifyKind).size() == 2),
                assert(replica_state.get("n0").nullified == false),
                assert(replica_state.get("n0").notarized.get(0) == "val_b0"),
                assert(is_contradicted(replica_state.get("n0"), 0, store_vote.get("n0")) == false),
                unchanged_all,
            })

            // no contradiction, no nullification will be sent.

            .then(all {
                assert(store_vote.get("n0").filter(v=>v.view==0).size() == 4),
                assert(replica_state.get("n0").nullified == false),
                unchanged_all,
            })

            // n1 gets vote for block from n0 and 3 nullify votes from n3-n5
            .then(replica_receives_nullify_vote("n1", 0, "n3"))
            .then(all {
                assert(store_vote.get("n1").filter(v=>v.view==0).size() == 2),
                assert(replica_state.get("n1").nullified == false),
                unchanged_all,
            })
            .then(replica_receives_nullify_vote("n1", 0, "n4"))
            .then(replica_receives_nullify_vote("n1", 0, "n5"))
            .then(all {
                assert(store_vote.get("n1").filter(v=>v.view==0 and v.kind==NullifyKind).size() == 3),
                assert(store_vote.get("n1").filter(v=>v.view==0).size() == 4),
                assert(replica_state.get("n1").view == 1),
                unchanged_all,
            })
    }

    action replica_receives_notarize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =
        on_vote_notarize(id, view, block,  Set(notarize(view, src, block)))
    
    action replica_receives_certificate(id: ReplicaId, cert: Certificate): bool =
        on_certificate(id, cert)

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
        leader' = leader,
        replica_state' = replica_state,
    }
}
