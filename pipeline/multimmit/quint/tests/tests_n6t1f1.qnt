// A scripted end-to-end scenario at N = 6, T = 1, F = 1: one good view,
// from block production to a non-empty log.
//
// Random simulation will not find this on its own. The shortest run that
// emits a block is around twenty steps -- produce, five DA-votes,
// propose, five deliveries, five votes, five vote-deliveries, finalize --
// each chosen from eleven action shapes over six replicas and six chains.
// So the liveness of the model is established by driving it, and the
// invariants are then checked along the way.
//
//   quint test tests/tests_n6t1f1.qnt

module tests_n6t1f1 {
    import types.* from "../types"
    import option.* from "../option"
    import blocks.* from "../blocks"
    import defs.* from "../defs"
    import chainrules.* from "../chainrules"
    import sweep.* from "../sweep"

    import consensus(
        N = 6,
        T = 1,
        F = 1,
        REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4"),
        CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
        TWINS = Set(),
        BYZANTINE = Set("n5"),
        REPLICA_KEYS = Map(
            "n0" -> "n0", "n1" -> "n1", "n2" -> "n2",
            "n3" -> "n3", "n4" -> "n4", "n5" -> "n5"
        ),
        CHAIN_OF = Map(
            "n0" -> 1, "n1" -> 2, "n2" -> 3,
            "n3" -> 4, "n4" -> 5, "n5" -> 6
        ),
        PAYLOADS = Set(1, 2),
        MAX_HEIGHT = 2,
        VIEWS = 0.to(5),
        MAX_VQC_HASH = 4,
        PIPELINE_D = 2,
        EXT_E = 1
    ).* from "../consensus"

    pure val CORRECT_IDS = Set("n0", "n1", "n2", "n3", "n4")

    // The leader of view 1 is lead(1) = 1 % 6 + 1 = chain 2, i.e. n1.
    pure val B2A = mkBlock(2, [1])
    pure val ORD_B1 = mkBlock(1, [1])
    pure val ORD_B2 = mkBlock(1, [1, 2])
    pure val ORD_C1 = mkBlock(2, [1])

    pure val ORD_LB1: LeaderBlock = {
        view: 1,
        parent_vqc: GENESIS_VQC_HASH,
        proposal: CHAINS.mapBy(i =>
            if (i == 1)
                { anchor: HashAnchor(genesis_block(i)), payloads: [1] }
            else
                { anchor: HashAnchor(genesis_block(i)), payloads: List() }),
    }

    pure val ORD_LB2: LeaderBlock = {
        view: 2,
        parent_vqc: 1,
        proposal: CHAINS.mapBy(i =>
            if (i == 1)
                { anchor: HashAnchor(ORD_B1), payloads: [2] }
            else
                { anchor: HashAnchor(genesis_block(i)), payloads: List() }),
    }

    pure val ORD_LB3: LeaderBlock = {
        view: 3,
        parent_vqc: 2,
        proposal: CHAINS.mapBy(i =>
            if (i == 1)
                { anchor: HashAnchor(ORD_B2), payloads: List() }
            else if (i == 2)
                { anchor: HashAnchor(genesis_block(i)), payloads: [1] }
            else
                { anchor: HashAnchor(genesis_block(i)), payloads: List() }),
    }

    pure def ord_fixture_vote(sig: Signature, lb: LeaderBlock, active: ChainId): NotarizeVote = {
        {
            leader_block: lb,
            positions: CHAINS.mapBy(i => if (i == active) 1 else 0),
            extensions: CHAINS.mapBy(_ => List()),
            sig: sig,
        }
    }

    pure def ord_fixture_pool(lb: LeaderBlock, active: ChainId): Tally = {
        Set(
            ord_fixture_vote("n0", lb, active), ord_fixture_vote("n1", lb, active),
            ord_fixture_vote("n2", lb, active), ord_fixture_vote("n3", lb, active),
            ord_fixture_vote("n4", lb, active))
    }

    pure val ORD_Q1: VQC = {
        id: 1,
        leader_block: ORD_LB1,
        votes: ord_fixture_pool(ORD_LB1, 1),
        novotes: Set(),
        other_votes: Set(),
        ghost_sender: "n0",
    }

    pure val ORD_Q2: VQC = {
        id: 2,
        leader_block: ORD_LB2,
        votes: ord_fixture_pool(ORD_LB2, 1),
        novotes: Set(),
        other_votes: Set(),
        ghost_sender: "n0",
    }

    pure val ORD_POOL3 = ord_fixture_pool(ORD_LB3, 2)

    // n5 owns chain 6 and therefore leads view 5. These two blocks let the
    // Byzantine leader equivocate after the correct replicas have advanced
    // through views 1--4 by nullification.
    pure def l1_lb_with(pl: PayloadId): LeaderBlock = {
        {
            view: 5,
            parent_vqc: GENESIS_VQC_HASH,
            proposal: CHAINS.mapBy(i =>
                if (i == 1)
                    { anchor: HashAnchor(genesis_block(1)), payloads: [pl] }
                else
                    { anchor: HashAnchor(genesis_block(i)), payloads: List() }),
        }
    }

    pure val L1_LB_A = l1_lb_with(1)
    pure val L1_LB_B = l1_lb_with(2)
    pure val L1_ZERO_POS: Positions = CHAINS.mapBy(_ => 0)
    pure val L1_NO_EXT: Extensions = CHAINS.mapBy(_ => List())

    // -------------------------------------------------
    // Frame helpers
    // -------------------------------------------------
    //
    // chain_produce / chain_da_vote come from consensus.qnt: a
    // chain-layer action with the consensus frame supplied.

    // With a single leader block in flight, `oneOf` is deterministic.
    action deliver_lb(id: ReplicaId): bool = all {
        sent_leader_block != Set(),
        nondet lb = oneOf(sent_leader_block)
        on_deliver_leader_block(id, lb),
    }

    action vote(id: ReplicaId): bool = all {
        store_leader_block.get(id) != Set(),
        nondet lb = oneOf(store_leader_block.get(id))
        on_vote(id, lb),
    }

    action deliver_vote(rcv: ReplicaId, from: ReplicaId): bool = all {
        nondet x = oneOf(sent_vote.filter(v => vote_sig(v) == from))
        on_deliver_vote(rcv, x),
    }

    action deliver_novote(rcv: ReplicaId, from: ReplicaId): bool = all {
        nondet x = oneOf(sent_vote.filter(v =>
            vote_sig(v) == from and vote_kind(v) == NovoteKind))
        on_deliver_vote(rcv, x),
    }

    action deliver_nullify(rcv: ReplicaId, from: ReplicaId): bool = all {
        nondet x = oneOf(sent_vote.filter(v =>
            vote_sig(v) == from and vote_kind(v) == NullifyKind))
        on_deliver_vote(rcv, x),
    }

    action deliver_vqc(id: ReplicaId): bool = all {
        nondet c = oneOf(sent_certificate.filter(c => cert_kind(c) == NotarizationKind))
        on_deliver_certificate(id, c),
    }

    // Add a Byzantine vote at a chosen (uniform) proposal position.
    // Fixing k lets equivocation tests control which vote arrives first.
    action byzantine_notarize_vote_at(k: int): bool = {
        nondet lb = oneOf(sent_leader_block)
        val positions = lb.proposal.keys().mapBy(i =>
            min(k, num_proposal_entries(lb.proposal, i)))
        val extensions = lb.proposal.keys().mapBy(_ => List())
        byzantine_notarize_vote_step_framed(
            "n5", lb, positions, extensions)
    }

    // Select the Byzantine branch that adds a fresh vote for the sole
    // leader block in flight; the adversary remains free to choose the
    // vote's well-formed position vector.
    action byzantine_notarize_vote: bool = {
        nondet k = oneOf(0.to(PIPELINE_D))
        byzantine_notarize_vote_at(k)
    }

    action deliver_byzantine_vote_at(rcv: ReplicaId, k: int): bool = all {
        nondet x = oneOf(notarize_votes(sent_vote).filter(v => and {
            v.sig == "n5",
            v.positions.get(2) == k,
        }))
        on_deliver_vote(rcv, Notarize(x)),
    }

    action finalize(id: ReplicaId): bool = all {
        store_leader_block.get(id) != Set(),
        nondet lb = oneOf(store_leader_block.get(id))
        on_finalize(id, lb),
    }

    action deliver_vqc_from(id: ReplicaId, v: ViewNumber, from: Signature): bool = all {
        nondet c = oneOf(sent_certificate.filter(c => and {
            cert_kind(c) == NotarizationKind,
            cert_view(c) == v,
            cert_ghost_sender(c) == from,
        }))
        on_deliver_certificate(id, c),
    }

    action l1_deliver_notarize(
        rcv: ReplicaId,
        from: ReplicaKey,
        lb: LeaderBlock
    ): bool = all {
        nondet x = oneOf(notarize_votes(sent_vote).filter(y =>
            y.sig == from and y.leader_block == lb))
        on_deliver_vote(rcv, Notarize(x)),
    }

    // Compact the routine four-view catch-up prefix. Every correct replica
    // holds valid nullification proofs for the skipped views and has entered
    // view 5. The equivocation and all subsequent votes/certificates remain
    // ordinary protocol actions in the regression below.
    action seed_l1_view_five: bool = {
        val proofs = 1.to(4).map(v =>
            nullification(v, Set("n0", "n1", "n2"), "n0"))
        val advanced = REPLICA_IDS.fold(replica_state, (states, id) =>
            states.set(id, {
                ...states.get(id),
                view: 5,
                nullified: false,
                propose_sent: false,
                timer_cancelled: false,
            }))
        val stores = REPLICA_IDS.fold(store_certificate, (certs, id) =>
            certs.set(id, certs.get(id).union(proofs)))
        all {
            replica_state' = advanced,
            sent_leader_block' = sent_leader_block,
            store_leader_block' = store_leader_block,
            sent_vote' = sent_vote,
            store_vote' = store_vote,
            sent_certificate' = sent_certificate.union(proofs),
            store_certificate' = stores,
            ghost_vqc' = ghost_vqc,
            chain_layer_unchanged,
        }
    }

    // A compact reachable-shape fixture for the ancestry-retrieval test.
    // n0 has Q1 and Q2; n4 has Q2 but is missing Q1. Both have the same
    // finalising view-3 pool, and Q1 remains available on the network.
    action seed_missing_ancestry_fixture: bool = {
        val votes = ORD_POOL3.map(v => Notarize(v))
        all {
            replica_state' = replica_state,
            sent_leader_block' = sent_leader_block.union(Set(ORD_LB3)),
            store_leader_block' = store_leader_block
                .set("n0", store_leader_block.get("n0").union(Set(ORD_LB3)))
                .set("n4", store_leader_block.get("n4").union(Set(ORD_LB3))),
            sent_vote' = sent_vote.union(votes),
            store_vote' = store_vote
                .set("n0", store_vote.get("n0").union(votes))
                .set("n4", store_vote.get("n4").union(votes)),
            sent_certificate' = sent_certificate.union(
                Set(Notarization(ORD_Q1), Notarization(ORD_Q2))),
            store_certificate' = store_certificate
                .set("n0", store_certificate.get("n0").union(
                    Set(Notarization(ORD_Q1), Notarization(ORD_Q2))))
                .set("n4", store_certificate.get("n4").union(
                    Set(Notarization(ORD_Q2)))),
            ghost_vqc' = ghost_vqc.put(1, ORD_Q1).put(2, ORD_Q2),
            chain_layer_unchanged,
        }
    }

    // -------------------------------------------------
    // The scenario
    // -------------------------------------------------

    // Keep the instance assumptions executable: changes to its replica sets,
    // key partition or quorum parameters must continue to satisfy the guards
    // under which the protocol invariants are stated.
    run assumptionsValidTest = assumptions_valid

    run oneGoodViewTest = {
        init
            // n1 produces the first block of its own chain, chain 2.
            .then(chain_produce("n1", genesis_block(2), 1))
            // Every correct replica DA-votes it. The leader must be among
            // them: ProposeChains draws its payload entries from the
            // leader's OWN DA-voting history.
            .then(chain_da_vote("n0", B2A))
            .then(chain_da_vote("n1", B2A))
            .then(chain_da_vote("n2", B2A))
            .then(chain_da_vote("n3", B2A))
            .then(chain_da_vote("n4", B2A))
            .expect(CORRECT_IDS.forall(id => da_voted_of(id).contains(B2A)))
            // The leader of view 1 proposes: an anchor per chain, and one
            // payload entry above the anchor of chain 2.
            .then(on_propose("n1"))
            .expect(sent_leader_block.size() == 1)
            .expect(sent_leader_block.forall(lb =>
                num_proposal_entries(lb.proposal, 2) == 1 and
                CHAINS.filter(j => j != 2).forall(j => num_proposal_entries(lb.proposal, j) == 0)))
            // Everyone receives it and votes.
            .then(deliver_lb("n0"))
            .then(deliver_lb("n1"))
            .then(deliver_lb("n2"))
            .then(deliver_lb("n3"))
            .then(deliver_lb("n4"))
            .then(vote("n0"))
            .then(vote("n1"))
            .then(vote("n2"))
            .then(vote("n3"))
            .then(vote("n4"))
            // Every correct vote reports position 1 on chain 2: the
            // proposal's single entry is a block they all DA-voted.
            .expect(notarize_votes(sent_vote).forall(v => v.positions.get(2) == 1))
            // n0 collects the five votes -- a finalising pool, L = 5.
            .then(deliver_vote("n0", "n0"))
            .then(deliver_vote("n0", "n1"))
            .then(deliver_vote("n0", "n2"))
            .then(deliver_vote("n0", "n3"))
            .then(deliver_vote("n0", "n4"))
            // ... and emits.
            .then(finalize("n0"))
            .expect(replica_state.get("n0").ghost_log == [B2A])
            // The invariants held throughout, and not vacuously.
            .expect(all_invariants)
    }

    // The same run, stopping at the V-QC instead of the pool. The assembler
    // holds six view-1 messages and selects exactly L = 5 distinct signers,
    // of which at least M = 3 voted for one leader block.
    run vqcAssemblyTest = {
        init
            .then(chain_produce("n1", genesis_block(2), 1))
            .then(chain_da_vote("n1", B2A))
            .then(on_propose("n1"))
            .then(deliver_lb("n0"))
            .then(deliver_lb("n1"))
            .then(deliver_lb("n2"))
            .then(deliver_lb("n3"))
            .then(deliver_lb("n4"))
            .then(vote("n0"))
            .then(vote("n1"))
            .then(vote("n2"))
            .then(vote("n3"))
            .then(vote("n4"))
            .then(byzantine_notarize_vote_at(0))
            .then(deliver_vote("n2", "n0"))
            .then(deliver_vote("n2", "n1"))
            .then(deliver_vote("n2", "n2"))
            .then(deliver_vote("n2", "n3"))
            .then(deliver_vote("n2", "n4"))
            .then(deliver_vote("n2", "n5"))
            .expect(select_votes(1, NotarizeKind, store_vote.get("n2"))
                .map(x => vote_sig(x)).size() == 6)
            .then(all {
                store_leader_block.get("n2") != Set(),
                nondet lb = oneOf(store_leader_block.get("n2"))
                on_vqc("n2", lb, 1),
            })
            .expect(sent_certificate.exists(c => cert_kind(c) == NotarizationKind))
            .expect(sent_certificate.filter(c =>
                cert_kind(c) == NotarizationKind and cert_view(c) == 1)
                .forall(c => cert_signers(c).size() == L))
            .expect(has_vqc("n2", 1))
            .expect(replica_state.get("n2").forwarded.get(1) != None)
            .expect(vqc_id_matches_key)
            .expect(vqc_content_has_unique_id)
            // Only n1 DA-voted the block, so the drop-3T rank cannot
            // reach position 1: four signers would be needed. The chain's
            // tip is finalised at the anchor, and nothing is emitted.
            .expect(notarize_votes(sent_vote).filter(v => v.sig != "n1")
                        .forall(v => v.positions.get(2) == 0))
            // n2 already voted through the ordinary proposal route. It
            // processes its newly assembled V-QC without voting twice.
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n2").size() == 1)
            .then(on_view_proof("n2"))
            .expect(replica_state.get("n2").view == 2)
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n2").size() == 1)
            .expect(all_invariants)
    }

    // A replica that did not receive the standalone proposal must still
    // vote for the leader block designated by a held current-view V-QC.
    // Delivery only records the proof; the state-triggered rule votes
    // along first and then enters the next view.
    run vqcVoteAlongTest = {
        init
            .then(chain_produce("n1", genesis_block(2), 1))
            .then(chain_da_vote("n1", B2A))
            .then(on_propose("n1"))
            // Three correct replicas vote normally. n0 is the eligible
            // vote-along target; n4 times out and tests the ineligible path.
            .then(deliver_lb("n1"))
            .then(deliver_lb("n2"))
            .then(deliver_lb("n3"))
            .then(vote("n1"))
            .then(vote("n2"))
            .then(vote("n3"))
            .then(on_timeout("n4"))
            .then(byzantine_notarize_vote)
            // n2 assembles an L=5 V-QC from four votes and n4's novote.
            .then(deliver_vote("n2", "n1"))
            .then(deliver_vote("n2", "n2"))
            .then(deliver_vote("n2", "n3"))
            .then(deliver_vote("n2", "n5"))
            .then(deliver_novote("n2", "n4"))
            .then(all {
                store_leader_block.get("n2") != Set(),
                nondet lb = oneOf(store_leader_block.get("n2"))
                on_vqc("n2", lb, 1),
            })
            // n0 never received the leader block, so on_vote is unavailable.
            .expect(store_leader_block.get("n0") == Set())
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n0") == Set())
            .then(deliver_vqc("n0"))
            // Receipt stores and forwards the proof trigger but does not
            // itself vote or enter a view.
            .expect(replica_state.get("n0").view == 1)
            .expect(has_vqc("n0", 1))
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n0") == Set())
            .then(on_view_proof("n0"))
            .expect(replica_state.get("n0").view == 2)
            .expect(replica_state.get("n0").notarized.get(1) != None)
            .expect(replica_state.get("n0").ghost_sent_votes.get(1).length() == 1)
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n0").size() == 1)
            // With no DA-voting history, n0 reports position zero and no
            // extensions on every chain, using the V-QC's embedded block.
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n0").forall(v =>
                CHAINS.forall(i =>
                    v.positions.get(i) == 0 and v.extensions.get(i) == List())))
            .expect(sent_certificate.exists(c =>
                match c {
                    | Notarization(q) => notarize_votes(sent_vote).exists(v =>
                        v.sig == "n0" and v.leader_block == q.leader_block)
                    | Nullification(_) => false
                }))
            // n4 is already nullified: the same state rule advances it
            // without contradicting its novote by sending a later vote.
            .then(deliver_vqc("n4"))
            .then(on_view_proof("n4"))
            .expect(replica_state.get("n4").view == 2)
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n4") == Set())
            .expect(all_invariants)
    }

    // A locally assembled nullification is immediately self-received.
    // The assembler can process the held proof without delivering its
    // own broadcast back to itself.
    run nullificationAssemblySelfReceiptTest = {
        init
            .then(on_timeout("n0"))
            .then(on_timeout("n1"))
            .then(on_timeout("n2"))
            .then(deliver_nullify("n3", "n0"))
            .then(deliver_nullify("n3", "n1"))
            .then(deliver_nullify("n3", "n2"))
            .then(on_nullification("n3", 1))
            .expect(replica_state.get("n3").view == 1)
            .expect(has_nullification("n3", 1))
            .expect(sent_certificate.exists(c =>
                cert_kind(c) == NullificationKind and cert_view(c) == 1))
            .expect(store_certificate.get("n3").exists(c =>
                cert_kind(c) == NullificationKind and cert_view(c) == 1))
            .then(on_view_proof("n3"))
            .expect(replica_state.get("n3").view == 2)
            .expect(notarize_votes(sent_vote).filter(v => v.sig == "n3") == Set())
            .expect(all_invariants)
    }

    // Algorithm 2 advances only on a proof for the current view. The
    // state-triggered proof action uses this helper after delivery has
    // stored and (for a V-QC) forwarded the certificate.
    run viewProofAdvanceDoesNotSkipViewsTest = {
        init
            // A current-view proof advances exactly one view.
            .expect(advance_on_view_proof(
                replica_state.get("n0"), 1, VIEWS).view == 2)
            // Later-view proofs cannot jump over views 1 or 2.
            .expect(advance_on_view_proof(
                replica_state.get("n0"), 2, VIEWS).view == 1)
            .expect(advance_on_view_proof(
                replica_state.get("n0"), 3, VIEWS).view == 1)
    }

    // A Byzantine signer sends two different votes for one leader block.
    // Each replica keeps only its first arrival, while the network retains
    // both messages so different delivery orders remain explorable.
    run finalizationSelectsOneVotePerSignerTest = {
        init
            .then(chain_produce("n1", genesis_block(2), 1))
            // Exactly three correct voters will report position 1. The
            // fourth reports 0, so n5's selected vote decides whether the
            // 3T+1 final-position threshold reaches the proposed block.
            .then(chain_da_vote("n0", B2A))
            .then(chain_da_vote("n1", B2A))
            .then(chain_da_vote("n2", B2A))
            .then(on_propose("n1"))
            .then(deliver_lb("n0"))
            .then(deliver_lb("n1"))
            .then(deliver_lb("n2"))
            .then(deliver_lb("n3"))
            .then(vote("n0"))
            .then(vote("n1"))
            .then(vote("n2"))
            .then(vote("n3"))
            .then(byzantine_notarize_vote_at(0))
            .then(byzantine_notarize_vote_at(1))
            // Both collectors receive the four correct votes.
            .then(deliver_vote("n4", "n0"))
            .then(deliver_vote("n4", "n1"))
            .then(deliver_vote("n4", "n2"))
            .then(deliver_vote("n4", "n3"))
            .then(deliver_vote("n3", "n0"))
            .then(deliver_vote("n3", "n1"))
            .then(deliver_vote("n3", "n2"))
            .then(deliver_vote("n3", "n3"))
            // n4 sees the low Byzantine vote first; n3 sees the high one.
            .then(deliver_byzantine_vote_at("n4", 0))
            .then(deliver_byzantine_vote_at("n4", 1))
            .then(deliver_byzantine_vote_at("n3", 1))
            .then(deliver_byzantine_vote_at("n3", 0))
            .expect(sent_leader_block.forall(lb => {
                val low = notarize_votes(store_vote.get("n4"))
                    .filter(v => vote_matches(v, lb))
                val high = notarize_votes(store_vote.get("n3"))
                    .filter(v => vote_matches(v, lb))
                val unselected = notarize_votes(sent_vote)
                    .filter(v => vote_matches(v, lb))
                and {
                    low.size() == 5,
                    high.size() == 5,
                    signers(low).size() == 5,
                    signers(high).size() == 5,
                    low.filter(v => v.sig == "n5").forall(v => v.positions.get(2) == 0),
                    high.filter(v => v.sig == "n5").forall(v => v.positions.get(2) == 1),
                    tips_f(low, lb, PARAMS).get(2) == genesis_block(2),
                    tips_f(high, lb, PARAMS).get(2) == B2A,
                    pool_finalizes(low, lb, PARAMS),
                    pool_finalizes(high, lb, PARAMS),
                    // Passing every network vote would combine both
                    // equivocations. The hardened predicate rejects it.
                    unselected.size() == 6,
                    signers(unselected).size() == 5,
                    tips_f(unselected, lb, PARAMS).get(2) == B2A,
                    not(pool_finalizes(unselected, lb, PARAMS)),
                }
            }))
            .then(finalize("n3"))
            .expect(replica_state.get("n3").ghost_log == [B2A])
            .expect(vote_pool_one_per_signer)
            .expect(all_invariants)
    }

    // Two correct replicas independently assemble the same V-QC and use
    // the same hash, while ghost_sender makes their network records
    // distinct. A receiver retains only one record for that hash, so
    // resolution remains unique.
    run duplicateVqcRecordDoesNotForkTheLogTest = {
        init
        .then(on_propose("n1"))
        .then(deliver_lb("n0")).then(deliver_lb("n1")).then(deliver_lb("n2"))
        .then(deliver_lb("n3")).then(deliver_lb("n4"))
        .then(vote("n0")).then(vote("n1")).then(vote("n2"))
        .then(vote("n3")).then(vote("n4"))
        // n0 and n1 each collect the same five votes and assemble the same
        // logical V-QC with hash 1.
        .then(deliver_vote("n0","n0")).then(deliver_vote("n0","n1"))
        .then(deliver_vote("n0","n2")).then(deliver_vote("n0","n3"))
        .then(deliver_vote("n0","n4"))
        .then(all {
            nondet lb = oneOf(store_leader_block.get("n0"))
            on_vqc("n0", lb, 1),
        })
        .then(deliver_vote("n1","n0")).then(deliver_vote("n1","n1"))
        .then(deliver_vote("n1","n2")).then(deliver_vote("n1","n3"))
        .then(deliver_vote("n1","n4"))
        .then(all {
            nondet lb = oneOf(store_leader_block.get("n1"))
            on_vqc("n1", lb, 1),
        })
        .expect(sent_certificate.filter(c =>
            cert_kind(c) == NotarizationKind and cert_view(c) == 1).size() == 2)
        .expect(vqc_id_matches_key)
        .expect(vqc_content_has_unique_id)
        // After one record arrives, the other network record's hash is
        // already known and its delivery guard is false.
        .then(deliver_vqc_from("n4",1,"n0"))
        .expect(has_vqc_hash("n4", 1))
        .expect(held_vqcs("n4").filter(q => q.id == 1).size() == 1)
        .expect(is_some(resolve_vqc(1,
            held_vqcs("n4").union(Set(genesis_vqc(CHAINS))))))
        .expect(all_invariants)
    }

    // A replica may receive a V-QC before an earlier V-QC on its reference
    // chain. Finalisation must remain disabled until the missing certificate
    // arrives; extraction then uses the complete ancestry.
    run missingVqcAncestryDefersFinalizationTest = {
        init
        .expect(vqc_wellformed(ORD_Q1, PARAMS))
        .expect(vqc_wellformed(ORD_Q2, PARAMS))
        .expect(pool_finalizes(ORD_POOL3, ORD_LB3, PARAMS))
        .then(chain_produce("n0", genesis_block(1), 1))
        .then(chain_produce("n0", ORD_B1, 2))
        .then(chain_produce("n1", genesis_block(2), 1))
        .then(seed_missing_ancestry_fixture)
        .then(finalize("n0"))
        .expect(replica_state.get("n0").ghost_log == [ORD_B1, ORD_B2, ORD_C1])
        .expect(emit(ORD_POOL3, ORD_LB3,
            held_vqcs("n4").union(Set(genesis_vqc(CHAINS))), PARAMS) == None)
        .expect(replica_state.get("n4").ghost_log == [])
        .expect(agreement)

        // Delivering the missing Q1 models retrieval. The unchanged pool now
        // yields the complete ordering rather than a partial suffix.
        .then(deliver_vqc_from("n4", 1, "n0"))
        .then(finalize("n4"))
        .expect(replica_state.get("n4").ghost_log == [ORD_B1, ORD_B2, ORD_C1])
        .expect(all_invariants)
    }

    // Two V-QCs may designate different blocks in the same view when neither
    // block has an L-QC. L1 becomes restrictive only once an L-sized vote pool
    // for one of the blocks is present.
    run twoVqcsWithoutLqcAreAllowedTest = {
        init
        .then(seed_l1_view_five)
        // The Byzantine view-5 leader equivocates.
        .then(byzantine_leader_block_step_framed("n5", L1_LB_A))
        .then(byzantine_leader_block_step_framed("n5", L1_LB_B))
        .expect(sent_leader_block == Set(L1_LB_A, L1_LB_B))
        .expect(bounded_byzantine_leader_block(L1_LB_A))
        .expect(bounded_byzantine_leader_block(L1_LB_B))
        .expect(proposal_wellformed(L1_LB_A, genesis_vqc(CHAINS), PARAMS))
        .expect(proposal_wellformed(L1_LB_B, genesis_vqc(CHAINS), PARAMS))

        // Correct replicas selectively receive and vote for one proposal.
        .then(on_deliver_leader_block("n0", L1_LB_A))
        .then(on_deliver_leader_block("n1", L1_LB_A))
        .then(on_deliver_leader_block("n3", L1_LB_B))
        .then(on_deliver_leader_block("n4", L1_LB_B))
        .then(on_vote("n0", L1_LB_A)).then(on_vote("n1", L1_LB_A))
        .then(on_vote("n3", L1_LB_B)).then(on_vote("n4", L1_LB_B))
        // The Byzantine key votes for both blocks.
        .then(byzantine_notarize_vote_step_framed(
            "n5", L1_LB_A, L1_ZERO_POS, L1_NO_EXT))
        .then(byzantine_notarize_vote_step_framed(
            "n5", L1_LB_B, L1_ZERO_POS, L1_NO_EXT))

        // Each collector receives an exact-L message set with M votes for
        // its designated block and two votes for the other block.
        .then(l1_deliver_notarize("n0","n0",L1_LB_A))
        .then(l1_deliver_notarize("n0","n1",L1_LB_A))
        .then(l1_deliver_notarize("n0","n5",L1_LB_A))
        .then(l1_deliver_notarize("n0","n3",L1_LB_B))
        .then(l1_deliver_notarize("n0","n4",L1_LB_B))
        .then(on_vqc("n0", L1_LB_A, 1))
        .then(l1_deliver_notarize("n3","n3",L1_LB_B))
        .then(l1_deliver_notarize("n3","n4",L1_LB_B))
        .then(l1_deliver_notarize("n3","n5",L1_LB_B))
        .then(l1_deliver_notarize("n3","n0",L1_LB_A))
        .then(l1_deliver_notarize("n3","n1",L1_LB_A))
        .then(on_vqc("n3", L1_LB_B, 2))

        .expect(store_certificate.get("n0").exists(c =>
            match c {
                | Notarization(q) => q.leader_block == L1_LB_A
                | Nullification(_) => false
            }))
        .expect(store_certificate.get("n3").exists(c =>
            match c {
                | Notarization(q) => q.leader_block == L1_LB_B
                | Nullification(_) => false
            }))
        // Neither block has L votes, so no L-QC is present and the two
        // differently designated V-QCs satisfy L1.
        .expect(REPLICA_IDS.forall(id => {
            val pool = notarize_votes(store_vote.get(id))
            not(pool.exists(v => pool_finalizes(pool, v.leader_block, PARAMS)))
        }))
        .expect(l1_lqc_vqc_designation)
        .expect(all_invariants)
    }
}
