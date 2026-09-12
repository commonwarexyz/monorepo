// Focused coverage for the explicit Byzantine consensus actions at
// N = 6, T = 1, F = 1. Unlike the ordinary scripted instance, this one
// includes view 5, whose leader is n5 (chain 6), and raises e to 2 so a
// single vote can demonstrate the complete bounded extension domain.
//
//   quint test tests/tests_byzantine_n6t1f1.qnt

module tests_byzantine_n6t1f1 {
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
        EXT_E = 2
    ).* from "../consensus"

    pure val B1A = mkBlock(1, [1])

    action send_complex_proposal: bool = {
        nondet c = oneOf(sent_da_certificates.filter(dc => dc.block == B1A))
        val lb: LeaderBlock = {
            view: 5,
            // A syntactically bounded but unresolved parent is allowed
            // onto the network. Correct proposal validation rejects it.
            parent_vqc: EMPTY_VQC_HASH,
            proposal: Map(
                1 -> { anchor: CertAnchor(c), payloads: [2, 1] },
                2 -> { anchor: HashAnchor(mkBlock(2, [2])), payloads: [1, 2] },
                3 -> { anchor: HashAnchor(genesis_block(3)), payloads: [2] },
                4 -> { anchor: HashAnchor(mkBlock(4, [1, 1])), payloads: List() },
                5 -> { anchor: HashAnchor(genesis_block(5)), payloads: [1] },
                6 -> { anchor: HashAnchor(mkBlock(6, [2])), payloads: [2, 2] }
            ),
        }
        byzantine_leader_block_step_framed("n5", lb)
    }

    action send_complex_vote: bool = {
        nondet lb = oneOf(sent_leader_block.filter(x => x.view == 5))
        val positions: Positions = Map(
            1 -> 1, 2 -> 2, 3 -> 0, 4 -> 0, 5 -> 1, 6 -> 0)
        val extensions: Extensions = Map(
            1 -> [1, 2], 2 -> List(), 3 -> [2],
            4 -> [1], 5 -> [2, 2], 6 -> [1])
        byzantine_notarize_vote_step_framed(
            "n5", lb, positions, extensions)
    }

    run fullByzantineMessageSpaceTest = {
        init
            // Build one authentic DA-certificate so the proposal can
            // atomically mix certificate and arbitrary hash anchors.
            .then(chain_produce("n0", genesis_block(1), 1))
            .then(chain_da_vote("n0", B1A))
            .then(chain_da_vote("n1", B1A))
            .then(chain_da_vote("n2", B1A))
            .then(chain_da_vote("n3", B1A))
            .then(chain_certify(B1A))
            .expect(sent_da_certificates.exists(c => c.block == B1A))
            .expect(bounded_payload_lists(2).size() == 7)
            .expect(bounded_payload_lists(2).contains([1, 2]))
            .then(send_complex_proposal)
            .expect(sent_leader_block.exists(lb => and {
                lb.view == 5,
                lb.parent_vqc == EMPTY_VQC_HASH,
                bounded_byzantine_leader_block(lb),
                match lb.proposal.get(1).anchor {
                    | CertAnchor(c) => c.block == B1A
                    | HashAnchor(_) => false
                },
                num_proposal_entries(lb.proposal, 1) == 2,
                num_proposal_entries(lb.proposal, 2) == 2,
                num_proposal_entries(lb.proposal, 3) == 1,
                num_proposal_entries(lb.proposal, 4) == 0,
                lb.proposal.get(1).payloads != lb.proposal.get(2).payloads,
            }))
            .then(send_complex_vote)
            .expect(notarize_votes(sent_vote).exists(v => and {
                v.sig == "n5",
                vote_wellformed(v, PARAMS),
                v.positions.get(1) == 1,
                v.positions.get(2) == 2,
                v.positions.get(3) == 0,
                v.extensions.get(1) == [1, 2],
                v.extensions.get(2) == List(),
                v.extensions.get(5) == [2, 2],
                endorsed_tip(v, 1) == mkBlock(1, [1, 2, 1, 2]),
                endorsed_tip(v, 2) == mkBlock(2, [2, 1, 2]),
                endorsed_tip(v, 4) == mkBlock(4, [1, 1, 1]),
            }))
            .expect(all_invariants)
    }
}
