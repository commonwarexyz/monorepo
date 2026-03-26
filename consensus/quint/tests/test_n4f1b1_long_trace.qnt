module tests {
    import types.* from "../types"
    import defs.* from "../defs"
    import option.* from "../option"
    import automaton(
        CERTIFY_DOMAIN = Set("val_b0", "val_b1", "val_b2", "val_b3", "val_b4", "val_b5", "val_b6", "val_b7", "val_b8", "val_b9", "val_b10", "val_b11", "val_b12", "val_b13", "val_b14", "val_b15", "val_b16"),
    ) as app from "../automaton"
    import replica(
        N = 4,
        F = 1,
        Q = 3,
        CORRECT = Set("n1", "n2", "n3"),
        BYZANTINE = Set("n0"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3"),
        VIEWS = 1.to(14),
        VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2", "val_b3", "val_b4", "val_b5", "val_b6", "val_b7", "val_b8", "val_b9", "val_b10", "val_b11", "val_b12", "val_b13", "val_b14", "val_b15", "val_b16"),
        INVALID_PAYLOADS = Set()
    ).* from "../replica"

    pure val CERTIFY_POLICY = Map(
        GENESIS_PAYLOAD -> true,
        "val_b0" -> true,
        "val_b1" -> true,
        "val_b2" -> true,
        "val_b3" -> false,
        "val_b4" -> true,
        "val_b5" -> true,
        "val_b6" -> true,
        "val_b7" -> true,
        "val_b8" -> true,
        "val_b9" -> true,
        "val_b10" -> true,
        "val_b11" -> false,
        "val_b12" -> true,
        "val_b13" -> false,
        "val_b14" -> false,
        "val_b15" -> true,
        "val_b16" -> false,
    )
    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)

    pure val proposal_v1_val_b0 = { payload: "val_b0", view: 1, parent: GENESIS_VIEW, sig: sig_of("n2") }
    pure val proposal_v2_val_b1 = { payload: "val_b1", view: 2, parent: 1, sig: sig_of("n3") }
    pure val proposal_v3_val_b2 = { payload: "val_b2", view: 3, parent: 2, sig: sig_of("n0") }
    pure val proposal_v3_val_b3 = { payload: "val_b3", view: 3, parent: 2, sig: sig_of("n0") }
    pure val proposal_v4_val_b4 = { payload: "val_b4", view: 4, parent: 2, sig: sig_of("n1") }
    pure val proposal_v5_val_b5 = { payload: "val_b5", view: 5, parent: 4, sig: sig_of("n2") }
    pure val proposal_v6_val_b6 = { payload: "val_b6", view: 6, parent: 5, sig: sig_of("n3") }
    pure val proposal_v7_val_b7 = { payload: "val_b7", view: 7, parent: 6, sig: sig_of("n0") }
    pure val proposal_v7_val_b8 = { payload: "val_b8", view: 7, parent: 6, sig: sig_of("n0") }
    pure val proposal_v8_val_b9 = { payload: "val_b9", view: 8, parent: 7, sig: sig_of("n1") }
    pure val proposal_v9_val_b10 = { payload: "val_b10", view: 9, parent: 8, sig: sig_of("n2") }
    pure val proposal_v10_val_b11 = { payload: "val_b11", view: 10, parent: 9, sig: sig_of("n3") }
    pure val proposal_v11_val_b12 = { payload: "val_b12", view: 11, parent: 9, sig: sig_of("n0") }
    pure val proposal_v11_val_b13 = { payload: "val_b13", view: 11, parent: 9, sig: sig_of("n0") }
    pure val proposal_v12_val_b14 = { payload: "val_b14", view: 12, parent: 9, sig: sig_of("n1") }
    pure val proposal_v13_val_b15 = { payload: "val_b15", view: 13, parent: 9, sig: sig_of("n2") }
    pure val proposal_v14_val_b16 = { payload: "val_b16", view: 14, parent: 13, sig: sig_of("n3") }

    action trace_part_00 =
        initWithLeaderAndCertify(
            Map(0 -> "n1", 1 -> "n2", 2 -> "n3", 3 -> "n0", 4 -> "n1", 5 -> "n2", 6 -> "n3", 7 -> "n0", 8 -> "n1", 9 -> "n2", 10 -> "n3", 11 -> "n0", 12 -> "n1", 13 -> "n2", 14 -> "n3"),
            CERTIFY_CUSTOM
        )
            .then(inject_proposal(proposal_v1_val_b0))
            .then(on_proposal("n2", proposal_v1_val_b0))
            .then(on_vote_notarize("n2", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n2"))))
            .then(on_proposal("n1", proposal_v1_val_b0))
            .then(on_vote_notarize("n1", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n1"), notarize(proposal_v1_val_b0, "n2"))))
            .then(on_proposal("n3", proposal_v1_val_b0))
            .then(on_vote_notarize("n3", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n3"), notarize(proposal_v1_val_b0, "n2"))))
            .then(inject_vote(notarize(proposal_v1_val_b0, "n0")))
            .then(on_vote_notarize("n3", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n0"), notarize(proposal_v1_val_b0, "n1"))))
            .then(on_vote_notarize("n2", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n0"), notarize(proposal_v1_val_b0, "n3"), notarize(proposal_v1_val_b0, "n1"))))
            .then(on_vote_notarize("n1", 1, "val_b0", Set(notarize(proposal_v1_val_b0, "n0"), notarize(proposal_v1_val_b0, "n3"))))
            .then(on_certificate("n3", notarization(proposal_v1_val_b0, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n2", notarization(proposal_v1_val_b0, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n1", notarization(proposal_v1_val_b0, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n3", notarization(proposal_v1_val_b0, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n2", notarization(proposal_v1_val_b0, Set("n0", "n1", "n2"), "n1")))
            .then(on_vote_finalize("n1", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n1"), finalize(proposal_v1_val_b0, "n2"), finalize(proposal_v1_val_b0, "n3"))))
            .then(on_vote_finalize("n3", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n1"), finalize(proposal_v1_val_b0, "n3"), finalize(proposal_v1_val_b0, "n2"))))
            .then(on_vote_finalize("n2", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n1"), finalize(proposal_v1_val_b0, "n2"), finalize(proposal_v1_val_b0, "n3"))))
            .then(inject_vote(finalize(proposal_v1_val_b0, "n0")))
            .then(on_vote_finalize("n1", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n0"))))
            .then(on_vote_finalize("n3", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n0"))))
            .then(on_vote_finalize("n2", 1, "val_b0", Set(finalize(proposal_v1_val_b0, "n0"))))
            .then(inject_proposal(proposal_v2_val_b1))
            .then(on_proposal("n3", proposal_v2_val_b1))
            .expect(all_invariants)

    action trace_part_01 =
        trace_part_00
            .then(on_vote_notarize("n3", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n3"))))
            .then(on_proposal("n1", proposal_v2_val_b1))
            .then(on_vote_notarize("n1", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n1"), notarize(proposal_v2_val_b1, "n3"))))
            .then(on_proposal("n2", proposal_v2_val_b1))
            .then(on_vote_notarize("n2", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n2"), notarize(proposal_v2_val_b1, "n3"))))
            .then(on_certificate("n1", finalization(proposal_v1_val_b0, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n3", finalization(proposal_v1_val_b0, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", finalization(proposal_v1_val_b0, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n2", finalization(proposal_v1_val_b0, Set("n0", "n1", "n2"), "n0")))
            .then(on_certificate("n3", finalization(proposal_v1_val_b0, Set("n0", "n1", "n2"), "n0")))
            .then(on_certificate("n1", finalization(proposal_v1_val_b0, Set("n0", "n1", "n2"), "n0")))
            .then(inject_vote(notarize(proposal_v2_val_b1, "n0")))
            .then(on_vote_notarize("n3", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n0"), notarize(proposal_v2_val_b1, "n2"))))
            .then(on_vote_notarize("n2", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n0"))))
            .then(on_vote_notarize("n1", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n2"))))
            .then(on_certificate("n3", notarization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n2")))
            .then(on_vote_notarize("n3", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n1"))))
            .then(on_vote_notarize("n2", 2, "val_b1", Set(notarize(proposal_v2_val_b1, "n1"))))
            .then(on_certificate("n1", notarization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n3", notarization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", notarization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n2", notarization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n1")))
            .then(on_vote_finalize("n2", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n2"))))
            .then(on_vote_finalize("n1", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n2"))))
            .then(on_vote_finalize("n3", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n2"))))
            .expect(all_invariants)

    action trace_part_02 =
        trace_part_01
            .then(inject_vote(finalize(proposal_v2_val_b1, "n0")))
            .then(on_vote_finalize("n2", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n0"), finalize(proposal_v2_val_b1, "n1"))))
            .then(on_vote_finalize("n3", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n0"))))
            .then(on_vote_finalize("n1", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n1"))))
            .then(on_certificate("n1", notarization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n0")))
            .then(on_vote_finalize("n3", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n1"), finalize(proposal_v2_val_b1, "n3"))))
            .then(on_vote_finalize("n1", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n3"))))
            .then(on_vote_finalize("n2", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n3"))))
            .then(on_certificate("n1", finalization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n3")))
            .then(on_vote_finalize("n1", 2, "val_b1", Set(finalize(proposal_v2_val_b1, "n0"))))
            .then(on_certificate("n3", finalization(proposal_v2_val_b1, Set("n0", "n1", "n2"), "n2")))
            .then(inject_proposal(proposal_v3_val_b2))
            .then(on_proposal("n3", proposal_v3_val_b2))
            .then(on_vote_notarize("n3", 3, "val_b2", Set(notarize(proposal_v3_val_b2, "n3"))))
            .then(inject_vote(notarize(proposal_v3_val_b2, "n0")))
            .then(on_vote_notarize("n3", 3, "val_b2", Set(notarize(proposal_v3_val_b2, "n0"))))
            .then(on_certificate("n2", finalization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n1", finalization(proposal_v2_val_b1, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n3", finalization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", finalization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n3", finalization(proposal_v2_val_b1, Set("n0", "n2", "n3"), "n0")))
            .then(inject_proposal(proposal_v3_val_b3))
            .then(on_proposal("n2", proposal_v3_val_b3))
            .then(on_vote_notarize("n2", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n2"))))
            .then(inject_vote(notarize(proposal_v3_val_b3, "n0")))
            .expect(all_invariants)

    action trace_part_03 =
        trace_part_02
            .then(on_vote_notarize("n2", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n0"))))
            .then(on_proposal("n1", proposal_v3_val_b3))
            .then(on_vote_notarize("n1", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n1"), notarize(proposal_v3_val_b3, "n0"))))
            .then(on_vote_notarize("n2", 3, "val_b2", Set(notarize(proposal_v3_val_b2, "n3"))))
            .then(on_certificate("n1", finalization(proposal_v2_val_b1, Set("n1", "n2", "n3"), "n0")))
            .then(on_vote_notarize("n1", 3, "val_b2", Set(notarize(proposal_v3_val_b2, "n3"))))
            .then(on_vote_notarize("n3", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n2"), notarize(proposal_v3_val_b3, "n1"))))
            .then(on_vote_notarize("n1", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n2"))))
            .then(on_vote_notarize("n2", 3, "val_b3", Set(notarize(proposal_v3_val_b3, "n1"))))
            .then(on_certificate("n2", notarization(proposal_v3_val_b3, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n3", notarization(proposal_v3_val_b3, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v3_val_b3, Set("n0", "n1", "n2"), "n2")))
            .then(on_vote_nullify("n2", 3, Set(nullify(3, "n2"), nullify(3, "n1"))))
            .then(on_vote_nullify("n3", 3, Set(nullify(3, "n2"), nullify(3, "n1"))))
            .then(on_vote_nullify("n1", 3, Set(nullify(3, "n1"), nullify(3, "n2"))))
            .then(inject_vote(nullify(3, "n0")))
            .then(on_vote_nullify("n2", 3, Set(nullify(3, "n0"))))
            .then(on_vote_nullify("n1", 3, Set(nullify(3, "n0"))))
            .then(on_certificate("n2", nullification(3, Set("n0", "n1", "n2"), "n0")))
            .then(on_vote_nullify("n3", 3, Set(nullify(3, "n3"))))
            .then(on_vote_nullify("n2", 3, Set(nullify(3, "n3"))))
            .then(on_certificate("n1", nullification(3, Set("n0", "n1", "n2"), "n0")))
            .then(on_vote_nullify("n1", 3, Set(nullify(3, "n3"))))
            .then(on_certificate("n1", nullification(3, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n2", nullification(3, Set("n1", "n2", "n3"), "n3")))
            .expect(all_invariants)

    action trace_part_04 =
        trace_part_03
            .then(on_certificate("n3", nullification(3, Set("n0", "n1", "n2"), "n2")))
            .then(on_vote_nullify("n3", 3, Set(nullify(3, "n0"))))
            .then(on_certificate("n3", nullification(3, Set("n1", "n2", "n3"), "n0")))
            .then(inject_proposal(proposal_v4_val_b4))
            .then(on_proposal("n1", proposal_v4_val_b4))
            .then(on_vote_notarize("n1", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n1"))))
            .then(on_proposal("n2", proposal_v4_val_b4))
            .then(on_vote_notarize("n2", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n2"), notarize(proposal_v4_val_b4, "n1"))))
            .then(on_proposal("n3", proposal_v4_val_b4))
            .then(on_vote_notarize("n3", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n3"), notarize(proposal_v4_val_b4, "n1"), notarize(proposal_v4_val_b4, "n2"))))
            .then(on_vote_notarize("n1", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n2"), notarize(proposal_v4_val_b4, "n3"))))
            .then(on_vote_notarize("n2", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n3"))))
            .then(inject_vote(notarize(proposal_v4_val_b4, "n0")))
            .then(on_vote_notarize("n1", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n0"))))
            .then(on_vote_notarize("n3", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n0"))))
            .then(on_vote_notarize("n2", 4, "val_b4", Set(notarize(proposal_v4_val_b4, "n0"))))
            .then(on_certificate("n2", notarization(proposal_v4_val_b4, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n1", notarization(proposal_v4_val_b4, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n1", notarization(proposal_v4_val_b4, Set("n0", "n1", "n2"), "n0")))
            .then(on_certificate("n3", notarization(proposal_v4_val_b4, Set("n0", "n1", "n2"), "n0")))
            .then(on_certificate("n3", notarization(proposal_v4_val_b4, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", notarization(proposal_v4_val_b4, Set("n0", "n1", "n2"), "n0")))
            .then(on_vote_finalize("n3", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n3"), finalize(proposal_v4_val_b4, "n1"))))
            .then(on_vote_finalize("n2", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n3"), finalize(proposal_v4_val_b4, "n1"))))
            .then(on_vote_finalize("n1", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n3"), finalize(proposal_v4_val_b4, "n1"))))
            .expect(all_invariants)

    action trace_part_05 =
        trace_part_04
            .then(inject_vote(finalize(proposal_v4_val_b4, "n0")))
            .then(on_vote_finalize("n3", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n0"), finalize(proposal_v4_val_b4, "n2"))))
            .then(on_vote_finalize("n2", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n2"), finalize(proposal_v4_val_b4, "n0"))))
            .then(on_vote_finalize("n1", 4, "val_b4", Set(finalize(proposal_v4_val_b4, "n0"), finalize(proposal_v4_val_b4, "n2"))))
            .then(on_certificate("n1", finalization(proposal_v4_val_b4, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n1", finalization(proposal_v4_val_b4, Set("n0", "n1", "n3"), "n0")))
            .then(inject_proposal(proposal_v5_val_b5))
            .then(on_proposal("n2", proposal_v5_val_b5))
            .then(on_vote_notarize("n2", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n2"))))
            .then(on_proposal("n1", proposal_v5_val_b5))
            .then(on_vote_notarize("n1", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n1"), notarize(proposal_v5_val_b5, "n2"))))
            .then(on_certificate("n3", finalization(proposal_v4_val_b4, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n3", finalization(proposal_v4_val_b4, Set("n0", "n1", "n3"), "n0")))
            .then(on_proposal("n3", proposal_v5_val_b5))
            .then(on_vote_notarize("n3", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n3"), notarize(proposal_v5_val_b5, "n2"))))
            .then(on_certificate("n2", finalization(proposal_v4_val_b4, Set("n0", "n1", "n3"), "n0")))
            .then(inject_vote(notarize(proposal_v5_val_b5, "n0")))
            .then(on_vote_notarize("n1", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n0"), notarize(proposal_v5_val_b5, "n3"))))
            .then(on_vote_notarize("n3", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n0"), notarize(proposal_v5_val_b5, "n1"))))
            .then(on_vote_notarize("n2", 5, "val_b5", Set(notarize(proposal_v5_val_b5, "n3"), notarize(proposal_v5_val_b5, "n0"), notarize(proposal_v5_val_b5, "n1"))))
            .then(on_certificate("n1", notarization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n3", notarization(proposal_v5_val_b5, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n2", notarization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n2", notarization(proposal_v5_val_b5, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n3", notarization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n2")))
            .expect(all_invariants)

    action trace_part_06 =
        trace_part_05
            .then(on_vote_finalize("n2", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n2"), finalize(proposal_v5_val_b5, "n3"), finalize(proposal_v5_val_b5, "n1"))))
            .then(on_vote_finalize("n1", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n2"), finalize(proposal_v5_val_b5, "n3"), finalize(proposal_v5_val_b5, "n1"))))
            .then(on_vote_finalize("n3", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n2"), finalize(proposal_v5_val_b5, "n3"), finalize(proposal_v5_val_b5, "n1"))))
            .then(inject_vote(finalize(proposal_v5_val_b5, "n0")))
            .then(on_vote_finalize("n3", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n0"))))
            .then(inject_proposal(proposal_v6_val_b6))
            .then(on_proposal("n3", proposal_v6_val_b6))
            .then(on_vote_notarize("n3", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n3"))))
            .then(on_proposal("n1", proposal_v6_val_b6))
            .then(on_vote_notarize("n1", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n1"), notarize(proposal_v6_val_b6, "n3"))))
            .then(on_vote_finalize("n1", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n0"))))
            .then(on_vote_finalize("n2", 5, "val_b5", Set(finalize(proposal_v5_val_b5, "n0"))))
            .then(on_proposal("n2", proposal_v6_val_b6))
            .then(on_vote_notarize("n2", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n2"), notarize(proposal_v6_val_b6, "n3"))))
            .then(on_certificate("n3", finalization(proposal_v5_val_b5, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n1", finalization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n2", finalization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n2", finalization(proposal_v5_val_b5, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n3", finalization(proposal_v5_val_b5, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n1", finalization(proposal_v5_val_b5, Set("n1", "n2", "n3"), "n2")))
            .then(inject_vote(notarize(proposal_v6_val_b6, "n0")))
            .then(on_vote_notarize("n3", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n0"), notarize(proposal_v6_val_b6, "n1"), notarize(proposal_v6_val_b6, "n2"))))
            .then(on_vote_notarize("n2", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n0"), notarize(proposal_v6_val_b6, "n1"))))
            .then(on_vote_notarize("n1", 6, "val_b6", Set(notarize(proposal_v6_val_b6, "n2"))))
            .then(on_certificate("n1", notarization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n2")))
            .expect(all_invariants)

    action trace_part_07 =
        trace_part_06
            .then(on_certificate("n3", notarization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n2", notarization(proposal_v6_val_b6, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n1", notarization(proposal_v6_val_b6, Set("n0", "n1", "n3"), "n3")))
            .then(on_vote_finalize("n2", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n2"))))
            .then(on_vote_finalize("n3", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n2"))))
            .then(on_vote_finalize("n1", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n2"))))
            .then(on_certificate("n2", notarization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", notarization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n3", notarization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n1")))
            .then(on_vote_finalize("n3", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n3"))))
            .then(on_vote_finalize("n2", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n3"))))
            .then(on_vote_finalize("n1", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n3"))))
            .then(inject_vote(finalize(proposal_v6_val_b6, "n0")))
            .then(on_vote_finalize("n2", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n0"))))
            .then(on_vote_finalize("n3", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n0"))))
            .then(on_certificate("n1", notarization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n0")))
            .then(on_vote_finalize("n1", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n1"))))
            .then(on_vote_finalize("n3", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n1"))))
            .then(on_certificate("n2", finalization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n3", finalization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n0")))
            .then(on_vote_finalize("n2", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n1"))))
            .then(on_certificate("n3", finalization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", finalization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n1", finalization(proposal_v6_val_b6, Set("n0", "n2", "n3"), "n2")))
            .then(inject_proposal(proposal_v7_val_b7))
            .expect(all_invariants)

    action trace_part_08 =
        trace_part_07
            .then(on_proposal("n3", proposal_v7_val_b7))
            .then(on_vote_notarize("n3", 7, "val_b7", Set(notarize(proposal_v7_val_b7, "n3"))))
            .then(inject_vote(notarize(proposal_v7_val_b7, "n0")))
            .then(on_vote_notarize("n3", 7, "val_b7", Set(notarize(proposal_v7_val_b7, "n0"))))
            .then(on_vote_finalize("n1", 6, "val_b6", Set(finalize(proposal_v6_val_b6, "n0"))))
            .then(on_certificate("n1", finalization(proposal_v6_val_b6, Set("n1", "n2", "n3"), "n0")))
            .then(on_vote_notarize("n2", 7, "val_b7", Set(notarize(proposal_v7_val_b7, "n3"))))
            .then(on_vote_notarize("n1", 7, "val_b7", Set(notarize(proposal_v7_val_b7, "n3"))))
            .then(inject_proposal(proposal_v7_val_b8))
            .then(on_proposal("n1", proposal_v7_val_b8))
            .then(on_vote_notarize("n1", 7, "val_b8", Set(notarize(proposal_v7_val_b8, "n1"))))
            .then(inject_vote(notarize(proposal_v7_val_b8, "n0")))
            .then(on_vote_notarize("n1", 7, "val_b8", Set(notarize(proposal_v7_val_b8, "n0"))))
            .then(on_proposal("n2", proposal_v7_val_b8))
            .then(on_vote_notarize("n2", 7, "val_b8", Set(notarize(proposal_v7_val_b8, "n2"), notarize(proposal_v7_val_b8, "n0"), notarize(proposal_v7_val_b8, "n1"))))
            .then(on_vote_notarize("n1", 7, "val_b8", Set(notarize(proposal_v7_val_b8, "n2"))))
            .then(on_vote_notarize("n3", 7, "val_b8", Set(notarize(proposal_v7_val_b8, "n2"), notarize(proposal_v7_val_b8, "n1"))))
            .then(on_certificate("n2", notarization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n3", notarization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n2")))
            .then(on_vote_finalize("n1", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n1"))))
            .then(on_vote_finalize("n2", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n1"))))
            .then(on_vote_finalize("n3", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n1"))))
            .then(inject_vote(finalize(proposal_v7_val_b8, "n0")))
            .then(on_vote_finalize("n1", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n0"), finalize(proposal_v7_val_b8, "n2"))))
            .expect(all_invariants)

    action trace_part_09 =
        trace_part_08
            .then(on_vote_finalize("n2", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n0"), finalize(proposal_v7_val_b8, "n2"))))
            .then(on_vote_finalize("n3", 7, "val_b8", Set(finalize(proposal_v7_val_b8, "n2"))))
            .then(on_certificate("n1", finalization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n3", finalization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n2")))
            .then(inject_proposal(proposal_v8_val_b9))
            .then(on_proposal("n1", proposal_v8_val_b9))
            .then(on_vote_notarize("n1", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n1"))))
            .then(on_proposal("n3", proposal_v8_val_b9))
            .then(on_vote_notarize("n3", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n3"), notarize(proposal_v8_val_b9, "n1"))))
            .then(on_proposal("n2", proposal_v8_val_b9))
            .then(on_vote_notarize("n2", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n2"), notarize(proposal_v8_val_b9, "n1"))))
            .then(on_certificate("n2", finalization(proposal_v7_val_b8, Set("n0", "n1", "n2"), "n1")))
            .then(inject_vote(notarize(proposal_v8_val_b9, "n0")))
            .then(on_vote_notarize("n1", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n0"), notarize(proposal_v8_val_b9, "n2"), notarize(proposal_v8_val_b9, "n3"))))
            .then(on_vote_notarize("n2", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n0"), notarize(proposal_v8_val_b9, "n3"))))
            .then(on_vote_notarize("n3", 8, "val_b9", Set(notarize(proposal_v8_val_b9, "n0"), notarize(proposal_v8_val_b9, "n2"))))
            .then(on_certificate("n1", notarization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n2", notarization(proposal_v8_val_b9, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n1", notarization(proposal_v8_val_b9, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n3", notarization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n2", notarization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n1")))
            .then(on_vote_finalize("n1", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n1"))))
            .then(on_vote_finalize("n3", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n1"))))
            .then(on_vote_finalize("n2", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n1"))))
            .then(inject_vote(finalize(proposal_v8_val_b9, "n0")))
            .expect(all_invariants)

    action trace_part_10 =
        trace_part_09
            .then(on_vote_finalize("n2", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n0"), finalize(proposal_v8_val_b9, "n2"), finalize(proposal_v8_val_b9, "n3"))))
            .then(on_vote_finalize("n3", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n0"), finalize(proposal_v8_val_b9, "n2"), finalize(proposal_v8_val_b9, "n3"))))
            .then(on_vote_finalize("n1", 8, "val_b9", Set(finalize(proposal_v8_val_b9, "n0"), finalize(proposal_v8_val_b9, "n2"), finalize(proposal_v8_val_b9, "n3"))))
            .then(on_certificate("n3", finalization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n1", finalization(proposal_v8_val_b9, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n1", finalization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n2", finalization(proposal_v8_val_b9, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n2", finalization(proposal_v8_val_b9, Set("n0", "n1", "n3"), "n3")))
            .then(inject_proposal(proposal_v9_val_b10))
            .then(on_proposal("n2", proposal_v9_val_b10))
            .then(on_vote_notarize("n2", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n2"))))
            .then(on_proposal("n1", proposal_v9_val_b10))
            .then(on_vote_notarize("n1", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n1"), notarize(proposal_v9_val_b10, "n2"))))
            .then(on_proposal("n3", proposal_v9_val_b10))
            .then(on_vote_notarize("n3", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n3"), notarize(proposal_v9_val_b10, "n2"), notarize(proposal_v9_val_b10, "n1"))))
            .then(on_vote_notarize("n1", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n3"))))
            .then(on_vote_notarize("n2", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n3"), notarize(proposal_v9_val_b10, "n1"))))
            .then(inject_vote(notarize(proposal_v9_val_b10, "n0")))
            .then(on_vote_notarize("n2", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n0"))))
            .then(on_vote_notarize("n3", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n0"))))
            .then(on_vote_notarize("n1", 9, "val_b10", Set(notarize(proposal_v9_val_b10, "n0"))))
            .then(on_certificate("n2", notarization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n2", notarization(proposal_v9_val_b10, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v9_val_b10, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n1", notarization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n0")))
            .expect(all_invariants)

    action trace_part_11 =
        trace_part_10
            .then(on_certificate("n3", notarization(proposal_v9_val_b10, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n3", notarization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n0")))
            .then(on_vote_finalize("n2", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n2"))))
            .then(on_vote_finalize("n3", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n2"))))
            .then(on_vote_finalize("n1", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n2"))))
            .then(inject_vote(finalize(proposal_v9_val_b10, "n0")))
            .then(on_vote_finalize("n1", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n0"), finalize(proposal_v9_val_b10, "n3"), finalize(proposal_v9_val_b10, "n1"))))
            .then(on_vote_finalize("n2", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n0"), finalize(proposal_v9_val_b10, "n3"), finalize(proposal_v9_val_b10, "n1"))))
            .then(on_vote_finalize("n3", 9, "val_b10", Set(finalize(proposal_v9_val_b10, "n0"), finalize(proposal_v9_val_b10, "n3"), finalize(proposal_v9_val_b10, "n1"))))
            .then(on_certificate("n1", finalization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n2", finalization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n3")))
            .then(on_certificate("n2", finalization(proposal_v9_val_b10, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n3", finalization(proposal_v9_val_b10, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n3", finalization(proposal_v9_val_b10, Set("n0", "n1", "n2"), "n1")))
            .then(inject_proposal(proposal_v10_val_b11))
            .then(on_proposal("n3", proposal_v10_val_b11))
            .then(on_vote_notarize("n3", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n3"))))
            .then(on_proposal("n2", proposal_v10_val_b11))
            .then(on_vote_notarize("n2", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n2"), notarize(proposal_v10_val_b11, "n3"))))
            .then(on_proposal("n1", proposal_v10_val_b11))
            .then(on_vote_notarize("n1", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n1"), notarize(proposal_v10_val_b11, "n3"), notarize(proposal_v10_val_b11, "n2"))))
            .then(on_vote_notarize("n2", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n1"))))
            .then(on_vote_notarize("n3", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n1"))))
            .then(inject_vote(notarize(proposal_v10_val_b11, "n0")))
            .then(on_vote_notarize("n3", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n0"), notarize(proposal_v10_val_b11, "n2"))))
            .expect(all_invariants)

    action trace_part_12 =
        trace_part_11
            .then(on_vote_notarize("n2", 10, "val_b11", Set(notarize(proposal_v10_val_b11, "n0"))))
            .then(on_certificate("n1", notarization(proposal_v10_val_b11, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n3", notarization(proposal_v10_val_b11, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n2", notarization(proposal_v10_val_b11, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v10_val_b11, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n2", notarization(proposal_v10_val_b11, Set("n0", "n1", "n3"), "n3")))
            .then(on_certificate("n2", notarization(proposal_v10_val_b11, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n3", notarization(proposal_v10_val_b11, Set("n0", "n2", "n3"), "n0")))
            .then(on_vote_nullify("n2", 10, Set(nullify(10, "n2"), nullify(10, "n3"))))
            .then(on_vote_nullify("n1", 10, Set(nullify(10, "n2"), nullify(10, "n3"))))
            .then(on_vote_nullify("n3", 10, Set(nullify(10, "n2"), nullify(10, "n3"))))
            .then(inject_vote(nullify(10, "n0")))
            .then(on_vote_nullify("n3", 10, Set(nullify(10, "n0"), nullify(10, "n1"))))
            .then(on_vote_nullify("n2", 10, Set(nullify(10, "n0"), nullify(10, "n1"))))
            .then(on_vote_nullify("n1", 10, Set(nullify(10, "n1"))))
            .then(on_certificate("n3", nullification(10, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n2", nullification(10, Set("n0", "n2", "n3"), "n0")))
            .then(on_certificate("n1", nullification(10, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n3", nullification(10, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n2", nullification(10, Set("n1", "n2", "n3"), "n1")))
            .then(on_certificate("n1", nullification(10, Set("n1", "n2", "n3"), "n0")))
            .then(inject_proposal(proposal_v11_val_b12))
            .then(on_proposal("n3", proposal_v11_val_b12))
            .then(on_vote_notarize("n3", 11, "val_b12", Set(notarize(proposal_v11_val_b12, "n3"))))
            .then(inject_vote(notarize(proposal_v11_val_b12, "n0")))
            .expect(all_invariants)

    action trace_part_13 =
        trace_part_12
            .then(on_vote_notarize("n3", 11, "val_b12", Set(notarize(proposal_v11_val_b12, "n0"))))
            .then(inject_proposal(proposal_v11_val_b13))
            .then(on_proposal("n1", proposal_v11_val_b13))
            .then(on_vote_notarize("n1", 11, "val_b13", Set(notarize(proposal_v11_val_b13, "n1"))))
            .then(inject_vote(notarize(proposal_v11_val_b13, "n0")))
            .then(on_vote_notarize("n1", 11, "val_b13", Set(notarize(proposal_v11_val_b13, "n0"))))
            .then(on_proposal("n2", proposal_v11_val_b13))
            .then(on_vote_notarize("n2", 11, "val_b13", Set(notarize(proposal_v11_val_b13, "n2"), notarize(proposal_v11_val_b13, "n0"), notarize(proposal_v11_val_b13, "n1"))))
            .then(on_vote_notarize("n2", 11, "val_b12", Set(notarize(proposal_v11_val_b12, "n3"))))
            .then(on_vote_notarize("n1", 11, "val_b12", Set(notarize(proposal_v11_val_b12, "n3"))))
            .then(on_vote_notarize("n3", 11, "val_b13", Set(notarize(proposal_v11_val_b13, "n2"), notarize(proposal_v11_val_b13, "n1"))))
            .then(on_vote_notarize("n1", 11, "val_b13", Set(notarize(proposal_v11_val_b13, "n2"))))
            .then(on_certificate("n2", notarization(proposal_v11_val_b13, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n3", notarization(proposal_v11_val_b13, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v11_val_b13, Set("n0", "n1", "n2"), "n0")))
            .then(on_vote_nullify("n1", 11, Set(nullify(11, "n1"))))
            .then(on_vote_nullify("n2", 11, Set(nullify(11, "n1"))))
            .then(on_vote_nullify("n3", 11, Set(nullify(11, "n1"))))
            .then(inject_vote(nullify(11, "n0")))
            .then(on_vote_nullify("n2", 11, Set(nullify(11, "n0"), nullify(11, "n3"), nullify(11, "n2"))))
            .then(on_vote_nullify("n3", 11, Set(nullify(11, "n3"), nullify(11, "n2"))))
            .then(on_vote_nullify("n1", 11, Set(nullify(11, "n3"), nullify(11, "n0"), nullify(11, "n2"))))
            .then(on_certificate("n3", nullification(11, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n3", nullification(11, Set("n0", "n1", "n3"), "n1")))
            .then(on_certificate("n2", nullification(11, Set("n0", "n1", "n3"), "n1")))
            .expect(all_invariants)

    action trace_part_14 =
        trace_part_13
            .then(on_certificate("n1", nullification(11, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n1", nullification(11, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n2", nullification(11, Set("n1", "n2", "n3"), "n3")))
            .then(on_certificate("n2", nullification(11, Set("n0", "n1", "n2"), "n0")))
            .then(on_vote_nullify("n3", 11, Set(nullify(11, "n0"))))
            .then(inject_proposal(proposal_v12_val_b14))
            .then(on_proposal("n1", proposal_v12_val_b14))
            .then(on_vote_notarize("n1", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n1"))))
            .then(on_proposal("n2", proposal_v12_val_b14))
            .then(on_vote_notarize("n2", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n2"), notarize(proposal_v12_val_b14, "n1"))))
            .then(on_proposal("n3", proposal_v12_val_b14))
            .then(on_vote_notarize("n3", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n3"), notarize(proposal_v12_val_b14, "n1"))))
            .then(on_certificate("n3", nullification(11, Set("n1", "n2", "n3"), "n0")))
            .then(on_vote_notarize("n1", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n3"), notarize(proposal_v12_val_b14, "n2"))))
            .then(on_vote_notarize("n2", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n3"))))
            .then(on_vote_notarize("n3", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n2"))))
            .then(inject_vote(notarize(proposal_v12_val_b14, "n0")))
            .then(on_vote_notarize("n2", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n0"))))
            .then(on_certificate("n3", notarization(proposal_v12_val_b14, Set("n1", "n2", "n3"), "n2")))
            .then(on_vote_notarize("n3", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n0"))))
            .then(on_certificate("n1", notarization(proposal_v12_val_b14, Set("n1", "n2", "n3"), "n2")))
            .then(on_certificate("n1", notarization(proposal_v12_val_b14, Set("n0", "n1", "n3"), "n0")))
            .then(on_vote_notarize("n1", 12, "val_b14", Set(notarize(proposal_v12_val_b14, "n0"))))
            .then(on_certificate("n3", notarization(proposal_v12_val_b14, Set("n0", "n1", "n3"), "n0")))
            .then(on_certificate("n2", notarization(proposal_v12_val_b14, Set("n0", "n1", "n3"), "n0")))
            .expect(all_invariants)

    action trace_part_15 =
        trace_part_14
            .then(on_certificate("n2", notarization(proposal_v12_val_b14, Set("n1", "n2", "n3"), "n1")))
            .then(inject_vote(nullify(12, "n0")))
            .then(on_vote_nullify("n1", 12, Set(nullify(12, "n0"), nullify(12, "n3"), nullify(12, "n1"), nullify(12, "n2"))))
            .then(on_vote_nullify("n3", 12, Set(nullify(12, "n3"), nullify(12, "n0"), nullify(12, "n1"), nullify(12, "n2"))))
            .then(on_vote_nullify("n2", 12, Set(nullify(12, "n3"), nullify(12, "n0"), nullify(12, "n2"), nullify(12, "n1"))))
            .then(on_certificate("n1", nullification(12, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n2", nullification(12, Set("n0", "n1", "n3"), "n1")))
            .then(on_certificate("n3", nullification(12, Set("n0", "n2", "n3"), "n2")))
            .then(on_certificate("n3", nullification(12, Set("n0", "n1", "n3"), "n1")))
            .then(on_certificate("n1", nullification(12, Set("n0", "n1", "n3"), "n3")))
            .then(inject_proposal(proposal_v13_val_b15))
            .then(on_proposal("n2", proposal_v13_val_b15))
            .then(on_vote_notarize("n2", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n2"))))
            .then(on_proposal("n1", proposal_v13_val_b15))
            .then(on_vote_notarize("n1", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n1"), notarize(proposal_v13_val_b15, "n2"))))
            .then(on_proposal("n3", proposal_v13_val_b15))
            .then(on_vote_notarize("n3", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n3"), notarize(proposal_v13_val_b15, "n2"))))
            .then(inject_vote(notarize(proposal_v13_val_b15, "n0")))
            .then(on_vote_notarize("n1", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n0"), notarize(proposal_v13_val_b15, "n3"))))
            .then(on_vote_notarize("n3", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n1"), notarize(proposal_v13_val_b15, "n0"))))
            .then(on_vote_notarize("n2", 13, "val_b15", Set(notarize(proposal_v13_val_b15, "n0"), notarize(proposal_v13_val_b15, "n1"), notarize(proposal_v13_val_b15, "n3"))))
            .then(on_certificate("n2", notarization(proposal_v13_val_b15, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v13_val_b15, Set("n0", "n1", "n2"), "n2")))
            .then(on_certificate("n3", notarization(proposal_v13_val_b15, Set("n0", "n1", "n2"), "n1")))
            .then(on_certificate("n1", notarization(proposal_v13_val_b15, Set("n1", "n2", "n3"), "n3")))
            .expect(all_invariants)

    action trace_part_16 =
        trace_part_15
            .then(on_certificate("n2", notarization(proposal_v13_val_b15, Set("n1", "n2", "n3"), "n3")))
            .then(on_vote_finalize("n3", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n3"))))
            .then(on_vote_finalize("n2", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n3"))))
            .then(on_vote_finalize("n1", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n3"))))
            .then(inject_vote(finalize(proposal_v13_val_b15, "n0")))
            .then(on_vote_finalize("n3", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n0"), finalize(proposal_v13_val_b15, "n2"), finalize(proposal_v13_val_b15, "n1"))))
            .then(on_vote_finalize("n2", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n2"), finalize(proposal_v13_val_b15, "n0"))))
            .then(on_vote_finalize("n1", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n2"), finalize(proposal_v13_val_b15, "n0"), finalize(proposal_v13_val_b15, "n1"))))
            .then(inject_proposal(proposal_v14_val_b16))
            .then(on_proposal("n3", proposal_v14_val_b16))
            .then(on_vote_notarize("n3", 14, "val_b16", Set(notarize(proposal_v14_val_b16, "n3"))))
            .then(on_vote_notarize("n1", 14, "val_b16", Set(notarize(proposal_v14_val_b16, "n3"))))
            .then(on_vote_notarize("n2", 14, "val_b16", Set(notarize(proposal_v14_val_b16, "n3"))))
            .then(on_vote_finalize("n2", 13, "val_b15", Set(finalize(proposal_v13_val_b15, "n1"))))
            .expect(all_invariants)

    run traceTest =
        trace_part_16
            .expect(all_invariants)
            .expect(replica_state.get("n1").last_finalized >= 10)
            .expect(replica_state.get("n2").last_finalized >= 10)
            .expect(replica_state.get("n3").last_finalized >= 10)

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
        certify_policy' = certify_policy,
        lastAction' = "inject_proposal",
    }

    action inject_vote(vote: Vote): bool = all {
        sent_vote' = sent_vote.union(Set(vote)),
        sent_proposal' = sent_proposal,
        sent_certificate' = sent_certificate,
        store_vote' = store_vote,
        store_certificate' = store_certificate,
        ghost_proposal' = ghost_proposal,
        ghost_committed_blocks' = ghost_committed_blocks,
        leader' = leader,
        replica_state' = replica_state,
        certify_policy' = certify_policy,
        lastAction' = "inject_vote",
    }
}
