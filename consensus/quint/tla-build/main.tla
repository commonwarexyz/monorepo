--------------------------------- MODULE main ---------------------------------

EXTENDS Integers, Sequences, FiniteSets, TLC, Apalache, Variants

(*
  @type: (() => Set(Int));
*)
main_replica_VIEWS == 1 .. 30

(*
  @type: (() => Set(Str));
*)
main_replica_CORRECT == { "n0", "n1", "n2", "n3" }

(*
  @type: (() => Set(Str));
*)
main_replica_BYZANTINE == {}

(*
  @type: (() => Set(Str));
*)
main_replica_VALID_PAYLOADS ==
  { "val_b0",
    "val_b1",
    "val_b2",
    "val_b3",
    "val_b4",
    "val_b5",
    "val_b6",
    "val_b7",
    "val_b8",
    "val_b9",
    "val_b10" }

(*
  @type: (() => Str);
*)
main_replica_GENESIS_PAYLOAD == "GENESIS_PAYLOAD"

(*
  @type: (() => Set(Str));
*)
main_replica_INVALID_PAYLOADS == { "inval_0", "inval_1" }

VARIABLE
  (*
    @type: (Str -> { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
  *)
  main_replica_replica_state

(*
  @type: (() => Int);
*)
main_replica_FIRST_VIEW == 1

(*
  @type: (() => Int);
*)
main_replica_GENESIS_VIEW == 0

(*
  @type: (() => None({ tag: Str }) | Some(a));
*)
main_replica_None == Variant("None", [tag |-> "UNIT"])

(*
  @type: ((b) => None({ tag: Str }) | Some(b));
*)
main_replica_Some(main_replica___SomeParam_5823) ==
  Variant("Some", main_replica___SomeParam_5823)

VARIABLE
  (*
    @type: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str });
  *)
  main_replica_sent_notarize_votes

VARIABLE
  (*
    @type: Set({ sig: Str, view: Int });
  *)
  main_replica_sent_nullify_votes

VARIABLE
  (*
    @type: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str });
  *)
  main_replica_sent_finalize_votes

VARIABLE
  (*
    @type: Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
  *)
  main_replica_sent_certificates

VARIABLE
  (*
    @type: (Str -> Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_store_notarize_votes

VARIABLE
  (*
    @type: (Str -> Set({ sig: Str, view: Int }));
  *)
  main_replica_store_nullify_votes

VARIABLE
  (*
    @type: (Str -> Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_store_finalize_votes

VARIABLE
  (*
    @type: (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_store_certificates

VARIABLE
  (*
    @type: (Str -> Seq({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_ghost_committed_blocks

VARIABLE
  (*
    @type: (Int -> Str);
  *)
  main_replica_leader

VARIABLE
  (*
    @type: (Str -> Set(Str));
  *)
  main_replica_certify_policy

VARIABLE
  (*
    @type: Str;
  *)
  main_replica_lastAction

(*
  @type: ((None({ tag: Str }) | Some(d)) => Bool);
*)
main_replica_is_some(main_replica_opt_5844) ==
  CASE VariantTag(main_replica_opt_5844) = "Some"
      -> LET (*
        @type: ((d) => Bool);
      *)
      __QUINT_LAMBDA0(main_replica___5839) == TRUE
      IN
      __QUINT_LAMBDA0(VariantGetUnsafe("Some", main_replica_opt_5844))
    [] VariantTag(main_replica_opt_5844) = "None"
      -> LET (*
        @type: (({ tag: Str }) => Bool);
      *)
      __QUINT_LAMBDA1(main_replica___5842) == FALSE
      IN
      __QUINT_LAMBDA1(VariantGetUnsafe("None", main_replica_opt_5844))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_is_nullification_cert(main_replica_c_349) ==
  CASE VariantTag(main_replica_c_349) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
      *)
      __QUINT_LAMBDA2(main_replica___344) == TRUE
      IN
      __QUINT_LAMBDA2(VariantGetUnsafe("Nullification", main_replica_c_349))
    [] OTHER
      -> (LET (*
        @type: ((e) => Bool);
      *)
      __QUINT_LAMBDA3(main_replica___347) == FALSE
      IN
      __QUINT_LAMBDA3({}))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Int);
*)
main_replica_cert_view(main_replica_c_191) ==
  CASE VariantTag(main_replica_c_191) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Int);
      *)
      __QUINT_LAMBDA4(main_replica_n_183) ==
        main_replica_n_183["proposal"]["view"]
      IN
      __QUINT_LAMBDA4(VariantGetUnsafe("Notarization", main_replica_c_191))
    [] VariantTag(main_replica_c_191) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Int);
      *)
      __QUINT_LAMBDA5(main_replica_n_186) == main_replica_n_186["view"]
      IN
      __QUINT_LAMBDA5(VariantGetUnsafe("Nullification", main_replica_c_191))
    [] VariantTag(main_replica_c_191) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Int);
      *)
      __QUINT_LAMBDA6(main_replica_f_189) ==
        main_replica_f_189["proposal"]["view"]
      IN
      __QUINT_LAMBDA6(VariantGetUnsafe("Finalization", main_replica_c_191))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_is_finalization_cert(main_replica_c_364) ==
  CASE VariantTag(main_replica_c_364) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA7(main_replica___359) == TRUE
      IN
      __QUINT_LAMBDA7(VariantGetUnsafe("Finalization", main_replica_c_364))
    [] OTHER
      -> (LET (*
        @type: ((f) => Bool);
      *)
      __QUINT_LAMBDA8(main_replica___362) == FALSE
      IN
      __QUINT_LAMBDA8({}))

(*
  @type: (() => (Str -> Str));
*)
main_replica_REPLICA_KEYS ==
  SetAsFun({ <<"n0", "n0">>, <<"n1", "n1">>, <<"n2", "n2">>, <<"n3", "n3">> })

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, Str) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_remember_timeout_reason(main_replica_self_1065, main_replica_view_1065,
main_replica_reason_1065) ==
  main_replica_self_1065

(*
  @type: (() => Str);
*)
main_replica_InvalidProposalReason == "InvalidProposal"

(*
  @type: (() => Str);
*)
main_replica_NotarizeKind == "NOTARIZE_KIND"

(*
  @type: (() => Str);
*)
main_replica_NullifyKind == "NULLIFY_KIND"

(*
  @type: ((None({ tag: Str }) | Some(h), ((h) => Bool)) => Bool);
*)
main_replica_option_has(main_replica_opt_5895, main_replica_pred_5895(_)) ==
  CASE VariantTag(main_replica_opt_5895) = "None"
      -> LET (*
        @type: (({ tag: Str }) => Bool);
      *)
      __QUINT_LAMBDA22(main_replica___5890) == FALSE
      IN
      __QUINT_LAMBDA22(VariantGetUnsafe("None", main_replica_opt_5895))
    [] VariantTag(main_replica_opt_5895) = "Some"
      -> LET (*
        @type: ((h) => Bool);
      *)
      __QUINT_LAMBDA23(main_replica_e_5893) ==
        main_replica_pred_5895(main_replica_e_5893)
      IN
      __QUINT_LAMBDA23(VariantGetUnsafe("Some", main_replica_opt_5895))

(*
  @type: (() => Str);
*)
main_replica_LeaderTimeoutKind == "LEADER_TIMEOUT_KIND"

(*
  @type: (() => Str);
*)
main_replica_CertificationTimeoutKind == "CERTIFICATION_TIMEOUT_KIND"

(*
  @type: (() => Str);
*)
main_replica_LeaderTimeoutReason == "LeaderTimeout"

(*
  @type: (() => Str);
*)
main_replica_CertificationTimeoutReason == "CertificationTimeout"

(*
  @type: (() => Int);
*)
main_replica_Q == 3

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Str);
*)
main_replica_cert_ghost_sender(main_replica_c_242) ==
  CASE VariantTag(main_replica_c_242) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA30(main_replica_n_234) == main_replica_n_234["ghost_sender"]
      IN
      __QUINT_LAMBDA30(VariantGetUnsafe("Notarization", main_replica_c_242))
    [] VariantTag(main_replica_c_242) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Str);
      *)
      __QUINT_LAMBDA31(main_replica_n_237) == main_replica_n_237["ghost_sender"]
      IN
      __QUINT_LAMBDA31(VariantGetUnsafe("Nullification", main_replica_c_242))
    [] VariantTag(main_replica_c_242) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA32(main_replica_f_240) == main_replica_f_240["ghost_sender"]
      IN
      __QUINT_LAMBDA32(VariantGetUnsafe("Finalization", main_replica_c_242))

(*
  @type: (() => Str);
*)
main_replica_NotarizationKind == "NOTARIZATION_KIND"

(*
  @type: (() => Str);
*)
main_replica_NullificationKind == "NULLIFICATION_KIND"

(*
  @type: (() => Str);
*)
main_replica_FinalizationKind == "FINALIZATION_KIND"

(*
  @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_Notarization(main_replica___NotarizationParam_5683) ==
  Variant("Notarization", main_replica___NotarizationParam_5683)

(*
  @type: (() => Str);
*)
main_replica_FailedCertificationReason == "FailedCertification"

(*
  @type: (() => Str);
*)
main_replica_FinalizeKind == "FINALIZE_KIND"

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_is_notarization_cert(main_replica_c_334) ==
  CASE VariantTag(main_replica_c_334) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA36(main_replica___329) == TRUE
      IN
      __QUINT_LAMBDA36(VariantGetUnsafe("Notarization", main_replica_c_334))
    [] OTHER
      -> (LET (*
        @type: ((k) => Bool);
      *)
      __QUINT_LAMBDA37(main_replica___332) == FALSE
      IN
      __QUINT_LAMBDA37({}))

(*
  @type: (() => Int);
*)
main_replica_ACTIVITY_TIMEOUT == 10

(*
  @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_Finalization(main_replica___FinalizationParam_5695) ==
  Variant("Finalization", main_replica___FinalizationParam_5695)

(*
  @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_Nullification(main_replica___NullificationParam_5689) ==
  Variant("Nullification", main_replica___NullificationParam_5689)

(*
  @type: ((Seq({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => Bool);
*)
main_replica_list_contains_proposal(main_replica_chain_1200, main_replica_proposal_1200) ==
  \E main_replica_i_1198 \in LET (*
    @type: (() => Set(Int));
  *)
  __quint_var14 == DOMAIN main_replica_chain_1200
  IN
  IF __quint_var14 = {}
  THEN {}
  ELSE (__quint_var14 \union {0}) \ {(Len(main_replica_chain_1200))}:
    main_replica_chain_1200[(main_replica_i_1198 + 1)]
      = main_replica_proposal_1200

(*
  @type: (() => Str);
*)
main_replica_LeaderNullifyReason == "LeaderNullify"

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set(Str));
*)
main_replica_cert_signatures(main_replica_c_217) ==
  CASE VariantTag(main_replica_c_217) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Str));
      *)
      __QUINT_LAMBDA66(main_replica_n_209) == main_replica_n_209["signatures"]
      IN
      __QUINT_LAMBDA66(VariantGetUnsafe("Notarization", main_replica_c_217))
    [] VariantTag(main_replica_c_217) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Set(Str));
      *)
      __QUINT_LAMBDA67(main_replica_n_212) == main_replica_n_212["signatures"]
      IN
      __QUINT_LAMBDA67(VariantGetUnsafe("Nullification", main_replica_c_217))
    [] VariantTag(main_replica_c_217) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Str));
      *)
      __QUINT_LAMBDA68(main_replica_f_215) == main_replica_f_215["signatures"]
      IN
      __QUINT_LAMBDA68(VariantGetUnsafe("Finalization", main_replica_c_217))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_same_certificate_subject(main_replica_existing_1131, main_replica_cert_1131) ==
  CASE VariantTag(main_replica_existing_1131) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA71(main_replica_n1_1123) ==
        CASE VariantTag(main_replica_cert_1131) = "Notarization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA69(main_replica_n2_1084) ==
              main_replica_n1_1123["proposal"]
                = main_replica_n2_1084["proposal"]
            IN
            __QUINT_LAMBDA69(VariantGetUnsafe("Notarization", main_replica_cert_1131))
          [] OTHER
            -> (LET (*
              @type: ((l) => Bool);
            *)
            __QUINT_LAMBDA70(main_replica___1087) == FALSE
            IN
            __QUINT_LAMBDA70({}))
      IN
      __QUINT_LAMBDA71(VariantGetUnsafe("Notarization", main_replica_existing_1131))
    [] VariantTag(main_replica_existing_1131) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
      *)
      __QUINT_LAMBDA74(main_replica_n1_1126) ==
        CASE VariantTag(main_replica_cert_1131) = "Nullification"
            -> LET (*
              @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
            *)
            __QUINT_LAMBDA72(main_replica_n2_1100) ==
              main_replica_n1_1126["view"] = main_replica_n2_1100["view"]
            IN
            __QUINT_LAMBDA72(VariantGetUnsafe("Nullification", main_replica_cert_1131))
          [] OTHER
            -> (LET (*
              @type: ((m) => Bool);
            *)
            __QUINT_LAMBDA73(main_replica___1103) == FALSE
            IN
            __QUINT_LAMBDA73({}))
      IN
      __QUINT_LAMBDA74(VariantGetUnsafe("Nullification", main_replica_existing_1131))
    [] VariantTag(main_replica_existing_1131) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA77(main_replica_f1_1129) ==
        CASE VariantTag(main_replica_cert_1131) = "Finalization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA75(main_replica_f2_1116) ==
              main_replica_f1_1129["proposal"]
                = main_replica_f2_1116["proposal"]
            IN
            __QUINT_LAMBDA75(VariantGetUnsafe("Finalization", main_replica_cert_1131))
          [] OTHER
            -> (LET (*
              @type: ((n) => Bool);
            *)
            __QUINT_LAMBDA76(main_replica___1119) == FALSE
            IN
            __QUINT_LAMBDA76({}))
      IN
      __QUINT_LAMBDA77(VariantGetUnsafe("Finalization", main_replica_existing_1131))

(*
  @type: (() => Set(Str));
*)
main_replica_Replicas == main_replica_CORRECT \union main_replica_BYZANTINE

(*
  @type: (() => Set(Str));
*)
main_replica_AllPayloads ==
  (main_replica_VALID_PAYLOADS \union {(main_replica_GENESIS_PAYLOAD)})
    \union main_replica_INVALID_PAYLOADS

(*
  @type: (((Int -> Str), (Str -> Set(Str))) => Bool);
*)
main_replica_initWithLeaderAndCertify(main_replica_l_2271, main_replica_certify_2271) ==
  main_replica_replica_state
      = [
        main_replica_id_2210 \in main_replica_CORRECT |->
          [view |-> main_replica_FIRST_VIEW,
            ghost_last_seen_notarization |-> main_replica_GENESIS_VIEW,
            last_finalized |-> main_replica_GENESIS_VIEW,
            proposal |->
              [
                main_replica___2174 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_proposal |->
              [
                main_replica___2180 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_proposal_conflicted |->
              [ main_replica___2186 \in main_replica_VIEWS |-> FALSE ],
            certified |->
              [
                main_replica___2192 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_timeout |->
              [
                main_replica___2199 \in main_replica_VIEWS |->
                  main_replica_Some(FALSE)
              ],
            certification_timeout |->
              [
                main_replica___2206 \in main_replica_VIEWS |->
                  main_replica_Some(FALSE)
              ]]
      ]
    /\ main_replica_sent_notarize_votes = {}
    /\ main_replica_sent_nullify_votes = {}
    /\ main_replica_sent_finalize_votes = {}
    /\ main_replica_sent_certificates = {}
    /\ main_replica_store_notarize_votes
      = [ main_replica___2229 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_nullify_votes
      = [ main_replica___2236 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_finalize_votes
      = [ main_replica___2243 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_certificates
      = [ main_replica___2250 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_ghost_committed_blocks
      = [ main_replica___2257 \in main_replica_CORRECT |-> <<>> ]
    /\ main_replica_leader = main_replica_l_2271
    /\ main_replica_certify_policy = main_replica_certify_2271
    /\ main_replica_lastAction = "init"

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Bool);
*)
main_replica_is_view_nullified(main_replica_view_844, main_replica_certificates_844) ==
  main_replica_view_844 = main_replica_GENESIS_VIEW
    \/ (\E main_replica_c_841 \in main_replica_certificates_844:
      main_replica_is_nullification_cert(main_replica_c_841)
        /\ main_replica_cert_view(main_replica_c_841) = main_replica_view_844)

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_cert_proposal(main_replica_c_300) ==
  CASE VariantTag(main_replica_c_300) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA9(main_replica_n_292) ==
        main_replica_Some(main_replica_n_292["proposal"])
      IN
      __QUINT_LAMBDA9(VariantGetUnsafe("Notarization", main_replica_c_300))
    [] VariantTag(main_replica_c_300) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA10(main_replica___295) == main_replica_None
      IN
      __QUINT_LAMBDA10(VariantGetUnsafe("Nullification", main_replica_c_300))
    [] VariantTag(main_replica_c_300) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA11(main_replica_f_298) ==
        main_replica_Some(main_replica_f_298["proposal"])
      IN
      __QUINT_LAMBDA11(VariantGetUnsafe("Finalization", main_replica_c_300))

(*
  @type: ((Str) => Str);
*)
main_replica_sig_of(main_replica_id_94) ==
  (main_replica_REPLICA_KEYS)[main_replica_id_94]

(*
  @type: ((None({ tag: Str }) | Some(c)) => Bool);
*)
main_replica_is_none(main_replica_opt_5854) ==
  ~(main_replica_is_some(main_replica_opt_5854))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_observe_leader_proposal(main_replica_self_933, main_replica_proposal_933) ==
  LET (*
    @type: (() => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_known ==
    main_replica_self_933["leader_proposal"][main_replica_proposal_933["view"]]
  IN
  [
    [
      main_replica_self_933 EXCEPT
        !["leader_proposal"] =
          LET (*
            @type: (() => (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })));
          *)
          __quint_var0 == main_replica_self_933["leader_proposal"]
          IN
          LET (*
            @type: (() => Set(Int));
          *)
          __quint_var1 == DOMAIN __quint_var0
          IN
          [
            __quint_var2 \in
              {main_replica_proposal_933["view"]} \union __quint_var1 |->
              IF __quint_var2 = main_replica_proposal_933["view"]
              THEN CASE VariantTag((main_replica_known)) = "Some"
                  -> LET (*
                    @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
                  *)
                  __QUINT_LAMBDA24(main_replica_p_900) ==
                    main_replica_Some(main_replica_p_900)
                  IN
                  __QUINT_LAMBDA24(VariantGetUnsafe("Some", (main_replica_known)))
                [] VariantTag((main_replica_known)) = "None"
                  -> LET (*
                    @type: (({ tag: Str }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
                  *)
                  __QUINT_LAMBDA25(main_replica___903) ==
                    main_replica_Some(main_replica_proposal_933)
                  IN
                  __QUINT_LAMBDA25(VariantGetUnsafe("None", (main_replica_known)))
              ELSE (__quint_var0)[__quint_var2]
          ]
    ] EXCEPT
      !["leader_proposal_conflicted"] =
        LET (*
          @type: (() => (Int -> Bool));
        *)
        __quint_var3 == main_replica_self_933["leader_proposal_conflicted"]
        IN
        LET (*@type: (() => Set(Int)); *) __quint_var4 == DOMAIN __quint_var3 IN
        [
          __quint_var5 \in
            {main_replica_proposal_933["view"]} \union __quint_var4 |->
            IF __quint_var5 = main_replica_proposal_933["view"]
            THEN main_replica_self_933["leader_proposal_conflicted"][
                main_replica_proposal_933["view"]
              ]
              \/ LET (*
                @type: (({ parent: Int, payload: Str, view: Int }) => Bool);
              *)
              __QUINT_LAMBDA26(main_replica_p_925) ==
                main_replica_p_925 /= main_replica_proposal_933
              IN
              main_replica_option_has((main_replica_known), __QUINT_LAMBDA26)
            ELSE (__quint_var3)[__quint_var5]
        ]
  ]

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_record_local_proposal(main_replica_self_963, main_replica_proposal_963) ==
  IF main_replica_self_963["proposal"][main_replica_proposal_963["view"]]
    = main_replica_None
  THEN [
    main_replica_self_963 EXCEPT
      !["proposal"] =
        [
          main_replica_self_963["proposal"] EXCEPT
            ![main_replica_proposal_963["view"]] =
              main_replica_Some(main_replica_proposal_963)
        ]
  ]
  ELSE main_replica_self_963

(*
  @type: (((Int -> None({ tag: Str }) | Some(Bool)), Int) => Bool);
*)
main_replica_timeout_pending(main_replica_timers_1551, main_replica_view_1551) ==
  main_replica_timers_1551[main_replica_view_1551] = main_replica_Some(FALSE)

(*
  @type: (((Int -> None({ tag: Str }) | Some(Bool)), Int) => Bool);
*)
main_replica_timeout_fired(main_replica_timers_1568, main_replica_view_1568) ==
  main_replica_timers_1568[main_replica_view_1568] = main_replica_Some(TRUE)

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => Bool);
*)
main_replica_has_leader_proposal_conflict(main_replica_self_1055, main_replica_proposal_1055) ==
  main_replica_self_1055["leader_proposal_conflicted"][
      main_replica_proposal_1055["view"]
    ]
    \/ LET (*
      @type: (({ parent: Int, payload: Str, view: Int }) => Bool);
    *)
    __QUINT_LAMBDA27(main_replica_known_1052) ==
      main_replica_known_1052 /= main_replica_proposal_1055
    IN
    main_replica_option_has(main_replica_self_1055["leader_proposal"][
      main_replica_proposal_1055["view"]
    ], __QUINT_LAMBDA27)

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }, Bool) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_observe_round_proposal(main_replica_self_1027, main_replica_proposal_1027,
main_replica_recovered_1027) ==
  IF main_replica_self_1027["leader_proposal_conflicted"][
    main_replica_proposal_1027["view"]
  ]
  THEN main_replica_self_1027
  ELSE CASE VariantTag(main_replica_self_1027["proposal"][
      main_replica_proposal_1027["view"]
    ])
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
      *)
      __QUINT_LAMBDA28(main_replica___1021) ==
        [
          main_replica_self_1027 EXCEPT
            !["proposal"] =
              [
                main_replica_self_1027["proposal"] EXCEPT
                  ![main_replica_proposal_1027["view"]] =
                    main_replica_Some(main_replica_proposal_1027)
              ]
        ]
      IN
      __QUINT_LAMBDA28(VariantGetUnsafe("None", main_replica_self_1027[
        "proposal"
      ][
        main_replica_proposal_1027["view"]
      ]))
    [] VariantTag(main_replica_self_1027["proposal"][
      main_replica_proposal_1027["view"]
    ])
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
      *)
      __QUINT_LAMBDA29(main_replica_existing_1024) ==
        IF main_replica_existing_1024 = main_replica_proposal_1027
        THEN main_replica_self_1027
        ELSE IF main_replica_recovered_1027
        THEN [
          main_replica_self_1027 EXCEPT
            !["proposal"] =
              [
                main_replica_self_1027["proposal"] EXCEPT
                  ![main_replica_proposal_1027["view"]] =
                    main_replica_Some(main_replica_proposal_1027)
              ]
        ]
        ELSE main_replica_self_1027
      IN
      __QUINT_LAMBDA29(VariantGetUnsafe("Some", main_replica_self_1027[
        "proposal"
      ][
        main_replica_proposal_1027["view"]
      ]))

(*
  @type: ((Str, Str) => Bool);
*)
main_replica_can_certify(main_replica_id_1501, main_replica_payload_1501) ==
  main_replica_payload_1501
    \in main_replica_certify_policy[main_replica_id_1501]

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Str);
*)
main_replica_cert_kind(main_replica_c_319) ==
  CASE VariantTag(main_replica_c_319) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA33(main_replica___311) == main_replica_NotarizationKind
      IN
      __QUINT_LAMBDA33(VariantGetUnsafe("Notarization", main_replica_c_319))
    [] VariantTag(main_replica_c_319) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Str);
      *)
      __QUINT_LAMBDA34(main_replica___314) == main_replica_NullificationKind
      IN
      __QUINT_LAMBDA34(VariantGetUnsafe("Nullification", main_replica_c_319))
    [] VariantTag(main_replica_c_319) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA35(main_replica___317) == main_replica_FinalizationKind
      IN
      __QUINT_LAMBDA35(VariantGetUnsafe("Finalization", main_replica_c_319))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_enter_view(main_replica_self_1534, main_replica_new_view_1534) ==
  IF ~(main_replica_new_view_1534 \in main_replica_VIEWS)
    \/ main_replica_self_1534["view"] >= main_replica_new_view_1534
  THEN main_replica_self_1534
  ELSE [
    [
      [ main_replica_self_1534 EXCEPT !["view"] = main_replica_new_view_1534 ] EXCEPT
        !["leader_timeout"] = main_replica_self_1534["leader_timeout"]
    ] EXCEPT
      !["certification_timeout"] =
        main_replica_self_1534["certification_timeout"]
  ]

(*
  @type: (({ parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => Bool);
*)
main_replica_is_proposal_notarized_votes(main_replica_proposal_783, main_replica_votes_783) ==
  (main_replica_proposal_783["view"] = main_replica_GENESIS_VIEW
      /\ main_replica_proposal_783["payload"] = main_replica_GENESIS_PAYLOAD)
    \/ Cardinality({
      main_replica_v_777["sig"]:
        main_replica_v_777 \in
          {
            main_replica_v_771 \in main_replica_votes_783:
              main_replica_v_771["proposal"] = main_replica_proposal_783
          }
    })
      >= main_replica_Q

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Str) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_cert_with_sender(main_replica_cert_1182, main_replica_sender_1182) ==
  CASE VariantTag(main_replica_cert_1182) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA52(main_replica_n_1174) ==
        main_replica_Notarization([
          main_replica_n_1174 EXCEPT
            !["ghost_sender"] = main_replica_sender_1182
        ])
      IN
      __QUINT_LAMBDA52(VariantGetUnsafe("Notarization", main_replica_cert_1182))
    [] VariantTag(main_replica_cert_1182) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA53(main_replica_n_1177) ==
        main_replica_Nullification([
          main_replica_n_1177 EXCEPT
            !["ghost_sender"] = main_replica_sender_1182
        ])
      IN
      __QUINT_LAMBDA53(VariantGetUnsafe("Nullification", main_replica_cert_1182))
    [] VariantTag(main_replica_cert_1182) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA54(main_replica_f_1180) ==
        main_replica_Finalization([
          main_replica_f_1180 EXCEPT
            !["ghost_sender"] = main_replica_sender_1182
        ])
      IN
      __QUINT_LAMBDA54(VariantGetUnsafe("Finalization", main_replica_cert_1182))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_cancel_all_timers(main_replica_self_1618, main_replica_view_1618) ==
  [
    [
      main_replica_self_1618 EXCEPT
        !["leader_timeout"] =
          [
            main_replica_self_1618["leader_timeout"] EXCEPT
              ![main_replica_view_1618] = main_replica_None
          ]
    ] EXCEPT
      !["certification_timeout"] =
        [
          main_replica_self_1618["certification_timeout"] EXCEPT
            ![main_replica_view_1618] = main_replica_None
        ]
  ]

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_fire_all_timers(main_replica_self_1594, main_replica_view_1594) ==
  [
    [
      main_replica_self_1594 EXCEPT
        !["leader_timeout"] =
          [
            main_replica_self_1594["leader_timeout"] EXCEPT
              ![main_replica_view_1594] = main_replica_Some(TRUE)
          ]
    ] EXCEPT
      !["certification_timeout"] =
        [
          main_replica_self_1594["certification_timeout"] EXCEPT
            ![main_replica_view_1594] = main_replica_Some(TRUE)
        ]
  ]

(*
  @type: (((Int -> Str)) => Bool);
*)
main_replica_initWithLeader(main_replica_l_2151) ==
  LET (*
    @type: (() => (Str -> Set(Str)));
  *)
  main_replica_default_certify_policy ==
    [
      main_replica___2144 \in main_replica_Replicas |->
        main_replica_AllPayloads
    ]
  IN
  main_replica_initWithLeaderAndCertify(main_replica_l_2151, (main_replica_default_certify_policy))

(*
  @type: ((Int, Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Bool);
*)
main_replica_are_views_nullified(main_replica_v1_871, main_replica_v2_871, main_replica_certificates_871) ==
  \A main_replica_v_869 \in {
    main_replica_v_863 \in main_replica_VIEWS:
      main_replica_v_863 > main_replica_v1_871
        /\ main_replica_v_863 < main_replica_v2_871
  }:
    main_replica_is_view_nullified(main_replica_v_869, main_replica_certificates_871)

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_finalized_proposal_at(main_replica_view_1255, main_replica_certificates_1255) ==
  LET (*
    @type: (() => Set({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_proposals ==
    LET (*
      @type: ((Set({ parent: Int, payload: Str, view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set({ parent: Int, payload: Str, view: Int }));
    *)
    __QUINT_LAMBDA14(main_replica_acc_1237, main_replica_c_1237) ==
      IF main_replica_is_finalization_cert(main_replica_c_1237)
        /\ main_replica_cert_view(main_replica_c_1237) = main_replica_view_1255
      THEN CASE VariantTag((main_replica_cert_proposal(main_replica_c_1237)))
          = "Some"
          -> LET (*
            @type: (({ parent: Int, payload: Str, view: Int }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA12(main_replica_p_1230) ==
            main_replica_acc_1237 \union {main_replica_p_1230}
          IN
          __QUINT_LAMBDA12(VariantGetUnsafe("Some", (main_replica_cert_proposal(main_replica_c_1237))))
        [] VariantTag((main_replica_cert_proposal(main_replica_c_1237)))
          = "None"
          -> LET (*
            @type: (({ tag: Str }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA13(main_replica___1233) == main_replica_acc_1237
          IN
          __QUINT_LAMBDA13(VariantGetUnsafe("None", (main_replica_cert_proposal(main_replica_c_1237))))
      ELSE main_replica_acc_1237
    IN
    ApaFoldSet(__QUINT_LAMBDA14, {}, main_replica_certificates_1255)
  IN
  IF Cardinality((main_replica_proposals)) = 1
  THEN LET (*
    @type: ((None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA15(main_replica__acc_1250, main_replica_p_1250) ==
    main_replica_Some(main_replica_p_1250)
  IN
  ApaFoldSet(__QUINT_LAMBDA15, (main_replica_None), (main_replica_proposals))
  ELSE main_replica_None

(*
  @type: ((Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Str, Int) => Bool);
*)
main_replica_broadcast_finalize_in(main_replica_sent_finalize_494, main_replica_id_494,
main_replica_view_494) ==
  \E main_replica_v_492 \in main_replica_sent_finalize_494:
    main_replica_v_492["sig"] = main_replica_sig_of(main_replica_id_494)
      /\ main_replica_v_492["proposal"]["view"] = main_replica_view_494

(*
  @type: ((Str, Int, Str) => Bool);
*)
main_replica_has_sent_vote(main_replica_id_433, main_replica_view_433, main_replica_kind_433) ==
  IF main_replica_kind_433 = main_replica_NotarizeKind
  THEN \E main_replica_v_392 \in main_replica_sent_notarize_votes:
    main_replica_v_392["sig"] = main_replica_sig_of(main_replica_id_433)
      /\ main_replica_v_392["proposal"]["view"] = main_replica_view_433
  ELSE IF main_replica_kind_433 = main_replica_NullifyKind
  THEN \E main_replica_v_411 \in main_replica_sent_nullify_votes:
    main_replica_v_411["sig"] = main_replica_sig_of(main_replica_id_433)
      /\ main_replica_v_411["view"] = main_replica_view_433
  ELSE \E main_replica_v_429 \in main_replica_sent_finalize_votes:
    main_replica_v_429["sig"] = main_replica_sig_of(main_replica_id_433)
      /\ main_replica_v_429["proposal"]["view"] = main_replica_view_433

(*
  @type: ((Str, { parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
*)
main_replica_create_notarization(main_replica_id_2054, main_replica_proposal_2054,
main_replica_votes_2054) ==
  LET (*
    @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_2026 \in main_replica_votes_2054:
        main_replica_v_2026["proposal"] = main_replica_proposal_2054
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_2034["sig"]:
        main_replica_v_2034 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([proposal |-> main_replica_proposal_2054,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2054)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_notarization(main_replica_id_519, main_replica_view_519) ==
  \E main_replica_c_517 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_517)
        = main_replica_sig_of(main_replica_id_519)
      /\ main_replica_cert_kind(main_replica_c_517)
        = main_replica_NotarizationKind
      /\ main_replica_cert_view(main_replica_c_517) = main_replica_view_519

(*
  @type: ((Str, { parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
*)
main_replica_create_finalization(main_replica_id_2103, main_replica_proposal_2103,
main_replica_votes_2103) ==
  LET (*
    @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_2075 \in main_replica_votes_2103:
        main_replica_v_2075["proposal"] = main_replica_proposal_2103
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_2083["sig"]:
        main_replica_v_2083 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([proposal |-> main_replica_proposal_2103,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2103)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_finalization(main_replica_id_569, main_replica_view_569) ==
  \E main_replica_c_567 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_567)
        = main_replica_sig_of(main_replica_id_569)
      /\ main_replica_cert_kind(main_replica_c_567)
        = main_replica_FinalizationKind
      /\ main_replica_cert_view(main_replica_c_567) = main_replica_view_569

(*
  @type: ((Str, Int, Set({ sig: Str, view: Int })) => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_create_nullification(main_replica_id_2005, main_replica_view_2005, main_replica_votes_2005) ==
  LET (*
    @type: (() => Set({ sig: Str, view: Int }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_1977 \in main_replica_votes_2005:
        main_replica_v_1977["view"] = main_replica_view_2005
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_1985["sig"]:
        main_replica_v_1985 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([view |-> main_replica_view_2005,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2005)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_nullification(main_replica_id_544, main_replica_view_544) ==
  \E main_replica_c_542 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_542)
        = main_replica_sig_of(main_replica_id_544)
      /\ main_replica_cert_kind(main_replica_c_542)
        = main_replica_NullificationKind
      /\ main_replica_cert_view(main_replica_c_542) = main_replica_view_544

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_same_certificate_kind_and_view(main_replica_existing_1149, main_replica_cert_1149) ==
  main_replica_cert_kind(main_replica_existing_1149)
      = main_replica_cert_kind(main_replica_cert_1149)
    /\ main_replica_cert_view(main_replica_existing_1149)
      = main_replica_cert_view(main_replica_cert_1149)

(*
  @type: (() => Bool);
*)
main_replica_init ==
  LET (*
    @type: (() => (Int -> Str));
  *)
  main_replica_l ==
    [
      main_replica_v_2129 \in main_replica_VIEWS |->
        IF main_replica_v_2129 % 4 = 0
        THEN "n0"
        ELSE IF main_replica_v_2129 % 4 = 1
        THEN "n1"
        ELSE IF main_replica_v_2129 % 4 = 2 THEN "n2" ELSE "n3"
    ]
  IN
  main_replica_initWithLeader((main_replica_l))

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some(Str));
*)
main_replica_finalized_payload_at(main_replica_view_1280, main_replica_certificates_1280) ==
  CASE VariantTag((main_replica_finalized_proposal_at(main_replica_view_1280, main_replica_certificates_1280)))
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA16(main_replica_p_1275) ==
        main_replica_Some(main_replica_p_1275["payload"])
      IN
      __QUINT_LAMBDA16(VariantGetUnsafe("Some", (main_replica_finalized_proposal_at(main_replica_view_1280,
      main_replica_certificates_1280))))
    [] VariantTag((main_replica_finalized_proposal_at(main_replica_view_1280, main_replica_certificates_1280)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA17(main_replica___1278) == main_replica_None
      IN
      __QUINT_LAMBDA17(VariantGetUnsafe("None", (main_replica_finalized_proposal_at(main_replica_view_1280,
      main_replica_certificates_1280))))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Str, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_forced_timeout_expired(main_replica_self_1883, main_replica_id_1883,
main_replica_view_1883, main_replica_reason_1883, main_replica_sent_nullify_1883,
main_replica_sent_finalize_1883, main_replica_stored_nullify_1883) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1883,
      sig |-> main_replica_sig_of(main_replica_id_1883)]
  IN
  IF main_replica_self_1883["view"] /= main_replica_view_1883
  THEN [next_self |-> main_replica_self_1883,
    next_sent_nullify |-> main_replica_sent_nullify_1883,
    next_stored_nullify |-> main_replica_stored_nullify_1883]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1883, main_replica_id_1883,
  main_replica_view_1883)
  THEN [next_self |->
      main_replica_remember_timeout_reason([
        [
          main_replica_self_1883 EXCEPT
            !["leader_timeout"] =
              [
                main_replica_self_1883["leader_timeout"] EXCEPT
                  ![main_replica_view_1883] = main_replica_None
              ]
        ] EXCEPT
          !["certification_timeout"] =
            [
              main_replica_self_1883["certification_timeout"] EXCEPT
                ![main_replica_view_1883] = main_replica_None
            ]
      ], main_replica_view_1883, main_replica_reason_1883),
    next_sent_nullify |-> main_replica_sent_nullify_1883,
    next_stored_nullify |-> main_replica_stored_nullify_1883]
  ELSE [next_self |->
      [
        [
          (main_replica_remember_timeout_reason(main_replica_self_1883, main_replica_view_1883,
          main_replica_reason_1883)) EXCEPT
            !["leader_timeout"] =
              [
                main_replica_self_1883["leader_timeout"] EXCEPT
                  ![main_replica_view_1883] = main_replica_None
              ]
        ] EXCEPT
          !["certification_timeout"] =
            [
              main_replica_self_1883["certification_timeout"] EXCEPT
                ![main_replica_view_1883] = main_replica_None
            ]
      ],
    next_sent_nullify |->
      main_replica_sent_nullify_1883 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1883 \union {(main_replica_local_nullify)}]

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_nullify(main_replica_id_455, main_replica_view_455) ==
  main_replica_has_sent_vote(main_replica_id_455, main_replica_view_455, (main_replica_NullifyKind))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Str, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_timer_expired(main_replica_self_1778, main_replica_id_1778, main_replica_view_1778,
main_replica_expired_1778, main_replica_sent_nullify_1778, main_replica_sent_finalize_1778,
main_replica_stored_nullify_1778) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1778,
      sig |-> main_replica_sig_of(main_replica_id_1778)]
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_leader_expired ==
    main_replica_expired_1778 = main_replica_LeaderTimeoutKind
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_advance_expired ==
    main_replica_expired_1778 = main_replica_CertificationTimeoutKind
  IN
  IF main_replica_self_1778["view"] /= main_replica_view_1778
  THEN [next_self |-> main_replica_self_1778,
    next_sent_nullify |-> main_replica_sent_nullify_1778,
    next_stored_nullify |-> main_replica_stored_nullify_1778]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1778, main_replica_id_1778,
  main_replica_view_1778)
  THEN [next_self |->
      [
        [
          main_replica_self_1778 EXCEPT
            !["leader_timeout"] =
              IF main_replica_leader_expired
              THEN [
                main_replica_self_1778["leader_timeout"] EXCEPT
                  ![main_replica_view_1778] = main_replica_Some(TRUE)
              ]
              ELSE main_replica_self_1778["leader_timeout"]
        ] EXCEPT
          !["certification_timeout"] =
            IF main_replica_advance_expired
            THEN [
              main_replica_self_1778["certification_timeout"] EXCEPT
                ![main_replica_view_1778] = main_replica_Some(TRUE)
            ]
            ELSE main_replica_self_1778["certification_timeout"]
      ],
    next_sent_nullify |-> main_replica_sent_nullify_1778,
    next_stored_nullify |-> main_replica_stored_nullify_1778]
  ELSE LET (*
    @type: (() => Str);
  *)
  main_replica_timeout_reason ==
    IF main_replica_leader_expired
    THEN main_replica_LeaderTimeoutReason
    ELSE main_replica_CertificationTimeoutReason
  IN
  [next_self |->
      [
        [
          (main_replica_remember_timeout_reason(main_replica_self_1778, main_replica_view_1778,
          (main_replica_timeout_reason))) EXCEPT
            !["leader_timeout"] =
              IF main_replica_leader_expired
              THEN [
                main_replica_self_1778["leader_timeout"] EXCEPT
                  ![main_replica_view_1778] = main_replica_Some(TRUE)
              ]
              ELSE main_replica_self_1778["leader_timeout"]
        ] EXCEPT
          !["certification_timeout"] =
            IF main_replica_advance_expired
            THEN [
              main_replica_self_1778["certification_timeout"] EXCEPT
                ![main_replica_view_1778] = main_replica_Some(TRUE)
            ]
            ELSE main_replica_self_1778["certification_timeout"]
      ],
    next_sent_nullify |->
      main_replica_sent_nullify_1778 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1778 \union {(main_replica_local_nullify)}]

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_notarize(main_replica_id_444, main_replica_view_444) ==
  main_replica_has_sent_vote(main_replica_id_444, main_replica_view_444, (main_replica_NotarizeKind))

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_finalize(main_replica_id_466, main_replica_view_466) ==
  main_replica_has_sent_vote(main_replica_id_466, main_replica_view_466, (main_replica_FinalizeKind))

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_next_committable_proposal(main_replica_parent_view_1350, main_replica_certificates_1350) ==
  LET (*
    @type: (() => Set({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_proposals ==
    LET (*
      @type: ((Set({ parent: Int, payload: Str, view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set({ parent: Int, payload: Str, view: Int }));
    *)
    __QUINT_LAMBDA57(main_replica_acc_1332, main_replica_c_1332) ==
      IF main_replica_is_finalization_cert(main_replica_c_1332)
      THEN CASE VariantTag((main_replica_cert_proposal(main_replica_c_1332)))
          = "Some"
          -> LET (*
            @type: (({ parent: Int, payload: Str, view: Int }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA55(main_replica_p_1325) ==
            IF (main_replica_p_1325["parent"] = main_replica_parent_view_1350
                /\ main_replica_p_1325["view"] > main_replica_parent_view_1350)
              /\ main_replica_are_views_nullified(main_replica_parent_view_1350,
              main_replica_p_1325["view"], main_replica_certificates_1350)
            THEN main_replica_acc_1332 \union {main_replica_p_1325}
            ELSE main_replica_acc_1332
          IN
          __QUINT_LAMBDA55(VariantGetUnsafe("Some", (main_replica_cert_proposal(main_replica_c_1332))))
        [] VariantTag((main_replica_cert_proposal(main_replica_c_1332)))
          = "None"
          -> LET (*
            @type: (({ tag: Str }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA56(main_replica___1328) == main_replica_acc_1332
          IN
          __QUINT_LAMBDA56(VariantGetUnsafe("None", (main_replica_cert_proposal(main_replica_c_1332))))
      ELSE main_replica_acc_1332
    IN
    ApaFoldSet(__QUINT_LAMBDA57, {}, main_replica_certificates_1350)
  IN
  IF Cardinality((main_replica_proposals)) = 1
  THEN LET (*
    @type: ((None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA58(main_replica__acc_1345, main_replica_p_1345) ==
    main_replica_Some(main_replica_p_1345)
  IN
  ApaFoldSet(__QUINT_LAMBDA58, (main_replica_None), (main_replica_proposals))
  ELSE main_replica_None

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_leader_nullify_expired(main_replica_self_1958, main_replica_id_1958,
main_replica_view_1958, main_replica_sent_nullify_1958, main_replica_sent_finalize_1958,
main_replica_stored_nullify_1958) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1958,
      sig |-> main_replica_sig_of(main_replica_id_1958)]
  IN
  IF main_replica_self_1958["view"] /= main_replica_view_1958
  THEN [next_self |-> main_replica_self_1958,
    next_sent_nullify |-> main_replica_sent_nullify_1958,
    next_stored_nullify |-> main_replica_stored_nullify_1958]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1958, main_replica_id_1958,
  main_replica_view_1958)
  THEN [next_self |->
      main_replica_remember_timeout_reason((main_replica_fire_all_timers(main_replica_self_1958,
      main_replica_view_1958)), main_replica_view_1958, (main_replica_LeaderNullifyReason)),
    next_sent_nullify |-> main_replica_sent_nullify_1958,
    next_stored_nullify |-> main_replica_stored_nullify_1958]
  ELSE [next_self |->
      main_replica_remember_timeout_reason((main_replica_fire_all_timers(main_replica_self_1958,
      main_replica_view_1958)), main_replica_view_1958, (main_replica_LeaderNullifyReason)),
    next_sent_nullify |->
      main_replica_sent_nullify_1958 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1958 \union {(main_replica_local_nullify)}]

(*
  @type: (() => Bool);
*)
q_init == main_replica_init

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some(Str));
*)
main_replica_parent_payload(main_replica_self_1489, main_replica_view_1489, main_replica_parent_view_1489,
main_replica_certificates_1489) ==
  IF main_replica_view_1489 <= main_replica_parent_view_1489
  THEN main_replica_None
  ELSE IF main_replica_parent_view_1489
    < main_replica_self_1489["last_finalized"]
  THEN main_replica_None
  ELSE IF ~(main_replica_are_views_nullified(main_replica_parent_view_1489, main_replica_view_1489,
  main_replica_certificates_1489))
  THEN main_replica_None
  ELSE IF main_replica_parent_view_1489 = main_replica_GENESIS_VIEW
  THEN main_replica_Some((main_replica_GENESIS_PAYLOAD))
  ELSE CASE VariantTag((main_replica_finalized_payload_at(main_replica_parent_view_1489,
    main_replica_certificates_1489)))
      = "Some"
      -> LET (*
        @type: ((Str) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA18(main_replica_p_1480) ==
        main_replica_Some(main_replica_p_1480)
      IN
      __QUINT_LAMBDA18(VariantGetUnsafe("Some", (main_replica_finalized_payload_at(main_replica_parent_view_1489,
      main_replica_certificates_1489))))
    [] VariantTag((main_replica_finalized_payload_at(main_replica_parent_view_1489,
    main_replica_certificates_1489)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA21(main_replica___1483) ==
        IF main_replica_self_1489["certified"][main_replica_parent_view_1489]
          = main_replica_Some(TRUE)
        THEN CASE VariantTag(main_replica_self_1489["proposal"][
            main_replica_parent_view_1489
          ])
            = "Some"
            -> LET (*
              @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some(Str));
            *)
            __QUINT_LAMBDA19(main_replica_proposal_1471) ==
              main_replica_Some(main_replica_proposal_1471["payload"])
            IN
            __QUINT_LAMBDA19(VariantGetUnsafe("Some", main_replica_self_1489[
              "proposal"
            ][
              main_replica_parent_view_1489
            ]))
          [] VariantTag(main_replica_self_1489["proposal"][
            main_replica_parent_view_1489
          ])
            = "None"
            -> LET (*
              @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
            *)
            __QUINT_LAMBDA20(main_replica___1474) == main_replica_None
            IN
            __QUINT_LAMBDA20(VariantGetUnsafe("None", main_replica_self_1489[
              "proposal"
            ][
              main_replica_parent_view_1489
            ]))
        ELSE main_replica_None
      IN
      __QUINT_LAMBDA21(VariantGetUnsafe("None", (main_replica_finalized_payload_at(main_replica_parent_view_1489,
      main_replica_certificates_1489))))

(*
  @type: ((Str, Str) => Bool);
*)
main_replica_on_timeout(main_replica_id_4755, main_replica_expired_4755) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4755]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_leader_mode ==
      main_replica_expired_4755 = main_replica_LeaderTimeoutKind
        /\ main_replica_timeout_pending((main_replica_self)["leader_timeout"], (main_replica_self)[
          "view"
        ])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_advance_mode ==
      main_replica_expired_4755 = main_replica_CertificationTimeoutKind
        /\ main_replica_timeout_fired((main_replica_self)["leader_timeout"], (main_replica_self)[
          "view"
        ])
        /\ main_replica_timeout_pending((main_replica_self)[
          "certification_timeout"
        ], (main_replica_self)["view"])
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_timer_expired((main_replica_self), main_replica_id_4755, (main_replica_self)[
        "view"
      ], main_replica_expired_4755, main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
      main_replica_store_nullify_votes[main_replica_id_4755])
    IN
    ~(main_replica_broadcast_nullify(main_replica_id_4755, (main_replica_self)[
        "view"
      ]))
      /\ (main_replica_leader_mode \/ main_replica_advance_mode)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes'
        := (main_replica_timer)["next_sent_nullify"]
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
      /\ main_replica_store_nullify_votes'
        := [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_4755] =
              (main_replica_timer)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4755] = (main_replica_timer)["next_self"]
        ]
      /\ main_replica_sent_certificates' := main_replica_sent_certificates
      /\ main_replica_store_certificates' := main_replica_store_certificates
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "timeout")

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, { parent: Int, payload: Str, view: Int }, Bool) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_construct_notarize(main_replica_id_697, main_replica_self_697, main_replica_view_697,
main_replica_proposal_697, main_replica_is_verified_697) ==
  IF main_replica_broadcast_notarize(main_replica_id_697, main_replica_view_697)
    \/ main_replica_broadcast_nullify(main_replica_id_697, main_replica_view_697)
  THEN main_replica_None
  ELSE IF ~main_replica_is_verified_697
  THEN main_replica_None
  ELSE main_replica_Some(main_replica_proposal_697)

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, { parent: Int, payload: Str, view: Int }, Bool, Bool) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_construct_finalize(main_replica_id_745, main_replica_self_745, main_replica_view_745,
main_replica_proposal_745, main_replica_proposal_conflicted_745, main_replica_is_certified_745) ==
  IF main_replica_broadcast_finalize(main_replica_id_745, main_replica_view_745)
    \/ main_replica_broadcast_nullify(main_replica_id_745, main_replica_view_745)
  THEN main_replica_None
  ELSE IF main_replica_proposal_conflicted_745
  THEN main_replica_None
  ELSE IF ~main_replica_is_certified_745
  THEN main_replica_None
  ELSE main_replica_Some(main_replica_proposal_745)

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => Bool);
*)
main_replica_construct_nullify(main_replica_id_710, main_replica_self_710, main_replica_view_710) ==
  ~(main_replica_broadcast_finalize(main_replica_id_710, main_replica_view_710))

(*
  @type: ((Seq({ parent: Int, payload: Str, view: Int }), Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Seq({ parent: Int, payload: Str, view: Int }));
*)
main_replica_extend_committed_chain_once(main_replica_chain_1395, main_replica_certificates_1395) ==
  LET (*
    @type: (() => Int);
  *)
  main_replica_parent_view ==
    IF Len(main_replica_chain_1395) = 0
    THEN main_replica_GENESIS_VIEW
    ELSE main_replica_chain_1395[(Len(main_replica_chain_1395) - 1 + 1)]["view"]
  IN
  CASE VariantTag((main_replica_next_committable_proposal((main_replica_parent_view),
    main_replica_certificates_1395)))
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => Seq({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA59(main_replica_p_1389) ==
        IF main_replica_list_contains_proposal(main_replica_chain_1395, main_replica_p_1389)
        THEN main_replica_chain_1395
        ELSE Append(main_replica_chain_1395, main_replica_p_1389)
      IN
      __QUINT_LAMBDA59(VariantGetUnsafe("Some", (main_replica_next_committable_proposal((main_replica_parent_view),
      main_replica_certificates_1395))))
    [] VariantTag((main_replica_next_committable_proposal((main_replica_parent_view),
    main_replica_certificates_1395)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => Seq({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA60(main_replica___1392) == main_replica_chain_1395
      IN
      __QUINT_LAMBDA60(VariantGetUnsafe("None", (main_replica_next_committable_proposal((main_replica_parent_view),
      main_replica_certificates_1395))))

(*
  @type: ((Str, Str, Int) => Bool);
*)
main_replica_propose(main_replica_id_2676, main_replica_new_payload_2676, main_replica_parent_view_2676) ==
  (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_notarize ==
      main_replica_store_notarize_votes[main_replica_id_2676]
    IN
    LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_2676]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_2676]
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_2676]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_proposal_ok ==
      main_replica_new_payload_2676 \in main_replica_VALID_PAYLOADS
        /\ main_replica_is_some((main_replica_parent_payload((main_replica_self),
        (main_replica_self)["view"], main_replica_parent_view_2676, (main_replica_certs))))
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal ==
      [view |-> (main_replica_self)["view"],
        parent |-> main_replica_parent_view_2676,
        payload |-> main_replica_new_payload_2676]
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_forced_timeout_expired((main_replica_self), main_replica_id_2676,
      (main_replica_self)["view"], (main_replica_InvalidProposalReason), main_replica_sent_nullify_votes,
      main_replica_sent_finalize_votes, (main_replica_store_nullify))
    IN
    main_replica_id_2676 = main_replica_leader[(main_replica_self)["view"]]
      /\ main_replica_is_none((main_replica_self)["proposal"][
        (main_replica_self)["view"]
      ])
      /\ ~(main_replica_broadcast_nullify(main_replica_id_2676, (main_replica_self)[
        "view"
      ]))
      /\ main_replica_proposal_ok
      /\ main_replica_sent_notarize_votes'
        := (main_replica_sent_notarize_votes
          \union {[proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_2676)]})
      /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_store_notarize_votes'
        := [
          main_replica_store_notarize_votes EXCEPT
            ![main_replica_id_2676] =
              main_replica_store_notarize
                \union {[proposal |-> main_replica_proposal,
                  sig |-> main_replica_sig_of(main_replica_id_2676)]}
        ]
      /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
      /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_2676] =
              [
                (main_replica_observe_leader_proposal((main_replica_record_local_proposal((main_replica_self),
                (main_replica_proposal))), (main_replica_proposal))) EXCEPT
                  !["leader_timeout"] =
                    [
                      (main_replica_self)["leader_timeout"] EXCEPT
                        ![(main_replica_self)["view"]] = main_replica_None
                    ]
              ]
        ]
      /\ main_replica_sent_certificates' := main_replica_sent_certificates
      /\ main_replica_store_certificates' := main_replica_store_certificates
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "propose")

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Bool, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_notarize_effect(main_replica_self_4264, main_replica_id_4264, main_replica_notarization_4264,
main_replica_can_cert_4264, main_replica_sent_nullify_votes_4264, main_replica_sent_finalize_votes_4264,
main_replica_stored_nullify_4264, main_replica_stored_finalize_4264) ==
  LET (*
    @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
  *)
  main_replica_cert == main_replica_Notarization(main_replica_notarization_4264)
  IN
  LET (*
    @type: (() => Int);
  *)
  main_replica_cert_view_num ==
    main_replica_notarization_4264["proposal"]["view"]
  IN
  LET (*
    @type: (() => Int);
  *)
  main_replica_seen_notarization ==
    IF main_replica_self_4264["ghost_last_seen_notarization"]
      < main_replica_cert_view_num
    THEN main_replica_cert_view_num
    ELSE main_replica_self_4264["ghost_last_seen_notarization"]
  IN
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_prop == main_replica_notarization_4264["proposal"]
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_proposal_conflicted ==
    main_replica_has_leader_proposal_conflict(main_replica_self_4264, (main_replica_cert_prop))
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_should_broadcast ==
    ~(main_replica_broadcast_notarization(main_replica_id_4264, (main_replica_cert_view_num)))
  IN
  LET (*
    @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
  *)
  main_replica_timer ==
    main_replica_forced_timeout_expired(main_replica_self_4264, main_replica_id_4264,
    (main_replica_cert_view_num), (main_replica_FailedCertificationReason), main_replica_sent_nullify_votes_4264,
    main_replica_sent_finalize_votes_4264, main_replica_stored_nullify_4264)
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_is_certified ==
    main_replica_can_cert_4264
      /\ main_replica_self_4264["certified"][(main_replica_cert_view_num)]
        = main_replica_None
  IN
  LET (*
    @type: (() => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_finalize_result ==
    main_replica_construct_finalize(main_replica_id_4264, main_replica_self_4264,
    (main_replica_cert_view_num), (main_replica_cert_prop), (main_replica_proposal_conflicted),
    (main_replica_is_certified))
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_can_send_nullify ==
    ~main_replica_can_cert_4264
      /\ main_replica_self_4264["view"] = main_replica_cert_view_num
      /\ main_replica_construct_nullify(main_replica_id_4264, main_replica_self_4264,
      (main_replica_cert_view_num))
      /\ ~(main_replica_broadcast_nullify(main_replica_id_4264, (main_replica_cert_view_num)))
  IN
  LET (*
    @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
  *)
  main_replica_observed ==
    main_replica_observe_leader_proposal((main_replica_observe_round_proposal(main_replica_self_4264,
    (main_replica_cert_prop), TRUE)), (main_replica_cert_prop))
  IN
  IF main_replica_is_some((main_replica_finalize_result))
  THEN [next_self |->
      main_replica_enter_view([
        [
          [
            [
              (main_replica_observed) EXCEPT
                !["leader_timeout"] =
                  [
                    main_replica_self_4264["leader_timeout"] EXCEPT
                      ![main_replica_cert_view_num] = main_replica_None
                  ]
            ] EXCEPT
              !["certification_timeout"] =
                [
                  main_replica_self_4264["certification_timeout"] EXCEPT
                    ![main_replica_cert_view_num] = main_replica_None
                ]
          ] EXCEPT
            !["ghost_last_seen_notarization"] = main_replica_seen_notarization
        ] EXCEPT
          !["certified"] =
            LET (*
              @type: (() => (Int -> None({ tag: Str }) | Some(Bool)));
            *)
            __quint_var6 == main_replica_self_4264["certified"]
            IN
            LET (*
              @type: (() => Set(Int));
            *)
            __quint_var7 == DOMAIN __quint_var6
            IN
            [
              __quint_var8 \in
                {(main_replica_cert_view_num)} \union __quint_var7 |->
                IF __quint_var8 = main_replica_cert_view_num
                THEN main_replica_Some(TRUE)
                ELSE (__quint_var6)[__quint_var8]
            ]
      ], (main_replica_cert_view_num + 1)),
    next_sent_nullify |-> main_replica_sent_nullify_votes_4264,
    next_sent_finalize |->
      main_replica_sent_finalize_votes_4264
        \union {[proposal |-> main_replica_cert_prop,
          sig |-> main_replica_sig_of(main_replica_id_4264)]},
    next_stored_nullify |-> main_replica_stored_nullify_4264,
    next_stored_finalize |->
      main_replica_stored_finalize_4264
        \union {[proposal |-> main_replica_cert_prop,
          sig |-> main_replica_sig_of(main_replica_id_4264)]}]
  ELSE IF main_replica_is_certified
  THEN [next_self |->
      main_replica_enter_view([
        [
          [
            [
              (main_replica_observed) EXCEPT
                !["leader_timeout"] =
                  [
                    main_replica_self_4264["leader_timeout"] EXCEPT
                      ![main_replica_cert_view_num] = main_replica_None
                  ]
            ] EXCEPT
              !["certification_timeout"] =
                [
                  main_replica_self_4264["certification_timeout"] EXCEPT
                    ![main_replica_cert_view_num] = main_replica_None
                ]
          ] EXCEPT
            !["ghost_last_seen_notarization"] = main_replica_seen_notarization
        ] EXCEPT
          !["certified"] =
            LET (*
              @type: (() => (Int -> None({ tag: Str }) | Some(Bool)));
            *)
            __quint_var9 == main_replica_self_4264["certified"]
            IN
            LET (*
              @type: (() => Set(Int));
            *)
            __quint_var10 == DOMAIN __quint_var9
            IN
            [
              __quint_var11 \in
                {(main_replica_cert_view_num)} \union __quint_var10 |->
                IF __quint_var11 = main_replica_cert_view_num
                THEN main_replica_Some(TRUE)
                ELSE (__quint_var9)[__quint_var11]
            ]
      ], (main_replica_cert_view_num + 1)),
    next_sent_nullify |-> main_replica_sent_nullify_votes_4264,
    next_sent_finalize |-> main_replica_sent_finalize_votes_4264,
    next_stored_nullify |-> main_replica_stored_nullify_4264,
    next_stored_finalize |-> main_replica_stored_finalize_4264]
  ELSE IF main_replica_can_send_nullify
  THEN [next_self |->
      [
        [
          (main_replica_observe_leader_proposal((main_replica_observe_round_proposal((main_replica_timer)[
            "next_self"
          ], (main_replica_cert_prop), TRUE)), (main_replica_cert_prop))) EXCEPT
            !["certified"] =
              [
                (main_replica_timer)["next_self"]["certified"] EXCEPT
                  ![main_replica_cert_view_num] = main_replica_Some(FALSE)
              ]
        ] EXCEPT
          !["ghost_last_seen_notarization"] = main_replica_seen_notarization
      ],
    next_sent_nullify |-> (main_replica_timer)["next_sent_nullify"],
    next_sent_finalize |-> main_replica_sent_finalize_votes_4264,
    next_stored_nullify |-> (main_replica_timer)["next_stored_nullify"],
    next_stored_finalize |-> main_replica_stored_finalize_4264]
  ELSE [next_self |->
      [
        (main_replica_observed) EXCEPT
          !["ghost_last_seen_notarization"] = main_replica_seen_notarization
      ],
    next_sent_nullify |-> main_replica_sent_nullify_votes_4264,
    next_sent_finalize |-> main_replica_sent_finalize_votes_4264,
    next_stored_nullify |-> main_replica_stored_nullify_4264,
    next_stored_finalize |-> main_replica_stored_finalize_4264]

(*
  @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Seq({ parent: Int, payload: Str, view: Int }));
*)
main_replica_rebuild_committed_chain(main_replica_certificates_1411) ==
  LET (*
    @type: ((Seq({ parent: Int, payload: Str, view: Int }), Int) => Seq({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA61(main_replica_chain_1409, main_replica__view_1409) ==
    main_replica_extend_committed_chain_once(main_replica_chain_1409, main_replica_certificates_1411)
  IN
  ApaFoldSet(__QUINT_LAMBDA61, <<>>, (main_replica_VIEWS))

(*
  @type: ((Str, { proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_on_notarize(main_replica_id_3294, main_replica_vote_3294) ==
  main_replica_vote_3294 \in main_replica_sent_notarize_votes
    /\ (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_notarize ==
      main_replica_store_notarize_votes[main_replica_id_3294]
    IN
    LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_3294]
    IN
    LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_finalize ==
      main_replica_store_finalize_votes[main_replica_id_3294]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3294]
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_3294]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal == main_replica_vote_3294["proposal"]
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_view_3286 == (main_replica_proposal)["view"]
    IN
    LET (*
      @type: (() => Str);
    *)
    main_replica_payload == (main_replica_proposal)["payload"]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_parent_ok ==
      main_replica_is_some((main_replica_parent_payload((main_replica_self), (main_replica_proposal)[
        "view"
      ], (main_replica_proposal)["parent"], (main_replica_certs))))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_payload_ok ==
      main_replica_payload \in main_replica_VALID_PAYLOADS
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_is_leader_vote ==
      main_replica_vote_3294["sig"]
        = main_replica_sig_of(main_replica_leader[(main_replica_view_3286)])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_proposal_conflicted ==
      main_replica_has_leader_proposal_conflict((main_replica_self), (main_replica_proposal))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_can_process_as_proposal ==
      main_replica_is_leader_vote
        /\ main_replica_view_3286 = (main_replica_self)["view"]
        /\ ~(main_replica_broadcast_notarize(main_replica_id_3294, (main_replica_self)[
          "view"
        ]))
        /\ ~(main_replica_broadcast_nullify(main_replica_id_3294, (main_replica_view_3286)))
    IN
    IF main_replica_proposal_conflicted
    THEN main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_sent_certificates' := main_replica_sent_certificates
      /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
      /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
      /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
      /\ main_replica_store_certificates' := main_replica_store_certificates
      /\ main_replica_replica_state' := main_replica_replica_state
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_notarize"
    ELSE IF main_replica_can_process_as_proposal
    THEN LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_forced_timeout_expired((main_replica_self), main_replica_id_3294,
      (main_replica_view_3286), (main_replica_InvalidProposalReason), main_replica_sent_nullify_votes,
      main_replica_sent_finalize_votes, (main_replica_store_nullify))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_notarize_ok ==
      main_replica_is_some((main_replica_construct_notarize(main_replica_id_3294,
      (main_replica_self), (main_replica_view_3286), (main_replica_proposal), (main_replica_payload_ok
        /\ main_replica_parent_ok))))
    IN
    LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_new_store_notarize_p ==
      IF main_replica_notarize_ok
      THEN main_replica_store_notarize
        \union { main_replica_vote_3294,
          [proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_3294)] }
      ELSE main_replica_store_notarize
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_proposal_self ==
      IF main_replica_notarize_ok
      THEN [
        (main_replica_observe_leader_proposal((main_replica_observe_round_proposal((main_replica_self),
        (main_replica_proposal), FALSE)), (main_replica_proposal))) EXCEPT
          !["leader_timeout"] =
            [
              (main_replica_self)["leader_timeout"] EXCEPT
                ![(main_replica_self)["view"]] = main_replica_None
            ]
      ]
      ELSE main_replica_observe_leader_proposal((main_replica_observe_round_proposal((main_replica_timer)[
        "next_self"
      ], (main_replica_proposal), FALSE)), (main_replica_proposal))
    IN
    LET (*
      @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
    *)
    main_replica_cert_existing ==
      IF main_replica_notarize_ok
      THEN main_replica_create_notarization(main_replica_id_3294, (main_replica_proposal),
      (main_replica_store_notarize))
      ELSE main_replica_None
    IN
    LET (*
      @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
    *)
    main_replica_cert_leader ==
      IF main_replica_is_some((main_replica_cert_existing))
      THEN main_replica_cert_existing
      ELSE IF main_replica_notarize_ok
      THEN main_replica_create_notarization(main_replica_id_3294, (main_replica_proposal),
      (main_replica_store_notarize \union {main_replica_vote_3294}))
      ELSE main_replica_None
    IN
    LET (*
      @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
    *)
    main_replica_maybe_not_cert_p ==
      IF main_replica_is_some((main_replica_cert_leader))
      THEN main_replica_cert_leader
      ELSE IF main_replica_notarize_ok
      THEN main_replica_create_notarization(main_replica_id_3294, (main_replica_proposal),
      (main_replica_new_store_notarize_p))
      ELSE main_replica_None
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_can_cert_p ==
      main_replica_can_certify(main_replica_id_3294, (main_replica_proposal)[
        "payload"
      ])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_not_p ==
      ~(main_replica_broadcast_notarization(main_replica_id_3294, (main_replica_view_3286)))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect_p ==
      CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA38(main_replica_cert_2943) ==
            main_replica_notarize_effect((main_replica_proposal_self), main_replica_id_3294,
            main_replica_cert_2943, (main_replica_can_cert_p), main_replica_sent_nullify_votes,
            main_replica_sent_finalize_votes, main_replica_store_nullify_votes[
              main_replica_id_3294
            ], main_replica_store_finalize_votes[main_replica_id_3294])
          IN
          __QUINT_LAMBDA38(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
        [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA39(main_replica___2946) ==
            [next_self |-> main_replica_proposal_self,
              next_sent_nullify |-> main_replica_sent_nullify_votes,
              next_sent_finalize |-> main_replica_sent_finalize_votes,
              next_stored_nullify |->
                main_replica_store_nullify_votes[main_replica_id_3294],
              next_stored_finalize |->
                main_replica_store_finalize_votes[main_replica_id_3294]]
          IN
          __QUINT_LAMBDA39(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p)))
    IN
    main_replica_sent_notarize_votes'
        := (IF main_replica_notarize_ok
        THEN main_replica_sent_notarize_votes
          \union {[proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_3294)]}
        ELSE main_replica_sent_notarize_votes)
      /\ main_replica_sent_nullify_votes'
        := (IF main_replica_notarize_ok
        THEN (main_replica_effect_p)["next_sent_nullify"]
        ELSE (main_replica_timer)["next_sent_nullify"])
      /\ main_replica_sent_finalize_votes'
        := (main_replica_effect_p)["next_sent_finalize"]
      /\ main_replica_store_notarize_votes'
        := [
          main_replica_store_notarize_votes EXCEPT
            ![main_replica_id_3294] = main_replica_new_store_notarize_p
        ]
      /\ main_replica_store_nullify_votes'
        := (IF main_replica_notarize_ok
        THEN [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3294] =
              (main_replica_effect_p)["next_stored_nullify"]
        ]
        ELSE [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3294] =
              (main_replica_timer)["next_stored_nullify"]
        ])
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_3294] =
              (main_replica_effect_p)["next_stored_finalize"]
        ]
      /\ main_replica_store_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA41(main_replica_cert_3022) ==
              LET (*
                @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
              *)
              __quint_var12 == main_replica_store_certificates
              IN
              [
                (__quint_var12) EXCEPT
                  ![main_replica_id_3294] =
                    LET (*
                      @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
                    *)
                    __QUINT_LAMBDA40(main_replica_old_3017) ==
                      main_replica_old_3017
                        \union {(main_replica_Notarization(main_replica_cert_3022))}
                    IN
                    __QUINT_LAMBDA40((__quint_var12)[main_replica_id_3294])
              ]
            IN
            __QUINT_LAMBDA41(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
          [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA42(main_replica___3025) ==
              main_replica_store_certificates
            IN
            __QUINT_LAMBDA42(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p))))
      /\ main_replica_sent_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA43(main_replica_cert_3041) ==
              IF main_replica_should_broadcast_not_p
              THEN main_replica_sent_certificates
                \union {(main_replica_Notarization(main_replica_cert_3041))}
              ELSE main_replica_sent_certificates
            IN
            __QUINT_LAMBDA43(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
          [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA44(main_replica___3044) ==
              main_replica_sent_certificates
            IN
            __QUINT_LAMBDA44(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p))))
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_3294] = (main_replica_effect_p)["next_self"]
        ]
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_notarize"
    ELSE LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_new_store_notarize ==
      main_replica_store_notarize \union {main_replica_vote_3294}
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_had_notarization ==
      \E main_replica_c_3094 \in main_replica_certs:
        main_replica_is_notarization_cert(main_replica_c_3094)
          /\ main_replica_cert_proposal(main_replica_c_3094)
            = main_replica_Some((main_replica_proposal))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_now_notarized ==
      main_replica_is_proposal_notarized_votes((main_replica_proposal), (main_replica_new_store_notarize))
    IN
    LET (*
      @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
    *)
    main_replica_cert_before_vote ==
      main_replica_create_notarization(main_replica_id_3294, (main_replica_proposal),
      (main_replica_store_notarize))
    IN
    LET (*
      @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
    *)
    main_replica_maybe_not_cert ==
      IF main_replica_is_some((main_replica_cert_before_vote))
      THEN main_replica_cert_before_vote
      ELSE main_replica_create_notarization(main_replica_id_3294, (main_replica_proposal),
      (main_replica_new_store_notarize))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_can_cert ==
      main_replica_can_certify(main_replica_id_3294, (main_replica_proposal)[
        "payload"
      ])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_is_new_cert == ~main_replica_had_notarization
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_not ==
      ~(main_replica_broadcast_notarization(main_replica_id_3294, (main_replica_view_3286)))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect ==
      CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA45(main_replica_cert_3160) ==
            main_replica_notarize_effect((main_replica_self), main_replica_id_3294,
            main_replica_cert_3160, (main_replica_can_cert), main_replica_sent_nullify_votes,
            main_replica_sent_finalize_votes, main_replica_store_nullify_votes[
              main_replica_id_3294
            ], main_replica_store_finalize_votes[main_replica_id_3294])
          IN
          __QUINT_LAMBDA45(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
        [] VariantTag((main_replica_maybe_not_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA46(main_replica___3163) ==
            [next_self |-> main_replica_self,
              next_sent_nullify |-> main_replica_sent_nullify_votes,
              next_sent_finalize |-> main_replica_sent_finalize_votes,
              next_stored_nullify |->
                main_replica_store_nullify_votes[main_replica_id_3294],
              next_stored_finalize |->
                main_replica_store_finalize_votes[main_replica_id_3294]]
          IN
          __QUINT_LAMBDA46(VariantGetUnsafe("None", (main_replica_maybe_not_cert)))
    IN
    (main_replica_is_none((main_replica_maybe_not_cert))
        \/ main_replica_now_notarized)
      /\ main_replica_store_notarize_votes'
        := [
          main_replica_store_notarize_votes EXCEPT
            ![main_replica_id_3294] = main_replica_new_store_notarize
        ]
      /\ main_replica_store_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA48(main_replica_cert_3193) ==
              IF main_replica_is_new_cert
              THEN LET (*
                @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
              *)
              __quint_var13 == main_replica_store_certificates
              IN
              [
                (__quint_var13) EXCEPT
                  ![main_replica_id_3294] =
                    LET (*
                      @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
                    *)
                    __QUINT_LAMBDA47(main_replica_old_3186) ==
                      main_replica_old_3186
                        \union {(main_replica_Notarization(main_replica_cert_3193))}
                    IN
                    __QUINT_LAMBDA47((__quint_var13)[main_replica_id_3294])
              ]
              ELSE main_replica_store_certificates
            IN
            __QUINT_LAMBDA48(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
          [] VariantTag((main_replica_maybe_not_cert)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA49(main_replica___3196) ==
              main_replica_store_certificates
            IN
            __QUINT_LAMBDA49(VariantGetUnsafe("None", (main_replica_maybe_not_cert))))
      /\ main_replica_sent_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA50(main_replica_cert_3212) ==
              IF main_replica_should_broadcast_not
              THEN main_replica_sent_certificates
                \union {(main_replica_Notarization(main_replica_cert_3212))}
              ELSE main_replica_sent_certificates
            IN
            __QUINT_LAMBDA50(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
          [] VariantTag((main_replica_maybe_not_cert)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA51(main_replica___3215) ==
              main_replica_sent_certificates
            IN
            __QUINT_LAMBDA51(VariantGetUnsafe("None", (main_replica_maybe_not_cert))))
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes'
        := (main_replica_effect)["next_sent_nullify"]
      /\ main_replica_sent_finalize_votes'
        := (main_replica_effect)["next_sent_finalize"]
      /\ main_replica_store_nullify_votes'
        := [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3294] =
              (main_replica_effect)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_3294] =
              (main_replica_effect)["next_stored_finalize"]
        ]
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_3294] = (main_replica_effect)["next_self"]
        ]
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_notarize")

(*
  @type: ((Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Bool) => Bool);
*)
main_replica__add_finalization(main_replica_id_4634, main_replica_finalization_4634,
main_replica_is_new_cert_4634) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4634]
    IN
    LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Finalization(main_replica_finalization_4634)
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_finalization ==
      ~(main_replica_broadcast_finalization(main_replica_id_4634, main_replica_finalization_4634[
        "proposal"
      ][
        "view"
      ]))
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_cert_view_num ==
      main_replica_finalization_4634["proposal"]["view"]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_cert_prop == main_replica_finalization_4634["proposal"]
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_seen_notarization ==
      IF (main_replica_self)["ghost_last_seen_notarization"]
        < main_replica_cert_view_num
      THEN main_replica_cert_view_num
      ELSE (main_replica_self)["ghost_last_seen_notarization"]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_newer ==
      main_replica_cert_view_num > (main_replica_self)["last_finalized"]
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_next_certs ==
      IF main_replica_is_new_cert_4634
      THEN main_replica_store_certificates[main_replica_id_4634]
        \union {(main_replica_cert)}
      ELSE main_replica_store_certificates[main_replica_id_4634]
    IN
    Cardinality(main_replica_finalization_4634["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4634
        THEN [
          main_replica_store_certificates EXCEPT
            ![main_replica_id_4634] = main_replica_next_certs
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_finalization
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4634))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_ghost_committed_blocks'
        := (IF main_replica_is_new_cert_4634
        THEN [
          main_replica_ghost_committed_blocks EXCEPT
            ![main_replica_id_4634] =
              main_replica_rebuild_committed_chain((main_replica_next_certs))
        ]
        ELSE main_replica_ghost_committed_blocks)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4634] =
              main_replica_enter_view([
                [
                  (main_replica_observe_leader_proposal((main_replica_observe_round_proposal((main_replica_cancel_all_timers((main_replica_self),
                  (main_replica_cert_view_num))), (main_replica_cert_prop), TRUE)),
                  (main_replica_cert_prop))) EXCEPT
                    !["last_finalized"] =
                      IF main_replica_newer
                      THEN main_replica_cert_view_num
                      ELSE (main_replica_self)["last_finalized"]
                ] EXCEPT
                  !["ghost_last_seen_notarization"] =
                    main_replica_seen_notarization
              ], (main_replica_cert_view_num + 1))
        ])

(*
  @type: ((Str, { ghost_sender: Str, signatures: Set(Str), view: Int }, Bool, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }) => Bool);
*)
main_replica__add_nullification(main_replica_id_4485, main_replica_nullification_4485,
main_replica_is_new_cert_4485, main_replica_base_self_4485) ==
  (LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Nullification(main_replica_nullification_4485)
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_cert_view_num == main_replica_nullification_4485["view"]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_nullification ==
      ~(main_replica_broadcast_nullification(main_replica_id_4485, (main_replica_cert_view_num)))
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_next_certs ==
      IF main_replica_is_new_cert_4485
      THEN main_replica_store_certificates[main_replica_id_4485]
        \union {(main_replica_cert)}
      ELSE main_replica_store_certificates[main_replica_id_4485]
    IN
    Cardinality(main_replica_nullification_4485["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4485
        THEN [
          main_replica_store_certificates EXCEPT
            ![main_replica_id_4485] = main_replica_next_certs
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_nullification
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4485))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4485] =
              main_replica_enter_view((main_replica_cancel_all_timers(main_replica_base_self_4485,
              (main_replica_cert_view_num))), (main_replica_cert_view_num + 1))
        ]
      /\ main_replica_ghost_committed_blocks'
        := (IF main_replica_is_new_cert_4485
        THEN [
          main_replica_ghost_committed_blocks EXCEPT
            ![main_replica_id_4485] =
              main_replica_rebuild_committed_chain((main_replica_next_certs))
        ]
        ELSE main_replica_ghost_committed_blocks))

(*
  @type: ((Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Bool) => Bool);
*)
main_replica__add_notarization(main_replica_id_4388, main_replica_notarization_4388,
main_replica_is_new_cert_4388) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4388]
    IN
    LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Notarization(main_replica_notarization_4388)
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_notarization ==
      ~(main_replica_broadcast_notarization(main_replica_id_4388, main_replica_notarization_4388[
        "proposal"
      ][
        "view"
      ]))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect ==
      main_replica_notarize_effect((main_replica_self), main_replica_id_4388, main_replica_notarization_4388,
      (main_replica_can_certify(main_replica_id_4388, main_replica_notarization_4388[
        "proposal"
      ][
        "payload"
      ])), main_replica_sent_nullify_votes, main_replica_sent_finalize_votes, main_replica_store_nullify_votes[
        main_replica_id_4388
      ], main_replica_store_finalize_votes[main_replica_id_4388])
    IN
    Cardinality(main_replica_notarization_4388["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4388
        THEN LET (*
          @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
        *)
        __quint_var15 == main_replica_store_certificates
        IN
        [
          (__quint_var15) EXCEPT
            ![main_replica_id_4388] =
              LET (*
                @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
              *)
              __QUINT_LAMBDA78(main_replica_old_4324) ==
                main_replica_old_4324 \union {(main_replica_cert)}
              IN
              __QUINT_LAMBDA78((__quint_var15)[main_replica_id_4388])
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_notarization
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4388))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes'
        := (main_replica_effect)["next_sent_nullify"]
      /\ main_replica_sent_finalize_votes'
        := (main_replica_effect)["next_sent_finalize"]
      /\ main_replica_store_nullify_votes'
        := [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_4388] =
              (main_replica_effect)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_4388] =
              (main_replica_effect)["next_stored_finalize"]
        ]
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4388] = (main_replica_effect)["next_self"]
        ]
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks)

(*
  @type: ((Str, { proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_on_finalize(main_replica_id_3463, main_replica_vote_3463) ==
  main_replica_vote_3463 \in main_replica_sent_finalize_votes
    /\ (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_finalize ==
      main_replica_store_finalize_votes[main_replica_id_3463]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3463]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal == main_replica_vote_3463["proposal"]
    IN
    (main_replica_proposal)["view"]
        >= (main_replica_self)["last_finalized"] - main_replica_ACTIVITY_TIMEOUT
      /\ (main_replica_proposal)["view"] <= (main_replica_self)["view"] + 1
      /\ (LET (*
        @type: (() => Bool);
      *)
      main_replica_conflict ==
        main_replica_has_leader_proposal_conflict((main_replica_self), (main_replica_proposal))
      IN
      LET (*
        @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
      *)
      main_replica_new_store_finalize ==
        main_replica_store_finalize \union {main_replica_vote_3463}
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
      *)
      main_replica_cert_before_vote ==
        IF main_replica_conflict
        THEN main_replica_None
        ELSE main_replica_create_finalization(main_replica_id_3463, (main_replica_proposal),
        (main_replica_store_finalize))
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
      *)
      main_replica_maybe_fin_cert ==
        IF main_replica_is_some((main_replica_cert_before_vote))
        THEN main_replica_cert_before_vote
        ELSE IF main_replica_conflict
        THEN main_replica_None
        ELSE main_replica_create_finalization(main_replica_id_3463, (main_replica_proposal),
        (main_replica_new_store_finalize))
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_is_new_cert ==
        ~(\E main_replica_c_3375 \in main_replica_store_certificates[
          main_replica_id_3463
        ]:
          main_replica_is_finalization_cert(main_replica_c_3375)
            /\ main_replica_cert_proposal(main_replica_c_3375)
              = main_replica_Some((main_replica_proposal)))
      IN
      CASE VariantTag((main_replica_maybe_fin_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA62(main_replica_cert_3439) ==
            main_replica_store_finalize_votes'
                := (IF main_replica_conflict
                THEN main_replica_store_finalize_votes
                ELSE [
                  main_replica_store_finalize_votes EXCEPT
                    ![main_replica_id_3463] = main_replica_new_store_finalize
                ])
              /\ main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica__add_finalization(main_replica_id_3463, main_replica_cert_3439,
              (main_replica_is_new_cert))
          IN
          __QUINT_LAMBDA62(VariantGetUnsafe("Some", (main_replica_maybe_fin_cert)))
        [] VariantTag((main_replica_maybe_fin_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => Bool);
          *)
          __QUINT_LAMBDA63(main_replica___3442) ==
            main_replica_store_finalize_votes'
                := (IF main_replica_conflict
                THEN main_replica_store_finalize_votes
                ELSE [
                  main_replica_store_finalize_votes EXCEPT
                    ![main_replica_id_3463] = main_replica_new_store_finalize
                ])
              /\ main_replica_store_certificates'
                := main_replica_store_certificates
              /\ main_replica_sent_certificates'
                := main_replica_sent_certificates
              /\ main_replica_sent_notarize_votes'
                := main_replica_sent_notarize_votes
              /\ main_replica_sent_nullify_votes'
                := main_replica_sent_nullify_votes
              /\ main_replica_sent_finalize_votes'
                := main_replica_sent_finalize_votes
              /\ main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica_replica_state' := main_replica_replica_state
              /\ main_replica_ghost_committed_blocks'
                := main_replica_ghost_committed_blocks
          IN
          __QUINT_LAMBDA63(VariantGetUnsafe("None", (main_replica_maybe_fin_cert))))
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_finalize")

(*
  @type: ((Str, { sig: Str, view: Int }) => Bool);
*)
main_replica_on_nullify(main_replica_id_3697, main_replica_vote_3697) ==
  main_replica_vote_3697 \in main_replica_sent_nullify_votes
    /\ (LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_3697]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3697]
    IN
    main_replica_vote_3697["view"]
        >= (main_replica_self)["last_finalized"] - main_replica_ACTIVITY_TIMEOUT
      /\ main_replica_vote_3697["view"] <= (main_replica_self)["view"] + 1
      /\ (LET (*
        @type: (() => Set({ sig: Str, view: Int }));
      *)
      main_replica_new_nullify_votes ==
        main_replica_store_nullify \union {main_replica_vote_3697}
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_leader_nullify_trigger ==
        main_replica_id_3697
            /= main_replica_leader[main_replica_vote_3697["view"]]
          /\ ~(main_replica_broadcast_nullify(main_replica_id_3697, main_replica_vote_3697[
            "view"
          ]))
          /\ main_replica_vote_3697["sig"]
            = main_replica_sig_of(main_replica_leader[
              main_replica_vote_3697["view"]
            ])
      IN
      LET (*
        @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
      *)
      main_replica_timer ==
        IF main_replica_leader_nullify_trigger
        THEN main_replica_leader_nullify_expired((main_replica_self), main_replica_id_3697,
        main_replica_vote_3697["view"], main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
        (main_replica_new_nullify_votes))
        ELSE [next_self |-> main_replica_self,
          next_sent_nullify |-> main_replica_sent_nullify_votes,
          next_stored_nullify |-> main_replica_new_nullify_votes]
      IN
      LET (*
        @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
      *)
      main_replica_certs ==
        main_replica_store_certificates[main_replica_id_3697]
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_had_nullification ==
        \E main_replica_c_3563 \in main_replica_certs:
          main_replica_is_nullification_cert(main_replica_c_3563)
            /\ main_replica_cert_view(main_replica_c_3563)
              = main_replica_vote_3697["view"]
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      main_replica_cert_existing ==
        main_replica_create_nullification(main_replica_id_3697, main_replica_vote_3697[
          "view"
        ], (main_replica_store_nullify))
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      main_replica_cert_before_own ==
        IF main_replica_is_some((main_replica_cert_existing))
        THEN main_replica_cert_existing
        ELSE main_replica_create_nullification(main_replica_id_3697, main_replica_vote_3697[
          "view"
        ], (main_replica_new_nullify_votes))
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      main_replica_maybe_null_cert ==
        IF main_replica_is_some((main_replica_cert_before_own))
        THEN main_replica_cert_before_own
        ELSE main_replica_create_nullification(main_replica_id_3697, main_replica_vote_3697[
          "view"
        ], (main_replica_timer)["next_stored_nullify"])
      IN
      CASE VariantTag((main_replica_maybe_null_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
          *)
          __QUINT_LAMBDA64(main_replica_cert_3671) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := [
                  main_replica_store_nullify_votes EXCEPT
                    ![main_replica_id_3697] =
                      (main_replica_timer)["next_stored_nullify"]
                ]
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_sent_nullify_votes'
                := (main_replica_timer)["next_sent_nullify"]
              /\ main_replica__add_nullification(main_replica_id_3697, main_replica_cert_3671,
              (~main_replica_had_nullification), (main_replica_timer)[
                "next_self"
              ])
          IN
          __QUINT_LAMBDA64(VariantGetUnsafe("Some", (main_replica_maybe_null_cert)))
        [] VariantTag((main_replica_maybe_null_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => Bool);
          *)
          __QUINT_LAMBDA65(main_replica___3674) ==
            main_replica_store_certificates' := main_replica_store_certificates
              /\ main_replica_sent_certificates'
                := main_replica_sent_certificates
              /\ main_replica_sent_notarize_votes'
                := main_replica_sent_notarize_votes
              /\ main_replica_sent_nullify_votes'
                := (main_replica_timer)["next_sent_nullify"]
              /\ main_replica_sent_finalize_votes'
                := main_replica_sent_finalize_votes
              /\ main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := [
                  main_replica_store_nullify_votes EXCEPT
                    ![main_replica_id_3697] =
                      (main_replica_timer)["next_stored_nullify"]
                ]
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_replica_state'
                := [
                  main_replica_replica_state EXCEPT
                    ![main_replica_id_3697] = (main_replica_timer)["next_self"]
                ]
              /\ main_replica_ghost_committed_blocks'
                := main_replica_ghost_committed_blocks
          IN
          __QUINT_LAMBDA65(VariantGetUnsafe("None", (main_replica_maybe_null_cert))))
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_nullify")

(*
  @type: ((Str, Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_on_certificate(main_replica_id_3986, main_replica_cert_3986) ==
  (LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_3986]
    IN
    Cardinality((main_replica_cert_signatures(main_replica_cert_3986)))
        >= main_replica_Q
      /\ (LET (*
        @type: (() => Bool);
      *)
      main_replica_duplicate ==
        \E main_replica_existing_3872 \in main_replica_certs:
          main_replica_same_certificate_subject(main_replica_existing_3872, main_replica_cert_3986)
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_seen_kind_and_view ==
        \E main_replica_existing_3880 \in main_replica_certs:
          main_replica_same_certificate_kind_and_view(main_replica_existing_3880,
          main_replica_cert_3986)
      IN
      IF main_replica_duplicate
      THEN main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
        /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
        /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
        /\ main_replica_sent_certificates' := main_replica_sent_certificates
        /\ main_replica_store_notarize_votes'
          := main_replica_store_notarize_votes
        /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
        /\ main_replica_store_finalize_votes'
          := main_replica_store_finalize_votes
        /\ main_replica_store_certificates' := main_replica_store_certificates
        /\ main_replica_replica_state' := main_replica_replica_state
        /\ main_replica_ghost_committed_blocks'
          := main_replica_ghost_committed_blocks
      ELSE CASE VariantTag(main_replica_cert_3986) = "Notarization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA79(main_replica_n_3963) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica__add_notarization(main_replica_id_3986, main_replica_n_3963,
              (~main_replica_seen_kind_and_view))
          IN
          __QUINT_LAMBDA79(VariantGetUnsafe("Notarization", main_replica_cert_3986))
        [] VariantTag(main_replica_cert_3986) = "Nullification"
          -> LET (*
            @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
          *)
          __QUINT_LAMBDA80(main_replica_n_3966) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_sent_nullify_votes'
                := main_replica_sent_nullify_votes
              /\ main_replica__add_nullification(main_replica_id_3986, main_replica_n_3966,
              (~main_replica_seen_kind_and_view), main_replica_replica_state[
                main_replica_id_3986
              ])
          IN
          __QUINT_LAMBDA80(VariantGetUnsafe("Nullification", main_replica_cert_3986))
        [] VariantTag(main_replica_cert_3986) = "Finalization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA81(main_replica_f_3969) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica__add_finalization(main_replica_id_3986, main_replica_f_3969,
              (~main_replica_seen_kind_and_view))
          IN
          __QUINT_LAMBDA81(VariantGetUnsafe("Finalization", main_replica_cert_3986)))
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_certificate")

(*
  @type: ((Str, Int, Int, Str, Str) => Bool);
*)
main_replica_on_notarization_cert(main_replica_id_3753, main_replica_cert_view_3753,
main_replica_cert_parent_3753, main_replica_cert_payload_3753, main_replica_cert_sender_3753) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_proposal_3752 ==
    [view |-> main_replica_cert_view_3753,
      parent |-> main_replica_cert_parent_3753,
      payload |-> main_replica_cert_payload_3753]
  IN
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3741 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3741) = "Notarization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA82(main_replica_n_3736) ==
              main_replica_n_3736["proposal"] = main_replica_cert_proposal_3752
                /\ main_replica_n_3736["ghost_sender"]
                  = main_replica_cert_sender_3753
            IN
            __QUINT_LAMBDA82(VariantGetUnsafe("Notarization", main_replica_c_3741))
          [] OTHER
            -> (LET (*
              @type: ((o) => Bool);
            *)
            __QUINT_LAMBDA83(main_replica___3739) == FALSE
            IN
            __QUINT_LAMBDA83({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_3753, main_replica_cert)

(*
  @type: ((Str, Int, Int, Str, Str) => Bool);
*)
main_replica_on_finalization_cert(main_replica_id_3809, main_replica_cert_view_3809,
main_replica_cert_parent_3809, main_replica_cert_payload_3809, main_replica_cert_sender_3809) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_proposal_3808 ==
    [view |-> main_replica_cert_view_3809,
      parent |-> main_replica_cert_parent_3809,
      payload |-> main_replica_cert_payload_3809]
  IN
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3797 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3797) = "Finalization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA84(main_replica_f_3792) ==
              main_replica_f_3792["proposal"] = main_replica_cert_proposal_3808
                /\ main_replica_f_3792["ghost_sender"]
                  = main_replica_cert_sender_3809
            IN
            __QUINT_LAMBDA84(VariantGetUnsafe("Finalization", main_replica_c_3797))
          [] OTHER
            -> (LET (*
              @type: ((p) => Bool);
            *)
            __QUINT_LAMBDA85(main_replica___3795) == FALSE
            IN
            __QUINT_LAMBDA85({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_3809, main_replica_cert)

(*
  @type: ((Str, Int, Str) => Bool);
*)
main_replica_on_nullification_cert(main_replica_id_3851, main_replica_cert_view_3851,
main_replica_cert_sender_3851) ==
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3840 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3840) = "Nullification"
            -> LET (*
              @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
            *)
            __QUINT_LAMBDA86(main_replica_n_3835) ==
              main_replica_n_3835["view"] = main_replica_cert_view_3851
                /\ main_replica_n_3835["ghost_sender"]
                  = main_replica_cert_sender_3851
            IN
            __QUINT_LAMBDA86(VariantGetUnsafe("Nullification", main_replica_c_3840))
          [] OTHER
            -> (LET (*
              @type: ((q) => Bool);
            *)
            __QUINT_LAMBDA87(main_replica___3838) == FALSE
            IN
            __QUINT_LAMBDA87({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_3851, main_replica_cert)

(*
  @type: (() => Bool);
*)
main_replica_step ==
  ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_new_payload \in main_replica_VALID_PAYLOADS:
          \E main_replica_parent_view \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            main_replica_propose(main_replica_id, main_replica_new_payload, main_replica_parent_view)))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        main_replica_on_timeout(main_replica_id, (main_replica_LeaderTimeoutKind))))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        main_replica_on_timeout(main_replica_id, (main_replica_CertificationTimeoutKind))))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_vote_view \in main_replica_VIEWS:
          \E main_replica_vote_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_vote_payload \in main_replica_VALID_PAYLOADS:
              \E main_replica_vote_sig \in {
                main_replica_sig_of(main_replica_r_2328):
                  main_replica_r_2328 \in main_replica_Replicas
              }:
                main_replica_on_notarize(main_replica_id, [proposal |->
                    [view |-> main_replica_vote_view,
                      parent |-> main_replica_vote_parent,
                      payload |-> main_replica_vote_payload],
                  sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_vote_view \in main_replica_VIEWS:
          \E main_replica_vote_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_vote_payload \in main_replica_VALID_PAYLOADS:
              \E main_replica_vote_sig \in {
                main_replica_sig_of(main_replica_r_2370):
                  main_replica_r_2370 \in main_replica_Replicas
              }:
                main_replica_on_finalize(main_replica_id, [proposal |->
                    [view |-> main_replica_vote_view,
                      parent |-> main_replica_vote_parent,
                      payload |-> main_replica_vote_payload],
                  sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_vote_view \in main_replica_VIEWS:
          \E main_replica_vote_sig \in {
            main_replica_sig_of(main_replica_r_2403):
              main_replica_r_2403 \in main_replica_Replicas
          }:
            main_replica_on_nullify(main_replica_id, [view |->
                main_replica_vote_view,
              sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2450 \in main_replica_VIEWS:
          \E main_replica_cert_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_cert_payload_2448 \in main_replica_VALID_PAYLOADS:
              \E main_replica_cert_sender \in {
                main_replica_sig_of(main_replica_r_2437):
                  main_replica_r_2437 \in main_replica_Replicas
              }:
                main_replica_on_notarization_cert(main_replica_id, main_replica_cert_view_2450,
                main_replica_cert_parent, main_replica_cert_payload_2448, main_replica_cert_sender)))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2485 \in main_replica_VIEWS:
          \E main_replica_cert_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_cert_payload_2483 \in main_replica_VALID_PAYLOADS:
              \E main_replica_cert_sender \in {
                main_replica_sig_of(main_replica_r_2472):
                  main_replica_r_2472 \in main_replica_Replicas
              }:
                main_replica_on_finalization_cert(main_replica_id, main_replica_cert_view_2485,
                main_replica_cert_parent, main_replica_cert_payload_2483, main_replica_cert_sender)))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2507 \in main_replica_VIEWS:
          \E main_replica_cert_sender \in {
            main_replica_sig_of(main_replica_r_2498):
              main_replica_r_2498 \in main_replica_Replicas
          }:
            main_replica_on_nullification_cert(main_replica_id, main_replica_cert_view_2507,
            main_replica_cert_sender)))

(*
  @type: (() => Bool);
*)
q_step == main_replica_step

================================================================================
