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
    "val_b10",
    "val_b11",
    "val_b12",
    "val_b13",
    "val_b14",
    "val_b15",
    "val_b16",
    "val_b17",
    "val_b18",
    "val_b19",
    "val_b20",
    "val_b21",
    "val_b22" }

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
    @type: (Str -> { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
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
main_replica_Some(main_replica___SomeParam_5792) ==
  Variant("Some", main_replica___SomeParam_5792)

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
main_replica_is_some(main_replica_opt_5813) ==
  CASE VariantTag(main_replica_opt_5813) = "Some"
      -> LET (*
        @type: ((d) => Bool);
      *)
      __QUINT_LAMBDA0(main_replica___5808) == TRUE
      IN
      __QUINT_LAMBDA0(VariantGetUnsafe("Some", main_replica_opt_5813))
    [] VariantTag(main_replica_opt_5813) = "None"
      -> LET (*
        @type: (({ tag: Str }) => Bool);
      *)
      __QUINT_LAMBDA1(main_replica___5811) == FALSE
      IN
      __QUINT_LAMBDA1(VariantGetUnsafe("None", main_replica_opt_5813))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_is_nullification_cert(main_replica_c_361) ==
  CASE VariantTag(main_replica_c_361) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
      *)
      __QUINT_LAMBDA2(main_replica___356) == TRUE
      IN
      __QUINT_LAMBDA2(VariantGetUnsafe("Nullification", main_replica_c_361))
    [] OTHER
      -> (LET (*
        @type: ((e) => Bool);
      *)
      __QUINT_LAMBDA3(main_replica___359) == FALSE
      IN
      __QUINT_LAMBDA3({}))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Int);
*)
main_replica_cert_view(main_replica_c_203) ==
  CASE VariantTag(main_replica_c_203) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Int);
      *)
      __QUINT_LAMBDA4(main_replica_n_195) ==
        main_replica_n_195["proposal"]["view"]
      IN
      __QUINT_LAMBDA4(VariantGetUnsafe("Notarization", main_replica_c_203))
    [] VariantTag(main_replica_c_203) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Int);
      *)
      __QUINT_LAMBDA5(main_replica_n_198) == main_replica_n_198["view"]
      IN
      __QUINT_LAMBDA5(VariantGetUnsafe("Nullification", main_replica_c_203))
    [] VariantTag(main_replica_c_203) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Int);
      *)
      __QUINT_LAMBDA6(main_replica_f_201) ==
        main_replica_f_201["proposal"]["view"]
      IN
      __QUINT_LAMBDA6(VariantGetUnsafe("Finalization", main_replica_c_203))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_is_finalization_cert(main_replica_c_376) ==
  CASE VariantTag(main_replica_c_376) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA7(main_replica___371) == TRUE
      IN
      __QUINT_LAMBDA7(VariantGetUnsafe("Finalization", main_replica_c_376))
    [] OTHER
      -> (LET (*
        @type: ((f) => Bool);
      *)
      __QUINT_LAMBDA8(main_replica___374) == FALSE
      IN
      __QUINT_LAMBDA8({}))

(*
  @type: (() => (Str -> Str));
*)
main_replica_REPLICA_KEYS ==
  SetAsFun({ <<"n0", "n0">>, <<"n1", "n1">>, <<"n2", "n2">>, <<"n3", "n3">> })

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, Str) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_remember_timeout_reason(main_replica_self_1077, main_replica_view_1077,
main_replica_reason_1077) ==
  main_replica_self_1077

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
main_replica_option_has(main_replica_opt_5864, main_replica_pred_5864(_)) ==
  CASE VariantTag(main_replica_opt_5864) = "None"
      -> LET (*
        @type: (({ tag: Str }) => Bool);
      *)
      __QUINT_LAMBDA22(main_replica___5859) == FALSE
      IN
      __QUINT_LAMBDA22(VariantGetUnsafe("None", main_replica_opt_5864))
    [] VariantTag(main_replica_opt_5864) = "Some"
      -> LET (*
        @type: ((h) => Bool);
      *)
      __QUINT_LAMBDA23(main_replica_e_5862) ==
        main_replica_pred_5864(main_replica_e_5862)
      IN
      __QUINT_LAMBDA23(VariantGetUnsafe("Some", main_replica_opt_5864))

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
main_replica_cert_ghost_sender(main_replica_c_254) ==
  CASE VariantTag(main_replica_c_254) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA30(main_replica_n_246) == main_replica_n_246["ghost_sender"]
      IN
      __QUINT_LAMBDA30(VariantGetUnsafe("Notarization", main_replica_c_254))
    [] VariantTag(main_replica_c_254) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Str);
      *)
      __QUINT_LAMBDA31(main_replica_n_249) == main_replica_n_249["ghost_sender"]
      IN
      __QUINT_LAMBDA31(VariantGetUnsafe("Nullification", main_replica_c_254))
    [] VariantTag(main_replica_c_254) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA32(main_replica_f_252) == main_replica_f_252["ghost_sender"]
      IN
      __QUINT_LAMBDA32(VariantGetUnsafe("Finalization", main_replica_c_254))

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
main_replica_Notarization(main_replica___NotarizationParam_5649) ==
  Variant("Notarization", main_replica___NotarizationParam_5649)

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
main_replica_is_notarization_cert(main_replica_c_346) ==
  CASE VariantTag(main_replica_c_346) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA36(main_replica___341) == TRUE
      IN
      __QUINT_LAMBDA36(VariantGetUnsafe("Notarization", main_replica_c_346))
    [] OTHER
      -> (LET (*
        @type: ((k) => Bool);
      *)
      __QUINT_LAMBDA37(main_replica___344) == FALSE
      IN
      __QUINT_LAMBDA37({}))

(*
  @type: (() => Int);
*)
main_replica_ACTIVITY_TIMEOUT == 10

(*
  @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_Finalization(main_replica___FinalizationParam_5661) ==
  Variant("Finalization", main_replica___FinalizationParam_5661)

(*
  @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_Nullification(main_replica___NullificationParam_5655) ==
  Variant("Nullification", main_replica___NullificationParam_5655)

(*
  @type: ((Seq({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => Bool);
*)
main_replica_list_contains_proposal(main_replica_chain_1212, main_replica_proposal_1212) ==
  \E main_replica_i_1210 \in LET (*
    @type: (() => Set(Int));
  *)
  __quint_var14 == DOMAIN main_replica_chain_1212
  IN
  IF __quint_var14 = {}
  THEN {}
  ELSE (__quint_var14 \union {0}) \ {(Len(main_replica_chain_1212))}:
    main_replica_chain_1212[(main_replica_i_1210 + 1)]
      = main_replica_proposal_1212

(*
  @type: (() => Str);
*)
main_replica_LeaderNullifyReason == "LeaderNullify"

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set(Str));
*)
main_replica_cert_signatures(main_replica_c_229) ==
  CASE VariantTag(main_replica_c_229) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Str));
      *)
      __QUINT_LAMBDA66(main_replica_n_221) == main_replica_n_221["signatures"]
      IN
      __QUINT_LAMBDA66(VariantGetUnsafe("Notarization", main_replica_c_229))
    [] VariantTag(main_replica_c_229) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Set(Str));
      *)
      __QUINT_LAMBDA67(main_replica_n_224) == main_replica_n_224["signatures"]
      IN
      __QUINT_LAMBDA67(VariantGetUnsafe("Nullification", main_replica_c_229))
    [] VariantTag(main_replica_c_229) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Str));
      *)
      __QUINT_LAMBDA68(main_replica_f_227) == main_replica_f_227["signatures"]
      IN
      __QUINT_LAMBDA68(VariantGetUnsafe("Finalization", main_replica_c_229))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_same_certificate_subject(main_replica_existing_1143, main_replica_cert_1143) ==
  CASE VariantTag(main_replica_existing_1143) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA71(main_replica_n1_1135) ==
        CASE VariantTag(main_replica_cert_1143) = "Notarization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA69(main_replica_n2_1096) ==
              main_replica_n1_1135["proposal"]
                = main_replica_n2_1096["proposal"]
            IN
            __QUINT_LAMBDA69(VariantGetUnsafe("Notarization", main_replica_cert_1143))
          [] OTHER
            -> (LET (*
              @type: ((l) => Bool);
            *)
            __QUINT_LAMBDA70(main_replica___1099) == FALSE
            IN
            __QUINT_LAMBDA70({}))
      IN
      __QUINT_LAMBDA71(VariantGetUnsafe("Notarization", main_replica_existing_1143))
    [] VariantTag(main_replica_existing_1143) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
      *)
      __QUINT_LAMBDA74(main_replica_n1_1138) ==
        CASE VariantTag(main_replica_cert_1143) = "Nullification"
            -> LET (*
              @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
            *)
            __QUINT_LAMBDA72(main_replica_n2_1112) ==
              main_replica_n1_1138["view"] = main_replica_n2_1112["view"]
            IN
            __QUINT_LAMBDA72(VariantGetUnsafe("Nullification", main_replica_cert_1143))
          [] OTHER
            -> (LET (*
              @type: ((m) => Bool);
            *)
            __QUINT_LAMBDA73(main_replica___1115) == FALSE
            IN
            __QUINT_LAMBDA73({}))
      IN
      __QUINT_LAMBDA74(VariantGetUnsafe("Nullification", main_replica_existing_1143))
    [] VariantTag(main_replica_existing_1143) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
      *)
      __QUINT_LAMBDA77(main_replica_f1_1141) ==
        CASE VariantTag(main_replica_cert_1143) = "Finalization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA75(main_replica_f2_1128) ==
              main_replica_f1_1141["proposal"]
                = main_replica_f2_1128["proposal"]
            IN
            __QUINT_LAMBDA75(VariantGetUnsafe("Finalization", main_replica_cert_1143))
          [] OTHER
            -> (LET (*
              @type: ((n) => Bool);
            *)
            __QUINT_LAMBDA76(main_replica___1131) == FALSE
            IN
            __QUINT_LAMBDA76({}))
      IN
      __QUINT_LAMBDA77(VariantGetUnsafe("Finalization", main_replica_existing_1143))

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
main_replica_initWithLeaderAndCertify(main_replica_l_2289, main_replica_certify_2289) ==
  main_replica_replica_state
      = [
        main_replica_id_2228 \in main_replica_CORRECT |->
          [view |-> main_replica_FIRST_VIEW,
            ghost_last_seen_notarization |-> main_replica_GENESIS_VIEW,
            last_finalized |-> main_replica_GENESIS_VIEW,
            proposal |->
              [
                main_replica___2186 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_proposal |->
              [
                main_replica___2192 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_proposal_conflicted |->
              [ main_replica___2198 \in main_replica_VIEWS |-> FALSE ],
            certified |->
              [
                main_replica___2204 \in main_replica_VIEWS |->
                  main_replica_None
              ],
            leader_timeout |->
              [
                main_replica___2211 \in main_replica_VIEWS |->
                  main_replica_Some(FALSE)
              ],
            certification_timeout |->
              [
                main_replica___2218 \in main_replica_VIEWS |->
                  main_replica_Some(FALSE)
              ],
            locally_built |->
              [ main_replica___2224 \in main_replica_VIEWS |-> FALSE ]]
      ]
    /\ main_replica_sent_notarize_votes = {}
    /\ main_replica_sent_nullify_votes = {}
    /\ main_replica_sent_finalize_votes = {}
    /\ main_replica_sent_certificates = {}
    /\ main_replica_store_notarize_votes
      = [ main_replica___2247 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_nullify_votes
      = [ main_replica___2254 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_finalize_votes
      = [ main_replica___2261 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_store_certificates
      = [ main_replica___2268 \in main_replica_CORRECT |-> {} ]
    /\ main_replica_ghost_committed_blocks
      = [ main_replica___2275 \in main_replica_CORRECT |-> <<>> ]
    /\ main_replica_leader = main_replica_l_2289
    /\ main_replica_certify_policy = main_replica_certify_2289
    /\ main_replica_lastAction = "init"

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Bool);
*)
main_replica_is_view_nullified(main_replica_view_856, main_replica_certificates_856) ==
  main_replica_view_856 = main_replica_GENESIS_VIEW
    \/ (\E main_replica_c_853 \in main_replica_certificates_856:
      main_replica_is_nullification_cert(main_replica_c_853)
        /\ main_replica_cert_view(main_replica_c_853) = main_replica_view_856)

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_cert_proposal(main_replica_c_312) ==
  CASE VariantTag(main_replica_c_312) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA9(main_replica_n_304) ==
        main_replica_Some(main_replica_n_304["proposal"])
      IN
      __QUINT_LAMBDA9(VariantGetUnsafe("Notarization", main_replica_c_312))
    [] VariantTag(main_replica_c_312) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA10(main_replica___307) == main_replica_None
      IN
      __QUINT_LAMBDA10(VariantGetUnsafe("Nullification", main_replica_c_312))
    [] VariantTag(main_replica_c_312) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA11(main_replica_f_310) ==
        main_replica_Some(main_replica_f_310["proposal"])
      IN
      __QUINT_LAMBDA11(VariantGetUnsafe("Finalization", main_replica_c_312))

(*
  @type: ((Str) => Str);
*)
main_replica_sig_of(main_replica_id_106) ==
  (main_replica_REPLICA_KEYS)[main_replica_id_106]

(*
  @type: ((None({ tag: Str }) | Some(c)) => Bool);
*)
main_replica_is_none(main_replica_opt_5823) ==
  ~(main_replica_is_some(main_replica_opt_5823))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_observe_leader_proposal(main_replica_self_945, main_replica_proposal_945) ==
  LET (*
    @type: (() => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_known ==
    main_replica_self_945["leader_proposal"][main_replica_proposal_945["view"]]
  IN
  [
    [
      main_replica_self_945 EXCEPT
        !["leader_proposal"] =
          LET (*
            @type: (() => (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })));
          *)
          __quint_var0 == main_replica_self_945["leader_proposal"]
          IN
          LET (*
            @type: (() => Set(Int));
          *)
          __quint_var1 == DOMAIN __quint_var0
          IN
          [
            __quint_var2 \in
              {main_replica_proposal_945["view"]} \union __quint_var1 |->
              IF __quint_var2 = main_replica_proposal_945["view"]
              THEN CASE VariantTag((main_replica_known)) = "Some"
                  -> LET (*
                    @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
                  *)
                  __QUINT_LAMBDA24(main_replica_p_912) ==
                    main_replica_Some(main_replica_p_912)
                  IN
                  __QUINT_LAMBDA24(VariantGetUnsafe("Some", (main_replica_known)))
                [] VariantTag((main_replica_known)) = "None"
                  -> LET (*
                    @type: (({ tag: Str }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
                  *)
                  __QUINT_LAMBDA25(main_replica___915) ==
                    main_replica_Some(main_replica_proposal_945)
                  IN
                  __QUINT_LAMBDA25(VariantGetUnsafe("None", (main_replica_known)))
              ELSE (__quint_var0)[__quint_var2]
          ]
    ] EXCEPT
      !["leader_proposal_conflicted"] =
        LET (*
          @type: (() => (Int -> Bool));
        *)
        __quint_var3 == main_replica_self_945["leader_proposal_conflicted"]
        IN
        LET (*@type: (() => Set(Int)); *) __quint_var4 == DOMAIN __quint_var3 IN
        [
          __quint_var5 \in
            {main_replica_proposal_945["view"]} \union __quint_var4 |->
            IF __quint_var5 = main_replica_proposal_945["view"]
            THEN main_replica_self_945["leader_proposal_conflicted"][
                main_replica_proposal_945["view"]
              ]
              \/ LET (*
                @type: (({ parent: Int, payload: Str, view: Int }) => Bool);
              *)
              __QUINT_LAMBDA26(main_replica_p_937) ==
                main_replica_p_937 /= main_replica_proposal_945
              IN
              main_replica_option_has((main_replica_known), __QUINT_LAMBDA26)
            ELSE (__quint_var3)[__quint_var5]
        ]
  ]

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_record_local_proposal(main_replica_self_975, main_replica_proposal_975) ==
  IF main_replica_self_975["proposal"][main_replica_proposal_975["view"]]
    = main_replica_None
  THEN [
    main_replica_self_975 EXCEPT
      !["proposal"] =
        [
          main_replica_self_975["proposal"] EXCEPT
            ![main_replica_proposal_975["view"]] =
              main_replica_Some(main_replica_proposal_975)
        ]
  ]
  ELSE main_replica_self_975

(*
  @type: (((Int -> None({ tag: Str }) | Some(Bool)), Int) => Bool);
*)
main_replica_timeout_pending(main_replica_timers_1563, main_replica_view_1563) ==
  main_replica_timers_1563[main_replica_view_1563] = main_replica_Some(FALSE)

(*
  @type: (((Int -> None({ tag: Str }) | Some(Bool)), Int) => Bool);
*)
main_replica_timeout_fired(main_replica_timers_1580, main_replica_view_1580) ==
  main_replica_timers_1580[main_replica_view_1580] = main_replica_Some(TRUE)

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }) => Bool);
*)
main_replica_has_leader_proposal_conflict(main_replica_self_1067, main_replica_proposal_1067) ==
  main_replica_self_1067["leader_proposal_conflicted"][
      main_replica_proposal_1067["view"]
    ]
    \/ LET (*
      @type: (({ parent: Int, payload: Str, view: Int }) => Bool);
    *)
    __QUINT_LAMBDA27(main_replica_known_1064) ==
      main_replica_known_1064 /= main_replica_proposal_1067
    IN
    main_replica_option_has(main_replica_self_1067["leader_proposal"][
      main_replica_proposal_1067["view"]
    ], __QUINT_LAMBDA27)

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, { parent: Int, payload: Str, view: Int }, Bool) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_observe_round_proposal(main_replica_self_1039, main_replica_proposal_1039,
main_replica_recovered_1039) ==
  IF main_replica_self_1039["leader_proposal_conflicted"][
    main_replica_proposal_1039["view"]
  ]
  THEN main_replica_self_1039
  ELSE CASE VariantTag(main_replica_self_1039["proposal"][
      main_replica_proposal_1039["view"]
    ])
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
      *)
      __QUINT_LAMBDA28(main_replica___1033) ==
        [
          main_replica_self_1039 EXCEPT
            !["proposal"] =
              [
                main_replica_self_1039["proposal"] EXCEPT
                  ![main_replica_proposal_1039["view"]] =
                    main_replica_Some(main_replica_proposal_1039)
              ]
        ]
      IN
      __QUINT_LAMBDA28(VariantGetUnsafe("None", main_replica_self_1039[
        "proposal"
      ][
        main_replica_proposal_1039["view"]
      ]))
    [] VariantTag(main_replica_self_1039["proposal"][
      main_replica_proposal_1039["view"]
    ])
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
      *)
      __QUINT_LAMBDA29(main_replica_existing_1036) ==
        IF main_replica_existing_1036 = main_replica_proposal_1039
        THEN main_replica_self_1039
        ELSE IF main_replica_recovered_1039
        THEN [
          main_replica_self_1039 EXCEPT
            !["proposal"] =
              [
                main_replica_self_1039["proposal"] EXCEPT
                  ![main_replica_proposal_1039["view"]] =
                    main_replica_Some(main_replica_proposal_1039)
              ]
        ]
        ELSE main_replica_self_1039
      IN
      __QUINT_LAMBDA29(VariantGetUnsafe("Some", main_replica_self_1039[
        "proposal"
      ][
        main_replica_proposal_1039["view"]
      ]))

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Str);
*)
main_replica_cert_kind(main_replica_c_331) ==
  CASE VariantTag(main_replica_c_331) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA33(main_replica___323) == main_replica_NotarizationKind
      IN
      __QUINT_LAMBDA33(VariantGetUnsafe("Notarization", main_replica_c_331))
    [] VariantTag(main_replica_c_331) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Str);
      *)
      __QUINT_LAMBDA34(main_replica___326) == main_replica_NullificationKind
      IN
      __QUINT_LAMBDA34(VariantGetUnsafe("Nullification", main_replica_c_331))
    [] VariantTag(main_replica_c_331) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Str);
      *)
      __QUINT_LAMBDA35(main_replica___329) == main_replica_FinalizationKind
      IN
      __QUINT_LAMBDA35(VariantGetUnsafe("Finalization", main_replica_c_331))

(*
  @type: ((Str, Str) => Bool);
*)
main_replica_can_certify(main_replica_id_1513, main_replica_payload_1513) ==
  main_replica_payload_1513
    \in main_replica_certify_policy[main_replica_id_1513]

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_enter_view(main_replica_self_1546, main_replica_new_view_1546) ==
  IF ~(main_replica_new_view_1546 \in main_replica_VIEWS)
    \/ main_replica_self_1546["view"] >= main_replica_new_view_1546
  THEN main_replica_self_1546
  ELSE [
    [
      [ main_replica_self_1546 EXCEPT !["view"] = main_replica_new_view_1546 ] EXCEPT
        !["leader_timeout"] = main_replica_self_1546["leader_timeout"]
    ] EXCEPT
      !["certification_timeout"] =
        main_replica_self_1546["certification_timeout"]
  ]

(*
  @type: (({ parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => Bool);
*)
main_replica_is_proposal_notarized_votes(main_replica_proposal_795, main_replica_votes_795) ==
  (main_replica_proposal_795["view"] = main_replica_GENESIS_VIEW
      /\ main_replica_proposal_795["payload"] = main_replica_GENESIS_PAYLOAD)
    \/ Cardinality({
      main_replica_v_789["sig"]:
        main_replica_v_789 \in
          {
            main_replica_v_783 \in main_replica_votes_795:
              main_replica_v_783["proposal"] = main_replica_proposal_795
          }
    })
      >= main_replica_Q

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Str) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_cert_with_sender(main_replica_cert_1194, main_replica_sender_1194) ==
  CASE VariantTag(main_replica_cert_1194) = "Notarization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA52(main_replica_n_1186) ==
        main_replica_Notarization([
          main_replica_n_1186 EXCEPT
            !["ghost_sender"] = main_replica_sender_1194
        ])
      IN
      __QUINT_LAMBDA52(VariantGetUnsafe("Notarization", main_replica_cert_1194))
    [] VariantTag(main_replica_cert_1194) = "Nullification"
      -> LET (*
        @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA53(main_replica_n_1189) ==
        main_replica_Nullification([
          main_replica_n_1189 EXCEPT
            !["ghost_sender"] = main_replica_sender_1194
        ])
      IN
      __QUINT_LAMBDA53(VariantGetUnsafe("Nullification", main_replica_cert_1194))
    [] VariantTag(main_replica_cert_1194) = "Finalization"
      -> LET (*
        @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      __QUINT_LAMBDA54(main_replica_f_1192) ==
        main_replica_Finalization([
          main_replica_f_1192 EXCEPT
            !["ghost_sender"] = main_replica_sender_1194
        ])
      IN
      __QUINT_LAMBDA54(VariantGetUnsafe("Finalization", main_replica_cert_1194))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_cancel_all_timers(main_replica_self_1630, main_replica_view_1630) ==
  [
    [
      main_replica_self_1630 EXCEPT
        !["leader_timeout"] =
          [
            main_replica_self_1630["leader_timeout"] EXCEPT
              ![main_replica_view_1630] = main_replica_None
          ]
    ] EXCEPT
      !["certification_timeout"] =
        [
          main_replica_self_1630["certification_timeout"] EXCEPT
            ![main_replica_view_1630] = main_replica_None
        ]
  ]

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
*)
main_replica_fire_all_timers(main_replica_self_1606, main_replica_view_1606) ==
  [
    [
      main_replica_self_1606 EXCEPT
        !["leader_timeout"] =
          [
            main_replica_self_1606["leader_timeout"] EXCEPT
              ![main_replica_view_1606] = main_replica_Some(TRUE)
          ]
    ] EXCEPT
      !["certification_timeout"] =
        [
          main_replica_self_1606["certification_timeout"] EXCEPT
            ![main_replica_view_1606] = main_replica_Some(TRUE)
        ]
  ]

(*
  @type: (({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_send_notarize_vote(main_replica_vote_5022) ==
  main_replica_sent_notarize_votes'
      := (main_replica_sent_notarize_votes \union {main_replica_vote_5022})
    /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
    /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
    /\ main_replica_sent_certificates' := main_replica_sent_certificates
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_vote"

(*
  @type: (({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_send_finalize_vote(main_replica_vote_5070) ==
  main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
    /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
    /\ main_replica_sent_finalize_votes'
      := (main_replica_sent_finalize_votes \union {main_replica_vote_5070})
    /\ main_replica_sent_certificates' := main_replica_sent_certificates
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_vote"

(*
  @type: (({ sig: Str, view: Int }) => Bool);
*)
main_replica_send_nullify_vote(main_replica_vote_5118) ==
  main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
    /\ main_replica_sent_nullify_votes'
      := (main_replica_sent_nullify_votes \union {main_replica_vote_5118})
    /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
    /\ main_replica_sent_certificates' := main_replica_sent_certificates
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_vote"

(*
  @type: (({ parent: Int, payload: Str, view: Int }, Set(Str), Str) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_notarization(main_replica_proposal_5679, main_replica_signatures_5679,
main_replica_ghost_sender_5679) ==
  main_replica_Notarization([proposal |-> main_replica_proposal_5679,
    signatures |-> main_replica_signatures_5679,
    ghost_sender |-> main_replica_ghost_sender_5679])

(*
  @type: (({ parent: Int, payload: Str, view: Int }, Set(Str), Str) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_finalization(main_replica_proposal_5715, main_replica_signatures_5715,
main_replica_ghost_sender_5715) ==
  main_replica_Finalization([proposal |-> main_replica_proposal_5715,
    signatures |-> main_replica_signatures_5715,
    ghost_sender |-> main_replica_ghost_sender_5715])

(*
  @type: ((Int, Set(Str), Str) => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_nullification(main_replica_view_5697, main_replica_signatures_5697,
main_replica_ghost_sender_5697) ==
  main_replica_Nullification([view |-> main_replica_view_5697,
    signatures |-> main_replica_signatures_5697,
    ghost_sender |-> main_replica_ghost_sender_5697])

(*
  @type: (((Int -> Str)) => Bool);
*)
main_replica_initWithLeader(main_replica_l_2163) ==
  LET (*
    @type: (() => (Str -> Set(Str)));
  *)
  main_replica_default_certify_policy ==
    [
      main_replica___2156 \in main_replica_Replicas |->
        main_replica_AllPayloads
    ]
  IN
  main_replica_initWithLeaderAndCertify(main_replica_l_2163, (main_replica_default_certify_policy))

(*
  @type: ((Int, Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Bool);
*)
main_replica_are_views_nullified(main_replica_v1_883, main_replica_v2_883, main_replica_certificates_883) ==
  \A main_replica_v_881 \in {
    main_replica_v_875 \in main_replica_VIEWS:
      main_replica_v_875 > main_replica_v1_883
        /\ main_replica_v_875 < main_replica_v2_883
  }:
    main_replica_is_view_nullified(main_replica_v_881, main_replica_certificates_883)

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_finalized_proposal_at(main_replica_view_1267, main_replica_certificates_1267) ==
  LET (*
    @type: (() => Set({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_proposals ==
    LET (*
      @type: ((Set({ parent: Int, payload: Str, view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set({ parent: Int, payload: Str, view: Int }));
    *)
    __QUINT_LAMBDA14(main_replica_acc_1249, main_replica_c_1249) ==
      IF main_replica_is_finalization_cert(main_replica_c_1249)
        /\ main_replica_cert_view(main_replica_c_1249) = main_replica_view_1267
      THEN CASE VariantTag((main_replica_cert_proposal(main_replica_c_1249)))
          = "Some"
          -> LET (*
            @type: (({ parent: Int, payload: Str, view: Int }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA12(main_replica_p_1242) ==
            main_replica_acc_1249 \union {main_replica_p_1242}
          IN
          __QUINT_LAMBDA12(VariantGetUnsafe("Some", (main_replica_cert_proposal(main_replica_c_1249))))
        [] VariantTag((main_replica_cert_proposal(main_replica_c_1249)))
          = "None"
          -> LET (*
            @type: (({ tag: Str }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA13(main_replica___1245) == main_replica_acc_1249
          IN
          __QUINT_LAMBDA13(VariantGetUnsafe("None", (main_replica_cert_proposal(main_replica_c_1249))))
      ELSE main_replica_acc_1249
    IN
    ApaFoldSet(__QUINT_LAMBDA14, {}, main_replica_certificates_1267)
  IN
  IF Cardinality((main_replica_proposals)) = 1
  THEN LET (*
    @type: ((None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA15(main_replica__acc_1262, main_replica_p_1262) ==
    main_replica_Some(main_replica_p_1262)
  IN
  ApaFoldSet(__QUINT_LAMBDA15, (main_replica_None), (main_replica_proposals))
  ELSE main_replica_None

(*
  @type: ((Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Str, Int) => Bool);
*)
main_replica_broadcast_finalize_in(main_replica_sent_finalize_506, main_replica_id_506,
main_replica_view_506) ==
  \E main_replica_v_504 \in main_replica_sent_finalize_506:
    main_replica_v_504["sig"] = main_replica_sig_of(main_replica_id_506)
      /\ main_replica_v_504["proposal"]["view"] = main_replica_view_506

(*
  @type: ((Str, Int, Str) => Bool);
*)
main_replica_has_sent_vote(main_replica_id_445, main_replica_view_445, main_replica_kind_445) ==
  IF main_replica_kind_445 = main_replica_NotarizeKind
  THEN \E main_replica_v_404 \in main_replica_sent_notarize_votes:
    main_replica_v_404["sig"] = main_replica_sig_of(main_replica_id_445)
      /\ main_replica_v_404["proposal"]["view"] = main_replica_view_445
  ELSE IF main_replica_kind_445 = main_replica_NullifyKind
  THEN \E main_replica_v_423 \in main_replica_sent_nullify_votes:
    main_replica_v_423["sig"] = main_replica_sig_of(main_replica_id_445)
      /\ main_replica_v_423["view"] = main_replica_view_445
  ELSE \E main_replica_v_441 \in main_replica_sent_finalize_votes:
    main_replica_v_441["sig"] = main_replica_sig_of(main_replica_id_445)
      /\ main_replica_v_441["proposal"]["view"] = main_replica_view_445

(*
  @type: ((Str, { parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
*)
main_replica_create_notarization(main_replica_id_2066, main_replica_proposal_2066,
main_replica_votes_2066) ==
  LET (*
    @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_2038 \in main_replica_votes_2066:
        main_replica_v_2038["proposal"] = main_replica_proposal_2066
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_2046["sig"]:
        main_replica_v_2046 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([proposal |-> main_replica_proposal_2066,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2066)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_notarization(main_replica_id_531, main_replica_view_531) ==
  \E main_replica_c_529 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_529)
        = main_replica_sig_of(main_replica_id_531)
      /\ main_replica_cert_kind(main_replica_c_529)
        = main_replica_NotarizationKind
      /\ main_replica_cert_view(main_replica_c_529) = main_replica_view_531

(*
  @type: ((Str, { parent: Int, payload: Str, view: Int }, Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
*)
main_replica_create_finalization(main_replica_id_2115, main_replica_proposal_2115,
main_replica_votes_2115) ==
  LET (*
    @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_2087 \in main_replica_votes_2115:
        main_replica_v_2087["proposal"] = main_replica_proposal_2115
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_2095["sig"]:
        main_replica_v_2095 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([proposal |-> main_replica_proposal_2115,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2115)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_finalization(main_replica_id_581, main_replica_view_581) ==
  \E main_replica_c_579 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_579)
        = main_replica_sig_of(main_replica_id_581)
      /\ main_replica_cert_kind(main_replica_c_579)
        = main_replica_FinalizationKind
      /\ main_replica_cert_view(main_replica_c_579) = main_replica_view_581

(*
  @type: ((Str, Int, Set({ sig: Str, view: Int })) => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
*)
main_replica_create_nullification(main_replica_id_2017, main_replica_view_2017, main_replica_votes_2017) ==
  LET (*
    @type: (() => Set({ sig: Str, view: Int }));
  *)
  main_replica_similar_votes ==
    {
      main_replica_v_1989 \in main_replica_votes_2017:
        main_replica_v_1989["view"] = main_replica_view_2017
    }
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_signers ==
    {
      main_replica_v_1997["sig"]:
        main_replica_v_1997 \in main_replica_similar_votes
    }
  IN
  IF Cardinality((main_replica_signers)) < main_replica_Q
  THEN main_replica_None
  ELSE main_replica_Some([view |-> main_replica_view_2017,
    signatures |-> main_replica_signers,
    ghost_sender |-> main_replica_sig_of(main_replica_id_2017)])

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_nullification(main_replica_id_556, main_replica_view_556) ==
  \E main_replica_c_554 \in main_replica_sent_certificates:
    main_replica_cert_ghost_sender(main_replica_c_554)
        = main_replica_sig_of(main_replica_id_556)
      /\ main_replica_cert_kind(main_replica_c_554)
        = main_replica_NullificationKind
      /\ main_replica_cert_view(main_replica_c_554) = main_replica_view_556

(*
  @type: ((Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Bool);
*)
main_replica_same_certificate_kind_and_view(main_replica_existing_1161, main_replica_cert_1161) ==
  main_replica_cert_kind(main_replica_existing_1161)
      = main_replica_cert_kind(main_replica_cert_1161)
    /\ main_replica_cert_view(main_replica_existing_1161)
      = main_replica_cert_view(main_replica_cert_1161)

(*
  @type: (() => Set(Str));
*)
main_replica_CorrectSigs ==
  {
    main_replica_sig_of(main_replica_id_119):
      main_replica_id_119 \in main_replica_CORRECT
  }

(*
  @type: ((Int, Int, Str, Str, Set(Str)) => Bool);
*)
main_replica_send_notarization_cert(main_replica_cert_view_5244, main_replica_cert_parent_5244,
main_replica_cert_payload_5244, main_replica_ghost_sender_5244, main_replica_signers_5244) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_proposal ==
    [view |-> main_replica_cert_view_5244,
      parent |-> main_replica_cert_parent_5244,
      payload |-> main_replica_cert_payload_5244]
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_have_sigs ==
    {
      main_replica_v_5154["sig"]:
        main_replica_v_5154 \in
          {
            main_replica_v_5148 \in main_replica_sent_notarize_votes:
              main_replica_v_5148["proposal"] = main_replica_proposal
          }
    }
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_no_duplicate ==
    \A main_replica_c_5180 \in main_replica_sent_certificates:
      CASE VariantTag(main_replica_c_5180) = "Notarization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA89(main_replica_n_5175) ==
            ~(main_replica_n_5175["proposal"] = main_replica_proposal
              /\ main_replica_n_5175["ghost_sender"]
                = main_replica_ghost_sender_5244)
          IN
          __QUINT_LAMBDA89(VariantGetUnsafe("Notarization", main_replica_c_5180))
        [] OTHER
          -> (LET (*
            @type: ((r) => Bool);
          *)
          __QUINT_LAMBDA90(main_replica___5178) == TRUE
          IN
          __QUINT_LAMBDA90({}))
  IN
  Cardinality(main_replica_signers_5244) >= main_replica_Q
    /\ (\A main_replica_s_5192 \in main_replica_signers_5244:
      main_replica_s_5192 \in main_replica_have_sigs)
    /\ main_replica_no_duplicate
    /\ main_replica_sent_certificates'
      := (main_replica_sent_certificates
        \union {(main_replica_notarization((main_replica_proposal), main_replica_signers_5244,
        main_replica_ghost_sender_5244))})
    /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
    /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
    /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_cert"

(*
  @type: ((Int, Int, Str, Str, Set(Str)) => Bool);
*)
main_replica_send_finalization_cert(main_replica_cert_view_5370, main_replica_cert_parent_5370,
main_replica_cert_payload_5370, main_replica_ghost_sender_5370, main_replica_signers_5370) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_proposal ==
    [view |-> main_replica_cert_view_5370,
      parent |-> main_replica_cert_parent_5370,
      payload |-> main_replica_cert_payload_5370]
  IN
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_have_sigs ==
    {
      main_replica_v_5280["sig"]:
        main_replica_v_5280 \in
          {
            main_replica_v_5274 \in main_replica_sent_finalize_votes:
              main_replica_v_5274["proposal"] = main_replica_proposal
          }
    }
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_no_duplicate ==
    \A main_replica_c_5306 \in main_replica_sent_certificates:
      CASE VariantTag(main_replica_c_5306) = "Finalization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA91(main_replica_f_5301) ==
            ~(main_replica_f_5301["proposal"] = main_replica_proposal
              /\ main_replica_f_5301["ghost_sender"]
                = main_replica_ghost_sender_5370)
          IN
          __QUINT_LAMBDA91(VariantGetUnsafe("Finalization", main_replica_c_5306))
        [] OTHER
          -> (LET (*
            @type: ((s) => Bool);
          *)
          __QUINT_LAMBDA92(main_replica___5304) == TRUE
          IN
          __QUINT_LAMBDA92({}))
  IN
  Cardinality(main_replica_signers_5370) >= main_replica_Q
    /\ (\A main_replica_s_5318 \in main_replica_signers_5370:
      main_replica_s_5318 \in main_replica_have_sigs)
    /\ main_replica_no_duplicate
    /\ main_replica_sent_certificates'
      := (main_replica_sent_certificates
        \union {(main_replica_finalization((main_replica_proposal), main_replica_signers_5370,
        main_replica_ghost_sender_5370))})
    /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
    /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
    /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_cert"

(*
  @type: ((Int, Str, Set(Str)) => Bool);
*)
main_replica_send_nullification_cert(main_replica_cert_view_5482, main_replica_ghost_sender_5482,
main_replica_signers_5482) ==
  LET (*
    @type: (() => Set(Str));
  *)
  main_replica_have_sigs ==
    {
      main_replica_v_5393["sig"]:
        main_replica_v_5393 \in
          {
            main_replica_v_5387 \in main_replica_sent_nullify_votes:
              main_replica_v_5387["view"] = main_replica_cert_view_5482
          }
    }
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_no_duplicate ==
    \A main_replica_c_5419 \in main_replica_sent_certificates:
      CASE VariantTag(main_replica_c_5419) = "Nullification"
          -> LET (*
            @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
          *)
          __QUINT_LAMBDA93(main_replica_n_5414) ==
            ~(main_replica_n_5414["view"] = main_replica_cert_view_5482
              /\ main_replica_n_5414["ghost_sender"]
                = main_replica_ghost_sender_5482)
          IN
          __QUINT_LAMBDA93(VariantGetUnsafe("Nullification", main_replica_c_5419))
        [] OTHER
          -> (LET (*
            @type: ((t) => Bool);
          *)
          __QUINT_LAMBDA94(main_replica___5417) == TRUE
          IN
          __QUINT_LAMBDA94({}))
  IN
  Cardinality(main_replica_signers_5482) >= main_replica_Q
    /\ (\A main_replica_s_5431 \in main_replica_signers_5482:
      main_replica_s_5431 \in main_replica_have_sigs)
    /\ main_replica_no_duplicate
    /\ main_replica_sent_certificates'
      := (main_replica_sent_certificates
        \union {(main_replica_nullification(main_replica_cert_view_5482, main_replica_signers_5482,
        main_replica_ghost_sender_5482))})
    /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
    /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
    /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
    /\ main_replica_store_notarize_votes' := main_replica_store_notarize_votes
    /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
    /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
    /\ main_replica_store_certificates' := main_replica_store_certificates
    /\ main_replica_ghost_committed_blocks'
      := main_replica_ghost_committed_blocks
    /\ main_replica_leader' := main_replica_leader
    /\ main_replica_replica_state' := main_replica_replica_state
    /\ main_replica_certify_policy' := main_replica_certify_policy
    /\ main_replica_lastAction' := "inject_cert"

(*
  @type: (() => Bool);
*)
main_replica_init ==
  LET (*
    @type: (() => (Int -> Str));
  *)
  main_replica_l ==
    [
      main_replica_v_2141 \in main_replica_VIEWS |->
        IF main_replica_v_2141 % 4 = 0
        THEN "n0"
        ELSE IF main_replica_v_2141 % 4 = 1
        THEN "n1"
        ELSE IF main_replica_v_2141 % 4 = 2 THEN "n2" ELSE "n3"
    ]
  IN
  main_replica_initWithLeader((main_replica_l))

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some(Str));
*)
main_replica_finalized_payload_at(main_replica_view_1292, main_replica_certificates_1292) ==
  CASE VariantTag((main_replica_finalized_proposal_at(main_replica_view_1292, main_replica_certificates_1292)))
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA16(main_replica_p_1287) ==
        main_replica_Some(main_replica_p_1287["payload"])
      IN
      __QUINT_LAMBDA16(VariantGetUnsafe("Some", (main_replica_finalized_proposal_at(main_replica_view_1292,
      main_replica_certificates_1292))))
    [] VariantTag((main_replica_finalized_proposal_at(main_replica_view_1292, main_replica_certificates_1292)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA17(main_replica___1290) == main_replica_None
      IN
      __QUINT_LAMBDA17(VariantGetUnsafe("None", (main_replica_finalized_proposal_at(main_replica_view_1292,
      main_replica_certificates_1292))))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Str, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_forced_timeout_expired(main_replica_self_1895, main_replica_id_1895,
main_replica_view_1895, main_replica_reason_1895, main_replica_sent_nullify_1895,
main_replica_sent_finalize_1895, main_replica_stored_nullify_1895) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1895,
      sig |-> main_replica_sig_of(main_replica_id_1895)]
  IN
  IF main_replica_self_1895["view"] /= main_replica_view_1895
  THEN [next_self |-> main_replica_self_1895,
    next_sent_nullify |-> main_replica_sent_nullify_1895,
    next_stored_nullify |-> main_replica_stored_nullify_1895]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1895, main_replica_id_1895,
  main_replica_view_1895)
  THEN [next_self |->
      main_replica_remember_timeout_reason([
        [
          main_replica_self_1895 EXCEPT
            !["leader_timeout"] =
              [
                main_replica_self_1895["leader_timeout"] EXCEPT
                  ![main_replica_view_1895] = main_replica_None
              ]
        ] EXCEPT
          !["certification_timeout"] =
            [
              main_replica_self_1895["certification_timeout"] EXCEPT
                ![main_replica_view_1895] = main_replica_None
            ]
      ], main_replica_view_1895, main_replica_reason_1895),
    next_sent_nullify |-> main_replica_sent_nullify_1895,
    next_stored_nullify |-> main_replica_stored_nullify_1895]
  ELSE [next_self |->
      [
        [
          (main_replica_remember_timeout_reason(main_replica_self_1895, main_replica_view_1895,
          main_replica_reason_1895)) EXCEPT
            !["leader_timeout"] =
              [
                main_replica_self_1895["leader_timeout"] EXCEPT
                  ![main_replica_view_1895] = main_replica_None
              ]
        ] EXCEPT
          !["certification_timeout"] =
            [
              main_replica_self_1895["certification_timeout"] EXCEPT
                ![main_replica_view_1895] = main_replica_None
            ]
      ],
    next_sent_nullify |->
      main_replica_sent_nullify_1895 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1895 \union {(main_replica_local_nullify)}]

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_nullify(main_replica_id_467, main_replica_view_467) ==
  main_replica_has_sent_vote(main_replica_id_467, main_replica_view_467, (main_replica_NullifyKind))

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Str, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_timer_expired(main_replica_self_1790, main_replica_id_1790, main_replica_view_1790,
main_replica_expired_1790, main_replica_sent_nullify_1790, main_replica_sent_finalize_1790,
main_replica_stored_nullify_1790) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1790,
      sig |-> main_replica_sig_of(main_replica_id_1790)]
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_leader_expired ==
    main_replica_expired_1790 = main_replica_LeaderTimeoutKind
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_advance_expired ==
    main_replica_expired_1790 = main_replica_CertificationTimeoutKind
  IN
  IF main_replica_self_1790["view"] /= main_replica_view_1790
  THEN [next_self |-> main_replica_self_1790,
    next_sent_nullify |-> main_replica_sent_nullify_1790,
    next_stored_nullify |-> main_replica_stored_nullify_1790]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1790, main_replica_id_1790,
  main_replica_view_1790)
  THEN [next_self |->
      [
        [
          main_replica_self_1790 EXCEPT
            !["leader_timeout"] =
              IF main_replica_leader_expired
              THEN [
                main_replica_self_1790["leader_timeout"] EXCEPT
                  ![main_replica_view_1790] = main_replica_Some(TRUE)
              ]
              ELSE main_replica_self_1790["leader_timeout"]
        ] EXCEPT
          !["certification_timeout"] =
            IF main_replica_advance_expired
            THEN [
              main_replica_self_1790["certification_timeout"] EXCEPT
                ![main_replica_view_1790] = main_replica_Some(TRUE)
            ]
            ELSE main_replica_self_1790["certification_timeout"]
      ],
    next_sent_nullify |-> main_replica_sent_nullify_1790,
    next_stored_nullify |-> main_replica_stored_nullify_1790]
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
          (main_replica_remember_timeout_reason(main_replica_self_1790, main_replica_view_1790,
          (main_replica_timeout_reason))) EXCEPT
            !["leader_timeout"] =
              IF main_replica_leader_expired
              THEN [
                main_replica_self_1790["leader_timeout"] EXCEPT
                  ![main_replica_view_1790] = main_replica_Some(TRUE)
              ]
              ELSE main_replica_self_1790["leader_timeout"]
        ] EXCEPT
          !["certification_timeout"] =
            IF main_replica_advance_expired
            THEN [
              main_replica_self_1790["certification_timeout"] EXCEPT
                ![main_replica_view_1790] = main_replica_Some(TRUE)
            ]
            ELSE main_replica_self_1790["certification_timeout"]
      ],
    next_sent_nullify |->
      main_replica_sent_nullify_1790 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1790 \union {(main_replica_local_nullify)}]

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_notarize(main_replica_id_456, main_replica_view_456) ==
  main_replica_has_sent_vote(main_replica_id_456, main_replica_view_456, (main_replica_NotarizeKind))

(*
  @type: ((Str, Int) => Bool);
*)
main_replica_broadcast_finalize(main_replica_id_478, main_replica_view_478) ==
  main_replica_has_sent_vote(main_replica_id_478, main_replica_view_478, (main_replica_FinalizeKind))

(*
  @type: ((Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_next_committable_proposal(main_replica_parent_view_1362, main_replica_certificates_1362) ==
  LET (*
    @type: (() => Set({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_proposals ==
    LET (*
      @type: ((Set({ parent: Int, payload: Str, view: Int }), Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })) => Set({ parent: Int, payload: Str, view: Int }));
    *)
    __QUINT_LAMBDA57(main_replica_acc_1344, main_replica_c_1344) ==
      IF main_replica_is_finalization_cert(main_replica_c_1344)
      THEN CASE VariantTag((main_replica_cert_proposal(main_replica_c_1344)))
          = "Some"
          -> LET (*
            @type: (({ parent: Int, payload: Str, view: Int }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA55(main_replica_p_1337) ==
            IF (main_replica_p_1337["parent"] = main_replica_parent_view_1362
                /\ main_replica_p_1337["view"] > main_replica_parent_view_1362)
              /\ main_replica_are_views_nullified(main_replica_parent_view_1362,
              main_replica_p_1337["view"], main_replica_certificates_1362)
            THEN main_replica_acc_1344 \union {main_replica_p_1337}
            ELSE main_replica_acc_1344
          IN
          __QUINT_LAMBDA55(VariantGetUnsafe("Some", (main_replica_cert_proposal(main_replica_c_1344))))
        [] VariantTag((main_replica_cert_proposal(main_replica_c_1344)))
          = "None"
          -> LET (*
            @type: (({ tag: Str }) => Set({ parent: Int, payload: Str, view: Int }));
          *)
          __QUINT_LAMBDA56(main_replica___1340) == main_replica_acc_1344
          IN
          __QUINT_LAMBDA56(VariantGetUnsafe("None", (main_replica_cert_proposal(main_replica_c_1344))))
      ELSE main_replica_acc_1344
    IN
    ApaFoldSet(__QUINT_LAMBDA57, {}, main_replica_certificates_1362)
  IN
  IF Cardinality((main_replica_proposals)) = 1
  THEN LET (*
    @type: ((None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }), { parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA58(main_replica__acc_1357, main_replica_p_1357) ==
    main_replica_Some(main_replica_p_1357)
  IN
  ApaFoldSet(__QUINT_LAMBDA58, (main_replica_None), (main_replica_proposals))
  ELSE main_replica_None

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, Int, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_leader_nullify_expired(main_replica_self_1970, main_replica_id_1970,
main_replica_view_1970, main_replica_sent_nullify_1970, main_replica_sent_finalize_1970,
main_replica_stored_nullify_1970) ==
  LET (*
    @type: (() => { sig: Str, view: Int });
  *)
  main_replica_local_nullify ==
    [view |-> main_replica_view_1970,
      sig |-> main_replica_sig_of(main_replica_id_1970)]
  IN
  IF main_replica_self_1970["view"] /= main_replica_view_1970
  THEN [next_self |-> main_replica_self_1970,
    next_sent_nullify |-> main_replica_sent_nullify_1970,
    next_stored_nullify |-> main_replica_stored_nullify_1970]
  ELSE IF main_replica_broadcast_finalize_in(main_replica_sent_finalize_1970, main_replica_id_1970,
  main_replica_view_1970)
  THEN [next_self |->
      main_replica_remember_timeout_reason((main_replica_fire_all_timers(main_replica_self_1970,
      main_replica_view_1970)), main_replica_view_1970, (main_replica_LeaderNullifyReason)),
    next_sent_nullify |-> main_replica_sent_nullify_1970,
    next_stored_nullify |-> main_replica_stored_nullify_1970]
  ELSE [next_self |->
      main_replica_remember_timeout_reason((main_replica_fire_all_timers(main_replica_self_1970,
      main_replica_view_1970)), main_replica_view_1970, (main_replica_LeaderNullifyReason)),
    next_sent_nullify |->
      main_replica_sent_nullify_1970 \union {(main_replica_local_nullify)},
    next_stored_nullify |->
      main_replica_stored_nullify_1970 \union {(main_replica_local_nullify)}]

(*
  @type: (() => Bool);
*)
q_init == main_replica_init

(*
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, Int, Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => None({ tag: Str }) | Some(Str));
*)
main_replica_parent_payload(main_replica_self_1501, main_replica_view_1501, main_replica_parent_view_1501,
main_replica_certificates_1501) ==
  IF main_replica_view_1501 <= main_replica_parent_view_1501
  THEN main_replica_None
  ELSE IF main_replica_parent_view_1501
    < main_replica_self_1501["last_finalized"]
  THEN main_replica_None
  ELSE IF ~(main_replica_are_views_nullified(main_replica_parent_view_1501, main_replica_view_1501,
  main_replica_certificates_1501))
  THEN main_replica_None
  ELSE IF main_replica_parent_view_1501 = main_replica_GENESIS_VIEW
  THEN main_replica_Some((main_replica_GENESIS_PAYLOAD))
  ELSE CASE VariantTag((main_replica_finalized_payload_at(main_replica_parent_view_1501,
    main_replica_certificates_1501)))
      = "Some"
      -> LET (*
        @type: ((Str) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA18(main_replica_p_1492) ==
        main_replica_Some(main_replica_p_1492)
      IN
      __QUINT_LAMBDA18(VariantGetUnsafe("Some", (main_replica_finalized_payload_at(main_replica_parent_view_1501,
      main_replica_certificates_1501))))
    [] VariantTag((main_replica_finalized_payload_at(main_replica_parent_view_1501,
    main_replica_certificates_1501)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
      *)
      __QUINT_LAMBDA21(main_replica___1495) ==
        IF main_replica_self_1501["certified"][main_replica_parent_view_1501]
          = main_replica_Some(TRUE)
        THEN CASE VariantTag(main_replica_self_1501["proposal"][
            main_replica_parent_view_1501
          ])
            = "Some"
            -> LET (*
              @type: (({ parent: Int, payload: Str, view: Int }) => None({ tag: Str }) | Some(Str));
            *)
            __QUINT_LAMBDA19(main_replica_proposal_1483) ==
              main_replica_Some(main_replica_proposal_1483["payload"])
            IN
            __QUINT_LAMBDA19(VariantGetUnsafe("Some", main_replica_self_1501[
              "proposal"
            ][
              main_replica_parent_view_1501
            ]))
          [] VariantTag(main_replica_self_1501["proposal"][
            main_replica_parent_view_1501
          ])
            = "None"
            -> LET (*
              @type: (({ tag: Str }) => None({ tag: Str }) | Some(Str));
            *)
            __QUINT_LAMBDA20(main_replica___1486) == main_replica_None
            IN
            __QUINT_LAMBDA20(VariantGetUnsafe("None", main_replica_self_1501[
              "proposal"
            ][
              main_replica_parent_view_1501
            ]))
        ELSE main_replica_None
      IN
      __QUINT_LAMBDA21(VariantGetUnsafe("None", (main_replica_finalized_payload_at(main_replica_parent_view_1501,
      main_replica_certificates_1501))))

(*
  @type: ((Str, Str) => Bool);
*)
main_replica_on_timeout(main_replica_id_4974, main_replica_expired_4974) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4974]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_leader_mode ==
      main_replica_expired_4974 = main_replica_LeaderTimeoutKind
        /\ main_replica_timeout_pending((main_replica_self)["leader_timeout"], (main_replica_self)[
          "view"
        ])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_advance_mode ==
      main_replica_expired_4974 = main_replica_CertificationTimeoutKind
        /\ main_replica_timeout_fired((main_replica_self)["leader_timeout"], (main_replica_self)[
          "view"
        ])
        /\ main_replica_timeout_pending((main_replica_self)[
          "certification_timeout"
        ], (main_replica_self)["view"])
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_timer_expired((main_replica_self), main_replica_id_4974, (main_replica_self)[
        "view"
      ], main_replica_expired_4974, main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
      main_replica_store_nullify_votes[main_replica_id_4974])
    IN
    ~(main_replica_broadcast_nullify(main_replica_id_4974, (main_replica_self)[
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
            ![main_replica_id_4974] =
              (main_replica_timer)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4974] = (main_replica_timer)["next_self"]
        ]
      /\ main_replica_sent_certificates' := main_replica_sent_certificates
      /\ main_replica_store_certificates' := main_replica_store_certificates
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "timeout")

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, { parent: Int, payload: Str, view: Int }, Bool) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_construct_notarize(main_replica_id_709, main_replica_self_709, main_replica_view_709,
main_replica_proposal_709, main_replica_is_verified_709) ==
  IF main_replica_broadcast_notarize(main_replica_id_709, main_replica_view_709)
    \/ main_replica_broadcast_nullify(main_replica_id_709, main_replica_view_709)
  THEN main_replica_None
  ELSE IF ~main_replica_is_verified_709
  THEN main_replica_None
  ELSE main_replica_Some(main_replica_proposal_709)

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int, { parent: Int, payload: Str, view: Int }, Bool, Bool) => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
*)
main_replica_construct_finalize(main_replica_id_757, main_replica_self_757, main_replica_view_757,
main_replica_proposal_757, main_replica_proposal_conflicted_757, main_replica_is_certified_757) ==
  IF main_replica_broadcast_finalize(main_replica_id_757, main_replica_view_757)
    \/ main_replica_broadcast_nullify(main_replica_id_757, main_replica_view_757)
  THEN main_replica_None
  ELSE IF main_replica_proposal_conflicted_757
  THEN main_replica_None
  ELSE IF ~main_replica_is_certified_757
  THEN main_replica_None
  ELSE main_replica_Some(main_replica_proposal_757)

(*
  @type: ((Str, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Int) => Bool);
*)
main_replica_construct_nullify(main_replica_id_722, main_replica_self_722, main_replica_view_722) ==
  ~(main_replica_broadcast_finalize(main_replica_id_722, main_replica_view_722))

(*
  @type: ((Seq({ parent: Int, payload: Str, view: Int }), Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Seq({ parent: Int, payload: Str, view: Int }));
*)
main_replica_extend_committed_chain_once(main_replica_chain_1407, main_replica_certificates_1407) ==
  LET (*
    @type: (() => Int);
  *)
  main_replica_parent_view ==
    IF Len(main_replica_chain_1407) = 0
    THEN main_replica_GENESIS_VIEW
    ELSE main_replica_chain_1407[(Len(main_replica_chain_1407) - 1 + 1)]["view"]
  IN
  CASE VariantTag((main_replica_next_committable_proposal((main_replica_parent_view),
    main_replica_certificates_1407)))
      = "Some"
      -> LET (*
        @type: (({ parent: Int, payload: Str, view: Int }) => Seq({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA59(main_replica_p_1401) ==
        IF main_replica_list_contains_proposal(main_replica_chain_1407, main_replica_p_1401)
        THEN main_replica_chain_1407
        ELSE Append(main_replica_chain_1407, main_replica_p_1401)
      IN
      __QUINT_LAMBDA59(VariantGetUnsafe("Some", (main_replica_next_committable_proposal((main_replica_parent_view),
      main_replica_certificates_1407))))
    [] VariantTag((main_replica_next_committable_proposal((main_replica_parent_view),
    main_replica_certificates_1407)))
      = "None"
      -> LET (*
        @type: (({ tag: Str }) => Seq({ parent: Int, payload: Str, view: Int }));
      *)
      __QUINT_LAMBDA60(main_replica___1404) == main_replica_chain_1407
      IN
      __QUINT_LAMBDA60(VariantGetUnsafe("None", (main_replica_next_committable_proposal((main_replica_parent_view),
      main_replica_certificates_1407))))

(*
  @type: ((Str, Str, Int) => Bool);
*)
main_replica_propose(main_replica_id_2893, main_replica_new_payload_2893, main_replica_parent_view_2893) ==
  (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_notarize ==
      main_replica_store_notarize_votes[main_replica_id_2893]
    IN
    LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_2893]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_2893]
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_2893]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_proposal_ok ==
      main_replica_new_payload_2893 \in main_replica_VALID_PAYLOADS
        /\ main_replica_is_some((main_replica_parent_payload((main_replica_self),
        (main_replica_self)["view"], main_replica_parent_view_2893, (main_replica_certs))))
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal ==
      [view |-> (main_replica_self)["view"],
        parent |-> main_replica_parent_view_2893,
        payload |-> main_replica_new_payload_2893]
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_forced_timeout_expired((main_replica_self), main_replica_id_2893,
      (main_replica_self)["view"], (main_replica_InvalidProposalReason), main_replica_sent_nullify_votes,
      main_replica_sent_finalize_votes, (main_replica_store_nullify))
    IN
    main_replica_id_2893 = main_replica_leader[(main_replica_self)["view"]]
      /\ main_replica_is_none((main_replica_self)["proposal"][
        (main_replica_self)["view"]
      ])
      /\ ~(main_replica_broadcast_nullify(main_replica_id_2893, (main_replica_self)[
        "view"
      ]))
      /\ main_replica_proposal_ok
      /\ main_replica_sent_notarize_votes'
        := (main_replica_sent_notarize_votes
          \union {[proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_2893)]})
      /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_store_notarize_votes'
        := [
          main_replica_store_notarize_votes EXCEPT
            ![main_replica_id_2893] =
              main_replica_store_notarize
                \union {[proposal |-> main_replica_proposal,
                  sig |-> main_replica_sig_of(main_replica_id_2893)]}
        ]
      /\ main_replica_store_nullify_votes' := main_replica_store_nullify_votes
      /\ main_replica_store_finalize_votes' := main_replica_store_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_2893] =
              [
                [
                  (main_replica_observe_leader_proposal((main_replica_record_local_proposal((main_replica_self),
                  (main_replica_proposal))), (main_replica_proposal))) EXCEPT
                    !["leader_timeout"] =
                      [
                        (main_replica_self)["leader_timeout"] EXCEPT
                          ![(main_replica_self)["view"]] = main_replica_None
                      ]
                ] EXCEPT
                  !["locally_built"] =
                    [
                      (main_replica_self)["locally_built"] EXCEPT
                        ![(main_replica_self)["view"]] = TRUE
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
  @type: (({ certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), Set({ sig: Str, view: Int }), Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
*)
main_replica_notarize_effect(main_replica_self_4440, main_replica_id_4440, main_replica_notarization_4440,
main_replica_sent_nullify_votes_4440, main_replica_sent_finalize_votes_4440, main_replica_stored_nullify_4440,
main_replica_stored_finalize_4440) ==
  LET (*
    @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
  *)
  main_replica_cert == main_replica_Notarization(main_replica_notarization_4440)
  IN
  LET (*
    @type: (() => Int);
  *)
  main_replica_cert_view_num ==
    main_replica_notarization_4440["proposal"]["view"]
  IN
  LET (*
    @type: (() => Int);
  *)
  main_replica_seen_notarization ==
    IF main_replica_self_4440["ghost_last_seen_notarization"]
      < main_replica_cert_view_num
    THEN main_replica_cert_view_num
    ELSE main_replica_self_4440["ghost_last_seen_notarization"]
  IN
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_prop == main_replica_notarization_4440["proposal"]
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_proposal_conflicted ==
    main_replica_has_leader_proposal_conflict(main_replica_self_4440, (main_replica_cert_prop))
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_should_broadcast ==
    ~(main_replica_broadcast_notarization(main_replica_id_4440, (main_replica_cert_view_num)))
  IN
  LET (*
    @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
  *)
  main_replica_timer ==
    main_replica_forced_timeout_expired(main_replica_self_4440, main_replica_id_4440,
    (main_replica_cert_view_num), (main_replica_FailedCertificationReason), main_replica_sent_nullify_votes_4440,
    main_replica_sent_finalize_votes_4440, main_replica_stored_nullify_4440)
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_local_auto_cert ==
    main_replica_self_4440["locally_built"][(main_replica_cert_view_num)]
      /\ ~main_replica_proposal_conflicted
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_cert_succeeds ==
    main_replica_local_auto_cert
      \/ main_replica_can_certify(main_replica_id_4440, (main_replica_cert_prop)[
        "payload"
      ])
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_is_certified ==
    main_replica_cert_succeeds
      /\ main_replica_self_4440["certified"][(main_replica_cert_view_num)]
        = main_replica_None
  IN
  LET (*
    @type: (() => None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int }));
  *)
  main_replica_finalize_result ==
    main_replica_construct_finalize(main_replica_id_4440, main_replica_self_4440,
    (main_replica_cert_view_num), (main_replica_cert_prop), (main_replica_proposal_conflicted),
    (main_replica_is_certified))
  IN
  LET (*
    @type: (() => Bool);
  *)
  main_replica_can_send_nullify ==
    ~main_replica_cert_succeeds
      /\ main_replica_self_4440["view"] = main_replica_cert_view_num
      /\ main_replica_construct_nullify(main_replica_id_4440, main_replica_self_4440,
      (main_replica_cert_view_num))
      /\ ~(main_replica_broadcast_nullify(main_replica_id_4440, (main_replica_cert_view_num)))
  IN
  LET (*
    @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
  *)
  main_replica_observed ==
    main_replica_observe_leader_proposal((main_replica_observe_round_proposal(main_replica_self_4440,
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
                    main_replica_self_4440["leader_timeout"] EXCEPT
                      ![main_replica_cert_view_num] = main_replica_None
                  ]
            ] EXCEPT
              !["certification_timeout"] =
                [
                  main_replica_self_4440["certification_timeout"] EXCEPT
                    ![main_replica_cert_view_num] = main_replica_None
                ]
          ] EXCEPT
            !["ghost_last_seen_notarization"] = main_replica_seen_notarization
        ] EXCEPT
          !["certified"] =
            LET (*
              @type: (() => (Int -> None({ tag: Str }) | Some(Bool)));
            *)
            __quint_var6 == main_replica_self_4440["certified"]
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
    next_sent_nullify |-> main_replica_sent_nullify_votes_4440,
    next_sent_finalize |->
      main_replica_sent_finalize_votes_4440
        \union {[proposal |-> main_replica_cert_prop,
          sig |-> main_replica_sig_of(main_replica_id_4440)]},
    next_stored_nullify |-> main_replica_stored_nullify_4440,
    next_stored_finalize |->
      main_replica_stored_finalize_4440
        \union {[proposal |-> main_replica_cert_prop,
          sig |-> main_replica_sig_of(main_replica_id_4440)]}]
  ELSE IF main_replica_is_certified
  THEN [next_self |->
      main_replica_enter_view([
        [
          [
            [
              (main_replica_observed) EXCEPT
                !["leader_timeout"] =
                  [
                    main_replica_self_4440["leader_timeout"] EXCEPT
                      ![main_replica_cert_view_num] = main_replica_None
                  ]
            ] EXCEPT
              !["certification_timeout"] =
                [
                  main_replica_self_4440["certification_timeout"] EXCEPT
                    ![main_replica_cert_view_num] = main_replica_None
                ]
          ] EXCEPT
            !["ghost_last_seen_notarization"] = main_replica_seen_notarization
        ] EXCEPT
          !["certified"] =
            LET (*
              @type: (() => (Int -> None({ tag: Str }) | Some(Bool)));
            *)
            __quint_var9 == main_replica_self_4440["certified"]
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
    next_sent_nullify |-> main_replica_sent_nullify_votes_4440,
    next_sent_finalize |-> main_replica_sent_finalize_votes_4440,
    next_stored_nullify |-> main_replica_stored_nullify_4440,
    next_stored_finalize |-> main_replica_stored_finalize_4440]
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
    next_sent_finalize |-> main_replica_sent_finalize_votes_4440,
    next_stored_nullify |-> (main_replica_timer)["next_stored_nullify"],
    next_stored_finalize |-> main_replica_stored_finalize_4440]
  ELSE [next_self |->
      [
        (main_replica_observed) EXCEPT
          !["ghost_last_seen_notarization"] = main_replica_seen_notarization
      ],
    next_sent_nullify |-> main_replica_sent_nullify_votes_4440,
    next_sent_finalize |-> main_replica_sent_finalize_votes_4440,
    next_stored_nullify |-> main_replica_stored_nullify_4440,
    next_stored_finalize |-> main_replica_stored_finalize_4440]

(*
  @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Seq({ parent: Int, payload: Str, view: Int }));
*)
main_replica_rebuild_committed_chain(main_replica_certificates_1423) ==
  LET (*
    @type: ((Seq({ parent: Int, payload: Str, view: Int }), Int) => Seq({ parent: Int, payload: Str, view: Int }));
  *)
  __QUINT_LAMBDA61(main_replica_chain_1421, main_replica__view_1421) ==
    main_replica_extend_committed_chain_once(main_replica_chain_1421, main_replica_certificates_1423)
  IN
  ApaFoldSet(__QUINT_LAMBDA61, <<>>, (main_replica_VIEWS))

(*
  @type: ((Str, { proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_on_notarize(main_replica_id_3490, main_replica_vote_3490) ==
  main_replica_vote_3490 \in main_replica_sent_notarize_votes
    /\ (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_notarize ==
      main_replica_store_notarize_votes[main_replica_id_3490]
    IN
    LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_3490]
    IN
    LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_finalize ==
      main_replica_store_finalize_votes[main_replica_id_3490]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3490]
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_3490]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal == main_replica_vote_3490["proposal"]
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_view == (main_replica_proposal)["view"]
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
      main_replica_vote_3490["sig"]
        = main_replica_sig_of(main_replica_leader[(main_replica_view)])
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
        /\ main_replica_view = (main_replica_self)["view"]
        /\ ~(main_replica_broadcast_notarize(main_replica_id_3490, (main_replica_self)[
          "view"
        ]))
        /\ ~(main_replica_broadcast_nullify(main_replica_id_3490, (main_replica_view)))
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
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_timer ==
      main_replica_forced_timeout_expired((main_replica_self), main_replica_id_3490,
      (main_replica_view), (main_replica_InvalidProposalReason), main_replica_sent_nullify_votes,
      main_replica_sent_finalize_votes, (main_replica_store_nullify))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_notarize_ok ==
      main_replica_is_some((main_replica_construct_notarize(main_replica_id_3490,
      (main_replica_self), (main_replica_view), (main_replica_proposal), (main_replica_payload_ok
        /\ main_replica_parent_ok))))
    IN
    LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_new_store_notarize_p ==
      IF main_replica_notarize_ok
      THEN main_replica_store_notarize
        \union { main_replica_vote_3490,
          [proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_3490)] }
      ELSE main_replica_store_notarize
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
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
    main_replica_maybe_not_cert_p ==
      IF main_replica_notarize_ok
      THEN main_replica_create_notarization(main_replica_id_3490, (main_replica_proposal),
      (main_replica_new_store_notarize_p))
      ELSE main_replica_None
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_not_p ==
      ~(main_replica_broadcast_notarization(main_replica_id_3490, (main_replica_view)))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect_p ==
      CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA38(main_replica_cert_3126) ==
            main_replica_notarize_effect((main_replica_proposal_self), main_replica_id_3490,
            main_replica_cert_3126, main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
            main_replica_store_nullify_votes[main_replica_id_3490], main_replica_store_finalize_votes[
              main_replica_id_3490
            ])
          IN
          __QUINT_LAMBDA38(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
        [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA39(main_replica___3129) ==
            [next_self |-> main_replica_proposal_self,
              next_sent_nullify |-> main_replica_sent_nullify_votes,
              next_sent_finalize |-> main_replica_sent_finalize_votes,
              next_stored_nullify |->
                main_replica_store_nullify_votes[main_replica_id_3490],
              next_stored_finalize |->
                main_replica_store_finalize_votes[main_replica_id_3490]]
          IN
          __QUINT_LAMBDA39(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p)))
    IN
    main_replica_sent_notarize_votes'
        := (IF main_replica_notarize_ok
        THEN main_replica_sent_notarize_votes
          \union {[proposal |-> main_replica_proposal,
            sig |-> main_replica_sig_of(main_replica_id_3490)]}
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
            ![main_replica_id_3490] = main_replica_new_store_notarize_p
        ]
      /\ main_replica_store_nullify_votes'
        := (IF main_replica_notarize_ok
        THEN [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3490] =
              (main_replica_effect_p)["next_stored_nullify"]
        ]
        ELSE [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3490] =
              (main_replica_timer)["next_stored_nullify"]
        ])
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_3490] =
              (main_replica_effect_p)["next_stored_finalize"]
        ]
      /\ main_replica_store_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA41(main_replica_cert_3205) ==
              LET (*
                @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
              *)
              __quint_var12 == main_replica_store_certificates
              IN
              [
                (__quint_var12) EXCEPT
                  ![main_replica_id_3490] =
                    LET (*
                      @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
                    *)
                    __QUINT_LAMBDA40(main_replica_old_3200) ==
                      main_replica_old_3200
                        \union {(main_replica_Notarization(main_replica_cert_3205))}
                    IN
                    __QUINT_LAMBDA40((__quint_var12)[main_replica_id_3490])
              ]
            IN
            __QUINT_LAMBDA41(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
          [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA42(main_replica___3208) ==
              main_replica_store_certificates
            IN
            __QUINT_LAMBDA42(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p))))
      /\ main_replica_sent_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert_p)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA43(main_replica_cert_3224) ==
              IF main_replica_should_broadcast_not_p
              THEN main_replica_sent_certificates
                \union {(main_replica_Notarization(main_replica_cert_3224))}
              ELSE main_replica_sent_certificates
            IN
            __QUINT_LAMBDA43(VariantGetUnsafe("Some", (main_replica_maybe_not_cert_p)))
          [] VariantTag((main_replica_maybe_not_cert_p)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA44(main_replica___3227) ==
              main_replica_sent_certificates
            IN
            __QUINT_LAMBDA44(VariantGetUnsafe("None", (main_replica_maybe_not_cert_p))))
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_3490] = (main_replica_effect_p)["next_self"]
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
      main_replica_store_notarize \union {main_replica_vote_3490}
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_had_notarization ==
      \E main_replica_c_3274 \in main_replica_certs:
        main_replica_is_notarization_cert(main_replica_c_3274)
          /\ main_replica_cert_proposal(main_replica_c_3274)
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
    main_replica_maybe_not_cert ==
      IF main_replica_had_notarization
      THEN main_replica_None
      ELSE main_replica_create_notarization(main_replica_id_3490, (main_replica_proposal),
      (main_replica_new_store_notarize))
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
      ~(main_replica_broadcast_notarization(main_replica_id_3490, (main_replica_view)))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect ==
      CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA45(main_replica_cert_3327) ==
            main_replica_notarize_effect((main_replica_self), main_replica_id_3490,
            main_replica_cert_3327, main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
            main_replica_store_nullify_votes[main_replica_id_3490], main_replica_store_finalize_votes[
              main_replica_id_3490
            ])
          IN
          __QUINT_LAMBDA45(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
        [] VariantTag((main_replica_maybe_not_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
          *)
          __QUINT_LAMBDA46(main_replica___3330) ==
            [next_self |-> main_replica_self,
              next_sent_nullify |-> main_replica_sent_nullify_votes,
              next_sent_finalize |-> main_replica_sent_finalize_votes,
              next_stored_nullify |->
                main_replica_store_nullify_votes[main_replica_id_3490],
              next_stored_finalize |->
                main_replica_store_finalize_votes[main_replica_id_3490]]
          IN
          __QUINT_LAMBDA46(VariantGetUnsafe("None", (main_replica_maybe_not_cert)))
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_can_self_notarize_agg ==
      main_replica_is_some((main_replica_maybe_not_cert))
        /\ ~(main_replica_broadcast_notarize(main_replica_id_3490, (main_replica_view)))
        /\ ~(main_replica_broadcast_nullify(main_replica_id_3490, (main_replica_view)))
    IN
    LET (*
      @type: (() => { proposal: { parent: Int, payload: Str, view: Int }, sig: Str });
    *)
    main_replica_self_vote_agg ==
      [proposal |-> main_replica_proposal,
        sig |-> main_replica_sig_of(main_replica_id_3490)]
    IN
    (main_replica_is_none((main_replica_maybe_not_cert))
        \/ main_replica_now_notarized)
      /\ main_replica_store_notarize_votes'
        := [
          main_replica_store_notarize_votes EXCEPT
            ![main_replica_id_3490] =
              IF main_replica_can_self_notarize_agg
              THEN main_replica_new_store_notarize
                \union {(main_replica_self_vote_agg)}
              ELSE main_replica_new_store_notarize
        ]
      /\ main_replica_store_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA48(main_replica_cert_3383) ==
              LET (*
                @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
              *)
              __quint_var13 == main_replica_store_certificates
              IN
              [
                (__quint_var13) EXCEPT
                  ![main_replica_id_3490] =
                    LET (*
                      @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
                    *)
                    __QUINT_LAMBDA47(main_replica_old_3378) ==
                      main_replica_old_3378
                        \union {(main_replica_Notarization(main_replica_cert_3383))}
                    IN
                    __QUINT_LAMBDA47((__quint_var13)[main_replica_id_3490])
              ]
            IN
            __QUINT_LAMBDA48(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
          [] VariantTag((main_replica_maybe_not_cert)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
            *)
            __QUINT_LAMBDA49(main_replica___3386) ==
              main_replica_store_certificates
            IN
            __QUINT_LAMBDA49(VariantGetUnsafe("None", (main_replica_maybe_not_cert))))
      /\ main_replica_sent_certificates'
        := (CASE VariantTag((main_replica_maybe_not_cert)) = "Some"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA50(main_replica_cert_3402) ==
              IF main_replica_should_broadcast_not
              THEN main_replica_sent_certificates
                \union {(main_replica_Notarization(main_replica_cert_3402))}
              ELSE main_replica_sent_certificates
            IN
            __QUINT_LAMBDA50(VariantGetUnsafe("Some", (main_replica_maybe_not_cert)))
          [] VariantTag((main_replica_maybe_not_cert)) = "None"
            -> LET (*
              @type: (({ tag: Str }) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
            *)
            __QUINT_LAMBDA51(main_replica___3405) ==
              main_replica_sent_certificates
            IN
            __QUINT_LAMBDA51(VariantGetUnsafe("None", (main_replica_maybe_not_cert))))
      /\ main_replica_sent_notarize_votes'
        := (IF main_replica_can_self_notarize_agg
        THEN main_replica_sent_notarize_votes
          \union {(main_replica_self_vote_agg)}
        ELSE main_replica_sent_notarize_votes)
      /\ main_replica_sent_nullify_votes'
        := (main_replica_effect)["next_sent_nullify"]
      /\ main_replica_sent_finalize_votes'
        := (main_replica_effect)["next_sent_finalize"]
      /\ main_replica_store_nullify_votes'
        := [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_3490] =
              (main_replica_effect)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_3490] =
              (main_replica_effect)["next_stored_finalize"]
        ]
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_3490] = (main_replica_effect)["next_self"]
        ]
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_notarize")

(*
  @type: ((Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Bool) => Bool);
*)
main_replica__add_finalization(main_replica_id_4853, main_replica_finalization_4853,
main_replica_is_new_cert_4853) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4853]
    IN
    LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Finalization(main_replica_finalization_4853)
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_finalization ==
      ~(main_replica_broadcast_finalization(main_replica_id_4853, main_replica_finalization_4853[
        "proposal"
      ][
        "view"
      ]))
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_cert_view_num ==
      main_replica_finalization_4853["proposal"]["view"]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_cert_prop == main_replica_finalization_4853["proposal"]
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
      IF main_replica_is_new_cert_4853
      THEN main_replica_store_certificates[main_replica_id_4853]
        \union {(main_replica_cert)}
      ELSE main_replica_store_certificates[main_replica_id_4853]
    IN
    Cardinality(main_replica_finalization_4853["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4853
        THEN [
          main_replica_store_certificates EXCEPT
            ![main_replica_id_4853] = main_replica_next_certs
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_finalization
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4853))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_ghost_committed_blocks'
        := (IF main_replica_is_new_cert_4853
        THEN [
          main_replica_ghost_committed_blocks EXCEPT
            ![main_replica_id_4853] =
              main_replica_rebuild_committed_chain((main_replica_next_certs))
        ]
        ELSE main_replica_ghost_committed_blocks)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_nullify_votes' := main_replica_sent_nullify_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4853] =
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
  @type: ((Str, { ghost_sender: Str, signatures: Set(Str), view: Int }, Bool, { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }) => Bool);
*)
main_replica__add_nullification(main_replica_id_4704, main_replica_nullification_4704,
main_replica_is_new_cert_4704, main_replica_base_self_4704) ==
  (LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Nullification(main_replica_nullification_4704)
    IN
    LET (*
      @type: (() => Int);
    *)
    main_replica_cert_view_num == main_replica_nullification_4704["view"]
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_nullification ==
      ~(main_replica_broadcast_nullification(main_replica_id_4704, (main_replica_cert_view_num)))
    IN
    LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_next_certs ==
      IF main_replica_is_new_cert_4704
      THEN main_replica_store_certificates[main_replica_id_4704]
        \union {(main_replica_cert)}
      ELSE main_replica_store_certificates[main_replica_id_4704]
    IN
    Cardinality(main_replica_nullification_4704["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4704
        THEN [
          main_replica_store_certificates EXCEPT
            ![main_replica_id_4704] = main_replica_next_certs
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_nullification
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4704))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_sent_notarize_votes' := main_replica_sent_notarize_votes
      /\ main_replica_sent_finalize_votes' := main_replica_sent_finalize_votes
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4704] =
              main_replica_enter_view((main_replica_cancel_all_timers(main_replica_base_self_4704,
              (main_replica_cert_view_num))), (main_replica_cert_view_num + 1))
        ]
      /\ main_replica_ghost_committed_blocks'
        := (IF main_replica_is_new_cert_4704
        THEN [
          main_replica_ghost_committed_blocks EXCEPT
            ![main_replica_id_4704] =
              main_replica_rebuild_committed_chain((main_replica_next_certs))
        ]
        ELSE main_replica_ghost_committed_blocks))

(*
  @type: ((Str, { ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }, Bool) => Bool);
*)
main_replica__add_notarization(main_replica_id_4607, main_replica_notarization_4607,
main_replica_is_new_cert_4607) ==
  (LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_4607]
    IN
    LET (*
      @type: (() => Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }));
    *)
    main_replica_cert ==
      main_replica_Notarization(main_replica_notarization_4607)
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_should_broadcast_notarization ==
      ~(main_replica_broadcast_notarization(main_replica_id_4607, main_replica_notarization_4607[
        "proposal"
      ][
        "view"
      ]))
    IN
    LET (*
      @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_finalize: Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }), next_stored_nullify: Set({ sig: Str, view: Int }) });
    *)
    main_replica_effect ==
      main_replica_notarize_effect((main_replica_self), main_replica_id_4607, main_replica_notarization_4607,
      main_replica_sent_nullify_votes, main_replica_sent_finalize_votes, main_replica_store_nullify_votes[
        main_replica_id_4607
      ], main_replica_store_finalize_votes[main_replica_id_4607])
    IN
    LET (*
      @type: (() => Bool);
    *)
    main_replica_can_self_notarize ==
      ~(main_replica_broadcast_notarize(main_replica_id_4607, main_replica_notarization_4607[
          "proposal"
        ][
          "view"
        ]))
        /\ ~(main_replica_broadcast_nullify(main_replica_id_4607, main_replica_notarization_4607[
          "proposal"
        ][
          "view"
        ]))
    IN
    LET (*
      @type: (() => { proposal: { parent: Int, payload: Str, view: Int }, sig: Str });
    *)
    main_replica_self_vote ==
      [proposal |-> main_replica_notarization_4607["proposal"],
        sig |-> main_replica_sig_of(main_replica_id_4607)]
    IN
    Cardinality(main_replica_notarization_4607["signatures"]) >= main_replica_Q
      /\ main_replica_store_certificates'
        := (IF main_replica_is_new_cert_4607
        THEN LET (*
          @type: (() => (Str -> Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))));
        *)
        __quint_var15 == main_replica_store_certificates
        IN
        [
          (__quint_var15) EXCEPT
            ![main_replica_id_4607] =
              LET (*
                @type: ((Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int }))) => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
              *)
              __QUINT_LAMBDA78(main_replica_old_4521) ==
                main_replica_old_4521 \union {(main_replica_cert)}
              IN
              __QUINT_LAMBDA78((__quint_var15)[main_replica_id_4607])
        ]
        ELSE main_replica_store_certificates)
      /\ main_replica_sent_certificates'
        := (IF main_replica_should_broadcast_notarization
        THEN main_replica_sent_certificates
          \union {(main_replica_cert_with_sender((main_replica_cert), (main_replica_sig_of(main_replica_id_4607))))}
        ELSE main_replica_sent_certificates)
      /\ main_replica_sent_notarize_votes'
        := (IF main_replica_can_self_notarize
        THEN main_replica_sent_notarize_votes \union {(main_replica_self_vote)}
        ELSE main_replica_sent_notarize_votes)
      /\ main_replica_sent_nullify_votes'
        := (main_replica_effect)["next_sent_nullify"]
      /\ main_replica_sent_finalize_votes'
        := (main_replica_effect)["next_sent_finalize"]
      /\ main_replica_store_notarize_votes'
        := (IF main_replica_can_self_notarize
        THEN LET (*
          @type: (() => (Str -> Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })));
        *)
        __quint_var16 == main_replica_store_notarize_votes
        IN
        [
          (__quint_var16) EXCEPT
            ![main_replica_id_4607] =
              LET (*
                @type: ((Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str })) => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
              *)
              __QUINT_LAMBDA79(main_replica_old_4566) ==
                main_replica_old_4566 \union {(main_replica_self_vote)}
              IN
              __QUINT_LAMBDA79((__quint_var16)[main_replica_id_4607])
        ]
        ELSE main_replica_store_notarize_votes)
      /\ main_replica_store_nullify_votes'
        := [
          main_replica_store_nullify_votes EXCEPT
            ![main_replica_id_4607] =
              (main_replica_effect)["next_stored_nullify"]
        ]
      /\ main_replica_store_finalize_votes'
        := [
          main_replica_store_finalize_votes EXCEPT
            ![main_replica_id_4607] =
              (main_replica_effect)["next_stored_finalize"]
        ]
      /\ main_replica_replica_state'
        := [
          main_replica_replica_state EXCEPT
            ![main_replica_id_4607] = (main_replica_effect)["next_self"]
        ]
      /\ main_replica_ghost_committed_blocks'
        := main_replica_ghost_committed_blocks)

(*
  @type: ((Str, { proposal: { parent: Int, payload: Str, view: Int }, sig: Str }) => Bool);
*)
main_replica_on_finalize(main_replica_id_3646, main_replica_vote_3646) ==
  main_replica_vote_3646 \in main_replica_sent_finalize_votes
    /\ (LET (*
      @type: (() => Set({ proposal: { parent: Int, payload: Str, view: Int }, sig: Str }));
    *)
    main_replica_store_finalize ==
      main_replica_store_finalize_votes[main_replica_id_3646]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3646]
    IN
    LET (*
      @type: (() => { parent: Int, payload: Str, view: Int });
    *)
    main_replica_proposal == main_replica_vote_3646["proposal"]
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
        main_replica_store_finalize \union {main_replica_vote_3646}
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }));
      *)
      main_replica_maybe_fin_cert ==
        IF main_replica_conflict
        THEN main_replica_None
        ELSE main_replica_create_finalization(main_replica_id_3646, (main_replica_proposal),
        (main_replica_new_store_finalize))
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_is_new_cert ==
        ~(\E main_replica_c_3559 \in main_replica_store_certificates[
          main_replica_id_3646
        ]:
          main_replica_is_finalization_cert(main_replica_c_3559)
            /\ main_replica_cert_proposal(main_replica_c_3559)
              = main_replica_Some((main_replica_proposal)))
      IN
      CASE VariantTag((main_replica_maybe_fin_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA62(main_replica_cert_3623) ==
            main_replica_store_finalize_votes'
                := (IF main_replica_conflict
                THEN main_replica_store_finalize_votes
                ELSE [
                  main_replica_store_finalize_votes EXCEPT
                    ![main_replica_id_3646] = main_replica_new_store_finalize
                ])
              /\ main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica__add_finalization(main_replica_id_3646, main_replica_cert_3623,
              (main_replica_is_new_cert))
          IN
          __QUINT_LAMBDA62(VariantGetUnsafe("Some", (main_replica_maybe_fin_cert)))
        [] VariantTag((main_replica_maybe_fin_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => Bool);
          *)
          __QUINT_LAMBDA63(main_replica___3626) ==
            main_replica_store_finalize_votes'
                := (IF main_replica_conflict
                THEN main_replica_store_finalize_votes
                ELSE [
                  main_replica_store_finalize_votes EXCEPT
                    ![main_replica_id_3646] = main_replica_new_store_finalize
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
main_replica_on_nullify(main_replica_id_3856, main_replica_vote_3856) ==
  main_replica_vote_3856 \in main_replica_sent_nullify_votes
    /\ (LET (*
      @type: (() => Set({ sig: Str, view: Int }));
    *)
    main_replica_store_nullify ==
      main_replica_store_nullify_votes[main_replica_id_3856]
    IN
    LET (*
      @type: (() => { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int });
    *)
    main_replica_self == main_replica_replica_state[main_replica_id_3856]
    IN
    main_replica_vote_3856["view"]
        >= (main_replica_self)["last_finalized"] - main_replica_ACTIVITY_TIMEOUT
      /\ main_replica_vote_3856["view"] <= (main_replica_self)["view"] + 1
      /\ (LET (*
        @type: (() => Set({ sig: Str, view: Int }));
      *)
      main_replica_new_nullify_votes ==
        main_replica_store_nullify \union {main_replica_vote_3856}
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_leader_nullify_trigger ==
        main_replica_id_3856
            /= main_replica_leader[main_replica_vote_3856["view"]]
          /\ ~(main_replica_broadcast_nullify(main_replica_id_3856, main_replica_vote_3856[
            "view"
          ]))
          /\ main_replica_vote_3856["sig"]
            = main_replica_sig_of(main_replica_leader[
              main_replica_vote_3856["view"]
            ])
      IN
      LET (*
        @type: (() => { next_self: { certification_timeout: (Int -> None({ tag: Str }) | Some(Bool)), certified: (Int -> None({ tag: Str }) | Some(Bool)), ghost_last_seen_notarization: Int, last_finalized: Int, leader_proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), leader_proposal_conflicted: (Int -> Bool), leader_timeout: (Int -> None({ tag: Str }) | Some(Bool)), locally_built: (Int -> Bool), proposal: (Int -> None({ tag: Str }) | Some({ parent: Int, payload: Str, view: Int })), view: Int }, next_sent_nullify: Set({ sig: Str, view: Int }), next_stored_nullify: Set({ sig: Str, view: Int }) });
      *)
      main_replica_timer ==
        IF main_replica_leader_nullify_trigger
        THEN main_replica_leader_nullify_expired((main_replica_self), main_replica_id_3856,
        main_replica_vote_3856["view"], main_replica_sent_nullify_votes, main_replica_sent_finalize_votes,
        (main_replica_new_nullify_votes))
        ELSE [next_self |-> main_replica_self,
          next_sent_nullify |-> main_replica_sent_nullify_votes,
          next_stored_nullify |-> main_replica_new_nullify_votes]
      IN
      LET (*
        @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
      *)
      main_replica_certs ==
        main_replica_store_certificates[main_replica_id_3856]
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_had_nullification ==
        \E main_replica_c_3746 \in main_replica_certs:
          main_replica_is_nullification_cert(main_replica_c_3746)
            /\ main_replica_cert_view(main_replica_c_3746)
              = main_replica_vote_3856["view"]
      IN
      LET (*
        @type: (() => None({ tag: Str }) | Some({ ghost_sender: Str, signatures: Set(Str), view: Int }));
      *)
      main_replica_maybe_null_cert ==
        main_replica_create_nullification(main_replica_id_3856, main_replica_vote_3856[
          "view"
        ], (main_replica_timer)["next_stored_nullify"])
      IN
      CASE VariantTag((main_replica_maybe_null_cert)) = "Some"
          -> LET (*
            @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
          *)
          __QUINT_LAMBDA64(main_replica_cert_3832) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := [
                  main_replica_store_nullify_votes EXCEPT
                    ![main_replica_id_3856] =
                      (main_replica_timer)["next_stored_nullify"]
                ]
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_sent_nullify_votes'
                := (main_replica_timer)["next_sent_nullify"]
              /\ main_replica__add_nullification(main_replica_id_3856, main_replica_cert_3832,
              (~main_replica_had_nullification), (main_replica_timer)[
                "next_self"
              ])
          IN
          __QUINT_LAMBDA64(VariantGetUnsafe("Some", (main_replica_maybe_null_cert)))
        [] VariantTag((main_replica_maybe_null_cert)) = "None"
          -> LET (*
            @type: (({ tag: Str }) => Bool);
          *)
          __QUINT_LAMBDA65(main_replica___3835) ==
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
                    ![main_replica_id_3856] =
                      (main_replica_timer)["next_stored_nullify"]
                ]
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_replica_state'
                := [
                  main_replica_replica_state EXCEPT
                    ![main_replica_id_3856] = (main_replica_timer)["next_self"]
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
main_replica_on_certificate(main_replica_id_4145, main_replica_cert_4145) ==
  (LET (*
      @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
    *)
    main_replica_certs == main_replica_store_certificates[main_replica_id_4145]
    IN
    main_replica_cert_4145 \in main_replica_sent_certificates
      /\ Cardinality((main_replica_cert_signatures(main_replica_cert_4145)))
        >= main_replica_Q
      /\ (LET (*
        @type: (() => Bool);
      *)
      main_replica_duplicate ==
        \E main_replica_existing_4034 \in main_replica_certs:
          main_replica_same_certificate_subject(main_replica_existing_4034, main_replica_cert_4145)
      IN
      LET (*
        @type: (() => Bool);
      *)
      main_replica_seen_kind_and_view ==
        \E main_replica_existing_4042 \in main_replica_certs:
          main_replica_same_certificate_kind_and_view(main_replica_existing_4042,
          main_replica_cert_4145)
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
      ELSE CASE VariantTag(main_replica_cert_4145) = "Notarization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA80(main_replica_n_4122) ==
            main_replica__add_notarization(main_replica_id_4145, main_replica_n_4122,
              (~main_replica_seen_kind_and_view))
          IN
          __QUINT_LAMBDA80(VariantGetUnsafe("Notarization", main_replica_cert_4145))
        [] VariantTag(main_replica_cert_4145) = "Nullification"
          -> LET (*
            @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
          *)
          __QUINT_LAMBDA81(main_replica_n_4125) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica_sent_nullify_votes'
                := main_replica_sent_nullify_votes
              /\ main_replica__add_nullification(main_replica_id_4145, main_replica_n_4125,
              (~main_replica_seen_kind_and_view), main_replica_replica_state[
                main_replica_id_4145
              ])
          IN
          __QUINT_LAMBDA81(VariantGetUnsafe("Nullification", main_replica_cert_4145))
        [] VariantTag(main_replica_cert_4145) = "Finalization"
          -> LET (*
            @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
          *)
          __QUINT_LAMBDA82(main_replica_f_4128) ==
            main_replica_store_notarize_votes'
                := main_replica_store_notarize_votes
              /\ main_replica_store_nullify_votes'
                := main_replica_store_nullify_votes
              /\ main_replica_store_finalize_votes'
                := main_replica_store_finalize_votes
              /\ main_replica__add_finalization(main_replica_id_4145, main_replica_f_4128,
              (~main_replica_seen_kind_and_view))
          IN
          __QUINT_LAMBDA82(VariantGetUnsafe("Finalization", main_replica_cert_4145)))
      /\ main_replica_leader' := main_replica_leader
      /\ main_replica_certify_policy' := main_replica_certify_policy
      /\ main_replica_lastAction' := "on_certificate")

(*
  @type: ((Str, Int, Int, Str, Str) => Bool);
*)
main_replica_on_notarization_cert(main_replica_id_3912, main_replica_cert_view_3912,
main_replica_cert_parent_3912, main_replica_cert_payload_3912, main_replica_cert_sender_3912) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_proposal_3911 ==
    [view |-> main_replica_cert_view_3912,
      parent |-> main_replica_cert_parent_3912,
      payload |-> main_replica_cert_payload_3912]
  IN
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3900 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3900) = "Notarization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA83(main_replica_n_3895) ==
              main_replica_n_3895["proposal"] = main_replica_cert_proposal_3911
                /\ main_replica_n_3895["ghost_sender"]
                  = main_replica_cert_sender_3912
            IN
            __QUINT_LAMBDA83(VariantGetUnsafe("Notarization", main_replica_c_3900))
          [] OTHER
            -> (LET (*
              @type: ((o) => Bool);
            *)
            __QUINT_LAMBDA84(main_replica___3898) == FALSE
            IN
            __QUINT_LAMBDA84({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_3912, main_replica_cert)

(*
  @type: ((Str, Int, Int, Str, Str) => Bool);
*)
main_replica_on_finalization_cert(main_replica_id_3968, main_replica_cert_view_3968,
main_replica_cert_parent_3968, main_replica_cert_payload_3968, main_replica_cert_sender_3968) ==
  LET (*
    @type: (() => { parent: Int, payload: Str, view: Int });
  *)
  main_replica_cert_proposal_3967 ==
    [view |-> main_replica_cert_view_3968,
      parent |-> main_replica_cert_parent_3968,
      payload |-> main_replica_cert_payload_3968]
  IN
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3956 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3956) = "Finalization"
            -> LET (*
              @type: (({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) => Bool);
            *)
            __QUINT_LAMBDA85(main_replica_f_3951) ==
              main_replica_f_3951["proposal"] = main_replica_cert_proposal_3967
                /\ main_replica_f_3951["ghost_sender"]
                  = main_replica_cert_sender_3968
            IN
            __QUINT_LAMBDA85(VariantGetUnsafe("Finalization", main_replica_c_3956))
          [] OTHER
            -> (LET (*
              @type: ((p) => Bool);
            *)
            __QUINT_LAMBDA86(main_replica___3954) == FALSE
            IN
            __QUINT_LAMBDA86({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_3968, main_replica_cert)

(*
  @type: ((Str, Int, Str) => Bool);
*)
main_replica_on_nullification_cert(main_replica_id_4010, main_replica_cert_view_4010,
main_replica_cert_sender_4010) ==
  LET (*
    @type: (() => Set(Finalization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Notarization({ ghost_sender: Str, proposal: { parent: Int, payload: Str, view: Int }, signatures: Set(Str) }) | Nullification({ ghost_sender: Str, signatures: Set(Str), view: Int })));
  *)
  main_replica_matching ==
    {
      main_replica_c_3999 \in main_replica_sent_certificates:
        CASE VariantTag(main_replica_c_3999) = "Nullification"
            -> LET (*
              @type: (({ ghost_sender: Str, signatures: Set(Str), view: Int }) => Bool);
            *)
            __QUINT_LAMBDA87(main_replica_n_3994) ==
              main_replica_n_3994["view"] = main_replica_cert_view_4010
                /\ main_replica_n_3994["ghost_sender"]
                  = main_replica_cert_sender_4010
            IN
            __QUINT_LAMBDA87(VariantGetUnsafe("Nullification", main_replica_c_3999))
          [] OTHER
            -> (LET (*
              @type: ((q) => Bool);
            *)
            __QUINT_LAMBDA88(main_replica___3997) == FALSE
            IN
            __QUINT_LAMBDA88({}))
    }
  IN
  \E main_replica_cert \in main_replica_matching:
    main_replica_on_certificate(main_replica_id_4010, main_replica_cert)

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
                main_replica_sig_of(main_replica_r_2346):
                  main_replica_r_2346 \in main_replica_Replicas
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
                main_replica_sig_of(main_replica_r_2388):
                  main_replica_r_2388 \in main_replica_Replicas
              }:
                main_replica_on_finalize(main_replica_id, [proposal |->
                    [view |-> main_replica_vote_view,
                      parent |-> main_replica_vote_parent,
                      payload |-> main_replica_vote_payload],
                  sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_vote_view \in main_replica_VIEWS:
          \E main_replica_vote_sig \in {
            main_replica_sig_of(main_replica_r_2421):
              main_replica_r_2421 \in main_replica_Replicas
          }:
            main_replica_on_nullify(main_replica_id, [view |->
                main_replica_vote_view,
              sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2468 \in main_replica_VIEWS:
          \E main_replica_cert_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_cert_payload_2466 \in main_replica_VALID_PAYLOADS:
              \E main_replica_cert_sender \in {
                main_replica_sig_of(main_replica_r_2455):
                  main_replica_r_2455 \in main_replica_Replicas
              }:
                main_replica_on_notarization_cert(main_replica_id, main_replica_cert_view_2468,
                main_replica_cert_parent, main_replica_cert_payload_2466, main_replica_cert_sender)))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2503 \in main_replica_VIEWS:
          \E main_replica_cert_parent \in main_replica_VIEWS
            \union {(main_replica_GENESIS_VIEW)}:
            \E main_replica_cert_payload_2501 \in main_replica_VALID_PAYLOADS:
              \E main_replica_cert_sender \in {
                main_replica_sig_of(main_replica_r_2490):
                  main_replica_r_2490 \in main_replica_Replicas
              }:
                main_replica_on_finalization_cert(main_replica_id, main_replica_cert_view_2503,
                main_replica_cert_parent, main_replica_cert_payload_2501, main_replica_cert_sender)))
    \/ ((\E main_replica_id \in main_replica_CORRECT:
        \E main_replica_cert_view_2525 \in main_replica_VIEWS:
          \E main_replica_cert_sender \in {
            main_replica_sig_of(main_replica_r_2516):
              main_replica_r_2516 \in main_replica_Replicas
          }:
            main_replica_on_nullification_cert(main_replica_id, main_replica_cert_view_2525,
            main_replica_cert_sender)))
    \/ ((\E main_replica_vote_view \in main_replica_VIEWS:
        \E main_replica_vote_parent \in main_replica_VIEWS
          \union {(main_replica_GENESIS_VIEW)}:
          \E main_replica_vote_payload \in main_replica_VALID_PAYLOADS:
            \E main_replica_vote_sig \in {
              main_replica_sig_of(main_replica_r_2544):
                main_replica_r_2544 \in main_replica_Replicas
            }:
              main_replica_send_notarize_vote([proposal |->
                  [view |-> main_replica_vote_view,
                    parent |-> main_replica_vote_parent,
                    payload |-> main_replica_vote_payload],
                sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_vote_view \in main_replica_VIEWS:
        \E main_replica_vote_parent \in main_replica_VIEWS
          \union {(main_replica_GENESIS_VIEW)}:
          \E main_replica_vote_payload \in main_replica_VALID_PAYLOADS:
            \E main_replica_vote_sig \in {
              main_replica_sig_of(main_replica_r_2581):
                main_replica_r_2581 \in main_replica_Replicas
            }:
              main_replica_send_finalize_vote([proposal |->
                  [view |-> main_replica_vote_view,
                    parent |-> main_replica_vote_parent,
                    payload |-> main_replica_vote_payload],
                sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_vote_view \in main_replica_VIEWS:
        \E main_replica_vote_sig \in {
          main_replica_sig_of(main_replica_r_2609):
            main_replica_r_2609 \in main_replica_Replicas
        }:
          main_replica_send_nullify_vote([view |-> main_replica_vote_view,
            sig |-> main_replica_vote_sig])))
    \/ ((\E main_replica_cert_view_2656 \in main_replica_VIEWS:
        \E main_replica_cert_parent \in main_replica_VIEWS
          \union {(main_replica_GENESIS_VIEW)}:
          \E main_replica_cert_payload_2654 \in main_replica_VALID_PAYLOADS:
            \E main_replica_ghost_sender \in {
              main_replica_sig_of(main_replica_r_2638):
                main_replica_r_2638 \in main_replica_Replicas
            }:
              \E main_replica_signers \in SUBSET main_replica_CorrectSigs:
                main_replica_send_notarization_cert(main_replica_cert_view_2656,
                main_replica_cert_parent, main_replica_cert_payload_2654, main_replica_ghost_sender,
                main_replica_signers)))
    \/ ((\E main_replica_cert_view_2692 \in main_replica_VIEWS:
        \E main_replica_cert_parent \in main_replica_VIEWS
          \union {(main_replica_GENESIS_VIEW)}:
          \E main_replica_cert_payload_2690 \in main_replica_VALID_PAYLOADS:
            \E main_replica_ghost_sender \in {
              main_replica_sig_of(main_replica_r_2674):
                main_replica_r_2674 \in main_replica_Replicas
            }:
              \E main_replica_signers \in SUBSET main_replica_CorrectSigs:
                main_replica_send_finalization_cert(main_replica_cert_view_2692,
                main_replica_cert_parent, main_replica_cert_payload_2690, main_replica_ghost_sender,
                main_replica_signers)))
    \/ ((\E main_replica_cert_view_2715 \in main_replica_VIEWS:
        \E main_replica_ghost_sender \in {
          main_replica_sig_of(main_replica_r_2701):
            main_replica_r_2701 \in main_replica_Replicas
        }:
          \E main_replica_signers \in SUBSET main_replica_CorrectSigs:
            main_replica_send_nullification_cert(main_replica_cert_view_2715, main_replica_ghost_sender,
            main_replica_signers)))

(*
  @type: (() => Bool);
*)
q_step == main_replica_step

================================================================================
