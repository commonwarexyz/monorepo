// -*- mode: Bluespec; -*-

// This is an explorative module applying the basic Twins style test
// to model byzantine behaviour with 1 faulty replicas and 5 correct replicas.
module twins {
  import automaton(
    CERTIFY_DOMAIN = Set("val_b0", "val_b1", "val_b2", "inval_0", "inval_1"),
  ) as app from "./automaton"

  // A specification instance for n=4, f=1 with 3 correct replicas and 1 byzantine replica.
  import replica(
    CORRECT = Set("n0", "n1", "n2", "n3_1", "n3_2"),
    REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3_1"->"n3", "n3_2"->"n3"),
    // Faulty set must be empty in this case
    BYZANTINE = Set(),
    N = 4,
    F = 1,
    Q = 3,
    VALID_PAYLOADS = Set("val_b0", "val_b1", "val_b2"),
    INVALID_PAYLOADS = Set("inval_0", "inval_1"),
    VIEWS = 1.to(6),
    ACTIVITY_TIMEOUT = 10,
  ) as i from "./replica"

  pure val CERTIFY_ALL_TRUE = i::Replicas.mapBy(_ => app::certify_always_true)

  action init = all {
    i::initWithLeaderAndCertify(
      Map(0 -> "n3_1", 1 -> "n3_2", 2 -> "n0", 3 -> "n3_1", 4 -> "n3_2", 5 -> "n1", 6 -> "n1"),
      CERTIFY_ALL_TRUE
    ),

    // 2 replicas from the CORRECT set have twins that makes them byzantine
    assert(i::N + 1 == i::CORRECT.size()),
    assert(i::BYZANTINE.size()==0)
  }


  action step = i::correct_replica_step

  val safe_invariants = i::safe_invariants
  val test_invariants = i::test_invariants
  val no_notarize_equivocation = i::no_notarize_equivocation
  val agreement = i::agreement
  val no_vote_equivocation_inv = i::no_vote_equivocation_inv
  val no_nullification_and_finalization_in_the_same_view = i::no_nullification_and_finalization_in_the_same_view
  val validity = i::validity
  val valid_last_finalized = i::valid_last_finalized
  val notarized_consistency = i::notarized_consistency
  val unique_notarized_or_finalized_payload_per_view = i::unique_notarized_or_finalized_payload_per_view
  val finalize_vote_requires_notarization_cert = i::finalize_vote_requires_notarization_cert
  val finalized_views_have_unique_proposal = i::finalized_views_have_unique_proposal
  val finalized_certificates_are_committed = i::finalized_certificates_are_committed
  val committed_blocks_no_duplicates = i::committed_blocks_no_duplicates
  val certificates_require_sent_votes = i::certificates_require_sent_votes
}
