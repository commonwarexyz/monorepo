// -*- mode: Bluespec; -*-

// This is an explorative module applying the basic Twins style test 
// to model byzantine behaviour with 1 faulty replicas and 5 correct replicas.
module twins {
  // A specification instance for n=6, f=1 with 5 correct replicas and 1 byzantine replica.
  import replica(
    CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5_1", "n5_2"),
    REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5_1"->"n5", "n5_2"->"n5"),
    // Faulty set must be empty in this case
    BYZANTINE = Set(),
    N = 6,
    F = 1,
    VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
    INVALID_BLOCKS = Set("inval_0", "inval_1"),
    VIEWS = 0.to(6),
  ) as i from "./replica"

  action init = all {
    i::initWithLeader(Map(0 -> "n5_1", 1 -> "n5_2", 2 -> "n0", 3 -> "n5_1", 4 -> "n5_2", 5 -> "n1")),
            
    // 2 replicas from the CORRECT set have twins that makes them byzantine
    assert(i::N + 1 == i::CORRECT.size()),
    assert(i::BYZANTINE.size()==0)
  }


  action step = i::correct_replica_step

  val safe = i::safe
  val all_invariants = safe
  val no_proposal_equivocation = i::no_proposal_equivocation
  val agreement = i::agreement
  val no_vote_equivocation_inv = i::no_vote_equivocation_inv
  val no_nullification_and_finalization_in_the_same_view = i::no_nullification_and_finalization_in_the_same_view
  val validity = i::validity
  val valid_last_finalized = i::valid_last_finalized
  val certificates_are_valid_inv = i::certificates_are_valid_inv
  val notarized_consistency = i::notarized_consistency
  val safe_finalization = i::safe_finalization
}