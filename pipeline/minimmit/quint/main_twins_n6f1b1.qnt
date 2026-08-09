// -*- mode: Bluespec; -*-

/// An exploratory configuration implementing the basic Twins testing approach.
///
/// The protocol is configured with N = 6 logical replicas and F = 1, so it is designed
/// to tolerate at most one Byzantine replica. Five logical replicas are represented by
/// a single correct process each. The sixth logical replica, n5, is represented by two
/// independent twins, n5_1 and n5_2, which share the same replica key ("n5").
///
/// The twins are both placed in CORRECT and BYZANTINE is intentionally empty. Byzantine
/// behavior is modeled by allowing the two independent twins to act under the same logical
/// identity, which can produce equivocation and other Byzantine behavior without using the
/// explicit Byzantine actions of the base model.
///
/// Consequently, N remains 6 even though CORRECT contains 7 modeled processes:
/// 5 ordinary replicas + 2 twins representing a single logical replica.
///
/// This is a valid adversarial configuration within the F = 1 fault assumption and is
/// intended for safety analysis, invariant checking, and counterexample exploration.
module twins {
  import replica(
    CORRECT = Set("n0", "n1", "n2", "n3", "n4", "n5_1", "n5_2"),
    REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5_1"->"n5", "n5_2"->"n5"),
    BYZANTINE = Set(),
    N = 6,
    F = 1,
    VALID_BLOCKS = Set("val_b0", "val_b1", "val_b2"),
    INVALID_BLOCKS = Set("inval_0", "inval_1"),
    VIEWS = 0.to(6),
  ) as i from "./replica"

  action init = all {
    i::initWithLeader(Map(0 -> "n5_1", 1 -> "n5_2", 2 -> "n0", 3 -> "n5_1", 4 -> "n5_2", 5 -> "n1", 6 -> "n2")),
            
    assert(i::N + 1 == i::CORRECT.size()),
    assert(i::BYZANTINE.size()==0)
  }
  
  action step = i::correct_step

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
  val certificates_are_backed = i::certificates_are_backed
  val committed_blocks_are_finalized = i::committed_blocks_are_finalized
  val committed_chain_is_connected = i::committed_chain_is_connected
  val no_nullification_and_finalization_globally = i::no_nullification_and_finalization_globally
}