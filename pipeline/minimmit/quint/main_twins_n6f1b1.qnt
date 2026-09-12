// -*- mode: Bluespec; -*-

/// An exploratory configuration implementing the basic Twins testing approach.
///
/// The protocol is configured with N = 6 logical replicas and F = 1, so it is designed
/// to tolerate at most one Byzantine replica. Five logical replicas are represented by
/// a single correct process each. The sixth logical replica, n5, is represented by two
/// independent twins, n5_1 and n5_2, which share the same replica key ("n5").
///
/// The twins are placed in REPLICA_IDS and TWINS, and BYZANTINE is intentionally empty.
/// Byzantine behavior is modeled by letting the two independent twins act under the same
/// faulty logical identity, which can produce equivocation and other Byzantine behavior
/// without using the explicit Byzantine actions of the base model.
///
/// Consequently, N remains 6 even though REPLICA_IDS contains 7 modeled processes:
/// 5 ordinary replicas + 2 twins representing a single logical replica. Quorums are
/// counted over KEYS, so the twin pair contributes exactly one signature.
module twins {
  import replica(
    N = 6,
    F = 1,
    REPLICA_IDS = Set("n0", "n1", "n2", "n3", "n4", "n5_1", "n5_2"),
    // Only the five single-process replicas are honest; the twins are the faulty logical replica.
    CORRECT = Set("n0", "n1", "n2", "n3", "n4"),
    TWINS = Set("n5_1", "n5_2"),
    // The explicit byzantine actions are unused here: the twins provide the faulty behaviour.
    BYZANTINE = Set(),
    REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", "n2"->"n2", "n3"->"n3", "n4" -> "n4", "n5_1"->"n5", "n5_2"->"n5"),
    VALID_BLOCK_IDS = Set("val_b0", "val_b1", "val_b2"),
    INVALID_BLOCK_IDS = Set("inval_0", "inval_1"),
    VIEWS = 0.to(6),
  ) as i from "./replica"

  action init = all {
    // The leader map must be total over VIEWS = 0..6; a missing entry would make
    // `leader.get(v)` an out-of-domain lookup as soon as a replica reached that view.
    i::initWithLeader(Map(0 -> "n5_1", 1 -> "n5_2", 2 -> "n0", 3 -> "n5_1", 4 -> "n5_2", 5 -> "n1", 6 -> "n2")),

    // 7 modeled processes for 6 logical replicas: one logical replica is a twin pair.
    assert(i::N + 1 == i::REPLICA_IDS.size()),
    assert(i::assumptions_valid),
    assert(i::BYZANTINE.size() == 0)
  }

  // `correct_step`, not `correct_replica_step`: the latter excludes `proposer_step`, so using it
  // here would make the whole configuration vacuous - no proposal could ever be sent.
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
}
