# Consensus

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. Two conflicting blocks are finalized, because the application commits
   irreversible state on two incompatible histories and the protocol has no way
   to undo it.
2. Consensus halts indefinitely, because user transactions never settle and
   recovery requires manual operator intervention.
3. An honest validator is reported as faulty in the vote evidence exported by
   consensus, because the slashing system takes its stake for misbehavior it
   did not commit and removes it from the committee, which also shrinks the
   honest majority the protocol depends on.
4. A Byzantine validator's equivocation is not reported in the evidence
   exported by consensus, because it keeps its stake and committee seat, can
   repeat the attack at no cost, and the economic deterrent the fault budget
   `f` implicitly relies on disappears.
5. An honest validator crashes while processing a peer message, because the
   same message can crash every honest validator that receives it, so more than
   `f` validators are down at once and consensus halts until operators restart
   them.
6. An honest validator's memory or CPU is exhausted by peer traffic, because
   the attacker can do the same to more than `f` honest validators for the
   price of bandwidth, so they fall behind the current view and consensus
   stalls.
7. An honest validator is blocked by its peers, because its votes no longer
   reach the nodes that blocked it, they stop counting toward quorum there, and
   it is treated as faulty until the block expires after the configured
   `block_duration` (hours by default) or the blocking peers restart.
8. A notarized block treated as speculatively final is later excluded from the
   chain, because applications that acted on two-hop finality have already
   released goods, revealed outcomes, or sent cross-chain messages, and that
   exposure becomes a double-spend. The simplex documentation states when
   exclusion is possible, including a Byzantine leader that revokes its own
   notarized proposal ("Optimistic Finality" in
   `consensus/src/simplex/mod.rs`); only exclusion outside those conditions
   is a defect.
9. A Byzantine participant learns the round randomness or next leader before
   the round resolves, because it can front-run lotteries, timelocked data, and
   leader-dependent ordering, and steer leader selection toward itself over
   many rounds.
10. The application receives finalized blocks out of order or with a missing
    height, because it executes a block against the wrong parent state, its
    state diverges from every other node, and the divergence is discovered only
    when it later disagrees on a state root.
