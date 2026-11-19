# Glue

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

## dkg

1. An epoch's reshare ceremony fails and the next epoch keeps the previous
   threshold output, because the validators the application selected never
   receive shares, operators who left the committee keep shares that still sign
   for any round, and shares leaked earlier are never refreshed.
2. An epoch's threshold output is installed with more than `f` of its players'
   shares published in finalized dealer logs, because a Byzantine coalition can
   then complete threshold signatures without an honest quorum and forge the
   certificates that consensus, state sync, and the probe accept as proof of
   finality.
3. An honest validator cannot derive the epoch's final block payload and leaves
   that block's verification unresolved, because it counts against the fault
   budget at the boundary, and once more than `f` validators are in that state
   the final block never finalizes, the chain stops at the epoch boundary, and
   recovery needs operators to roll those nodes back to a point before the
   midpoint.
4. Honest validators derive different epoch infos for the same final block,
   because no proposal at the boundary height gains a quorum and the chain
   halts until operators fix the participants provider on every node, or, where
   a quorum does agree, the dissenting honest validators enter the next epoch
   without a signing share and count toward `f` for the whole epoch.
5. Every validator panics at the same epoch boundary, because the network stops
   producing blocks, each restart re-derives the same final block and panics
   again, and the chain stays down until operators ship corrected code or
   configuration.
6. A validator's orchestrator exits at an epoch boundary and the node never
   re-enters consensus on its own, because it counts toward `f` for as long as
   it is out, operators must perform a manual state sync, and a second such loss
   in the meantime takes the committee below quorum.
7. A joining node adopts a state-sync floor and committee that the network never
   finalized, because it syncs to attacker-chosen state, activates the
   attacker's peer directory, and follows a private fork for as long as the
   attacker keeps feeding it.
8. A joining node's bootstrap never completes or resolves to an epoch the
   network has long left, because new or replaced validators cannot be onboarded
   until someone hand-distributes a fresh checkpoint, and the committee keeps
   shrinking toward quorum in the meantime.
9. A restarted dealer deals a different polynomial than before its restart and
   blocks the honest players that acknowledged the first one, because those
   players stay disconnected from it until a restart, its log is unusable, and
   the ceremony loses both its contribution and the connectivity consensus
   needs between those peers.

## stateful

1. Every honest node panics while applying the same finalized block, because
   the whole network stops at that height at once, a restart reproduces the
   panic since marshal redelivers the block, and only a coordinated code or
   data fix brings the network back.
2. A block is finalized whose committed state root matches no honest node's
   database, because light clients and bridges that verify proofs against that
   root reject the valid proofs honest nodes produce and accept proofs the
   proposer crafted against a root only it knows.
3. The application's finalized hook runs a second time for a block the node
   already applied, because external effects driven from the hook, such as
   payouts, notifications, or outbound messages, are emitted twice and the
   application's users receive the duplicate.
4. A node that joined through state sync never runs the capture or finalized
   hooks for the blocks between its previous tip and the sync anchor, because
   every record the application derives from those hooks, such as an event
   index or receipts, has a hole on that node and its clients cannot tell the
   gap from the blocks never having happened.
5. A node cannot open its databases at the block marshal last acknowledged and
   panics at startup, because the only remedy is to wipe local state and
   re-sync from peers, the validator is absent for the whole rebuild and counts
   toward `f`, and a storage fault shared across operators takes several
   validators down in the same restart.
6. A validator that fell behind never rejoins consensus, because it declines
   every proposal and defers every verification while syncing, counts toward
   `f` the whole time, and the operator must wipe it and rejoin it as a new
   node, so a network with short block retention loses every validator that
   suffers a long outage.
7. A node stops applying finalized blocks and acknowledging marshal without
   crashing, because process supervision never restarts it, block delivery to
   the application stops once the acknowledgement window fills, and the node
   looks healthy while it contributes nothing and counts toward `f` until an
   operator notices.
8. A validator misses votes and leader slots while it serves peers' state sync
   and probe requests from its live databases, because it earns nothing for
   those views, the requesters pay only request bandwidth, and draining several
   validators at once shrinks the network's effective quorum.
9. A node that needs a floor never obtains one and never begins state sync,
   because operators cannot add or replace validators after committee churn,
   and a network that has already lost nodes cannot restore its fault budget.

## transfers

1. A settled transfer is applied again in a later block, because the payer is
   debited and the payee credited a second time, and nothing in the ledger can
   undo it once that block finalizes.
2. Honest nodes settle the same finalized block to different accounts, because
   their state roots diverge, no later block that commits a root can gain a
   quorum, and operators must decide by hand which copy of the ledger is
   canonical.
3. A batch settles to balances that do not conserve the value it moved, because
   value is minted for or destroyed from whoever holds the affected accounts and
   every later balance builds on the wrong figure.
4. A proposer builds a block whose transfers verifiers settle as rejected,
   because the block is never certified, the leader's turn is wasted, and in a
   reshare epoch the dealer log it carried misses the inclusion window.
5. A validator spends far more time or memory settling a block than the block's
   size justifies, because it misses the view deadline, the block times out, and
   a Byzantine leader can repeat the cost on every turn while paying only the
   block.
