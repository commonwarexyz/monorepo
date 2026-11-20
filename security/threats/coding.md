# Coding

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. Two honest nodes decode different data from shards that all verified against
   the same commitment, because validators execute different blocks under one
   finalized commitment and their state roots diverge with no protocol
   mechanism to tell which node is wrong.
2. Two honest validators disagree about whether the same shard is valid,
   because each blocks the peer whose shard failed its own check, honest
   validators block each other, their shards and votes stop flowing between
   them, and the block cannot be reconstructed even though enough honest shards
   exist.
3. Every validator's assigned shard passes verification for a commitment that
   no set of shards can decode, because validators cast their notarize vote on
   shard validity alone, the notarized block can never be reconstructed or
   certified, the view is lost, and marshal keeps requesting a block that does
   not exist until the record is evicted.
4. A shard is accepted at a position other than the one it was encoded for,
   because the shard engine marks that participant's index as contributed, the
   honest owner of the index is blocked as an equivocator when its real shard
   arrives, and reconstruction fails or never gathers enough distinct indices.
5. An honest node re-encodes a block and obtains a commitment different from
   the one the honest proposer published, because the proposer's block fails
   validation at every peer, the honest leader is treated as faulty and its view
   is nullified, and a committee whose members run different execution
   strategies (`commonware_parallel::Strategy`) or builds never agrees on any
   block.
6. An honest validator crashes while checking or reconstructing a block from
   peer shards, because a leader or relayer can send the same shards to every
   honest validator, so more than `f` validators are down at once and consensus
   halts until operators restart them.
7. A block that a quorum voted to notarize cannot be reconstructed, because
   reconstruction needs `minimum_shards` correct shards and only the honest
   holders are sure to serve theirs, so a threshold above the honest share lets
   `f` withholding validators turn a notarized block into one that no honest
   node can ever certify or execute. Coding marshal derives `f+1`
   (`consensus/src/marshal/coding/types.rs`); a custom configuration can
   exceed it.
