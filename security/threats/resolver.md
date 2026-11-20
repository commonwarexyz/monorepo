# Resolver

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. A block or certificate the node has requested arrives only after several
   attempts have each waited out the full fetch timeout, because the node stays
   behind the chain head for the whole delay, cannot verify or vote on proposals
   that build on the missing data, and misses leader slots, while the peers
   that failed to answer lose nothing they cannot earn back by serving other
   keys.
2. A fetch restricted to target peers is never delivered, because the data it
   was meant to retrieve never reaches the consumer, the caller's dependent work
   stalls until the caller itself re-issues an untargeted fetch, and a Byzantine
   peer that advertised data it does not hold can keep the fetch open at no
   cost.
3. An honest peer is blocked by a node for serving a response that was correct
   for the requested key, because the block disconnects the two for hours, each
   loses the other as a source and destination for backfill and for every other
   channel, and if many nodes reach the same verdict the honest peer is treated
   as faulty network-wide and shrinks the honest majority.
4. A node's outbound bandwidth and storage reads are consumed serving backfill
   responses to peers that do not need them, because its own votes and proposals
   queue behind multi-megabyte responses, it falls behind the current view, and
   each response cost the requester only a few dozen bytes.
