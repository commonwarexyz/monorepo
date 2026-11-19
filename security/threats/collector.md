# Collector

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. The monitor is handed a Byzantine handler's well-formed but invalid response
   together with a collected count that includes it, because an application that
   treats the count as its quorum proceeds with fewer valid replies than it
   believes it has, and its aggregate signature or decision fails or has to be
   redone after the fact.
2. A node runs its request handler and keeps a pending reply task for every
   request any connected peer sends it, because a peer that was never a
   legitimate originator can make the node spend CPU on handler work at its full
   rate limit, memory grows with every reply the handler leaves unanswered, and
   the node's own work is delayed.
3. An honest originator or handler is blocked by a peer after a single request
   or response fails to decode there, because the block disconnects the two for
   hours, no response from that handler can be collected on any commitment, and
   a systematic decode failure such as a version skew cuts the originator off
   from every handler at once.
