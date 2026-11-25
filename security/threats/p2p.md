# P2P

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

## authenticated

1. A validator stops admitting new connections from honest peers while
   unauthenticated strangers hold its handshake slots, because the peers it
   has lost cannot reconnect, their votes and proposals stop reaching it, it
   drifts behind the current view, and the operator can only restore service by
   fronting the node with an external filter.
2. A message is delivered to the application attributed to an honest peer that
   never sent it, because the consensus engine counts the attacker's vote as
   that peer's, blocks or reports that peer for the attacker's invalid data,
   and the attacker's own identity never appears in any log.

## discovery and lookup

1. A newly started node connects only to the peers its bootstrapper chooses to
   reveal, because it joins consensus late or never, counts toward the fault
   budget the whole time, can be shown a network made only of attacker
   identities, and recovers only when an operator supplies a different
   bootstrapper.
2. Honest validators fail to establish connections to a peer whose address
   another peer has claimed as its own, because their votes and proposals cross
   that link late or not at all until the dial shuffle happens to win, a node
   behind a firewall that cannot dial out is isolated outright, and the
   attacker renews the claim each time its record is marked stale.
3. Two honest peers that hold peer sets of different sizes under the same
   index disconnect each other whenever one of them gossips that index,
   because no application message crosses that link before it is torn down,
   the reconnect cooldown (60 seconds in the recommended configuration) keeps
   them apart for most of each minute, and a membership change applied at
   different times on different validators looks like a network partition
   until the application resynchronizes.
4. Any peer admitted to any tracked set, including a follower-tier secondary
   peer, learns the ingress address of every validator the responder is
   connected to, because validators can then be targeted one by one with
   volumetric or handshake floods that the p2p layer cannot absorb, and a
   permissionless follower tier turns the validator address list into public
   information.

## router

1. Messages from honest peers are silently discarded at the receiving node when
   a channel's shared inbound mailbox or a mux subchannel queue is full,
   because the consensus engine never sees the votes or certificates they
   carried, the view times out and must be nullified, and an attacker needs
   only enough admitted identities and a consumer slower than its drain rate to
   make honest traffic disappear.
2. The application is given a recipient list that includes a peer that will
   never receive the message, because the voter or broadcaster does not retry,
   the peer has to recover the proposal or certificate through backfill, and a
   leader with several slow links sees its views time out while its own
   accounting shows every message as delivered.
3. A validator's own vote is refused at submission while it answers a burst of
   backfill or broadcast requests, because the vote is never transmitted, the
   validator misses a view although it is honest and online, and the peers that
   caused the burst only asked for data they were entitled to request.
4. All traffic from an honest peer to a node is delayed while that peer exceeds
   its quota on any single channel, because its votes on the consensus channel
   arrive late or after the view has moved on, a burst that is normal under
   load on one channel costs it participation on the others, and if the backlog
   outlasts the runtime's read/write timeout (60 seconds by default) the
   connection drops and a reconnect cooldown follows.
5. Honest peers running an older or newer message format are blocked for hours
   by the peers that cannot parse them, because the two halves of a rolling
   upgrade stop exchanging votes and blocks, the committee can sit below quorum
   until the blocks expire, and operators must restart nodes to clear the
   blocks early.
