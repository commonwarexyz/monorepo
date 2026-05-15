# Round Tracking

## Role

Round tracking maintains each sender's `rnd(m) = max protocol round it has sent or received` so network faults are attributed to the sender's current round rather than a possibly stale view encoded in the wire bytes. Process faults use the decoded view carried by the byzantine message itself.

## Key Files

- `consensus/fuzz/src/byzzfuzz/intercept.rs` - sender-round cell, inbound round-tracking wrapper, channel view extractors.
- `consensus/fuzz/src/byzzfuzz/forwarder.rs` - outbound sites that fold the carried view into the cell before reading it.

## Behavior

Each validator has a single sender-round cell that advances monotonically. The cell is consulted before applying network faults and updated from both directions of traffic:

- **Outbound.** For each channel, the outbound interception site attempts to decode the view carried in the wire bytes (vote / certificate view; resolver request key or response certificate view). When a view is recovered, the cell is advanced to it; otherwise the cell is left untouched.
- **Inbound.** A wrapper installed on every validator's incoming vote, certificate, and resolver channels performs the same decode and advances the cell, then forwards the message to the engine unchanged.

A retransmission of an old view at a later round therefore inherits the sender's current round for network partitions, but it does not inherit process faults scheduled for that later round. Process faults still match the retransmitted message's decoded view.

Inbound extractors additionally feed the observed-value pool used by the vote mutator.

## Error Handling

Undecodable wire bytes leave the cell unchanged and the message is forwarded as-is. Inbound errors propagate from the wrapped receiver unchanged.

## Related Invariants

- [Network Interception](../../invariants/invariants.md#network-interception) - undecodable-byte handling and resolver wire decoding.
- [Fault Flow](../../invariants/invariants.md#fault-flow) - the cell is updated before network fault decisions read it.

## Related Specs

- [Network Interception](README.md) - consumers of the cell.
- [Forwarder/Injector Contract](../../contracts/forwarder-injector.md) - the boundary that wires the cells.
