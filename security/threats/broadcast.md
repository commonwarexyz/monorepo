# Broadcast

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. An honest proposer's block is not available to a validator through the
   broadcast buffer in time for it to vote or certify, because the validator
   needs the block to notarize it in inline and deferred mode and to certify it
   in deferred mode, so without it the validator cannot vote, the view times
   out, and the honest proposer's turn is wasted.
2. An honest validator broadcasting a valid block is blocked by the peers that
   cannot decode it, because those peers disconnect it on every channel and
   refuse to reconnect for hours, so its votes do not reach them, its turns as
   leader are wasted, and it counts toward `f` although it did nothing wrong.
