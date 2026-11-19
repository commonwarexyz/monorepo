# Stream

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. A connection is authenticated under an identity its remote end does not
   hold, because the real validator can no longer connect while its single
   connection slot is occupied, messages addressed to it such as its assigned
   shard go to the impostor, and every payload that is not independently signed
   is accepted as that validator's.
2. A message is delivered on an authenticated connection that the peer did not
   send in that order, because p2p hands it to the peer's channels as
   authentic, unsigned protocol data such as resolver responses, relayed shards,
   and discovery peer lists is acted on as the honest peer's, and an injected
   invalid or duplicate payload gets the honest peer blocked.
3. An observer on the network path reads the plaintext of messages between two
   authenticated peers, now or after a later compromise of one peer's identity
   key, because DKG and resharing deliver private shares over this channel,
   enough shares let the observer reconstruct the threshold key and forge the
   committee's signatures, and recorded traffic becomes readable retroactively.
4. A receiver allocates or waits for more bytes than the bound for the
   connection's current stage, because an unauthenticated internet host can
   open such a connection to every validator, so more than `f` of them run out
   of memory or stall at once while the attacker holds no key.
5. A listener's handshake capacity and signing CPU are spent on connections that
   never authenticate, because honest validators' dials are rejected by the
   concurrency limiter and their votes never reach this node, while the
   attacker needs no key of its own.
6. Two nodes configured for different applications or networks complete a
   handshake with each other, or two nodes that differ only in record version
   or cipher, which the handshake does not authenticate, go on to exchange
   records, because every record then fails to authenticate or decode on the
   other side, no application message crosses the link, and a validator that
   reuses its key on a test network is cut off from the network it meant to
   join.
