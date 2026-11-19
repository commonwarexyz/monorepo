# Cryptography

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

## bls12381

1. A multi-signature certificate verifies for a subject that no honest quorum
   signed, because the dependent consensus finalizes a block or the aggregation
   scheme certifies a value with fewer than `f+1` honest signers behind it, and
   the attributable signer bitmap blames honest validators for a vote they
   never cast.
2. A signature verifies under a participant key that is the group identity or
   lies outside the prime-order subgroup, because anyone can then produce
   accepted signatures for that seat without a secret key, so a quorum is
   reached with fewer real signers than the fault budget assumes.
3. A batch of attestations containing an invalid signature is reported as
   entirely valid, because the invalid signer's vote counts toward quorum on
   that node while nodes that verified individually reject it, so honest nodes
   disagree on whether a quorum exists and the malformed votes are never
   flagged for blocking.
4. An honest participant is blamed for a threshold partial signature it never
   produced, because slashing, peer blocking, or liveness accounting that
   consumes partials as evidence punishes a correct validator while the
   coalition that forged the partial pays nothing.
5. A timelock ciphertext targeted at a future consensus round is decrypted
   before any certificate for that round exists, because sealed bids,
   encrypted transactions, and commit-reveal payloads bound to that round are
   read early by the leader coalition, which front-runs or censors them and
   leaves no attributable evidence.
6. A node panics while constructing a threshold scheme from a public polynomial
   whose participant count or recovery threshold does not match the committee,
   because the validator leaves the committee until an operator restarts it,
   and when the polynomial came from a synced epoch artifact every node that
   loads the same artifact stops at the same point so the committee cannot
   form.
7. More than `f` players' shares are publicly known after a DKG or reshare round
   completes (the interactive DKG bounds reveals from honest dealers by `f`
   only under synchrony, `cryptography/src/bls12381/dkg/feldman_desmedt.rs`),
   because a coalition holding those shares plus its own can recover
   threshold certificates for a second conflicting block, so the threshold the
   dependent consensus relies on for safety no longer holds and the epoch's key
   must be abandoned.
8. Honest participants finish the same DKG round holding shares of different
   keys or different public polynomials, because their partial signatures never
   combine into one certificate, the committee certifies nothing until the next
   successful reshare, and each group treats the other as faulty.

## ed25519 and secp256r1

1. A certificate accepted by the committee is rejected by an external verifier
   using a stricter Ed25519 implementation, because light clients, bridges, or
   HSM-backed relayers that re-check the same signatures drop messages the
   chain considers final, and relayers that disagree with one another deliver a
   message to some destinations and not others.
2. Two committee entries that decode to the same Ed25519 point are admitted as
   distinct participants, because one key holder controls two seats and two
   votes, so a quorum is reached with fewer independent parties than the fault
   budget assumes and its equivocations are attributed to two different
   identities.
3. Two different encodings of the same signer's signature over the same subject
   are both accepted, because caches and equivocation detectors keyed on
   signature or certificate bytes see two distinct certificates for one
   subject, so an honest signer is reported as equivocating or the same vote is
   counted twice by a deduplication filter.
4. A signature produced for one protocol context is accepted in another
   context, because a handshake signature, DKG acknowledgement, or transcript
   signature is replayed as a consensus vote or vice versa, binding a validator
   to a statement it never made.

## handshake and chacha20_poly1305

1. A listener completes a handshake believing the dialer is one identity while
   the shared secret is actually held by another, because application records
   on that connection are credited to a validator that never sent them, so
   votes, blocks, and DKG private dealings are accepted from or delivered to
   the wrong party.
2. A listener performs the full signature verification, key exchange, and
   signing work for a replayed Syn message, because an attacker who captured
   one valid Syn spends only bandwidth to burn the listener's CPU for the whole
   acceptance window, and the dialer named in the Syn fills the listener's
   single per-peer connection slot so the genuine dialer is refused.
3. A handshake completes with a shared secret that a third party can compute,
   because every record on the connection is readable and forgeable by that
   party, so votes, dealings, and blocks exchanged with the peer are observed
   and altered in transit without either peer noticing.
4. Past connection traffic is decrypted after a validator's identity key or
   process memory is compromised, because DKG private shares sent over those
   connections are recovered, which hands the attacker shares from earlier
   rounds that combine with reveals to exceed the `f` share budget of the
   threshold key.
5. Two records are sealed under the same key and nonce, because the XOR of
   their plaintexts leaks and the authentication key becomes recoverable, so the
   attacker forges arbitrary records on the authenticated stream and injects
   votes or dealings as the peer.

## reed_solomon and lthash

1. A decoder returns data that differs from what was encoded when some supplied
   shards belong to a different codeword, because two honest nodes that
   received different shard subsets of a maliciously encoded block reconstruct
   different blocks under the same commitment, so one executes a block the
   other never sees and the application state forks.
2. A node allocates working space sized by attacker-chosen shard counts or
   shard widths, because one small frame sent to every honest validator gets
   more than `f` of them killed by the OS or stalled at once, for the price of
   a few bytes each.
3. Two different sets of elements produce the same LtHash checksum, because a
   state-equality or update-propagation check passes for tampered data, so a
   node accepts a wrong state as matching its peers.

## certificate, transcript, and secret

1. A certificate counts the same participant twice or counts an index outside
   the participant set toward quorum, because finality is reached with up to
   `f` fewer real signers than the fault model requires, so a Byzantine
   minority finalizes blocks on its own.
2. A node allocates a signer bitmap or signature list sized by an attacker's
   claimed participant count, because one network message sent to every honest
   validator gets more than `f` of them killed or stalled at once, and
   consensus halts until operators restart them.
3. An attestation that is invalid on its own is retained as verified after a
   certificate assembled with it passed, because the Byzantine signer is never
   recorded as invalid, so a node that blocks or reports misbehaving peers from
   that result never does, the attacker repeats the behavior for free, and
   attributable evidence exported later fails third-party verification.
4. Two different sequences of committed packets produce the same transcript
   summary, because a signature or confirmation made over one history verifies
   for another, so a peer is bound to a handshake or DKG round it did not take
   part in and randomness drawn from the transcript is shared between contexts
   meant to be independent.
5. A secret remains readable in process memory after its holder has finished
   with it, because a later memory disclosure, core dump, or swapped page
   reveals past ephemeral keys, in-flight DKG shares, or signing keys,
   defeating forward secrecy and allowing dealings from earlier rounds to be
   decrypted retroactively.

## bloomfilter and zk

1. A bloom filter fed attacker-chosen items answers true for every query,
   because a node that uses it to skip already seen messages drops everything,
   or if it uses it to admit unseen messages floods itself, so gossip for that
   node stalls.
2. A golden DKG dealing (`bls12381/dkg/golden`, proved with `zk/bulletproofs`)
   is accepted although its masked shares were not derived from the dealer's
   eVRF key, because the dealer can give different players
   inconsistent shares in a protocol whose only defense is public
   verifiability, so players finish with shares of different polynomials and
   the committee cannot certify until a reshare.
