# Threat Model

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

## Adversarial Settings

- Network peers may be malicious, unauthorized, fast, slow, stale, replaying old
  traffic, using malformed handshakes, sending oversized or invalid frames,
  manipulating discovery messages, or attempting to consume connection,
  decoding, cryptographic, or application-buffer resources.
- Byzantine consensus participants may equivocate, replay cross-view,
  cross-term, or cross-epoch artifacts, send invalid votes, certificates,
  proposals, attestations, chunks, or blocks, withhold ancestry data and blocks,
  trigger resolver or backfill work, crash and restart, or exploit persistence
  gaps.
- Serialized bytes, storage records, storage proofs, commitments, checkpoints,
  metadata, peer messages, quorum certificates, votes, proposals, shares, stream
  frames, shards, and cryptographic artifacts may be malformed, oversized,
  non-canonical, corrupted, stale, or adversarial when accepted by a primitive
  through its documented public boundary.
- Durable storage may contain partial writes, truncated records, stale records,
  corrupted checksums, unsynced writes, duplicate indices, pruned data, or
  artifacts left by earlier initialization attempts.
- Application-provided callbacks, automata, certifiers, and proposal logic are
  integration boundaries when their documented return values influence voting,
  certification, finalization, persistence, or delivered state.
- Local configuration is trusted only to the extent documented by the relevant
  primitive. Dangerous explicit configuration, such as IP-check bypass, must not
  remove independent cryptographic authentication requirements.

## Assumptions and Trust Boundaries

- Verification starts from the semantic public boundary that accepts the
  relevant input: peer message, handshake frame, p2p channel, consensus vote,
  certificate, durable journal, block archive, resolver delivery, public trait
  contract, or application-provided callback.
- The components are library primitives for adversarial environments. A claim is
  security-relevant only when the affected primitive is documented or intended
  to handle the relevant untrusted input, peer, artifact, storage record, or
  callback behavior.
- Cryptographic identities, signing keys, participant sets, namespaces, epochs,
  rounds, terms, views, heights, payload digests, and transcript histories are
  load-bearing bindings. They must remain domain-separated across protocols,
  applications, committees, and rotations.
- Configured limits, including message sizes, peer counts, bit-vector lengths,
  shard sizes, time bounds, channel buffers, rate limits, and concurrency
  bounds, are security boundaries before allocation, expensive verification,
  decryption, reconstruction, or persistent state changes.
- Crash recovery, restart behavior, and durable persistence are part of the
  security model when loss or replay can cause equivocation, conflicting
  signatures, conflicting certificates, missing delivery, corrupted state, or
  inconsistent honest participant decisions.
- Consensus-visible state machine behavior must be deterministic for the same
  ordered inputs across honest participants, including behavior delegated to
  application callbacks when those callbacks affect voting, certification,
  finalization, or reported state.
- Byzantine consensus analysis assumes the protocol's configured fault
  threshold, with at most `f` Byzantine participants: (1) for Simplex-based
  protocols (`N3f1`, `n >= 3f+1`), a valid `n-f` quorum certificate (`2f+1` when
  `n = 3f+1`) contains at least `f+1` honest signers; (2) for protocols on the
  `N5f1` fault model (`n >= 5f+1`, `utils/src/faults.rs`), a valid `n-f`
  L-quorum certificate (`4f+1` when `n = 5f+1`) contains at least `3f+1` honest
  signers, and a valid `2f+1` M-quorum certificate contains at least `f+1`
  honest signers. No engine under `consensus/src` uses `N5f1` at this revision
  (the engines are `simplex`, `marshal`, and `aggregation`). Do not
  report against an `N5f1` engine unless its code is in the reviewed tree.
- If honest signer code enforces the protocol's signing preconditions, receivers
  may treat a valid quorum certificate as quorum-backed evidence for those
  preconditions unless the component's documented contract separately requires
  local materialization or replay of the supporting ancestry before reporting or
  building on it.

## Trust Model

The codebase assumes at most `f` participants are Byzantine or unavailable.
Because quorum requirements vary across consensus protocols and fault models,
use `utils/src/faults.rs` to derive the quorum for each concrete primitive.

Crashed, lagging, or state-syncing nodes count toward the fault budget. Valid
quorum certificates may be trusted only for conditions that honest signers are
required to enforce.

Main trust boundaries:

- Network bytes -> encrypted and authenticated stream -> authenticated P2P peer
  -> codec.
- Peer artifacts -> Resolver/Marshal -> Simplex voting and finalization.
- Consensus output -> application callbacks, acknowledgements, and state
  transitions.
- Persistent bytes -> journal recovery -> QMDB/Merkle authenticated state.
- DKG/resharing -> epoch and committee handoff.
- Serialized crypto artifacts -> domain-separated verification and batching.

Peers, Byzantine validators, protocol messages, and documented untrusted storage
are hostile. Local configuration, setup files, and imported threshold state are
trusted unless explicitly documented otherwise. Findings are invalid when they
exceed the shared `f` budget.

## Consensus Timing Rule

This rule is a review default for consensus-related liveness in the consensus
protocols implemented in this repository. It is not a guarantee of any
component, and it does not apply to other primitives.

1. Safety is expected under asynchrony: a safety finding may use any message
   delay and any message order, within the fault budget.
2. Liveness is expected only after the network is synchronous.
3. Each component's documented contract overrides this default, and the
   components document different assumptions. `simplex` states a "partially
   synchronous setting". `aggregation`
   recovers certificates "over an externally synchronized sequencer of items".
   The module documentation of
   `marshal` promises delivery of finalized blocks in height order and at
   least once, and states no synchrony assumption.
4. Bounded clock skew is assumed only where a component documents it.
5. A liveness finding names the synchrony assumption it uses.
