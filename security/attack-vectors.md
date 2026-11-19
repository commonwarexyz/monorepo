# Attack Vectors

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

The paths by which a peer, a Byzantine participant, an application callback, or
damaged storage reaches a threat under ["Threats"](threats.md). These lists are
open in the same way
as the threat lists: each entry is an example, and a missing entry means
nothing.

## Consensus

- Quorum, view, epoch, height, term, round, and certificate validation failures.
- Missing or wrong identity binding.
- Non-determinism and concurrency issues.
- Validation gaps for untrusted votes, certificates, proposals, and messages.
- Non-canonical protocol representations.
- Integer overflows and boundary arithmetic errors.
- Timeout, skip, and leader-inactivity handling that stalls honest views.
- Reliable-broadcast assumption breaks and retry logic bugs.
- Redundant or unnecessary data processing.
- Threshold/quorum-intersection mistakes.
- Equivocation and replay.
- Peer blocking on verdicts an honest node can trigger.
- Unverified or incomplete activity exported to reporters.
- Seed and leader exposure before a round resolves.
- Marshal delivery, floor, and acknowledgement ordering bugs.

## Broadcast

- Untrusted peer broadcast and caching behavior.
- Rate limiting and backpressure gaps.
- Subscription/waiter retention and cancellation.
- Replay and deduplication failures.
- Withholding or delaying a block a validator needs to vote.
- Codec-boundary decode issues before admission.
- Codec limit or version drift between honest peers.

## Codec

- Decode bounds missing or enforced after allocation.
- Non-canonical or ambiguous encodings.
- Allocation before validation.
- Encode/decode round-trip and version-compatibility breaks.
- Truncated or trailing-byte acceptance.
- Decoders that panic or skip type invariants instead of returning an error.

## Cryptography

- Private-key or secret leakage through logs, files, display/debug, or missing
  zeroization.
- Key reuse or key/share binding failures.
- Domain-separation and transcript-binding gaps.
- Subgroup, rogue-key, signature/proof malleability, and invalid-public-key
  issues.
- Certificate verification and signer-index mistakes.
- Replay and forget-and-forgive preconditions.
- Randomness misuse.
- Public elements added to transcripts without required validation.
- Sizes taken from peer-supplied shares, proofs, or shard parameters without
  bounds.
- Nonce or key reuse across records or connections.
- Reconstruction from shards whose contents are not authenticated.
- Non-cryptographic or collision-prone hashing of attacker-chosen inputs.

## Coding

- Shard-width amplification.
- Pathological coding configuration.
- Reconstruction threshold above the honest share of shards.
- Non-canonical codewords.
- Shard identity or commitment confusion.
- Verification and reconstruction flooding.
- Check and re-encode results that differ between honest nodes.

## P2P

- Peer/message trust-boundary failures.
- Admission and membership bypass.
- Rate-limit, backpressure, and channel-separation failures.
- Authentication and identity confusion.
- Sybil and eclipse vectors.
- Blocking and cooldown applied to honest peers.
- Handshake slot and connection exhaustion by unauthenticated sources.
- Self-attested address records and gossip of peer addresses.
- Peer set composition drift between honest nodes.
- Codec limit or version drift between honest peers.

## Stream

- Missing zeroization or forward secrecy.
- Unknown-key-share, key-compromise impersonation, MITM, reflection, and selfie
  attacks.
- Small-order (non-contributory) X25519 public keys and parameter confusion.
- Ephemeral key reuse.
- Cross-protocol attacks.
- Signature key substitution under a scheme without exclusive ownership
  (SAKE `Version::V0`).
- Plaintext or length exposure before authentication.
- Record reordering, replay, or injection on an established connection.
- Transcript binding gaps, and cipher exhaustion that is not followed by a
  new connection.
- Nonce overflow or reuse.
- KDF misuse for transport keys.
- Handshake replay and per-stage size bounds.

## Storage

- Recovery that selects a wrong or uncommitted tail after a crash.
- Durable record, metadata, and checkpoint corruption.
- Proof and authenticated-state validation gaps.
- Pruning and replay inconsistencies.
- Untrusted or peer-derived durable-state handling.
- Oversized or malformed proofs and sync responses.
- Non-deterministic merkleization or floor handling across nodes.
- Key grinding against translators, indexes, and tables.
- Sync reported before data is durable.

## Glue

- Probe and anchor manipulation.
- State-sync retarget and restart races.
- DKG/reshare generation splicing.
- Key-rotation inclusion starvation.
- Application callback and acknowledgement exhaustion.
- Pruning and epoch-boundary loss.
- Participant and epoch derivation that differs between honest nodes.
- Hooks repeated or skipped around durability and state sync.
- Replay-unsafe or non-deterministic account logic in transfers.
- Settlement cost or verdicts that differ between proposer and verifiers.

## Runtime

- Nondeterministic scheduling affecting consensus-visible behavior.
- Time, timeout, and cancellation bugs.
- Task ownership and supervision failures.
- Platform-specific I/O differences, especially io_uring paths.
- Runtime/storage/network errors that are collapsed into unsafe states.
- Sync semantics weaker than callers assume.
- Allocation sized by peer-supplied lengths.
- Directory holds and concurrent instances.
- Fault models in simulated storage weaker than real disks.
- Metric registration and label conflicts.

## Resolver

- Peer scoring shared across keys and unchanged by partial answers.
- Targeted fetches with no fallback to other peers.
- Consumer verdicts that block peers for locally stale reasons.
- Serving every request from storage without a per-peer budget beyond the
  channel rate limit.

## Collector

- Response counting without validation.
- Handlers invoked for requests from any connected peer.
- Blocking on decode failures between honest peers.

## Clearing

- Obligations of a role that the crate cannot check and a deployment breaks.
- Records persisted after, not before, a signature or attestation is released.
- Admission of one sender's states in more than one place at a time.
- A request signed again before the posts of its epochs are resolved.
- Ledger state read before it is final, or queues that change other than at
  their tail.
- Closes applied twice, out of order, or to databases at the wrong roots.
- Limits that differ between the operator and the validators.
- A deployment namespace shared by two deployments.
- Challenges, payout proofs, and claims verified against the wrong post, or
  posted matrix and payouts roots that the ledger did not keep.
- Deposits queued before custody, forced withdrawals queued without the
  account's authentication, and required counts set too low.
- Transfers made inside a post, and destinations chosen by the caller.
- Ledger checks that depend on anything but ledger state and call inputs.
- Amounts at the edge of the integer type.
