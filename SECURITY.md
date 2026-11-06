# Security Policy

## Reporting Security Issues

We welcome security disclosures and are committed to providing prompt attention
to any confirmed security issues.

Vulnerabilities should be reported privately
[via GitHub Security](https://github.com/commonwarexyz/monorepo/security)
instead of as a public issue.

We do not yet offer a bounty program for responsible disclosure of security
vulnerabilities; however, we do track contributions and record them on the
leaderboard below.

### Leaderboard

1. (Your Name Here)

## Threat Model

### Adversarial Settings

- Network peers may be malicious, unauthorized, slow, stale, replaying old
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

### Assumptions and Trust Boundaries

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
  `n = 3f+1`) contains at least `f+1` honest signers; (2) for Multimmit (`N5f1`,
  `n >= 5f+1`), a valid `n-f` L-quorum certificate (`4f+1` when `n = 5f+1`)
  contains at least `3f+1` honest signers, and a valid `2f+1` M-quorum
  certificate contains at least `f+1` honest signers.
- If honest signer code enforces the protocol's signing preconditions, receivers
  may treat a valid quorum certificate as quorum-backed evidence for those
  preconditions unless the component's documented contract separately requires
  local materialization or replay of the supporting ancestry before reporting or
  building on it.

### Trust Model

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

### Attack Vectors

#### Broadcast

- Untrusted peer broadcast and caching behavior.
- Rate limiting and backpressure gaps.
- Subscription/waiter retention and cancellation.
- Replay and deduplication failures.
- Codec-boundary decode issues before admission.
- Data withholding.

#### P2P

- Peer/message trust-boundary failures.
- Admission and membership bypass.
- Rate-limit, backpressure, and channel-separation failures.
- Authentication and identity confusion.
- Sybil and eclipse vectors.
- Blocking/cooldown bypass.
- Remote denial of service.

#### Coding

- Shard-width amplification.
- Pathological coding configuration.
- Non-canonical codewords.
- Shard identity or commitment confusion.
- Verification and reconstruction flooding.

#### Glue

- Probe and anchor manipulation.
- State-sync retarget and restart races.
- DKG/reshare generation splicing.
- Key-rotation inclusion starvation.
- Application callback and acknowledgement exhaustion.
- Pruning and epoch-boundary loss.

#### Codec

- Decode bounds missing or enforced after allocation.
- Non-canonical or ambiguous encodings.
- Allocation before validation.
- Encode/decode round-trip and version-compatibility breaks.
- Truncated or trailing-byte acceptance.

#### Runtime

- Nondeterministic scheduling affecting consensus-visible behavior.
- Time, timeout, and cancellation bugs.
- Task ownership and supervision failures.
- Platform-specific I/O differences, especially io_uring paths.
- Runtime/storage/network errors that are collapsed into unsafe states.

#### Storage

- Crash recovery failures.
- Durable record, metadata, and checkpoint corruption.
- Proof and authenticated-state validation gaps.
- Pruning and replay inconsistencies.
- Untrusted or peer-derived durable-state handling.
- Denial of service through oversized or malformed proofs.

#### Consensus

- Quorum, view, epoch, height, term, round, and certificate validation failures.
- Missing or wrong identity binding.
- Non-determinism and concurrency issues.
- Validation gaps for untrusted votes, certificates, proposals, and messages.
- Non-canonical protocol representations.
- Integer overflows and boundary arithmetic errors.
- Partition and liveness failures.
- Reliable-broadcast assumption breaks and retry logic bugs.
- Redundant or unnecessary data processing.
- Threshold/quorum-intersection mistakes.
- Equivocation and replay.

#### Cryptography

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

#### Stream

- Missing zeroization or forward secrecy.
- Unknown-key-share, key-compromise impersonation, MITM, reflection, and selfie
  attacks.
- Invalid-curve and parameter-confusion attacks.
- Ephemeral key reuse.
- Cross-protocol attacks.
- Bleichenbacher-style signature forgery.
- Heartbleed-style plaintext exposure.
- Mutual authentication, payload authentication, and confidentiality failures.
- Key rotation and transcript-hash binding bugs.
- Nonce overflow or reuse.
- KDF misuse for transport keys.

## Automatic Secure Code Review

### Severity Gates

- Critical or high requires concrete adversarial reachability through a
  supported integration boundary.
- Consensus-wide impact requires an in-model schedule that remains within the
  fault budget throughout.
- Configuration-dependent or integration-dependent claims are capped at medium
  unless the attacker can force the condition under a valid configuration.
- Trusted-local prerequisites, one-process recoverable failures, and documented
  misuse are normally capped at low.
- Remaining material uncertainty must lower confidence or severity; it must
  never be resolved by assuming the worst case.

### Findings Validation Process Lessons

- For DKG, resharing, MPC, threshold-certificate, and threshold-VRF findings,
  distinguish protocol-produced artifacts from serialized or configured
  artifacts imported from outside the protocol. Before claiming validator or
  protocol impact from malformed output, trace every in-tree construction path
  that can create the artifact and verify whether the malformed state can be
  produced by normal protocol execution or adversarial protocol messages.
- Verify that every DKG implementation produces output where
  `public.total() == players.len()`, including observer, player-finalization,
  resharing, trusted-dealer, restart, and import paths.
- Parser, codec, or durable-state harnesses that synthesize malformed
  cryptographic artifacts validate only the import boundary they exercise. Do
  not generalize those results to live DKG, resharing, consensus, or validator
  behavior unless a concrete integration path accepts the same bytes as
  adversarial input under the component's documented contract.
- Treat trusted setup files, local operator configuration, and manually supplied
  bootstrap threshold state as deployer-local inputs unless source review or
  integration validation shows that peers, Byzantine participants, or explicitly
  untrusted storage can control them.
- For cross-component limits, do not treat one inner representation fitting its
  channel as proof that the integration is valid. Identify who controls every
  relevant limit, enumerate every production representation (including recovery,
  wrappers, and variable-size certificates), and derive the intended outermost
  bound. A peer-triggered failure under an incompatible trusted configuration
  validates a configuration or API defect, not adversarial reachability under
  the primitive's intended contract.
- For trusted-setup SNARKs and related proof systems, do not report "knowledge
  of the seed/trapdoor breaks soundness" as a vulnerability by itself. First
  prove that the code or a realistic integration exposes that toxic material
  across an adversarial boundary and that accepted forged proofs reach an
  executed security-bearing state transition; otherwise treat the issue as
  trusted-setup documentation or API-hardening guidance.
- For consensus certificate-admission findings, do not treat missing local
  ancestry backfill as a vulnerability by itself when the received certificate
  is valid under the quorum threshold and the protocol intentionally supports
  certificate-based catch-up. First prove that honest signers can produce the
  certificate without the required ancestry checks, or that a documented local
  reporting, delivery, or descendant-voting contract requires the receiver to
  materialize and replay the ancestry before trusting the quorum certificate.
- For consensus liveness and state-sync findings, use one shared dynamic fault
  ledger across discovery, catch-up, and voting. Count Byzantine, silent, stale,
  lagging, and still-syncing participants against the applicable `f` budget
  whenever they are outside the documented honest synced same-view set. Do not
  compose separately passing sink, persistence, and quorum tests unless one
  integrated schedule satisfies the same budget throughout. For `f+1` floor
  samples, prove that a selected stale floor remains possible despite the
  required current honest reply, retention window, synchrony lag bound, and any
  restart re-probe before treating a local stale-floor wait as reachable.
- For storage crash-safety reviews, distinguish an interrupted sync that may
  roll back from a later operation that can destroy a previously durable
  recovery fallback. In particular, append buffers with alternating checksum,
  footer, metadata, or commit slots must track in-flight async durability
  barriers until the protected slot is durable; a later rewrite must not
  preserve a not-yet-durable slot while overwriting the last durable one. Check
  `start_sync`, `sync`, `replay`, resize, and drop/late-await handle paths with
  out-of-order plain-write durability models.

### Denial-of-Service Review Checks

Use these cross-cutting checks when reviewing any boundary that accepts peer,
storage, application, resolver, certificate, vote, proposal, shard, frame, or
codec input. They apply to CPU, memory, file descriptors, tasks, channels,
timers, storage, and protocol slots.

- Every scarce resource consumed on behalf of untrusted input must have a
  documented bound that is enforced before allocation, spawning, buffering,
  decoding, cryptographic verification, reconstruction, storage writes, or
  forwarding to another queue.
- Length prefixes, advertised counts, shard counts, peer counts, batch sizes,
  ranges, and configuration fields from untrusted input must be capped by
  trusted local configuration before they size buffers, vectors, maps, Merkle
  structures, proof arrays, task sets, or recovery work.
- Allocation up to a trusted caller-provided limit, such as a `RangeCfg`,
  message-size cap, shard-size cap, or peer-set cap, is not by itself a
  vulnerability when that limit is enforced before allocation. Treat such
  candidates as hardening or invalid unless they prove the limit is
  attacker-controlled, absent on a concrete untrusted path, misderived or
  expanded beyond the documented budget, or tied to a measured outage under a
  realistic configured maximum.
- Backpressure is preferred over unbounded buffering. When a consumer is slow,
  the producer, peer, resolver request, subscription, or application callback
  must be slowed, rejected, retried under a bounded policy, or attributed for
  blocking rather than accumulated indefinitely.
- Loops that receive untrusted requests must not spawn one task per item without
  a concurrency bound, queue one item per request into an unbounded channel, or
  retain deferred work in a grow-only collection.
- Dropping excess work is safe only when the protocol explicitly permits loss or
  retry and the drop does not silently strand consensus progress, subscriptions,
  acknowledgements, durable state, or peer attribution.
- Deferred authentication, batching, lazy decoding, and resolver repair are
  acceptable only when all pre-authentication work is cheap or bounded by
  trusted policy, and offending peers remain attributable when invalid input is
  later detected.

### Review Priority Order

#### 1. Simplex-Marshal-Resolver/P2P

This should receive most review time. Prioritize variant analysis around these
exact roots:

- Bind every artifact to the complete identity tuple: namespace, committee,
  epoch, view, parent view, parent payload, payload, and scheme.
- Compare optimistic, normal, recovery, replay, and resolver-delivered paths for
  missing checks.
- Ensure no vote, certificate, report, or network transmission becomes
  externally visible before required durable persistence.
- Treat finalization, nullification, certification, and ancestry-repair messages
  as non-lossy unless an independently guaranteed retry exists.
- Verify cancellation, timeout, replacement, and finalization clean up every
  request, subscription, and retained candidate.

#### 2. Resource Admission and Backpressure

Review the whole path from authenticated ingress to completed work:

receive -> decode -> authorize -> verify -> queue -> mutate state -> respond

At every transition, ask whether the previous bound still applies. Common
historical mistakes include draining a bounded mailbox into an unbounded future
pool, limiting workers but not queued jobs, removing request deadlines before
validation finishes, and dropping protocol-critical messages because an internal
channel is full. Coding Marshal deserves special attention because shard size,
participant count, Reed-Solomon allocation, decoding work, and consensus quorum
availability interact.

#### 3. QMDB and Journal Authentication

This is the broadest recurring defect family. Review it as one multi-component
state machine, not separate journals and Merkle trees.

The highest-value invariants are:

- Equal length never proves equal history.
- A cached root is not enough; readable operations and metadata must be bound to
  it.
- Failed sync attempts must not leave durable hybrid state.
- Root verification must precede publication and durable adoption.
- Recovery must authenticate component relationships, not merely each component
  independently.
- Pruning must preserve every object required by retained roots, floors, and
  restart plans.
- Async sync handles must prevent later writes from destroying the last durable
  fallback.

#### 4. DKG and Stateful Transitions

- Epoch-boundary persistence and registration ordering.
- Split logs or retries that can combine different resharing generations.
- Boundary and anchor retention across pruning.
- Restart behavior between "artifact accepted," "durably committed," and "scheme
  registered."
- Whether imported artifacts have stronger trust assumptions than
  protocol-produced artifacts.

#### 5. Cryptographic Verification Composition

Focus less on primitive arithmetic and more on how verification is composed:

- Batch deduplication keys must match the complete signed message.
- Independent invalid equations must not cancel without verifier-generated
  random weights.
- Transcript encoding must be unambiguous and domain-separated.
- Ordered/unordered or fixed/variable schemas must be authenticated as distinct
  domains.
- DKG and threshold artifacts must be traced through their actual construction
  paths before treating malformed synthetic values as reachable.

#### 6. Panic Severity Calibration

- High: An authenticated Byzantine peer can reliably panic a consensus-critical
  actor or validator using protocol-valid traffic. If the attacker then
  withholds its own vote, crashing one honest validator can prevent a 3-of-4
  quorum.
- Medium: Malicious peer input, proof bytes, or explicitly untrusted storage can
  panic one node, but restart is effective or special state is required.
- Low: Authorized configuration, extreme local state, benign operator error, or
  corruption causes a recoverable one-node panic.
- Informational/invalid: Requires violating a documented caller precondition or
  constructing an internal state no supported path can create.

A panic alone is rarely Critical unless it is remotely repeatable across many
nodes or causes persistent crash loops, corruption, or a broader safety failure.
