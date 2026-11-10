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

### Threats

Each threat is written as "X, because Y", which reads as "X is a threat,
because Y". X is something bad that can happen at a primitive's public
boundary. Y is why it is bad: the consequence for the protocol, its operators,
or its users, never the cause of X. The attack vectors below list the paths
that lead to X.

#### Consensus

1. Two conflicting blocks are finalized, because the application commits
   irreversible state on two incompatible histories and the protocol has no way
   to undo it.
2. Consensus halts indefinitely, because user transactions never settle and
   recovery requires manual operator intervention.
3. An honest validator is reported as faulty in the vote evidence exported by
   consensus, because the slashing system takes its stake for misbehavior it
   did not commit and removes it from the committee, which also shrinks the
   honest majority the protocol depends on.
4. A Byzantine validator's equivocation is not reported in the evidence
   exported by consensus, because it keeps its stake and committee seat, can
   repeat the attack at no cost, and the economic deterrent the fault budget
   `f` implicitly relies on disappears.
5. An honest validator crashes while processing a peer message, because the
   same message can crash every honest validator that receives it, so more than
   `f` validators are down at once and consensus halts until operators restart
   them.
6. An honest validator's memory or CPU is exhausted by peer traffic, because
   the attacker can do the same to more than `f` honest validators for the
   price of bandwidth, so they fall behind the current view and consensus
   stalls.
7. An honest validator is blocked by its peers, because its votes no longer
   reach the nodes that blocked it, they stop counting toward quorum there, and
   it is treated as faulty with no way to clear the block except peer restarts.
8. A notarized block treated as speculatively final is later excluded from the
   chain, because applications that acted on two-hop finality have already
   released goods, revealed outcomes, or sent cross-chain messages, and that
   exposure becomes a double-spend.
9. A Byzantine participant learns the round randomness or next leader before
   the round resolves, because it can front-run lotteries, timelocked data, and
   leader-dependent ordering, and steer leader selection toward itself over
   many rounds.
10. The application receives finalized blocks out of order or with a missing
    height, because it executes a block against the wrong parent state, its
    state diverges from every other node, and the divergence is discovered only
    when it later disagrees on a state root.

#### Broadcast

1. An honest proposer's block is not available to a validator through the
   broadcast buffer in time for it to vote or certify, because the validator
   needs the block to notarize it in inline and deferred mode and to certify it
   in deferred mode, so without it the validator cannot vote, the view times
   out, and the honest proposer's turn is wasted.
2. An honest validator broadcasting a valid block is blocked by the peers that
   cannot decode it, because those peers disconnect it on every channel and
   refuse to reconnect for hours, so its votes do not reach them, its turns as
   leader are wasted, and it counts toward `f` although it did nothing wrong.

#### Codec

1. Two honest parties given the same bytes do not obtain the same value, or
   given the same value do not produce the same bytes, because every signature,
   hash, cache key, and vote above the codec assumes they do, so the parties
   disagree about the identity or validity of a message without any of them
   being Byzantine.
2. Two different byte strings decode to the same value, because deduplication
   and replay caches keyed by received bytes or their hash treat each variant as
   a new message, one signed vote or block can be replayed without limit to fill
   caches and repeat verification, and two honest nodes that hash the bytes
   they received disagree about the identity of the same logical message.
3. A decoded value violates the invariant its Rust type promises, because code
   downstream that relies on the type instead of its own check panics or
   computes a wrong result on the first message carrying it.
4. A short message makes the decoder reserve memory many times its own size
   before any element is read, because the same message can exhaust the memory
   of every honest validator that receives it, so more than `f` validators are
   killed by the OS at once and the attacker pays only the bandwidth of the
   small message.
5. A decoder panics on peer-supplied bytes instead of returning an error,
   because the panic takes down the actor that called it, the same bytes can be
   sent to every honest validator, and with more than `f` validators down
   consensus halts until operators restart them.
6. Validators running adjacent releases can no longer decode each other's
   messages or their own stored records, because every frame from an upgraded
   peer fails to decode and drops the connection, the network partitions along
   version lines until quorum is lost, and a node whose journal format changed
   cannot restart without a manual migration.

#### Cryptography

##### bls12381

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
   completes, because a coalition holding those shares plus its own can recover
   threshold certificates for a second conflicting block, so the threshold the
   dependent consensus relies on for safety no longer holds and the epoch's key
   must be abandoned.
8. Honest participants finish the same DKG round holding shares of different
   keys or different public polynomials, because their partial signatures never
   combine into one certificate, the committee certifies nothing until the next
   successful reshare, and each group treats the other as faulty.

##### ed25519 and secp256r1

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

##### handshake and chacha20_poly1305

1. A listener completes a handshake believing the dialer is one identity while
   the shared secret is actually held by another, because application records
   on that connection are credited to a validator that never sent them, so
   votes, blocks, and DKG private dealings are accepted from or delivered to
   the wrong party.
2. A listener performs the full signature verification, key exchange, and
   signing work for a replayed Syn message, because an attacker who captured
   one valid Syn spends only bandwidth to burn the listener's CPU for the whole
   acceptance window, and the dialer named in the Syn fills the listener's
   per-peer connection slots so the genuine dialer is refused.
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

##### reed_solomon and lthash

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

##### certificate, transcript, and secret

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

##### bloomfilter and zk

1. A bloom filter fed attacker-chosen items answers true for every query,
   because a node that uses it to skip already seen messages drops everything,
   or if it uses it to admit unseen messages floods itself, so gossip for that
   node stalls.
2. A golden DKG dealing is accepted although its masked shares were not derived
   from the dealer's eVRF key, because the dealer can give different players
   inconsistent shares in a protocol whose only defense is public
   verifiability, so players finish with shares of different polynomials and
   the committee cannot certify until a reshare.

#### Coding

1. Two honest nodes decode different data from shards that all verified against
   the same commitment, because validators execute different blocks under one
   finalized commitment and their state roots diverge with no protocol
   mechanism to tell which node is wrong.
2. Two honest validators disagree about whether the same shard is valid,
   because each blocks the peer whose shard failed its own check, honest
   validators block each other, their shards and votes stop flowing between
   them, and the block cannot be reconstructed even though enough honest shards
   exist.
3. Every validator's assigned shard passes verification for a commitment that
   no set of shards can decode, because validators cast their notarize vote on
   shard validity alone, the notarized block can never be reconstructed or
   certified, the view is lost, and marshal keeps requesting a block that does
   not exist until the record is evicted.
4. A shard is accepted at a position other than the one it was encoded for,
   because the shard engine marks that participant's index as contributed, the
   honest owner of the index is blocked as an equivocator when its real shard
   arrives, and reconstruction fails or never gathers enough distinct indices.
5. An honest node re-encodes a block and obtains a commitment different from
   the one the honest proposer published, because the proposer's block fails
   validation at every peer, the honest leader is treated as faulty and its view
   is nullified, and a committee whose members run different strategies or
   builds never agrees on any block.
6. An honest validator crashes while checking or reconstructing a block from
   peer shards, because a leader or relayer can send the same shards to every
   honest validator, so more than `f` validators are down at once and consensus
   halts until operators restart them.
7. A block that a quorum voted to notarize cannot be reconstructed, because
   reconstruction needs `minimum_shards` correct shards and only the honest
   holders are sure to serve theirs, so a threshold above the honest share lets
   `f` withholding validators turn a notarized block into one that no honest
   node can ever certify or execute.

#### P2P

##### authenticated

1. A validator stops admitting new connections from honest peers while
   unauthenticated strangers hold its handshake slots, because the peers it
   has lost cannot reconnect, their votes and proposals stop reaching it, it
   drifts behind the current view, and the operator can only restore service by
   fronting the node with an external filter.
2. A message is delivered to the application attributed to an honest peer that
   never sent it, because the consensus engine counts the attacker's vote as
   that peer's, blocks or reports that peer for the attacker's invalid data,
   and the attacker's own identity never appears in any log.

##### discovery and lookup

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
3. Two honest peers that disagree on the membership of a peer set disconnect
   each other whenever one of them gossips the disputed set, because no
   application message crosses that link before it is torn down, the reconnect
   cooldown keeps them apart for most of each minute, and a membership change
   applied at different times on different validators looks like a network
   partition until the application resynchronizes.
4. Any peer admitted to any tracked set, including a follower-tier secondary
   peer, learns the ingress address of every validator the responder is
   connected to, because validators can then be targeted one by one with
   volumetric or handshake floods that the p2p layer cannot absorb, and a
   permissionless follower tier turns the validator address list into public
   information.

##### router

1. Messages from honest peers are silently discarded at the receiving node when
   a channel's shared inbound mailbox or a mux subchannel queue is full,
   because the consensus engine never sees the votes or certificates they
   carried, the view times out and must be nullified, and an attacker needs
   only enough admitted identities and a consumer slower than its drain rate to
   make honest traffic disappear.
2. The application is told a message was sent to a peer that will never receive
   it, because the voter or broadcaster does not retry, the peer has to recover
   the proposal or certificate through backfill, and a leader with several slow
   links sees its views time out while its own accounting shows every message
   as delivered.
3. A validator's own vote is refused at submission while it answers a burst of
   backfill or broadcast requests, because the vote is never transmitted, the
   validator misses a view although it is honest and online, and the peers that
   caused the burst only asked for data they were entitled to request.
4. All traffic from an honest peer to a node is delayed while that peer exceeds
   its quota on any single channel, because its votes on the consensus channel
   arrive late or after the view has moved on, a burst that is normal under
   load on one channel costs it participation on the others, and if the backlog
   outlasts the write timeout the connection drops and a reconnect cooldown
   follows.
5. Honest peers running an older or newer message format are blocked for hours
   by the peers that cannot parse them, because the two halves of a rolling
   upgrade stop exchanging votes and blocks, the committee can sit below quorum
   until the blocks expire, and operators must restart nodes to clear the
   blocks early.

#### Stream

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
6. Two nodes configured for different applications, networks, or protocol
   versions complete a handshake with each other, because every record they
   exchange is framed for the other deployment and fails to decode, each side
   blocks the other as malicious, and a validator that reuses its key on a test
   network is cut off from the network it meant to join.

#### Storage

##### qmdb

1. Two honest nodes that applied the same finalized blocks hold databases with
   different roots, because the node that diverged votes against every valid
   block and never gets its own proposals accepted, and once more than `f` nodes
   diverge no block can be finalized.
2. A proof that a key holds a value the database never recorded as its current
   value verifies against a finalized root, because light clients, bridges, and
   rollup verifiers that accept the proof release funds or honor state the chain
   never agreed to, and the committed root gives them no way to detect the
   forgery.
3. An exclusion proof verifies for a key that is active in the database, because
   a verifier that trusts it treats an existing account, nullifier, or
   registration as absent, so an attacker can double spend a note, re-register
   an identity, or claim a balance that already belongs to someone else.
4. An honest node cannot produce a verifiable proof for a key that is active
   under a published root, because users whose withdrawals, bridge transfers, or
   settlements depend on presenting that proof are stuck, and the relaying
   service has no other source for it until the node is repaired or the state is
   re-committed.
5. State whose commit was reported durable is missing after a restart, because
   the node has already acknowledged the matching finalized blocks to marshal,
   marshal has pruned them and will not redeliver them, so the node must resync
   from peers, and if enough nodes lose the same state the finalized history
   survives only while some peer still holds it.
6. After a crash the database reopens at a state that was never committed,
   because the node builds on history the network never finalized, serves that
   history to syncing peers and proof requesters as if it were canonical, and
   the fault surfaces only when its root later disagrees with a finalized block.
7. A node fails to reopen its database after a crash or restart, because the
   validator stays out of the committee until an operator wipes the database and
   resyncs from peers, counts toward `f` while down, and a failure that
   reproduces on every node at the same point halts the network.
8. Pruning removes operations or Merkle nodes that the retained root, the
   inactivity floor, or a later restart still needs, because the node can no
   longer serve state sync or proofs for live keys, syncing peers and light
   clients that depend on it receive errors instead of data, and when the node
   restarts at a checkpoint whose history is gone it has to be rebuilt from
   peers.
9. Two replicas at the same root return different values for the same read,
   because an application that reads such a key while executing a block
   produces different state on different nodes, and the divergence appears as a
   root mismatch several blocks later with no record of which read caused it.
10. An honest validator crashes or exhausts memory while answering a peer's
    state sync request or decoding a peer's response, because the same cheap
    messages can be sent to every honest validator, so more than `f` validators
    are down at once and the network stops finalizing blocks.

##### qmdb/store

1. Writes whose commit returned successfully are missing after a restart,
   because the application has already told its users and downstream systems
   the data is saved, so it loses or repeats work it believed complete and has
   no record of what was lost.
2. The store reopens with writes that were never committed, because the
   application resumes from a state it never acknowledged, and any external
   effect it tied to the commit boundary, such as a sent message or a released
   lock, is now inconsistent with what the store reports.

##### qmdb/sync

1. A state sync completes and persists a database whose history is not the one
   the target root commits to, because the node joins the committee holding
   state the network never agreed on, executes and votes on blocks from it,
   serves it to the next syncing node and to proof requesters, and the error is
   noticed only when its root first disagrees with a finalized block.
2. A node that is syncing from peers never reaches its target although honest
   peers hold the data, because the node cannot join or rejoin the committee,
   counts toward `f` for as long as it is stuck, and several nodes recovering at
   once can leave the network below quorum while the attacker pays only for a
   few bad responses.
3. A failed or interrupted sync leaves the node with durable state it can
   neither resume from nor reopen as its previous database, because the node
   loses its last good local checkpoint, must be wiped and resynced from
   scratch, and its downtime grows from a restart to a full state transfer
   during which it counts toward `f`.
4. A syncing node runs out of memory while one slow or withholding peer leaves a
   request unanswered, because the node is killed before it ever joins the
   committee, and an attacker who controls one of the peers it fetches from can
   repeat this at no cost beyond keeping a connection open.

##### merkle

1. A proof verifies for an element at a location the structure never held,
   because a light client or bridge releases funds or accepts a cross-chain
   message for an operation no validator ever committed, and the certified root
   lends that fabrication the authority of the whole committee.
2. Two honest nodes compute different roots from the same sequence of appended
   elements, because the validators disagree on the state root of every block
   from then on, the side with fewer nodes is outvoted and treated as faulty,
   and nobody can tell which history is wrong without manual inspection.
3. A node panics while computing its root or pinning nodes after it has pruned
   old history, because the database stops accepting blocks until an operator
   rebuilds it from an unpruned peer, and the node is out of the committee for
   the whole rebuild.
4. A persisted structure reopens after a crash with a root different from the
   one it had committed and reports no error, because the node resumes voting
   on state roots no other validator can reproduce, is outvoted on every block,
   and the only remedy is for an operator to notice, wipe its storage, and
   resync.
5. A persisted structure refuses to reopen after a crash or an interrupted
   state sync, because the node stays out of the committee until an operator
   deletes its state and completes a full resync, and it counts toward `f` the
   whole time.
6. A syncing node accepts operations or pinned nodes from a peer that do not
   belong to the database with the target root, because it finishes the
   download only to fail the final root check, discards everything, and starts
   over, so one malicious source can keep a new validator from ever joining
   while it counts toward `f`.
7. A proof generated by an honest node fails to verify at another honest node,
   because light clients and bridges reject genuine state, state sync stalls
   while the honest source is marked invalid, and new validators cannot join.
8. A node's memory or CPU is exhausted while decoding or verifying a
   peer-supplied proof, because the same proof can be sent to every validator
   that serves or runs state sync, so more than `f` validators are killed by
   the OS or fall behind the chain at once while the attacker spends only
   bandwidth.

##### bmt

1. A shard proof verifies against a commitment for shard data the encoder never
   placed at that index, because honest nodes decoding the same certified
   commitment reconstruct different block bodies or fail to decode, so a block
   the committee finalized has no single agreed content and execution forks or
   stops.
2. Two different sets of leaves produce the same root, because an encoder can
   hand different validators different shards under one commitment, the
   committee certifies a commitment that identifies no single block, and the
   chain's content at that height depends on which shards each node received.
3. A shard proof produced by an honest encoder fails to verify at an honest
   receiver, because the receiver blocks the peer that relayed it as a sender of
   invalid shards and drops a shard it needed, and when enough receivers do this
   the block cannot be reconstructed and the honest leader's slot is lost.
4. A node panics or exhausts memory while verifying a peer-supplied shard
   proof, because every shard delivery is a chance to trigger it and the same
   proof can be sent to every honest validator, so more than `f` validators are
   down at once and consensus halts until they are restarted.

##### bitmap

1. A proof verifies a bit with the opposite value from the one the bitmap
   holds, because a verifier that uses the bit to tell live state from history
   accepts a superseded balance or an already consumed withdrawal as current, or
   rejects a live one, and a bridge paying out on that answer loses the funds.
2. Two honest nodes compute different roots for the same sequence of bits,
   because the combined operations and activity root a current database commits
   per block differs across validators, they disagree on the state root of every
   later block, and the minority side is outvoted and treated as faulty.
3. A bitmap restored from its persisted pruned state plus a replay of retained
   elements has a different root than it had before the restart, because the
   node's current-state root diverges from the network after every restart and
   stays wrong until an operator wipes and resyncs it.
4. A node panics when asked for a bit or a proof at an already pruned location,
   because a caller that exposes location-addressed queries to peers or clients
   goes down on one request and goes down again on every retry until an
   operator restarts it.

##### journal

1. An item that `sync` reported durable is missing from replay after a restart,
   because the simplex voter relies on replay to remember the votes it already
   broadcast, signs a conflicting vote or nullify for the same view, and the
   equivocation evidence it produces gets an honest validator slashed and
   removed from the committee.
2. The item returned for a position or offset is not the item that was appended
   there, because callers address Merkle leaves, operations, and votes by
   position, rebuild authenticated state or vote history from the wrong
   records, and end up with a state root or vote set that no other honest node
   shares.
3. A journal that opened cleanly before fails to open or replay after a restart,
   because the voter, the aggregation engine, and the DKG reshare store all
   panic at startup, the validator stays out of the committee until an operator
   deletes the journal by hand, and deleting it also throws away the vote record
   that stops the node from equivocating.

##### archive

1. A read of a block or certificate that was committed long ago fails with a
   corruption error, because marshal panics on any archive read error, a peer
   can trigger that read by requesting the block, and the node crashes every
   time it is asked until an operator repairs the files by hand.
2. An index below the prune floor is stored and served again after a restart,
   because the archive's range reports count it as present, marshal's gap repair
   requests every height between it and the live floor from peers, and the node
   spends bandwidth and disk on history it had already discarded.
3. An archive that reported a successful sync comes back empty, or rewound to an
   earlier commit, after a restart, because the finalized blocks and
   certificates marshal already acknowledged to the application are gone,
   marshal's recorded processed position has no stored block behind it, and the
   node panics on startup until an operator wipes its state and resyncs from
   peers.
4. The archive reports a height as present that it cannot serve, because marshal
   panics during gap repair, the application stops receiving finalized blocks
   at that height, and the node falls permanently behind the chain.
5. Archive initialization fails on a damaged or mismatched record, because
   marshal and the DKG bootstrap panic before they can deliver or serve
   anything, and the validator stays out of the committee until an operator
   intervenes.

##### freezer

1. Lookups for keys that share a table slot with attacker-chosen keys take one
   disk read per colliding key, because a Byzantine proposer can grind block
   digests into the slot of an honest block in a few thousand hash tries, and
   every honest validator's lookups for blocks in that slot stay slow for as
   long as the archive is retained.

##### metadata

1. The store comes back holding the previous version's values after a restart
   that followed a successful sync, because the archives and marshal caches that
   use it as their commit record rewind to an older checkpoint and delete data
   written since, and a DKG state-sync plan that was already consumed and
   removed is applied again at the next startup.
2. Metadata initialization fails with a corruption error, because every store
   built on it panics at startup, the node stays down, and the only operator
   remedy is to delete the metadata, which then wipes the archives that depend
   on it.

##### ordinal

1. A record the caller marked as committed is reported present but fails to
   read, because consumers treat presence as truth, marshal's gap repair panics
   when the read fails, and the node cannot finish startup.

##### index

1. Lookups and inserts for attacker-chosen keys take time linear in the number
   of colliding keys, because a QMDB-backed application pushes every operation
   of every block through the index, block execution slows on each honest node
   that uses the same translator, and validators miss view deadlines while the
   attacker pays only the cost of grinding short key prefixes.
2. A lookup yields values that were stored under other keys, because a caller
   that treats the first value as the answer reads or overwrites a different
   record, and in a key-value database that means one account's slot is read or
   updated in place of another's.

##### queue

1. An item is delivered to the reader a second time after a restart, because a
   consumer that performs a side effect per item, such as sending a message or a
   payment, repeats it.
2. An item the writer accepted is gone after a restart, because the writer's
   caller already treated the work as handed off, nothing re-enqueues it, and
   the task is silently never performed.

##### translator

1. Keys chosen by an attacker collide in the translated key space, because every
   structure keyed through the translator degrades to a linear scan over the
   colliding records, and with the marshal cache keyed by the first two bytes of
   block digests a Byzantine proposer can grind digests cheaply to slow the
   lookups every honest validator performs on each view.

#### Glue

##### dkg

1. An epoch's reshare ceremony fails and the next epoch keeps the previous
   threshold output, because the validators the application selected never
   receive shares, operators who left the committee keep shares that still sign
   for any round, and shares leaked earlier are never refreshed.
2. An epoch's threshold output is installed with more than `f` of its players'
   shares published in finalized dealer logs, because a Byzantine coalition can
   then complete threshold signatures without an honest quorum and forge the
   certificates that consensus, state sync, and the probe accept as proof of
   finality.
3. An honest validator cannot derive the epoch's final block payload and leaves
   that block's verification unresolved, because it counts against the fault
   budget at the boundary, and once more than `f` validators are in that state
   the final block never finalizes, the chain stops at the epoch boundary, and
   recovery needs operators to roll those nodes back to a point before the
   midpoint.
4. Honest validators derive different epoch infos for the same final block,
   because no proposal at the boundary height gains a quorum and the chain
   halts until operators fix the participants provider on every node, or, where
   a quorum does agree, the dissenting honest validators enter the next epoch
   without a signing share and count toward `f` for the whole epoch.
5. Every validator panics at the same epoch boundary, because the network stops
   producing blocks, each restart re-derives the same final block and panics
   again, and the chain stays down until operators ship corrected code or
   configuration.
6. A validator's orchestrator exits at an epoch boundary and the node never
   re-enters consensus on its own, because it counts toward `f` for as long as
   it is out, operators must perform a manual state sync, and a second such loss
   in the meantime takes the committee below quorum.
7. A joining node adopts a state-sync floor and committee that the network never
   finalized, because it syncs to attacker-chosen state, activates the
   attacker's peer directory, and follows a private fork for as long as the
   attacker keeps feeding it.
8. A joining node's bootstrap never completes or resolves to an epoch the
   network has long left, because new or replaced validators cannot be onboarded
   until someone hand-distributes a fresh checkpoint, and the committee keeps
   shrinking toward quorum in the meantime.
9. A restarted dealer deals a different polynomial than before its restart and
   blocks the honest players that acknowledged the first one, because those
   players stay disconnected from it until a restart, its log is unusable, and
   the ceremony loses both its contribution and the connectivity consensus
   needs between those peers.

##### stateful

1. Every honest node panics while applying the same finalized block, because
   the whole network stops at that height at once, a restart reproduces the
   panic since marshal redelivers the block, and only a coordinated code or
   data fix brings the network back.
2. A block is finalized whose committed state root matches no honest node's
   database, because light clients and bridges that verify proofs against that
   root reject the valid proofs honest nodes produce and accept proofs the
   proposer crafted against a root only it knows.
3. The application's finalized hook runs a second time for a block the node
   already applied, because external effects driven from the hook, such as
   payouts, notifications, or outbound messages, are emitted twice and the
   application's users receive the duplicate.
4. A node that joined through state sync never runs the capture or finalized
   hooks for the blocks between its previous tip and the sync anchor, because
   every record the application derives from those hooks, such as an event
   index or receipts, has a hole on that node and its clients cannot tell the
   gap from the blocks never having happened.
5. A node cannot open its databases at the block marshal last acknowledged and
   panics at startup, because the only remedy is to wipe local state and
   re-sync from peers, the validator is absent for the whole rebuild and counts
   toward `f`, and a storage fault shared across operators takes several
   validators down in the same restart.
6. A validator that fell behind never rejoins consensus, because it declines
   every proposal and defers every verification while syncing, counts toward
   `f` the whole time, and the operator must wipe it and rejoin it as a new
   node, so a network with short block retention loses every validator that
   suffers a long outage.
7. A node stops applying finalized blocks and acknowledging marshal without
   crashing, because process supervision never restarts it, block delivery to
   the application stops once the acknowledgement window fills, and the node
   looks healthy while it contributes nothing and counts toward `f` until an
   operator notices.
8. A validator misses votes and leader slots while it serves peers' state sync
   and probe requests from its live databases, because it earns nothing for
   those views, the requesters pay only request bandwidth, and draining several
   validators at once shrinks the network's effective quorum.
9. A node that needs a floor never obtains one and never begins state sync,
   because operators cannot add or replace validators after committee churn,
   and a network that has already lost nodes cannot restore its fault budget.

##### transfers

1. A settled transfer is applied again in a later block, because the payer is
   debited and the payee credited a second time, and nothing in the ledger can
   undo it once that block finalizes.
2. Honest nodes settle the same finalized block to different accounts, because
   their state roots diverge, no later block that commits a root can gain a
   quorum, and operators must decide by hand which copy of the ledger is
   canonical.
3. A batch settles to balances that do not conserve the value it moved, because
   value is minted for or destroyed from whoever holds the affected accounts and
   every later balance builds on the wrong figure.
4. A proposer builds a block whose transfers verifiers settle as rejected,
   because the block is never certified, the leader's turn is wasted, and in a
   reshare epoch the dealer log it carried misses the inclusion window.
5. A validator spends far more time or memory settling a block than the block's
   size justifies, because it misses the view deadline, the block times out, and
   a Byzantine leader can repeat the cost on every turn while paying only the
   block.

#### Runtime

##### storage

1. A vote the node already broadcast is missing from its journal when the node
   restarts after a crash, because the restarted node treats that view as
   unvoted, signs a conflicting vote, and the resulting equivocation is
   slashable and shrinks the honest majority the protocol depends on.
2. A write sequence that survives power loss on a developer's macOS machine
   loses its earlier unsynced bytes on a Linux validator, because the recovery
   path that handles the resulting gap is never exercised before deployment,
   and the first time it runs is on a live validator's vote journal.
3. Two processes write the same storage directory at the same time, each
   believing it is the only instance of that validator, because both sign and
   broadcast votes under the same key, their interleaved writes corrupt each
   other's recovery state, and the validator is slashed for equivocating against
   itself.
4. A restarted node blocks before user code runs, waiting for the storage
   directory hold while the previous process's storage threads are still alive,
   because the validator is absent from the committee and counted toward `f`
   for as long as nobody notices, and the only signal is one warning log line.
5. After a power loss a blob holds a record that is partly new bytes and partly
   old bytes, because a reader that trusts the blob length or a record's own
   length prefix decodes garbage as a vote or a block, and either refuses to
   start or acts on data nobody wrote.
6. A blob whose creation was interrupted by a crash fails every later open with
   a corruption, layout, or version error, because the node cannot start until
   an operator identifies and deletes the half-created file, and it stays out
   of the committee the whole time.
7. A write or resize whose future the caller dropped completes on disk after the
   caller has moved on, because the caller's later writes land at offsets
   computed from a stale size, overwrite live records or leave holes that
   recovery trims, and committed entries disappear.

##### network and I/O

1. The runtime allocates a receive buffer of the full requested length before a
   single byte arrives, because one unauthenticated host can make every
   validator it connects to allocate gigabytes, so more than `f` validators are
   killed by the OS at once while the attacker sends only a few bytes.
2. Every I/O request on an io_uring worker stalls behind receives that occupy
   all of the ring's in-flight slots, because journal syncs and sends to honest
   peers on that worker wait up to the receive timeout, the node misses its view
   deadlines, and the attacker needs only idle connections.
3. The listener reports a terminal-looking error for a transient accept failure
   such as descriptor exhaustion, because the consumer either stops accepting
   inbound connections for the life of the process or retries in a hot loop
   that starves the other tasks on that worker, and honest peers cannot dial in
   while the attacker pays only for half-open connections.
4. A connection to an honest peer is closed after one receive or send on it was
   cancelled or exceeded its timeout, because every in-flight consensus message
   on that link is lost, both sides must re-handshake, and a consumer that races
   a receive against a timer tears down healthy links repeatedly, which looks
   to the rest of the committee like a flapping validator.

##### scheduling, supervision, and time

1. A timer armed for a future deadline fires immediately when the host clock
   steps forward, and a timer armed before a backward step fires late by the
   size of the step, because view timeouts built on those timers nullify a live
   leader's view early or let a stalled leader hold a view far past its
   deadline, and rate limiters keyed on the same clock either admit a burst or
   refuse honest peers until the clock catches up.
2. A long-lived actor stops running while every other task in the node
   continues, because the node keeps serving metrics, holding connections, and
   answering peers, so nothing restarts it, it stops voting or relaying for as
   long as nobody reads a single error log line, and it counts toward `f` the
   whole time.
3. A task spawned from a future that was later dropped keeps running until the
   task that spawned it exits, because it continues to send requests, write
   storage, and hold resources for an operation the caller already abandoned,
   duplicating or contradicting the caller's replacement work.
4. Shutdown never completes because a dedicated or blocking task that never
   yields cannot observe its abort, because the process stays alive holding its
   ports and the storage directory hold, the replacement process blocks on that
   hold, and the operator must kill both by hand while the validator is absent
   from the committee.
5. On the io_uring runtime, timers and I/O completions registered on one worker
   are delayed for as long as any task on that worker runs a long synchronous
   poll, because view timeouts and journal syncs owned by tasks that have since
   moved to other workers fire late, and a burst of expensive verification work
   triggered by one peer slows the node's consensus progress.
6. Two runs of the deterministic runtime with the same seed take different
   paths, because a failure found by a fuzzer or CI cannot be reproduced from
   its seed, is dismissed as flaky, and ships to validators where it recurs
   under real scheduling.
7. A recovery path passes every simulated crash but fails on a real disk,
   because a journal that mishandles a half-written record survives the test
   suite and corrupts a validator's state after its first power loss.

#### Resolver

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

#### Collector

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

### Attack Vectors

The paths by which a peer, a Byzantine participant, an application callback, or
damaged storage reaches a threat above.

#### Consensus

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

#### Broadcast

- Untrusted peer broadcast and caching behavior.
- Rate limiting and backpressure gaps.
- Subscription/waiter retention and cancellation.
- Replay and deduplication failures.
- Withholding or delaying a block a validator needs to vote.
- Codec-boundary decode issues before admission.
- Codec limit or version drift between honest peers.

#### Codec

- Decode bounds missing or enforced after allocation.
- Non-canonical or ambiguous encodings.
- Allocation before validation.
- Encode/decode round-trip and version-compatibility breaks.
- Truncated or trailing-byte acceptance.
- Decoders that panic or skip type invariants instead of returning an error.

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
- Sizes taken from peer-supplied shares, proofs, or shard parameters without
  bounds.
- Nonce or key reuse across records or connections.
- Reconstruction from shards whose contents are not authenticated.
- Non-cryptographic or collision-prone hashing of attacker-chosen inputs.

#### Coding

- Shard-width amplification.
- Pathological coding configuration.
- Reconstruction threshold above the honest share of shards.
- Non-canonical codewords.
- Shard identity or commitment confusion.
- Verification and reconstruction flooding.
- Check and re-encode results that differ between honest nodes.

#### P2P

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

#### Stream

- Missing zeroization or forward secrecy.
- Unknown-key-share, key-compromise impersonation, MITM, reflection, and selfie
  attacks.
- Invalid-curve and parameter-confusion attacks.
- Ephemeral key reuse.
- Cross-protocol attacks.
- Bleichenbacher-style signature forgery.
- Plaintext or length exposure before authentication.
- Record reordering, replay, or injection on an established connection.
- Key rotation and transcript-hash binding bugs.
- Nonce overflow or reuse.
- KDF misuse for transport keys.
- Handshake replay and per-stage size bounds.

#### Storage

- Recovery that selects a wrong or uncommitted tail after a crash.
- Durable record, metadata, and checkpoint corruption.
- Proof and authenticated-state validation gaps.
- Pruning and replay inconsistencies.
- Untrusted or peer-derived durable-state handling.
- Oversized or malformed proofs and sync responses.
- Non-deterministic merkleization or floor handling across nodes.
- Key grinding against translators, indexes, and tables.
- Sync reported before data is durable.

#### Glue

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

#### Runtime

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

#### Resolver

- Peer scoring shared across keys and unchanged by partial answers.
- Targeted fetches with no fallback to other peers.
- Consumer verdicts that block peers for locally stale reasons.
- Serving every request from storage without a per-peer budget.

#### Collector

- Response counting without validation.
- Handlers invoked for requests from any connected peer.
- Blocking on decode failures between honest peers.

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

### Top 10 Lessons Learned

1. Trace the complete production path, not just the suspicious sink.
   Many claims missed an earlier guard, wrapper, ordering guarantee, deduplication step, or later validation.
   Examples include acknowledgements already checking quorum before buffering and resolver subscribers being retained elsewhere.
   Lesson: document the full input → validation → state transition → sink path.
2. Respect documented API preconditions.
   Reproductions frequently passed duplicate signers, orphaned batches, invalid indexes, or reused resources after terminal errors. The panic or corruption mechanism was real, but the caller behavior was explicitly unsupported.
   Lesson: reproduce through a compliant public caller before reporting an implementation vulnerability.
3. Prove the actor actually controls the input across an intended trust boundary.
   Local configuration, trusted setup, application subscriptions, filesystem contents, and internal reporter channels were repeatedly treated as malicious peer input.
   Lesson: name the actor, capability, ingress, and ownership of every prerequisite.
4. Use one consistent quorum and fault-budget ledger.
   Several consensus schedules silently exceeded f, required mutually impossible quorum artifacts, or ignored what honest signers prove by producing a valid certificate.
   Lesson: enumerate every Byzantine, offline, stale, lagging, and unsynchronized participant throughout the entire schedule.
5. Do not substitute a preferred design for the documented invariant.
   At-least-once redelivery, lazy verification, certificate-based catch-up, cache eviction, and retained certification work were sometimes intentional semantics rather than defects.
   Lesson: state the source-backed invariant before judging observed behavior.
6. A harness can prove a sink without proving production reachability.
   Synthetic serialized DKG output, directly populated internal maps, inconsistent test configurations, incomplete fuzz oracles, and deliberately parked synchronization contexts produced convincing failures that normal construction could not produce.
   Lesson: construct state through production constructors and real actor transitions.
7. Validate the claimed impact after all recovery and fallback paths.
   Some mechanisms produced only the expected faulty-leader delay, local hardening concern, cache miss, or recoverable retry—not permanent liveness loss, safety failure, or remote DoS.
   Lesson: demonstrate the worst claimed observable outcome, not merely an intermediate bad state.
8. Use a supported configuration and composition.
   Findings depended on explicitly disabled merge-train states, incompatible roots, non-compliant custom electors, unsafe transports, or reporter compositions different from the shipped integration.
   Lesson: establish that the exact configuration is documented or constructible by supported APIs.
9. Pin and recheck the exact revision.
   Several reports described earlier code, code absent from the recorded PR head, or implementations present only in closed unmerged PRs.
   Lesson: verify every cited function and defense at the recorded revision before triage.
10. Quantify resource exhaustion against enforced bounds.
    Allocation or retention was often bounded by a trusted codec cap, peer-set size, handshake reservation, resolver coalescing, or concurrency limit.
    Lesson: record attacker cost, amplification, default maximum, concurrency, cleanup, and measured outage.

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
