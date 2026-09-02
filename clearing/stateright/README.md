# Bajillion Stateright model

This directory contains Bajillion's executable Rust model. Stateright explores every reachable
state in each declared finite instance to a fixed point. There is no depth cutoff, randomized
sampling, or hand-seeded terminal state in the exhaustive checks. Deterministic traces separately
exercise the longer user journeys and rejected calls against the same transition functions. A
bounded implementation-refinement suite then executes the same settlement actions through real
signed Bajillion objects and compares production state to the abstract state after every step.

The complete protocol diagrams live in the
[Bajillion module documentation](../src/bajillion/mod.rs). The checked composition is:

```text
REGISTERED PROOF CONTEXT
        |
        | prepare -> deal -> missing / incomplete / exact delivery
        v
  honest validator seal
  - every assigned slice
  - every distinct payer/operator signature
  - typed openings, rows, outputs, and coverage
        |
        +-- reject malformed/incomplete attempt
        |        |
        |        +--> reset attempt-local state and retry
        |             under the same live registration
        |
        +-- exact 2f+1 certificate --> sound CertifiedClose capability

OPEN SETTLEMENT SLOT
        | register exact next epoch and predecessor
        v
REGISTERED -- missed admission deadline ------------------------------+
        | certified admission (CertifiedClose)
        v
OPEN + [Pending e, Pending e+1, ...]
        |
        +-- front now > challenge deadline --> finalize front
        |                                      create reserves
        |                                      advance head
        |                                            |
        +<---------------- next operating FIFO state +
        |
        +-- proven challenge --> challenge target; invalidate suffix --+
        |                                                               |
        +-- pending deposit or withdrawal expires ----------------------+
                                                                        |
                                                                        v
                                                               PERMANENT FAULT
                                                                        |
                                                    drain every earlier clean
                                                    Pending prefix in FIFO order
                                                                        |
                                                                        v
                                                       freeze last finalized root
                                                           +------------+-----------+
                                                           |                        |
                                                    claim each state       refund each account's
                                                    position once          aggregate deposit once
                                                           |                        |
                                                           +------------+-----------+
                                                                        v
                                                                     SETTLED

Finalized withdrawal and external-payout reserves remain independently claimable before,
during, and after terminal recovery.
```

An empty registration slot has no heartbeat. A registration activates one immutable payment
context. Missing its inclusive admission window is therefore a permanent fault, not a retry that
reopens the slot. Failed construction or certification can retry under the same still-live
registration.

## Model decomposition

| File | Exhaustive responsibility |
| --- | --- |
| `certification.rs` | A four-validator, two-slice `n = 3f + 1`, `q = 2f + 1` instance. It explores the valid verifier result plus 27 distinct local failure classes on either slice, missing/incomplete/exact delivery, every exact quorum, durable retention, rejection, and same-registration retry. The failure classes abstract outcomes of the production verifier. They do not reimplement cryptography or Merkle proofs. |
| `challenge.rs` | All settlement targets and every payer-signature, operator-signature, and context-authentication bit combination over representative semantic endpoints. It separately checks structural validity, semantic contradiction, and `NoContradiction` for the three acknowledgment challenge kinds: a retained endpoint above the committed terminal debit, a retained per-edge entry above the committed public entry, and an operator acknowledgment fork at one payer sequence number. The higher-debit kind is modeled as the strictly-higher-debit arm only. The production adjudicator's sequence arms (a different countersigned body at the committed sequence, an equal endpoint at a strictly later sequence, and the earlier-retry and credit-only declines) are pinned by unit tests in `src/bajillion/tests.rs`, not by this model. |
| `claims.rs` | Eight exact replay identities: two typed namespaces, two batches, and two positions. It explores every claim ordering while checking typed root identity, output value and position, destination routing, atomic mutation, reserve conservation, and independence across kind, batch, and position. |
| `settlement.rs` | A three-account, eight-candidate, three-pending-slot, bounded-time instance. It explores intake, superset registration with operator-carried requests, deadline ties, certified admission including coverage-degraded and carried-offset closes, strict ancestry and FIFO finalization, challenge suffix cuts, clean-prefix drain, finalized reserve creation, claim routing, replay expiry, custody conservation, and terminal recovery. |
| `scenarios.rs` | Twenty-six deterministic end-to-end traces using the same settlement transition function. They cover accepted and rejected boundaries, every challenge kind, front/middle/tail operator faults, registration and intake expiry, every sender-value bucket, Amount and Close, exact claim routing, replay, and finalized reserves that survive a later fault. |
| `refinement.rs` | Test-only production adapter for the settlement model. It constructs real deposits, signed withdrawals, payments, closes, proof slices, sealed dealings, certificates, challenges, openings, and claims, then checks action acceptance, returned value, and a behavior-relevant private state projection after every step. |

The models compose through two opaque capabilities. A `CertifiedClose` is emitted for one exact
candidate and registration only after the certification transition function reaches exact valid
delivery, quorum formation, a sound certificate, and capability issuance. A merely matching
registered pair cannot issue it. A `ProvenChallenge` is emitted only after the challenge model adjudicates
authenticated evidence for one exact target. The settlement model accepts those capabilities
instead of manufacturing raw certificates or contradictions. The claim model separately owns the
finalized-output ledger. This is an assume-guarantee decomposition: it checks each finite component
to completion without taking the impractical Cartesian product of every proof delivery, challenge
witness, and settlement ordering.

The checked state counts are part of the tests so an accidental state-space reduction is visible:

- 153,886 certification states, including all 27 invalid-proof profiles on either slice and every
  exact quorum and delivery ordering;
- 1,502 challenge states, including every authentication-bit combination for every target, the
  representative endpoint classes for both excess dimensions (cumulative credit and payment
  count), and the equal-endpoint terminal control that must not convict;
- 1,025 claim-ledger states covering every ordering of eight typed batch-position identities;
- 3,000,804 settlement states from the ordinary initial state, including the operator-carried
  registration branch and the coverage-degraded certification branch; and
- 26 deterministic end-to-end scenarios using the same settlement transition function.

The reachability properties require examples for all three challenge kinds, every liveness-fault class and exact tie priority, a full three-close pipeline, four
ordered finalizations, front/middle/tail suffix cuts, exact admission and challenge boundaries,
Amount and Close claims, external payouts, batch-position replay, reserve survival after a later
fault, exact front/middle/tail and registration-expiry recovery outcomes, a carried withdrawal
clearing at full value, a degraded amount finalizing with a zero reserve, an uncovered
carried amount degrading at the frozen root, and a carried offset deferring its staged deposit. Each safety predicate
also has a deliberately corrupted negative-control state so a disconnected or vacuous property
fails its ordinary Rust test.

## Evidence matrix

| Obligation | Exhaustive finite graph | Deterministic trace | Production refinement |
| --- | --- | --- | --- |
| Exact dealing, quorum intersection, retention, and retry | `certification.rs` | Certification unit traces | Every refined admission runs `assemble_slices`, `seal`, certificate formation, and `admit`. Malformed-dealing tests remain separate |
| Both signatures, typed lookups, and challenge relation | `challenge.rs` | Every challenge edge in `scenarios.rs` | Refinement constructs real evidence for all three kinds. Production verifier tests cover malformed evidence and codecs |
| Consecutive admission and FIFO finalization | `settlement.rs` | Skip and out-of-order rejection | Four real epochs refine step by step. Rejected skip/finalize calls must stutter |
| Front, middle, tail, registration, deposit, and withdrawal faults | `settlement.rs` | Exact recovery traces in `scenarios.rs` | Real challenged-suffix and all three deadline classes refine through terminal fund recovery. Broader malicious-operator tests remain separate |
| Typed `(kind, batch, position)` replay and reserve accounting | `claims.rs` | Clean claims and later-fault reserve survival | Real payout, Amount, and Close claims compare outputs, reserves, replay sets, and repeated-call rejection |
| Codec, hash framing, Merkle verification, and signature batching | Not abstracted as byte arrays | Rejected production inputs | Rust unit/integration tests and fuzzing |
| Durable crash cuts and asset transfers | Assumed atomic and idempotent | Not owned by this in-memory crate | Embedding recovery tests |
| Arbitrary cardinalities | Not proved inductively | Larger production fixtures | Quorum algebra plus implementation tests |

"Exhaustive" in this document always means the complete reachable graph of the declared finite
instance. The deterministic traces demonstrate specific causal user journeys. They are not a
substitute for the graph, the bounded implementation-refinement profiles, or crash-consistency
evidence.

## Implementation refinement

The settlement adapter has an exhaustive top-level match over `SettlementAction`. Adding an action
without a production mapping fails compilation. A coverage test also requires a real refinement
path for every action variant. For each mapped call, the test compares acceptance or rejection,
returned custody output, and a private projection containing the finalized root and liability,
custody buckets, staged deposits and withdrawals, deadlines, registration, ordered pipeline and
statuses, replay keys, claim reserves, fault and fence identity, frozen terminal boundary,
and consumed state positions. Per-account deposit refunds and terminal recovery outputs are also
compared exactly. Rejected calls at the already-observed time must stutter. A separate timed-call
profile checks the production rule that observing a deadline may persist a permanent fault even
when the requested operation returns an error.

The profiles cover a four-epoch clean pipeline, strict FIFO finalization, independent external,
Amount, and amountless Close claims, replay rejection, malformed and mispositioned withdrawal
openings, a challenged middle suffix with clean-prefix drain, registration/deposit/withdrawal
expiry, direct deposit refund, terminal state recovery, an operator-carried request that
registers, admits, and claims without ever being queued, and a coverage-degraded close whose
uncovered amount finalizes with a zero release and no claimable output. It also checks that beginning terminal
settlement is idempotently retryable while claims remain.
Every admission uses the production proof-slice assembler and `seal`, so a modeled
`CertifiedClose` reaches settlement only alongside a real authenticated dealing and certificate.
All three challenge kinds use real payer and operator signatures and production openings, so
every abstract contradiction the settlement model can raise has a constructible production
counterpart.

This is bounded trace refinement, not the Cartesian product of the 3,000,804-state lifecycle graph
with cryptographic fixtures. The independent fixed-point model proves the declared finite
interleavings. The refinement profiles catch drift at every production action and state component
they traverse. Neither result is an inductive proof for arbitrary cardinalities or evidence of
durable crash safety.

## Fund-recovery contract

For every modeled permanent fault, new intake and admission stay fenced. A proven challenge may
leave an earlier clean prefix, which must resolve FIFO. No later epoch can skip it. Terminal
settlement then freezes the last finalized state and exposes one replay-protected claim per live
account plus one replay-protected aggregate refund per account with unfinalized deposits. Deposit
IDs remain intake replay keys, but multiple deposits to one account settle together. An Amount
request the frozen balance covers splits the tail into withdrawal and residual, and one it cannot
cover routes nothing with the whole balance residual. An amountless Close sends the entire
authenticated tail to its destination. Clean reserves created before the fault stay in separate
claim ledgers.

The checker proves conservation and enabled recovery, not fairness. Completion assumes an
authenticated monotonic clock, available claim material, eventual claim submission, and an
embedding that persists each returned asset transfer atomically and idempotently with the state
mutation.

## Refinement boundary

The model uses small enums, ideal cryptography, mathematical amounts, explicit proof-fault profiles,
and representative challenge endpoint classes. It does not independently derive the production
Merkle/row verifier or quantify over every numeric payment tuple. The refinement exercises real
hash framing, Merkle verification, BLS certification, randomized payment-signature batching, and
claim openings for its declared fixtures. Broader codecs, arithmetic limits, allocation bounds,
adversarial byte domains, storage crash cuts, and external asset adapters remain covered by
Bajillion's Rust unit tests, fuzz targets, and the embedding's crash-consistency tests. The finite
results establish every reachable state of these instances. They are not an inductive proof for
arbitrary account, validator, slice, or payment counts.

## Why Stateright

Bajillion's central obligations are temporal: many enabled actions can interleave, the first fault
must be retained, an admitted suffix can be cut, and only the clean FIFO prefix may finalize before
recovery. Stateright directly represents that nondeterministic transition system in Rust and checks
`always` and `sometimes` properties over its complete reachable finite graph.

Kani is complementary, not a replacement for this lifecycle model. It is most valuable for a
bounded symbolic harness around one production function, arithmetic boundary, or unsafe block. No
distinct Kani-only obligation was found here: byte-level adversarial inputs already belong to the
production verifier and fuzz targets, while reproducing the temporal scheduler in Kani would add a
second model with substantially higher search cost. A focused Kani harness can still be added if a
specific production-only invariant later warrants it.

## Run

```bash
cargo test -p commonware-clearing --lib bajillion::model
cargo test -p commonware-clearing --lib refinement::
```

The model and refinement are ordinary clearing unit tests and therefore run in the workspace's
normal Rust test jobs. No Node.js, JVM, Docker image, or external model-checker process is required.

## Explore

Stateright's built-in web explorer exposes the actual initial states, enabled actions, successor
states, and property status for each component. Start one component and open the printed URL:

```bash
cargo run -p commonware-clearing --example bajillion_model -- settlement
```

The command accepts `certification`, `challenge`, `claims`, or `settlement`, followed by an optional
listen address such as `127.0.0.1:3001`. Exploration is on demand: the browser follows only the
selected paths unless **Run to completion** is requested. The exhaustive tests remain the canonical
fixed-point check and assert the complete finite state counts above.

The explorer is an interactive action/path view, not a static rendering of every graph node. A
single image containing the settlement instance's 3,000,804 states would not be usable.

There is no single monolithic explorer target. The four models deliberately compose through
`CertifiedClose` and `ProvenChallenge` capabilities so the checked graph does not multiply every
proof delivery and challenge witness by every settlement ordering. The deterministic scenarios are
named paths through the same settlement transition function, not a fifth transition system.
