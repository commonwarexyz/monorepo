# Bajillion formal model

This directory contains an executable finite-state model of Bajillion. It covers every protocol
state category and transition class, including construction and certification, FIFO settlement,
all four challenge relations, deadlines, permanent operator faults, finalized claim reserves, and
terminal fund recovery. The instance is finite: it uses representative accounts, batches, roots,
requests, proofs, and times so Quint can execute and Apalache can exhaustively explore a bounded
prefix of the lifecycle.

The complete user and operator flows are shown as ASCII state machines in the
[Bajillion module documentation](../src/bajillion/mod.rs). This model is the executable counterpart
to those diagrams.

## Why Quint

Quint is a good fit for the protocol-level questions. Its state-machine notation makes adversarial
action ordering explicit, its simulator explores long executions, and its Apalache backend checks
all executions within a stated finite bound. The workspace already uses Quint, so this model can
share one toolchain and CI path.

TLA+ with Apalache would provide similar protocol-level analysis but would duplicate the existing
notation and tooling. Alloy is strongest for bounded relational structure, but Bajillion's primary
risks arise from temporal transitions and custody evolution. Kani is complementary rather than a
replacement: it can prove narrowly scoped Rust implementation properties, while this model reasons
about the distributed protocol independent of one implementation.

## Model structure

| File | Responsibility |
| --- | --- |
| `types.qnt` | Protocol, proof, challenge, settlement, and claim state types. |
| `transition.qnt` | Ideal typed commitments, row equations, proof-slice continuity, batched signature obligations, output linkage, and semantic challenges. |
| `settlement.qnt` | Registration, certification, FIFO admission/finalization, deadlines, faults, claims, custody, and invariants. |
| `fixtures.qnt` | One branch-complete finite instance plus valid and adversarial witnesses. |
| `instance.qnt` | Instantiation and the public checker surface. |
| `tests/scenarios.qnt` | Deterministic end-to-end and negative scenarios. |
| `main.qnt` | Full transition relation used by simulation. |
| `bounded.qnt` | Reduced lifecycle relation used by bounded exhaustive checking. |

The finite instance has three accounts, four validators (`n = 4`, `f = 1`, exact quorum `q = 3`),
two proof slices, and a three-close pending pipeline. Every possible certificate quorum intersects
every slice's holder set in at least one honest validator. Fixtures cover valid closes, an invalid
proof, a root/content alias attempt, exact-offset deposit deferral, Amount and Close withdrawals,
external payouts, every challenge kind, and faults at the front, middle, and tail of the pipeline.

Registration has its own identity and owns the immutable payment context. A candidate batch and its
Header are derived later, so an invalid construction can be discarded and corrected against the
same unexpired registration. Missing the registered admission deadline is different: the active
payment anchor may already have issued operator receipts, so expiry permanently faults the
deployment and opens terminal recovery. An empty registration slot has no heartbeat.

```text
OPEN
  | register exact epoch, predecessor, inputs, and deadline policy
  v
REGISTERED -------------------- deadline missed --------------------+
  | prepare -> deal -> exact per-validator delivery                 |
  | seal exact assigned slices + all distinct payment signatures   |
  | exact quorum certificate -> admit                              |
  v                                                               v
OPEN + FIFO [Pending e, Pending e+1, ...]                    PERMANENT FAULT
  |                 | proven challenge at position i               |
  |                 +------------------------------+                |
  | front challenge deadline passed                v                |
  v                                      keep clean prefix;         |
FINALIZED HEAD                            invalidate suffix          |
  | create independent output reserves             |                |
  +-------------------------------------------------+----------------+
                                                    v
                                         drain clean FIFO prefix
                                                    |
                                                    v
                                      freeze last finalized state
                                      + staged/suffix deposits
                                                    |
                        +---------------------------+------------------+
                        |                                              |
              claim each state position                    refund each deposit
              Amount split or Close sweep                   without operator data
                        |                                              |
                        +---------------------------+------------------+
                                                    v
                                                 SETTLED

Finalized withdrawal/output reserves remain independently claimable throughout a later fault.
```

## Checked properties

The full invariant set checks:

- exact quorum assumptions and honest retained-slice coverage;
- typed root role, vector length, position, content, and domain separation;
- gap-free coverage boundaries and exact terminal tails;
- both payer and operator signatures, exact request/output linkage, and one distinct signature
  batch per sealer dealing;
- semantic validity of latest-send, higher-shard-tip, inconsistent-range, and receipt-fork
  evidence against the explicitly selected pending batch;
- strict epoch ancestry, FIFO finalization, suffix invalidation, and no skipped epoch;
- atomic replay protection by claim kind, batch, and output position;
- exact finalized withdrawal and payout reserves, with claim material retained;
- monotonic deadline observation and permanent fault fencing;
- custody conservation, active-state backing, exact hard-fault recovery, and enabled recovery
  progress whenever recoverable value remains.

The deterministic scenarios additionally exercise malformed or misrouted evidence, every challenge
kind, registration/deposit/withdrawal expiry, admitted withdrawal expiry on both challenge and clean
finalization paths, earliest-deposit-deadline retention, exact-offset deposit deferral, independent
finalized claims, and sender recovery after front, middle, and tail operator faults.

Fund recovery is a conditional protocol guarantee. Under the assumptions below, a malicious or
failed operator cannot make active custody disappear: a clean prefix may finalize, every invalid
suffix is excluded, finalized reserves remain claimable, and the frozen state plus unfinalized
deposits has an exact terminal claim path. Completion still requires an authenticated time
observation, submission of available claims, and an embedding that atomically performs each asset
transfer with its state mutation.

## Checker surfaces and bounds

The full `step` relation retains every intermediate `prepare`, `deal`, delivery, `seal`, certificate,
admission, and semantic challenge action. It is used by deterministic scenarios and randomized
simulation.

The exhaustive checker uses `bounded_step`, which replaces a valid proof/certificate sequence with
`admit_valid` and a valid semantic challenge with `challenge_proven`. Those are lifecycle endpoints,
not extra protocol actions. This reduction keeps FIFO, deadline, fault, claim, and custody state
exact while avoiding the certification power set in Apalache. Proof/certificate causality and each
challenge predicate remain checked on the full relation.

The checked baseline is:

- 24 deterministic scenarios;
- 10,000 seeded simulator traces of up to 30 full-relation steps;
- exhaustive Apalache checking of the reduced lifecycle relation through three actions.

The Apalache result is bounded, not inductive or unbounded. Three actions cover every individual
lifecycle edge and short compositions; the longer deterministic scenarios cover complete flows.
No result here establishes fairness or eventual user action. The progress invariant instead proves
that an appropriate recovery transition is enabled whenever recoverable value remains.

The fixture clock ends at `TIME_HORIZON = 12`. The model rejects new obligations whose deadlines
would fall beyond that horizon so finite checking cannot silently strand an unobservable deadline.
This is a model bound, not a production protocol limit.

## Refinement boundary

The model uses ideal cryptography and mathematical integers. Its conclusions depend on these
implementation obligations:

| Model assumption | Production obligation |
| --- | --- |
| Typed root equality binds one exact vector. | Collision-resistant, domain-separated hashing binds role, vector length, position, and canonical encoding. |
| A valid signature check cannot be forged. | The Rust verifier checks the canonical registration-relative send/receipt bodies, proof of possession, and the randomized aggregate batch correctly. |
| One action is atomic. | The embedding persists settlement state, replay keys, custody, and external asset effects atomically and idempotently. |
| `now` is monotonic and authenticated. | The settlement environment supplies a trustworthy clock and persists an observed fault even when the requested call fails. |
| Claims and retained witnesses are available. | Validators/data availability retain certified dealings, roots, state openings, and output openings through their required lifetimes. |
| Integer arithmetic is exact. | Rust decoding and arithmetic reject malformed, narrowing, overflow, and resource-exhaustion cases without partial mutation. |

Consequently, the model does not prove codecs, Merkle/hash implementations, BLS implementation,
batch-verifier randomness, storage crash consistency, external asset adapters, memory bounds, or
denial-of-service resistance. Rust unit/integration tests, fuzzing, conformance fixtures, crash-cut
tests, and narrowly targeted Kani harnesses are the appropriate complementary checks.

## Running the model

Install Node.js and Quint 0.30.0:

```bash
npm install --global @informalsystems/quint@0.30.0
```

Run the CI-sized checks:

```bash
cd clearing/quint
make check
```

Run bounded exhaustive lifecycle verification separately on a high-memory machine with a JDK:

```bash
cd clearing/quint
make verify
```

`make verify` gives Apalache a 28 GiB Java heap. Override `JAVA_TOOL_OPTIONS` only when the machine
has a different safe ceiling. The full unreduced transition relation is intentionally not presented
as exhaustively checked: its certification sets exceed practical monolithic Apalache memory at this
instance size.
