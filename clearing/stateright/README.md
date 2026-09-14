# Bajillion Stateright model

Run the finite lifecycle checks and production refinement tests from the workspace
root:

```bash
just test -p commonware-clearing --lib bajillion::model
just test -p commonware-clearing --lib refinement::
```

These are ordinary Rust unit tests, included in the workspace's normal test jobs.
They need no separate model-checker process. The first command explores each
finite component to a fixed point and runs deterministic scenarios. The second
checks selected traces against real Bajillion operations.

To explore one component in a browser:

```bash
cargo run -p commonware-clearing --example bajillion_model -- \
  settlement 127.0.0.1:8088
```

Open `http://127.0.0.1:8088`. Replace `settlement` with `certification`, `challenge`,
or `claims` to inspect another component. The browser shows enabled actions,
successors, and property status along selected paths. It explores on demand unless
**Run to completion** is requested; the tests above are the canonical exhaustive
check. Port 8088 keeps the explorer separate from the terminal demo's port 3000.

## What is checked

"Exhaustive" means every reachable state of the declared finite instance, with no
depth cutoff or random sampling. The tests require completion, assert state
counts, and check safety and reachability properties:

| Component | States | Finite scope |
| --- | ---: | --- |
| [Certification](certification.rs) | 1,164 | 4 validators, 1 faulty, 1 dealing |
| [Challenges](challenge.rs) | 1,502 | 5 targets, representative evidence classes |
| [Claims](claims.rs) | 33 | 2 batches, 2 output positions each |
| [Settlement](settlement.rs) | 2,649,149 | 3 accounts, 8 candidates, 3 pending slots |

- **Certification** explores valid and invalid verifier outcomes, independent
  missing/incomplete/exact delivery, every exact three-vote quorum, evidence
  retention, rejection, and a valid retry under the same registration.
- **Challenges** explores payer/operator signature and context-authentication bit
  combinations, typed openings, contradictory evidence, and valid evidence that
  must not convict. It covers higher debit, higher per-edge credit or payment
  count, and operator acknowledgment forks. Forks require the operator's
  countersignatures; the payer signatures do not gate that verdict.
- **Claims** explores every ordering of four `(batch, position)` replay identities,
  checking authenticated root, position, value, destination, atomic mutation,
  and reserve conservation across independent batches and outputs.
- **Settlement** uses fixed balance/payment fixtures and time values from 0 through
  12. It covers intake, registration, admission, FIFO finalization, deadline ties,
  challenge suffix cuts, withdrawal reserves, replay expiry, and fault recovery.
  Its branches include first credit to an absent recipient, operator-carried
  withdrawals, uncovered Amount requests, and deposit/withdrawal offsets.

The challenge model's higher-debit case covers only the strictly-higher-debit arm.
The production adjudicator also handles conflicting bodies at the committed
sequence, equal endpoints at later sequences, earlier retries, and credit-only
cases. Those sequence rules are checked in
[production challenge tests](../src/bajillion/tests/challenges.rs).

[scenarios.rs](scenarios.rs) adds **26 deterministic traces** through the same
settlement transition function. They exercise accepted and rejected boundaries,
all three challenge kinds, front/middle/tail faults, all deadline-fault classes,
Amount and Close claims, and recovery after a later fault. Reachability properties
also require a full three-close pipeline, four ordered finalizations, exact
deadline boundaries, and completed recovery paths. Each safety predicate has a
corrupted negative-control state that must fail it, guarding against vacuous or
disconnected checks.

## How the components compose

```text
Certification model                         Challenge model
  complete dealing + exact quorum             authenticated contradiction
               |                                         |
        CertifiedClose                            ProvenChallenge
   (registration, candidate)                       (target, kind)
               |                                         |
               +------------------+----------------------+
                                  v
                         Settlement model
                      admission / fault / recovery

Claim model: independent finalized withdrawal-output ledger
```

`CertifiedClose` and `ProvenChallenge` are opaque capabilities. Certification
issues a capability for an exact candidate and registration only after valid
complete delivery, quorum formation, and certificate issuance. Matching identities
alone do not suffice. Challenge capabilities come from adjudicated evidence for
an exact target.

This is an **assume-guarantee decomposition**: each finite component is checked to
completion, and settlement consumes its guarantees through those capabilities.
The checker does not multiply every delivery and witness by every settlement
ordering into one Cartesian-product graph.

An honest signer retains the complete dealing before voting. With `n = 3f + 1`
and `q = 2f + 1`, a certificate guarantees at least `q - f = f + 1` honest copies.
The canonical all-honest fixture has three copies; the four-validator instance's
general guarantee is two. Retention and voting are atomic in the model. The
embedding must durably persist evidence before publishing a vote. Incomplete
delivery blocks sealing; it does not establish semantic invalidity.

## Settlement and recovery

```text
Open slot -- register --> Registered -- admit --> Open slot + pending FIFO
                                                               |
                                                     clean front after
                                                     challenge deadline
                                                               |
                                                               v
                                                      Finalize + reserves

           proven challenge / registration or intake expiry
                                  |
                                  v
                            Permanent fault
                                  |
                     fence new intake and admission
                                  |
                     drain earlier clean FIFO prefix
                                  |
                     freeze last finalized state
                                  |
                     account claims + deposit refunds
                                  v
                         Recovery settled
```

An open slot has no heartbeat. Registration fixes an immutable payment context
with inclusive admission and challenge deadlines. Construction or certification
may retry within that registration's live window; missing admission permanently
faults the deployment. Finalization requires a clean FIFO front strictly after
its challenge deadline. Epochs cannot skip predecessors or the pending prefix.

A proven challenge invalidates its target and suffix. After any permanent fault,
recovery waits for the earlier clean prefix to resolve, then uses the last
finalized root. Each live account has one claim keyed by frozen root and account;
each account's unfinalized deposits are refunded in aggregate with replay
protection. Deposit IDs remain intake replay keys. Pending deposits can also be
refunded before terminal settlement begins.

For an outstanding Amount request, a covered amount goes to its destination and
the remainder stays residual. An uncovered amount routes zero and leaves the
whole frozen balance residual. Close routes the entire balance. Previously
finalized withdrawal reserves remain independently claimable before, during, and
after recovery, using their authenticated `(batch, position)` identities.

The model checks conservation and an enabled next recovery step. **It does not
prove fairness or eventual completion.** Completion assumes an authenticated
monotonic clock, available claim material, eventual claim submission, and an
embedding that persists each returned asset transfer atomically and idempotently
with the state mutation.

## Connection to production

[refinement.rs](refinement.rs) maps every `SettlementAction` to production calls
with an exhaustive match; a coverage test requires every action variant to run.
After each step it compares acceptance, returned custody outputs, and a private
state projection: roots and liability, custody buckets, deposits and withdrawals,
deadlines, registration, pipeline order/status, replay identities, reserves,
faults, and terminal claims. Rejected calls at an already-observed time leave
state unchanged. A separate timed-call profile checks that observing an expired
deadline can persist a fault even when the requested operation returns an error.

The adapter builds real signed payments and withdrawals, complete dealings,
certificates, QMDB histories, challenges, and claim openings. Every admission runs
production preparation and whole-dealing `seal`; all three challenge kinds have
constructible production evidence. The profiles cover the clean four-epoch path,
rejected calls, first virtual credit, independent Amount/Close claims, malformed
or mispositioned openings, deadline faults, challenged-suffix recovery, carried
requests, and zero-release degraded closes.

Fixtures retain exact QMDB history: equal balances alone do not identify a
historical root. When recovery drains custody, production retains the last
finalized root; the adapter accounts for the model's `Empty` sentinel.

This is **bounded trace refinement**, not production execution of all 2,649,149
settlement states. Neither it nor the finite graphs prove arbitrary account,
validator, or payment counts. The model uses ideal cryptography and representative
values; it does not derive the production byte-level verifier. Codec and numeric
limits, adversarial inputs, and broader verifier coverage belong to Rust tests
and fuzzing. Durable crash cuts and external asset transfers require embedding
recovery tests.

See the [Bajillion module documentation](../src/bajillion/mod.rs) for the protocol
and the [Verus model](../verus/README.md) for the separate arithmetic proofs.
