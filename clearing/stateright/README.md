# Bajillion lifecycle models

These Stateright models check how Bajillion certifies closes, handles challenges,
settles withdrawals, and recovers after a fault. They check custody conservation,
exact replay identities, deadline ordering, and the availability of recovery
steps.

Run from the workspace root:

```bash
just test -p commonware-clearing --lib bajillion::model
just test -p commonware-clearing --lib refinement::
```

The first command explores the finite models and runs deterministic scenarios.
The second replays selected traces against production Bajillion operations.
Both are ordinary Rust tests included in the crate's test suite.

## Settlement lifecycle

```text
Registered epoch
      |
  certify + admit
      |
      v
Pending closes -- clean FIFO front past deadline --> Finalized
      |                                                  |
  proven challenge                                withdrawal claims
      |                                                  |
      v                                                  v
Permanent fault <--- missed deadline                     Paid
      |
finish earlier clean closes
      |
      v
Frozen-state claims + deposit refunds
```

Registration fixes the payment context. Admission requires a certified close
within its deadline; finalization processes the clean front of the pending queue
strictly after its challenge deadline. A proven challenge invalidates its target
and successors. Fault recovery resolves the earlier clean prefix before paying
claims against the frozen state and refunding unadmitted deposits. Previously
finalized withdrawal reserves remain claimable throughout recovery.

The [settlement model](settlement.rs) covers the queue and recovery flow above.
The [certification model](certification.rs) checks delivery, voting, and evidence
retention and accepts every certificate with at least `f + 1` signers: each
contains an honest validator that validated and retained the full dealing, while
two minimum certificates may share only a Byzantine signer. Certification
therefore does not choose between valid closes; ordered admission does. The
[challenge model](challenge.rs) checks authenticated contradictions.
The [claims model](claims.rs) checks sparse native output positions, latest-root proof
refresh, stale neighbor hints, zero-value consumption, empty closes, and
fault-frozen claims. It checks claimed ranges against an independent oracle of
finalized Commit positions plus paid output positions after every step. Pending
outputs and commits never enter the ledger. The aggregate reserve independently
equals the sum of unpaid amounts, including when zero-value outputs remain.

The production refinement compares native finalized operation counts and claimed
coverage after every action, including suffix invalidation and terminal recovery.
Its per-batch output and payment records are ghost state for this comparison.
Production settlement retains the paired finalized activity and payout heads;
the embedding stores canonical claimed ranges. Every newly finalized trailing
Commit is inserted as structurally consumed, including for an empty close, and
each successful payout inserts its output position. Adjacent ranges merge, so
fully settled history collapses to one range beginning at native position one;
genesis position zero is not stored. The refinement derives the exact claimed
union independently, including fault-frozen prefixes after pending suffixes are
invalidated.

## Production checks

Each component explores every reachable state of its small, symbolic fixtures.
[Scenarios](scenarios.rs) exercise specific lifecycle boundaries, while
[refinement tests](refinement.rs) compare acceptance, returned asset transfers,
and retained state after each production operation in selected traces.

Completing recovery requires advancing time and submitting claims.
The settlement embedding must commit state changes and returned asset transfers
atomically and idempotently.

See the [Bajillion module documentation](../src/bajillion/mod.rs) for the protocol.

Claim actions select an output proof source, native position, and whether to
refresh that proof under the current finalized head. They carry no target batch
identity or range hint. The embedding supplies exact claimed-range neighbors from
one state snapshot. The production fixture authenticates Append membership by
position and current finalized root before calling the real claim method;
claimed-range absence alone never establishes issuance. Independent batch records
account for issued and paid outputs. Equal native outputs from distinct
source-close identities remain interchangeable for payout claiming. A refinement
regression checks that the current finalized payout root authenticates each native
position without a source-batch admission gate.
