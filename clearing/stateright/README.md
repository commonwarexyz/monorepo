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
[Certification](certification.rs) checks delivery, voting, and evidence retention,
while [challenges](challenge.rs) checks authenticated contradictions. The
[claims model](claims.rs) checks output identity, replay protection, and reserves.

## Production checks

Each component explores every reachable state of its small, symbolic fixtures.
[Scenarios](scenarios.rs) exercise specific lifecycle boundaries, while
[refinement tests](refinement.rs) compare acceptance, returned asset transfers,
and retained state after each production operation in selected traces.

Completing recovery requires advancing time and submitting claims.
The settlement embedding must commit state changes and returned asset transfers
atomically and idempotently.

See the [Bajillion module documentation](../src/bajillion/mod.rs) for the protocol.
