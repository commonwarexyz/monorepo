# Bajillion lifecycle models

These Stateright models check how Bajillion certifies closes, handles challenges,
settles withdrawals, recovers after a fault, and lets wallets re-sign payments
across epochs. They check custody conservation, exact replay identities, deadline
ordering, the availability of recovery steps, and single settlement of each
payment.

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
Registrations wait in FIFO order
      |
  the frontier binds the admitted head
  and receives its deadlines
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

Registration fixes the payment context without waiting for earlier closes.
Registrations wait in FIFO order behind the admission frontier. An epoch becomes
the frontier at its registration when nothing awaits admission, and otherwise at
its predecessor's admission. Only then does it bind the admitted head and receive
its deadlines, so only the frontier can expire. Admission requires a certified
close within the frontier's admission deadline. Finalization processes the clean
front of the pending queue strictly after its challenge deadline. A proven
challenge invalidates its target and successors. Fault recovery resolves the
earlier clean prefix before paying claims against the frozen state and refunding
unadmitted deposits. Previously finalized withdrawal reserves remain claimable
throughout recovery.

The [settlement model](settlement.rs) covers the flow above and checks exactly
these registration and intake rules over its fixtures:

- At most two registrations await admission: the frontier and one queued epoch.
  Registration needs only the previous epoch registered.
- An epoch receives its admission and challenge deadlines when it becomes the
  frontier, with an admission delay of 1 and a challenge duration of 2. A queued
  epoch has no deadline. A candidate close is admissible only when its fixture
  predecessor is the head the frontier bound.
- Deposits and chain-queued withdrawals enter one ordered inbox with consecutive
  indices, including while epochs are registered. A registration pulls the inbox
  from the first unpulled index up to an end it names, and its fixture must commit
  exactly the deposits recorded there. Later intake stays in the inbox, and
  admission removes exactly the pulled deposits.
- Only unpulled deposits carry inclusion deadlines. The earliest deadline expires
  first, attributed to the latest deposit recorded with it, so a pulled deposit
  follows its epoch and never expires.
- A registration must carry every uncarried chain-queued request its pull reaches
  verbatim, and may carry one recorded later, which carries it early. A carried
  request cannot be carried again, and a request is carried exactly when one live
  registration carries it. Any other carried request runs the full intake gates
  as an operator-carried extra. An extra supersedes a different uncarried
  request its account queued at or past the pull, which then leaves the inbox
  obligations with its replay id consumed.
- An operator-carried extra has no balance proof. Its deadline must exceed the
  first instant its close can finalize: one past the frontier's exact challenge
  deadline, or one past the deadline a queued epoch would receive at once.
- A fault drops the frontier and the queue and clears every carriage. Unadmitted
  deposits and chain-queued withdrawals stay with their owners, and a refund
  returns every unadmitted deposit of an account once.

Three variants must fail, and each scenario pins the counterexample: requiring a
registration to pull the whole inbox, disallowing early carriage, and leaving
pulled deposits' deadlines armed.

Every reachable state also satisfies the custody, deposit-accounting, FIFO,
reserve, fault-fence, recovery, and deadline-observability invariants in the
model. The finite instance has three accounts, four sequential epochs with
alternative epoch-0 and epoch-1 fixtures, three deposit events, six withdrawal
authorizations, and time bounded by 12. Each fixture registers no later than a
fixed instant, which bounds the deadlines it can receive. No fixture pulls
Alice's deposit, so the checker records it only as the first intake at the
start, where it blocks every pull. Scenarios cover it arriving later. The model
does not check queues deeper than two, registration after those instants, or
cryptographic validity.

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

## Wallet lineage

The [lineage model](lineage.rs) checks that a payment settles at most once when a
wallet re-signs it across epoch boundaries. One payer signs two payment intents
over four epochs. Three cut epochs can await admission while the fourth takes
payments, and admission is FIFO.

- Each body signs its epoch-cumulative vector and a predecessor: the vector the
  wallet expects the preceding epoch to end at. The empty set stands for the
  empty vector root, which epoch 0 binds.
- The operator may receipt any live-epoch body, stay silent, or answer a
  resubmitted body of a cut epoch with a usable Stale report. A report is empty
  only while the wallet holds no receipt in that epoch. Otherwise it names a body
  at or above every receipt.
- Validators admit any body whose predecessor equals the preceding admitted
  terminal, or no body.
- The wallet binds the root it knows for the preceding epoch: the admitted
  terminal, the first usable report, or its highest receipted body once every
  body is receipted or dead. A body is dead once its predecessor epoch is
  admitted with another root. The wallet re-signs a payment only after the latest
  epoch that signed it excluded it, and only when every other body carrying it
  outside the preceding epoch is decided.

Every reachable state carries each intent at most once. Three variants must fail,
and each test pins the counterexample: re-signing without the lineage rule,
allowing a re-sign whenever the preceding endpoint is nonempty, and validators
that skip the predecessor check. Every body of one epoch binds the predecessor of
its first body, and the wallet signs nothing more there once they are dead. The
model does not check more intents or epochs, challenges, or signatures.

## Production checks

Each component explores every reachable state of its small, symbolic fixtures.
[Scenarios](scenarios.rs) exercise specific lifecycle boundaries, while
[refinement tests](refinement.rs) compare acceptance, returned asset transfers,
and retained state after each production operation in selected traces. The
settlement traces include a registration queued behind the frontier and compare
the exact bound frontier context, the queued registrations, the inbox counters,
the pending deposit totals, the deadline runs, and the chain-queued withdrawals
with their carriage after every step. Registrations pass production the model's
aggregate of the pulled prefix. Production has no counterpart to the model's
queue depth or fixture registration instants, so the traces stay within them.

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
