# commonware-clearing

[![Crates.io](https://img.shields.io/crates/v/commonware-clearing.svg)](https://crates.io/crates/commonware-clearing)
[![Docs.rs](https://docs.rs/commonware-clearing/badge.svg)](https://docs.rs/commonware-clearing)

Settle actions at scale.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

Bajillion is **ALPHA**. Its API and wire format may change without a migration path.

The `bajillion` module provides payer-signed payment vectors, operator acknowledgments,
complete-close validation, exact-quorum certificates, receipt challenges, and an in-memory
settlement state machine. The [terminal example](../examples/terminal) integrates these primitives
with an operator, wallets, consensus, and persistence.

Every validator retains the operator's complete account state in QMDB Current Ordered with MMB.
Each canonical 32-byte account key maps to a positive eight-byte balance; absence represents a
non-live account. A close derives credits from the signed payer vectors and applies one canonical
batch containing only changed balances. Deposits can create accounts, zero balances remove them,
and payments to absent recipients become certified external payouts.

The operator sends the same dealing to every validator. It contains account identities, terminal
payer authorizations, cumulative payment entries, and one combined operator acceptance signature.
Each validator checks the complete account equations and reconstructs three roots: account
activity, withdrawal outputs, and successor QMDB state. The activity and output trees provide
compact BMT openings for challenges and payout claims. Zero-net activity still appears in the
activity tree even when it needs no QMDB write. Payer-vector BMTs authenticate individual entries.

The 32-byte Header binds those roots, actual withdrawal and external-payout totals, and the exact
registered epoch context. An external settlement chain verifies an exact `2f + 1` certificate for
`n = 3f + 1` validators. Each honest signer validates the full dealing and durably retains its
state and evidence before publishing its vote, so the certificate has at least `f + 1` honest
holders of the entire close. Committee registration must authenticate proofs of possession.
The certificate proves the disclosed public relation; private receipts remain necessary to
challenge an operator's omitted or contradictory acknowledgments.

Payment counters and vectors are scoped to an immutable registered epoch. A wallet saves the
verified receipt before advancing its endpoint and retries the exact signed request after response
loss. An unresolved request must be reconciled with its original epoch before a replacement is
signed. Registration starts an admission deadline; an expired registered epoch cannot be rolled
forward to avoid that obligation.

Settlement admits certified closes into a FIFO queue and finalizes each after its challenge
window and predecessors. Finalization reserves withdrawals and external payouts for independent,
once-only claims. A proven fault or missed deadline stops new work; recovery freezes the last
finalized QMDB root after the surviving clean prefix drains. Historical Current proofs support
forced-withdrawal intake and balance recovery, while ordinary withdrawal claims use the output
BMT. State and proof material must remain available for every pending root and the finalized
recovery root, including while a close waits behind an earlier deadline.

The payment, boundary, vector, and BMT modules support `no_std`. QMDB state and settlement paths
require `std` and use generic Commonware runtime traits. Applications supply authenticated time,
networking, durable storage, and atomic persistence of protocol decisions with votes and asset
transfers. A database mutation failure consumes the affected state owner; callers must recover
from durable storage before resuming it.

## Benchmarks

The [benchmark guide](src/bajillion/benches/README.md) defines each measured stage and its
workload. Run one profile per process; `sizes` verifies actual encoded dealings and proof payloads:

```bash
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=sizes \
  cargo bench -p commonware-clearing --features bench --bench bajillion
```

Use `RUSTFLAGS="--cfg full_bench"` for the dense and sparse matrix through one million live
accounts. The harness uses 100 validators and an adaptive 16-worker pool. `prepare-apply` includes
construction, encoding, and canonical batch application to one Current database.
`receive-apply` includes decoding, full validation, signing, and the same application. Historical
queries reconstruct a native view on demand; that work belongs to the query cost and is excluded
from head-advancement measurements. These measurements also exclude journal commit/sync. Separate
receipt, certificate, challenge, and withdrawal-claim groups exercise their complete verifiers.

With 100 validators, the encoded Header and certificate occupy 101 bytes. The three roots and
two outflow totals add 112 bytes to the admission package. Dealing, admission, proof, and transport
costs are reported separately. Local runs validate correctness and encoded sizes; published
latency comparisons require matched runs on a quiet external machine.

## Formal model

The [executable Stateright model](stateright/README.md) exhausts its finite certification,
challenge, claim-ledger, and settlement state spaces to completion and pairs them with deterministic
end-to-end fund-recovery traces. Its documentation records the exact state counts, composition
boundaries, reachability matrix, and the refinement obligations that remain with the Rust
implementation and embedding.
