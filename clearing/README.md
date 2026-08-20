# commonware-clearing

[![Crates.io](https://img.shields.io/crates/v/commonware-clearing.svg)](https://crates.io/crates/commonware-clearing)
[![Docs.rs](https://docs.rs/commonware-clearing/badge.svg)](https://docs.rs/commonware-clearing)

Build payment clearing systems.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Bajillion

Bajillion is **ALPHA**. Its API and wire format may change without a migration path.

The `bajillion` module provides the runtime-agnostic objects and verification rules for Bajillion:
signed payments and receipts, receive-shard commitments, sparse exact state transitions,
deterministic proof slices for authenticated dissemination, exact-quorum validator certificates and
retained assignments, bounded receipt challenges, and a bounded in-memory settlement state machine
for registration, admission, FIFO finalization, custody accounting, hard-fault fencing, and terminal
unwind. `seal` authenticates and takes ownership of a validator's exact deterministic assignment
before signing the header. It accepts only the complete, canonically ordered slice set, checks the
local row equations and the exact state-update, prefix, and conservation relations represented by
the slices and shared header, and verifies every distinct signed send and receipt envelope carried
by the assignment in one aggregate batch. For every slice, its
`q = 2f + 1` holders and an exact certificate quorum of `q` signers intersect in more than `f`
validators, so at least one honest certificate signer has authenticated and retains that slice.
Across all slices, the certificate therefore attests to exhaustive honest authentication of the
represented predicates without requiring any validator to authenticate the complete public corpus.
That claim does not extend to a relation absent from both an authenticated slice and the shared
header.

The settlement state machine is a transition primitive, not a durable chain or asset adapter. An
embedding application must provide an authenticated monotonic clock and atomically persist each
state mutation with its custody effects. The crate does not provide an operator, network service,
persistence layer, or asset-adapter implementation.

## Benchmarks

The exact benchmark matrix from the Clearing blog uses one adaptive pool with eight workers and
selects one million-account profile per fresh process. Run profiles `0` through `3` separately:

```bash
COMMONWARE_CLEARING_PROFILE=0 \
COMMONWARE_CLEARING_BENCH=blog-chain \
RUSTFLAGS='--cfg full_bench' \
cargo bench -p commonware-clearing --bench bajillion
```

The harness reports raw encoded sizes and separately times proof-slice assembly, the complete
validator `seal` path for the byte-largest assignment,
repeatable commitment verification, and bounded challenge decode plus adjudication. It also
preflights the corresponding mutating `SettlementChain` admission and challenge paths outside
Criterion's timed loops.

Ordinary withdrawal amounts are exact. A full-close amount is a minimum floor, and settlement
effects pair the signed request with the exact authenticated balance released to its destination.
