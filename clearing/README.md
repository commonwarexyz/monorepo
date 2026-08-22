# commonware-clearing

[![Crates.io](https://img.shields.io/crates/v/commonware-clearing.svg)](https://crates.io/crates/commonware-clearing)
[![Docs.rs](https://docs.rs/commonware-clearing/badge.svg)](https://docs.rs/commonware-clearing)

Settle actions at scale.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

Bajillion is **ALPHA**. Its API and wire format may change without a migration path.

The `bajillion` module provides the runtime-agnostic objects and verification rules for Bajillion:
signed payments and receipts, receive-shard commitments, fresh live-state transitions,
deterministic proof slices for authenticated dissemination, exact-quorum commitment certificates and
retained dealings, bounded receipt challenges, and a bounded in-memory settlement state machine
for registration, admission, FIFO finalization, custody accounting, hard-fault fencing, and terminal
unwind. Deposits can create accounts, zero balances leave the committed state, and sends to absent
recipients become certified external payouts. Admission binds a 32-byte context-bound root-of-roots
Header to an ordered opening, change, closing, and slice-layout root bundle. The 128-byte
RootBundle is public witness data. It is retained by validators and the data-availability layer and
must be supplied or cached by external settlement operations.

`seal` authenticates and takes ownership of a validator's dealing before signing the Header. A
dealing is the complete, canonically ordered set of `ProofSlice` values assigned to one validator.
`seal` checks the local row equations and the exact state-update, prefix, and conservation relations
represented by the dealing and shared Header. It verifies every distinct signed send and receipt
envelope in one aggregate batch. Proofs of possession are checked when validators register. With
`n` validators, the BLS MinSig certificate contributes a 48-byte signature and a
`ceil(n / 8)`-byte signer bitmap on the external chain. For every slice, its `q = 2f + 1`
holders and an exact certificate quorum of `q` signers intersect in more than `f` validators, so at
least one honest certificate signer has authenticated and retains that slice. Across all slices,
the certificate therefore attests to exhaustive honest authentication of the represented
predicates without requiring any validator to authenticate the complete public corpus. That claim
does not extend to a relation absent from both an authenticated slice and the shared Header.

The settlement state machine is a transition primitive, not a durable chain or asset adapter. An
embedding application must provide an authenticated monotonic clock and atomically persist each
state mutation with its custody effects. A chain operated by the same validators may persist the
32-byte Header as its admitted commitment because consensus admission occurs only after those
validators have seen the RootBundle and authenticated their dealings. This does not remove the
chain's context, status, custody, or deadline state, and it does not replace RootBundle or data-
availability retention. The crate does not provide an operator, network service, persistence layer,
or asset-adapter implementation.

## Benchmarks

The exact benchmark matrix from the Clearing blog uses one adaptive pool with eight workers and
selects one live-account profile per fresh process. Run profiles `0` through `3` separately:

```bash
COMMONWARE_CLEARING_PROFILE=0 \
COMMONWARE_CLEARING_BENCH=blog-chain \
RUSTFLAGS='--cfg full_bench' \
cargo bench -p commonware-clearing --bench bajillion
```

The harness reports raw encoded sizes and separately times preparing roots, dealing slices, the
complete validator `seal` path for the byte-largest dealing, repeatable certified-commitment
validation, and bounded challenge decode plus adjudication. The protocol accounting distinguishes
the 32-byte validator-chain commitment, the external MinSig certificate's 48-byte signature plus
`ceil(n / 8)`-byte signer bitmap, and the 128-byte RootBundle witness. The generic codec adds an
eight-byte bitmap-length prefix, so the raw encoded Header-plus-certificate package is
`88 + ceil(n / 8)` bytes. The harness also preflights the corresponding mutating
`SettlementChain` admission and challenge paths outside Criterion's timed loops.

Ordinary withdrawal amounts are exact. A full-close amount is a minimum floor, and settlement
effects pair the signed request with the exact authenticated balance released to its destination.
