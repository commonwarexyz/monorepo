# commonware-clearing

[![Crates.io](https://img.shields.io/crates/v/commonware-clearing.svg)](https://crates.io/crates/commonware-clearing)
[![Docs.rs](https://docs.rs/commonware-clearing/badge.svg)](https://docs.rs/commonware-clearing)

Settle actions at scale.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

Bajillion is **ALPHA**. Its API and wire format may change without a migration path.

The `bajillion` module provides the runtime-agnostic objects and verification rules for Bajillion:
payer-signed sender-vector endpoints and operator acknowledgment countersignatures, per-payer
outgoing vectors and the recipient-major transpose, fresh live-state transitions, deterministic
proof slices for authenticated dissemination, exact-quorum commitment certificates and retained
dealings, bounded acknowledgment challenges, and a bounded in-memory settlement state machine
for registration, admission, FIFO finalization, custody accounting, hard-fault fencing, and
incremental hard-fault claims. Deposits can create accounts, zero balances leave the committed
state, and sends to absent recipients become certified external payouts. Compact change leaves
expose the validator-authenticated settlement and challenge projection, allowing independent payout
claims without opening a neighboring row. `CloseContext` owns the predecessor state root;
`RootBundle` carries the change, withdrawal-output, successor-state, coverage, and transpose roots
plus the exact transpose leaf count; and the 32-byte Header binds every contextual role. The
164-byte RootBundle is public witness data. It is retained by validators and the
data-availability layer and must be supplied or cached by external settlement operations.

The posted corpus ships movers and edges only: readers hold the previous certified state as a
`Replica`, live accounts ride as one-or-two-byte rank gaps, and the transpose, predecessor
states, successor states, and prefixes are all derived rather than shipped. Dealt slices travel
without their unchanged state: every slice assignee retains its key interval across closes,
hydrates each dealing against it, and validates the result against the certified roots.

Successful epoch registration activates one immutable payment anchor and a bounded obligation to
admit its certified close. Operator receipts must not be released before that exact registration
succeeds. The open registration slot has no periodic heartbeat, but the first authenticated-time
observation after a registered admission deadline permanently faults the deployment; the expired
anchor cannot be rolled into another epoch. Each cleanly finalized withdrawal is independently
claimable as its certified destination and amount plus one opening in the withdrawal-output tree.

`seal` authenticates and takes ownership of a validator's dealing before signing the Header. A
dealing is the complete, canonically ordered set of `ProofSlice` values assigned to one validator:
each slice is held by one quorum window of the validator ring, the window slides with the slice
index, so a validator's slices form one contiguous span (two when the window wraps) and its
dealing is one `ProofSlice` per span. `seal` checks the local row equations and the exact
state-update, prefix, accumulator, and conservation relations represented by the dealing and
shared Header, at every covered slice boundary. It verifies each slice's combined operator
countersignature and every distinct payer authorization in one randomized aggregate batch. The
embedding must verify each validator's proof of possession when it registers, and the crate
assumes it. With `n` validators, the BLS MinSig certificate contributes a 48-byte signature and a
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
chain's context, status, custody, or deadline state, and it does not replace RootBundle or
data-availability retention. The crate does not provide an operator, network service, persistence
layer, or asset-adapter implementation.

## Benchmarks

The benchmark matrix uses one adaptive pool with eight workers and selects one live-account
profile per fresh process. The default profile set is a smaller developer matrix with six
profiles, `0` through `5`. The blog's measured matrix needs `RUSTFLAGS="--cfg full_bench"` and
has seven profiles: `0` through `3` sweep the live-account count from 1,024 to one million with
every account sending, and `3` through `6` hold one million live accounts while the sender count
falls from one million to 1,024. Run one profile per process:

```bash
RUSTFLAGS="--cfg full_bench" \
COMMONWARE_CLEARING_PROFILE=0 \
COMMONWARE_CLEARING_BENCH=blog-chain \
cargo bench -p commonware-clearing --bench bajillion
```

The `sizes` group prints exact encoded sizes for the same profiles, including the posted corpus
against a reader-held replica and the dealt-slice corpus without unchanged state.

The harness reports raw encoded sizes and separately times preparing roots, dealing slices, the
complete validator `seal` path for the byte-largest dealing, repeatable certified-commitment
validation, bounded challenge decode plus adjudication, and fixed-amount and Close withdrawal
claims. The protocol accounting distinguishes the 32-byte validator-chain commitment, the external
MinSig certificate's 48-byte signature plus `ceil(n / 8)`-byte signer bitmap, and the 164-byte
RootBundle witness. The generic codec adds an eight-byte bitmap-length prefix, so the raw encoded
Header-plus-certificate package is `88 + ceil(n / 8)` bytes. The harness also preflights the
corresponding mutating `SettlementChain` admission and challenge paths outside Criterion's timed
loops.

Ordinary withdrawals authorize an exact positive amount. A close carries no amount and releases
the account's authenticated epoch-tail balance after that epoch's deposits, credits, and debits.
A zero tail is valid and removes the account without creating a payout claim.

## Formal model

The [executable Stateright model](stateright/README.md) exhausts its finite certification,
challenge, claim-ledger, and settlement state spaces to completion and pairs them with deterministic
end-to-end fund-recovery traces. Its documentation records the exact state counts, composition
boundaries, reachability matrix, and the refinement obligations that remain with the Rust
implementation and embedding.
