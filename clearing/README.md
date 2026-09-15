# commonware-clearing

[![Crates.io](https://img.shields.io/crates/v/commonware-clearing.svg)](https://crates.io/crates/commonware-clearing)
[![Docs.rs](https://docs.rs/commonware-clearing/badge.svg)](https://docs.rs/commonware-clearing)

Settle actions at scale.

**Bajillion** nets payments across accounts and settles their combined effects.
This crate provides signed payment vectors, operator receipts, close validation,
committee certificates, challenges, and the settlement state machine.

To run it, start with the [terminal example](../examples/terminal/README.md).
For the records and protocol rules, see the [module documentation](src/bajillion/mod.rs).

## Status

Bajillion is **ALPHA**: its API, wire format, and storage may change without a
migration path. See the workspace's [stability levels](../README.md#stability).

## From payments to settlement

Every validator keeps the operator's full balance state and receives the same
**dealing**, containing the signed inputs needed to check one epoch's close.
It derives incoming credits from payer vectors, applies the registered deposits
and withdrawals, and reconstructs three commitments:

```text
             signed payments + registered epoch boundary
                                  |
                         one shared dealing
                                  |
                    each validator checks it
                       against its prior state
                                  |
           +----------------------+----------------------+
           |                      |                      |
      Activity MMR            Payout MMR             Current QMDB
       challenges               claims                balances
           |                      |                      |
           +----------------------+----------------------+
                                  |
                        Header + certificate
                                  |
                    admit --> wait --> finalize
```

The header binds the three roots, operation counts, and pruning floors to the
registered epoch and its predecessor. Each signer durably commits all three native
candidates and records its private signing decision before publishing a vote.
Native stores recover their durable heads after interruptions; authenticated
synchronization maintains and catches up replicas independently of the vote
barrier. A committee of `n = 3f + 1` validators certifies a close with exactly
`2f + 1` votes.

Admission adds the close to an ordered queue and permits the next epoch to
register. Finalization waits for the challenge deadline and all earlier closes,
then makes withdrawals claimable. A successful receipt challenge blocks the
contested close and its descendants. Earlier clean closes can still finalize
before recovery freezes the surviving state.

## Balances and evidence

QMDB Current Ordered with MMB maps a canonical 32-byte account key to a positive
eight-byte balance. Absence means zero. Payments can create a recipient's balance
without an onchain account. Balances can accumulate across closes until their
owners choose to withdraw.

A close writes only changed balances. Every activity participant, including one
whose balance nets to zero, appears as a full row in the sorted prefix of its
cumulative activity-log range. Account membership and ordered absence are proved
directly from these native rows. A flat suffix retains the original outgoing
entries, whose positive amounts delimit each payer vector; its BMT is reconstructed
only when a requested entry proof needs it. Public Commit operations carry no
metadata: the certified close descriptor and registered context authenticate the
epoch and range. Withdrawal outputs live in the separate cumulative payout log,
and claims prove output membership under its current finalized head. Balance
recovery uses historical Current QMDB proofs.

Receipts let their holders challenge omitted or contradictory payments. Wallets
save verified receipts and keep them available through the challenge deadline.

## Embedding the protocol

Applications supply networking, authenticated time, durable storage, and custody.
The main responsibilities are:

- Durably commit all three native databases and the private signing decision before
  publishing votes.
- Recover each native database from its durable state after an interrupted update;
  synchronize and catch up from authenticated native replicas as maintenance.
- Serve proofs for pending closes and the finalized recovery state.
- Retain receipts and get any challenge included before its deadline.
- Persist protocol decisions and their asset transfers atomically.

The [module documentation](src/bajillion/mod.rs) defines the full contract,
including committee assumptions, retention, retries, and recovery. The terminal
example implements these responsibilities in a running application.

Payment, boundary, vector, and BMT types support `no_std`. QMDB, complete-close
validation, challenges, and settlement require `std` and use Commonware runtime
traits.

## Tests, models, and benchmarks

Run crate tests from the repository root:

```bash
just test -p commonware-clearing
```

- [Lifecycle models](stateright/README.md)
- [Arithmetic proofs](verus/README.md)
- [Benchmarks](src/bajillion/benches/README.md)
