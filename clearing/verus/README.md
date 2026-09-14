# Bajillion close arithmetic

From the workspace root, point `VERUS_BIN` at an installed Verus binary:

```bash
VERUS_BIN=/path/to/verus clearing/verus/verify.sh
```

If `verus` is on `PATH`, run `clearing/verus/verify.sh` directly. The script resolves
[close_kernel.rs](close_kernel.rs) relative to itself, so an absolute script path
also works from another directory. The recorded validation baseline is Verus
`0.2026.08.23.fbbbbcf` with Rust `1.97.1`: `11 verified, 0 errors`.

The script verifies an arithmetic model. **It does not machine-check the model's
correspondence to production Rust.** Review both together when either changes.

## The account equation

A row describes one account in one immutable epoch. Balances, deposit, debit, and
credit inputs are `u64`. Zero balance denotes absence; positive balances are the
values stored in QMDB. Credits remain virtual. Only an authorized withdrawal
produces a settlement output.

```text
predecessor + deposit + credit - debit
                   |
                   v
                  tail
                   |
        +----------+-----------+
        |          |           |
       None     Amount(a)     Close
        |          |           |
     release 0   a if covered   release tail
                 0 otherwise
        |          |           |
        +----------+-----------+
                   |
                   v
         successor = tail - release
```

Underfunding rejects. Both successor and withdrawal must fit `u64`; widened
intermediates allow valid netting even when an intermediate sum exceeds `u64`.
`None` produces `Output::None`. A withdrawal action that releases zero still
produces `Output::Withdrawal(0)`.

## What is proved

- **Soundness, completeness, and uniqueness:** `derive_successor` returns exactly
  when the balance/output equations have a representable solution, and those
  equations determine one successor and output.
- **Receive-only creation:** an account with no predecessor balance or sealed
  deposit can receive virtual credit, but cannot debit or withdraw in that epoch.
  Its successor is the credit and its output is `None`, whether it was never
  funded or previously deleted.
- **Row conservation:** for any sequence satisfying `row_valid`, the sum of
  successor balances, gross debits, and withdrawals equals the sum of predecessor
  balances, gross credits, and deposits. Withdrawal values come from the outputs.
- **Settlement liability:** assuming gross debit equals gross credit, summing the
  rows gives `successor liability = predecessor liability + deposits - withdrawals`.
  `checked_successor_liability` proves the widened executable computation and
  rejects exactly when the integer result is outside `u64`.

These arithmetic proofs are independent of the finite lifecycle exploration in
[Stateright](../stateright/README.md).

## Production correspondence and limits

The two executable mirrors correspond to
[transition.rs](../src/bajillion/transition.rs): `derive_successor` mirrors the
balance/output block in `derive`, and `checked_successor_liability` mirrors the
function of the same name. Production derives debit and credit from the same
vector entries and accumulates releases into `withdrawal_total`.

The mirror receives already-selected inputs. Production's
`Option<WithdrawalAction>` becomes `Action::None/Amount/Close`; the model also
covers Amount zero, which the production boundary type excludes. Production
`Result` errors become `None`, and checked conversions become explicit range
checks.

Arithmetic completeness applies after input selection. It does not establish
that every arithmetic-valid row is a valid protocol row. `row_valid` requires
receive-only behavior when predecessor and deposit are zero, but allows more
than production accepts, including an absent row with no activity. Exact boundary
coverage, account activity, per-edge amount/count rules, resource limits,
signatures, and canonical account/vector order remain production obligations.

Gross payment conservation is a hypothesis, not a verified vector traversal.
Checked aggregation of `withdrawal_total`, QMDB mutation, and the connection from
row sums to authenticated full-state liability and roots are outside the proof.
Unchanged accounts contribute equal balances to both sides. Withdrawal custody
and reserves, FIFO finalization, faults and finalized-only recovery, QMDB history,
hashing, receipt challenges, and certification retention also remain outside
this arithmetic model.
