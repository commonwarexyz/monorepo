# Bajillion close arithmetic

This directory uses Verus to check the balance and withdrawal equations for a
close, from individual accounts to the combined settlement liability.

From the workspace root, point `VERUS_BIN` at an installed Verus binary:

```bash
VERUS_BIN=/path/to/verus clearing/verus/verify.sh
```

If `verus` is on `PATH`, run `clearing/verus/verify.sh` directly. The recorded
validation baseline is Verus `0.2026.08.23.fbbbbcf` with Rust `1.97.1`.

## The account equation

A row describes one account's activity in an epoch. Its predecessor balance,
deposit, credit, and debit determine the balance available for withdrawal:

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

The debit must be covered. Inputs and results fit `u64`, while intermediate
arithmetic is widened to allow netting. Zero successor balance means absence
from QMDB. A withdrawal that releases zero still produces `Withdrawal(0)`,
distinct from having no withdrawal action. Each output, including `Withdrawal(0)`,
occupies a native payout Append location; the interval ledger consumes that
location independently of its monetary amount. These log and ledger guarantees
are checked by the Stateright and production tests, outside this arithmetic proof.

## What is proved

- **Account results:** the equations determine one successor balance and output.
  `derive_successor` returns them exactly when they fit the supported range.
- **Absent accounts:** an account without a predecessor balance or deposit
  cannot debit. Incoming credit can create a balance or fund a selected withdrawal.
- **Conservation:** summing valid rows preserves balances, deposits, payments,
  and withdrawals. If total debit equals total credit, the payment terms cancel:

```text
  successor liability = predecessor liability + deposits - withdrawals
```

`checked_successor_liability` also verifies this computation's range checks.

## Maintaining the proofs

[close_kernel.rs](close_kernel.rs) models the balance/output block of `derive`
and `checked_successor_liability` in
[transition.rs](../src/bajillion/transition.rs). Review them together when either
changes. Verus checks the model, not its correspondence to production Rust.

The proofs start from selected row inputs and withdrawal actions. Input
authentication, action eligibility, and persistence belong to the surrounding
protocol. Equal total debit and credit is an assumption of the liability proof.
