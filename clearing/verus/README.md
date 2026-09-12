# Verified close arithmetic

`close_kernel.rs` models the full-replica close's balance-only account arithmetic.
A predecessor or successor is a `u64`; zero denotes absence, and positive balances
are the values stored in QMDB. Debit and credit are totals for one immutable epoch.
No lifetime counters, active flag, or running prefix are modeled.

The Verus proofs establish:

- **Soundness and completeness:** `derive_successor` returns exactly when the
  balance and output equations have a representable solution. Underfunding and
  final-balance overflow reject; widened intermediates permit valid netting.
- **Uniqueness:** those equations determine one successor balance and one
  settlement output. An uncovered Amount request still produces `Withdrawal(0)`.
- **Liability conservation:** for any sequence of arithmetic-valid rows whose
  withdrawals target registered accounts, successor balances plus gross debit,
  withdrawals, and payouts equal predecessor balances plus gross credit and
  deposits. The amounts are extracted from the actual classified outputs.
- **Settlement liability:** assuming the epoch's gross debit equals gross credit,
  the two output totals determine successor liability. The executable
  `checked_successor_liability` mirror proves the exact widened computation and
  rejects precisely when its integer result is outside `u64`.

Run from any directory:

```bash
VERUS_BIN=/path/to/verus /path/to/clearing/verus/verify.sh
```

Validated with official Verus release `0.2026.08.23.fbbbbcf` and Rust `1.97.1`:
`8 verified, 0 errors`.

## Production correspondence

Both executable mirrors correspond to `clearing/src/bajillion/transition.rs`:

| Model | Production |
| --- | --- |
| `derive_successor` | The balance/output block in `derive` |
| `checked_successor_liability` | `checked_successor_liability` |
| `row_valid` withdrawal eligibility | `derive` rejects an unregistered account with a withdrawal request |
| Gross debit equals gross credit | `derive` sums each outgoing vector and routes those same entries to incoming credit |
| Output sums | Checked additions to `CloseAmounts.withdrawal` and `.payout` |

`derive_successor` receives the already selected balance, epoch vector totals,
deposit amount, and withdrawal action. Production uses `Option<WithdrawalAction>`
and positive Amount values; the model uses `Action::None` and also proves the
arithmetic for Amount zero. Production `Result` errors become `None`, `u128::from`
becomes a widening cast, and checked combinators and narrowing conversions become
explicit matches and range checks. These are arithmetic mirrors, not identical
source text or a machine-checked refinement of production Rust. Review these two
production blocks alongside the model whenever either changes; `verify.sh` only
checks the model.

## Proof boundary

Arithmetic completeness applies after input selection; it does not claim every
arithmetic solution passes full-close validation. In particular, activity
eligibility, exact boundary coverage, per-edge amount/count rules, limits,
signatures, and canonical account/vector order remain production obligations.
The summed liability theorem needs only the withdrawal eligibility implication,
so its `row_valid` predicate deliberately covers more than accepted protocol rows.

Gross payment conservation is a hypothesis of the liability theorem. The model
does not verify vector traversal, checked aggregation into `CloseAmounts`, or the
QMDB mutation application. Unchanged accounts contribute equal balances on both
sides, but connecting these sums to authenticated full-state liability and roots
remains outside the proof. QMDB history/recovery, hashing, signatures, private
receipt challenges, and certification retention are also outside this model.
