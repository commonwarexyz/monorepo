# Verified close kernels

Machine-checked proofs (Verus, SMT-backed) for the pure arithmetic the sender-vector close
leans on hardest, complementing the Stateright model's temporal coverage:

- `derive_successor` **soundness**: the forward derivation satisfies every
  successor-determining equation row validation checks.
- `derive_successor` **completeness**: when derivation refuses, no satisfying successor
  exists.
- **Uniqueness**: the equations admit exactly one successor and settlement output, so the
  posted corpus (which omits both) has exactly one reconstruction.
- **Prefix conservation**: a completed `checked_extend` chain equals the exact
  componentwise sum of its deltas, for all eight counters.
- **Liability conservation**: summed over any sequence of valid rows, successor balances
  plus withdrawals and payouts equal predecessor balances plus deposits once gross debit
  and credit cancel. This is the equation `checked_successor_liability` and
  `validate_terminal_prefix` enforce, proven from the per-row balance equations alone.

Out of scope: anything under a hash or signature (lattice-hash collision resistance,
commitment reconstruction, BLS aggregation) is axiomatized by the surrounding protocol
argument, not proven here.

Run `VERUS_BIN=/path/to/verus ./verify.sh`. The exec bodies mirror
`bajillion/posted.rs::derive_successor` and `bajillion/state.rs::Prefix::checked_extend`
and must be kept line-equivalent; single-source integration through `vstd` is the
production follow-up.
