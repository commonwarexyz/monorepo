# Minimmit Alteration - Quint Spec

This model challenges the claim that the following 3-quorum alteration can safely
support `f < 1/3`:

- notarization: `m = n - 3f`
- nullification: `q = 2f`
- finalization: `l = n - f`

It shows that this claim is false under Minimmit-style safety/liveness constraints.

## What Is Being Checked

The reusable module is [`three_quorum_family.qnt`](./three_quorum_family.qnt). It
defines:

- `X1` safety: `m + l >= n + f + 1`
  - If one block can be finalized in a view, a conflicting block in the same view must not be able to reach notarization support.
- `X2` safety: `q >= n - l + f + 1`
  - If a block can be finalized in a view, that same view must not also be nullifiable/abortable.
- progress: `q <= n - f - m + 1`
  - If notarization does not form, nullification must still be reachable so replicas can leave the view instead of getting stuck.
- `admissible := thresholds_in_range && X1 && X2 && progress`

Together, `X1` and `X2` avoid contradictory safety outcomes, while `progress` prevents deadlock.

## What Is Wrong With The Original Claim

1. In Minimmit, the small quorum is `2f+1`, not `2f`.
2. If you set `q = 2f`, then `X2` is violated immediately:
   - with `l = n - f`, `X2` becomes `q >= 2f + 1`
   - so `2f` is always too small.
3. Even if you fix nullification to `q = 2f+1`, `f ~ 33%` still fails:
   - with `m = n - 3f` and `l = n - f`, `X1` reduces to `n >= 5f + 1`
   - this caps faults at about `20%`, not `33%`.

So this family does not extend safe operation to `f < 1/3`. It stays in the `f < 1/5` regime.

## Concrete Counterexamples

- [`main_n100f32_q2f.qnt`](./main_n100f32_q2f.qnt): `n=100, f=32, q=2f`
  - `m=4, q=64, l=68`
  - `X1`: `m+l = 72 < n+f+1 = 133` (fails)
  - `X2`: `q = 64 < 65` (fails)
- [`main_n100f32_q2f1.qnt`](./main_n100f32_q2f1.qnt): `n=100, f=32, q=2f+1`
  - `X2` and progress hold, but `X1` still fails, so not admissible.
- [`main_n100f19_q2f1.qnt`](./main_n100f19_q2f1.qnt): `n=100, f=19, q=2f+1`
  - admissible (consistent with the `n >= 5f+1` bound).

## How To Read Verification Results

- `safe` checks symbolic identities/lemmas for the family (for example
  `X1 <=> n >= 5f+1`), not that a specific `(n,f)` is admissible.
- `expected` checks each instance-specific claim.
- To directly test if an instance is safe under this abstraction, verify `admissible`:

```bash
quint verify --invariant=admissible --max-steps=1 main_n100f32_q2f1.qnt   # should fail
quint verify --invariant=admissible --max-steps=1 main_n100f19_q2f1.qnt   # should pass
```

## Run

```bash
cd pipeline/minimmit-alteration/quint
make typecheck
make verify
```
