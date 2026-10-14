# PS-SAS vs BLS: benchmark results

Results for the Pointcheval-Sanders synchronized aggregate signature (PS-SAS) prototype against
the BLS batch verifier Multimmit uses today. The design and security analysis are in
[`SYNCHRONIZED_AGGREGATE.md`](SYNCHRONIZED_AGGREGATE.md).

## Summary

- With 70% of votes distinct (30% of voters share one body, the rest each cast their own),
  PS verifies a quorum certificate **3.8x / 7.0x / 10.2x** faster than BLS at quorums of 25 / 81
  / 201 signers (MinPk). A batch of independently signed votes verifies **2.4x / 3.7x / 4.6x**
  faster.
- The advantage grows with the number of distinct messages. BLS pays a hash to curve and a Miller
  loop per distinct message (about 0.22 ms each). PS pays two pairings, one period hash, and an MSM
  over the signers' public keys (about 10-20 us per signer in G1).
- When every vote is identical, PS is 10% (MinPk) to 20% (MinSig) slower on a certificate. The
  crossover is around 5 distinct messages.
- MinPk is the better layout for PS: its MSM runs in G1. Under MinSig the MSM runs in G2, and
  speedups roughly halve.
- Transaction blocks from different chains batch well when they share a height (3x to 6x
  faster). When every block is at a different height, PS is 20% (MinPk) to 40% (MinSig) slower.
- With a cached period base, PS signing is about 2x faster than BLS.

## What was measured

- **Primitive.** `commonware_cryptography::bls12381::primitives::ops::sas` (ALPHA): keys, Schnorr
  proof of knowledge, signing, and `verify_claims` with per-period grouping, per-message folding,
  random weights, and bisection.
- **Baseline.** `ops::batch::verify_claims`, which Multimmit's `claims.rs` and `batch.rs` call.
- **Bench.** `cryptography/src/bls12381/benches/sas_vs_bls.rs`, run with
  `cargo bench -p commonware-cryptography --bench bls12381_sas`. Both schemes get identical keys,
  150-byte messages, and claim shapes.
- **Workloads:**
  - `certificate`: one atomic aggregate over `q` signers, like a V-QC or L-QC.
  - `votes`: `q` independently signed claims in one period, as the verifier actor sees them.
  - `blocks`: `q` claims, each over its own message, spread across `periods` periods (heights).
    BLS ignores periods.
- **Message spreads:**
  - `distinct=d`: signer `i` signs message `i % d`.
  - `distinct=70pct`: 30% of signers share one message and the rest each sign their own.
- **Quorum sizes.** `q` = 25, 81, and 201 are the `n - f` quorums of committees of 31, 101, and 251
  (`n = 5f + 1`).
- **Environment:**
  - Apple M5 Pro, macOS Low Power Mode off, Rust 1.95.0.
  - Sequential verification only.
  - Criterion with 10 samples, 0.2 s warm-up, and 1 s measurement.
  - Times are means.
  - Identical BLS workloads (`votes distinct=all` and `blocks`) agree within 1%.

## Caveats

- These are cryptography-only costs. Multimmit also rebuilds the vote bodies from a certificate
  and runs structural checks, which both schemes pay, so the end-to-end speedup on `verify_lqc` will
  be smaller. The Multimmit `aggregate` bench now takes a vote-divergence setting and a known-vote
  setting for BLS, but it has not been run yet.
- Discharging votes that were already verified individually is not measured here. It removes terms
  from both schemes, which shrinks the absolute gap.
- An earlier run used 8 threads on this machine's 6 performance cores, and its results were
  dominated by noise. Parallel results are not reported.
- PS is not integrated into the Multimmit `Scheme`.

## Results

### MinPk (keys in G1, signatures in G2)


`certificate` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| distinct=1 | 0.63 / 0.71 (0.89x) | 0.85 / 0.94 (0.90x) | 1.29 / 1.44 (0.90x) |
| distinct=5 | 1.40 / 0.78 (1.79x) | 1.61 / 1.02 (1.59x) | 2.07 / 1.52 (1.36x) |
| distinct=20 | 4.32 / 1.10 (3.93x) | 4.57 / 1.32 (3.48x) | 5.11 / 1.83 (2.79x) |
| distinct=70pct | 4.17 / 1.10 (3.79x) | 12.38 / 1.78 (6.95x) | 31.40 / 3.07 (10.23x) |
| distinct=all | 5.31 / 1.16 (4.60x) | 16.62 / 1.92 (8.64x) | 41.18 / 3.46 (11.90x) |

`votes` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| distinct=1 | 1.96 / 1.99 (0.98x) | 4.71 / 3.38 (1.40x) | 10.47 / 6.43 (1.63x) |
| distinct=5 | 2.60 / 2.00 (1.30x) | 5.39 / 3.82 (1.41x) | 11.19 / 7.21 (1.55x) |
| distinct=20 | 5.08 / 2.01 (2.53x) | 7.88 / 3.81 (2.07x) | 13.67 / 7.36 (1.86x) |
| distinct=70pct | 5.01 / 2.13 (2.36x) | 14.62 / 3.95 (3.70x) | 34.97 / 7.56 (4.63x) |
| distinct=all | 5.92 / 2.01 (2.94x) | 18.09 / 3.88 (4.66x) | 44.23 / 7.58 (5.84x) |

`blocks` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| periods=1 | 5.91 / 2.01 (2.94x) | 18.11 / 3.84 (4.72x) | 44.47 / 7.46 (5.96x) |
| periods=2 | 5.92 / 2.24 (2.64x) | 18.15 / 4.37 (4.15x) | 44.60 / 8.19 (5.45x) |
| periods=4 | 5.94 / 2.69 (2.21x) | 18.13 / 5.50 (3.29x) | 44.38 / 9.39 (4.72x) |
| periods=all | 5.94 / 7.51 (0.79x) | 18.22 / 23.32 (0.78x) | 44.60 / 57.48 (0.78x) |

One invalid claim, isolated by bisection (BLS / PS ms, speedup):

| workload | q=25 | q=81 | q=201 |
|---|---|---|---|
| votes distinct=all | 14.51 / 9.69 (1.50x) | 41.50 / 22.37 (1.86x) | 97.09 / 47.10 (2.06x) |
| blocks periods=4 | 14.56 / 11.87 (1.23x) | 41.53 / 26.33 (1.58x) | 98.62 / 52.11 (1.89x) |

### MinSig (keys in G2, signatures in G1)


`certificate` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| distinct=1 | 0.63 / 0.80 (0.79x) | 0.93 / 1.15 (0.81x) | 1.54 / 1.90 (0.81x) |
| distinct=5 | 1.34 / 0.98 (1.37x) | 1.65 / 1.33 (1.24x) | 2.25 / 2.09 (1.08x) |
| distinct=20 | 4.12 / 1.58 (2.60x) | 4.43 / 1.94 (2.28x) | 5.05 / 2.69 (1.87x) |
| distinct=70pct | 3.84 / 1.54 (2.50x) | 11.45 / 3.32 (3.45x) | 27.81 / 6.22 (4.47x) |
| distinct=all | 5.06 / 1.78 (2.85x) | 15.75 / 3.88 (4.06x) | 38.69 / 7.42 (5.22x) |

`votes` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| distinct=1 | 2.66 / 2.61 (1.02x) | 7.34 / 4.58 (1.60x) | 17.43 / 8.84 (1.97x) |
| distinct=5 | 3.08 / 2.62 (1.18x) | 7.79 / 5.77 (1.35x) | 17.86 / 10.47 (1.71x) |
| distinct=20 | 4.76 / 2.62 (1.81x) | 9.43 / 5.77 (1.63x) | 19.51 / 11.45 (1.70x) |
| distinct=70pct | 4.63 / 2.67 (1.73x) | 13.77 / 5.86 (2.35x) | 33.39 / 11.49 (2.91x) |
| distinct=all | 5.33 / 2.62 (2.03x) | 16.27 / 5.80 (2.81x) | 39.75 / 11.40 (3.49x) |

`blocks` (BLS / PS ms, speedup):

| shape | q=25 | q=81 | q=201 |
|---|---|---|---|
| periods=1 | 5.33 / 2.62 (2.03x) | 16.25 / 5.81 (2.80x) | 39.75 / 11.38 (3.49x) |
| periods=2 | 5.34 / 3.09 (1.73x) | 16.27 / 6.89 (2.36x) | 39.78 / 13.15 (3.02x) |
| periods=4 | 5.33 / 3.59 (1.48x) | 16.27 / 7.71 (2.11x) | 39.74 / 15.59 (2.55x) |
| periods=all | 5.34 / 8.90 (0.60x) | 16.37 / 27.88 (0.59x) | 39.75 / 68.59 (0.58x) |

One invalid claim, isolated by bisection (BLS / PS ms, speedup):

| workload | q=25 | q=81 | q=201 |
|---|---|---|---|
| votes distinct=all | 13.08 / 12.48 (1.05x) | 36.51 / 31.06 (1.18x) | 84.47 / 67.36 (1.25x) |
| blocks periods=4 | 13.09 / 14.96 (0.87x) | 36.58 / 35.38 (1.03x) | 84.50 / 74.50 (1.13x) |

### Signing (us)

| variant | BLS | PS, base hashed | PS, base cached |
|---|---|---|---|
| minpk | 163.0 | 162.2 | 77.8 |
| minsig | 68.0 | 69.6 | 40.4 |

## Next steps

1. Run the Multimmit `aggregate` bench (BLS, sequential) across `distinct` and `known`, to measure
   the non-cryptographic overhead that bounds the end-to-end speedup.
2. Measure real vote-body divergence and chain-height spread from `log-multimmit` runs, to pick the
   rows that matter.
3. If the gains hold, integrate PS behind the Multimmit `Scheme`. This covers ordinary keys only;
   DA and nullification stay threshold BLS.
