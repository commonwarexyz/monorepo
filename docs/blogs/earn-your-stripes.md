---
title: "Earn Your Stripes"
description: "Striping Reed-Solomon recovery across cores and avoiding a separate re-encode made worst-case decoding nearly 4x faster."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Sunghyeon Jo (QED)"
author_twitter: "https://x.com/kaizero_ainta"
author2: "Patrick O'Grady"
author2_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/earn-your-stripes"
image: "https://commonware.xyz/imgs/reed-solomon-stripes.png"
katex: true
---

When one leader pushes a full block to every validator, its egress bounds throughput while everyone else's bandwidth sits idle. [Deliver Us in Pieces](/blogs/coding) showed how erasure coding puts that idle bandwidth to work. In `marshal::coding`, the leader sends each validator one shard. Validators relay them and vote on the commitment before anyone reconstructs the whole payload.

The expensive transforms still sit on the critical path. The leader must finish encoding before it can disperse the block. At `certify`, each validator must reconstruct the full block before full application verification can begin. On the original recovery path, it also re-encoded the recovered originals to verify the commitment. Reed-Solomon recovery was the most expensive step, and until recently it ran on one core.

## Parallel Hashing, Serial Recovery

Decode already accepted a `Strategy`, but it used the worker pool only to hash missing shards for the Merkle root. Reed-Solomon recovery remained one synchronous `decoder.decode()` call. `reed-solomon-simd` selects a SIMD backend on supported CPUs, but one encode or decode call does not spawn worker threads. Even at `conc=8`, the costly part still ran on one core.

Benchmarks on an Apple M5 Pro (8 MiB block, 250 chunks) show where recovery stops scaling. The all-original case does no recovery. The full-recovery case reconstructs every original:

```{=html}
<style>
  .cw-rs-chart {
    aspect-ratio: 500 / 310;
    margin: 24px auto 6px;
    max-width: 600px;
  }
</style>
<noscript>
  <style>
    .cw-rs-chart {
      display: none;
    }
  </style>
</noscript>
<div id="earn-your-stripes-chart-recovery-gap" class="cw-rs-chart" role="img" aria-label="Line chart of latency by worker count. With 1, 8, and 16 workers, full recovery takes 51.19, 26.85, and 25.94 milliseconds, while the all-original path takes 34.96, 9.45, and 7.90 milliseconds. The recovery-heavy path flattens as more workers are added."></div>
<noscript>
  <table>
    <thead><tr><th>Workers</th><th>Full recovery</th><th>All originals</th></tr></thead>
    <tbody>
      <tr><td>1</td><td>51.19 ms</td><td>34.96 ms</td></tr>
      <tr><td>8</td><td>26.85 ms</td><td>9.45 ms</td></tr>
      <tr><td>16</td><td>25.94 ms</td><td>7.90 ms</td></tr>
    </tbody>
  </table>
</noscript>
```

From 1 to 16 workers, all-original end-to-end latency dropped from 34.96 ms to 7.90 ms. Full recovery improved through 8 workers, then flattened near 26 ms. The 16 to 18 ms separation is only a proxy for recovery because the two cases hash different missing shards. Even so, concurrency was not reaching the full-width decoder.

## From One Decoder to Many

Reed-Solomon encoding represents the block as $k + m$ equal-length shards, with $k$ original shards and $m$ recovery shards. When original shards are missing, any $k$ shards can recover the original block. Before this change, recovery handed the full shard width to one Reed-Solomon decoder.

To recover one 16-bit symbol inside a missing shard, the decoder only needs the corresponding symbol column from the available shards. We turn that into parallel work by cutting the shard width into contiguous byte ranges, or stripes. Each stripe covers the same range across all shards, runs as its own Reed-Solomon job, and is scheduled through `Strategy`.

Let $a_i$ be the codeword index of supplied shard $S_i$, for $i = 1, \ldots, k$, and write $A = (a_1, \ldots, a_k)$. All supplied shards have the same even byte length. Split them into $p$ stripes at identical boundaries. Every non-final boundary is aligned to `SHARD_CHUNK_BYTES` (64 bytes), so the original partial tail, if any, remains wholly in the final stripe. For every stripe $t$, the decoder receives the indexed slices $(a_i, S_i^{(t)})$, preserving each shard's original codeword index:

$$
S_i = S_i^{(0)} \mathbin\Vert S_i^{(1)} \mathbin\Vert \cdots \mathbin\Vert S_i^{(p-1)}.
$$

Reed-Solomon recovery works independently at each symbol position. Stripe $t$ therefore recovers only stripe $t$ of the missing shard $D_1$:

$$
D_1^{(t)} = \operatorname{recover}_{D_1,A}\!\left(S_1^{(t)}, \ldots, S_k^{(t)}\right),
\qquad
D_1 = D_1^{(0)} \mathbin\Vert \cdots \mathbin\Vert D_1^{(p-1)}.
$$

No stripe reads or writes another stripe. `Strategy` can schedule the $p$ decoder calls in parallel, and concatenating their outputs produces the same $D_1$ as one full-width call.

```{=html}
<style>
  .cw-rs-figure {
    aspect-ratio: 800 / 570;
    margin: 28px 0 6px;
  }

  .cw-rs-figure-verify {
    aspect-ratio: 800 / 415;
  }
</style>
<noscript>
  <style>
    .cw-rs-figure {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      margin: 28px 0 6px;
      padding-left: 12px;
    }
  </style>
</noscript>
<div id="earn-your-stripes-fig-striping" class="cw-rs-figure" role="img" aria-label="Animated comparison of full-width and striped Reed-Solomon recovery. Checked shards D0, D2, and R0 recover missing original shard D1. Before striping, one job spans the full shard width. After striping, aligned vertical cuts divide the three inputs and D1 output into the same ranges, which run as independent Reed-Solomon jobs through Strategy and reconstruct the same D1 in parallel.">
  <noscript>Checked shards D0, D2, and R0 recover missing original shard D1. Before striping, one Reed-Solomon job processes the full shard width. Striping applies the same byte-range cuts to the three inputs and D1 output; each range is an independent job, so Strategy can run them in parallel. Non-final cuts are aligned to 64-byte engine-block boundaries, and the reconstructed slices concatenate to the same D1.</noscript>
</div>
<script type="module" src="earn-your-stripes.js"></script>
```

::: {.image-caption}
Figure 1: Recovering missing original shard `D1` used to run as one full-width Reed-Solomon job. After striping, each aligned range becomes its own job. `Strategy` runs them in parallel, then the recovered ranges concatenate into the same full-width `D1`.
:::

The alignment is specific to the vendored codec rather than Reed-Solomon itself. `reed-solomon-simd` packs work into 64-byte shard chunks, and cutting through one would change how a sub-instance packs and pads its tail. Aligned cuts produce the same output as one full-width decode, just scheduled across several disjoint ranges.

## Recovery Scales

We reran the same worst-case decode before and after striping:

```{=html}
<div id="earn-your-stripes-chart-striping" class="cw-rs-chart" role="img" aria-label="Line chart of worst-case decode latency before and after striping. With 1, 8, and 16 workers, latency changes from 51.19 to 51.79 milliseconds, 26.85 to 10.22 milliseconds, and 25.94 to 7.67 milliseconds. The latter two improvements are 2.63 and 3.38 times."></div>
<noscript>
  <table>
    <thead><tr><th>Workers</th><th>Before</th><th>After</th><th>Speedup</th></tr></thead>
    <tbody>
      <tr><td>1</td><td>51.19 ms</td><td>51.79 ms</td><td>-</td></tr>
      <tr><td>8</td><td>26.85 ms</td><td>10.22 ms</td><td>2.63x</td></tr>
      <tr><td>16</td><td>25.94 ms</td><td>7.67 ms</td><td>3.38x</td></tr>
    </tbody>
  </table>
</noscript>
```

At `conc=1`, one stripe follows the original full-width decode, so no parallel speedup is expected. At `conc=8`, recovery finally rides the same cores as everything else, and worst-case decode drops from 26.85 ms to 10.22 ms, a 2.63x speedup. At `conc=16`, it drops to 7.67 ms, a 3.38x speedup. The recovery tail that used to ignore concurrency is now the part that shrinks the most.

## Removing the Second Transform

Striping made recovery parallel, but the verification path still ran Reed-Solomon twice. After it decoded missing originals, it re-encoded every recovery shard, compared any provided recoveries with that output, and rebuilt the Merkle root over the complete codeword. As explained in [Deliver Us in Pieces](/blogs/coding), checking a shard against the commitment does not by itself show that all committed shards form one valid Reed-Solomon codeword.

Once we [vendored `reed-solomon-simd`](https://github.com/commonwarexyz/monorepo/pull/4092), we could extend the decoder to reveal missing recovery positions and remove the second pass whenever an original shard was missing. The expensive decode transform had already evaluated those positions, but the existing API returned only missing originals.

Write the systematic generator matrix as

$$
G = \begin{bmatrix} I_k \\ P \end{bmatrix},
\qquad
C = GX,
$$

where $X$ contains the $k$ original shards, $P$ generates the recovery shards, and $C$ is the complete codeword. In Figure 2, take the ordered row lists $A = (D_0, D_2, R_0)$ and $M = (D_1, R_1)$. Let $G_A$ and $G_M$ select rows of $G$ in those orders. Any $k$ codeword rows determine $X$, so one decode determines both missing rows:

$$
\begin{bmatrix} D_1 \\ R_1 \end{bmatrix}
= G_M G_A^{-1}
\begin{bmatrix} D_0 \\ D_2 \\ R_0 \end{bmatrix}.
$$

The old API returned only $D_1$. Verification then rebuilt the original vector and ran the encoder:

$$
\begin{bmatrix} R_0 \\ R_1 \end{bmatrix}
= P
\begin{bmatrix} D_0 \\ D_1 \\ D_2 \end{bmatrix},
$$

That re-encode repeated the expensive codeword transform to materialize canonical $R_1$. The decode had already evaluated the $R_1$ position. Decode-reveal applies the remaining unscale and final-chunk undo, then returns canonical $R_1$ alongside $D_1$. This is much faster than re-encoding because it finishes the existing decode output instead of running another full Reed-Solomon transform.

The recovery path now feeds exactly $k$ shards to the decoder. If more were received, surplus recovery shards are forgotten and reconstructed too. Let $\rho$ be the committed root. The acceptance condition is unchanged:

$$
\operatorname{BMT}\!\left(H(C_0), \ldots, H(C_{k+m-1})\right)
\stackrel{?}{=} \rho.
$$

Checked positions reuse their verified digests, while reconstructed positions are hashed before the tree is rebuilt. We skip the encode, not the verification.

When the supplied set contains all $k$ original shards, no inverse decode runs and there are no hidden recovery rows to reveal. That path still computes $R = PX$.

The block itself only needs the missing originals. Missing recovery positions matter here because decode also verifies the commitment: rebuilding the BMT root requires a digest at every shard position.

```{=html}
<div id="earn-your-stripes-fig-reveal" class="cw-rs-figure cw-rs-figure-verify" role="img" aria-label="Animated comparison of Reed-Solomon verification before and after decode-reveal. Recovering the block needs missing original D1; rebuilding the commitment root also needs missing recovery R1. Given checked shards D0, D2, and R0, the old decoder computes D1 and R1 but returns only D1. An encoder then regenerates R0 and R1 before the complete codeword is verified. The new decoder reveals both D1 and R1, removing the second transform while retaining the same full commitment check.">
  <noscript>Recovering the block needs missing original D1; rebuilding the commitment root also needs missing recovery R1. Given checked shards D0, D2, and R0, the old decoder computes D1 and R1 but returns only D1. The original shards are then re-encoded to regenerate R0 and R1 before the complete codeword is verified. Decode-reveal returns D1 and R1 from the first transform, so the separate encode is skipped. The implementation still reuses checked digests, hashes reconstructed shards, rebuilds the Merkle tree over all shards, and requires its root to match the commitment. If all original shards are already present, re-encode verification is still used.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Both paths derive `D1` and `R1`. The old decoder hid `R1`, so the encoder derived `R0` and `R1` again before verification. Decode-reveal returns the already-derived `R1` with `D1`, eliminating the second transform while preserving the full-root check. When all `k` originals are supplied there is nothing to decode, so the re-encode path remains.
:::

Exposing recovery positions required updating both the high-rate and low-rate decoders so each revealed recovery shard is byte-identical to the encoder's output, including shard widths that are not 64-byte aligned.

A back-to-back rerun of the striped-only checkpoint and the immediate decode-reveal change isolates the improvement:

```{=html}
<div id="earn-your-stripes-chart-reveal" class="cw-rs-chart" role="img" aria-label="Line chart of recovery-heavy verification latency for decode plus encode and decode plus reveal. With 8 and 16 workers, latency changes from 10.20 to 9.09 milliseconds and from 7.64 to 6.87 milliseconds, reductions of 10.8 and 10.1 percent."></div>
<noscript>
  <table>
    <thead><tr><th>Workers</th><th>Decode + encode</th><th>Decode + reveal</th><th>Change</th></tr></thead>
    <tbody>
      <tr><td>8</td><td>10.20 ms</td><td>9.09 ms</td><td>10.8% lower</td></tr>
      <tr><td>16</td><td>7.64 ms</td><td>6.87 ms</td><td>10.1% lower</td></tr>
    </tbody>
  </table>
</noscript>
```

These are end-to-end measurements of the recovery-heavy verification path, not isolated timings of the two transforms.

The final [pull request](https://github.com/commonwarexyz/monorepo/pull/4091) combines striping with decode-reveal:

```{=html}
<div id="earn-your-stripes-chart-final" class="cw-rs-chart" role="img" aria-label="Line chart of baseline and final recovery-heavy verification latency. With 1, 8, and 16 workers, latency changes from 51.19 to 47.14 milliseconds, 26.85 to 8.91 milliseconds, and 25.94 to 6.51 milliseconds, improvements of 1.09, 3.01, and 3.99 times."></div>
<noscript>
  <table>
    <thead><tr><th>Workers</th><th>Baseline</th><th>Final</th><th>Speedup</th></tr></thead>
    <tbody>
      <tr><td>1</td><td>51.19 ms</td><td>47.14 ms</td><td>1.09x</td></tr>
      <tr><td>8</td><td>26.85 ms</td><td>8.91 ms</td><td>3.01x</td></tr>
      <tr><td>16</td><td>25.94 ms</td><td>6.51 ms</td><td>3.99x</td></tr>
    </tbody>
  </table>
</noscript>
```

The one-worker row is an end-to-end comparison of the baseline and final implementations, so it does not isolate either optimization. The final patch also checks that striped and full-width operations produce the same codeword, that revealed recovery shards match encoder output, and that tampered originals, recoveries, padding, and surplus shards are rejected.

## An AI Research Loop

QED's bot, our AI research agent, found this optimization by reading the coding stack and noticing that hashing the missing shards in decode was parallelized, but Reed-Solomon recovery was not. It then tested whether recovery could be split into independent stripes and run in parallel.

The loop resembles the one used by our security audit agent. It scans the code, gathers repository evidence, forms hypotheses, and verifies them with tests and benchmarks. Whether a finding is useful depends on repository context, since the same pattern may be a known issue or an intentional design choice. Lessons from continuously auditing Commonware helped the bot identify a valid optimization.

## Next Steps

We found similar sequential bottlenecks elsewhere in the coding stack. The NTTs under ZODA are next, and that work is already underway.
