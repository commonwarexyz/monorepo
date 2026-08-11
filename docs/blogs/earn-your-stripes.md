---
title: "Earn Your Stripes"
description: "Reed-Solomon recovery stayed single-core inside Commonware's parallel reconstruction path. By splitting shards into aligned stripes and removing a redundant re-encode, we made worst-case block reconstruction scale with available cores."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Sunghyeon Jo"
author_twitter: "https://x.com/kaizero_ainta"
author2: "Patrick O'Grady"
author2_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/earn-your-stripes"
image: "https://commonware.xyz/imgs/reed-solomon-stripes.png"
katex: true
---

In `marshal::coding`, a leader erasure-codes a block into shards and sends one to each validator. Validators can check their shard and vote on the commitment without waiting for the whole payload.

But eventually, a node needs the full block. Once it gathers enough checked shards, it can begin reconstruction. The most expensive part of this reconstruction is Reed-Solomon recovery, and until recently, it was stuck on a single core.

## Where `Strategy` fell short

Decode already accepted a `Strategy` for parallelism, and it helped: the per-shard hashing and Merkle work around decode spread across cores. The recovery itself did not. It stayed a single sequential `decoder.decode()` call, because `reed-solomon-simd` is optimized for one core with SIMD rather than threads. So even at `conc=8`, the costly part still ran on one core.

Benchmarks on an Apple M5 Pro (8 MiB block, 250 chunks) show the gap. `best` decodes with all originals present (no recovery); `worst` forces full recovery:

| Workers | Best | Worst | Gap |
|:--------|-----:|------:|----:|
| 1 | 34.96 ms | 51.19 ms | 16.23 ms |
| 8 | 9.45 ms | 26.85 ms | 17.40 ms |
| 16 | 7.90 ms | 25.94 ms | 18.04 ms |

From 1 to 16 workers the parallelizable work dropped from 34.96 ms to 7.90 ms, but the gap between `best` and `worst` held near 16 to 18 ms. That gap is only a proxy for recovery because the two cases hash different missing shards, but concurrency was not reaching the full-width decoder.

## From One Decoder to Many

Reed-Solomon encoding represents the block as `k + m` equal-length shards, with `k` original shards and `m` recovery shards. When original shards are missing, any `k` shards can recover the original block. Before this change, recovery handed the full shard width to one Reed-Solomon decoder.

To recover one position inside a missing shard, the decoder only needs that same position from the available shards. We turn that into parallel work by cutting the shard width into contiguous byte ranges, or stripes. Each stripe covers the same range across all shards, runs as its own Reed-Solomon job, and is scheduled through `Strategy`.

```{=html}
<style>
  .cw-rs-figure {
    aspect-ratio: 800 / 690;
    margin: 28px 0 6px;
  }

  .cw-rs-figure-verify {
    aspect-ratio: 800 / 510;
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
Figure 1: Recovering missing original shard `D1` used to run as one full-width Reed-Solomon job. After striping, each aligned range becomes its own job; `Strategy` runs them in parallel, then the recovered ranges concatenate into the same full-width `D1`.
:::

Stripe cuts land on 64-byte shard-chunk boundaries (`SHARD_CHUNK_BYTES`) so the vendored codec (`reed-solomon-simd`) sees the layout it expects. The output is the same as one full-width decode, just scheduled across several disjoint ranges.

## Results

The same worst-case decode, before and after striping:

| Workers | Before | After | Speedup |
|:--------|-------:|------:|--------:|
| 1 | 51.19 ms | 51.79 ms | - |
| 8 | 26.85 ms | 10.22 ms | 2.63x |
| 16 | 25.94 ms | 7.67 ms | 3.38x |

At `conc=1` nothing changes; one stripe is the original decode. At `conc=8`, recovery finally rides the same cores as everything else, and worst-case decode drops from 26.85 ms to 10.22 ms, a 2.63x speedup. At `conc=16`, it drops to 7.67 ms, a 3.38x speedup. The recovery tail that used to ignore concurrency is now the part that shrinks the most.

## Vendoring and Further Optimizations

Striping made recovery parallel, but the verification path still ran Reed-Solomon twice. After it decoded missing originals, it re-encoded every recovery shard, compared any provided recoveries with that output, and rebuilt the Merkle root over the complete codeword. As explained in [Deliver Us in Pieces](/blogs/coding), checking a shard against the commitment does not by itself show that all committed shards form one valid Reed-Solomon codeword.

After we [vendored `reed-solomon-simd`](https://github.com/commonwarexyz/monorepo/pull/4092), Patrick noticed that the second pass was unnecessary whenever an original shard was missing. The decoder had already computed the missing recovery positions but exposed only missing originals, so we extended it to reveal both.

The recovery path now feeds exactly `k` shards to the decoder. If more were received, surplus recovery shards are forgotten and reconstructed too. One decode returns every missing original and recovery position, and rebuilding the Merkle root still binds the complete codeword to the commitment. We skip the encode, not the verification.

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

| Workers | Decode + encode | Decode + reveal | Change |
|:--------|----------------:|----------------:|-------:|
| 8 | 10.20 ms | 9.09 ms | 10.8% lower |
| 16 | 7.64 ms | 6.87 ms | 10.1% lower |

These are end-to-end measurements of the recovery-heavy verification path, not isolated timings of the two transforms.

The final [pull request](https://github.com/commonwarexyz/monorepo/pull/4091) combines striping with decode-reveal:

| Workers | Baseline | Final | Speedup |
|:--------|---------:|------:|--------:|
| 1 | 51.19 ms | 47.14 ms | 1.09x |
| 8 | 26.85 ms | 8.91 ms | 3.01x |
| 16 | 25.94 ms | 6.51 ms | 3.99x |

The one-worker row is an end-to-end baseline-to-final comparison; it does not isolate either optimization on its own. The final patch also checks that striped and full-width operations produce the same codeword, that revealed recovery shards match encoder output, and that tampered originals, recoveries, padding, and surplus shards are rejected.

## LLM in a Research Loop

QED's bot—our AI research agent—found this optimization by reading the coding stack and noticing that the hashing and Merkle work in decode was parallelized, but Reed-Solomon recovery was not. Then it tested the hypothesis that recovery could be split into independent stripes and run in parallel.

The loop used here looks a lot like our security audit agent. It keeps scanning the code, gathers evidence from the repo, forms hypotheses, and verifies them with tests and benchmarks. Whether a finding is useful depends on repository context. A finding may be a known issue or an intentional design choice, so the lessons from continuous auditing Commonware helped a lot to find a valid optimization.

## Next Steps

We found similar sequential bottlenecks elsewhere in the coding stack. The NTTs under ZODA are next, and that work is already underway.
