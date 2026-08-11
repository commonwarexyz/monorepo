---
title: "Simplex, Pipelined"
description: "In a 50-validator Alto deployment, Stable Leader and Optimistic Validation sustained about 200 successful views per second at 5ms median block spacing."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Brendan Chou"
author_twitter: "https://x.com/B_Chou"
url: "https://commonware.xyz/blogs/pipelining-simplex"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

Finality tells you when a block is settled. Block spacing tells you how soon the next one can start.

Today, we're introducing Stable Leader and Optimistic Validation, two options that pipeline [Simplex](https://eprint.iacr.org/2023/463) views. Stable Leader removes the handoff between consecutive proposers. Optimistic Validation lets the leader propose a child, and validators vote for it, without first receiving the parent's notarization.

In a global [Alto](https://alto.commonware.xyz) deployment with 50 validators, this combination sustained about 200 successful views per second. Every successful view finalized one block, and the median block spacing was 5ms.

```{=html}
<style>
  .simplex-loop {
    aspect-ratio: 1024 / 430;
    margin: 28px 0 6px;
  }

  .simplex-loop-cadence {
    aspect-ratio: 1024 / 400;
  }
</style>
<noscript>
  <style>
    .simplex-loop {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      margin: 28px 0 6px;
      padding-left: 12px;
    }
  </style>
</noscript>
<div id="simplex-fig-cadence" class="simplex-loop simplex-loop-cadence" role="img" aria-label="Animated 20 by 10 grid showing 200 view intervals in one second. The grid fills at a rate of one red square per 5ms interval. After a pause, the squares return to gray from left to right and the cycle repeats.">
  <noscript>At a 5ms target, 200 view intervals fit into one second. This figure shows them as a 20 by 10 grid of red squares.</noscript>
</div>
<script type="module" src="pipelining-simplex.loops.js"></script>
```

::: {.image-caption}
Figure 1: Each square represents one 5ms target interval. A 20 by 10 grid fills in one second. Alto sustained about 200 successful views per second.
:::

The pipeline keeps new views moving while earlier blocks finish. Once data reaches the leader, it gets another ordering opportunity after one block interval.

A *view* is one opportunity for a leader to propose a block. Validators check and vote on the proposal. The application finishes any remaining work before finalization.

These steps remain ordered for each block, but different blocks can be at different steps. Two waits otherwise limit how quickly new views notarize: a proposer handoff and waiting to receive the parent notarization.

[Stable Leader](https://github.com/commonwarexyz/monorepo/pull/3352) removes the first wait. [Optimistic Validation](https://github.com/commonwarexyz/monorepo/pull/3416) removes the second wait from the path to the next proposal and votes.

## Wait One: The Proposer Handoff

Round-robin assigns each view to a new leader. The next leader may be in another region and receive the prior proposal or certificate later than other validators. The chain waits for that leader to catch up and propose.

Stable Leader groups consecutive views into a *term*. One leader proposes throughout the term. After the leader sees a block notarized, the same leader already has the block and ancestry needed for the next proposal. Election still runs at the term boundary.

```{=html}
<div id="simplex-fig-leaders" class="simplex-loop" role="img" aria-label="Animated comparison of round-robin and stable leaders across 12 views. Round-robin rotates among three leaders every view. With a term length of four, each stable leader proposes four consecutive views before leadership changes. The timeline shows three complete terms and two term boundaries.">
  <noscript>Across 12 views, round-robin changes leaders every view. With a term length of four, each stable leader proposes four consecutive views. The timeline shows three complete terms and two term boundaries.</noscript>
</div>
```

::: {.image-caption}
Figure 2: With a term length of four, round-robin changes the proposer every view while Stable Leader changes it once per term. The timeline shows three complete terms.
:::

Stable leadership removes the proposer handoff. The next proposal and votes can still wait for the parent notarization.

## Wait Two: Waiting for the Parent Notarization

Without Optimistic Validation, the stable leader waits to receive the notarization for view `v` before it proposes view `v+1`. Other validators wait for the same evidence before voting on the child. This puts the network time to form and distribute each notarization on the path between views.

With Optimistic Validation, the leader can start `v+1` after it builds and votes for `v`. A validator that checked and voted for `v` can also check and vote on `v+1` when the proposal arrives. Neither needs to receive the notarization for `v` first.

The proposal and votes for `v+1` can overlap the network round that forms the notarization for `v`. The same rule can carry the pipeline across several views within the stable-leader term.

The optimization changes when validators cast notarize votes. It does not change the finalization rule.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop" role="img" aria-label="Animated comparison of sequential and optimistic validation. In the sequential path, each child proposal and its votes wait for the parent notarization. In the optimistic path, child views begin closer together while parent notarizations form on a parallel lane.">
  <noscript>Without Optimistic Validation, each child view waits for the parent notarization. With Optimistic Validation, child views can begin while parent notarizations form.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Optimistic Validation pipelines new views (red) over the formation of parent notarizations (blue). Both panels use the same horizontal time scale.
:::

## How Optimism Stays Safe

`Optimistic` describes when a participant starts the next view. It does not weaken the evidence required for finalization.

A participant works ahead only after it has voted for the parent, or when it holds usable quorum proof. The same rule applies to every optimistic ancestor. A validator only certifies a child or votes to finalize it after the parent is certified. If an ancestor fails to notarize or certify, optimistic votes above it become inert. Validators then abandon that part of the term through the normal timeout path.

The lookahead stops at the term boundary. The first view of a new term must start from ancestry that has passed the application check.

The lookahead is local policy. A value of zero disables Optimistic Validation. Validators can choose different values without affecting safety. A larger value uses more CPU and memory on work that may later be discarded. A smaller value can limit the pipeline when notarizations fall behind.

## What We Measured

Here are the relevant configuration and results for the 50-validator Alto run:

| | |
|---|---:|
| Deployment | 50 validators, 5 in each of 10 AWS regions |
| Instance | `c7gd.4xlarge` |
| Workload | Header-only blocks, no transactions or execution |
| Block target | 5ms |
| Stable term | 10,000 views |
| Optimistic lookahead | 100 views |
| Throughput capture | About three minutes of one-second reporting windows |
| Successful views / finalized blocks | About 200 per second |
| Median block spacing | 5ms in each reporting window |
| External-observer finality | p50 300ms / p99 376ms (`n=3,736`) |

A separate capture measured 300ms median latency from the leader-stamped block timestamp until an external observer received its finalization certificate. This measurement includes indexer and WebSocket delivery. At 5ms per view, one 300ms observer-latency window spans about 60 view intervals.

## Choose the Pipeline

Start with the stage that limits your view rate. Alto's settings are an example, not a default.

| Limiting stage | Configuration | Main cost |
|---|---|---|
| Proposer handoff | Stable Leader without Optimistic Validation | Longer proposer authority |
| Waiting for parent notarizations | Add Optimistic Validation | More speculative CPU and memory |
| Application checks, execution, storage, proposal checks, or dissemination capacity | Improve that stage first | A deeper window will fill |

Longer terms amortize more handoffs, but give one leader more consecutive proposals. Alto's 10,000-view term lasted roughly 50 seconds at the measured cadence. Validators can skip a stalled term. A term-wide timeout covers a leader that keeps views moving without finalizing blocks. Neither control removes a leader that finalizes blocks while selectively censoring transactions.

The combined configuration fits networks with reliable connectivity and enough CPU and memory for many in-flight views. A rotating leader or smaller lookahead may fit better when validators are heterogeneous or leaders frequently fail.

Stable leadership keeps one leader on the transaction data path for the whole term. Networks with many concurrent producers can pair this pipeline with [Multimmit](/blogs/multimmit).

Stable terms currently use round-robin election. Every validator must use the same term length.

## The Next Ordering Opportunity

An orderbook update, batch reference, or game action that misses one proposal gets another opportunity after one block interval.

For builders who have already made dissemination and execution fast, the ordering clock can become the next visible limit. Each network can tune that clock around its own latency, capacity, and proposer-rotation requirements.

Stable Leader and Optimistic Validation are [available on `main`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/simplex/mod.rs). [Alto](https://github.com/commonwarexyz/alto) shows the complete integration. In our global deployment, that ordering clock ticked every 5ms at the median.
