---
title: "A Finer Ordering Clock"
description: "In a 50-validator Alto deployment, Stable Leader and Optimistic Validation sustained about 200 successful views per second at 5ms median block spacing."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Brendan Chou"
author_twitter: "https://x.com/B_Chou"
url: "https://commonware.xyz/blogs/pipelining-simplex"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

For applications sequencing already-disseminated data, the wait for the next block can matter as much as the wait for finality.

Today, we're introducing Stable Leader and Optimistic Validation, two options that pipeline [Simplex](https://eprint.iacr.org/2023/463) views. Stable Leader removes the handoff between consecutive proposers. Optimistic Validation lets validators begin checking the next proposal while the application finishes checking its parent.

In a global [Alto](https://alto.commonware.xyz) deployment with 50 validators, this combination sustained about 200 successful views per second. Every successful view finalized one block, and the median block spacing was 5ms.

A separate capture measured 300ms median latency from the leader-stamped block timestamp until an external observer received its finalization certificate. The two measurements describe different clocks. At 5ms per view, one 300ms observer-latency window spans about 60 view intervals.

The pipeline keeps new views moving while earlier blocks finish. Once data reaches the leader, it gets another ordering opportunity after one block interval.

```{=html}
<img src="/imgs/pipelining-simplex.png" alt="About sixty view intervals fit inside a 300ms median external-observer finalization-latency window at 5ms median block spacing.">
```

::: {.image-caption}
Figure 1: Alto's median block spacing was 5ms. Median external-observer finalization latency was 300ms. Their ratio gives about 60 view intervals per observer-latency window.
:::

A *view* is one opportunity for a leader to propose a block and for validators to vote. Three steps matter here:

1. The leader proposes a block.
2. Validators verify and notarize the proposal.
3. The application runs its full deterministic safety check before validators finalize the block. Commonware calls this check *certification*.

These steps remain ordered for each block, but different blocks can be at different steps. Two waits otherwise limit how quickly new views begin: a proposer handoff and application certification.

[Stable Leader](https://github.com/commonwarexyz/monorepo/pull/3352) removes the first wait. [Optimistic Validation](https://github.com/commonwarexyz/monorepo/pull/3416) moves the second wait out of the path between proposals.

## Wait One: The Proposer Handoff

Round-robin assigns each view to a new leader. The next leader may be in another region and receive the prior proposal or certificate later than other validators. The chain waits for that leader to catch up and propose.

Stable Leader groups consecutive views into a *term*. One leader proposes throughout the term. After the leader sees a block notarized, the same leader already has the block and ancestry needed for the next proposal. Election still runs at the term boundary.

```{=html}
<style>
  .simplex-loop {
    aspect-ratio: 1024 / 430;
    margin: 28px 0 6px;
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
<div id="simplex-fig-leaders" class="simplex-loop" role="img" aria-label="Animated comparison of round-robin and stable leaders across six views. With round-robin rotation, responsibility moves among three leaders and every view crosses a proposer handoff. With a stable leader, one leader proposes all six views in the term, then leadership changes once at the term boundary.">
  <noscript>In this round-robin example, responsibility moves among three leaders across six views. With a stable leader, one leader proposes all six views and leadership changes once at the term boundary.</noscript>
</div>
<script type="module" src="pipelining-simplex.loops.js"></script>
```

::: {.image-caption}
Figure 2: Round-robin rotation changes the proposer every view. A stable leader extends its own chain and pays the handoff cost once per term.
:::

A stable leader is not free. One leader controls more consecutive proposals.

If a leader stops making progress, validators vote to abandon the current view. Once a quorum agrees, the network skips the rest of the term and moves to a new leader.

A subtler faulty leader can keep views moving while preventing finality. A term-wide stall timeout bounds that case.

These controls do not evict a leader that keeps finalizing blocks while selectively censoring transactions. That leader can retain proposal authority for the full term. Alto's 10,000-view term lasted roughly 50 seconds at the measured cadence.

Term length therefore makes a direct tradeoff. Longer terms amortize more handoffs, but give one leader more consecutive proposals. Networks that rely on proposer rotation for censorship resistance should use shorter terms.

Every validator must use the same term length. Stable terms currently work with round-robin leader election.

Stable leadership removes the proposer handoff. One wait remains: application certification.

## Wait Two: Certification on the View Path

Application certification can take time for good reasons. An erasure-coded application may wait until it has enough shards to reconstruct a block. Optimistic Validation changes when the next work begins.

A stable leader can propose view `v+1` as soon as view `v` is notarized. Without Optimistic Validation, followers wait for the application to certify `v` before they verify and notarize `v+1`. Certification remains on the critical path of every view.

With Optimistic Validation, a validator may verify and notarize the child while the application certifies its parent. The application still certifies blocks in order. Validators finalize each block only after its own certification.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop" role="img" aria-label="Animated comparison of sequential and optimistic proposal validation. In the sequential path, each child proposal waits for its parent's application certification before validators verify and notarize it. In the optimistic path, child proposals are closer together because validators verify and notarize them while application certification continues in order on a parallel lane.">
  <noscript>Without Optimistic Validation, each child proposal waits for its parent to certify. With Optimistic Validation, proposal verification and notarization continue while certification runs in order on a parallel lane.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Optimistic Validation pipelines proposal verification and notarization (red) over application certification (blue). Both panels use the same horizontal time scale.
:::

## How Optimism Stays Safe

`Optimistic` describes when a validator starts work. It does not weaken the evidence required for finalization.

A validator works ahead only if it has verified and voted for the parent, or holds usable quorum proof for it. The same rule applies to every optimistic ancestor. Application certification still proceeds parent by parent. If the application rejects an ancestor, no descendant can certify or finalize through it. Validators then abandon that part of the term through the normal timeout path.

The lookahead stops at the term boundary. The first view of a new term must start from certified ancestry.

The lookahead is local policy. A value of zero disables Optimistic Validation. Validators can choose different values without affecting safety. A larger value uses more CPU and memory on work that may later be discarded. A smaller value can limit the pipeline when application certification falls behind.

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
| Throughput capture | 189 samples spanning 188 nominal one-second intervals |
| Successful views / finalized blocks | 198.1 per nominal second |
| Median block spacing | 5ms in all 189 reporting windows |
| External-observer finality | p50 300ms / p99 376ms (`n=3,736`) |

The analyzer observed 37,249 finalized height and view increments between its first and last samples. Across 188 nominal one-second intervals, that is 198.13 successful views and blocks per second. We round this result to about 200.

### How to Read This Result

This was a capability run of the combined configuration. We did not compare it with a baseline. The result shows that one global deployment sustained the 5ms target, but it does not isolate the contribution of either feature.

The run used header-only blocks. Transaction throughput also depends on dissemination, execution, storage, and the application workload.

The finality capture measured from the leader-stamped block timestamp until an external client received the finalization certificate. It includes indexer and WebSocket delivery. Leader clock offsets were not preserved, and a timestamp could lead its leader's wall clock by up to 1ms.

The exact deployed Alto patch, raw captures, dashboards, and deployment assets were not preserved. The result cannot be reproduced exactly from the surviving records. The missing raw stream also prevents deeper analysis of individual samples.

## Choose the Pipeline

Start with the stage that limits your view rate. Alto's settings are an example, not a default.

| Limiting stage | Configuration | Main cost |
|---|---|---|
| Proposer handoff | Stable Leader without Optimistic Validation | Longer proposer authority |
| Certification latency, with enough certification capacity | Add Optimistic Validation | More speculative CPU and memory |
| Certification, execution, storage, verification, or dissemination capacity | Improve that stage first | A deeper window will fill |

Stable Leader reduces handoff latency. Optimistic Validation hides certification latency when certification can still keep up. Neither feature makes a slower stage process more work per second.

The combined configuration fits networks with reliable connectivity and enough CPU and memory for many in-flight views. Application certification must run concurrently, and transactions or block references still need a reliable path to the current leader.

A rotating leader or smaller lookahead may fit better when validators are heterogeneous, leaders frequently fail, or proposer rotation is an important censorship defense.

Stable leadership keeps the leader on the transaction data path for the whole term. Networks that need concurrent dissemination from many producers can combine this pipeline with another design. [Multimmit](/blogs/multimmit) describes one such approach.

Choose enough lookahead to cover measured certification lag at your target view rate. A larger window helps only when certification catches up before the window fills. It also costs CPU and memory. Choose the term length based on how long one leader should retain proposal authority.

Stable terms currently use the round-robin elector. Every validator must use the same term length, while each validator can choose its own optimistic lookahead. The configuration API is [available on `main`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/simplex/elector.rs#L282-L291) and will appear on docs.rs with the next release. [Alto](https://github.com/commonwarexyz/alto) provides a complete blockchain integration.

## The Next Ordering Opportunity

A shorter block interval reduces the wait for the next ordering opportunity after data reaches the proposer. An order-book update, batch reference, or game action that misses one proposal gets another opportunity after one block interval.

At Alto's measured cadence, that interval was 5ms at the median. Stable Leader and Optimistic Validation let Simplex overlap more work without changing its fault threshold or finalization rule.

For builders who have already made dissemination and execution fast, the ordering clock can become the next visible limit. Each network can tune that clock around its own latency, capacity, and proposer-rotation requirements.

If that is your bottleneck, explore the [Simplex source documentation on `main`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/simplex/mod.rs), study the complete [Alto integration](https://github.com/commonwarexyz/alto), or ask an integration question in [Commonware Q&A](https://github.com/commonwarexyz/monorepo/discussions/categories/q-a).
