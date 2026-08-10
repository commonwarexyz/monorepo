---
title: "198.1 Blocks Per Second: Pipelining Simplex"
description: "At 5ms median block spacing, Alto's analyzer reported 198.1 finalized blocks per nominal second across 50 validators. Median external-observer finalization latency was 300ms."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Brendan Chou"
author_twitter: "https://x.com/B_Chou"
author2: "Patrick O'Grady"
author2_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/pipelining-simplex"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

For applications sequencing already-disseminated data, block spacing sets how often fresh data gets another ordering opportunity.

In one global deployment with 50 validators, [Alto's](https://alto.commonware.xyz) analyzer reported 198.1 finalized blocks per nominal second. The per-window median block spacing was 5ms.

A separate capture measured 300ms median latency from the leader-stamped block timestamp until an external observer received its finalization certificate. Those numbers may look inconsistent at first, but they describe two different clocks.

At 5ms per block, one 300ms observer-latency window spans about 60 block intervals. This ratio estimates the pipeline depth. It does not directly measure concurrent views.

Once data reaches the leader, it has another ordering opportunity after one block interval while earlier blocks continue toward finality.

This is 5ms median block spacing, not 5ms finality or transaction throughput.

```{=html}
<img src="/imgs/pipelining-simplex.png" alt="About sixty view intervals fit inside a 300ms median external-observer finalization-latency window at 5ms median block spacing.">
```

::: {.image-caption}
Figure 1: Alto's per-window median block spacing was 5ms. Median external-observer finalization latency was 300ms. Their ratio gives about 60 view intervals per observer-latency window.
:::

A *view* is one opportunity for a leader to propose a block and for validators to vote. [Simplex](https://eprint.iacr.org/2023/463) moves a block through four steps:

1. The leader proposes a block.
2. Validators verify the block and broadcast `notarize` votes.
3. After a quorum notarizes the block, the [application certifies](https://docs.rs/commonware-consensus/latest/commonware_consensus/trait.CertifiableAutomaton.html) that the verified payload is safe to commit.
4. Validators broadcast `finalize` votes, and a quorum forms the finalization.

That order matters within each block. It does not require the network to finish one block before starting the next. Validators can work on several views at different stages.

Honest applications must make the same deterministic certification decision. Temporary uncertainty should keep certification pending. Rejection means the payload can never certify.

Two waits otherwise couple view cadence to finality latency. [Stable Leader](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/elector/struct.RoundRobin.html#method.with_term) removes proposer handoffs inside a term. [Optimistic Validation](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html#optimistic-validation) lets validators verify and notarize the next proposal while its parent is still being certified.

Stable leadership is useful on its own. If certification is still the limiting stage, Optimistic Validation builds on the stable term. Together, they remove both waits from the path between proposals.

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

A stable leader is not free. A faulty leader can delay the network for more than one view. A censoring leader also controls more consecutive proposals.

Simplex bounds stalls in two ways. First, a *nullification* is quorum proof that validators abandoned a view. A local timeout makes one validator broadcast `nullify`. A quorum certificate covers the rest of the term and advances the network to a new leader. Second, a stall timeout detects a leader that keeps per-view timers satisfied but prevents finality.

These controls do not evict a leader that keeps finalizing blocks while selectively censoring transactions. That leader can retain proposal authority for the full term. Alto's 10,000-view term lasted roughly 50 seconds at the measured cadence.

Term length therefore makes a direct tradeoff. Longer terms amortize more handoffs, but give one leader more consecutive proposals. Networks that rely on proposer rotation for censorship resistance should use shorter terms.

Stable terms also add one safety rule. After a validator broadcasts `nullify` for a view, it withholds finalize votes for later views in that term. It resumes after observing a same-term finalization at or above its highest nullify vote.

Every validator must use the same term length. The current implementation supports stable terms with round-robin election. The threshold-VRF elector remains rotating because validators may enter a view with different certificates.

Stable leadership removes the proposer handoff. One wait remains: application certification.

## Wait Two: Certification on the View Path

Certification can take time for good reasons. An erasure-coded application may wait until it has enough shards to reconstruct a block. Optimistic Validation does not weaken this check. It changes when the next work begins.

A stable leader can propose view `v+1` as soon as view `v` is notarized. Without Optimistic Validation, followers wait for the application to certify `v` before they verify and notarize `v+1`. Certification remains on the critical path of every view.

Optimistic Validation removes that dependency from the view path. Within a stable term, a validator may verify and notarize the child while the application certifies its parent. The child may notarize early, but its certification waits for its parent to certify. Its finalize vote follows its own certification; it does not wait for parent finalization.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop" role="img" aria-label="Animated comparison of sequential and optimistic proposal validation. In the sequential path, each child proposal waits for its parent's application certification before validators verify and notarize it. In the optimistic path, child proposals are verified and notarized while parent certification continues in a parallel lane. Finalization remains ordered behind certification.">
  <noscript>Without optimistic validation, each child proposal waits for its parent to certify. With optimistic validation, proposal verification and notarization continue while certification runs in the background. Finalization still waits for certification.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Optimistic Validation pipelines proposal verification and notarization (red) over application certification (blue). Certification and finalization remain ordered.
:::

## What We Measured

Here is the configuration for the 50-validator Alto run:

| | |
|---|---:|
| Deployment | 50 validators, 5 in each of 10 AWS regions |
| Instance | `c7gd.4xlarge` |
| Build | Optimized aarch64 release with debug information |
| Worker / signature threads | 8 / 16 |
| Workload | Header-only blocks, no transactions or execution |
| Block target | 5ms |
| Leader early wake | 1ms before the pacing deadline |
| Term length | 10,000 views |
| Stall timeout | 12 seconds |
| `optimistic_views` (local policy) | 100 |
| Throughput capture | 189 samples spanning 188 nominal one-second intervals |
| Analyzer-reported successful views / blocks | 198.1 per nominal second |
| Median block spacing | 5ms in all 189 reporting windows |
| External-observer finality | p50 300ms / p99 376ms (`n=3,736`) |
| View intervals per observer-latency window | roughly 60 |

The analyzer observed 37,249 finalized height and view increments between its first and last samples. It divided this change by 188 nominal one-second timer intervals, giving 198.13 successful views and blocks per nominal second. The raw tick timestamps were not preserved.

For block spacing, the analyzer divided the change in block timestamps by the change in finalized height. A delivery gap could make one observation average across several heights. The missing raw stream prevents us from ruling out such gaps.

A separate finality capture measured from the leader-stamped block timestamp until an external client received the finalization certificate. It included indexer and WebSocket delivery. The observer's clock was checked, but the leaders' clock offsets were not preserved, so this is end-to-end observer latency rather than a strict bound on consensus-network finality.

A filled pipeline can emit blocks at 5ms median spacing while median external-observer finalization latency remains 300ms.

This is a capability result, not an ablation. It shows that one global deployment sustained the combined configuration near its 5ms target. It does not isolate how much either feature improved the baseline.

The run measured consensus cadence, not transaction throughput. The number of transactions a chain can process still depends on block dissemination, execution, storage, and the application workload.

Stable Leader and Optimistic Validation allow views to overlap. In this run, the overall deployment sustained the 5ms target.

The analyzer flagged four samples near expected term boundaries. Those samples contained 155 to 163 blocks, and the following sample contained 189 to 200. The deleted raw data prevents exact attribution to the transition. If certification, storage, networking, or verification runs slower than proposal production, the lookahead fills and that slower stage limits the view rate.

The deployed Alto worktree included uncommitted changes, and its exact patch was not preserved. The raw captures, dashboards, and deployment assets were also lost. These gaps prevent exact reproduction. The 1ms early wake also meant that a leader-stamped timestamp could lead the leader's wall clock by up to 1ms.

## How Optimism Stays Safe

`Optimistic` describes when a validator starts work. It does not relax the evidence required for finalization.

A validator can vote optimistically when it has one of two forms of evidence for the parent:

1. The validator holds a usable notarization or finalization certificate for the parent.
2. The validator verified the parent's proposal, saw no conflicting proposal from the leader, and already broadcast its own notarize vote.

A notarization becomes unusable if the application rejects its payload. An observed finalization overrides that validator's local rejection.

The rule recurses through every optimistic ancestor until it reaches certificate-backed ancestry. If an ancestor fails application certification, no descendant can certify or finalize through it. The normal nullification path then abandons the failed part of the term.

One `optimistic_views` setting bounds two local windows:

- The *issuance window* limits local notarize votes to `optimistic_views` beyond the child of the last directly observed notarization. A certificate inferred from a descendant does not move this anchor.
- The *admission window* retains peer votes up to `optimistic_views` beyond the validator's current view.

Both windows stop at the term boundary. The first view of a new term must start from explicitly certified ancestry.

Mid-term certification also proceeds parent by parent. If a validator sees a child certificate but missed the exact parent notarization, it fetches the parent from the stable leader or another peer. The child certificate cannot replace it.

The lookahead is local policy, and zero disables Optimistic Validation. Validators can use different values without affecting safety. A smaller value can reduce throughput if too many future votes are dropped. A larger value keeps more rounds in memory and may perform work above an ancestor that later fails.

## Choose the Pipeline

Start with the stage that limits your view rate. Alto's settings are an example, not a default.

| Limiting stage | Configuration | Main cost |
|---|---|---|
| Proposer handoff | Stable Leader with zero optimistic views | Longer proposer authority |
| Certification latency, with enough certification capacity | Add Optimistic Validation | More speculative CPU and memory |
| Certification, execution, storage, verification, or dissemination capacity | Improve that stage first | A deeper window will fill |

Stable Leader reduces handoff latency. Optimistic Validation hides certification latency when certification can still keep up. Neither feature makes a slower stage process more work per second.

The combined configuration fits networks with reliable connectivity and enough CPU and memory for many active views. Application certification must run concurrently, and transactions or block references still need a reliable path to the current leader.

A rotating leader or smaller lookahead may fit better when validators are heterogeneous, leaders frequently fail, or proposer rotation is an important censorship defense.

Stable leadership keeps the leader on the transaction data path for the whole term. Networks that need concurrent dissemination from many producers can combine this pipeline with another design. [Multimmit](/blogs/multimmit) describes one such approach.

Configure both features on the round-robin elector:

```rust
let elector = RoundRobin::default().with_term(
    term_length,       // Consensus-critical: identical at every validator.
    stall_timeout,     // Local policy: evict a leader that prevents finality.
    optimistic_views,  // Local policy: zero disables Optimistic Validation.
);
```

Stable terms require a term length greater than one and a nonzero stall timeout. Use `RoundRobin::default()` to rotate every view. Use `with_term(..., ViewDelta::zero())` to enable Stable Leader without Optimistic Validation.

Choose enough lookahead to cover measured certification lag at your target view rate. A larger window helps only when certification catches up before the window fills. It also costs CPU and memory. Choose the term length based on how long one leader should retain proposal authority.

See [`RoundRobin::with_term`](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/elector/struct.RoundRobin.html#method.with_term) for the configuration API. [Alto](https://github.com/commonwarexyz/alto) provides a complete blockchain integration.

## A Finer Ordering Clock

A shorter block interval reduces the wait for the next ordering opportunity after data reaches the proposer. An order-book update, batch reference, or game action that misses one proposal gets another opportunity after one block interval.

At Alto's measured cadence, that interval was 5ms at the median. Median external-observer finalization latency was 300ms. Stable Leader and Optimistic Validation changed how much consensus work could overlap without changing the fault threshold or finalization rule.

For builders who have already made dissemination and execution fast, the ordering clock can become the next visible limit. These options let each network tune that clock around its own latency, capacity, and proposer-rotation requirements.

If that is your bottleneck, explore the [Simplex documentation](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html), study the complete [Alto integration](https://github.com/commonwarexyz/alto), or ask an integration question in [Commonware Q&A](https://github.com/commonwarexyz/monorepo/discussions/categories/q-a).
