---
title: "Simplex, Pipelined"
description: "In a 50-validator Alto deployment, Stable Leader and Optimistic Validation sustained about 200 blocks per second, with a median of 5ms between blocks."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Brendan Chou"
author_twitter: "https://x.com/B_Chou"
url: "https://commonware.xyz/blogs/pipelining-simplex"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

Network latency does not have to set the pace of new blocks.

Today, we're introducing [Stable Leader](https://github.com/commonwarexyz/monorepo/pull/3352) and [Optimistic Validation](https://github.com/commonwarexyz/monorepo/pull/3416), two options that pipeline [Simplex](https://eprint.iacr.org/2023/463) views. Stable Leader lets one proposer lead many views in a row, reducing the overhead of leader handoff. Optimistic Validation lets that leader keep proposing, and validators keep voting, without waiting for the previous view's notarization. Together, they take network round trips out of the critical path for producing new blocks.

In a globally distributed [Alto](https://alto.commonware.xyz) deployment with 50 validators, this combination sustained about 200 blocks per second. The pipeline kept new views moving while earlier blocks finalized.

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
<div id="simplex-fig-cadence" class="simplex-loop simplex-loop-cadence" role="img" aria-label="A 20 by 10 grid representing 200 blocks in one second, with one red square per 5ms interval.">
  <noscript>At 5ms between blocks, 200 blocks fit into one second. This figure shows them as a 20 by 10 grid of red squares.</noscript>
</div>
<script type="module" src="pipelining-simplex.loops.js"></script>
```

::: {.image-caption}
Figure 1: Each square represents one 5ms target interval. Alto sustained 200 successful blocks per second.
:::

## From One View to the Next

A *view* is one opportunity for a leader to propose a block. Validators verify the proposal and vote. Once a quorum votes for the same proposal, it is *notarized*.

Traditionally, two network hops separate consecutive views: the next leader must receive the previous proposal, then votes must cross the network to form its notarization. Stable Leader and Optimistic Validation remove these hops in turn.

## Wait One: The Proposer Handoff

Traditionally, rotating leadership assigns each view to a new proposer. The next proposer must first receive the previous proposal. It still cannot safely build: the previous leader may have sent other validators a different block, so the next proposer must wait for a notarization showing which block won a quorum.

Stable Leader groups consecutive views into a *term*. One leader proposes throughout the term. Because that leader built the previous block, it already knows the block and its ancestry before a single network message arrives. There is no handoff before the next proposal. Election still runs at the term boundary.

```{=html}
<div id="simplex-fig-leaders" class="simplex-loop" role="img" aria-label="A comparison of round-robin and stable leaders across 12 views. Round-robin rotates among three leaders every view. With a term length of four, each stable leader proposes four consecutive views before leadership changes. The timeline shows three complete terms and two term boundaries.">
  <noscript>Across 12 views, round-robin changes leaders every view. With a term length of four, each stable leader proposes four consecutive views. The timeline shows three complete terms and two term boundaries.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Round-robin rotates the proposer every view while Stable Leader changes it once per term.
:::

Stable leadership removes the proposer handoff. Without Optimistic Validation, the next view still waits for the parent notarization and the application check that follows.

## Wait Two: Forming the Parent Notarization

Without Optimistic Validation, the stable leader waits for view `v` to be notarized before proposing view `v+1`. Other validators also wait for `v` to pass its application check before voting on the child. Forming the notarization requires votes to cross the network. The child must then cross the network before other validators can vote. Even without a leader handoff, network latency paces each view.

With Optimistic Validation, the leader can start `v+1` after it builds and votes for `v`. A validator that checked and voted for `v` can also check and vote on `v+1` when the proposal arrives. Neither needs to receive the notarization for `v` or wait for its application check first.

The proposal and votes for `v+1` can overlap the network round that forms the notarization for `v` and the application check that follows. The same rule can carry the pipeline across several views within the stable-leader term. Consecutive proposals can begin less than one network round trip apart, limited by local work and network capacity rather than latency alone. Finalization still follows the same rules.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop" role="img" aria-label="A comparison of sequential and optimistic validation. In the sequential path, each child proposal and its votes wait for the parent notarization. In the optimistic path, child views begin closer together while parent notarizations form. Finalization continues behind new views in both paths.">
  <noscript>Without Optimistic Validation, each child view waits for the parent notarization. With Optimistic Validation, child views can begin while parent notarizations form. Finalization continues behind new views in both paths.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Optimistic Validation packs new views closer together while notarization and finalization continue in parallel. Both panels use the same horizontal time scale.
:::

## How Optimism Stays Safe

*Optimistic* describes when a participant starts the next view. It does not weaken the evidence required for finalization.

Notarization is not finalization. The application check that follows is called *certification*. After a block is notarized, each validator asks its application to certify the payload before voting to finalize it. This lets an application finish checks such as confirming that enough erasure-coded data is available.

A participant works ahead only after it has voted for the parent, or when it holds usable quorum proof. The same rule applies to every optimistic ancestor. A validator still waits for the parent to be certified before certifying a child or voting to finalize it. If an ancestor fails to notarize or certify, optimistic votes above it become inert. Validators then abandon that part of the term through the normal timeout path.

Optimistic work stops at the term boundary. The first view of a new term must start from certified ancestry.

Each validator sets a local bound, measured in views, on how far it will run ahead at one time. A value of zero disables Optimistic Validation. Validators can choose different limits without affecting safety. A larger limit can keep the pipeline full when notarizations fall behind, but uses more CPU and memory on work that may later be discarded.

## What We Measured

We ran Alto with 50 validators spread evenly across ten AWS regions. With Stable Leader and Optimistic Validation enabled, the network sustained about 200 blocks per second. The median time between blocks was 5ms.

The blocks were light: headers only, with no transactions or execution. The goal was to measure consensus cadence, not transaction throughput.

We measured finality separately, from the leader-stamped proposal time until an external observer received its finalization certificate. The median was 300ms. That path includes indexer and WebSocket delivery. At that cadence, about 60 later views could start while the original block finalized.

## Where the Pipeline Fits

These features remove two specific bottlenecks: leader handoffs and waits for parent notarization. They do not speed up application checks, execution, storage, proposal verification, or data dissemination. If one of those stages is slower, improve it first.

Longer terms remove more handoffs, but give one leader more consecutive proposals. Alto's 10,000-view term lasted roughly 50 seconds at the measured cadence. If a leader stays offline, validators can nullify its first stalled view and skip the rest of its term. For a term of `L` views, this reduces that leader's timeout overhead per successful block to about `1/L` of per-view rotation. If a leader keeps views moving without finalizing blocks, a term-wide timeout lets validators rotate. These timeout rules cannot remove a leader that finalizes blocks while selectively censoring transactions.

The combined configuration fits networks with reliable connectivity and enough CPU and memory for many in-flight views. Rotating leaders may fit networks where leaders frequently fail or proposer rotation is an important censorship defense.

Stable terms currently use round-robin election. Every validator must use the same term length.

## The Next Block

Every view gives applications another opportunity to order new data. Alto began a new view every 5ms at the median. That finer schedule can help orderbooks, batchers, and games respond to new input sooner.

This pipeline helps one ordering leader move quickly. [Multimmit](/blogs/multimmit) addresses a complementary bottleneck by separating parallel transaction production from the single ordering leader.

Stable Leader and Optimistic Validation are available through [`RoundRobin::with_term` on `main`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/simplex/elector.rs#L269-L290). The API will appear on docs.rs after the next `commonware-consensus` release. [Alto's integration](https://github.com/commonwarexyz/alto/blob/304b8232df939199d1d856dfb58c2930f45b5e3c/chain/src/engine.rs#L81-L94) shows the complete setup. Within a stable term, Simplex can begin the next block without waiting for a network round trip. In Alto, the median interval between blocks was 5ms.
