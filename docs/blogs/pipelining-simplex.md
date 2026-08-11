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

New blocks no longer have to wait for network round trips.

Today, we're introducing [Stable Leader](https://github.com/commonwarexyz/monorepo/pull/3352) and [Optimistic Validation](https://github.com/commonwarexyz/monorepo/pull/3416), two features that pipeline [Simplex](https://eprint.iacr.org/2023/463) views. Stable Leader keeps one proposer for many views in a row, reducing handoff overhead. Optimistic Validation lets that leader keep proposing and validators keep voting without waiting for the previous view's notarization. Together, they let Simplex produce new blocks without waiting for network round trips.

In an [Alto](https://alto.commonware.xyz) deployment with 50 validators spread across ten AWS regions worldwide, this combination sustained about 200 blocks per second. The median time between blocks was 5ms, while the median time from proposal to finalization was 300ms. At that cadence, about 60 newer blocks could be in flight while the first finalized.

```{=html}
<style>
  .simplex-loop {
    aspect-ratio: 1024 / 430;
    margin: 28px 0 6px;
  }

  .simplex-loop-cadence {
    aspect-ratio: 1024 / 400;
  }

  .simplex-loop-recovery {
    aspect-ratio: 1024 / 300;
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
Figure 1: Each square represents one 5ms target interval. Alto sustained about 200 blocks per second.
:::

## Two Waits Between Views

A *view* is one opportunity for a leader to propose a block. Validators verify the proposal and vote. Once a quorum votes for the same proposal, it is *notarized*.

Traditionally, two network hops separate consecutive views: the next leader must receive the previous proposal, then votes must cross the network to form its notarization. Within a term, Stable Leader removes the first wait from the critical path. Optimistic Validation removes the second.

## Wait One: The Proposer Handoff

With rotating leadership, each view has a new proposer. The next proposer must first receive the previous proposal. Even then, the next proposer cannot safely build until a notarization forms: a Byzantine leader may have sent conflicting proposals.

Stable Leader groups consecutive views into a *term*. One leader proposes throughout the term, reducing proposer handoffs from one per view to one per term. Within the term, the leader already knows the previous block and its ancestry before a single network message arrives. An honest leader also knows it did not equivocate, so it can begin building and distributing the next proposal's data early. This cuts the wait between views from two network hops to one: the hop that forms the parent notarization.

```{=html}
<div id="simplex-fig-leaders" class="simplex-loop" role="img" aria-label="A comparison of round-robin and stable leaders over the same time span. Round-robin rotates among three leaders every view, with views spaced two network hops apart. With a term length of four, Stable Leader spaces views one hop apart within each term, while term-boundary handoffs still take two hops. The timeline shows three complete stable-leader terms and two term boundaries.">
  <noscript>Over the same time span, round-robin changes leaders every view and spaces views two network hops apart. With a term length of four, Stable Leader spaces views one hop apart within each term and two hops apart at leader handoffs. The timeline shows three complete stable-leader terms.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Round-robin spaces views two network hops apart. With four-view terms, Stable Leader spaces them one hop apart within each term and two hops apart at each leader handoff.
:::

## Wait Two: The Parent Notarization

Without Optimistic Validation, validators wait for the parent to be notarized before voting to notarize its child. Network latency still paces each view.

With Optimistic Validation, validators can vote to notarize the child as soon as its proposal arrives, provided they already voted for the parent. They do not need to receive the parent's notarization first.

The child can therefore be proposed and voted on while the parent's notarization is still forming. The same rule can carry the pipeline across several views within the stable-leader term. Consecutive proposals can begin less than one network round trip apart, limited by local work and network capacity rather than latency alone.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop" role="img" aria-label="A comparison of Stable Leader with and without Optimistic Validation. With Stable Leader alone, each child view starts when the parent notarization arrives, spacing views one network hop apart. With Optimistic Validation, three child views start in that same interval while parent notarizations form. Finalization continues behind new views in both paths.">
  <noscript>With Stable Leader alone, each child view starts when the parent notarization arrives, spacing views one network hop apart. With Optimistic Validation, three child views start in that same interval while parent notarizations form. Finalization continues behind new views in both paths.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Stable Leader spaces views one network hop apart. Here, Optimistic Validation starts three views in the same interval.
:::

## How Optimism Stays Safe

*Optimistic* means a participant can vote to notarize a proposal before it receives notarizations for every ancestor in the term. It does not weaken the evidence required for finalization.

Notarization is not finalization. The application check that follows is called *certification*. After a block is notarized, each validator asks its application to certify the payload before voting to finalize it. This lets an application finish any checks required before commit, such as confirming data availability or validating application-specific block and transaction rules.

A participant only votes optimistically when every earlier proposal in the term is consistent with the chain it has already supported. A validator still waits for the parent to be certified before certifying the child. Once the child is certified, the validator broadcasts its finalize vote. It can certify later views without waiting for the child to finalize, so certification and finalization continue in parallel. If any proposal fails to notarize or certify, optimistic votes later in the term become inert. Validators can then vote to abandon the rest of the term through Simplex's normal nullification path.

```{=html}
<div id="simplex-fig-recovery" class="simplex-loop simplex-loop-recovery" role="img" aria-label="An optimistic term with four views. View two fails, making the optimistic work in views three and four inert. A nullification skips the rest of the term and starts view five in the next term.">
  <noscript>View two fails, making the optimistic work in views three and four inert. A nullification skips the rest of the term and starts view five in the next term.</noscript>
</div>
```

::: {.image-caption}
Figure 4: If a view fails, later optimistic work becomes inert. A nullification skips the rest of the term.
:::

The term boundary is also a leader handoff, so optimistic work stops there. The first view of a new term must start from certified ancestry.

Lastly, the consensus configuration sets a bound on how many views validators can work ahead at once. A value of zero disables Optimistic Validation. A larger bound can keep the pipeline full when notarizations fall behind, but uses more CPU and memory on work that could be discarded if an earlier view fails.

## Where the Pipeline Fits

The test used header-only blocks with no transactions or execution, so it measured consensus cadence rather than transaction throughput. A higher block rate puts more load on execution, storage, proposal verification, and network bandwidth. Pipelining does not shorten the time from proposal to finalization, but it does shorten the wait before a transaction can enter the next proposal.

Longer terms reduce handoff overhead, but give one leader more consecutive proposals. Alto's 10,000-view term lasted roughly 50 seconds at the measured cadence. Any nullification skips the rest of the term and rotates to the next leader. An offline leader causes one timeout for the entire term, so longer terms spread that overhead across more successful blocks.

A Byzantine leader could still finalize blocks while selectively censoring transactions. This risk also exists with rotating leaders, but longer terms can increase inclusion delay because the same leader proposes more consecutive blocks. Selective censorship can be difficult to detect when the leader otherwise performs well.

This pipeline fits networks with reliable connectivity and enough CPU and memory for many in-flight views. Networks that prioritize proposer rotation as a censorship defense may prefer shorter terms.

## The Next Block

Each 5ms view gives applications another opportunity to order new data. That finer schedule can help orderbooks, batchers, and games respond to new input sooner.

This pipeline lets one ordering leader publish new blocks as quickly as local work and network capacity allow. [Multimmit](/blogs/multimmit) addresses a complementary bottleneck by separating parallel transaction production from the single ordering leader.

Stable Leader and Optimistic Validation will be available in the next `commonware-consensus` release.
