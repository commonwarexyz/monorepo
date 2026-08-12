---
title: "The Long and Short of It"
description: "Stable Leader and Optimistic Validation shorten the wait between Simplex proposals, sustaining about 200 blocks per second with 5ms median spacing in Alto."
date: "August 12th, 2026"
published-time: "2026-08-12T00:00:00Z"
modified-time: "2026-08-12T00:00:00Z"
author: "Brendan Chou"
author_twitter: "https://x.com/B_Chou"
url: "https://commonware.xyz/blogs/pipelining-simplex"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

Submitting a transaction and seeing it finalize should feel like clicking a button and getting a response.

Consensus contributes two delays to that experience: the wait for the next proposal and the two rounds of voting that finalize it. This pipeline tackles the first. Even fast consensus can be slow when proposals remain far apart. Simplex normally waits two network hops before starting the next view. Optimistic proposals can cut that to one hop even as leaders rotate. What if a leader could start the next proposal without waiting on the network and still know how each transaction would execute?

Today, we're introducing [Stable Leader](https://github.com/commonwarexyz/monorepo/pull/3352) and [Optimistic Validation](https://github.com/commonwarexyz/monorepo/pull/3416), two features that pipeline [Simplex](https://eprint.iacr.org/2023/463) views. Stable Leader keeps one proposer for many views in a row, reducing handoffs. Optimistic Validation lets that leader keep proposing and validators keep voting while the previous view's notarization forms. Together, they start new blocks while earlier ones continue toward finality.

In an [Alto](https://alto.commonware.xyz) deployment with 50 validators across ten AWS regions, the pipeline sustained about 200 blocks per second with a median interval of 5ms. Median finality for an external observer was 300ms from the leader's block timestamp through the indexer and WebSocket. At that cadence, roughly 60 newer blocks could be in flight before the first finalized. The demo uses headers-only blocks to isolate the cadence of consensus from transaction dissemination and execution. To reproduce the setup, run [`deploy.sh`](https://github.com/commonwarexyz/alto/pull/202).

```{=html}
<style>
  .simplex-loop {
    aspect-ratio: 1024 / 430;
    margin: 28px 0 6px;
  }

  .simplex-loop-cadence {
    aspect-ratio: 1024 / 400;
  }

  .simplex-loop-validation {
    aspect-ratio: 1024 / 380;
  }

  .simplex-loop-recovery {
    aspect-ratio: 1024 / 320;
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

## Two Network Waits Between Views

A *view* is one opportunity for a leader to propose a block. Validators verify the proposal and vote. Once a quorum votes for the same proposal, it is *notarized*.

Traditionally, two network hops separate consecutive views: the next leader must receive the previous proposal, then votes must cross the network to form its notarization. Within a term, Stable Leader removes the first wait from the critical path. Optimistic Validation removes the second.

### Wait One: The Proposer Handoff

With rotating leaders, each view has a new proposer. The next proposer must first receive the previous proposal. Even then, the next proposer cannot safely build until a notarization forms: a Byzantine leader may have sent conflicting proposals.

Stable Leader groups consecutive views into a *term*, an approach described in [Sing a Song of Simplex](https://eprint.iacr.org/2023/1916) and referred to as *multi-view leadership* in [The Carnot Bound: Limits and Possibilities for Bandwidth-Efficient Consensus](https://arxiv.org/abs/2603.11797). One leader proposes throughout the term, reducing proposer handoffs from one per view to one per term. Within the term, the leader already knows the previous block and its ancestry before a single network message arrives. An honest leader also knows it did not equivocate, so it can begin building and distributing the next proposal's data early. This cuts the wait between views from two network hops to one: the hop that forms the parent notarization.

```{=html}
<div id="simplex-fig-leaders" class="simplex-loop" role="img" aria-label="A comparison of round-robin and stable leaders over the same time span. Round-robin rotates among three leaders every view, with views spaced two network hops apart. With a term length of four, Stable Leader spaces views one hop apart within each term, while term-boundary handoffs still take two hops. The timeline shows three complete stable-leader terms and two term boundaries.">
  <noscript>Over the same time span, round-robin changes leaders every view and spaces views two network hops apart. With a term length of four, Stable Leader spaces views one hop apart within each term and two hops apart at leader handoffs. The timeline shows three complete stable-leader terms.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Round-robin spaces views two network hops apart. With four-view terms, Stable Leader spaces them one hop apart within each term and two hops apart at each leader handoff.
:::

### Wait Two: The Parent Notarization

Without Optimistic Validation, validators wait for the parent to be notarized before voting to notarize its child. Network latency still paces each view.

With Optimistic Validation, validators can vote to notarize the child as soon as its proposal arrives, provided they already voted for the parent. They do not need to receive the parent's notarization first. [Moonshot: Optimizing Chain-Based Rotating Leader BFT via Optimistic Proposals](https://arxiv.org/abs/2401.01791) shows that optimistic proposals can achieve the same one-hop block period with rotating leaders.

The child can therefore be proposed and voted on while the parent's notarization is still forming. The same rule can carry the pipeline across several views within the stable-leader term. Consecutive proposals can begin less than one network round trip apart, limited by local work and network capacity rather than latency alone. These waits for network messages can overlap, but every validator still performs the local verification and application work for each block.

```{=html}
<div id="simplex-fig-validation" class="simplex-loop simplex-loop-validation" role="img" aria-label="A comparison of Stable Leader with and without Optimistic Validation. Red blocks are proposed, gray blocks with one check are notarized, and green blocks with two checks are finalized. With Stable Leader alone, validators wait for each parent notarization before voting in the child view. With Optimistic Validation, three child views start during the same network interval while earlier blocks continue toward finalization.">
  <noscript>Red blocks are proposed, gray blocks with one check are notarized, and green blocks with two checks are finalized. With Stable Leader alone, validators wait for each parent notarization before voting in the child view. With Optimistic Validation, three child views start during the same network interval while earlier blocks continue toward finalization.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Without optimism, validators wait for the parent notarization before voting in the next view. Optimistic Validation starts three views during the same network interval.
:::

## Same Evidence, Earlier Work

*Optimistic* means a participant can vote to notarize a proposal before receiving notarizations for every ancestor in the term.

Notarization is not finalization. After a block is notarized, each validator asks its application whether the payload is safe to commit. This decision is called *certification* and happens before the validator votes to finalize the block. Certification lets an application finish any checks required before commit, such as confirming data availability or validating application-specific block and transaction rules.

A participant only votes optimistically when every earlier proposal in the term is consistent with the chain it has already supported. A validator still waits for the parent to be certified before certifying the child. Once the child is certified, the validator broadcasts its finalize vote. It can certify later views without waiting for the child to finalize, so certification and finalization continue in parallel. If any proposal fails to notarize or certify, later optimistic votes in the term cannot be used. Validators can then vote to abandon the rest of the term through Simplex's normal nullification path.

The term boundary is also a leader handoff, so optimistic work stops there. The first view of a new term must start from certified ancestry. Together, these rules let Simplex views pipeline without changing the evidence required for finalization.

The consensus configuration also sets a bound on how many views validators can work ahead at once. A value of zero disables Optimistic Validation. A larger bound can keep the pipeline full when notarizations fall behind, at the cost of more CPU and memory for work that could be discarded if an earlier view fails.

```{=html}
<div id="simplex-fig-recovery" class="simplex-loop simplex-loop-recovery" role="img" aria-label="An optimistic term with eight views. View one is finalized, view two is notarized, and view three times out. Validators nullify view three. Optimistic proposals in views four and five are discarded, and views six through eight are skipped. View two then finalizes, and view nine builds on it in the next term before notarizing and finalizing. View ten follows, and the pipeline continues offscreen.">
  <noscript>View one is finalized, view two is notarized, and view three times out. Validators nullify view three. Optimistic proposals in views four and five are discarded, and views six through eight are skipped. View two then finalizes, and view nine builds on it in the next term before notarizing and finalizing. View ten follows, and the pipeline continues.</noscript>
</div>
```

::: {.image-caption}
Figure 4: When v3 times out, validators nullify it. Later proposals are discarded, and the rest of the term is skipped. In the next term, v9 builds on v2 and the pipeline resumes.
:::

## Where the Pipeline Fits

Pipelining overlaps network waits, but every validator still performs the verification, execution, and storage required for each block. A higher block rate therefore puts more pressure on validator compute, storage, and network bandwidth. Pipelining does not shorten the time from proposal to finalization, but it does shorten the wait before a transaction can enter the next proposal.

Sub-network-delay block cadence does not require a stable leader. [Gatling: Rapid-Fire Consensus from Parallel Composition](https://arxiv.org/abs/2606.18220) takes another route: it runs several rotating-leader consensus instances in parallel, staggers their proposal schedules, and deterministically interleaves their confirmed outputs. Each instance can retain a much slower cadence while the aggregate inter-proposal time becomes arbitrarily small. A delayed instance can still hold back later positions in the merged log.

That composition changes the execution contract. At sub-network-delay cadence with rotating leaders, vanilla Gatling gives up *predictable validity*: a proposer may not know the state against which a transaction will eventually execute. Its variants recover that property with slowly rotating leaders, either by inserting gaps of empty proposals or by splitting block space into prime and state-independent subprime tiers whose execution order differs from consensus order. A conventional stateful execution layer would therefore have to defer balance, nonce, and fee checks until the merged prefix is confirmed, execute speculatively with rollback, or adopt one of those variants.

This Simplex pipeline takes the other route. It keeps one chained consensus instance, and validators certify each parent before its child, so stateful verification can advance before finalization without a separate execution order. The cost is slower leader rotation: longer terms reduce handoff overhead but give one leader more consecutive proposals. At Alto's measured cadence, a 10,000-view term lasted roughly 50 seconds. If a leader goes offline, nullifying its first stalled view skips the rest of the term and rotates to the next leader. One timeout therefore covers the offline leader's entire term.

A Byzantine leader could still finalize blocks while selectively censoring transactions. This risk also exists with rotating leaders, but longer terms can increase inclusion delay because the same leader proposes more consecutive blocks. Selective censorship can be difficult to detect when the leader otherwise performs well.

This pipeline fits networks with reliable connectivity and enough CPU and memory for many in-flight views. Networks that prioritize proposer rotation as a censorship defense may prefer shorter terms.

## A Finer Ordering Clock

Each 5ms view gives applications another opportunity to order new data. That finer schedule can help orderbooks, batchers, and games respond to new input sooner.

This pipeline lets one ordering leader publish new blocks as quickly as local work and network capacity allow. [Multimmit](/blogs/multimmit) addresses a complementary bottleneck by separating parallel transaction production from the single ordering leader.

Stable Leader and Optimistic Validation will be available in the next `commonware-consensus` release.
