---
title: "Multimmit: Extending Blocks for Faster Finality"
description: "Every high-throughput consensus design must decide when a block may enter the ordering process: wait for a proof of availability and every transaction pays for round trips it rarely needs, or reference blocks immediately and voters fetch missing data at the worst possible time. Multimmit does neither, finalizing a block as little as two message delays after it hits the wire."
date: "July 23rd, 2026"
published-time: "2026-07-23T00:00:00Z"
modified-time: "2026-07-23T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/multimmit"
image: "https://commonware.xyz/imgs/multimmit.png"
katex: true
---

A few years ago, I wrote [Vryx](https://hackmd.io/@patrickogrady/rys8mdl5p), an argument for reorienting State Machine Replication from (sequence → execute → replicate) to (replicate → sequence → execute). Decouple transaction dissemination from consensus, the reasoning went, and a blockchain can finalize transactions at roughly the rate validators can *download* them rather than the rate one leader can *upload* them. That reorientation is now standard among high-throughput designs. What never got settled is the seam between the two halves: when may consensus reference data still in flight?

Wait until a block's availability is certified, and every transaction pays for certificate round trips it rarely needs. Reference blocks immediately and voters must fetch whatever they are missing, on the critical path, from the one node the whole design exists to unburden. Today we're sharing [Multimmit](https://github.com/commonwarexyz/monorepo/tree/main/pipeline/multimmit), a construction developed with Andrew Lewis-Pye that combines [Minimmit](/blogs/minimmit.html)'s one-round-voting consensus (for $n \geq 5f+1$) with a chain of blocks per producer. Multimmit leaders reference blocks the moment they arrive, voters attest blocks the leader never saw, and certification runs in the background. A transaction block disseminated at time $t$ is finalized by $t+2\delta$ at best and $t+3\delta$ in expectation, where $\delta$ bounds message delay after GST. Those figures are measured from the block hitting the wire, not from the leader's proposal, and, for an honest chain's blocks, they hold while up to $f$ producers misbehave.

## The Ride to the Leader

Start with the shape of most deployed protocols: one proposer at a time, drawn with [Simplex](https://eprint.iacr.org/2023/463)-style notarize and finalize rounds. Consensus is usually benchmarked in isolation, with the clock starting at the leader's proposal. A user's clock starts at submission and ends at finality, so that is the axis every figure in this post uses. Follow the transaction rather than the block.

```{=html}
<style>
  .cw-loop {
    aspect-ratio: 1024 / 464;
    margin: 28px 0 6px;
  }

  .cw-loop-dag {
    aspect-ratio: 1024 / 424;
  }

  .cw-loop-dagstructure {
    aspect-ratio: 1024 / 384;
  }

  .cw-loop-dagfetch {
    aspect-ratio: 1024 / 408;
  }

  @media (max-width: 600px) {
    .cw-loop {
      aspect-ratio: auto;
      height: 295px;
      overflow-x: auto;
    }

    .cw-loop-dag {
      height: 270px;
    }

    .cw-loop-dagstructure {
      height: 245px;
    }

    .cw-loop-dagfetch {
      height: 260px;
    }

    .cw-loop svg {
      min-width: 640px;
    }
  }
</style>
<noscript>
  <style>
    .cw-loop {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      height: auto;
      margin: 28px 0 6px;
      overflow-x: visible;
      padding-left: 12px;
    }
  </style>
</noscript>
<div id="multimmit-fig-simplex" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of a single-proposer protocol. A transaction travels from the user to an API node, is forwarded to the leader, and is broadcast in the leader's block. Two rounds of voting follow. Finality lands three message delays after the block broadcast, five after submission.">
  <noscript>This figure animates a transaction's path through a single-proposer protocol: user to API node, API node to leader, then the leader's block broadcast followed by notarize and finalize vote rounds. The transaction spends 2δ reaching the block that carries it, then 3δ more to finality.</noscript>
</div>
<script type="module" src="multimmit.loops.js"></script>
```

::: {.image-caption}
Figure 1: A transaction's path through a single-proposer protocol, on an axis of message delays ($\delta$) since submission. Every figure in this post shares that axis and draws the best case, with no waits for proposal or production events. The clock that consensus papers report starts at "block". The user has been waiting $2\delta$ by then.
:::

Two problems, one on each side of the figure. On the right, finality costs two rounds of voting, and a recent cohort ([Minimmit](/blogs/minimmit.html), [Alpenglow](https://www.anza.xyz/blog/alpenglow-a-new-consensus-for-solana), [Kudzu](https://arxiv.org/abs/2505.08771)) cuts it to one round when $n \geq 5f+1$ (Multimmit inherits exactly that skeleton, and figures 3 and 4 draw it). On the left, the transaction crosses to an API node, crosses again to the leader, and in expectation sits in a mempool until the leader's next proposal, all before the reported clock starts. Worse, every one of those bytes must flow *out* of the leader again inside the block: the leader's uplink is the throughput ceiling for the entire network. One-round voting fixes nothing on the left side.

## Many Chains, Gated on Certificates

[Autobahn](https://arxiv.org/abs/2401.10369) fixes the uplink. Every producer builds its own *lane* of transaction batches, streaming each batch to all validators as it is produced, so transaction data crosses the network exactly once. Blocks still exist, but they shrink: the leader's block carries references to lane tips instead of transactions, and finalizing it finalizes everything below the referenced tips. This architecture also collapses the left side of Figure 1, because the node that accepts your transaction *is* a producer. Submission is dissemination.

Autobahn then gives the latency right back. A leader may only reference a *certified* tip: validators return data-availability votes (DA-votes) to the producer, the producer aggregates them into a proof of availability (PoA), and the PoA races to reach the leader before its next proposal. Certification is robust (a certified reference can always be resolved) but it inserts three message delays between a batch and its earliest possible inclusion in a block, and the batch still queues for the next proposal after that. Returning DA-votes to every validator instead of just the producer would shave one delay by letting the leader assemble the PoA itself, at the cost of cubic communication per height of lane growth ($n$ voters sending to $n$ validators, for each of $n$ lanes).

```{=html}
<div id="multimmit-fig-lanes" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of producer lanes with certified tips. The API node broadcasts a batch, validators return DA-votes, the producer broadcasts a proof of availability, and only then does the leader's block reference the batch, with two rounds of votes finalizing it six message delays after its broadcast, seven after submission.">
  <noscript>This figure animates the certified-tip pipeline: batch broadcast, DA-votes back to the producer, PoA certificate out, then the leader's block and two rounds of votes. Finality lands 6δ after the batch broadcast.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Producer lanes with certified tips, over the same Simplex-style two-round consensus as figure 1 (three message delays from proposal to finality, the same total as Autobahn's fast path). The batch (green) carries the transaction data and crosses the network once. Its PoA follows two message delays later, the earliest the leader's block, red as in figure 1 but now carrying only references, may include it.
:::

The obvious escape is to reference blocks before they certify, and the known ways to do it each break something. Autobahn sketches uncertified references as an optimization: a voter missing a referenced block holds its vote and fetches the block from the leader. Faulty producers that disclose their latest blocks to the leader alone can then force $\Omega(n^2)$ block transmissions through the leader's uplink before the view can progress, exactly the traffic pattern producer chains exist to avoid. [Raptr](https://arxiv.org/abs/2504.18649) eliminates the fetch: voters support the longest prefix of the proposal they hold data for, and the protocol finalizes a prefix supported by a quorum. But prefixes are order-sensitive. Withhold the data behind a single early batch and the proposal finalizes little or nothing, however much available data it references, so $k$ faulty producers taking turns can deny the whole network its fast path for $k$ consecutive proposals. Raptr counters with reputation (voters blame the authors of missing batches, and a producer blamed by $f+1$ validators is demoted to certified-only inclusion), but the mitigation is reactive: each producer spoils before it is blamed, and a reputation forgiving enough to readmit slow-but-honest producers re-arms the attack on every reset. This fragility is exactly why reputation shows up wherever uncertified references do, and DAG deployments have scored anchors the same way since [Shoal](https://arxiv.org/abs/2306.03058). The DAG world hits the same fork: [Mysticeti](https://arxiv.org/abs/2310.14821) references uncertified vertices, and dropping just 1% of egress traffic at 5 of 100 validators has been [observed](https://arxiv.org/abs/2405.20488) to increase its median latency by an order of magnitude at moderate load.

## Checkpoint Now, Certify in the Background

Multimmit keeps the producer lanes but makes each a real chain: every producer signs its own sequence of transaction blocks, each referencing its parent by hash, extended as transactions arrive. The design is built around a single principle: **a faulty participant other than the leader should only be able to significantly delay the finalization of blocks in its own chain**. Two mechanisms deliver it.

*Proposal-relative voting.* The leader proposes tips for every chain, certified or not. A referenced block costs one hash, nothing certifies that it exists, and nobody fetches anything. Each validator answers with a single vote reporting, per chain, how far up the proposal it can support (that is, how many of the referenced blocks it holds and has DA-voted). A chain finalizes through the deepest position that $3f+1$ votes stand behind, and the next leader must extend the deepest position $f+1$ votes stand behind. A withheld block lowers one chain's tally and nothing else: no timeout, no fetch, no spoiled proposal. A vote that simply supports every proposed tip is constant size.

```{=html}
<div id="multimmit-fig-checkpoint" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's checkpoint path. The API node broadcasts a transaction block, the leader references it in the next leader block before any certificate forms, and one round of votes finalizes it three message delays after the block broadcast, four after submission. Dashed markers show where figures 1 and 2 finalized on the same axis.">
  <noscript>This figure animates Multimmit's checkpoint path: the leader block references the uncertified transaction block and one vote round finalizes it at block + 3δ, while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Transaction block $b$ (green, as batches in figure 2) reaches the leader in time and is checkpointed in the leader block before any PoA forms. Minimmit's single round of votes finalizes it $3\delta$ after its broadcast. The faint arrows are the DA-votes and PoA, forming off the critical path. The dashed markers are where figures 1 and 2 finalized on the same axis, and no transaction data flows through the leader here.
:::

*Extension votes.* A vote may also attest up to $e$ fresh blocks *beyond* the proposed tips, anchored at the voter's own reported position. A block no longer needs to reach the leader before the proposal to finalize in a view. It needs to reach the voters before they vote.

```{=html}
<div id="multimmit-fig-extend" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's extension path. The transaction block and the leader block cross on the wire, so the leader block cannot reference it. Voters attest the block in their votes anyway, finalizing it two message delays after the block broadcast, three after submission. Dashed markers show where the earlier figures finalized on the same axis.">
  <noscript>This figure animates Multimmit's extension path: the transaction block misses the leader block but reaches the voters, whose extension votes attest it directly, finalizing at block + 2δ while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 4: Transaction block $b$ misses the leader block, crossing it on the wire, but reaches the voters before they vote. Their votes attest $b$ directly and it finalizes $2\delta$ after its broadcast. The dashed markers are where the earlier figures finalized on the same axis.
:::

Read the User row of either figure: submit to an API node, the API node's next block carries the transaction to every validator, and one round of votes finalizes it. There is no separate journey to the leader because there is nothing the leader must gather first. Averaged over the wait for the next vote event, a block disseminated at time $t$ is finalized by $t+3\delta$, and by $t+2\delta$ when the timing is favorable. Two message delays is optimal. Reported from the leader's proposal instead, the convention most consensus papers use, Multimmit's figure would simply read $2\delta$: the mechanisms above act on the leg that convention never measures. For comparison, Raptr finalizes a batch disseminated at time $t$ at $t+5\delta$ in expectation with *no* faults, degrading to $t+5.5\delta$ (and spoilable) once faulty producers show up. Multimmit's figures do not degrade: an honest chain's block still finalizes by $t+3\delta$ in expectation with $f$ faulty producers doing their worst, and at most waits one extra view for its slot in the total ordering behind a lagging faulty chain.

Spoiling is worth seeing concretely. A Raptr proposal is one ordered sequence, and a vote is a single prefix length, so one hole caps every vote behind it.

```{=html}
<div id="multimmit-fig-spoiling" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated diagram of easy spoiling in Raptr. The leader proposes an ordered sequence of six batches from six producers, A through F. Producer B withholds batch 2, shown as a dashed hole. Votes arrive as dots, and nearly every vote supports only prefix 1 because it lacks batch 2, with a single vote reaching prefix 6. The proposal finalizes prefix 1 in gold, and batches 3 through 6 dim to gray: available, yet stranded behind the hole.">
  <noscript>This figure animates easy spoiling: a Raptr proposal is an ordered sequence of six batches from six producers, producer B withholds batch 2, so nearly every vote supports only prefix 1. The proposal finalizes prefix 1, stranding batches 3-6 even though their data is fully available.</noscript>
</div>
```

::: {.image-caption}
Figure 5: Easy spoiling. A Raptr proposal is an ordered sequence of batches, and each voter supports the longest prefix whose data it holds. One withheld batch early in the sequence caps almost every vote at the hole, so the proposal finalizes prefix 1 and strands every available batch behind position 2. The batches belong to six different producers, so producer B's hole strands the data of C through F. Stranded batches eventually land through the certified slow path, which is exactly the path prefix voting exists to avoid. Multimmit's votes (next figure) report per chain instead of per prefix, so there is no position to poison: a withheld block costs its own chain and nothing else.
:::


What does one round of votes actually pin down? Everything is read off the certificate by rank rules. An L-QC is any $n-f$ votes for the leader block, and each vote already reports, per chain, the highest proposed position it supports. Sorting a chain's reported positions and discarding the top $3f$ yields its finalized tip, discarding only the top $f$ yields the tip the next leader must extend, and quorum intersection keeps the second at or above the first. The finalized tips then enter the log in a deterministic sweep.

```{=html}
<div id="multimmit-fig-certificate" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated diagram of Multimmit's certificate rules, drawn at n equals 11 and f equals 2. Left: nine votes stack as dots above one chain's proposed positions. Discarding the top six votes marks position 3 finalized in gold, and discarding only the top two marks position 4 safe to extend in blue. Right: a four-chain grid where the finalized tips of every chain are stamped into a single order, each chain's first new block before any chain's second.">
  <noscript>This figure animates the certificate rules at n=11, f=2. Nine votes stack above one chain's proposed positions. Dropping the top 3f=6 votes yields the finalized tip (position 3), and dropping only the top f=2 yields the safe-to-extend tip (position 4). The finalized tips of all chains are then stamped into a single order by a fixed sweep, each chain's first new block before any chain's second.</noscript>
</div>
```

::: {.image-caption}
Figure 6: From votes to an ordering, drawn at $n=11$, $f=2$ so the discards are visible. Left: one chain of the proposal inside an L-QC, which is any $n-f=9$ votes for the leader block. Each vote reports the highest proposed position it supports. Dropping the top $3f=6$ leaves the finalized tip (gold), backed by $3f+1=7$ votes. The low votes belong to voters missing this chain's newest blocks, and they lower only this chain's tip. Dropping only the top $f=2$ leaves the safe-to-extend tip (blue), which the next leader must build on, so a finalized tip can never be orphaned. Right: every chain's finalized tips enter the log by a fixed sweep, each chain's first new block before any chain's second (gray cells are the previous tips, already ordered).
:::


The thresholds above are exact, and they carry guarantees that go beyond latency:

- A faulty producer can withhold blocks, equivocate, or disclose blocks selectively, and the only chain it delays is its own (other chains wait at most one view for their slot in the total ordering).
- A leader cannot finalize its own block while censoring someone else's. If a fresh honest block reaches the honest validators before they vote, then either the view finalizes nothing at all or that block's membership in the ledger is settled in that view, whatever the leader proposed.
- Consensus messages stay tens of kilobytes per view, independent of transaction volume. With views lasting 100-200ms, a single view at line rate can order tens of megabytes of transactions on a commodity gigabit link.

Multimmit can carry a reputation mechanism too, but as a refinement rather than a defense. With damage already confined to a faulty producer's own chain, blame only tunes where lagging chains sit in the ordering sweep, no guarantee depends on it, and forgiveness can be generous.

## DAGs Wait in Waves

DAG-based protocols ([Narwhal](https://arxiv.org/abs/2105.11827), [Bullshark](https://arxiv.org/abs/2201.05677), [Mysticeti](https://arxiv.org/abs/2310.14821)) reach the same bandwidth goal, every validator disseminating in parallel, with a different coupling: the transaction-carrying structure *is* the consensus structure. Every validator's vertex carries transactions and must reference $n-f$ vertices from the previous round, and it is the reference pattern itself that the ordering logic interprets.

```{=html}
<div id="multimmit-fig-dagstructure" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG construction. Four validators each emit one vertex per round. As each new round of vertices appears, edges draw back from every vertex to three of the four vertices in the previous round, forming a lattice.">
  <noscript>This figure animates DAG construction: four validators emit one vertex per round, and each new vertex draws reference edges back to n−f (here 3 of 4) vertices of the previous round.</noscript>
</div>
```

::: {.image-caption}
Figure 7: How a DAG mempool is built. Each round, every validator emits a vertex referencing $n-f$ vertices of the previous round. The references are the protocol: they carry availability and voting information, so the ordering logic can read finality out of the lattice.
:::

Reading finality out of the lattice takes more rounds still. A reference is not finality on its own: the ordering logic designates periodic anchor vertices, and an anchor commits only once the following rounds' reference pattern proves enough of the network built on top of it. Committing the anchor then orders every vertex in its causal history, and everything else waits for a later anchor.

```{=html}
<div id="multimmit-fig-dagfinality" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG finality. Four validators emit one vertex per round. Validator 2's round-r vertex, labeled A, is the anchor. Gold reference edges from round r+1 mark its support, and once round r+2 lands, A and its causal history turn gold, two rounds after A entered the DAG. Every other vertex stays pending until a later anchor commits.">
  <noscript>This figure animates DAG finality: anchor A enters in round r, is referenced by n−f round r+1 vertices, and commits only once round r+2 lands, ordering its causal history with it. Finality arrives two rounds of DAG growth after the vertex itself.</noscript>
</div>
```

::: {.image-caption}
Figure 8: Finality read out of the lattice, drawn with a Mysticeti-style three-round pattern. Anchor $A$ enters in round $r$, gathers support (gold references) in $r+1$, and commits once the $r+2$ pattern lands, ordering its causal history (gold) with it. Every other vertex waits for a later anchor, and in a certified DAG each of these rounds is itself a certificate round trip.
:::

The coupling cuts both ways. A vertex may only enter round $r+1$ once $n-f$ round-$r$ vertices have arrived, so the whole network produces in lockstep, and nobody's next block can outrun the slowest quorum step of the last one. In certified DAGs like Narwhal, that step is a certificate round trip between every pair of consecutive vertices. In uncertified DAGs like Mysticeti, the round trip goes away and the fetch problem comes back: every vertex is a dependency of the vertices that reference it, so a validator missing a vertex must fetch it before processing anything built on top.

```{=html}
<div id="multimmit-fig-dagfetch" class="cw-loop cw-loop-dagfetch" role="img" aria-label="Animated diagram of a fetch stall in an uncertified DAG with four validators. Validator 3 withholds its round r+1 vertex, shown as a dashed hole, disclosing it only to validator 2, whose round r+2 vertex references it with a red edge. A vertex is unusable until its full ancestry is held, so validators 1 and 4 must fetch the withheld vertex from validator 2 before they can build on validator 2's vertex, and round r+3 starts 1.7 message delays later than the dashed on-time marker.">
  <noscript>This figure animates a fetch stall in an uncertified DAG with four validators: validator 3 withholds its round r+1 vertex from all but validator 2, whose next vertex references it. A vertex is unusable without its full ancestry, so validators 1 and 4 must fetch the withheld vertex before they can build on validator 2's, and round r+3 starts a fetch round trip late.</noscript>
</div>
```

::: {.image-caption}
Figure 9: The fetch problem. Validator 3 withholds its round-$(r+1)$ vertex, disclosing it only to validator 2, whose next vertex references it (red edge). A vertex is unusable until its full ancestry is held, so validators 1 and 4 must fetch the withheld vertex before they can build on validator 2's, and without it they hold only two of the $n-f=3$ round-$(r+2)$ vertices that round $r+3$ requires. Every lane's round $r+3$ starts late. At larger scale the DAG routes around one hole, but every hole still puts a fetch on someone's critical path, and at real block rates sustained loss keeps holes in nearly every round (the measured blowup above). In Multimmit a reference never obligates a download: voters report how far they can support each chain and vote on schedule, so a withheld block costs its own chain's tally and nobody else's.
:::

```{=html}
<div id="multimmit-fig-dag" class="cw-loop cw-loop-dag" role="img" aria-label="Animated comparison of block production over eight message delays. A DAG producer emits a vertex, waits for a two-delay certificate round trip, and only then emits the next, producing four vertices. A Multimmit producer emits a block every two-thirds of a message delay with certificate round trips overlapping in the background, producing thirteen blocks in the same time.">
  <noscript>This figure animates block production over 8δ. The DAG producer waits out a 2δ certificate round trip between consecutive vertices (4 vertices total). The Multimmit producer keeps emitting while certificates form in the background (13 blocks in the same window), constrained only by its pipelining window.</noscript>
</div>
```

::: {.image-caption}
Figure 10: One producer, identical $2\delta$ certificate round trips. The DAG producer's next vertex waits for the previous round's certificates, drawn charitably as if every other producer's certificate arrives with its own votes (spreading them costs a certified DAG a third delay per round). The Multimmit producer waits only on its own chain and runs ahead of certification, up to $d$ uncertified blocks in flight (drawn with production paced by load, filling the $d=3$ window).
:::

Multimmit's chains carry no cross-producer references, so there is nothing for a producer to wait on. Each producer extends its own chain as transactions arrive and may run up to $d$ blocks ahead of its last certified block, with certificates forming behind it. Under sustained load a chain grows up to $d$ blocks per certificate round trip rather than one, and consensus never waits on certification either way: the leader checkpoints whatever has arrived, and the voters extend past whatever the leader missed.

## Onward

Multimmit is the end of the thread Vryx started: transaction dissemination and consensus running concurrently, with neither ever blocking on the other. Blocks enter the ordering process the moment they hit the wire, availability is voted rather than fetched, and the failure of any producer is confined to its own chain. The draft specification includes proofs of consistency and liveness, an availability accounting for every block that enters the ordering, and the exact extension threshold for every $n$, with the protocol's rules optimal at $n=5f+1$.

Like Minimmit before it, Multimmit is not yet peer-reviewed or fully implemented, and we are releasing it under both MIT and Apache-2 licenses for others to build with and build upon. Have an idea to simplify, improve, or extend Multimmit? [Open a PR](https://github.com/commonwarexyz/monorepo/tree/main/pipeline/multimmit) or reach out at [multimmit@commonware.xyz](mailto:multimmit@commonware.xyz).
