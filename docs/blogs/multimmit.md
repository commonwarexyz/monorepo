---
title: "The Best of Both Worlds"
description: "Two-delay finality is the theoretical minimum, but existing protocols, including DAGs, provide it only for designated leader blocks. Multimmit extends two-delay finality to every honest producer's blocks at once: the best of both worlds."
date: "July 23rd, 2026"
published-time: "2026-07-23T00:00:00Z"
modified-time: "2026-07-23T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/multimmit"
image: "https://commonware.xyz/imgs/multimmit.png"
katex: true
---

For users, a blockchain's speed is the time from submitting a transaction to seeing it final. Most consensus benchmarks start their timer later, when a leader proposes a block. In a traditional leader-based protocol, a transaction must first reach the current leader before it can appear in a block. That leader then broadcasts the same transaction back out to every validator, limiting network throughput to one node's egress.

Decoupling transaction dissemination from consensus removes this bottleneck. Every validator becomes a *producer* and streams its own transaction data in parallel, while consensus orders small references to that data. The network can then finalize transactions at roughly the rate validators can *ingress* them instead of the rate one leader can *egress* them. This split is [now standard among high-throughput designs](https://hackmd.io/@patrickogrady/rys8mdl5p).

However, decoupling has typically increased finality latency. Consensus cannot finalize a reference to data that the network cannot recover. Existing protocols either certify each block before it can be referenced or allow immediate references and require voters to fetch missing data. The first approach adds certificate round trips to every transaction. The second is faster until a producer misbehaves, at which point voters must fetch before they can vote.

Today, we're sharing [Multimmit](https://arxiv.org/abs/2607.21021), a construction that avoids both delays. Each producer extends its own chain of transaction blocks without waiting on other producers. Consensus references blocks as soon as they arrive, and the votes already being cast establish availability. No block waits for a certificate and no voter waits to fetch missing data. Votes can also include blocks the leader missed, allowing every producer to add to the finalized log in each view.

With Multimmit, an honest producer's block finalizes $2\delta$ after broadcast in the best case and $3\delta$ in expectation, even when up to $f$ producers are faulty (assuming $n \geq 5f+1$). Unlike the latency figures usually reported for consensus, this timer starts at broadcast, not at a later leader proposal. Two message delays is the [theoretical minimum](https://arxiv.org/abs/2102.07240) for fault-tolerant consensus. Existing two-round protocols, including DAG protocols such as [BlueBottle](https://arxiv.org/abs/2511.15361), reach it only for designated leader blocks. Multimmit reaches that bound for blocks from every honest producer without giving up concurrent dissemination: the best of both worlds.

## The Ride to the Leader

Consider a typical deployed protocol with one proposer at a time and [Simplex](https://eprint.iacr.org/2023/463)-style notarize and finalize rounds. Figures 1, 2, 4, and 5 measure from transaction submission and track the transaction through finality.

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

  .cw-loop-certificate {
    aspect-ratio: 1024 / 520;
  }

  .cw-loop-spoiling {
    aspect-ratio: 1024 / 500;
  }
</style>
<noscript>
  <style>
    .cw-loop {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      margin: 28px 0 6px;
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
Figure 1: A transaction's path through a single-proposer protocol, measured in message delays ($\delta$) since submission. Figures 1, 2, 4, and 5 use the same axis and assume there is no wait for the next proposal or production event. Consensus papers typically start their timers at "block", after the user has already waited $2\delta$.
:::

After the leader broadcasts a block, finality takes two rounds of voting. A recent cohort ([Minimmit](/blogs/minimmit.html), [Alpenglow](https://www.anza.xyz/blog/alpenglow-a-new-consensus-for-solana), [Kudzu](https://arxiv.org/abs/2505.08771)) reduces this to one round when $n \geq 5f+1$ (Multimmit uses the same consensus skeleton in Figures 4 and 5). Before the broadcast, however, the transaction must reach an API node, travel again to the leader, and wait for the leader's next proposal. This time is usually excluded from reported consensus latency. The leader must then send every transaction back out inside its block, making its egress the throughput limit for the entire network. One-round voting only improves the part after the broadcast.

## Removing the Leader Bottleneck

[Autobahn](https://arxiv.org/abs/2401.10369) removes the leader's egress bottleneck. Every producer builds its own *lane* of transaction batches and streams each batch to all validators as it is produced, so transaction data crosses the network only once. The leader still proposes a block, but it now contains references to lane tips instead of transactions. When the leader block finalizes, so does everything below those tips.

The node accepting a transaction is also a producer, so submission begins dissemination immediately. Lanes continue growing during failed consensus views, and the first successful proposal commits the accumulated backlog. Autobahn calls this property *seamlessness*.

The catch is that a leader may only reference a *certified* tip. Validators return data-availability votes (DA-votes) to the producer, the producer aggregates them into a proof of availability (PoA), and the PoA must reach the leader before its next proposal. Certification guarantees that a referenced batch can be recovered, but it adds three message delays between dissemination and the earliest possible proposal (plus any wait for that proposal). Sending DA-votes to every validator would save one delay by allowing the leader to assemble the PoA, but would require cubic communication per height of lane growth ($n$ voters sending to $n$ validators for each of $n$ lanes).

```{=html}
<div id="multimmit-fig-lanes" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of producer lanes with certified tips. The API node broadcasts a batch, validators return DA-votes, the producer broadcasts a proof of availability, and only then does the leader's block reference the batch, with two rounds of votes finalizing it six message delays after its broadcast, seven after submission.">
  <noscript>This figure animates the certified-tip pipeline: batch broadcast, DA-votes back to the producer, PoA certificate out, then the leader's block and two rounds of votes. Finality lands 6δ after the batch broadcast.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Producer lanes with certified tips, using the same Simplex-style two-round consensus as Figure 1. Like Autobahn's fast path, finality takes three message delays after the proposal. The transaction batch (green) crosses the network once. Its PoA arrives two message delays later, after which the leader's block may reference it. The leader block remains red but now contains only references.
:::

Why not reference blocks before they are certified? Autobahn sketches this as an optimization: a voter missing a referenced batch delays its vote and fetches the batch from the leader. A faulty producer can disclose its latest batch only to the leader, forcing the leader to relay it to every voter before the view can progress. Across faulty producers, this creates $\Omega(n^2)$ batch transmissions through the leader's egress (the same bottleneck producer lanes were introduced to remove).

[Raptr](https://arxiv.org/abs/2504.18649) avoids the fetch by having voters support the longest prefix of a proposal for which they hold data. The protocol then finalizes the prefix supported by a quorum. This makes one missing batch enough to *spoil* everything after it. Even if all later batches are available, they cannot finalize. By taking turns, $k$ faulty producers can deny the fast path for $k$ consecutive proposals.

Raptr uses reputation to limit this attack. Voters blame the authors of missing batches, and a producer blamed by $f+1$ validators is restricted to certified references. This only helps after the producer has spoiled a proposal. Any policy that eventually readmits slow-but-honest producers also gives a faulty producer another chance to spoil.

```{=html}
<div id="multimmit-fig-spoiling" class="cw-loop cw-loop-spoiling" role="img" aria-label="Animated diagram of easy spoiling in Raptr. The leader block is drawn as a red container holding one flat sequence of six batches from six producers, P1 through P6. Producer P2 withholds batch 2, shown as a dashed hole. Votes arrive as dots, and nearly every vote supports only prefix 1 because it lacks batch 2, with a single vote reaching prefix 6. The proposal finalizes prefix 1 in gold, and batches 3 through 6 dim to gray: available, yet stranded behind the hole.">
  <noscript>This figure animates easy spoiling: a Raptr leader block carries one flat sequence of six batches from six producers, producer P2 withholds batch 2, so nearly every vote supports only prefix 1. The proposal finalizes prefix 1, stranding batches 3-6 even though their data is fully available.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Easy spoiling. A Raptr leader block carries one sequence of batches from many producers, and each voter supports the longest prefix whose data it holds. When P2 withholds its batch, almost every vote stops at the gap. The proposal finalizes prefix 1 even though the batches from P3 through P6 are available. These batches eventually land through the certified slow path. Multimmit votes (Figure 6) report a position for each chain, so a withheld block only lowers the position reported for its own chain.
:::

[Mysticeti](https://arxiv.org/abs/2310.14821) makes the same tradeoff for a DAG by referencing uncertified vertices. Dropping just 1% of egress traffic at 5 of 100 validators has been [observed](https://arxiv.org/abs/2405.20488) to increase its median latency by an order of magnitude at moderate load. DAG deployments use reputation for the same reason and have scored anchors (their leader equivalents) since [Shoal](https://arxiv.org/abs/2306.03058). We return to DAGs below.

*Erasure coding takes a different approach: keep the leader on the data path, but send each validator a smaller fragment of each block. A stable leader can then pipeline proposals without gaps between them. Together, these techniques let a leader-based protocol approach line-rate throughput. The tradeoff is that every transaction must still reach that leader before dissemination begins, and the leader can censor transactions throughout its tenure. We explain the coding in [Deliver Us in Pieces](/blogs/coding.html) and establish its limits in [The Carnot Bound](/blogs/carnot-bound.html).*

## Multimmit: Checkpoint First, Certify in the Background

Multimmit keeps producer lanes but makes each one a chain. Every producer signs its own sequence of transaction blocks, with each block referencing its parent by hash. DA-votes and PoAs still form for every block, as in Figure 2, but consensus does not wait for them. A producer may run up to $d$ blocks ahead of its last certified block, leaving a short uncertified tail while everything below it remains recoverable.

Multimmit is designed around one rule: **a faulty participant other than the leader should only be able to significantly delay the finalization of blocks in its own chain**. Its votes have two parts: proposal-relative positions and extensions.

*Proposal-relative voting.* The leader *checkpoints* one tip for every chain, whether it is certified or not. Each reference costs one hash. A validator does not fetch missing blocks. Its vote reports how far it can support each chain in the proposal (the blocks it holds and has DA-voted). A chain finalizes through the highest position supported by $3f+1$ votes, and the next leader must extend the highest position supported by $f+1$ votes. If a producer withholds a block, only its own reported position falls. Other chains do not wait or fetch, and the proposal is not spoiled. A vote supporting every proposed tip remains constant size.

```{=html}
<div id="multimmit-fig-checkpoint" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's checkpoint path. The API node broadcasts a transaction block, the leader references it in the next leader block before any certificate forms, and one round of votes finalizes it three message delays after the block broadcast, four after submission. Dashed markers show where Figures 1 and 2 finalized on the same axis.">
  <noscript>This figure animates Multimmit's checkpoint path: the leader block references the uncertified transaction block and one vote round finalizes it at block + 3δ, while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 4: Transaction block $b$ (green, like the batch in Figure 2) reaches the leader before its proposal and is checkpointed before a PoA forms. Minimmit's single voting round finalizes $b$ $3\delta$ after its broadcast. DA-votes and the PoA (faint arrows) form in the background. The dashed markers show the finality times from Figures 1 and 2. No transaction data passes through the leader.
:::

*Extension votes.* A vote may also attest to as many as $e$ fresh blocks *beyond* the proposed tips, anchored at the voter's reported position. A block that misses the leader's proposal can still finalize in the same view if it reaches voters before they vote. Because each extension is anchored to the position reported by that voter, junk or stale entries cannot prevent correct voters from attaching recent blocks. A leader cannot finalize its own block while excluding a well-disseminated honest block. It must allow that block to finalize or prevent the entire view from finalizing.

```{=html}
<div id="multimmit-fig-extend" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's extension path. The transaction block and the leader block cross on the wire, so the leader block cannot reference it. Voters attest the block in their votes anyway, finalizing it two message delays after the block broadcast, three after submission. Dashed markers show where the earlier figures finalized on the same axis.">
  <noscript>This figure animates Multimmit's extension path: the transaction block misses the leader block but reaches the voters, whose extension votes attest it directly, finalizing at block + 2δ while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 5: Transaction block $b$ crosses the leader block on the wire and misses the proposal, but reaches validators before they vote. Extension votes attest $b$ directly, finalizing it $2\delta$ after its broadcast. Certification continues in the background (faint arrows) and finishes after $b$ has already finalized.
:::

From the user's perspective, both paths are simple: submit to an API node, let its next block carry the transaction to every validator, and wait one round of votes for finality. The producer can pre-confirm the transaction as soon as it arrives, potentially before it could reach a leader an ocean away. Nothing must reach the leader before dissemination begins. Including the wait for the next vote event, a block sent at time $t$ finalizes at $t+3\delta$ in expectation (and by $t+2\delta$ with favorable timing). The two-delay case is optimal.

If we started the timer at the leader's proposal, as consensus papers often do, Multimmit finality would be reported as $2\delta$. That convention misses where checkpoints and extension votes save time. Raptr, measured from dissemination, finalizes a batch at $t+5\delta$ in expectation with *no* faults and at $t+5.5\delta$ once faulty producers are present (with the fast path still subject to spoiling). Roughly one $\delta$ of Multimmit's improvement comes from assuming $n \geq 5f+1$ and using one voting round instead of two. Checkpoints and extension votes provide the rest. An honest chain's expected $t+3\delta$ finality does not change when $f$ producers misbehave.

How does one round of votes produce a single ordering? Each Multimmit vote carries an independent position for every chain. Voters do not vote on how blocks from different chains are interleaved. That ordering is computed afterwards from the finalized tips, which prevents a gap in one chain from limiting any other chain.

An L-QC (a quorum certificate on the leader block) aggregates any $n-f$ votes for it. For each chain, sort the positions reported by those votes. Discarding the top $3f$ positions gives the finalized tip. Discarding only the top $f$ gives the tip that the next leader must extend. Quorum intersection keeps the second tip at or above the first. After applying these rules independently to every chain, the finalized blocks enter the log in a fixed sweep.

```{=html}
<div id="multimmit-fig-certificate" class="cw-loop cw-loop-certificate" role="img" aria-label="Animated diagram of Multimmit's certificate rules, drawn at n equals 11 and f equals 2. Left: the leader block is drawn as a red container holding one compact coordinate row per chain, chains 1 through 4, each a gray previous tip followed by as many green proposed entries as the leader has seen for that chain, and chain 1's coordinate is zoomed below it: blocks 1B through 1E proposed above its previous tip 1A. Nine votes stack as dots above the entries. Discarding the top six votes finalizes 1D in gold, and discarding only the top two marks 1E safe to extend in blue. Right: a four-chain grid where the finalized tips of every chain are stamped into a single order, each chain's first new block before any chain's second, with chain 1's column carrying the same gold 1D and blue 1E as the zoomed coordinate.">
  <noscript>This figure animates the certificate rules at n=11, f=2. The leader block carries one coordinate per chain, and chain 1's coordinate is zoomed: nine votes stack above its proposed entries (1B through 1E, above its previous tip 1A). Dropping the top 3f=6 votes finalizes 1D, and dropping only the top f=2 marks 1E safe to extend. The finalized tips of all chains are then stamped into a single order by a fixed sweep, each chain's first new block before any chain's second.</noscript>
</div>
```

::: {.image-caption}
Figure 6: Converting votes into an ordering at $n=11$, $f=2$. The leader block (left) contains one coordinate for each producer chain. Chain 1 is expanded below it, from the previous tip 1A through proposed blocks 1B-1E. An L-QC contains $n-f=9$ votes, each reporting its highest supported block on every chain. Dropping the top $3f=6$ positions finalizes 1D (gold) with $3f+1=7$ votes. Voters missing newer chain 1 blocks lower only this result. Dropping the top $f=2$ positions gives the safe-to-extend tip 1E (blue), which prevents the next leader from orphaning 1D. These rules run independently for every chain. The resulting tips enter the log (right) in a fixed sweep, with each chain's first new block ordered before any chain's second. Gray cells were ordered previously.
:::

At $n=5f+1$, these thresholds provide three other useful properties:

- A faulty producer can withhold blocks, equivocate, or disclose blocks selectively, but any resulting delay is confined to its own chain (other chains wait at most one view for their position in the total ordering).
- A leader cannot finalize its own block while censoring someone else's. If a fresh honest block reaches the honest validators before they vote, its membership in the ledger is settled in that view unless the view finalizes nothing.
- Consensus messages stay tens of kilobytes per view, independent of transaction volume. With views lasting 100-200ms, a single view at line rate can order tens of megabytes of transactions on a commodity gigabit link.

## Why Not a DAG?

DAG-based protocols ([Narwhal](https://arxiv.org/abs/2105.11827), [Bullshark](https://arxiv.org/abs/2201.05677), [Mysticeti](https://arxiv.org/abs/2310.14821)) were the first to have every validator disseminate transactions in parallel. The costs of this approach motivated designs like Autobahn and Raptr. In a DAG, the transaction-carrying structure is also the consensus structure. Every validator's vertex carries transactions and references $n-f$ vertices from the previous round. Consensus determines finality by interpreting this pattern of references.

```{=html}
<div id="multimmit-fig-dagstructure" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG construction. Four validators each emit one vertex per round. As each new round of vertices appears, edges draw back from every vertex to three of the four vertices in the previous round, forming a lattice.">
  <noscript>This figure animates DAG construction: four validators emit one vertex per round, and each new vertex draws reference edges back to n−f (here 3 of 4) vertices of the previous round.</noscript>
</div>
```

::: {.image-caption}
Figure 7: How a DAG mempool is built. Each round, every validator emits a vertex referencing $n-f$ vertices of the previous round. The references are the protocol: they carry availability and voting information, so the ordering logic can read finality out of the lattice.
:::

A reference does not provide finality on its own. The ordering logic designates periodic anchor vertices, and an anchor commits only after later rounds show that enough validators built on top of it. Committing the anchor orders every vertex in its causal history. The remaining vertices wait for a later anchor.

```{=html}
<div id="multimmit-fig-dagfinality" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG finality. Four validators emit one vertex per round. Validator 2's round-r vertex, labeled A, is the anchor. Gold reference edges from round r+1 mark its support, and once round r+2 lands, A and its causal history turn gold, two rounds after A entered the DAG. Every other vertex stays pending until a later anchor commits.">
  <noscript>This figure animates DAG finality: anchor A enters in round r, is referenced by n−f round r+1 vertices, and commits only once round r+2 lands, ordering its causal history with it. Finality arrives two rounds of DAG growth after the vertex itself.</noscript>
</div>
```

::: {.image-caption}
Figure 8: Finality in a Mysticeti-style three-round pattern. Anchor $A$ enters in round $r$, gathers support (gold references) in $r+1$, and commits when round $r+2$ arrives. Its causal history (gold) is ordered with it, while every other vertex waits for a later anchor. In a certified DAG, each round also requires a certificate round trip.
:::

This coupling also controls production. A validator may only create a round-$r+1$ vertex after receiving $n-f$ round-$r$ vertices, so the network produces in lockstep (deployments add round timeouts to keep the DAG well connected). In certified DAGs like Narwhal, a certificate round trip separates each pair of consecutive vertices. Uncertified DAGs like Mysticeti remove that round trip but reintroduce fetching. Because every referenced vertex is a dependency, a validator must fetch a missing vertex before it can process anything built on top of it.

```{=html}
<div id="multimmit-fig-dagfetch" class="cw-loop cw-loop-dagfetch" role="img" aria-label="Animated diagram of a fetch stall in an uncertified DAG with four validators. Validator 3 withholds its round r+1 vertex, shown as a dashed hole, disclosing it only to validator 2, whose round r+2 vertex references it with a red edge. A vertex is unusable until its full ancestry is held, so validators 1 and 4 must fetch the withheld vertex from validator 2 before they can build on validator 2's vertex, and round r+3 starts 1.7 message delays later than the dashed on-time marker.">
  <noscript>This figure animates a fetch stall in an uncertified DAG with four validators: validator 3 withholds its round r+1 vertex from all but validator 2, whose next vertex references it. A vertex is unusable without its full ancestry, so validators 1 and 4 must fetch the withheld vertex before they can build on validator 2's, and round r+3 starts a fetch round trip late.</noscript>
</div>
```

::: {.image-caption}
Figure 9: The fetch problem. Validator 3 sends its round-$(r+1)$ vertex only to validator 2, whose next vertex references it (red edge). Validators 1 and 4 cannot use validator 2's vertex without its full ancestry, leaving them with only two of the $n-f=3$ round-$(r+2)$ vertices needed to enter round $r+3$. They must fetch the withheld vertex first, delaying the next round for everyone. Larger DAGs can route around an isolated gap, but each gap still puts a fetch on someone's critical path. At real block rates, sustained loss creates gaps in nearly every round (producing the order-of-magnitude slowdown measured above). A Multimmit reference never requires a download. Voters report how far they can support each chain and vote on schedule.
:::

Whether the protocol waits for fetches or certificates, a collective step limits every producer's output. Figure 10 compares that pace with a Multimmit producer paying the same certificate round trips.

```{=html}
<div id="multimmit-fig-dag" class="cw-loop cw-loop-dag" role="img" aria-label="Animated comparison of block production over eight message delays. A DAG producer emits a vertex, waits for a two-delay certificate round trip, and only then emits the next, producing four vertices. A Multimmit producer emits a block every two-thirds of a message delay with certificate round trips overlapping in the background, producing thirteen blocks in the same time.">
  <noscript>This figure animates block production over 8δ. The DAG producer waits out a 2δ certificate round trip between consecutive vertices (4 vertices total). The Multimmit producer keeps emitting while certificates form in the background (13 blocks in the same window), constrained only by its pipelining window.</noscript>
</div>
```

::: {.image-caption}
Figure 10: One producer with identical $2\delta$ certificate round trips. The DAG producer waits for the previous round's certificates before creating its next vertex (assuming every other producer's certificate arrives with its votes, since spreading them costs a certified DAG a third delay per round). The Multimmit producer runs as many as $d$ blocks ahead of certification, shown here filling a $d=3$ window under load.
:::

Multimmit chains contain no cross-producer references. Each producer extends its own chain as transactions arrive and can run as many as $d$ blocks ahead of its last certified block. Certificates form in the background. Under sustained load, a chain can grow by $d$ blocks per certificate round trip instead of one.

Consensus also proceeds without waiting for certification. The leader checkpoints the blocks it has received, and voters extend beyond anything the leader missed. Producers continue building through leader failures and view changes. The first successful view checkpoints the backlog.

```{=html}
<div id="multimmit-fig-blip" class="cw-loop cw-loop-dag" role="img" aria-label="Animated diagram of a Multimmit producer through a consensus blip. Two rows: consensus views above, one producer below. The producer emits a block every two-thirds of a message delay for the whole window, with certificate arcs forming behind each block. An early leader block finalizes the first two blocks with gold edges. Then a consensus blip begins, marked by dashed boundaries: two views time out, drawn as dashed hollow leader blocks, while the producer keeps emitting and certificates keep forming. When the blip ends, the first successful leader block draws gold edges back to the entire backlog, and one message delay later seven blocks finalize at once.">
  <noscript>This figure animates a consensus blip: two views time out while a Multimmit producer keeps emitting blocks on cadence, certificates forming behind them. The first successful view references the whole backlog, and one round of votes finalizes everything the blip delayed.</noscript>
</div>
```

::: {.image-caption}
Figure 11: Two consensus views time out between the dashed markers. The producer keeps emitting blocks and forming certificates without the leader. The first successful view checkpoints the backlog, and one round of votes finalizes it. Blocks emitted after that proposal wait for the next view.
:::

## Every Producer, Every View

Multimmit runs transaction dissemination and consensus concurrently. Blocks enter the ordering process as soon as they reach validators, consensus votes establish their availability, and a faulty producer only delays its own chain. The [specification](https://arxiv.org/abs/2607.21021) includes proofs of consistency and liveness, accounts for the availability of every ordered block, and gives the exact extension threshold for every $n$ (with optimal rules at $n=5f+1$).

Submit a transaction to any producer. One round of votes later, it is final.
