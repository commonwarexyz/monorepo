---
title: "Multimmit: The Best of Both Worlds"
description: "The fastest path to finality no longer belongs exclusively to the leader. In Multimmit, blocks from every honest sequencer can reach the two-message-delay lower bound, even when they miss the leader's proposal, while all sequencers disseminate independent transaction chains in parallel."
date: "July 23rd, 2026"
published-time: "2026-07-23T00:00:00Z"
modified-time: "2026-07-23T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/multimmit"
image: "https://commonware.xyz/imgs/multimmit.png"
katex: true
---

For users, the only blockchain speed that matters is the time from submitting a transaction to seeing it finalize.

In a "traditional" leader-based protocol, this means sending a transaction to an API, the API sending that transaction to the leader (wherever it may be in the world), and then landing in a finalized block (unless you just missed the leader's proposal and land in the next one). The throughput of all of this bound by the leader's egress (which bounds the rate they can push their block, erasure coded or not, to other validators).

[Decoupling transaction dissemination from consensus removes the scale bottleneck (at least)](https://hackmd.io/@patrickogrady/rys8mdl5p). Instead of one leader sequencing all transaction data, many independent *producers* each sequence and stream their own chain of transaction blocks in parallel. Consensus then orders small references from those chains into one log (or uses the broadcast directly as consensus in a DAG). 

However, decoupling often increases the latency of finality (the number we just said is the only thing users care about). Consensus cannot finalize a reference to data that the network cannot recover. Existing protocols either certify each block before it can be referenced or reference blocks immediately. The first approach adds certificate round trips to every transaction. The second is faster until data is missing, at which point voters must fetch it or the protocol finalizes only the prefix before the gap.

Today, we're revealing [Multimmit](https://arxiv.org/abs/2607.21021), a construction that avoids both delays. Producers, validators and optionally API nodes, each emit their own stream of transaction blocks. Consensus references these blocks as soon as they arrive, and votes already being cast establish availability. No block waits for a certificate, no voter waits to fetch missing data, and a withheld block delays finality only on a producer's own chain. Votes can also include blocks the leader missed (or censored), allowing blocks from every producer chain to enter the finalized log in each view.

With Multimmit, a block from any honest producer chain can finalize $2\delta$ after broadcast, even when up to $f$ non-leader producers are faulty (assuming $n \geq 5f+1$). Two message delays is the [theoretical minimum](https://arxiv.org/abs/2102.07240) for fault-tolerant consensus. Existing protocols, including DAG protocols such as [BlueBottle](https://arxiv.org/abs/2511.15361), reach it only for designated leaders (or anchors). Multimmit extends it to every honest producer chain at once without giving up concurrent dissemination: the best of both worlds.

## The Ride to the Leader

Consider a typical consensus protocol with one proposer at a time and [Simplex](https://eprint.iacr.org/2023/463)-style notarize and finalize rounds. A transaction travels from the user to an API node, is forwarded to a leader that is ready to propose, and is broadcast in the leader's block. 

```{=html}
<style>
  .cw-loop {
    aspect-ratio: 1024 / 464;
    margin: 28px 0 6px;
  }

  .cw-loop-dag {
    aspect-ratio: 1024 / 424;
  }

  .cw-loop-cadence {
    aspect-ratio: 1024 / 320;
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
<div id="multimmit-fig-simplex" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of a single-proposer protocol. A transaction travels from the user to an API node, is forwarded to a leader that is ready to propose, and is broadcast in the leader's block. Two rounds of voting follow. Under this favorable alignment, finality lands three message delays after the block broadcast and five after submission. An arbitrary arrival may wait up to two additional message delays for the leader's next proposal.">
  <noscript>This figure animates a transaction's path through a single-proposer protocol: user to API node, API node to a leader that is ready to propose, then the leader's block broadcast followed by notarize and finalize vote rounds. Under this favorable alignment, the transaction spends 2δ reaching the block that carries it, then 3δ more reaching finality. An arbitrary arrival may wait up to another 2δ for the leader's next proposal.</noscript>
</div>
<script type="module" src="multimmit.loops.js"></script>
```

::: {.image-caption}
Figure 1: A transaction's path through a single-proposer protocol, measured in message delays ($\delta$) since submission. Figures 1, 3, 5, and 6 use the same axis and omit the wait for the next proposal or producer block, which Figure 2 draws. Here, the transaction reaches the leader just as it is ready to propose.
:::

From the "block" marker (when the leader's block is broadcast), finality takes two rounds of voting (or one round when $n \geq 5f+1$). The user's clock, however, started at submission. The transaction spends $\delta$ reaching an API node and another $\delta$ reaching the leader, where Figure 1 had it arrive exactly as the next block went out.

Blocks are emitted when the leader is ready to propose, so the same two hops can just as easily land the moment after one, leaving the transaction to wait out the rest of the interval: as long as $2\delta$, and $\delta$ on average (a shorter interval between blocks shrinks both numbers, which is why [Minimmit](https://arxiv.org/abs/2508.10862) optimizes for view latency).

```{=html}
<div id="multimmit-fig-cadence" class="cw-loop cw-loop-cadence" role="img" aria-label="Animated diagram of arrival timing against a block schedule. Three rows, user, API node and leader, on the same axis as Figure 1. The leader produces a block every two message delays, drawn as red squares. Transaction A travels user to API node to leader and reaches the leader exactly as a block is produced, so it waits nothing. Transaction B, submitted later in the cycle, takes the same two hops but lands just after a block, and a red arrow shows it waiting almost two message delays for the next one.">
  <noscript>This figure replays Figure 1's two inbound hops for two submissions against a leader producing a block every 2δ. Transaction A reaches the leader exactly as a block is produced and waits nothing. Transaction B takes the same 2δ on the wire, lands just after a block, and waits almost 2δ for the next. Averaged over arrival times, the wait is δ.</noscript>
</div>
```

::: {.image-caption}
Figure 2: The same inbound hops as Figure 1, drawn on the same axis, for two submissions. Transaction A is Figure 1's: it reaches the leader exactly as a block goes out. Transaction B spends the same $2\delta$ on the wire but lands just after a block and waits almost the full interval for the next one. Nothing about the network changed. Only where the submission fell in the leader's schedule.
:::

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
Figure 3: Producer lanes with certified tips, using the same Simplex-style two-round consensus as Figure 1. Like Autobahn's fast path, finality takes three message delays after the proposal. The transaction batch (green) crosses the network once. Its PoA arrives two message delays after the batch does, after which the leader's block may reference it. The leader block remains red but now contains only references.
:::

Why not reference blocks before they are certified? [Raptr](https://arxiv.org/abs/2504.18649) avoids this certificate round trip by having voters signal the longest prefix of a proposal for which they hold data. The protocol then finalizes the prefix supported by a quorum. One missing batch, however, spoils everything after it. Even if all later batches are available, they cannot finalize. By taking turns, $k$ faulty producers can deny the fast path for $k$ consecutive proposals.

Raptr uses reputation to limit this attack. Voters blame the authors of missing batches, and a producer blamed by $f+1$ validators is restricted to certified references. This only helps after the producer has spoiled a proposal. Any policy that eventually readmits slow-but-honest producers also gives a faulty producer another chance to spoil.

```{=html}
<div id="multimmit-fig-spoiling" class="cw-loop cw-loop-spoiling" role="img" aria-label="Animated diagram of easy spoiling in Raptr. The leader block is drawn as a red container holding one flat sequence of six batches from six producers, P1 through P6. Producer P2 withholds batch 2, shown as a dashed hole. Votes arrive as dots, and nearly every vote supports only prefix 1 because it lacks batch 2, with a single vote reaching prefix 6. The proposal finalizes prefix 1 in gold, and batches 3 through 6 dim to gray: available, yet stranded behind the hole.">
  <noscript>This figure animates easy spoiling: a Raptr leader block carries one flat sequence of six batches from six producers, producer P2 withholds batch 2, so nearly every vote supports only prefix 1. The proposal finalizes prefix 1, stranding batches 3-6 even though their data is fully available.</noscript>
</div>
```

::: {.image-caption}
Figure 4: Easy spoiling. A Raptr leader block carries one sequence of batches from many producers, and each voter supports the longest prefix whose data it holds. When P2 withholds its batch, almost every vote stops at the gap. The proposal finalizes prefix 1 even though the batches from P3 through P6 are available. These batches eventually land through the certified slow path. Multimmit votes (Figure 7) report a position for each chain, so a withheld block only lowers the position reported for its own chain.
:::

[Mysticeti](https://arxiv.org/abs/2310.14821) makes the same tradeoff for a DAG by referencing uncertified vertices. Dropping just 1% of egress traffic at 5 of 100 validators has been [observed](https://arxiv.org/abs/2405.20488) to increase its median latency by an order of magnitude at moderate load. DAG deployments use reputation for the same reason and have scored anchors (their leader equivalents) since [Shoal](https://arxiv.org/abs/2306.03058). We return to DAGs below.

*Erasure coding takes a different approach: keep the leader on the data path, but send each validator a smaller fragment of each block. A stable leader can then pipeline proposals without gaps between them. Together, these techniques let a leader-based protocol approach line-rate throughput. The tradeoff is that every transaction must still reach that leader before dissemination begins, and the leader can censor transactions throughout its tenure. We explain the coding in [Deliver Us in Pieces](/blogs/coding) and establish its limits in [The Carnot Bound](/blogs/carnot-bound).*

## Multimmit: Checkpoint First, Certify in the Background

Multimmit keeps producer lanes, each a chain as in Autobahn. Every producer signs its own sequence of transaction blocks, with each block referencing its parent by hash. DA-votes and PoAs still form for every block, as in Figure 3, but consensus does not wait for them. A producer may run up to $d$ blocks ahead of its last certified block, leaving a short uncertified tail while everything below it remains recoverable.

Multimmit is designed around one rule: **a faulty participant other than the leader should only be able to significantly delay the finalization of blocks in its own chain**. Its votes have two parts, proposal-relative positions and extensions.

*Proposal-relative voting.* The leader *checkpoints* one tip for every chain, whether it is certified or not. Each reference costs one hash. A validator does not fetch missing blocks. Its vote reports how far it can support each chain in the proposal (the blocks it holds and has DA-voted). A chain finalizes through the highest position supported by $3f+1$ votes, and the next leader must extend the highest position supported by $f+1$ votes. If a producer withholds a block, only its own reported position falls. Other chains do not wait or fetch, and the proposal is not spoiled. Supporting every proposed tip takes constant space. Lower positions are encoded only as deviations from full support.

```{=html}
<div id="multimmit-fig-checkpoint" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's checkpoint path. The API node broadcasts a transaction block, the leader references it in the next leader block before any certificate forms, and one round of votes finalizes it three message delays after the block broadcast, four after submission. Dashed markers show where Figures 1 and 3 finalized on the same axis.">
  <noscript>This figure animates Multimmit's checkpoint path: the leader block references the uncertified transaction block and one vote round finalizes it at block + 3δ, while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 5: Transaction block $b$ (green, like the batch in Figure 3) reaches the leader before its proposal and is checkpointed before a PoA forms. Minimmit's single voting round finalizes $b$ $3\delta$ after its broadcast. DA-votes and the PoA (faint arrows) form in the background. The dashed markers show the finality times from Figures 1 and 3. No transaction data passes through the leader.
:::

*Extension votes.* A vote may also attest to as many as $e$ fresh blocks *beyond* the proposed tips, anchored at the voter's reported position. A block that misses the leader's proposal (or is censored) can still finalize in the same view if it reaches voters before they vote. A faulty participant can fill a proposal or vote with junk or stale entries, but each extension is anchored at its own voter's reported position, so correct voters can always attach recent blocks. A leader cannot finalize its own block while excluding a well-disseminated honest block. It must settle that block's membership in the ledger or prevent the entire view from finalizing.

```{=html}
<div id="multimmit-fig-extend" class="cw-loop cw-loop-consensus" role="img" aria-label="Animated sequence diagram of Multimmit's extension path. The transaction block and the leader block cross on the wire, so the leader block cannot reference it. Voters attest the block in their votes anyway, finalizing it two message delays after the block broadcast, three after submission. Dashed markers show where the earlier figures finalized on the same axis.">
  <noscript>This figure animates Multimmit's extension path: the transaction block misses the leader block but reaches the voters, whose extension votes attest it directly, finalizing at block + 2δ while DA-votes and the PoA form in the background.</noscript>
</div>
```

::: {.image-caption}
Figure 6: Transaction block $b$ crosses the leader block on the wire and misses the proposal, but reaches validators before they vote. Extension votes attest $b$ directly, finalizing it $2\delta$ after its broadcast. Certification continues in the background (faint arrows) and finishes after $b$ has already finalized.
:::

From the user's perspective, both paths are simple: submit to an API node (a producer with no weight in consensus), let its next block carry the transaction to every validator, and wait one round of votes for finality. The producer can pre-confirm the transaction as soon as it arrives, potentially before it could reach a leader an ocean away. Nothing must reach the leader before dissemination begins. Including the wait for the next vote event, a block sent at time $t$ can finalize at $t+2\delta$. 

How does one round of votes produce a single ordering? Each Multimmit vote carries an independent position for every chain. Voters do not vote on how blocks from different chains are interleaved. That ordering is computed afterwards from the finalized tips, which prevents a gap in one chain from limiting any other chain's finalization.

An L-QC (a quorum certificate on the leader block) aggregates any $n-f$ votes for it. For each chain, sort the positions reported by those votes. Discarding the top $3f$ positions gives the finalized tip. Discarding only the top $f$ gives the tip that the next leader must extend. Quorum intersection ensures that the extend tip derived from any L-QC is at least as high as the tip finalized by any other L-QC for the same view. After applying these rules independently to every chain, the finalized blocks enter the log in a fixed sweep.

```{=html}
<div id="multimmit-fig-certificate" class="cw-loop cw-loop-certificate" role="img" aria-label="Animated diagram of Multimmit's certificate rules, drawn at n equals 11 and f equals 2. Left: the leader block is drawn as a red container holding one compact coordinate row per chain, chains 1 through 4, each a gray previous tip followed by as many green proposed entries as the leader has seen for that chain, and chain 1's coordinate is zoomed below it: blocks 1B through 1E proposed above its previous tip 1A. Nine votes stack as dots above the entries. Discarding the top six votes finalizes 1D in gold, and discarding only the top two marks 1E safe to extend in blue. Right: a four-chain grid where the finalized tips of every chain are stamped into a single order, each chain's first new block before any chain's second, with chain 1's column carrying the same gold 1D and blue 1E as the zoomed coordinate.">
  <noscript>This figure animates the certificate rules at n=11, f=2. The leader block carries one coordinate per chain, and chain 1's coordinate is zoomed: nine votes stack above its proposed entries (1B through 1E, above its previous tip 1A). Dropping the top 3f=6 votes finalizes 1D, and dropping only the top f=2 marks 1E safe to extend. The finalized tips of all chains are then stamped into a single order by a fixed sweep, each chain's first new block before any chain's second.</noscript>
</div>
```

::: {.image-caption}
Figure 7: Converting votes into an ordering at $n=11$, $f=2$. The leader block (left) contains one coordinate for each producer chain. Chain 1 is expanded below it, from the previous tip 1A through proposed blocks 1B-1E. An L-QC contains $n-f=9$ votes, each reporting its highest supported block on every chain. Dropping the top $3f=6$ positions finalizes 1D (gold) with $3f+1=7$ votes. Voters missing newer chain 1 blocks lower only this result. Dropping the top $f=2$ positions gives the safe-to-extend tip 1E (blue), which prevents the next leader from orphaning 1D. These rules run independently for every chain. The resulting tips enter the log (right) in a fixed sweep, with each chain's first new block ordered before any chain's second. Gray cells were ordered previously.
:::

At $n=5f+1$, these thresholds provide three other properties:

- A faulty producer can withhold blocks, equivocate, or disclose blocks selectively, but any resulting delay is confined to its own chain (other chains wait at most one view for their position in the total ordering).
- A leader cannot finalize its own block while censoring someone else's. If a fresh honest block reaches the honest validators before they vote, its membership in the ledger is settled in that view unless the view finalizes nothing.
- Consensus messages stay tens of kilobytes per view when votes agree, independent of transaction volume.

## Why Not a DAG?

DAG-based protocols ([Narwhal](https://arxiv.org/abs/2105.11827), [Bullshark](https://arxiv.org/abs/2201.05677), [Mysticeti](https://arxiv.org/abs/2310.14821)) popularized the idea of having every validator disseminate transactions in parallel. The costs of this approach motivated designs like Autobahn and Raptr. In a DAG, the transaction-carrying structure is also the consensus structure. Every validator's vertex carries transactions and references $n-f$ vertices from the previous round. Consensus determines finality by interpreting this pattern of references.

```{=html}
<div id="multimmit-fig-dagstructure" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG construction. Four validators each emit one vertex per round. As each new round of vertices appears, edges draw back from every vertex to three of the four vertices in the previous round, forming a lattice.">
  <noscript>This figure animates DAG construction: four validators emit one vertex per round, and each new vertex draws reference edges back to n−f (here 3 of 4) vertices of the previous round.</noscript>
</div>
```

::: {.image-caption}
Figure 8: How a DAG mempool is built. Each round, every validator emits a vertex referencing $n-f$ vertices of the previous round. The references are the protocol: they carry availability and voting information, so the ordering logic can read finality out of the lattice.
:::

A reference does not provide finality on its own. The ordering logic designates periodic anchor vertices, and an anchor commits only after later rounds show that enough validators built on top of it. Committing the anchor orders every vertex in its causal history. The remaining vertices wait for a later anchor.

```{=html}
<div id="multimmit-fig-dagfinality" class="cw-loop cw-loop-dagstructure" role="img" aria-label="Animated diagram of DAG finality. Four validators emit one vertex per round. Validator 2's round-r vertex, labeled A, is the anchor. Gold reference edges from round r+1 mark its support, and once round r+2 lands, A and its causal history turn gold, two rounds after A entered the DAG. Every other vertex stays pending until a later anchor commits.">
  <noscript>This figure animates DAG finality: anchor A enters in round r, is referenced by n−f round r+1 vertices, and commits only once round r+2 lands, ordering its causal history with it. Finality arrives two rounds of DAG growth after the vertex itself.</noscript>
</div>
```

::: {.image-caption}
Figure 9: Finality in a Mysticeti-style three-round pattern. Anchor $A$ enters in round $r$, gathers support (gold references) in $r+1$, and commits when round $r+2$ arrives. Its causal history (gold) is ordered with it. In a certified DAG, each round also requires a certificate round trip.
:::

This coupling also controls production. A validator may only create a round-$r+1$ vertex after receiving $n-f$ round-$r$ vertices, so the network produces in lockstep (deployments add round timeouts to keep the DAG well connected). In certified DAGs like Narwhal, a certificate round trip separates each pair of consecutive vertices. Uncertified DAGs like Mysticeti remove that round trip but reintroduce fetching. Because every referenced vertex is a dependency, a validator must fetch a missing vertex before it can process anything built on top of it.

```{=html}
<div id="multimmit-fig-dagfetch" class="cw-loop cw-loop-dagfetch" role="img" aria-label="Animated diagram of a fetch stall in an uncertified DAG with four validators. Validator 3 withholds its round r+1 vertex, shown as a dashed hole, disclosing it only to validator 2, whose round r+2 vertex references it with a red edge. A vertex is unusable until its full ancestry is held, so validators 1 and 4 must fetch the withheld vertex from validator 2 before they can build on validator 2's vertex, and round r+3 starts 1.7 message delays later than the dashed on-time marker.">
  <noscript>This figure animates a fetch stall in an uncertified DAG with four validators: validator 3 withholds its round r+1 vertex from all but validator 2, whose next vertex references it. A vertex is unusable without its full ancestry, so validators 1 and 4 must fetch the withheld vertex before they can build on validator 2's, and round r+3 starts 1.7 message delays late.</noscript>
</div>
```

::: {.image-caption}
Figure 10: The fetch problem. Validator 3 sends its round-$(r+1)$ vertex only to validator 2, whose next vertex references it (red edge). Validators 1 and 4 cannot use validator 2's vertex without its full ancestry, leaving them with only two of the $n-f=3$ round-$(r+2)$ vertices needed to enter round $r+3$. They must fetch the withheld vertex first, delaying the next round for everyone. Larger DAGs can route around an isolated gap, but each gap still puts a fetch on someone's critical path. At real block rates, sustained loss creates gaps in nearly every round (producing the order-of-magnitude slowdown measured above). A Multimmit reference never puts a fetch on a critical path. Voters report how far they can support each chain and vote on schedule.
:::

The coupling also fixes who may produce. A vertex is a vote, so contributing transaction data means being a validator. Multimmit keeps the two structures apart, and a transaction block is never itself the subject of a consensus vote, so a producer does not have to be a validator and a deployment can run a different number of chains than it has voters.

Whether the protocol waits for fetches or certificates, a collective step limits every producer's output. Figure 11 compares that pace with a Multimmit producer paying the same certificate round trips.

```{=html}
<div id="multimmit-fig-dag" class="cw-loop cw-loop-dag" role="img" aria-label="Animated comparison of block production over eight message delays. A DAG producer emits a vertex, waits for a two-delay certificate round trip, and only then emits the next, producing four vertices. A Multimmit producer emits a block every two-thirds of a message delay with certificate round trips overlapping in the background, producing twelve blocks in the same time.">
  <noscript>This figure animates block production over 8δ. The DAG producer waits out a 2δ certificate round trip between consecutive vertices (4 vertices total). The Multimmit producer keeps emitting while certificates form in the background (12 blocks in the same window), constrained only by its pipelining window.</noscript>
</div>
```

::: {.image-caption}
Figure 11: One producer with identical $2\delta$ certificate round trips. The DAG producer waits for the previous round's certificates before creating its next vertex (assuming every other producer's certificate arrives with its votes, since spreading them costs a certified DAG a third delay per round). The Multimmit producer runs as many as $d$ blocks ahead of certification, shown here filling a $d=3$ window under load.
:::

Figure 2 showed the cost of coupling production to consensus: a transaction that misses a proposal waits for the next one, $\delta$ on average when blocks leave every $2\delta$. Multimmit separates block production from that schedule. Each producer controls when a transaction enters its own block, and its chain contains no cross-producer references, so it can run as many as $d$ blocks ahead of certification. Under sustained load, a chain grows by $d$ blocks per certificate round trip instead of one, cutting that wait to $\delta/d$. Producers keep building through leader failures and view changes, and the first successful view checkpoints the backlog.

```{=html}
<div id="multimmit-fig-blip" class="cw-loop cw-loop-dag" role="img" aria-label="Animated diagram of a Multimmit producer through a consensus blip. Two rows: consensus views above, one producer below. The producer emits a block every two-thirds of a message delay for the whole window, with certificate arcs forming behind each block. An early leader block finalizes the first two blocks with gold edges. Then a consensus blip begins, drawn as a shaded band: two views time out, drawn as dashed hollow leader blocks, while the producer keeps emitting and certificates keep forming. When the blip ends, the first successful leader block draws gold edges back to the entire backlog, and two message delays later seven blocks finalize at once.">
  <noscript>This figure animates a consensus blip: two views time out while a Multimmit producer keeps emitting blocks on cadence, certificates forming behind them. The first successful view references the whole backlog, and one round of votes finalizes everything the blip delayed.</noscript>
</div>
```

::: {.image-caption}
Figure 12: Two consensus views time out in the shaded interval. The producer keeps emitting blocks and forming certificates without the leader. The first successful view carries the backlog, and one round of votes finalizes it. Blocks emitted after that proposal wait for the next view.
:::

## Every Producer, Every View

Multimmit runs transaction dissemination and consensus concurrently. Blocks enter the ordering process as soon as they reach validators, consensus votes establish their availability, and a faulty producer only delays its own chain. Submit a transaction to any producer. One round of votes later, it is final.

Checkout the (draft) [specification](https://arxiv.org/abs/2607.21021) for proofs of consistency and liveness. Follow GitHub for an MIT/Apache-2 implementation over the coming weeks.