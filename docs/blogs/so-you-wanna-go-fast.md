---
title: "So you wanna go fast?"
description: "Ordering a few GB/s efficiently on a blockchain is hard. How do we keep up with incoming blocks while leaving room to recover from slowdowns and crashes?"
date: "September 19th, 2026"
published-time: "2026-09-19T00:00:00Z"
modified-time: "2026-09-19T00:00:00Z"
author: "Ben Clabby"
author_twitter: "https://x.com/vex_0x"
url: "https://commonware.xyz/blogs/so-you-wanna-go-fast"
image: "https://commonware.xyz/imgs/so-you-wanna-go-fast.png"
katex: false
---

Ordering a few GB/s efficiently on a blockchain is hard. Keeping up with incoming blocks leaves little room to catch up after a slowdown or crash.

We're building [Multimmit](/blogs/multimmit) to increase throughput by enabling producers to build and broadcast their own chains in parallel. Consensus agrees on references to those chains, leaving each replica to assemble their blocks into the same ordered stream for the application. We'll call that stream the application log. That work belongs to *marshal*, the component between the Multimmit engine and the application. We have to overlap work across the network, disk, and application while keeping the memory used by unfinished work under control.

Multimmit sustains one million 512-byte transactions per second across 50 validators. Median submission-to-finality latency is 400 ms globally and 63 ms in North America. The [results below](#how-fast-does-it-go) show the comparisons and fault scenarios. Getting there takes more than a fast consensus protocol.

Let's follow three producers, Alice, Bob, and Carol. Their blocks might appear in the application log like this:

```{=html}
<link rel="stylesheet" href="so-you-wanna-go-fast.css?v=fc77aa645b03">
<figure class="log-stream" aria-describedby="log-stream-caption">
  <ol role="list">
    <li><span class="log-position">1</span><strong>Alice</strong><span>block 1</span></li>
    <li><span class="log-position">2</span><strong>Bob</strong><span>block 1</span></li>
    <li><span class="log-position">3</span><strong>Carol</strong><span>block 1</span></li>
    <li><span class="log-position">4</span><strong>Alice</strong><span>block 2</span></li>
  </ol>
  <figcaption id="log-stream-caption">Figure 1. Blocks from different producers share one application log. Here, Alice's first block occupies position 1 and her second occupies position 4, with Bob's and Carol's first blocks in between.</figcaption>
</figure>
```

Adding producers increases the work on every replica. If we waited for each block to arrive, reach disk, and finish processing before starting the next, those delays would accumulate while more data arrived. We need to overlap that work, but even listing Alice, Bob, and Carol's entire backlog could exhaust memory. Marshal constructs the log a little at a time.

## Finding the next block

Alice's block arriving first doesn't give it the first position. To produce the same log everywhere, we use consensus to determine how far to include each producer's chain, then visit their blocks in a fixed order.

In this pass, consensus has finalized three blocks from Alice, two from Bob, and three from Carol. We visit each producer's first new block before anyone's second, then continue row by row. After Bob's second block, his portion is finished, so we skip his column on the third row.

```{=html}
<div data-log-figure="order">
  <p class="log-fallback">Three producers advance independently. Once their boundaries are final, a settled pass visits A1, B1, C1, A2, B2, C2, A3, C3. The traversal determines each block's position regardless of when it arrives.</p>
</div>
<script type="module" src="so-you-wanna-go-fast.js"></script>
```

::: {.image-caption}
Figure 2. One settled pass, starting from empty histories. Each row is visited in producer order. Figures number application positions from 1 for readability.
:::

We can skip Bob's column because consensus has settled where his portion ends. Without that boundary, we may have to wait, since another block from Bob could belong before our next output.

One consensus update can cover a long backlog, but we generate positions a batch at a time. We only need to track our progress through each producer's chain, so the bookkeeping grows with the number of producers rather than the number of blocks waiting. That progress also tells us which blocks we've already included when the next update arrives.

We record each position in a small on-disk index. Each entry identifies a block through its authenticated header, without loading its *body*, which holds the application data. Assigning a position therefore doesn't require reading the large part of the block.

## Which of Bob's blocks?

A faulty Bob could broadcast two different versions of `B1`. Only one can obtain the votes needed to certify its validity and availability, but we have to check and durably store a candidate before voting for it. We can't wait for certification to decide what to store. If storing one overwrote the other, we could lose the block that consensus eventually selects.

We retain the candidates separately and use their hashes to distinguish them. Before including Bob's chosen block, we also check that it connects to the history we've already emitted. Finding a block at the right height isn't enough.

Consensus history can contain competing records too. Our `MultiArchive` keeps these candidates separately, while keeping the common case cheap. Its index stores one candidate's location directly and allocates a list only when another appears. We rebuild the index after a restart from small records containing keys and locations. That avoids scanning all the archived values before we can get back to work.

Once consensus identifies the branch, we know exactly which of Bob's blocks belongs in the log. We'll use `B1` for that block in the rest of the example, even if its body hasn't arrived yet.

## Waiting for Bob

Now `A1` is ready and Carol's broadcast has delivered `C1`, but Bob's `B1` hasn't arrived yet. We can store `C1` while we wait for Bob, along with later blocks as they arrive. We can't deliver `C1` ahead of `B1`, though, because the application would see a different log on a replica that received Bob's data first.

We advance through consecutive positions whose bodies are safely on disk. Once `B1` is durable too, we can advance through both `B1` and `C1`, using the work we completed while waiting for Bob's broadcast. We'll call this consecutive stretch the *ready prefix*.

If Bob takes too long, later blocks could fill memory while waiting for their turn. We prepare a limited number of positions at a time and cap how many bytes that work can hold. This window includes both work in progress and bodies that are ready. When it fills, we stop preparing later positions until the gap closes. Broadcasts continue to arrive independently of this preparation window.

The output index refers back to these stored bodies, so recording their positions only requires writing the small index rows. Delivery uses cached bodies when they're available and reads from disk when they aren't.

## Saving the batch

Once Bob's block is durable, we can save the positions through Carol's block together. Their bodies are already stored, so only the small index rows remain. Batching those rows lets us share the cost of synchronizing them to disk.

We synchronize the output index and its supporting consensus history concurrently. Once they finish, we save a checkpoint recording how far we've constructed the log. After that checkpoint reaches durable storage, the batch is available for delivery.

```{=html}
<div data-log-figure="fetch">
  <p class="log-fallback">The order is already determined: A1, B1, C1, A2, B2, C2. While B1 is missing, C1, B2, and C2 can arrive and reach durable custody, but only A1 is in the ready prefix. Filling the gap lets the contiguous prefix advance.</p>
</div>
```

::: {.image-caption}
Figure 3. One publication batch. Broadcast bodies arrive and reach durable storage in a different order from their assigned positions. The index and history become durable before the checkpoint makes the batch available to delivery.
:::

After a crash, we resume from the previous checkpoint if the new one didn't reach disk, repeating the unfinished work. If the new checkpoint did reach disk, both the rows it refers to and their bodies are already durable. We can trust the checkpoint without reconstructing the batch to find out whether it survived.

That's why a batch's checkpoint sync waits for its index and history to sync. Starting them together could leave us with a checkpoint pointing to rows that were lost in the crash. We can still overlap adjacent batches, synchronizing the next batch's index and history while the current batch's checkpoint sync is running.

```{=html}
<figure class="log-pipeline" aria-describedby="log-pipeline-caption">
  <div class="log-pipeline-time" aria-hidden="true">Time →</div>
  <div class="log-pipeline-row">
    <strong>Batch A</strong>
    <span class="log-pipeline-data">Sync index<br>and history</span>
    <span class="log-pipeline-checkpoint">Sync<br>checkpoint</span>
  </div>
  <div class="log-pipeline-row">
    <strong>Batch B</strong>
    <span class="log-pipeline-data" style="grid-column:3">Sync index<br>and history</span>
    <span class="log-pipeline-checkpoint">Sync<br>checkpoint</span>
  </div>
  <figcaption id="log-pipeline-caption">Figure 4. Batch B can synchronize its index and history while batch A saves its checkpoint. Each checkpoint waits for its own batch's data to be durable. Durations are schematic.</figcaption>
</figure>
```

## What did the application finish?

The checkpoint now tells us which blocks we can deliver. It doesn't tell us whether the application has finished processing them. If we used it as our restart position, we could skip work the application never completed.

Waiting for an acknowledgement before delivering the next block would serialize application processing too. We allow several blocks to be in flight and track their acknowledgements separately. After delivering positions 1 through 6, we might receive acknowledgements for 1, 2, 4, and 5. We can save the application's progress only through 2, since position 3 is still outstanding. Acknowledgements for 4 and 5 stay in memory until that gap closes.

```{=html}
<div data-log-figure="recovery">
  <p class="log-fallback">Positions 1 through 6 are committed and delivered. The application acknowledges 1, 2, 4, and 5, but the durable acknowledgement cursor reaches only 2. After a crash, delivery starts again at 3, preserving the same positions and order. Positions 4 and 5 may be delivered again.</p>
</div>
```

::: {.image-caption}
Figure 5. After the acknowledgement cursor is durable through position 2, a crash leaves delivery able to resume at 3. Acknowledgements for 4 and 5 that were only held in memory must be obtained again.
:::

When acknowledgement 3 arrives, we can save progress through 5 with one write. A crash before that write becomes durable will cause us to deliver those blocks again, so the application must tolerate replay of completed work.

Keeping application progress separate from log construction lets both proceed independently after a restart. We can deliver already recorded positions while reconstructing newer ones, without asking consensus to decide the old history again.

## Catching up while producers keep going

Now suppose the replica was offline for a minute. At a production rate of 4 GB/s of finalized block data, it has missed 240 GB of blocks, with more arriving throughout recovery. That's application data alone, before network and storage overhead. The backlog can be much larger than memory, so we work through it using the same bounded window.

Before fetching that data, we need to know which blocks belong in the log. Consensus has already reconstructed parts of the selected producer histories while checking them. It can pass those block references to marshal, which can then request the missing bodies without discovering the same history again.

For a known stretch of Alice's chain, marshal can request several missing bodies together and consume them from oldest to newest. A slow response doesn't prevent the other requests from making progress. As each block is consumed, its slot becomes available for another request.

```{=html}
<figure class="log-forward" aria-describedby="log-forward-caption">
  <div data-log-figure="forward">
    <p class="log-fallback">Consensus hands marshal the authenticated references for Alice's blocks A1 through A6, then continues independently. Marshal requests bodies A1 through A4 concurrently within a four-slot window. A3 arrives before A1, and A4 before A2, but marshal consumes A1, A2, A3, and A4 in order. Consuming A1 frees a slot for A5, and consuming A2 frees a slot for A6.</p>
  </div>
  <figcaption id="log-forward-caption">Figure 6. Consensus shares known commitments. Marshal acquires their bodies concurrently and consumes them in chain order. Outstanding requests and waiting bodies share the same bound. The four-slot window is schematic.</figcaption>
</figure>
```

A replica recovering old history may be missing some of those references too. A certificate identifying the latest block doesn't contain every preceding header. To fill a gap, we follow the parent hash in each header back to history we already know, checking each response along the way. Once we know which blocks are missing, we can acquire their bodies using the same forward path.

```{=html}
<figure class="log-forward" aria-describedby="log-repair-caption">
  <div data-log-figure="repair">
    <p class="log-fallback">Marshal knows Alice's headers A2 and A5, but lacks A3 and A4. It requests A4's header from a peer using the exact parent commitment in A5, verifies the response, and repeats with A4's parent to obtain A3. A3's parent must match the known A2 anchor. Marshal can then acquire bodies A3 and A4 concurrently and consume them in order, even if A4 arrives first.</p>
  </div>
  <figcaption id="log-repair-caption">Figure 7. Repair follows authenticated parent commitments backward until the missing history joins a known anchor. These requests recover headers. Once the block identities are known, bounded body acquisition can proceed forward.</figcaption>
</figure>
```

Recovery still checks the recorded history, but it doesn't repeat the consensus rounds that finalized it. We reuse work where we can, repair what's missing, and apply the same batching and concurrency as we do to new blocks. Historical reads have their own cache budget so they don't evict newly arrived bodies that current delivery could reuse.

To catch up, we have to deliver block data through this whole path faster than the chain produces it, while also receiving new blocks. A fast network transfer alone won't do that if disk writes or application processing can't keep pace. We need capacity across all of them.

## Where the time goes

As the chain produces more data, each replica has more to receive, store, and deliver. Larger batches reduce synchronization costs, but waiting to fill them can delay delivery. More concurrent I/O can keep the disk busy while holding more buffers in memory. We need to understand which cost limits sustained throughput, then leave enough network, disk, and processing capacity for a lagging replica to catch up as well.

[tracer](https://github.com/clabby/tracer) lets us study these tradeoffs across deployed clusters by aggregating traces from every replica. Comparing the same consensus round on a shared timeline reveals which replicas lag and which phases account for the delay. Diffing round traces before and after a change shows whether speeding up one operation made another wait longer.

```{=html}
<figure aria-describedby="tracer-caption">
  <img src="/imgs/tracer.png" alt="Tracer showing consensus-round spans from multiple validators on a shared timeline." />
  <figcaption id="tracer-caption">
    Figure 8. A visualized aggregation of consensus round traces across several instances using the tracer tool.
  </figcaption>
</figure>
```

Traces include time spent waiting for disk, so we use [samply](https://github.com/mstange/samply) alongside them to find where the CPU is busy. Its profiles show time spent decoding records, copying buffers, or maintaining indexes. Combined with resource metrics, these can lead us into the codec, archive, and runtime primitives beneath marshal, where improvements benefit other components too.

## How fast does it go?

Batching writes, overlapping independent work, and avoiding repeated reads give us more room to handle incoming blocks. To see how that work adds up, we've been measuring Multimmit in two deployments of 50 validators, spread across either 13 regions around the world or three regions in North America.

The charts compare Multimmit with [BlueBottle](https://arxiv.org/abs/2511.15361) and [Raptr](https://arxiv.org/abs/2504.18649), running consensus-only workloads on the same testbeds. Each validator runs on an AWS `c8g.12xlarge` instance with 48 vCPUs and 96 GiB of RAM, processing synthetic 512-byte transactions. The measured work includes block construction and dissemination, signing and verification of consensus messages, and disk writes.

The protocols make different fault-tolerance tradeoffs. Raptr uses the `3f + 1` model, tolerating up to 16 Byzantine validators in this 50-validator testbed. Multimmit and BlueBottle's core use `5f + 1`, trading a lower fault budget of nine validators for shorter finality paths. Their respective quorums are 34 and 41 validators, but quorum size alone does not determine latency.

The load generator assigns transactions submission times to maintain the requested rate. **Submission-to-finality latency** starts at that assigned time and stops when the validator that produced the transaction's block first records its finality. If the implementation falls behind and admits a transaction late, that waiting time still counts, along with block construction, signing, and consensus.

A coordinated upgrade or a fault can stop every validator at once. To recover safely from that shutdown, Multimmit waits for block data and signing decisions to reach durable storage before making the corresponding availability promises or releasing signatures. Blocking on fsync this way isn't standard practice in consensus PoCs (as it provides stronger guarantees than a standard ≤ f crashed validator assumption), so the comparison disables it across all three implementations while retaining disk writes. The **Fsync on** toggle shows Multimmit's results with those durability barriers enabled.

In healthy runs with fsync disabled, increasing the offered load from 50,000 to one million transactions per second moves Multimmit's median submission-to-finality latency from 389 to 400 ms globally and from 52 to 63 ms in North America.

Healthy runs show how much work the system can handle when every validator responds. Production networks also have crashed nodes and missing messages, and the remaining validators must keep making progress while new transactions arrive. The fault scenarios test whether throughput holds up and how much longer transactions wait for finality under those conditions. Each run either stops one or nine validators, or drops 0.1% of complete application messages at the receiver, after decoding and before protocol delivery. Dropping messages there tests the protocol's recovery behavior because TCP cannot retransmit those injected drops.

```{=html}
<figure class="mm-results" aria-describedby="mm-results-caption">
  <div data-mm-results="global" class="mm-result-panel">
    <h3>Global</h3>
    <p>13 regions · 50 validators</p>
    <p class="mm-result-fallback">At one million offered transactions per second, median submission-to-finality latency is 400 ms and P99 is 635 ms.</p>
  </div>
  <div data-mm-results="na" class="mm-result-panel">
    <h3>North America</h3>
    <p>Virginia · Ohio · Canada · 50 validators</p>
    <p class="mm-result-fallback">At one million offered transactions per second, median submission-to-finality latency is 63 ms and P99 is 100 ms.</p>
  </div>
  <figcaption id="mm-results-caption">Figure 9. Latency from the submission time assigned by the load generator to finality recorded by the producing validator, measured on the same testbeds. Use the controls inside each chart to select its scenario, enable fsync, or switch between median and P99. Median plots include P25–P75 range bars. Fsync off compares all three implementations. Fsync on shows only Multimmit. Each point is one 120-second submission cohort after a 120-second warmup. Throughput counts transactions finalized during the measurement window. Hover, tap, or focus a load point to compare the measurements. Latency uses a logarithmic scale, fitted to each chart. Throughput uses a linear scale.</figcaption>
</figure>
<script type="module" src="so-you-wanna-go-fast.results.js?v=4e2bc62ff535"></script>
```

The [measurement dataset](/artifacts/multimmit-measurements.json.zst) contains the throughput, latency, and traffic measurements plotted here.

BlueBottle and Raptr's sweeps stop at 500,000 offered transactions per second because neither implementation achieved a steady result above that rate in our tests. BlueBottle exhausted memory in the global one-million-tx/s test. With nine crashes at 500,000 tx/s globally, additional validators exhausted memory, leaving fewer live validators than quorum. With 0.1% message loss, the 250,000 and 500,000 tx/s runs in both deployments failed to sustain the offered load and finalize the full submission cohort. The Raptr measurements include a small [payload-retention fix](https://github.com/clabby/aptos-core/commit/cffe99b0f3b9def4693a6e7893056ed411b20229) needed to complete the measurements. Raptr's backlog kept growing in the healthy global runs at 250,000 and 500,000 tx/s, preventing us from capturing a steady-state result. Those rates are excluded from its global results, and the corresponding fault scenarios were not run. In North America, its nine-crash runs at those rates did not sustain the required throughput, and the 500,000 tx/s run also failed to finalize the full submission cohort. If anyone is interested in further updating these binaries to run at this load for a complete comparison, please reach out!

We're working to bring Multimmit to production in the coming months. These measurements help ensure we're on the right track on such a large change.

The latest version of the Multimmit paper, including the experimental results, is available [here](/artifacts/multimmit.pdf).
