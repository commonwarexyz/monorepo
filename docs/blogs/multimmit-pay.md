---
title: "The Payment Heard Round the World"
description: "A payee can verify that a Multimmit payment is final before its place in the log is known. Across thirteen regions, producers had that proof in a median of 241ms at 100,000 transactions per second."
date: "November 23rd, 2026"
published-time: "2026-11-23T00:00:00Z"
modified-time: "2026-11-23T00:00:00Z"
author: "Andrew Lewis-Pye"
author_twitter: "https://x.com/AndrewLewisPye"
url: "https://commonware.xyz/blogs/multimmit-pay"
image: "https://commonware.xyz/imgs/multimmit-pay.png"
katex: true
---

When we introduced [Multimmit](/blogs/multimmit), the claim was that a total ordering could be both fast and robust: every validator disseminates its own chain of transaction blocks, and a single round of consensus votes places the transaction blocks of all chains in one total ordering. The measurements in the [paper](https://arxiv.org/abs/2607.21021v6) back up this claim. In our experiments, a global deployment with fifty validators placed ordinary transactions in the total ordering with a median of 383ms from submission at 100,000 tx/s, rising only to 411ms at 1M tx/s. With the deployment confined to North America, where round trips are much shorter, the medians were 54ms and 76ms.

The latest version of the paper adds even faster finality for payments, meaning transfers between accounts. For these, Multimmit now issues a *receipt*: a compact, transferable proof that the payment is irreversible. In the good case, the receipt exists roughly two message delays after the payment's transaction block is sent, with no leader required to reference the block, and potentially before any view of consensus has voted to include it. At 100,000 tx/s, the median time from scheduled submission to a receipt at the producer is 241ms globally and 37ms in North America. That is well ahead of the ordering itself (596ms and 88ms for these payment chains), and a fraction of the time to finality in the [other systems we measured](https://arxiv.org/html/2607.21021v6#S8.SS2), where a payment is final only once consensus has ordered it.

This post explains how the receipt works and exactly what it guarantees. A receipt costs the protocol almost nothing it wasn't already doing, and gives strong guarantees: no conflicting payment ever executes, and the payment enters the total ordering whatever leaders and producers do, even across committee changes.

```{=html}
<style>
  .mm-pay-timeline { aspect-ratio: 1024 / 408; margin: 28px 0 6px; }
  @media (max-width: 600px) {
    .mm-pay-timeline text { font-size: clamp(18px, calc(42px - 4vw), 27px); }
    .mm-pay-timeline text[text-anchor="middle"] { transform: translateY(6px); }
  }
</style>
<noscript>
  <style>
    .mm-pay-timeline { aspect-ratio: auto; border-left: 2px solid #d9251c; color: gray; padding-left: 12px; }
  </style>
</noscript>
<div id="multimmit-pay-receipt" class="mm-pay-timeline" role="img" aria-label="A producer broadcasts a payment block at time zero. Validators check its payments and return acknowledgments. At two message delays the producer holds enough acknowledgments for a receipt. Sending the certificate to a ready leader, proposing it, and voting places the block at five delays in this example.">
  <noscript>The validators receive the payment block at one message delay and the producer receives their acknowledgments at two. The receipt is ready then. A certificate reaches the leader at three delays; the proposal and votes place the block at five.</noscript>
</div>
<script type="module" src="multimmit.loops.js"></script>
```

::: {.image-caption}
Figure 1: A payment's transaction block, in the good case. The producer disseminates the transaction block; validators check the payments and send their acknowledgments (DA-votes) one message delay later. At $2\delta$ the producer holds the receipt: the payment is final. Here the availability certificate reaches a leader ready to propose at $3\delta$, and the proposal and votes place the block at $5\delta$.
:::

## Multimmit in sixty seconds

For a full explanation of how Multimmit works prior to the addition of payment receipts, read the [earlier post](/blogs/multimmit) or the [paper](https://arxiv.org/abs/2607.21021v6). Here, we give a brief summary.

The basic setup is that every validator produces its own chain of transaction blocks and disseminates each block as it is produced. The work of sending transaction blocks is therefore spread across the network, rather than the leader being a bottleneck. Dissemination already involves a round trip: validators respond to each transaction block with *availability acknowledgments* (DA-votes), and enough acknowledgments form a certificate that the block's data is recoverable.

Meanwhile, consensus runs alongside. The leader of each view issues a *leader proposal*, naming a tip (latest transaction block) for every chain, certified or not, and each validator replies with a single vote reporting, per chain, how far up the chain it can endorse. One round of voting finalises the leader proposal, under the assumption $n \geq 5f+1$ ($n$ validators, at most $f$ faulty). Nobody fetches missing data on the critical path to a consensus vote, since voters report what they hold, which is why 0.1% message loss leaves Multimmit's latency essentially unchanged while inflating one uncertified design's latency by orders of magnitude in North America. Votes may also *extend* beyond the proposed tips, so a leader cannot censor a fresh, well-circulated block from an honest producer. If the block is within extension range and all correct voters acknowledge it before voting in a view that finalises, it enters the ordering by the next finalised leader proposal, whatever the leader proposes.

Two per-chain parameters control how optimistic the ordering is. The *proposal window* $d$ bounds how many transaction blocks beyond its base (an inherited tip or a newer certified block) a leader proposal may reference in that chain, and the *extension allowance* $e$ bounds how many fresh transaction blocks a vote may endorse beyond the position the voter supports. Generous windows are what let ordinary transactions place in the total ordering about three message delays after dissemination when a block catches the next proposal (two in the best case, through extension votes), without waiting for certification. Keep $d$ and $e$ in mind: the payment design is, almost entirely, a choice of their values.

```{=html}
<img src="/imgs/multimmit-pay-chains.svg" style="display: block; margin: 20px auto;" alt="Three producers build separate chains. A leader names one tip per chain. On the first chain its tip is beyond the certified prefix; on the second a validator can endorse a fresh block beyond the named tip; on the third the named tip is already certified.">
```

::: {.image-caption}
Figure 2: The structure. Each producer appends transaction blocks to its own chain and disseminates them, with acknowledgments certifying availability in the background. A leader proposal names a tip for every chain, and one round of votes places the endorsed tips and their ancestors in the total ordering. The proposal window $d$ bounds how far a named tip may sit beyond its base (here, the last certified block). On chain 2, a voter that endorses the named tip may extend it by up to $e$ fresh blocks.
:::

```{=html}
<div id="multimmit-pay-order" class="mm-pay-timeline" role="img" aria-label="An ordinary producer broadcasts a block. One delay later the leader proposes its uncertified tip while availability acknowledgments return to the producer. Validators receive the proposal and vote. Placement takes three delays from the block broadcast in this example.">
  <noscript>The block reaches a ready leader at one delay. The leader proposes it without waiting for certification; acknowledgments go back to the producer in parallel. The proposal and one round of votes place the block at three delays.</noscript>
</div>
```

::: {.image-caption}
Figure 3: The main protocol, before payments: an ordinary transaction block in the good case. Here the next leader is ready to propose and references the fresh, uncertified transaction block at once ($d>0$), and one round of votes places it in the total ordering around $3\delta$ after dissemination. Acknowledgments return in parallel, certifying the block's availability in the background. In the best case, a transaction block that reaches the validators before they vote is placed even earlier, at $2\delta$, through extension votes, with no leader proposal referencing it at all.
:::

## Payments don't need ordering

Producing a total ordering costs latency. However, while general transactions (arbitrary state machines, contracts reading shared state) require the ordering, a payment does not. Two payments *conflict* only if they debit the same account at the same sequence number. If no payment conflicting with yours can ever execute, and yours eventually will, then you have been paid; whether unrelated transactions land before or after it changes nothing. The observation is not new: [FastPay](https://arxiv.org/abs/2003.11506) and the consensusless designs that followed it finalise payments with a single quorum round trip and no consensus at all. However, those systems give up the total ordering entirely. Multimmit keeps the total ordering, since this is required for general transactions and (even for payments) also facilitates epoch changes. The question is whether payments can have the round-trip guarantee described above and still take their place in the ordering, on the same validators, with the same votes.

We show that one simple rule makes payment conflicts locally checkable: in each epoch, every account has a single *home* chain, the one chain whose blocks may debit it. All of an account's outgoing payments in an epoch sit on one chain, so they can be validated in chain order, before and independently of the block's placement in the total ordering. Credits arriving from other chains are counted only once ordered and executed. An account's owner can move its home to another chain with a signed instruction, placeable on any chain so no account is captive to its home. The move takes effect two epochs after it is ordered.

## The receipt

A *payment chain* is a chain that carries only payments (and home-moves), configured with $d=0$ and $e=0$ (other chains can set these parameters separately). The consequences: a leader proposal may reference a payment chain only at a certified transaction block, and no vote extends past that. The payment chain thereby gives up optimistic ordering, but achieves something stronger.

Acknowledgments on a payment chain attest more than availability. Before acknowledging a payment block, a validator checks every payment in it (signature, home, consecutive sequence numbers, sufficient funds) against the executed state of a committed prefix that the block itself names, advanced through the block's own ancestors. The validator then signs the whole block or nothing. (Production still runs ahead within its own availability window, so setting $d=0$ does not limit production to one block per round trip.)

A **receipt** is then: the signed payment, the signed header of its block, a Merkle proof of inclusion, and acknowledgments from $n-f$ validators (41 of 50 in our experiments; $n-2f=32$ suffice for availability), aggregated into one signature with a bitmap of signers. During an epoch handoff, early acknowledgments count only with proof that the new committee adopted the log they depend on. Anyone can verify the receipt with the epoch's committee keys and quorum size (no account state and no chain download required). In the good case, the producer holds it roughly $2\delta$ after disseminating the block (the ordinary dissemination round trip). Receipts are free in the sense that the protocol already runs this round trip for every block. Payment chains just ask more of the acknowledgments.

Why do these acknowledgments make the payment irreversible? There are two possible issues. The first is a conflicting payment gathering a quorum of its own. This cannot happen: on the adopted history, each correct validator acknowledges at most one transaction block per chain per height. To acknowledge a later block it must follow a certified base and have acknowledged the intervening ancestors. Together with quorum overlap, these rules keep all certifiable blocks on one branch, so two incompatible blocks can never both be receipted. With the validity checks above, it follows that a receipted block's payments can never be contradicted by payments anywhere else, because all of an account's debits sit on its home chain. The second is the ordering routing around the receipt, placing some competing branch of the chain. This cannot happen either: with $d=e=0$, ordinary views place only certified tips and their ancestors on a payment chain, all of them on the receipted block's own branch. When an epoch ends, validators stop acknowledging and *report* what they acknowledged. Any closing quorum's reports provably cover every receipted block, which is how a receipted block enters the log even if its certificate was never shown to a single other party.

## What a receipt guarantees

If you hold a receipt for a payment, the protocol makes three guarantees, good against any $f$ faults, the leader and the producer included:

1. **No conflicting payment ever executes.** This is true for the present and all future epochs, whatever any leader proposes and whatever the producer does next, even if it equivocates, crashes, or withholds everything it holds.
2. **Inclusion is already settled.** The payment's transaction block enters the total ordering by the close of its epoch, even if the certificate is never broadcast and the producer disappears.
3. **Execution is exactly-once.** When execution reaches the block, every payment in it executes, funded and in sequence, exactly once. Acknowledgments are only ever given to fully valid blocks, so there is no "receipted but bounced".

The receipt is also a bearer object: the producer can hand it to the payee, the payee can present it offline, and anyone can check it against the committee's keys.

We list three caveats. A receipt guarantees execution; actual execution, and the spending of funds that arrive from another chain, wait for placement. A producer could assemble a receipt and withhold it; this costs the payee evidence, not the payment, since the guarantees above hold from the moment $n-f$ validators' acknowledgments count toward a receipt, whether or not anyone has collected them. The payee should nonetheless demand the receipt (or collect the acknowledgments itself) before releasing goods, as in FastPay. Finally, before a payment is receipted, the home producer can delay it by not including it. The account's owner can then respond by moving the account to another chain.

## The numbers

```{=html}
<link rel="stylesheet" href="multimmit-pay.chart.css">

<figure id="multimmit-pay-latency" aria-labelledby="multimmit-pay-latency-caption">
  <div class="latency-chart" hidden></div>
  <details>
    <summary>View P50 and P99 measurements</summary>
    <table>
      <caption>Latency in milliseconds by region and condition</caption>
      <colgroup span="1"></colgroup>
      <colgroup span="2"></colgroup>
      <colgroup span="2"></colgroup>
      <thead>
        <tr>
          <th scope="col" rowspan="2">Condition</th>
          <th scope="colgroup" colspan="2">Receipt</th>
          <th scope="colgroup" colspan="2">Placement</th>
        </tr>
        <tr>
          <th scope="col">P50</th>
          <th scope="col">P99</th>
          <th scope="col">P50</th>
          <th scope="col">P99</th>
        </tr>
      </thead>
      <tbody data-axis-max="900" data-axis-step="300">
        <tr><th scope="rowgroup" colspan="5">Global</th></tr>
        <tr><th scope="row">Healthy, 100k</th><td>241</td><td>303</td><td>596</td><td>776</td></tr>
        <tr><th scope="row">Healthy, 500k</th><td>236</td><td>320</td><td>603</td><td>895</td></tr>
        <tr><th scope="row">Healthy, 1M</th><td>245</td><td>466</td><td>658</td><td>1074</td></tr>
        <tr><th scope="row">Nine crashes, 500k</th><td>422</td><td>806</td><td>862</td><td>1537</td></tr>
        <tr><th scope="row">0.1% loss, 100k</th><td>245</td><td>306</td><td>592</td><td>780</td></tr>
      </tbody>
      <tbody data-axis-max="200" data-axis-step="50">
        <tr><th scope="rowgroup" colspan="5">North America</th></tr>
        <tr><th scope="row">Healthy, 100k</th><td>37</td><td>46</td><td>88</td><td>99</td></tr>
        <tr><th scope="row">Healthy, 500k</th><td>39</td><td>47</td><td>94</td><td>159</td></tr>
        <tr><th scope="row">Healthy, 1M</th><td>41</td><td>60</td><td>142</td><td>240</td></tr>
        <tr><th scope="row">Nine crashes, 500k</th><td>53</td><td>261</td><td>184</td><td>981</td></tr>
        <tr><th scope="row">0.1% loss, 100k</th><td>38</td><td>47</td><td>89</td><td>104</td></tr>
      </tbody>
    </table>
  </details>
  <figcaption id="multimmit-pay-latency-caption">Figure 4: Payment receipt and placement latency, in milliseconds, with all fifty chains configured as payment chains. Medians from scheduled submission at the producer; a receipt requires 41 of 50 acknowledgments. Each panel has its own scale. Offered rates are in transactions per second. Expand the table for the 99th percentiles. The <a href="https://arxiv.org/html/2607.21021v6#S8.SS1">experiment</a> used synthetic 512-byte transactions with storage sync disabled; these times exclude execution, committee changes and delivery to the payee.</figcaption>
</figure>

<script type="module" src="multimmit-pay.chart.js"></script>
```

With all fifty chains configured as payment chains, healthy receipt medians are essentially flat in load: 241, 236 and 245ms globally at 100k, 500k and 1M tx/s, and 37–41ms in North America. With 0.1% message loss at 100k tx/s, the global receipt median moves from 241 to 245ms, and nine crashed validators (the full $f=9$ the deployment tolerates) raise it from 236 to 422ms at 500k tx/s. A receipt still needs only one round trip, but it now needs an acknowledgment from every survivor.

## Committee changes

Consensusless payment systems are awkward to reconfigure. This is where keeping the total ordering pays off: time is divided into epochs, the committee may change between epochs, and the close of each epoch is itself driven through consensus. Validators report what they acknowledged, the reports select the paths the next epoch builds on, and every receipted block is provably on them. The next committee is fixed two epochs in advance, so receipts verify against a known key list throughout. All three guarantees above are stated, and proved in the paper, across committee changes. The proof assumes at most $f$ members of each committee are ever faulty, including after retirement; progress requires the network eventually to deliver messages on time.

## Pay first, order later

Multimmit already places transactions quickly in the total ordering. Payments now need not wait even for that: submit a payment to its home chain. In the good case, one network round trip after sending the block, its producer holds a proof, verifiable by any third party, that the payment is final. Placement in the total ordering follows later, but the payment's finality never depended on it.

The complete design, with the formal guarantees and their proofs, is in the [Multimmit paper](https://arxiv.org/abs/2607.21021v6).
