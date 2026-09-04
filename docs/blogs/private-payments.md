---
title: "Scalable Private Payments"
description: "Every private payment system has an ever growing global nullifier set. We desigm a payment system where state only grows with the number of accounts."
date: "September 3rd, 2026"
published-time: "2026-09-03T00:00:00Z"
modified-time: "2026-09-03T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/guruvamsip"
url: "https://commonware.xyz/blogs/private-payments"
image: "https://commonware.xyz/imgs/private-payments.png"
katex: true
---

```{=html}
<link rel="stylesheet" href="private-payments.css">
<div class="live-box">
    Since you opened this page, a ledger running at 1M private payments/s would
    have added <span class="live" id="live-bytes">0 MB</span> of nullifiers, across
    <span class="live" id="live-txs">0</span> transactions.
</div>
```

Our goal is to build extremely high throughput private payments (1M+ TPS) with low latency.
Assuming every payment is $\approx 200$ bytes and takes $0.5-1$ ms to verify (using [Groth16](https://eprint.iacr.org/2016/260) say), this requires massive amounts of:

- **bandwidth:** leaders disseminate <u>200 MB of data, every second</u>
- **storage:** the nullifier set (32 bytes per transaction) grows by <u>a petabyte every year</u>
- **compute:** equivalent of <u>500-1000 dedicated CPU cores</u>/validator

Below we present our design for a private payment scheme where

- **a million transactions** can be verified on an M5 Macbook Pro (18 cores)
- validator storage grows **logarithmically in \#(transactions)** and linearly in \#(accounts)
- work done by users **only depends on the transactions they are involved in**

## Decentralizing the Bank

Four accounts pay one another at random, and the same stream of payments is shown under each of eight designs. The top row shows who talks to whom, the balances, and what the ledger publishes; the row beneath shows what validators and users must store, drawn as the data structures they actually keep. The boxes at the bottom call out what each move changes. Step through with the arrows.

```{=html}
<div id="sim" role="region" aria-label="A bank to our construction.">
    <noscript>
        <style>
            #sim-source { display: block; }
        </style>
    </noscript>
</div>
```

<!-- Step text for the simulation. Each ### heading starts a step; the content
under it is shown beneath the stage when that step is selected. The block is
hidden when JavaScript is enabled and shown as plain sections otherwise. -->

::: {#sim-source}

### A Bank

A bank keeps every balance and moves money between them. A payment is a single instruction, *A pays B 120*, and the bank applies it. Storage could not be smaller: one balance per account and nothing per payment, and that is the baseline we will work our way back to. The cost is on the other side. The bank is inside every payment and sees everything about it: who paid whom, how much, and every balance.

### ecash

Split the payment in two so the bank is no longer inside it. To *send*, the sender has the bank blind-sign a coin carrying a fresh random serial number, its *nullifier*, and hands the coin to the receiver directly, off the ledger (the dashed arc). To *receive*, the receiver presents the coin, and the bank credits it after checking that its nullifier has not been seen before. Blindness means the bank cannot connect a send to a receive, so it no longer learns who paid whom. It still sees both halves, with amounts.

The price is in the storage panel: the nullifier set grows by one entry per coin and can never be pruned, because a coin sent years ago is still valid. And the bank remains the only thing between a coin and a double spend, one party that everyone must trust and that has to serve the whole world.

### Decentralized ecash

Replace the bank with a fault-tolerant committee of validators. Sends and receives become transactions, the coin's signature is issued by the committee, and the account table and the nullifier set move with it. This buys fault tolerance and, designed with care, confirmation latency competitive with a round trip to a bank ([Multimmit](/blogs/multimmit)). But the ledger panel has not changed: every validator, and anyone reading the ledger, sees every balance and every account's inflow and outflow. Even if the committee is trusted to run the ledger, users may not want to share their balances with all of it. So hide them.

### Hide balances

Replace each balance with a hiding commitment to the balance and a secret key, and let users update their own commitments with a zero-knowledge proof; validators only verify. The coin becomes a commitment too, a *receipt* that binds the amount, the sender, and the receiver, and since it hides its contents an ordinary validator signature on it does what the blind signature did. The two transactions prove minimal statements:

- **send**: the new commitment is the old one minus $v$, and the receipt opens to $(v, A \to B)$, with $0 \le v \le \mathsf{balance}$.
- **receive**: the new commitment is the old one plus $v$, I hold a validator signature on some receipt for $(v, \cdot \to B)$, and this nullifier is derived from that receipt under my committed key.

The nullifier is the price of hiding *which* signed receipt is being claimed: validators never see the receipt again, so they keep the set of nullifiers and reject repeats. It plays exactly the role the coin's nullifier played in ecash, and the storage panel is unchanged. Balances and amounts are gone from the ledger, but a send still carries a receipt and a receive a nullifier, so it still shows who sent and who received.

### Hide operations

Whether a transaction is a send or a receive is one bit, and zero knowledge removes it: give both transactions the same public form, a new commitment, a receipt, a nullifier, and a proof, and prove a disjunction. Either this is a valid send, the receipt is genuine and the nullifier is a fresh dummy, or it is a valid receive, the receipt is a dummy of a fixed form that can never be claimed, and the nullifier belongs to the receipt being consumed. The two kinds of row in the ledger are now indistinguishable, and the observer learns only that $X$ acted. The [consistent-histories](#histories) section below shows how much that one bit is worth.

Note the cost in the storage panel: every transaction now publishes a nullifier, real or dummy, so the set grows twice as fast.

### Prune receipts

This is the privacy we settle for: the observer learns which account acted, and nothing else. Now scale it. At a million transactions per second every validator receives about 200 MB of transaction data each second, the nullifier set grows by a petabyte a year and must sit in fast storage because every transaction is checked against it, and at 0.5 to 1 ms per proof verification alone occupies 500 to 1000 cores. Bandwidth is the tractable one, since erasure-coded dissemination lets a proposer use the whole network's egress; storage and compute are the problem.

Start with the receipts. A committee signature on every receipt is a threshold signature per transaction, so instead accumulate receipts in a Merkle Mountain Range and sign once per block. Validators keep only the frontier, a logarithmic number of hashes that suffices to append and to compute the root, and a short window of recent roots; the receive relation names one of them and proves membership of the receipt under it. The receipt itself, its position, and its opening live with the two parties: the sender hands them over off the ledger, exactly as it handed over the coin at the start.

### Delegate nullifier storage

The petabyte is the nullifier set, and it exists because validators do the crediting. But a receipt is committed to its recipient, so only $B$ can ever claim it, and only $B$ needs to remember which receipts it has claimed. Move the set into $B$'s account: the commitment now also commits to the root of $B$'s own Merkle tree of nullifiers, the nullifier is derived from the receipt's position under $B$'s committed key and is never published, and the receive relation proves that it was absent from the old tree and is present in the new one. Positions are unique, so no sender can collide with another's payment, and $A$, who does not know $B$'s key, never learns when its payment was claimed. Watch the nullifier tree leave the validators' side and reappear on the users' side, one tree per account, appended in insertion order and threaded in sorted order: whoever credits keeps the list, as the bank did at the start, and now that is the receiver.

Validator storage now grows with accounts, not transactions. Compute is handled by the proof system: ZK-Pari proofs are two group elements and a field element, and a batch of $N$ of them verifies with three multi-scalar multiplications and three pairings, a million per second on 18 cores. One thing still grows, though: each user's own tree holds every nullifier it has ever received.

### Prune nullifiers

Divide the ledger into epochs. A receipt's position fixes the block it was recorded in, and so its epoch, which gates senders to the current epoch: nobody can manufacture a receipt that belongs to the past. The receiver now keeps one nullifier tree per epoch and, in its account commitment, a second tree whose leaves are the epoch roots, appended once per epoch like an MMR. A receive proves the insertion in the tree of the receipt's epoch and the update of that one leaf.

Honest senders deliver receipts as soon as they are recorded, so once an epoch has ended the receiver expects nothing more from it and can drop that epoch's nullifiers, keeping only the root (a sender that withheld a receipt across the boundary can still be accommodated from cold storage, but never on the common path). Watch each user's tree empty at the epoch boundary while its root joins the user's own small mountain range of epoch roots. What everyone keeps at hand is now bounded by activity within an epoch: validators by the number of accounts, users by one epoch of receipts and one hash per epoch. Nothing grows with lifetime history, and the observer still learns only who acted. What that one hidden bit buys is the subject of the rest of this page.
:::

## Chapter 2: How many histories? {#histories}

In our private payment scheme a payment is two transactions: the sender publishes a receipt, and the receiver later claims it. Validators learn which account acts, and nothing about amounts or counterparties. Whether they also learn the *type* of a transaction is the difference between two leakage functions:

- `L_unl` reveals `(op, account)`: the ledger sees that $A$ sent and that $B$ received.
- `L_ind` reveals only `account`: the ledger sees that $A$ acted and that $B$ acted.

A *history* assigns every transaction a role, either a send or a receive claiming a specific earlier receipt, consistent with what the ledger saw. A receipt can be claimed only after it is published, and at most once; whether an account may claim its own receipt is a toggle below. Build a log below; the demo enumerates every history consistent with each transcript and draws them as a tree, one level per transaction. Each root-to-leaf path is one history. The one that actually happened is highlighted.

### Log {#log-heading}

```{=html}
<div id="controls" class="panel">
    <div class="control-row">
        <label for="acct">Account</label>
        <select id="acct"></select>
        <label for="op">Operation</label>
        <select id="op">
            <option value="send">send to</option>
            <option value="recv">receive</option>
        </select>
        <select id="target"></select>
        <button id="add">add</button>
    </div>
    <div class="control-row">
        <button id="undo">undo</button>
        <button id="clear">clear</button>
        <button id="random">random</button>
        <label for="rand-n" class="inline">length</label>
        <input id="rand-n" type="number" min="1" max="14" value="8">
        <label for="num-accts" class="inline">accounts</label>
        <input id="num-accts" type="number" min="2" max="6">
        <input id="allow-self" type="checkbox" class="inline">
        <label for="allow-self">allow self-payments</label>
    </div>
    <div id="status" class="status"></div>
</div>
```

Each leakage function's columns show what it sees of a transaction and how many histories are consistent with everything it has seen so far. With self-payments allowed, the `L_ind` count depends only on the length $n$ of the log: a history is a partial matching of the $n$ positions into send-claim pairs, and these are counted by the telephone numbers $T(n) = 1, 2, 4, 10, 26, 76, 232, \ldots$, with

$$
T(n) = T(n-1) + (n-1)\,T(n-2).
$$

Without self-payments a claim's actor must differ from the receipt's creator, and the count comes to depend on who acted when.

```{=html}
<table id="log">
    <thead>
        <tr>
            <th rowspan="2">t</th>
            <th rowspan="2">what happened</th>
            <th colspan="2"><code>L_unl</code></th>
            <th colspan="2"><code>L_ind</code></th>
        </tr>
        <tr>
            <th>sees</th><th class="num">histories</th>
            <th>sees</th><th class="num">histories</th>
        </tr>
    </thead>
    <tbody></tbody>
</table>
```

### Consistent histories

```{=html}
<p id="summary" class="summary"></p>
<div id="trees" class="tree-row"></div>
```

::: {.image-caption}
One level per transaction; each root-to-leaf path is a history, and the one that happened is highlighted. Node labels: $S$ is a send; $R_i$ is a receive claiming the receipt published at $t_i$. The first six levels are drawn in full; beyond that, each level shows only its number of consistent histories. Amounts and the recipients of unclaimed receipts are hidden under both leakage functions.
:::

```{=html}
<script src="private-payments.sim.js"></script>
<script src="private-payments.histories.js"></script>
```

([code](https://github.com/guruvamsi-policharla/zk-pari/tree/vanishing-poly-zk))