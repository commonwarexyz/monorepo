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

Additionally, we discuss the level of privacy our construction provides in the context of other private payment mechanisms such as shielded notes (Zcash).

## Decentralizing the Bank

As a working example we have four accounts paying each other using a random stream of payments. Additionally, we have four panels which display all communication between parties, (potentially private) account balances, transactions posted to the ledger and the storage of each party.

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

A centralized party maintains custody of all funds and applies all changes to balances. The bank is an intermediary in every transfer and is aware of who pays whom, and how much.

### ecash

David Chaum introduced [ecash] -- the first payment system to achieve *unlinkability* between the sender and receiver. The bank authorizes the withdrawal of a single unit (say 1\$) through a *blind signature*, which the sender can provide to a receiver who can then redeem the signature on the coin for 1\$.

Since the communication between the sender and receiver is hidden, the system hides who paid whom but the central authority/bank can still see balances and inflows/outflows of an account. However, the bank must remember a unique nullifer for every coin that was ever redeemed.

### Decentralized ecash

In order to provide much faster confirmations, and scale with confidence, the most natural strategy is to use a consensus algorithm that provides byzantine fault tolerance. The bank can be replaced a committee of validators and if designed correctly (see [Multimmit](https://commonware.xyz/blogs/multimmit) for example), payments from different parts of the world can be *simulatenously* ingested into the log. Providing must faster confirmations with a truly global payment network.

However this introduces additional privacy concerns: anyone reading the ledger, sees every balance and every account's inflow and outflow. Even if the committee is trusted to run the ledger, users may not want to share their balances with the world.

### Hide balances

Cryptographic commitments coupled with zero-knowledge proofs allow us to both hide balances and *verifiably* (but in zero-knowledge) update them when a transfer occurs. In fact, [Zether](https://eprint.iacr.org/2019/191) follows this recipie, but a payment updates the sender and the receiver in one transaction, so the ledger still sees who paid whom. We can take this one step further by *decoupling* the updates to sender and receiver balances -- as done in ecash -- to additionally hide who paid whom.

Concretely, we can prove during:

- **send**: the new account commitment is the old one minus $v$, and the on-chain receipt (another commitment) signed by the validators opens to $(v, A \to B)$.
- **receive**: the new account commitment is the old one plus $v$, I hold a validator signature on some receipt for $(v, \cdot \to B)$, and reveal some deterministic (yet random looking) nullifier.

Balances and amounts are now hidden from the ledger, but it still reveals which particular account sent/received funds.

### Hide operations

On the face of it, leaking whether I sent or received money seem innocuous but the ledger additionally provides an ***ordering*** for these operations. As we will see [later](#histories) in the blog, this greatly reduces the number of different "realities" that could have taken place. Hiding whether we are sending/receiving funds is actually quite straightforward -- simply prove a strict disjunction of the send and receive relations.

Of course this also means that every send and receive carries both a receipt and a nullifier and when naively done, the prover pays the cost of both relations. In practice, this can be optimized to reduce the redundant work being performed. The ledger now only reveals that an account can online and performed some action -- send/receive.

Note the cost in the storage panel: the nullifier set grows twice as fast.

### Scaling: prune receipts

We now focus on scaling the system and insist on three restrictions:

1. **Bounded state:** validators store state proportional to the number of accounts, not the number of transactions
2. **Constant work:** validators only do a constant amount of work per transaction, independent of the number of accounts (or anonymity sets)
3. **Fully offline users:** a user can be offline indefinitely and return knowing only its secrets and the current state, without reading any past transactions

First, instead of signing every single transaction, the committee can accumulate receipts in a Merkle Mountain Range and just sign the root (see Peter's [doc](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) or Roberto's [blog](https://commonware.xyz/blogs/mmr) for an explainer). The receive proof can be modified to additionally prove knowledge of a merkle tree opening.

Thus, validators only need maintain the roots of the receipt MMR which grows logartihmically in the number of transactions.

### Scaling: delegate nullifiers

Now we tackle the nullifier set. Unlike receipts where want to prove *membership* to claim them, we want to prove *non-membership* of nullifiers to prevent double spending. MMR's do not support (efficient) non-membership proofs so we cannot simply "forget" previous nullifiers.

The [Tachyon project](https://tachyon.z.cash/) uses [oblivious synchronization](https://eprint.iacr.org/2025/2031) to get around this issue. Here, validators periodically offload their nullifier set and users will ask untrusted services to create proofs that their coins have so far not been spent. Importantly, these services cannot link clients to their transactions when they eventually spend their coins. However, this
requires every unspent shielded note to *continually* synchronize non-membership proofs with the ledger -- hence users cannot be truly offline if they have unspent coins.

We have the benefit of working in the account based model and albeit providing less *on-chain* privacy that Zcash, it allows us to **efficiently delegate** nullifier storage. Each user remembers the nullifers for any transactions that received, accumulates them into an [indexed merkle tree](https://eprint.iacr.org/2021/1263) and stores the root inside their account commitment. Using zero-knowledge proofs they show that it was correctly updated whenever they carry receive funds.

Validator storage now grows with accounts, not transactions. Great.

But eventually... the nullifier set will grow too big for users to manage as well.

### Scaling: prune nullifiers

Now for the final optimization. Users can actually prune their nullifier sets as well! We divide the ledger into epochs and introduce a second MMR which store the roots of nullifier trees from previous epochs. Storage only grows logarithmically in the number of epochs plus the number of nullifiers in the current epoch.

Note that this means claiming a receipt from an old epoch is more expensive as they would need to update the MMR which requires retreiving the old roots and nullifiers.

In practice, we expect that this rarely happens as in typical transactions the seller will only hand over the goods when they have a receipt in-hand in which case they know all the receipts they need to claim before closing out the epoch.
:::

## Chapter 2: How many histories? {#histories}
<!-- todo: update below this -->
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