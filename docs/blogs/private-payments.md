---
title: "Scalable Private Payments"
description: "Every private payment system has an ever growing global nullifier set. We design a payment system where state only grows with the number of accounts."
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

A few years ago when I first started thinking about private payments, I wanted to understand what throughput can we sustain for private payments? And the answer I typically got was a few hundred to a thousand private payments per second. This made no sense to me because there are experiments handling 100K+ TPS for regular payments.
Surely cryptography was not the bottleneck? We can verify ~1000 Groth16 per second on a *single thread*. So what’s stopping us from scaling?

I never got a satisfactory answer and always left feeling like the problems could be overcome with better engineering. But at least cryptography was not the bottleneck. Right?

::: {data-align="center"}
> ***At commonware, the situation flipped. The chain is [really fast](https://x.com/_patrickogrady/status/2077449338230640739?s=20). [Scarily fast](https://commonware.xyz/blogs/pipelining-simplex).***<br>
> ***It very quickly turned into: how will the cryptography keep up with the chain?!***
:::

Our goal is to build extremely high throughput private payments (1M+ TPS) with low latency.
Assuming every payment is $\approx 200$ bytes and takes $0.5-1$ ms to verify (using [Groth16](https://eprint.iacr.org/2016/260) say), this requires massive amounts of:

- **bandwidth:** leaders disseminate <u>200 MB of data, every second</u>
- **storage:** the nullifier set (32 bytes per transaction) grows by <u>a petabyte every year</u>
- **compute:** equivalent of <u>500-1000 dedicated CPU cores</u>/validator

Sure you can always throw more threads at the problem and use bigger machines but that’s just not how commonware operates. We want the BEST solution at the LOWEST price point.
Below we present our design for a private payment scheme where:

- **a million transactions** can be verified on an M5 Macbook Pro (18 cores)
- validator storage grows **logarithmically in \#(transactions)** and linearly in \#(accounts)
- work done by users **only depends on the transactions they are involved in**

## Our Construction

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

::: {#sim-source}

### A Bank

A centralized party maintains custody of all funds and applies all changes to balances. The bank is an intermediary in every transfer and is aware of who pays whom, and how much.

### ecash

David Chaum introduced [ecash](https://chaum.com/wp-content/uploads/2022/01/Chaum-blind-signatures.pdf) -- the first payment system to achieve *unlinkability* between the sender and receiver. The bank authorizes the withdrawal of a single unit (say 1\$) through a *blind signature*, which the sender can provide to a receiver who can then redeem the signature on the coin for 1\$.

Since the communication between the sender and receiver is hidden, the system hides who paid whom but the central authority/bank can still see balances and inflows/outflows of an account. However, the bank must remember a unique nullifier for every coin that was ever redeemed.

Note that in this construction provides a very weak form of privacy if the amounts debited/credited are different across different transactions as it's effectively a finger print for the sender-receiver pair.

### Decentralized ecash

In order to provide much faster confirmations, and scale with confidence, the most natural strategy is to use a consensus algorithm that provides byzantine fault tolerance. The bank can be replaced by a committee of validators and if designed correctly (see [Multimmit](https://commonware.xyz/blogs/multimmit) for example), payments from different parts of the world can be *simultaneously* ingested into the log, providing much faster confirmations with a truly global payment network.

However this introduces additional privacy concerns: anyone reading the ledger, sees every balance and every account's inflow and outflow. Even if the committee is trusted to run the ledger, users may not want to share their balances with the world.

### Hide balances

Cryptographic commitments coupled with zero-knowledge proofs allow us to both hide balances and *verifiably* (but in zero-knowledge) update them when a transfer occurs. In fact, [Zether](https://eprint.iacr.org/2019/191) follows this recipe, but a payment updates the sender and the receiver in one transaction, so the ledger still sees who paid whom. We can take this one step further by *decoupling* the updates to sender and receiver balances -- as done in ecash -- to additionally hide who paid whom.

Concretely, we can prove during:

- **send**: the new account commitment is the old one minus $v$, and the on-chain receipt (another commitment) signed by the validators opens to $(v, A \to B)$.
- **receive**: the new account commitment is the old one plus $v$, I hold a validator signature on some receipt for $(v, \cdot \to B)$, and reveal some deterministic (yet random looking) nullifier.

Balances and amounts are now hidden from the ledger, but it still reveals which particular account sent/received funds.

### Hide operations

On the face of it, leaking whether a user sent or received money seems innocuous but the ledger additionally provides an ***ordering*** for these operations. As we will see [later](#histories) in the blog, this greatly reduces the number of different "realities" that could have taken place. Hiding whether we are sending/receiving funds is actually quite straightforward -- simply prove a strict disjunction of the send and receive relations.

Of course this also means that every send and receive carries both a receipt and a nullifier and when naively done, the prover pays the cost of both relations. In practice, this can be optimized to reduce the redundant work being performed. The ledger now only reveals that an account came online and performed some action -- send/receive.

Note the cost in the storage panel: the nullifier set grows twice as fast.

### Scaling: prune receipts

We now focus on scaling the system and insist on three restrictions:

1. **Bounded state:** validators store state proportional to the number of accounts, not the number of transactions
2. **Constant work:** validators only do a constant amount of work per transaction, independent of the number of accounts (or anonymity sets)
3. **Fully offline users:** a user can be offline indefinitely and return knowing only its secrets and the current state, without reading any past transactions

First, instead of signing every single transaction, the committee can accumulate receipts in a Merkle Mountain Range and just sign the root (see Peter's [doc](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) or Roberto's [blog](https://commonware.xyz/blogs/mmr) for an explainer). The receive proof can be modified to additionally prove knowledge of a merkle tree opening.

Thus, validators only need to maintain the peaks of the receipt MMR, which grow logarithmically in the number of transactions.

### Scaling: delegate nullifiers

Now we tackle the nullifier set. Unlike receipts where we want to prove *membership* to claim them, we want to prove *non-membership* of nullifiers to prevent double spending. MMR's do not support (efficient) non-membership proofs so we cannot simply "forget" previous nullifiers.

The [Tachyon project](https://tachyon.z.cash/) uses [oblivious synchronization](https://eprint.iacr.org/2025/2031) to get around this issue. Here, validators periodically offload their nullifier set and users will ask untrusted services to create proofs that their coins have so far not been spent. Importantly, these services cannot link clients to their transactions when they eventually spend their coins. However, this
requires every unspent shielded note to *continually* synchronize non-membership proofs with the ledger -- hence users cannot be truly offline if they have unspent coins.

We have the benefit of working in the account based model and albeit providing less *on-chain* privacy than Zcash, it allows us to **efficiently delegate** nullifier storage. Each user remembers the nullifiers for any transactions they received, accumulates them into an [indexed merkle tree](https://eprint.iacr.org/2021/1263) and stores the root inside their account commitment. Using zero-knowledge proofs they show that it was correctly updated whenever they receive funds.

Validator storage now grows with accounts, not transactions. Great.

But eventually... the nullifier set will grow too big for users to manage as well.

### Scaling: prune nullifiers

Now for the final optimization. Users can actually prune their nullifier sets as well! We divide the ledger into epochs and introduce a second MMR which stores the roots of nullifier trees from previous epochs. Storage only grows logarithmically in the number of epochs plus the number of nullifiers in the current epoch.

Note that this means claiming a receipt from an old epoch is more expensive as they would need to update the MMR which requires retrieving the old roots and nullifiers.

In practice, we expect that this rarely happens as in typical transactions the seller will only hand over the goods when they have a receipt in-hand in which case they know all the receipts they need to claim before closing out the epoch.
:::

## The full construction

**Accounts.** Every account is represented by a single commitment

$$
\mathsf{com}_A = \mathsf{Com}_{\mathsf{acct}}\big(b_A,\ \kappa_A,\ \mathsf{root}_{\mathsf{null}}(A);\ r_A\big)
$$

to its balance $b_A$, a secret PRF key $\kappa_A$, and the root $\mathsf{root}_{\mathsf{null}}(A)$ of the account's nullifier tree. With epoch based pruning, we store another root for the MMR of nullifier tree roots.

**Validators maintain:**

- the account commitments $\mathsf{Acct}[A] = \mathsf{com}_A$
- the frontier of the receipt MMR

**Receipts:** A payment of $v$ from $\mathsf{Sen}$ to $\mathsf{Rec}$ is recorded on chain as a hiding commitment (receipt):

$$
\rho = \mathsf{Com}_{\mathsf{rec}}\big(v,\ \mathsf{Sen},\ \mathsf{Rec},\ 1;\ r''\big),
$$

whose last entry demarcates whether it's a real receipt (coming from the send branch) or a dummy receipt (coming from the receive branch). The position $\mathsf{pid}$ at which the ledger inserts $\rho$ into the MMR is the payment's identifier and determines its nullifier,

$$
\mathsf{null} = \mathsf{CRPRF}_{\kappa_{\mathsf{Rec}}}(\mathsf{recv}, \mathsf{pid}),
$$

derived under the *receiver's* committed key. Positions are unique, so distinct receipts collide with negligible probability thereby preventing [Faerie Gold attacks](cite here). Note that the nullifier is never actually published on chain, it will be inserted into the tree maintained inside the account commitment. This means that a sender does not learn when a payment was claimed.

A send/receive is a strict disjunctive proof of the following relations, where only one branch is every proved at a time:

**If it is a send**, the proof shows that:

- the balance was updated correctly: $\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\kappa,\mathsf{root}_{\mathsf{null}};r) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b-v,\kappa,\mathsf{root}_{\mathsf{null}};r')$
- receipt was created correctly: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec},1;r'')$
- no overflows: $0 \le v \le b$ and $b,\,v,\,b-v \in \mathcal{B}$

Once the send transaction lands, the sender reads off its position $\mathsf{pid}$ and forwards the opening of $\rho$ together with $\mathsf{pid}$ to the receiver over a private channel.

**If it is a receive**, the proof shows that:

- the balance was updated correctly: $\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\kappa,\mathsf{root}_{\mathsf{null}};r) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b+v,\kappa,\mathsf{root}_{\mathsf{null}}';r')$
- claiming a receipt addressed to me: $\mathsf{MMR.Verify}(\mathsf{root}_\rho,\rho^\star,\mathsf{pid},\pi_{\mathsf{mmr}})=1 \wedge \rho^\star = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec},1;r'')$
- nullifer did not appear: $\mathsf{null} = \mathsf{CRPRF}_\kappa(\mathsf{recv},\mathsf{pid}) \wedge \mathsf{MT.AccVerifyInsert}(\mathsf{root}_{\mathsf{null}},\mathsf{null},\pi_{\mathsf{mt}})=\mathsf{root}_{\mathsf{null}}'$
- published a dummy receipt $\rho = \mathsf{Com}_{\mathsf{rec}}(\cdot,\cdot,\cdot,0;\cdot)$

**Wallets maintain.** The opening of its account commitment (balance, PRF key, randomness), the nullifiers of the current epoch together with their indexed Merkle tree, one root per past epoch, and the openings of any receipts it has been handed but not yet claimed.

When the sender and receiver are both online which is typically the case in e-commerce, the buyer can provide the seller with confirmation that a receipt has landed on chain and the seller can collect the receipt's opening to claim it at some point in the future. However, this is challenging when the receiver is not online in applications such as payments between friends or payroll. One option is to use existing communication channels such as end-to-end encrypted messaging or email to share the receipt opening, thereby using the rest of the conversation as cover traffic.

Note that a private channel is not strictly required as the sender could always encrypt the opening to the receiver and post it on chain alongside the transaction. But every wallet would have to trial-decrypt every incoming transaction to find the ones designated for it. We do not expect this approach to scale as it is linear work in the throughput of the whole ledger.

## Indistinguishable Send/Receive {#histories}

We analyze the leakage in our private payment scheme under two different leakage functions to highlight the benefits of obfuscating the operation.

- `L_unl`: the ledger sees the acting account and the operation send/receive
- `L_ind`: the ledger sees only sees the acting account

To provide a quantitative comparison of the privacy guarantees we compute the number of causally possible *histories* that a sequence of transactions can have. In the interactive demo below, for a given sequence of transactions, we represent all possible histories as a root-to-leaf path.

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
        <input id="rand-n" type="number" min="1" max="14" value="6">
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

```{=html}
<div id="trees" class="tree-row"></div>
```

::: {.image-caption}
One level per transaction; each root-to-leaf path is a history, and the one that happened is highlighted. Node labels: $S$ is a send; $R_i$ is a receive claiming the receipt published at $t_i$. The first six levels are drawn in full; beyond that, each level shows only its number of consistent histories. Amounts and the recipients of unclaimed receipts are hidden under both leakage functions.
:::

**Comparison to shielded notes.**
[Ledger indistinguishability](https://eprint.iacr.org/2014/349) in shielded notes guarantees that the ledger learns nothing about who is transacting. Our ledger, by contrast, always names the account that acted but is able to handle nullifiers more efficiently. Thus the **onchain** privacy in shielded notes is stronger than our protocol.

In a real world deployment however, the gap may be narrower. Typically, wallet don't talk to the ledger directly and go through intermediary RPC nodes which sees which client submitted each transaction and when. Whoever runs it holds a table mapping users to the transactions they broadcast, which is precisely the *acting account* that `L_ind` leaks.

```{=html}
<script src="private-payments.sim.js"></script>
<script src="private-payments.histories.js"></script>
```

## Early Benchmarks

A prototype of our payment system where the NIZK is instantiated with [Pari + batch verification](https://commonware.xyz/blogs/batch-pari) can be found [here](https://github.com/guruvamsi-policharla/zk-pari/tree/vanishing-poly-zk). Pari is not zero-knowledge as described in the [original paper](https://eprint.iacr.org/2024/1245). We use masking polynomials to add zk while ensuring the the proof size remains unchanged $2 \mathbb{G}_1 + \mathbb{F}$ and there is minimal overhead on the proving/verification time. All numbers below are on an M5 MacBook Pro (6 performance + 12 efficiency cores, 48 GB RAM) over BLS12-381, single-threaded unless stated, and exclude deserialization and subgroup checks.

**Batch Verification.** Verifying a proof takes about $0.7$ ms regardless of circuit size. But with batch verification, this can be brought down significantly. At $N = 65{,}536$ the three MSMs account for over 90% of the 729 ms total time. Computing the Fiat-Shamir challenges take 34 ms, the statement evaluations 24 ms (with inversions batched across proofs), and the final pairing under a millisecond.

**Throughput.** Batches are independent, so we shard them across threads with nothing shared, each thread verifying its own 80,000-proof chunk. Scaling is sub-linear because the efficiency cores are slower, but it crosses a million transactions per second on the laptop, where a transaction is a single send or receive.

::: {.table-row}
::: {.table-col}
| Batch size $N$ | Verify (amortized) | Speedup |
|:---:|:---:|:---:|
| 1 | 696 $\mu$s | -- |
| 256 | 29.4 $\mu$s | $24\times$ |
| 4,096 | 15.6 $\mu$s | $46\times$ |
| 65,536 | 11.2 $\mu$s | $64\times$ |
:::
::: {.table-col}
| Threads | Transactions / s |
|:---:|:---:|
| 1 | 86,532 |
| 4 | 314,710 |
| 8 | 537,862 |
| 16 | 970,676 |
| 18 | 1,017,948 |
:::
:::

**Proving.** The circuits use Pedersen hashes over Jubjub for Merkle nodes, and account/receipt commitments, and SHA-256 for the collision resistant PRF. As expected a send is cheaper than a receive as it does not have to prove merkle openings. In receive is where the cost sits, since it also verifies a depth-40 MMR opening and an insertion into the nullifier tree. The operation-hiding relation $\mathcal R_{\mathsf{op}}$ is *not* the sum of the two: send is structurally a sub-relation of receive, so the circuit instantiates each shared gadget once and lets the branch bit multiplex only the inputs, adding about 8K constraints on top of receive. $d$ is the depth of the user's nullifier tree.

| Circuit | R1CS | SR1CS | Prove | Verify |
|:--|---:|---:|---:|---:|
| $\mathcal R_{\mathsf{send}}$ | 19,293 | 38,595 | 1.6 s | 748 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$, $d = 10$ | 370,020 | 740,049 | 20.9 s | 760 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$, $d = 20$ | 497,360 | 994,729 | 21.9 s | 750 $\mu$s |
| $\mathcal R_{\mathsf{op}}$, $d = 10$ | 378,369 | 756,749 | 21.0 s | 743 $\mu$s |
| $\mathcal R_{\mathsf{op}}$, $d = 20$ | 505,709 | 1,011,429 | 21.6 s | 756 $\mu$s |

We note that the prover time can be halved by increasing the proof size by 1 field element (32 bytes), and we expect the number of constraints to come down as we optimize circuits.