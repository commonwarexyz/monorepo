---
title: "Out of Sight, Out of State"
description: "Private payments without an ever-growing global nullifier set. Validators keep one commitment per account, a small receipt frontier, and recent roots."
date: "September 11th, 2026"
published-time: "2026-09-11T00:00:00Z"
modified-time: "2026-09-11T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/guruvamsip"
url: "https://commonware.xyz/blogs/private-payments"
image: "https://commonware.xyz/imgs/private-payments.png"
katex: true
---

```{=html}
<link rel="stylesheet" href="private-payments.css">
```

When I first started thinking about private payments, I focused on throughput. The figures I saw usually ranged from a few hundred to a thousand payments per second, while experiments with ordinary payments were already reaching 100K+ TPS. With a single thread able to verify roughly 1,000 Groth16 proofs per second, I expected better engineering and more parallelism to close the gap.

Working on the Commonware Library raised that throughput target. Once the chain could process transactions [at this rate](https://commonware.xyz/blogs/pipelining-simplex), I had to ask what it would take to sustain comparable throughput for private payments.

Verification cost is only part of that question. Validators must also reject double spending without accumulating an unmanageable amount of state as the payment history grows. And a wallet that has been offline for months should be able to return and make a payment without catching up on everyone else's activity.

Our goal is to support private payments at over a million transactions per second, with low latency. Assuming each transaction is $\approx 200$ bytes and takes $0.5-1$ ms to verify (using [Groth16](https://eprint.iacr.org/2016/260), say), a million transactions per second requires:

- **bandwidth:** leaders disseminate <u>200 MB of data, every second</u>
- **storage:** the nullifier set (32 bytes per transaction) grows by <u>a petabyte every year</u>
- **compute:** equivalent of <u>500-1000 dedicated CPU cores</u>/validator

```{=html}
<div class="live-box">
    Since you opened this page, a ledger running at 1M transactions/s with a
    32-byte nullifier per transaction would have added
    <span class="live" id="live-bytes">0 MB</span> of nullifiers, across
    <span class="live" id="live-txs">0</span> transactions.
</div>
```

<!-- TODO: Add link to Bonsai paper -->
Bonsai addresses both the verification cost and the growing state. It keeps balances in account commitments and tracks claimed receipts inside each recipient's account, removing the need for a global nullifier set. Batch verification brings the proof-checking cost down enough to target commodity hardware:

- the prototype's batch verifier checks **over a million proofs per second** on an M5 MacBook Pro (18 cores)
- each operation has a **256-byte payload** and validators store a **single 32-byte commitment value per account**
- beyond account commitments, validators keep only a **small MMR frontier and a bounded window of recent roots**
- wallets can **stay offline and resume without scanning the ledger**, obtaining proofs for the receipts they want to claim

The ledger sees which account acts, while balances, amounts, payment links, and whether the action is a send or receive remain hidden.

## Our Construction

As a working example we have four accounts paying each other using a random stream of payments. Additionally, we have four panels which display all communication between parties, (potentially private) account balances, transactions posted to the ledger and the storage of each party.

```{=html}
<div id="sim" role="region" aria-label="From a bank to our construction.">
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

Note that this construction provides a very weak form of privacy if the amounts debited/credited are different across different transactions as it's effectively a finger print for the sender-receiver pair.

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

The ledger reveals the order in which accounts act. If it also reveals which actions are sends and which are receives, an observer can narrow down who might have paid whom: a receive must claim an earlier send. We hide this distinction by proving a strict disjunction of the send and receive relations.

Of course this also means that every send and receive carries both a receipt and a nullifier and when naively done, the prover pays the cost of both relations. In practice, this can be optimized to reduce the redundant work being performed. The ledger now only reveals that an account came online and performed some action -- send/receive.

Note the cost in the storage panel: the nullifier set grows twice as fast.

### Scaling: prune receipts

We now focus on scaling the system and insist on three restrictions:

1. **Bounded state:** validators keep account commitments, a logarithmic receipt frontier, and a bounded window of recent roots
2. **Succinct verification:** our proof system makes verification independent of the number of accounts or the anonymity set; validators also update the receipt MMR
3. **Fully offline users:** users need not stay online or scan the transaction history; they retain their wallet state and obtain receipt openings and inclusion proofs when they want to claim payments

First, instead of signing every single receipt, the ledger appends receipts to a Merkle Mountain Range (see Peter's [doc](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) or Roberto's [blogpost](https://commonware.xyz/blogs/mmr) for an explainer). The receive proof is modified to prove knowledge of an MMR opening under a root $\mathsf{root}_\rho$ which the receiver reveals in the clear.

For receipts, validators retain the MMR frontier and a bounded window of recent roots. The frontier contains at most one hash per tree height, so this is the part that grows logarithmically with the number of transactions. For example, fewer than $2^{40}$ receipts require at most 40 frontier hashes, or 1.25 KiB with 32-byte hashes. Validators do not need every historical root.

The recent-root window lets a proof remain valid while the ledger advances. An old receipt is still included in later roots, but claiming it requires an inclusion proof under a root the ledger currently accepts.

### Scaling: delegate nullifiers

Now we tackle the nullifier set. Unlike receipts where we want to prove *membership* to claim them, we want to prove *non-membership* of nullifiers to prevent double spending. MMR's do not support (efficient) non-membership proofs so we cannot simply "forget" previous nullifiers.

The [Tachyon project](https://tachyon.z.cash/) uses [oblivious synchronization](https://eprint.iacr.org/2025/2031) to let validators prune nullifiers. Users can obtain proofs from untrusted services that their coins remain unspent, without letting those services link them to their eventual transactions. Users can be offline, but resuming requires synchronization work by the user or a service that processes the ledger.

We have the benefit of working in the account based model and albeit providing less *on-chain* privacy than Zcash, it allows us to **efficiently delegate** nullifier storage. Each user remembers the nullifiers for any transactions they received, accumulates them into a [sparse Merkle tree](https://eprint.iacr.org/2016/683) and stores the root inside their account commitment. Using zero-knowledge proofs they show that it was correctly updated whenever they receive funds.

Since nullifiers are never published on chain, they no longer need to look random. The nullifier of a receipt can simply be its **position** $\mathsf{pid}$ in the receipt MMR.

Validator storage is now one commitment per account, plus the small receipt frontier and recent-root window.
But eventually... the nullifier set will grow too big for users to manage too? We've just delayed the problem.

### Scaling: prune nullifiers

Users can also **prune their nullifier state**. Receipt positions increase as receipts are created, although recipients may receive or claim them out of order. For a threshold $L$, a wallet summarizes the claimed positions below $L$ with a frontier of at most $\ell$ hashes, where $\ell$ is the depth of its nullifier tree. It keeps all claimed positions at or above $L$. Together, these suffice to reconstruct insertion proofs for unclaimed positions $\mathsf{pid} \geq L$.

Choosing $L$ to retain the $w$ largest claimed positions bounds this compact hot representation by $\ell$ hashes plus $w$ positions, independent of lifetime claims. Reconstructing paths can require additional memory and work. Older nullifiers remain in cold storage, so a receipt below $L$ can still be claimed by obtaining or reconstructing a current path from that state and updating the frontier.
:::

## The full construction

**Accounts.** An account name $A$ is a signature verification key. Registration proves knowledge of the corresponding signing key and that the account commitment starts with the permitted initial balance and an empty nullifier tree. Every account is represented by a single commitment

$$
\mathsf{com}_A = \mathsf{Com}_{\mathsf{acct}}\big(b_A,\ \mathsf{root}_{\mathsf{null}}(A);\ r_A\big)
$$

to its balance $b_A$ and the root $\mathsf{root}_{\mathsf{null}}(A)$ of the account's nullifier tree -- a sparse Merkle tree keyed by receipt position. Knowledge of the current commitment opening authorizes subsequent updates. Balances and payment amounts must lie in the allowed nonnegative range $\mathcal{B}$.
**Validators maintain:**

- the account commitments $\mathsf{Acct}[A] = \mathsf{com}_A$
- the frontier and size of the receipt MMR
- a bounded set $\mathcal{T}$ of recent receipt MMR roots accepted for transaction proofs

**Receipts:** A payment of $v$ from $\mathsf{Sen}$ to $\mathsf{Rec}$ is recorded on chain as a hiding commitment (receipt):

$$
\rho = \mathsf{Com}_{\mathsf{rec}}\big(v,\ \mathsf{Sen},\ \mathsf{Rec},\ 1;\ r''\big),
$$

whose last entry demarcates whether it's a real receipt (coming from the send branch) or a dummy receipt (coming from the receive branch). The position $\mathsf{pid}$ at which the ledger inserts $\rho$ into the MMR is the payment's identifier *and* its nullifier.

Positions are unique, so distinct receipts always carry distinct nullifiers and no send can block another pending payment (see [Faerie Gold attack](https://zips.z.cash/protocol/protocol.pdf)). The nullifier is inserted into the tree inside the account commitment and is never published on chain. No public nullifier tells the sender which receipt a receive claims.

Every transaction publishes the same record $(A, \mathsf{com}', \rho, \mathsf{root}_\rho, \pi)$: a 32-byte account identifier, the new account commitment, a receipt, an MMR root and a 128-byte proof, giving a 256-byte operation payload with these encodings. Here $\mathsf{root}_\rho$ is the public root under which a receive proves receipt membership. Both sends and receives select the latest available receipt root when preparing their proofs.

The ledger supplies $\mathsf{com} = \mathsf{Acct}[A]$ from its current state, checks $\mathsf{root}_\rho \in \mathcal{T}$, and verifies $\pi$. If all checks pass, it updates $\mathsf{Acct}[A] \gets \mathsf{com}'$, appends $\rho$ to the receipt MMR, and records the resulting root in $\mathcal{T}$. The proof $\pi$ is a strict disjunction of the following relations, where only one branch is ever proved at a time:

**If it is a send**, the proof shows that:

- the balance was updated correctly: $\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}};r) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b-v,\mathsf{root}_{\mathsf{null}};r')$
- receipt was created correctly: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec},1;r'')$ with $\mathsf{Sen} = A$ and $\mathsf{Rec}$ a valid account verification key
- no overflows: $0 \le v \le b$ and $b,\,v,\,b-v \in \mathcal{B}$

Once the send transaction lands, the sender reads off its position $\mathsf{pid}$ and forwards the opening of $\rho$ together with $\mathsf{pid}$ to the receiver over a private channel. The receiver need not have registered when the receipt is created, but must register before claiming it.

**If it is a receive**, the proof shows that:

- the balance was updated correctly: $\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}};r) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b+v,\mathsf{root}_{\mathsf{null}}';r')$
- claiming a receipt addressed to me: $\mathsf{MMR.Verify}(\mathsf{root}_\rho,\rho_{\mathsf{in}},\mathsf{pid},\pi_{\mathsf{mmr}})=1 \wedge \rho_{\mathsf{in}} = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec},1;r'')$ with $\mathsf{Rec} = A$
- nullifier did not appear: $\mathsf{SMT.VerifyInsert}(\mathsf{root}_{\mathsf{null}},\mathsf{pid},\pi_{\mathsf{smt}})=\mathsf{root}_{\mathsf{null}}'$
- published a dummy receipt $\rho = \mathsf{Com}_{\mathsf{rec}}(0,\bot,\bot,0;r''')$
- no overflows: $b,\,v,\,b+v \in \mathcal{B}$

The dummy receipt is appended to the MMR like any other, but since a receive may only consume receipts of type $1$, it can never be claimed. Fees can be supported by revealing $v_{\mathsf{fee}}$ in the statement and proving the new commitment carries $v_{\mathsf{fee}}$ less balance.

**Wallets maintain.** The opening of its account commitment (balance and randomness), the frontier of its nullifier tree together with the claimed positions at or above its chosen threshold, older nullifiers in cold storage, and the openings of any receipts it has been handed but not yet claimed.

To claim a receipt after its original root leaves $\mathcal{T}$, a wallet obtains a fresh MMR inclusion proof under an accepted root. Producing these proofs requires historical receipt-tree data to remain available, for example from an archive service; the validator frontier alone cannot reconstruct them. Wallets can verify the proofs against accepted roots without scanning the ledger.

### Sending Payments

A sender delivers the receipt opening and its position to the recipient through an existing communication channel, such as end-to-end encrypted messaging or encrypted email. This works for both live checkouts and payments to offline recipients: a merchant can verify that a receipt has landed during checkout, while a friend or employee can retrieve the message and claim the payment when they return. The payment details travel alongside the rest of the conversation, which can also provide cover traffic. Encrypting the opening to the recipient and posting it on chain is another option, but finding payments would then require every wallet to trial-decrypt every transaction on the ledger.

Receiving a receipt does not automatically credit an account. The recipient chooses whether and when to claim it, so they can leave unsolicited payments from unwanted or malicious sources unclaimed.

## Undermining Account Indistinguishability

Even when the ledger hides the acting account, an RPC service can learn which client submitted each transaction and when. If a wallet submits its own transactions through an identifiable connection or session, the operator can group those submissions.

In the example below, three wallets submit transactions through one RPC service. Switch between **Ledger observer** and **RPC operator** to see how submission metadata changes the view.

```{=html}
<div id="rpc-diagram" role="region" aria-label="Transaction grouping by an RPC operator">
    <noscript>
        <p>The RPC operator observes transactions 1, 3, and 6 from client A;
        2 and 5 from client B; and 4 from client C. The public ledger does
        not contain these client labels.</p>
    </noscript>
</div>
```

These groups identify submission sources: one client may use several accounts, and a relay may submit for several users. The grouping alone does not reveal payment amounts or recipients.

[Ledger indistinguishability](https://eprint.iacr.org/2014/349) in shielded-note systems still provides stronger **on-chain** privacy: it hides which account is acting. Bonsai publishes that account identifier while hiding balances, amounts, the recipient, and whether the action is a send or receive. The RPC observation is available to the service handling the submission; Bonsai's account identifier is visible to anyone reading the ledger. Both the public record and the wallet's network connection matter when evaluating privacy in practice.

```{=html}
<script src="private-payments.sim.js"></script>
<script src="private-payments.counter.js"></script>
<script src="private-payments.rpc.js"></script>
```

## Scalable Private Payments

A prototype of our payment system where the NIZK is instantiated with [Pari + batch verification](https://commonware.xyz/blogs/batch-pari) can be found [here](https://github.com/guruvamsi-policharla/zk-pari/pull/2). Pari is not zero-knowledge as described in the [original paper](https://eprint.iacr.org/2024/1245) or its [improvement](https://eprint.iacr.org/2025/1485). We use vanishing-polynomial masks to add zk while ensuring the proof size remains unchanged at $2 \mathbb{G}_1 + \mathbb{F}$ (128 bytes), there is negligible overhead on the prover, and the batch-verification strategy carries over. All numbers below are on an M5 MacBook Pro (6 performance + 12 efficiency cores, 48 GB RAM) over BLS12-381, single-threaded unless stated, and exclude serialization, deserialization, and subgroup checks.

**Batch Verification.** We first isolate proof-system costs using a squaring circuit with $2^{12}$ constraints and one public input. Individual verification takes about $0.7$ ms; batching reduces the amortized cost to $11.7$ $\mu$s per proof. At $N = 65{,}536$ the three MSMs account for over 90% of the 771 ms total time. Computing the Fiat-Shamir challenges takes 36 ms, the statement evaluations 25 ms (with inversions batched across proofs), and the final pairings under a millisecond.

**Throughput.** Batches are independent, so we shard them across threads with nothing shared, each thread verifying its own 80,000-proof chunk. Scaling is sub-linear because the efficiency cores are slower, but it crosses a million transactions per second on the laptop, where a transaction is a single send or receive (so roughly 525,000 payments per second, each being one send and one receive).

::: {.table-row}
::: {.table-col}
| Batch size $N$ | Verify (amortized) | Speedup |
|:---:|:---:|:---:|
| 1 | 723 $\mu$s | -- |
| 256 | 29.8 $\mu$s | $25\times$ |
| 4,096 | 16.1 $\mu$s | $46\times$ |
| 65,536 | 11.7 $\mu$s | $64\times$ |
:::
::: {.table-col}
| Threads | Transactions / s |
|:---:|:---:|
| 1 | 86,929 |
| 4 | 324,857 |
| 8 | 559,399 |
| 16 | 992,728 |
| 18 | 1,051,487 |
:::
:::

**Proving.** The circuits only use a collision-resistant hash function and we benchmark two instantiations: Pedersen hashes over Jubjub, whose security rests only on discrete log, and Poseidon over the BLS12-381 scalar field. Both the receipt MMR opening and the nullifier tree have depth 40. As expected a send is cheaper than a receive as it is just three commitment openings and range checks. In receive, the depth-40 MMR opening (40 hashes) and the sparse Merkle tree insertion (80 hashes) account for 120 of its 123 hash evaluations.

The operation-hiding relation $\mathcal R_{\mathsf{op}}$ is *not* the sum of the two as send is structurally a sub-relation of receive, so the circuit instantiates each shared gadget once and lets the branch bit multiplex only the inputs, adding about 8.3K (Pedersen) or 1K (Poseidon) constraints on top of receive.

| Circuit | Hash | R1CS | SR1CS | Prove<br>(1 thread) | Prove<br>(8 threads) | Verify |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| $\mathcal R_{\mathsf{send}}$ | Pedersen | 16,109 | 32,227 | 0.84 s | 0.14 s | 747 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$ | Pedersen | 398,111 | 796,231 | 20.1 s | 3.8 s | 754 $\mu$s |
| $\mathcal R_{\mathsf{op}}$ | Pedersen | 406,460 | 812,931 | 20.4 s | 3.8 s | 805 $\mu$s |
| $\mathcal R_{\mathsf{send}}$ | Poseidon | 1,647 | 3,303 | 0.14 s | 0.03 s | 806 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$ | Poseidon | 30,729 | 61,467 | 1.6 s | 0.29 s | 768 $\mu$s |
| $\mathcal R_{\mathsf{op}}$ | Poseidon | 31,706 | 63,423 | 1.6 s | 0.29 s | 761 $\mu$s |

Prover timings include witness generation but exclude constraint synthesis, which is performed once per circuit. Compiling R1CS to Square R1CS roughly doubles the constraint count; supporting R1CS directly is one opportunity to reduce prover cost.

These early results put batch proof verification above a million proofs per second on a laptop. Bonsai pairs that progress with compact transactions and validator state that avoids a global nullifier set, while letting wallets return from long periods offline. The next step is to carry that throughput through networking, consensus, and storage into a complete private payment system.
