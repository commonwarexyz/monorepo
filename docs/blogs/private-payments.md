---
title: "Out of Sight, Out of State"
description: "Private payments without an ever-growing global nullifier set. Bonsai keeps validator state proportional to the number of accounts and lets wallets go offline indefinitely."
date: "September 12th, 2026"
published-time: "2026-09-12T00:00:00Z"
modified-time: "2026-09-12T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/guruvamsip"
url: "https://commonware.xyz/blogs/private-payments"
image: "https://commonware.xyz/imgs/private-payments.png"
katex: true
---

```{=html}
<link rel="stylesheet" href="private-payments.css">
```

The [Commonware Library](https://github.com/commonwarexyz/monorepo) now processes [~250K payments per second](https://x.com/_patrickogrady/status/2077449338230640739) on [Constantinople](https://github.com/commonwarexyz/constantinople). [Stable leaders](/blogs/pipelining-simplex), [multiple proposers](/blogs/multimmit), and clearing solutions such as [Bajillion](/blogs/clearing) push throughput even higher. How can private payments deliver that throughput or better, with low latency?

Suppose each transaction is $\approx 200$ bytes and takes $0.5-1$ ms to verify (using [Groth16](https://eprint.iacr.org/2016/260) with a [shielded-note scheme](https://eprint.iacr.org/2014/349), for example). To support a million transactions per second:

- **bandwidth:** leaders need to disseminate <u>200 MB of data every second</u>
- **compute:** every validator needs the equivalent of <u>500-1000 dedicated CPU cores</u>
- **storage:** since you opened this page, the nullifier set (to prevent double spending) would have grown by <span class="live" id="live-bytes">0 MB</span> across <span class="live" id="live-txs">0</span> transactions, amounting to <u>a petabyte every year</u>

While bigger machines could address bandwidth and compute costs, requiring every validator to store another petabyte of nullifiers each year is not practical.

> *How do we process one million private transactions per second on commodity hardware?*

To get there, we need to rethink the responsibilities of validators and wallets. A system that runs at this rate indefinitely needs:

1. **Succinct validator state.** Validator storage may grow with the number of accounts, but not with the number of transactions, and processing a transaction takes a constant amount of work regardless of how many accounts exist.
2. **Offline wallets.** Wallets can go offline for arbitrarily long periods and, upon returning, send and receive payments without replaying intervening chain history, much like traditional payments. The work a wallet does depends only on the transactions it participates in.

We are excited to share [Bonsai](/artifacts/bonsai.pdf), a private payment scheme that addresses both verification cost and state growth:

- each operation has a **256-byte payload** and the prototype verifies **over a million operations per second** on an M5 MacBook Pro (18 cores)
- validators store a **single 32-byte commitment per account** and a small number of hashes
- wallets can **go offline indefinitely** and resume without replaying intervening chain history

These performance gains come with a [privacy tradeoff](#privacy-beyond-the-ledger): observers see when an account acts, but still cannot see amounts, counterparties, or whether it sends or receives. In practice, however, we see this as a reasonable tradeoff for most users because the RPC providers and validators they submit to can already see which transactions come from whom.

## Our Construction

David Chaum introduced [ecash](https://chaum.com/wp-content/uploads/2022/01/Chaum-blind-signatures.pdf) -- the first payment system to achieve *unlinkability* between the sender and receiver via blind signatures. However, it required a central authority to participate in every transaction and maintain a globally consistent view to prevent double spending.

To remove the bank as a single point of failure, we can replace it with a committee of validators that jointly maintains the set of spent coins. Byzantine fault-tolerant consensus keeps that set consistent while providing fast confirmations at scale. With the right design (see [Multimmit](/blogs/multimmit), for example), payments from different parts of the world can be *simultaneously* ingested into the log.

Cryptographic commitments coupled with zero-knowledge proofs allow us to both hide balances and *verifiably* update them when a transfer occurs. More formally, every account can be represented by a single commitment

$$
\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}\big(b,\ \mathsf{root}_{\mathsf{null}};\ r_A\big)
$$

to its balance $b$ and the root $\mathsf{root}_{\mathsf{null}}$ of the account's nullifier tree -- a sparse Merkle tree keyed by receipt position.

A payment of $v$ from $\mathsf{Sen}$ to $\mathsf{Rec}$ is recorded onchain as a hiding commitment (receipt):

$$
\rho = \mathsf{Com}_{\mathsf{rec}}\big(v,\ \mathsf{Sen},\ \mathsf{Rec}\big),
$$
in a Merkle Mountain Range (see Peter's [documentation](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) or Roberto's [blog post](/blogs/mmr)).

The sender $\mathsf{Sen}$ also proves that:

- the account is updated correctly: $$\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}}) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b-v,\mathsf{root}_{\mathsf{null}})$$
- the receipt is created correctly: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec})$

Once the send transaction is recorded, the sender obtains its position $\mathsf{pid}$ and forwards the opening of $\rho$ together with $\mathsf{pid}$ to the receiver over a private channel.

To prevent a receipt from being claimed twice, the proof requires the receiver to insert a nullifier into their nullifier tree. Typically, such nullifiers are computed as the output of a pseudorandom function on some unique input such as $\mathsf{pid}$. But in our case, nullifiers are never published, so we can choose the nullifier to be $\mathsf{pid}$ itself!

This has two benefits:

1. the receive circuit is smaller as we avoid having to prove a PRF evaluation to derive the nullifier
2. nullifiers are ordered by when their receipts were created

As we will see shortly, the latter observation will be critical for managing wallet state growth.

To claim a receipt, $\mathsf{Rec}$ shows that:

- the account is updated correctly: $$\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}}) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b+v,\mathsf{root}_{\mathsf{null}}')$$
- the receipt is valid: $\mathsf{MMR.Verify}(\mathsf{root}_\rho,\rho,\mathsf{pid},\pi_{\mathsf{mmr}})=1$
- the receipt is addressed to the receiver: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec})$
- the nullifier is inserted correctly: $\mathsf{SMT.VerifyInsert}(\mathsf{root}_{\mathsf{null}},\mathsf{pid},\pi_{\mathsf{smt}})=\mathsf{root}_{\mathsf{null}}'$

Fees can be supported in both send and receive by revealing $v_{\mathsf{fee}}$ in the statement and proving that the new committed balance is reduced by an additional $v_{\mathsf{fee}}$.

Balances and amounts are now hidden from the ledger, but it still reveals whether an account sent or received funds. We can also hide the operation type by proving a strict disjunction of the send and receive relations. This strengthens the privacy guarantees (see Section 6.1 of the [Bonsai paper](/artifacts/bonsai.pdf) for a detailed discussion).

In the operation-hiding variant, both send and receive publish the same 256-byte payload $(A, \mathsf{com}', \rho, \mathsf{root}_\rho, \pi)$: a 32-byte account identifier, the new account commitment, a receipt, an MMR root, and a 128-byte proof.

## Scaling

We now focus on scaling the system. Inserting an element into an MMR requires only the *frontier* -- a logarithmic number of hashes -- which allows validators to prune old receipts. With $2^{40}$ receipts, we need at most 40 frontier hashes, or 1.25 KiB with 32-byte hashes.

**Pruning Nullifiers.** The real challenge lies in managing nullifier growth. For receipts, we prove *membership*; for nullifiers, we need to prove *non-membership* to prevent double spending. MMRs do not support efficient non-membership proofs, so validators cannot use the same strategy.

One approach is to shift the burden of proving non-membership to users. To spend a coin, the user must use ledger history since the coin was created to prove that it has not already been spent. The [Tachyon project](https://tachyon.z.cash/) uses [oblivious synchronization](https://eprint.iacr.org/2025/2031) to privately delegate this non-membership proof to an untrusted service, without letting the service link users to their eventual transactions. Users can be offline, but resuming requires synchronization work by the user or a service that processes the ledger.

Bonsai's account model lets validators **delegate** nullifier storage to users instead of retaining a growing global set, at the cost of less *onchain* privacy than Zcash. Each user maintains the nullifiers for payments they have received, accumulates them into a [sparse Merkle tree](https://eprint.iacr.org/2016/683), and stores the root inside their account commitment.

But won't the nullifier set eventually grow too big for users to manage? We seem to have just delayed the problem.

Users can also **prune their nullifier state**. For a threshold $L$, a wallet can summarize the claimed positions below $L$ with a frontier of at most $\ell$ hashes, where $\ell$ is the depth of the nullifier tree. It keeps all claimed positions at or above $L$. Together, these suffice to produce insertion proofs for unclaimed positions at any $\mathsf{pid} \geq L$.

Recall that nullifiers are ordered by when their receipts were created. Choosing $L$ to retain the $w$ largest claimed positions bounds the wallet's storage to $\ell$ hashes plus $w$ positions, independent of the total number of receipts it has claimed. Older nullifiers can be moved to cold storage, so a receipt below $L$ can still be claimed by retrieving the relevant path from cold storage and updating the frontier.

## From Bank to Bonsai

The simulation below follows four accounts as they make payments to one another. Use **prev** and **next** to move from a traditional bank through ecash to Bonsai, adding privacy and pruning state along the way. The same stream of payments continues across stages.

The four panels show different views of the same activity:

- **Network:** messages exchanged with the bank or validators, and private handoffs between senders and receivers.
- **Balances:** funds held in each account and payments sent but not yet claimed.
- **Ledger:** what the bank records or validators publish, showing which payment details remain visible at each stage.
- **Storage:** the data retained by the bank, validators, and wallets. Observe the growing nullifier set move to wallets, then see how pruning reduces the active state.

```{=html}
<div id="sim" role="region" aria-label="From Bank to Bonsai"></div>
```

## Privacy Beyond the Ledger

As noted earlier, [ledger indistinguishability](https://eprint.iacr.org/2014/349) in shielded-note systems provides stronger **onchain** privacy than Bonsai because it also hides which account is acting. Bonsai trades some of that privacy to keep validator storage proportional to accounts rather than transaction history.

In practice, the privacy gap may be narrower than expected. Even when the ledger hides the acting account, submission metadata can link a transaction to the underlying wallet or user. For instance, when a wallet submits transactions to an RPC node through an identifiable connection or session, the operator can group those submissions under the same user. Both the public ledger and the wallet's network connection matter when evaluating privacy in practice.

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

```{=html}
<script src="private-payments.sim.js"></script>
<script src="private-payments.counter.js"></script>
<script src="private-payments.rpc.js"></script>
```

## Scalable Private Payments

Our [prototype](https://github.com/guruvamsi-policharla/zk-pari/pull/2) uses [Pari with batch verification](/blogs/batch-pari) for its non-interactive zero-knowledge proofs (NIZKs). Pari, as described in the [original paper](https://eprint.iacr.org/2024/1245) or its [improvement](https://eprint.iacr.org/2025/1485), is not zero-knowledge. We use vanishing-polynomial masks to make it zero-knowledge, keeping the proof size at $2 \mathbb{G}_1 + \mathbb{F}$ (128 bytes), adding negligible prover overhead, and preserving the batch-verification strategy. All numbers below are measured on an M5 MacBook Pro (6 performance + 12 efficiency cores, 48 GB RAM) over BLS12-381. Measurements are single-threaded unless stated otherwise and exclude serialization, deserialization, and subgroup checks.

**Batch Verification.** We first isolate proof-system costs using a squaring circuit with $2^{12}$ constraints and one public input. Individual verification takes about $0.7$ ms; batching reduces the amortized cost to $11.7$ $\mu$s per proof. At $N = 65{,}536$, the three MSMs account for over 90% of the 771 ms total time. Computing the Fiat-Shamir challenges takes 36 ms, the statement evaluations 25 ms (with inversions batched across proofs), and the final pairings under a millisecond.

**Throughput.** Batches are independent, so each thread verifies its own 80,000-proof chunk. Scaling is sublinear because the efficiency cores are slower, but verification throughput exceeds a million transactions per second on the laptop. Here, a transaction is a single send or receive, so this corresponds to roughly 525,000 payments per second, each requiring one send and one receive.

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

**Proving.** The circuits only use a collision-resistant hash function, and we benchmark two instantiations: Pedersen hashes over Jubjub, whose security rests only on the discrete logarithm assumption, and Poseidon over the BLS12-381 scalar field. Both the receipt MMR opening and the nullifier tree have depth 40. As expected, a send is cheaper than a receive because it requires only three commitment openings and range checks. For a receive, the depth-40 MMR opening (40 hashes) and the sparse Merkle tree insertion (80 hashes) account for 120 of its 123 hash evaluations.

The operation-hiding relation $\mathcal R_{\mathsf{op}}$ is *not* the sum of the two because send is structurally a sub-relation of receive, so the circuit instantiates each shared gadget once and lets the branch bit multiplex only the inputs, adding about 8.3K (Pedersen) or 1K (Poseidon) constraints on top of receive.

| Circuit | Hash | R1CS | SR1CS | Prove<br>(1 thread) | Prove<br>(8 threads) | Verify |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| $\mathcal R_{\mathsf{send}}$ | Pedersen | 16,109 | 32,227 | 0.84 s | 0.14 s | 747 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$ | Pedersen | 398,111 | 796,231 | 20.1 s | 3.8 s | 754 $\mu$s |
| $\mathcal R_{\mathsf{op}}$ | Pedersen | 406,460 | 812,931 | 20.4 s | 3.8 s | 805 $\mu$s |
| $\mathcal R_{\mathsf{send}}$ | Poseidon | 1,647 | 3,303 | 0.14 s | 0.03 s | 806 $\mu$s |
| $\mathcal R_{\mathsf{recv}}$ | Poseidon | 30,729 | 61,467 | 1.6 s | 0.29 s | 768 $\mu$s |
| $\mathcal R_{\mathsf{op}}$ | Poseidon | 31,706 | 63,423 | 1.6 s | 0.29 s | 761 $\mu$s |

Prover timings include witness generation but exclude constraint synthesis, which is performed once per circuit. Compiling R1CS to Square R1CS roughly doubles the constraint count; supporting R1CS directly is one opportunity to reduce prover cost.

These early results show batch proof verification exceeding a million proofs per second on a laptop. Bonsai pairs that verification throughput with compact transactions and validator state that avoids a global nullifier set, while letting wallets return after long periods offline. The next step is to carry that throughput through networking, consensus, and storage into a complete private payment system.
