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

The commonware stack can now comfortably process payments at [~250K TPS](https://x.com/_patrickogrady/status/2077449338230640739) with [Constantinople](https://github.com/commonwarexyz/constantinople). Throughput is much higher with [a stable leader](https://commonware.xyz/blogs/pipelining-simplex), [multiple proposers](https://commonware.xyz/blogs/multimmit), and clearing solutions such as [bajillion](https://commonware.xyz/blogs/clearing). We now turn our attention to privacy. What's stopping us from reaching similar throughput for private payments?

Our goal is to support private payments at over a million transactions per second, with low latency. Let's suppose each transaction is $\approx 200$ bytes and takes $0.5-1$ ms to verify (using [Groth16](https://eprint.iacr.org/2016/260) with a [shielded-note scheme](https://eprint.iacr.org/2014/349), say). To support a million transactions per second:

- **bandwidth:** leaders need to disseminate <u>200 MB of data every second</u>
- **compute:** every validator needs the equivalent of <u>500-1000 dedicated CPU cores</u>
- **storage:** since you opened this page, the nullifier set (to prevent double spending) would have grown by <span class="live" id="live-bytes">0 MB</span> across <span class="live" id="live-txs">0</span> transactions, amounting to <u>a petabyte every year</u>

While bandwidth and compute costs could be overcome with bigger machines, it is simply impractical for validators to store the nullifiers.

> *How do we process one million private transactions per second on commodity hardware?*

To get there, we need to rethink what validators and wallets are responsible for. Concretely, a system that runs at this rate indefinitely needs:

1. **Succinct validator state.** Validator storage may grow with the number of accounts, but not with the number of transactions, and processing a transaction takes a constant amount of work regardless of how many accounts exist.
2. **Offline wallets.** Wallets can go offline for arbitrarily long periods and, upon returning, send and receive payments without synchronizing with the chain, just like traditional payments. The work a wallet does depends only on the transactions it participates in.

<!-- TODO: Add link to Bonsai paper -->
We are excited to share Bonsai, a private payment scheme that addresses both the verification cost and the growing state:

- each operation has a **256-byte payload** and the prototype verifies **over a million operations per second** on an M5 MacBook Pro (18 cores)
- validators store a **single 32-byte commitment value per account** and a small number of hashes
- wallets can **go offline indefinitely** and resume without synchronizing state with the chain

An external observer learns that a particular account came online and performed some
action (a send or receive), but does not learn the amount or the counterparty.
<!-- todo: add a pointer to below discussion against zcash -->

## Our Construction

David Chaum introduced [ecash](https://chaum.com/wp-content/uploads/2022/01/Chaum-blind-signatures.pdf) -- the first payment system to achieve *unlinkability* between the sender and receiver via blind signatures. However, a central authority must participate in every single transaction and maintain a globally consistent view to prevent double spending.

To provide much faster confirmations and scale with confidence, the most natural strategy is to use a consensus algorithm that provides Byzantine fault tolerance. The bank can be replaced by a committee of validators. With the right design (see [Multimmit](https://commonware.xyz/blogs/multimmit), for example), payments from different parts of the world can be *simultaneously* ingested into the log.

However, this introduces additional privacy concerns: anyone reading the ledger sees every balance and every account's inflow and outflow.

Cryptographic commitments coupled with zero-knowledge proofs allow us to both hide balances and *verifiably* update them when a transfer occurs. More formally, every account can be represented by a single commitment

$$
\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}\big(b,\ \mathsf{root}_{\mathsf{null}};\ r_A\big)
$$

to its balance $b$ and the root $\mathsf{root}_{\mathsf{null}}$ of the account's nullifier tree -- a sparse Merkle tree keyed by receipt position.

A payment of $v$ from $\mathsf{Sen}$ to $\mathsf{Rec}$ is recorded on chain as a hiding commitment (receipt):

$$
\rho = \mathsf{Com}_{\mathsf{rec}}\big(v,\ \mathsf{Sen},\ \mathsf{Rec}\big),
$$
in a Merkle Mountain Range (MMR; see Peter's [doc](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) or Roberto's [blog post](https://commonware.xyz/blogs/mmr)).

The sender $\mathsf{Sen}$ additionally proves that:

- the account is updated correctly: $$\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}}) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b-v,\mathsf{root}_{\mathsf{null}})$$
- the receipt is created correctly: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec})$

Once the send transaction lands, the sender reads off its position $\mathsf{pid}$ and forwards the opening of $\rho$ together with $\mathsf{pid}$ to the receiver over a private channel.

To prevent a receipt from being claimed twice, the proof requires the receiver to insert a nullifier into their nullifier tree. Typically, such nullifiers are computed as the output of a pseudorandom function on some unique input such as $\mathsf{pid}$. But in our case, nullifiers are never published, so we can choose the nullifier to be $\mathsf{pid}$ itself!

This has two nice implications:

1. the receive circuit is smaller as we avoid having to prove a PRF evaluation to derive the nullifier
2. nullifiers are temporally ordered according to the time at which the receipt was created

As we will see shortly, the latter observation will be critical for managing wallet state growth.

To claim a receipt, $\mathsf{Rec}$ shows that:

- the account is updated correctly: $$\mathsf{com} = \mathsf{Com}_{\mathsf{acct}}(b,\mathsf{root}_{\mathsf{null}}) \wedge \mathsf{com}' = \mathsf{Com}_{\mathsf{acct}}(b+v,\mathsf{root}_{\mathsf{null}}')$$
- the receipt is valid: $\mathsf{MMR.Verify}(\mathsf{root}_\rho,\rho,\mathsf{pid},\pi_{\mathsf{mmr}})=1$
- the receipt is addressed to the receiver: $\rho = \mathsf{Com}_{\mathsf{rec}}(v,\mathsf{Sen},\mathsf{Rec})$
- the nullifier is inserted correctly: $\mathsf{SMT.VerifyInsert}(\mathsf{root}_{\mathsf{null}},\mathsf{pid},\pi_{\mathsf{smt}})=\mathsf{root}_{\mathsf{null}}'$

Fees can be supported in both send and receive by revealing $v_{\mathsf{fee}}$ in the statement and proving that the new committed balance is reduced by an additional $v_{\mathsf{fee}}$.

Balances and amounts are now hidden from the ledger, but it still reveals whether an account sent or received funds. We can take this one step further to also hide the operation type by proving a strict disjunction of the send and receive relations. This provides meaningful improvements to the privacy guarantees (see section 6.1 of the Bonsai paper for a detailed discussion).

In the operation-hiding variant, both send and receive publish the same 256-byte payload $(A, \mathsf{com}', \rho, \mathsf{root}_\rho, \pi)$: a 32-byte account identifier, the new account commitment, a receipt, an MMR root, and a 128-byte proof.

## Scaling

We now focus on scaling the system. First, observe that inserting an element in an MMR only requires the *frontier* -- a logarithmic number of hashes -- which allows the validators to prune old receipts. For the concrete case of $2^{40}$ receipts, we need at most 40 frontier hashes, or 1.25 KiB with 32-byte hashes.

**Pruning Nullifiers.** The real challenge lies in managing the nullifier growth. Unlike receipts where we prove *membership*, we need to prove *non-membership* of nullifiers to prevent double spending. MMRs do not support (efficient) non-membership proofs so validators cannot use the same strategy.

One approach is to shift the burden of non-membership to the users. To spend a coin, the user must prove that it has not already been spent, using the ledger's history since the coin was created. The [Tachyon project](https://tachyon.z.cash/) uses [oblivious synchronization](https://eprint.iacr.org/2025/2031) to privately delegate this non-membership proof to an untrusted service, without letting those services link them to their eventual transactions. Users can be offline, but resuming requires synchronization work by the user or a service that processes the ledger.

Bonsai has the benefit of working in the account based model and albeit providing less *on-chain* privacy than Zcash, it offers a simpler approach to **delegate** nullifier storage. As described above, each user maintains the nullifiers for any payments they received, accumulates them into a [sparse Merkle tree](https://eprint.iacr.org/2016/683) and stores the root inside their account commitment.

But won't the nullifier set eventually grow too big for users to manage? We seem to have just delayed the problem.

We observe that users can also **prune their nullifier state**. For a threshold $L$, a wallet can summarize the claimed positions below $L$ with a frontier of at most $\ell$ hashes, where $\ell$ is the depth of the nullifier tree. It keeps all claimed positions at or above $L$. Together, these suffice to produce insertion proofs for unclaimed positions at any $\mathsf{pid} \geq L$.

Recall that the nullifiers are temporally ordered based on the time the receipt was created. Choosing $L$ to retain the $w$ largest claimed positions bounds the wallet's storage to $\ell$ hashes plus $w$ positions, independent of the total number of receipts it has claimed. Older nullifiers can be pushed to cold storage, so a receipt below $L$ can still be claimed by retrieving the relevant path from cold storage and updating the frontier.

## An Interactive Example

The simulation below follows four accounts making payments to one another. Use **prev** and **next** to move from a traditional bank through ecash to Bonsai, adding privacy and pruning state along the way. The same stream of payments continues across stages.

The four panels show different views of the same activity:

- **Network:** messages exchanged with the bank or validators, and private handoffs between senders and receivers.
- **Balances:** funds held in each account and payments sent but not yet claimed.
- **Ledger:** what the bank records or validators publish, showing which payment details remain visible at each stage.
- **Storage:** the data retained by the bank, validators, and wallets. Observe the growing nullifier set move to wallets, then see how pruning reduces the active state.

```{=html}
<div id="sim" role="region" aria-label="From a bank to our construction."></div>
```

## Privacy Beyond the Ledger

As noted earlier, [ledger indistinguishability](https://eprint.iacr.org/2014/349) in shielded-note systems provides stronger **on-chain** privacy than Bonsai because it also hides which account is acting. But Bonsai comes with the benefit of a much simpler solution for nullifier management.

In practice, the privacy gap may be narrower than expected. Even when the ledger hides the acting account, there are several ways to map a transaction to the underlying wallet or user. For instance, when a wallet submits transactions through an RPC node, the node can already link each submitted transaction to the corresponding party. Similarly, if a wallet submits its own transactions through an identifiable connection or session, the operator can group those submissions under the same user. Both the public ledger and the wallet's network connection matter when evaluating privacy in practice.

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

A prototype of our payment system with the NIZK instantiated using [Pari + batch verification](https://commonware.xyz/blogs/batch-pari) can be found [here](https://github.com/guruvamsi-policharla/zk-pari/pull/2). Pari, as described in the [original paper](https://eprint.iacr.org/2024/1245) or its [improvement](https://eprint.iacr.org/2025/1485), is not zero-knowledge. We use vanishing-polynomial masks to make it zero-knowledge, keeping the proof size at $2 \mathbb{G}_1 + \mathbb{F}$ (128 bytes), adding negligible prover overhead, and preserving the batch-verification strategy. All numbers below are measured on an M5 MacBook Pro (6 performance + 12 efficiency cores, 48 GB RAM) over BLS12-381. Measurements are single-threaded unless stated otherwise and exclude serialization, deserialization, and subgroup checks.

**Batch Verification.** We first isolate proof-system costs using a squaring circuit with $2^{12}$ constraints and one public input. Individual verification takes about $0.7$ ms; batching reduces the amortized cost to $11.7$ $\mu$s per proof. At $N = 65{,}536$, the three MSMs account for over 90% of the 771 ms total time. Computing the Fiat-Shamir challenges takes 36 ms, the statement evaluations 25 ms (with inversions batched across proofs), and the final pairings under a millisecond.

**Throughput.** Batches are independent, so we shard them across threads with nothing shared, each thread verifying its own 80,000-proof chunk. Scaling is sublinear because the efficiency cores are slower, but it crosses a million transactions per second on the laptop, where a transaction is a single send or receive (so roughly 525,000 payments per second, each being one send and one receive).

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

These early results put batch proof verification above a million proofs per second on a laptop. Bonsai pairs that progress with compact transactions and validator state that avoids a global nullifier set, while letting wallets return from long periods offline. The next step is to carry that throughput through networking, consensus, and storage into a complete private payment system.
