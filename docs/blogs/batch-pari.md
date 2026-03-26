---
title: "The Proof is in the Pairing"
description: "Blockchains are especially well-suited for two use cases: payments and trading. We’ve made real progress in scaling these systems with many chains supporting 10K–100K TPS. But what happens when we introduce privacy?"
date: "March 24th, 2026"
published-time: "2026-03-24T00:00:00Z"
modified-time: "2026-03-24T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/gvamsip"
url: "https://commonware.xyz/blogs/batch-pari"
image: "https://commonware.xyz/imgs/batch-pari.png"
katex: true
---

Blockchains are especially well-suited for two use cases: payments and trading. We’ve made real progress in scaling these systems with many chains supporting 10K–100K TPS. But what happens when we introduce privacy?

Recall that there are really only two tools at our disposal:

- zero-knowledge proofs for private payments, smart contracts, and zk-identity
- *advanced* encryption schemes for privacy of pending bids/trades

The chain (validators) needs to verify every proof and decrypt every ciphertext to process the block. Very loosely speaking, this translates to a "few" public key operations (exponentiations/pairings) per transaction when using pairing-based techniques. Note that this is (asymptotically) optimal, so doing much better is difficult. So if we budget $\approx 1$ ms privacy overhead per transaction (about the time taken for a pairing on BLS12-381), processing 100K transactions requires 100s in single-core CPU time. Assuming perfect parallelization, we can of course reach 100K TPS with 100 cores—or a GPU—but this is deeply unsatisfying both cryptographically and because it places specialized hardware requirements on validators.

## Verifying zkSNARKs at Scale

Note that if we just want to quickly verify proofs on chain, there are known techniques that utilize an untrusted third party to reduce the cost of verification on chain ([MBK+19](https://eprint.iacr.org/2019/099), [BMM+19](https://eprint.iacr.org/2019/1177), [GMN21](https://eprint.iacr.org/2021/529)). In fact, [GMN21](https://eprint.iacr.org/2021/529) shows that verification time can be sub-linear in the number of proofs.

But this strategy comes with two limitations:

1. introduces an extra "hop" in each slot from proposer $\rightarrow$ aggregator $\rightarrow$ validator, which in turn increases latency
2. relies on availability of the aggregator to maintain the system's throughput

**Our goal:** fast verification of SNARKs on chain with <i><b><u>zero latency overhead</u></b></i> and no additional assumptions.

The zero-latency requirement immediately disallows any strategy that *delegates* verification to a third party. This also means that verification cannot be sub-linear time, as validators need to, at the very least, read all proofs in the block.
Giving up sub-linear verification might seem like we're going in the opposite direction of scaling, but in practice validators typically still perform a non-trivial amount of work for each transaction. In private payments, for instance, they update the state with newly minted UTXOs and check nullifiers to prevent double spending. Thus, if we can drive *amortized* proof verification costs down to roughly the cost of transaction processing/dissemination, we are in very good shape.

### Our Solution

While it's true that we can't verify individual proofs any faster, verifying a *batch* of proofs can be much faster. Similar ideas can be traced back to the early days of pairing-based signatures and Groth-Sahai proofs (see [CHP07](https://eprint.iacr.org/2007/172), [FGHP09](https://eprint.iacr.org/2008/015.pdf), and [BFI+10](https://eprint.iacr.org/2010/040.pdf)). In fact, the ZCash team also [discussed](https://github.com/zcash/zcash/issues/2465#issuecomment-310745119) batch verification of Groth16 proofs in the context of private payments back in 2017.

Our starting point is the Pari proof system ([DMS24](https://eprint.iacr.org/2024/1245)), which was later improved in Glock ([Eagen25](https://eprint.iacr.org/2025/1485)). We recall the verification algorithm:

1. Parse the verification key $\textsf{ivk} = ((A,B), [\alpha]_1, [\beta]_1, [\delta_1]_2, [\delta_2]_2, [\tau]_2, [\delta_1 \tau]_2)$, where $A$ and $B$ form the square R1CS relation.
2. Parse the proof $\pi = (T, U, v_a, v_b) \in \mathbb{G}_1^2 \times \mathbb{F}^2$.
3. Compute the challenge $r := H(\textsf{transcript})$.
4. Compute $x_A := A \cdot (x \| 0)$ and $x_B := B \cdot (x \| 0)$, and interpolate over domain $K$ to obtain polynomials $\hat{x}_A$ and $\hat{x}_B$.
5. Compute the quotient evaluation, where $z_K$ is the vanishing polynomial on the domain $K$:

    $$v_q := \frac{(v_a + \hat{x}_A(r))^2 - (v_b + \hat{x}_B(r))}{z_K(r)}$$

6. Check the pairing equation:

    $$e(T,\; [\delta_2]_2) \stackrel{?}{=} e(U,\; [\delta_1 \tau]_2 - r \cdot [\delta_1]_2) \cdot e(v_a \cdot [\alpha]_1 + v_b \cdot [\beta]_1 + v_q \cdot [1]_1,\; [1]_2)$$

Rearranging the last equation, we have:

$$e(\colorbox{lightgrey}{$T$},\; [\delta_2]_2) \stackrel{?}{=} e(\colorbox{lightgrey}{$U$},\; [\delta_1 \tau]_2) \cdot e(\colorbox{lightgrey}{$-r \cdot U$},\; [\delta_1]_2) \cdot e(\colorbox{lightgrey}{$v_a$} \cdot [\alpha]_1 + \colorbox{lightgrey}{$v_b$} \cdot [\beta]_1 + \colorbox{lightgrey}{$v_q$} \cdot [1]_1,\; [1]_2)$$

where only the $\colorbox{lightgrey}{\text{highlighted}}$ terms change across different proofs (under the same verification key). Thus, we can batch verify multiple proofs (see [FGHP09](https://eprint.iacr.org/2008/015.pdf)) by taking a random linear combination using three $\mathbb{G}_1$ MSMs for the $T, U, r\cdot U$ terms, field multiplications for the $v_a, v_b, v_q$ terms, and finally checking a single multi-pairing. Of course, we still need to carry out steps 1-5 for each proof, but these are very fast hashing and field operations.
This strategy applies more broadly to KZG opening proofs and KZG-based SNARKs such as Plonk. For example, [gnark](https://github.com/Consensys/gnark/blob/6e6960808dfdc41e56d089d870f12ce2bc7f8289/std/recursion/plonk/verifier.go#L946-L973) uses it for more efficient recursion of Plonk proofs.

A quick implementation (with room for further optimization) of this idea can be found [here](https://github.com/guruvamsi-policharla/garuda-pari/pull/1), and it shows a $60\times$ speedup when verifying $2^{16}$ proofs relative to naive individual verification. Both experiments were run in single-threaded mode. Concretely, this amounts to $\approx 10\mu\text{s}$ per proof on an M5 MacBook Pro, down from 0.6 ms per proof. And the more proofs you verify, the faster it gets!

<div align="center">

| N | Individual | Batch | Speedup |
|:---:|:---:|:---:|:---:|
| 2 | 1.361 ms | 0.882 ms | 1.54x |
| 32 | 19.123 ms | 2.007 ms | 9.53x |
| 512 | 303.118 ms | 9.934 ms | 30.51x |
| 8192 | 4834.206 ms | 100.030 ms | 48.33x |
| 65536 | 38307.696 ms | 644.543 ms | 59.43x |

</div>

Even at just 32 proofs, we see an order-of-magnitude speedup in verification time. If we can bring down gas costs proportionally, verifying a SNARK can be cheaper than an ERC-20 transfer. A parallel implementation using 8 threads is able to verify over 500K proofs in $<750$ ms.

<div align="center">

| N | Individual | Parallel Batch | Speedup |
|:---:|:---:|:---:|:---:|
| 16 | 8.898 ms | 1.635 ms | 5.44x |
| 256 | 154.882 ms | 3.124 ms | 49.58x |
| 4096 | 2456.701 ms | 14.391 ms | 170.71x |
| 65536 | 38665.625 ms | 120.024 ms | 322.15x |
| 524288 | 311908.648 ms | 735.246 ms | 424.22x |

</div>

Any project currently using Groth16 proofs can use Pari/Glock as a **drop-in replacement**. In fact, you don't even have to rewrite circuits as the Pari proof system can be extended to support standard R1CS circuits (see Remark 2.3 in [DMS24](https://eprint.iacr.org/2024/1245)) by increasing the proof size to 2 $\mathbb{G}_1$ elements and 3 $\mathbb{F}$ elements.

Stay tuned for our upcoming posts on scaling timelock encryption and batched threshold encryption for encrypted mempools!