---
title: "Minimal Extractable Value"
description: ""
date: "April 17th, 2026"
published-time: "2026-04-17T00:00:00Z"
modified-time: "2026-04-17T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/gvamsip"
url: "https://commonware.xyz/blogs/bte"
image: "https://commonware.xyz/imgs/bte.png"
katex: true
---

A threshold encryption scheme is a cryptographic primitive that allows users to encrypt messages to a committee of $n$ parties such that *any* $t$ out of $n$
 members can *non-interactively* decrypt the message.

A popular application of threshold encryption are encrypted mempools, to protect the privacy of pending transactions. Users encrypt transactions to a validator set, who wait to finalize them before decryption. However, decrypting $B$ ciphertexts requires $O(nB)$ communication to broadcast the decryption shares to the network. This can be orders of magnitude larger than the block itself!

[*Batched* Threshold Encryption (BTE)](https://eprint.iacr.org/2024/669) addresses this communication bottleneck.
It enables the committee to decrypt a *batch* of $B$ ciphertexts using sub-linear communication $o(nB)$. A long line of work has shown that it's in fact possible to design BTE schemes with communication complexity $O(n)$ which is *independent* of the batch size.

Up until recently, all constructions of BTE suffered from one of two issues:
- ***Epoch restriction***: ciphertexts must be encrypted to a certain batch number (epoch). Failure to be included in the chosen epoch would result in the ciphertext never being decrypted.
- ***Censorship issues***: users must pick a *position* in the batch. This leaves transactions vulnerable to censorship: an attacker can outbid a victim for a conflicting position and thereby block inclusion of the victim's transaction.

These issues have been addressed, with some caveats:
- [FPTX25](https://eprint.iacr.org/2025/2032) increases the CRS size to $O(kB)$ where $k$ is the number of batches that can be decrypted before the public key must be refreshed. The setup is a simple DKG protocol and the decryption complexity is $O(B\log^2{B})$.
- [BNRT26](https://eprint.iacr.org/2026/674) uses partial fraction techniques to avoid the epoch restriction and censorship issues but comes at the cost of a more complicated setup phase which requires secure inversions in MPC and the size of secret keys held by each party to grow with the batch size. Although the current version of the [paper](https://eprint.iacr.org/archive/2026/674/20260406:214807) describes a construction with $O(B^2)$ decryption complexity, the authors have communicated privately to us that they have a more efficient decryption algorithm with $O(B\log{B})$ complexity.

## Our Construction

We now describe a simple construction of BTE where the CPA ciphertext size is $|\mathbb{G}_1| + |\mathsf{msg}|$. On the BLS12-381 curve, this amounts to 48 bytes + $|\mathsf{msg}|$, which is only 16 bytes longer than threshold ElGamal.
The construction can be made CCA secure with a ZK proof, increasing the ciphertext size by $2|\mathbb{F}|$ (64 bytes).

Similar to [BNRT26](https://eprint.iacr.org/2026/674), the setup phase requires secure multiplications in MPC and the size of secret keys held by each party grows with the batch size. However, [BNRT26](https://eprint.iacr.org/2026/674) has a larger CPA ciphertext size of $2|\mathbb{G}_1| + |\mathsf{msg}|$ and a Schnorr-style proof for CCA security adds $3|\mathbb{F}|$ bytes.

For simplicity, we first describe the CPA-secure core of the construction
for a single server. We then explain how to add CCA security via a
ZK proof and how to thresholdize the scheme.

- A trusted party runs the setup protocol and publishes the encryption
  key together with the punctured powers-of-$\tau$ values needed for
  decryption:

  $$
  \mathsf{ek} := [\tau^{B+1}]_T
  \qquad\text{and}\qquad
  \mathsf{dk} := \left(\{h_j := [\tau^j]_2\}_{j\in[2B]\setminus\{B+1\}}\right)
  $$

- Encryption is then just an ElGamal-style ciphertext:

  $$
  \mathsf{ct} := \left([k]_1,\; m + [k\tau^{B+1}]_T\right)
  $$

- To decrypt a batch $(\mathsf{ct}_i)_{i\in[B]}$, let
  $\mathsf{ct}_i=(\mathsf{ct}_{i,1},\mathsf{ct}_{i,2})$. It is then sufficient to publish:

  $$
  \mathsf{pd} := \sum_{i\in[B]} \tau^i\cdot \mathsf{ct}_{i,1}
  = \left[\sum_{i\in[B]} k_i\tau^i\right]_1
  $$

- One can then decrypt the $i$-th ciphertext by computing:

  $$
  [k_i \tau^{B+1}]_T
  = \mathsf{pd}\circ h_{B+1-i}
  - \sum_{\substack{\ell\in[B]\\\ell\ne i}}
  \mathsf{ct}_{\ell,1}\circ h_{\ell+B+1-i}
  $$

  $$
  m_i = \mathsf{ct}_{i,2} - [k_i \tau^{B+1}]_T
  $$


**CCA Security:** To make the scheme CCA-secure, we can augment each ciphertext with
a straight-line simulation-extractable NIZK proof of knowledge of $k$ with $\mathsf{ct}_{i,2}$ as the tag:
$$
\pi_i := \left\{k \mid \mathsf{ct}_{i,1} = [k]_1 \wedge \mathsf{ct}_{i,2} \right\}
$$


**Thresholdization:** To thresholdize this scheme, we secret share $\{\tau^i\}_{i\in[B]}$ among
  the $N$ servers. Concretely, let server $j$ hold shares
  $(\sigma^i_j)_{i\in[B]}$ of $(\tau^i)_{i\in[B]}$ and return the partial
  decryption

  $$
  \mathsf{pd}_j := \sum_{i\in[B]} \sigma_j^i\cdot \mathsf{ct}_{i,1}
  $$

  Given any set $T$ of $t$ valid partial decryptions, one can reconstruct
  the aggregate value $\mathsf{pd}$ in the exponent via Lagrange
  interpolation:

  $$
  \mathsf{pd} = \sum_{j\in T} \lambda_j \mathsf{pd}_j
  $$

  where $(\lambda_j)_{j\in T}$ are the Lagrange coefficients for the shares
  indexed by $T$.

  To additionally enable verification of these shares publicly, we can publish
  $\{v_j^i := [\sigma_j^i]_2\}_{(i,j)\in[B]\times[N]}$ as part of the
  trusted setup. Correctness of partial decryptions can then be verified by
  checking whether

  $$
  \mathsf{pd}_j \circ g_2 = \sum_{i\in[B]} \mathsf{ct}_{i,1}\circ v_j^i
  $$

A more formal presentation can be found in the [paper](/imgs/bte.pdf).

## Accelerating Decryption via FFT

For the $i$-th ciphertext, decryption computes
$$
z_i = \mathsf{pd}\circ h_{B+1-i}
- \sum_{\substack{\ell\in[B]\\ \ell \ne i}}
\mathsf{ct}_{\ell,1}\circ h_{\ell+B+1-i}
$$
The bottleneck in decryption is computing the cross-term
$$
C_i := \sum_{\substack{\ell\in[B]\\ \ell \ne i}}
\mathsf{ct}_{\ell,1}\circ h_{\ell+B+1-i}
$$
If we compute each $C_i$ independently, then we end up doing $\Theta(B^2)$
pairings overall.

The key observation is that this sum has a convolution structure and a
Fourier Transform can be used to speed up decryption. Concretely, we form
a zero-padded length-$2B$ sequence $(a_i)_{i\in[2B]}$
$$
a_i :=
\begin{cases}
\mathsf{ct}_{i,1} & \text{for } i\in[B],\\
0 & \text{for } i\in\{B+1,\ldots,2B\},
\end{cases}
$$
and a length-$2B$ sequence $(b_d)_{d=-B}^{B-1}$
$$
b_d :=
\begin{cases}
h_{B+1+d} & \text{for } d\in\{-(B-1),\ldots,-1,1,\ldots,B-1\},\\
0 & \text{for } d\in\{-B,0\}.
\end{cases}
$$

Then:

1. Take an FFT of the $\mathbb{G}_1$ sequence.
2. Take an FFT of the $\mathbb{G}_2$ sequence (this can be preprocessed,
   since it depends only on the public parameters and not on the ciphertexts).
3. Pair the transformed values pointwise.
4. Apply the inverse FFT in $\mathbb{G}_T$.

This computes all of the cross-terms $C_i$ using $O(B\log{B})$ group operations and $O(B)$ pairings.

## Evaluation and Discussion

We implemented a prototype of the construction in Rust and benchmarked the FFT-accelerated
decryption on an M5 MacBook Pro in single-threaded mode (available [here](https://github.com/commonwarexyz/simple-bte)). Decryption time also accounts for verification of NIZK proofs.
We also expect decryption to scale well with parallelization.
Despite the interactive setup phase, we only need to carry it out once, and rotation of committees can be achieved via resharing of secrets.

<div align="center">

| Batch size $B$ | Ours | [FPTX25](https://eprint.iacr.org/2025/2032) | [ABD+25](https://eprint.iacr.org/2025/2115) |
|:--------------:|:----:|:------------:|:---------:|
| 32 | 121.81 ms | 100.7 ms | 301 ms |
| 128 | 593.62 ms | 638.4 ms | 1.4 s |
| 512 | 2.79 s | 5.39 s | 6.6 s |
| 2048 | 12.82 s | 46.2 s | 28.4 s |

</div>

[BNRT26](https://eprint.iacr.org/2026/674) does not have a public implementation to compare against.

In conclusion, our construction is a conceptually simple and efficient BTE scheme with no caveats of epoch restrictions or censorship issues coupled with a performance win!