---
title: "Pick Your Poison"
description: "Every construction of batched threshold encryption comes with caveats of epoch restrictions, censorship issues, or a complicated setup. Pick your poison. Or two?"
date: "July 22nd, 2026"
published-time: "2026-07-22T00:00:00Z"
modified-time: "2026-07-22T00:00:00Z"
author: "Guru Vamsi Policharla"
author_twitter: "https://x.com/guruvamsip"
url: "https://commonware.xyz/blogs/pick-your-poison"
image: "https://commonware.xyz/imgs/pick-your-poison.png"
katex: true
---

Encrypted mempools have emerged as the leading candidate for protecting the privacy of pending transactions. At a high level, users (threshold) encrypt transactions to the validator set, and once the chain fixes an ordering, validators quickly decrypt transactions and execute them. If we instantiate this scheme using a standard threshold encryption scheme such as ElGamal, each of the $n$ committee members must broadcast a decryption share for each of the $B$ ciphertexts in the block, for a total of $O(nB)$ communication, which can be orders of magnitude larger than the block itself.

[Batched threshold encryption](https://eprint.iacr.org/2024/669) (BTE) was introduced to address this communication bottleneck. Instead of decrypting ciphertexts independently, the committee publishes a *succinct* key that can be used to decrypt the entire batch of ciphertexts. Since the original construction of [CGPP24](https://eprint.iacr.org/2024/669), a long line of work has pushed (silent) batched threshold encryption schemes closer to practicality. We summarize them below.

```{=html}
<div id="pick-your-poison-magic-move" class="cw-magic-move" role="img" aria-label="Animated transition from the batched threshold encryption landscape to pick-your-poison tradeoffs.">
  <noscript>
    This section contains an animated transition from the batched threshold encryption landscape to pick-your-poison tradeoffs.
  </noscript>
</div>
<script type="module" src="pick-your-poison.magic-move.js?v=4"></script>
```

::: {#pick-your-poison-story-source .cw-magic-story-source}
The initial work of [CGPP24](https://eprint.iacr.org/2024/669) required a setup involving secure multiplications in MPC, and the size of secret keys held by each party grows with the batch size. They additionally required an interactive setup involving a constant number of secure multiplications for every batch that was decrypted.

Follow-up work [CGPW25](https://eprint.iacr.org/2024/1516) and [AFP25](https://eprint.iacr.org/2024/1575) simplified the construction to a one-time DKG setup at the start of the protocol, but ciphertexts needed to be encrypted to a particular batch number, which we refer to as an "epoch restriction". Failing to be included in the chosen batch would result in the ciphertext never being decrypted. Decryption requires $O(B \log^2{B})$ group operations.

Concurrently, [BFOQ25](https://eprint.iacr.org/2024/1533) used very different techniques to also require just a one-time DKG setup, without the epoch restriction. However, the ciphertexts needed to be encrypted to a particular *index* in the batch. As a result, two conflicting transactions encrypted to the same index could not be included in the same batch. This gives rise to a censorship issue, where an attacker can censor a victim's transaction by paying a slightly higher priority fee.

[ABDGMPRY25](https://eprint.iacr.org/2025/2115) improved [BFOQ25](https://eprint.iacr.org/2024/1533) to support quasi-linear decryption $O(B \log{B})$ and weighted threshold decryption but suffered from the same censorship issues.
They also propose a variant where censorship resistance can be improved by increasing the ciphertext size by essentially encrypting to multiple indices in the batch.

[FPTX25](https://eprint.iacr.org/2025/2032) shows that the epoch restriction in [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575) can be avoided if the CRS is allowed to grow with the number of batches $q$ that will *ever* be decrypted. Importantly, after $q$ decryption queries the public key must be re-sampled. Decryption requires $O(B \log^2{B})$ group operations.

[BNRT26](https://eprint.iacr.org/2026/674) took a different approach and showed that if the committee is willing to pay for a more complicated setup, it is possible to avoid both the epoch restriction and censorship issues. Concretely, they use partial fraction techniques and their setup involves secure inversions in MPC. The size of secret keys held by each party grows with the batch size. Decryption requires $O(B \log{B})$ group operations.

[Pol26a](https://eprint.iacr.org/2026/760) and [ADGRS26](https://eprint.iacr.org/2026/754) use a similar strategy but with a different algebraic structure -- "punctured powers-of-tau" -- to avoid the epoch restriction and censorship issues. Their setup uses secure multiplications and the size of secret keys held by each party grows with the batch size. Decryption requires $O(B \log{B})$ group operations but is slightly more efficient than [BNRT26](https://eprint.iacr.org/2026/674).

In a different line of work, [BCFGOPQW25](https://eprint.iacr.org/2025/1419) (suffers from censorship issues) and [GWWW25](https://eprint.iacr.org/2025/2103) (suffers from epoch restrictions) avoid interactive setup entirely and show that it is possible to have a batched threshold encryption scheme with Silent Setup (just a PKI).
:::

::: {#pick-your-poison-dream-source .cw-magic-dream-source}
Unfortunately, every single construction comes with caveats of epoch restrictions, censorship issues, or a complicated setup.

[The dream goal]{#dream-goal} is:

::: {data-align="center"}
> *A batched threshold encryption scheme with a constant-sized ciphertext, DKG/silent setup, quasi-linear decryption, and no censorship issues/epoch restrictions*
:::

but so far, all constructions fall short. Pick your poison. Or two?
:::

## (Just) A Little Bit of Everything

Observe that each construction occupies an extreme point in the tradeoff space.

- [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575), [GWWW25](https://eprint.iacr.org/2025/2103): no censorship issues and DKG/silent setup at the cost of epoch restrictions
- [BFOQ25](https://eprint.iacr.org/2024/1533), [ABDGMPRY25](https://eprint.iacr.org/2025/2115), [BCFGOPQW25](https://eprint.iacr.org/2025/1419): no epoch restrictions and DKG/silent setup at the cost of censorship issues
- [FPTX25](https://eprint.iacr.org/2025/2032): no censorship issues/epoch restrictions and DKG setup at the cost of a much larger CRS and forced DKG re-setup after a predetermined number of batches
- [BNRT26](https://eprint.iacr.org/2026/674), [Pol26a](https://eprint.iacr.org/2026/760), [ADGRS26](https://eprint.iacr.org/2026/754): no censorship issues/epoch restrictions at the cost of a complicated $O(B)$ circuit size MPC setup and $O(B)$ secret key size

In practice, it may be more interesting to consider a smooth tradeoff on the Pareto frontier.

## Two New Results

### Censorship Resistance v Secret Key Size

We quantify censorship resistance as the minimum number of ciphertexts an attacker needs to include in a batch before a victim's transaction is forced to be excluded.
Ideally, censorship resistance is the same as the maximum batch size $B$, i.e. censoring a transaction is as expensive as buying up the entire block.
[BFOQ25](https://eprint.iacr.org/2024/1533), [ABDGMPRY25](https://eprint.iacr.org/2025/2115) only achieve a censorship resistance of $1$ (without increasing ciphertext size).

[BNRT26](https://eprint.iacr.org/2026/674), [Pol26a](https://eprint.iacr.org/2026/760), [ADGRS26](https://eprint.iacr.org/2026/754) achieve maximum censorship resistance $B$ but they all have an $O(B)$ secret key size. This makes changing the committee at large batch sizes $B \gg n$ quite expensive as it requires $O(B/n)$ DKGs to reshare the secrets to the new committee even with the trick of [Hyper-Invertible Matrices](https://cs.au.dk/fileadmin/www.cfem.au.dk/Downloads/MPC_workshop/Martin_Hirt_slides-stacked.pdf).

> What if we could give up *some* censorship resistance in exchange for *shorter* secret keys?

It may be acceptable to reduce the price of censorship to buying $10\%$ of the block (say), if we can proportionally reduce the cost of resharing secrets.

In an updated version of [Pol26a](https://eprint.iacr.org/2026/760), we introduce Indexed Simple BTE, where the secret key size can be reduced from $O(B)$ to $O(\delta)$ to support a censorship resistance of $\delta$.

### Epoch Restrictions v Forced DKG Re-setup

[FPTX25](https://eprint.iacr.org/2025/2032) avoids censorship issues and epoch restrictions at the cost of a much larger $O(qB)$ CRS and a forced DKG re-setup after decrypting $q$ batches. In practice, deployments would choose $q$ large enough to support the *expected* number of batch decryptions over the committee rotation period, which typically lasts from a few hours to a few days.

But this might be overkill for the epoch restriction issue. Recall that in [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575), users had to "guess" the block height at which their transaction would be included, which is infeasible. But what if the user only had to guess a *window* of blocks in which their transaction could be included?

> What if we accept *some* epoch restrictions but are able to avoid a forced DKG re-setup?

Naively, one can encrypt to multiple blocks, but this increases the ciphertext size linearly with the number of blocks. In [Pol26b](https://eprint.iacr.org/2026/1452), we construct Labeled Multi-Key Batched IBE, a batched threshold encryption scheme where we can decrypt $q$ different batches per label (epoch). Each user still encrypts to an epoch but each epoch now contains $q$ blocks, making it much more reliable to guess the current epoch number. Although we still require a larger $O(qB)$ CRS, $q$ can be chosen to be much smaller than in [FPTX25](https://eprint.iacr.org/2025/2032) as we only need the window to be long enough to ensure transactions are included. We also avoid the forced DKG re-setup as the same CRS and public key can be used across different epochs.

```{=html}
<div id="pick-your-poison-new-constructions" class="cw-magic-final" role="img" aria-label="The batched threshold encryption landscape extended with the new Indexed Simple BTE and Labeled Multi-Key Batched IBE constructions."></div>
```

As of this writing, no efficient construction achieves [the dream goal](#dream-goal). System designers are forced to make undesirable compromises. Indexed Simple BTE and Labeled Multi-Key Batched IBE make these compromises tunable, allowing deployments to choose the balance that best fits their operating constraints.
