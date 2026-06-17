# Pick Your Poison

Encrypted mempools are an attractive way of building. Users encrypt transactions to the validators set which protects the privacy of pending transactions from block producers before transactions have been included on chain. Once the chain fixes an ordering, validators need to quickly decrypt transactions.

However, if we use a standard threshold encryption scheme such as ElGamal, each of the $n$ committee members must broadcast a decryption share for each of the $B$ ciphertexts in the block, for a total of $O(nB)$ communication, which can be orders of magnitude larger than the block itself. Batched threshold encryption (BTE) was introduced to address exactly this bottleneck. Instead of decrypting each ciphertext independently, the committee decrypts an entire batch using sublinear communication. Since the original construction of [CGPP24](https://eprint.iacr.org/2024/669), a long line of work has pushed (silent) batched threshold encryption schemes closer to practicality.

```{=html}
<div id="pick-your-poison-magic-move" class="cw-magic-move" role="img" aria-label="Animated transition from the batched threshold encryption landscape to pick-your-poison tradeoffs.">
  <noscript>
    This section contains an animated transition from the batched threshold encryption landscape to pick-your-poison tradeoffs.
  </noscript>
</div>
<script type="module" src="pick-your-poison.magic-move.js"></script>
```

::: {#pick-your-poison-story-source .cw-magic-story-source}
The inital work of [CGPP24](https://eprint.iacr.org/2024/669) required a setup involving secure multiplications in MPC and the size of secret keys held by each party grows with the batch size. They additionally required a interactive setup involving a constant number of secure multiplications for every batch that was decrypted.

Follow-up work [CGPW25](https://eprint.iacr.org/2024/1516) and [AFP25](https://eprint.iacr.org/2024/1575) simplified the construction to a one-time DKG setup at the start of the protocol, but ciphertexts needed to be encrypted to a particular batch number, which we refer to as an "epoch restriction". Failing to be included in the chosen batch would result in the ciphertext never being decrypted.

Concurrently, [BFOQ25](https://eprint.iacr.org/2024/1533) used very different techniques to also just require a one-time DKG setup, and without the epoch restriction. However, the ciphertexts needed to be encrypted to a particular *index* in the batch. As a result, two conflicting transactions encrypted to the same index could not be included in the same batch. This gives rise to a censorship issue, where an attacker can censor a victim's transaction by paying a slightly higher priority fee. We quantify censorship resistance as the minimum number of ciphertexts an attacker can include in a batch before a victim's transaction is forced to be excluded. Ideally, censorship resistance is the same as maximum batch size $B$. In other words, censorsing a transaction is as expensive as buying up the entire block.  But [BFOQ25](https://eprint.iacr.org/2024/1533) only achieves a censorship resistance of $1$.

[ABDGMPRY25](https://eprint.iacr.org/2025/2115) improved [BFOQ25](https://eprint.iacr.org/2024/1533) to support quasi-linear decryption $O(B \log{B})$ and weighted threshold decryption but still had a censorship resistance of $1$. They also propose a variant where censorship resistance scales linearly with the ciphertext size by essentially encrypting to multiple indices in the batch.

Next, [FPTX25](https://eprint.iacr.org/2025/2032) show that the epoch restriction in [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575) can be avoided if the CRS is allowed to grow with the number of batched that will ever be decrypted. After which, the public key must be sampled from scratch. This may be a reasonable tradeoff if the system refreshes its public key periodically regaradless, to handle committee members joining/leaving. One caveat to note is that the decryption complexity of [FPTX25](https://eprint.iacr.org/2025/2032), [CGPW25](https://eprint.iacr.org/2024/1516) and [AFP25](https://eprint.iacr.org/2024/1575) is $O(B\log^2{B})$ which is slower than the quasi-linear $O(B \log{B})$ achieved by other works.

[BNRT26](https://eprint.iacr.org/2026/674) took a different approach and showed that if the committee is willing to pay for a more complicated setup, it is possible to avoid both the epoch restriction and censorship issues. Concretely, they use partial fraction techniques and their setup involves secure inversions in MPC and the size of secret keys held by each party grows with the batch size.

[Pol26](https://eprint.iacr.org/2026/760) and [ADGRS26](https://eprint.iacr.org/2026/754) use a similar strategy of a more complicated setup but use a different algebraic structure -- "punctured power-of-tau" -- to avoid the epoch restriction and censorship issues. Their setup uses secure multiplications and the size of secret keys held by each party grows with the batch size.

In a different line of work [BCFGOPQW25](https://eprint.iacr.org/2025/1419) (censorship issues) and [GWWW25](https://eprint.iacr.org/2025/2103) (epoch restrictions) avoid interactive setup entirely and show that it is possible to have a batched threshold encryption scheme with Silent Setup (just a PKI).
:::

::: {#pick-your-poison-dream-source .cw-magic-dream-source}
Of course, the dream goal is:

> *A batched threshold encryption scheme with a constant-sized ciphertext, DKG/silent setup, quasi-linear decryption, and no censorship issues/epoch restrictions*

but so far, all constructions fall short. It appears that system designers must pick their poison.
:::

## (Just) A Little Bit of Everything

Observe that all constructions pick a "maxima" in the tradeoff space.

- [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575), [GWWW25](https://eprint.iacr.org/2025/2103): no censorship issues and DKG Setup at the cost of epoch restrictions
- [BFOQ25](https://eprint.iacr.org/2024/1533), [ABDGMPRY25](https://eprint.iacr.org/2025/2115), [BCFGOPQW25](https://eprint.iacr.org/2025/1419): no epoch restrictions and DKG/Silent Setup at the cost of censorship issues
- [FPTX25](https://eprint.iacr.org/2025/2032): no censorship issues/epoch restrictions and DKG setup at the cost of a much larger CRS and forced DKG re-setup after a predetermined number of batches
- [BNRT26](https://eprint.iacr.org/2026/674), [Pol26](https://eprint.iacr.org/2026/760), [ADGRS26](https://eprint.iacr.org/2026/754): no censorship issues/epoch restrictions at the cost of a complicated $O(B)$ circuit size MPC setup and $O(B)$ secret key size

In practice, it may be more interesting to consider a smooth tradeoff on the pareto frontier.

### Cenosrship Resistance v Secret Key Size

[BNRT26](https://eprint.iacr.org/2026/674), [Pol26](https://eprint.iacr.org/2026/760), [ADGRS26](https://eprint.iacr.org/2026/754) achieve maximum censorship resistance $B$ but they all have an $O(B)$ secret key size. This makes changing the committee at large batch sizes $B \gg n$ quite expensive as it requires $O(B/n)$ DKGs to reshare the secrets to the new committee even with the trick of [Hyper-Invertible Matrices](https://cs.au.dk/fileadmin/www.cfem.au.dk/Downloads/MPC_workshop/Martin_Hirt_slides-stacked.pdf).

>What if we could give up *some* censorship resistance in exchange for *shorter* secret keys?

It may be worth the tradeoff to reduce the price of censorship to buying $10\%$ of the block (say), if we can proportionally reduce the cost of resharing secrets.

### Epoch Restrictions v Forced DKG Re-setup

[FPTX25](https://eprint.iacr.org/2025/2032) avoids censorship issues and epoch restrictions at the cost of a much larger $O(KB)$ CRS and a forced DKG re-setup after decrypting $K$ batches. In practice, deployments would choose K large enough to support the *expected* number of batch decryptions over the committee rotation period, which typically lasts from a few hours to a few days.

But this might be overkill for the epoch restriction issue. Recall that in [CGPW25](https://eprint.iacr.org/2024/1516), [AFP25](https://eprint.iacr.org/2024/1575), users had to "guess" the block height at which their transaction would be included. Naively, one can encrypt to multiple block heights, but this increases the ciphertext size.

> What if we accept *some* epoch restrictions but are able to avoid a forced DKG re-setup?

Concretely, what if the user could instead select a window of block heights spanning 20 minutes (say) in which their transaction could be included and we paid for this privilege with an increase in the CRS size instead of the ciphertext size? This could also be a way to avoid the forced DKG re-setup in [FPTX25](https://eprint.iacr.org/2025/2032).

<!-- ## References

- CGPP24: [2024/669](https://eprint.iacr.org/2024/669)
- GKPW24: [2024/263](https://eprint.iacr.org/2024/263)
- CGPW25: [2024/1516](https://eprint.iacr.org/2024/1516)
- BFOQ25: [2024/1533](https://eprint.iacr.org/2024/1533)
- AFP25: [2024/1575](https://eprint.iacr.org/2024/1575)
- BLT25: [2025/1254](https://eprint.iacr.org/2025/1254)
- BCFGOPQW25: [2025/1419](https://eprint.iacr.org/2025/1419)
- WW25: [2025/1547](https://eprint.iacr.org/2025/1547)
- FPTX25: [2025/2032](https://eprint.iacr.org/2025/2032)
- GWWW25: [2025/2103](https://eprint.iacr.org/2025/2103)
- ABDGMPRY25: [2025/2115](https://eprint.iacr.org/2025/2115)
- BNRT26: [2026/674](https://eprint.iacr.org/2026/674)
- ADGRS26: [2026/754](https://eprint.iacr.org/2026/754)
- Pol26: [2026/760](https://eprint.iacr.org/2026/760) -->
