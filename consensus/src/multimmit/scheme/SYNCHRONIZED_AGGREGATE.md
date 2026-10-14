# PS synchronized aggregate signatures for Multimmit ordinary keys

Design notes for replacing Multimmit's ordinary BLS signatures with the Pointcheval-Sanders
synchronized aggregate signature (SAS) of Tezuka and Tanaka
([arXiv:2304.00265](https://arxiv.org/abs/2304.00265), ICISC 2022). The primitive is prototyped in
`commonware_cryptography::bls12381::primitives::ops::sas`; measured results are in
[`SYNCHRONIZED_AGGREGATE_RESULTS.md`](SYNCHRONIZED_AGGREGATE_RESULTS.md).

## Summary

- BLS batch verification collapses pairings only when terms share a **public key** or a
  **message**. V-QCs, L-QCs, batches of individual votes, and batches of transaction blocks from
  different producer chains share neither, so today they pay one Miller loop and one
  hash-to-curve per term.
- PS-SAS collapses on a shared **period** instead. Any number of signatures from distinct keys over
  distinct messages in one period verify with **2 pairings** and **1 hash-to-curve**. The new
  cost is an MSM over the signers' public keys.
- The price is a hard rule: **a key must never sign two different messages in one period**. Two
  such signatures let anyone forge that key's signature on any message in that period.
  Multimmit's durable view slot already enforces this rule for votes and novotes.
- Recommended scope: use PS-SAS for the ordinary key (votes, novotes, V-QCs, L-QCs, leader blocks,
  transaction blocks). Keep threshold BLS for DA certificates and nullifications, where BLS
  already pays a constant number of pairings.
- Estimated sequential speedup is about 3.5x (MinSig layout) to 7x (MinPk layout) for an L-QC,
  and 2x to 4x for a batch of 31 transaction blocks. These are estimates from primitive
  benchmarks, not measurements; see [Cost](#cost).

## The scheme

Notation: `S` is the signature group and `P` the public-key group, with `e: S x P -> GT`.
`G~` is the generator of `P`. The paper fixes `S = G1` and `P = G2`, the `MinSig` layout.
`H1: periods -> S` is a hash to curve, and `H2: (period, message) -> Zp` is a hash to field.

| Operation | Definition |
|---|---|
| KeyGen | `sk = (x, y)` with `x, y` nonzero; `pk = (X~, Y~) = (x G~, y G~)` |
| Sign(sk, t, m) | `h = H1(t)`, `m' = H2(t, m)`, `B = (x + m' y) h` |
| Verify | `e(H1(t), X~ + m' Y~) = e(B, G~)` |
| Aggregate | for one period `t`, distinct keys: `B* = sum_i B_i` |
| Aggregate verify | `e(H1(t), sum_i X~_i + sum_i m'_i Y~_i) = e(B*, G~)` |

Signing is one scalar multiplication in `S`, and `H1(t)` can be cached once per period. A
signature is one element of `S`, the same size as a BLS signature in that group. A public key is
two elements of `P`, so it is twice the size of a BLS key.

Signatures are deterministic in `(sk, t, m)`, so they are unique per key, period, and message,
just like BLS.

### Why one signature per period

If a key signs `m1 != m2` in the same period `t`, with `h = H1(t)`:

```text
B1 - B2            = (m1' - m2') y h      =>  y h = (B1 - B2) / (m1' - m2')
B1 - m1' (y h)     = x h
forgery on any m*  = x h + H2(t, m*) (y h)
```

Anyone can then sign any message under that key in period `t`. The secret key does not leak,
and other periods are unaffected because `H1(t)` differs per period. The security proof
(Theorem 4.2) only covers signers that sign at most once per period. `Sign` does not enforce this
itself, so the protocol must.

## Which subjects fit

| Subject | Signer key | Signatures per period | Period | Fit |
|---|---|---|---|---|
| Vote, NoVote | ordinary | one per view: `ViewStance` is `Voted` xor `NoVoted`, durably (`machine/view/slot.rs`) | `(VIEW, epoch, view)` | **Yes.** This is the main win: V-QCs, L-QCs, and batches of votes need 2 pairings. |
| LeaderBlock | ordinary | one per view (`SlotError::Proposal`), but the leader also votes in that view | `(LEADER, epoch, view)` | Needs its own period. No speedup, since a single signature costs 2 pairings either way. |
| TransactionBlock | ordinary | one header per height; each producer owns exactly one chain (`Parameters::new` rejects duplicate producers) | `(TX, epoch, height)` | **Partial.** Blocks from different chains at the **same height** aggregate. The speedup depends on how closely chain heights stay aligned. |
| DaVote, DaCertificate | DA threshold | the group key signs one header per `(chain, height)` | n/a | **No.** Keep threshold BLS (see below). |
| Nullify, Nullification | nullify threshold | one message per round; a node may sign nullify after its vote | n/a | **No.** All shares sign one message, so BLS already needs 2 pairings. |

### Vote and novote share one period

A V-QC combines votes for the designated leader, conflicting votes for other leader blocks, and
novotes, all from distinct signers in one view. Each signer contributes exactly one of these, so
they can share one period, and the whole certificate needs one `H1(t)`. The subject kind (vote or
novote) and the namespace therefore move into `H2`'s input. `H1`'s input carries only the period
domain.

Novotes all sign the same message, so their `Y~` terms share one coefficient:
`sum_{novoters} (X~_i + m'_nv Y~_i) = sum X~_i + m'_nv sum Y~_i`. This takes one scalar
multiplication, not one per novoter. In general, the MSM has one term per **distinct** message,
not per signer.

### Why DA certificates stay BLS

All DA certificates are signed under one group key. Across chains, BLS already groups them by that
shared public key:
`e(sum_c r_c sigma_c, g) = e(sum_c r_c H(m_c), PK)`. That is 2 pairings for any number of anchors.
The `shares` bench shows the same effect for shares over one header (3.6 ms for 31 shares,
against 10 to 11 ms for 31 transaction blocks).

PS cannot beat this without breaking the one-signature-per-period rule. Headers from different
chains at one height would be different messages under one group key in one period. Making that
safe requires an independent `y_c` per chain, which means `C + 1` shared secrets, one DKG secret
per chain. That is exactly the per-chain key material we want to avoid. Using one period per
`(chain, height)` is safe, but then nothing aggregates.

### Per-chain public keys

Today the code has one ordinary BLS key per participant (`Roster` stores `BiMap<P, V::Public>`).
`transaction_block_claim` maps a chain to its producer and uses that participant's key. There are
no per-chain keys. What differs per chain is that each block carries a different signer and a
different message, which is the case BLS cannot batch cheaply. PS-SAS removes that pairing cost
for blocks that share a height. It does not remove the per-signer keys. It doubles them.

## Verification algorithms

Throughout, `t` is a period, `h_t = H1(t)`, and `m'_i = H2(t, kind_i, msg_i)`.

**Single signature.** `e(h_t, X~ + m' Y~) * e(-B, G~) = 1`. This is the same 2-term pairing product
as a BLS verify. When `h_t` is cached, the hash to `S` disappears and `m' Y~` adds one scalar
multiplication in `P`.

**Certificate (V-QC or L-QC).** Group transcript entries by distinct message. Compute
`P~ = sum_i X~_i + sum_g m'_g (sum_{i in g} Y~_i)` and check `e(h_t, P~) * e(-B*, G~) = 1`.
Certificates are atomic aggregate claims, so no per-signer randomizers are needed.

**Batch of independent claims** (the verifier actor: individual votes, transaction blocks, and
certificates from many views). Draw a 128-bit weight `r_j` per claim and group the claims by
period:

```text
prod_t e(h_t, sum_{j in t} (r_j X~_j + (r_j m'_j) Y~_j)) * e(-sum_j r_j B_j, G~) = 1
```

This costs `#periods + 1` Miller loops and one final exponentiation. The public-key-side MSM has two terms
per single-signer claim: a 128-bit `r_j` on `X~_j` and a full-width `r_j m'_j` on `Y~_j`. The
signature side is a small-scalar MSM in `S`, as in BLS batching today. On failure, bisection
works the same way and reuses the same weights. The data structure has to change, though:
today's `SegmentTree` stores one `(V::Public, V::Signature)` sum per node. A batch spanning
several periods needs a separate public-key-side sum for each period at every node, or one tree per
period.

**Known-message discharge.** `reduced_aggregate_claim` subtracts known vote and novote signatures from
the aggregate. This relies only on signatures being unique per key and message, which still holds
per `(key, period, message)`. It carries over unchanged.

**Structural checks before any pairing** (in addition to today's): `X~ != 0` and `Y~ != 0` at
roster time. With `y = 0`, a signature does not depend on the message. With `x = 0`, a single
signature reveals `y h_t`, which allows forgery within that period. Honest keys never have these
values, and the proof of knowledge covers adversarial keys, but the checks are cheap. Also check
`B != 0`, `B* != 0`, and that the signers within one aggregate are distinct.

## Security

- **Assumption.** The proof reduces to the Generalized PS assumption in the random oracle model. GPS is
  interactive. The adversary gets `(G, G~, X~, Y~)`, an oracle `O0` returning fresh random bases,
  and an oracle `O1(A, m)` returning `(x + m y) A` once per base. It is justified only in the
  generic group model. This is a weaker foundation than co-CDH for BLS.
- **Reduction.** `Adv_GPS >= Adv_SAS - q_s^2/(p-1) - q_H2/p`, with no multiplicative loss. The
  game has a single honest challenge key, though. A committee has up to `n` honest keys, so
  applying the result costs a factor of `n` (by guessing the target), unless the proof is extended
  to multiple users.
- **Certified-key model.** The proof requires every key in a forgery other than the challenge key
  to have been registered with a certification oracle that accepts only honestly generated
  `(pk, sk)` pairs. The paper never defines "valid". A BLS-style proof of possession (a signature
  over the public key) does not obviously meet this. The roster should instead carry a Schnorr
  proof of knowledge of `(x, y)` for `(X~, Y~)`, bound to the base namespace and the identity
  key:
  - `R~ = r1 G~` and `S~ = r2 G~`
  - `c = H(ns_PoK, identity, X~, Y~, R~, S~)`
  - `z1 = r1 + c x` and `z2 = r2 + c y`
  - Check `z1 G~ = R~ + c X~` and `z2 G~ = S~ + c Y~`.

  `Roster::verify` already gates every key, so this replaces `verify_proof_of_possession` there.
- **Group layout.** The paper proves the `MinSig` layout (`B` in G1, keys in G2). The `MinPk` layout
  (`B` and `H1` in G2, keys in G1) is the same scheme with the groups swapped. The generic-group
  argument is symmetric for type-3 pairings, but the paper does not state or prove it.
- **Domain separation.** The `H1` input is `ns_period || epoch || view` (or `|| height` for
  transaction blocks), with a distinct `ns_period` for each of `VIEW`, `LEADER`, and `TX`. The
  `H2` input is `ns_H2 || H1 input || kind || message`, reduced to `Zp` with a wide reduction
  (hash to field, at least 48 bytes). Namespaces follow the `_COMMONWARE_CONSENSUS_MULTIMMIT_*`
  convention.
- **What double signing now means.** Today an equivocating key produces two signatures, which is
  slashable evidence and nothing more. Under PS-SAS, two signatures in one period are both evidence
  and a forgery primitive: anyone can then add that key's "vote" for any body in that view to any
  certificate.
  - Accountability stays sound. Forgery is possible only after the key signed twice in the period,
    and those two signatures are already proof.
  - An honest node that double signs because of a bug or a lost write effectively becomes Byzantine
    for that view, so a durability bug now affects safety, not only slashing.
  - The `ViewSlotSnapshot` and `ReservationBook` invariants become cryptographic requirements. They
    need tests showing that replay never yields two distinct vote or novote subjects for one view,
    or two distinct headers for one height.

## Cost

The estimates in this section predate the prototype and were taken in Low Power Mode. The measured
results in [`SYNCHRONIZED_AGGREGATE_RESULTS.md`](SYNCHRONIZED_AGGREGATE_RESULTS.md) supersede them.

Measured baseline on the `cl/multimmit` branch at `ea530e3b0` (Apple M5 Pro, criterion, n = 31,
f = 6, sequential, ms). **These runs were taken with macOS Low Power Mode on** (`pmset` reports
`powermode 1`). Absolute times are inflated, and the estimated ratios should be rechecked with it
off.

| Workload | Terms | MinPk | MinSig |
|---|---|---|---|
| L-QC verify | 25 distinct votes | 8.57 | 7.89 |
| V-QC verify | 13 distinct votes, 12 novotes | 5.09 | 4.72 |
| 31 transaction blocks (batch) | 31 keys, 31 messages | 11.43 | 10.01 |
| 31 DA shares (batch) | 1 message | 3.64 | 4.93 |

The bench fixture gives every voter a distinct vote body, which is the BLS worst case. If honest
voters with the same view cast identical bodies, `verify_claims` groups them by message, and BLS
gets closer to PS-SAS. Treat the vote-side speedups below as upper bounds. The transaction-block
case has no such caveat: different chains always mean different keys and messages.

Primitive costs used for the estimates (same machine, sequential):

| Primitive | Cost |
|---|---|
| Hash to G1 | about 45 us each |
| BLS verify, 2 pairings plus hash to G2 | 0.70 ms |
| G1 MSM, full scalars | 0.36 ms at n = 10; 1.16 ms at n = 50 |
| G2 MSM, full scalars | 0.86 ms at n = 10; 3.14 ms at n = 50 |

Estimated PS-SAS cost, assuming a cached `H1(t)` and about 0.55 ms for a 2-pairing check. The
MinPk layout puts the MSM in G1; the MinSig layout puts it in G2.

| Workload | PS MSM terms | PS (MinPk layout) | PS (MinSig layout) | BLS today |
|---|---|---|---|---|
| L-QC | 25 | about 1.2 ms (7x) | about 2.3 ms (3.4x) | 8.6 / 7.9 ms |
| V-QC | 13 + 1 (novotes grouped) | about 1.0 ms (5x) | about 1.7 ms (2.8x) | 5.1 / 4.7 ms |
| 31 transaction blocks, one height | 62 (randomized) | about 2.6 ms (4.4x) | about 4.6 ms (2.2x) | 11.4 / 10.0 ms |

The transaction-block estimate prices all 62 public-key-side terms as full-width scalars. Half of
them (`r_j` on `X~_j`) are 128-bit, so those figures overstate the cost, and the speedups shown are
lower bounds.

Tradeoffs between the layouts:
- **MinPk layout.** Fast G1 MSM, 96-byte signatures, 96-byte public keys, hash to G2 once per period.
- **MinSig layout.** 48-byte signatures, 192-byte public keys, and the MSM runs in G2 at about 3x
  the cost of G1.

Public keys are fixed for an epoch, so precomputed fixed-base tables for each `Y~_i` (and `X~_i`
for the randomized batch) would cut the MSM further, at the cost of memory per key. With 8 Rayon
threads, the MSM parallelizes, but the 2-pairing floor does not. Expect smaller ratios there (BLS
L-QC is 2.2 ms with Rayon).

## Implementation sketch

1. **Primitive.** Add `commonware_cryptography::bls12381::primitives::ops::sas` (ALPHA), generic
   over `Variant`, with `S = V::Signature` and `P = V::Public`. It needs:
   - a `KeyPair` type
   - a Schnorr `prove_knowledge` and `verify_knowledge`
   - `sign(sk, period, kind, msg)`
   - `verify`, and an atomic `verify_aggregate` with message grouping
   - a batch `verify_claims` with per-period grouping and bisection, mirroring `ops::batch`, with
     a segment tree that keeps a separate public-key-side sum per period

   The existing `batch::Claim` hashes messages to the curve, so it cannot be reused directly. All
   pairing work can still go through `multi_pairing_check`. Add codec conformance coverage for the
   new public key and proof types.
2. **Scheme.**
   - `SignerKeys::ordinary` becomes the PS key pair.
   - `Roster` stores `(X~, Y~)` and verifies the proof of knowledge.
   - `Subject` gains a period (vote and novote map to `VIEW`, leader block to `LEADER`, transaction
     block to `TX`).
   - `claims.rs` and `batch.rs` build PS claims for ordinary subjects and keep BLS claims for
     threshold material.
   - A batch then runs two checks, or one shared final exponentiation if the pairing products are
     merged.
3. **Wire format.** Certificates keep a single aggregate element and the same compact transcripts.
   Roster entries grow by one `P` element and carry a proof of knowledge in place of a proof of
   possession. Multimmit is unreleased, so no migration is needed.
4. **Tests.**
   - A test that two signatures in one period yield a forgery, documenting the rule.
   - Rogue-key rejection without a proof of knowledge.
   - Zero `X~` or `Y~` rejected.
   - Discharge equivalence with the BLS path.
   - Durability replay tests for the one-signature-per-period invariants.
5. **Benches.** Add PS variants alongside `aggregate`, `ordinary`, and `shares` in
   `consensus/src/multimmit/benches`. Add a vote fixture with realistic, partly identical bodies,
   so the comparison is not only against the BLS worst case.

## Open questions

1. Is a GGM-only interactive assumption acceptable for the consensus-critical signature? Mixed
   deployments (for example, PS for votes only, keeping BLS transaction blocks) are possible but
   need two ordinary key types.
2. Which layout? MinPk is about 2x faster to verify, with larger signatures and smaller keys.
3. How aligned are chain heights in practice? This decides whether transaction blocks are worth
   moving or whether only the vote path should change.
4. How often do honest vote bodies coincide in deployment? This decides how much of the
   vote-side gain is real.
