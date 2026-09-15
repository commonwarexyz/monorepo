---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-15T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/15/26): Operators can process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain the account state, activity, payouts, and local signing decisions in native QMDB owners and apply only the changes at each settlement.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a \~100-byte certified commitment that most chains can process. Binding receipts arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery onchain without its cooperation. And the protocol requires only signatures and Merkle openings.

One payment or a bajillion, each account settles once.

## Payments as Fast as Browsing the Web

If an API responds in milliseconds, no one will wait seconds to pay for it.

With Bajillion, a user can pay an API provider without waiting for settlement. Their chosen payment operator returns a binding receipt in one round trip. The user sends it with the API request, or the operator delivers it directly to save a hop. The provider can serve the response knowing the receipt gives it evidence to hold the operator accountable if settlement omits or contradicts the payment. The operator later nets payments across accounts without separate channels or funded routes, dramatically reducing the data needed for settlement.

Suppose a user $a$ has 100 and wants to pay 20 to $b$, who has 40. The operator verifies and records $a$'s signed request $S$, then countersigns it as $R$. Before forwarding the receipt to $b$, $a$ verifies and retains it.

```{=html}
<style>
  .clearing-loop {
    aspect-ratio: 1024 / 576;
    margin: 28px 0 6px;
  }
  .clearing-benchmark-plot {
    display: block;
    height: auto;
    width: 100%;
  }
  .clearing-benchmark-table {
    overflow-x: auto;
  }
  .clearing-benchmark-table table {
    min-width: 760px;
  }
  .clearing-proof-table table {
    min-width: 540px;
  }
  .clearing-proof-table caption {
    padding: 12px 0;
    text-align: left;
    font-weight: bold;
  }
  .clearing-calculator {
    border: 1px solid #d6d6d6;
    border-radius: 3px;
    margin: 28px 0 6px;
    padding: 20px;
  }
  @media (max-width: 640px) {
    .clearing-calculator { padding: 14px; }
  }
</style>
<noscript>
  <style>
    .clearing-loop {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      margin: 28px 0 6px;
      padding-left: 12px;
    }
    .clearing-calculator {
      border: 0;
      border-left: 2px solid #2424d4;
      border-radius: 0;
      color: gray;
      padding: 0 0 0 12px;
    }
  </style>
</noscript>
<div id="clearing-fig-payment" class="clearing-loop" role="img" aria-label="Animated payment timeline with payer a, the operator, and recipient b. Payer a sends S paying b 20. The operator locally verifies, commits a's balance from 100 to 80 and the a-to-b entry from (0,0) to (20,1), then countersigns R. The receipt, R plus an entry opening, returns to a in two message delays. The payer verifies and retains it before forwarding it to b in a third delay. An optional dotted operator push delivers the same receipt directly to b in two delays.">
  <noscript>The operator verifies, commits, and countersigns locally. Its receipt returns to payer a in two message delays. The payer verifies and retains it before forwarding it to b in a third delay. The operator may also push the same receipt directly to b, arriving in two delays.</noscript>
</div>
<script type="module" src="clearing.loops.js"></script>
```

::: {.image-caption}
Figure 1: The dotted path is an optional operator push that reaches the recipient one hop earlier. The entry accumulates amount and payment count.
:::

Payments are grouped into epochs. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

The payer tracks a balance $B_a$ and an epoch's total debit $D_a$, initially zero. It keeps a vector $V_a$ ordered by recipient, with one entry $(G,J)$ recording the cumulative amount and payment count for each. Before the example payment, $B_a=100$, $D_a=0$, and $V_a$ is empty.

To send $x>0$, $a$ advances $b$'s entry and signs the updated epoch-local sequence number $n_a$, cumulative debit, and vector's Merkle root. The operator countersigns this endpoint:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

For this payment, $n_a=1$, $D_a=20$, and $V_a=\{b:(20,1)\}$.

The wallet keeps one unacknowledged request in flight, retries it unchanged after response loss, and durably saves the verified acknowledgment and openings before signing the next endpoint. One signature can also advance several recipients in a batch. The operator accepts or rejects the whole batch and returns one acknowledgment with an opening for each advanced entry.

## Collecting Fees

An operator can require the payer to include a payment to a designated fee recipient, such as the operator's own account, in the same signed batch. It checks the requested payments and the fee increment before countersigning. If the fee is insufficient, it rejects the batch. The payer authorizes the fee alongside the other payments, and the operator's acknowledgment binds them together.

The operator can price each transfer type or payer independently, including volume discounts or negotiated rates. Validators net the fee entry like any other payment, and settlement uses the same commitments and proofs. The fee schedule stays with the operator; changing it requires no protocol change.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-fees.svg" alt="In a separate example, payer a batches payments of 20 to b, 7 to c, and a fee of 2 to the operator's designated account. One payer signature covers the whole batch. The operator checks the fee against its quoted policy and countersigns the same endpoint, acknowledging all three payments together. Validators process the fee as an ordinary payment.">
```

::: {.image-caption}
Figure 2: The payer includes the operator's quoted fee in the same signed batch as the recipient payments. One countersignature acknowledges the whole batch; validators process every entry as an ordinary payment.
:::

## Optimizing for Hot Accounts

Bajillion defines each payment as an update to the payer's outgoing vector. This lets the operator accept payments from different payers in parallel, even when they share a recipient. Existing accounts can spend receipt-backed incoming credit within the epoch, before settlement. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry in $a$'s vector:

$$
(G_{ab},J_{ab})\longrightarrow(G_{ab}+x,J_{ab}+1),
\qquad
\text{every other entry of every other vector unchanged.}
$$

However many payments an edge carries, the epoch ends with one cumulative entry for it.

Suppose accounts $(a,b,c,d)$ start with balances $(100,40,25,35)$ and make these payments:

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

$b$'s three incoming payments end as the entries $(20,1)$ in $a$'s vector, $(4,1)$ in $c$'s, and $(6,1)$ in $d$'s.

$$
\begin{bmatrix}
\underset{a\to b}{(20,1)} &
\underset{c\to b}{(4,1)} &
\underset{d\to b}{(6,1)}
\end{bmatrix}
$$

## One Row per Active Account

When an epoch ends, the operator builds a **close**, the settlement package that nets its payments into new account balances. Each payer's last vector of the epoch is its terminal vector. The operator and validators derive incoming credits from these vectors: $b$ receives $20+4+6=30$ across three payments. Each entry is authenticated by its payer's signed vector root.

Netting each of the four accounts' debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross debit equals gross credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. The six payments change four account rows, one per account.

For each account, the opening and closing balances are $B_a^0$ and $B_a^1$, with debit and credit deltas $d_a$ and $c_a$. Deposits $f_a$ and withdrawals $w_a$ complete the balance equation:

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Every payment credits its recipient's balance. A close creates payouts only for authorized withdrawals.

Each epoch records one row for every disclosed participant, including accounts whose net balance change is zero. The rows are sorted by account key and contain no duplicates. A sender's row includes its last signed payer state. Every validator derives the resulting balances and checks the epoch's gross debit $D_e$ and credit $C_e$:

$$
\boxed{D_e=C_e.}
$$

Here $D_e=C_e=54$. Summing account balances into $L_e$ and $L_{e+1}$ cancels payments, leaving only deposits $F_e$ and withdrawals $W_e$:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

Without deposits or withdrawals, $L_{e+1}=L_e=200$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-netting.svg" alt="100 million payments across six directed pairs net into balance changes for four active accounts. Account a sends $30 and receives $10, moving from $100 to $80. Account b sends $25 and receives $55, moving from $40 to $70. Account c sends $20 and receives $25, moving from $25 to $30. Account d sends $25 and receives $10, moving from $35 to $20. The close retains six cumulative entries and four account records.">
```

::: {.image-caption}
Figure 3: A separate epoch with 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

QMDB Current Ordered with MMB stores each live account's balance under its public key, committed by $\mathsf{StateRoot}$. Deposits and payments can add accounts, and a zero balance removes the record. Payment totals and counts belong to the epoch's evidence.

When a payment names a new public key, the operator records a balance for it without an onchain registration transaction. The recipient can spend the balance after the close is admitted, or let payments from many senders accumulate across multiple closes before authorizing a sweep.

## Keep the State, Send the Changes

Every validator retains the complete account state in QMDB. At each close, the operator publishes one dealing for all of them: active account keys, senders' terminal signed payer states, and cumulative payment entries. Recipients are identified by position in the account list. A CDN can cache this shared dealing for efficient distribution.

Each validator checks the payer signatures and the operator's countersignatures, derives incoming credits, and combines them with its stored balances and the deposits and withdrawals fixed at epoch registration.

From these results, every validator derives the same three shared roots:

- The **state root** commits the current positive balances.
- The **activity root** commits the cumulative log of account Rows and payment Entries.
- The **payout root** commits the cumulative log of external payout outputs.

The activity log starts each epoch with a sorted Row for every participant, including zero-net accounts so their receipts remain challengeable. Each Row directly records the account's final debit, sequence number, and payer-vector BMT root. Individual Entry records follow the Row prefix in payer-row order. A positive-debit Row consumes entries until their cumulative values sum to its debit; a zero-debit Row consumes none. Commit(None) ends the epoch. In Figure 4, the blue branch expands the BMT for $c$'s outgoing payment vector: $c$ signs that root, and the leaves below are $c$'s payments. The payout log receives every external payout output, currently the validator-derived output for each authorized withdrawal, followed by its own Commit(None).

The certified activity start and row count $G_e$ identify exactly the contiguous Row prefix $[A_e^0,A_e^0+G_e)$. The Entry records and Commit(None) follow outside that compact proof range. The payout interval $[P_e^0,P_e^1)$ identifies exactly the candidate output positions; once those outputs finalize, their global indices are never reused. Its Commit(None) follows them. An empty epoch certifies $G_e=0$; an epoch without outputs certifies equal payout offsets. QMDB updates positive balance records incrementally and removes an account when its balance reaches zero.

All three roots are results of validation. A 32-byte commitment binds a ProposalId for the canonical dealing bytes, the successor QMDB root, activity-MMR root and count, certified row count, candidate payout-MMR root and count, and exact output range to the epoch, their predecessor values, and the close's totals. Validators already hold the balances needed to compute the new state, so the dealing needs no state-change proof. They promote the selected candidate state once the close is admitted.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-trees.svg" alt="A close commitment binds three validator-derived roots: state, activity, and payout. A separate activity-log strip shows earlier closes followed by this close's four sorted Rows, original Entries grouped by payer, and Commit(None). The highlighted Row for c contains debit 11, sequence 2, and a link to the outgoing-payment BMT root signed by c. Its two leaves pay 4 to b and 7 to d, one payment each. QMDB retains the resulting balances; this close appends no new payout outputs.">
```

::: {.image-caption}
Figure 4: The close binds three validator-derived roots. The activity log appends this close's Rows and original Entries after earlier history. Below, $c$'s Row names the BMT root that $c$ signs; its two entries sum to the Row's debit of 11.
:::

The settlement chain holds pooled custody, the certified state root, current finalized log heads, bounded pending log metadata, control and boundary state, and a map of unclaimed payout intervals. It does not store every account row, output, claimed index, or finalized epoch descriptor.

Validators own the authenticated state and log construction. The operator only has to collect signed payer and boundary data and propose the dealing; serving payments and preparing a close do not require it to construct QMDB or either MMR. It may run best-effort replicas to serve balance, challenge, and payout openings directly.

The storage target gives each validator three shared native owners: Current Ordered QMDB over MMB for live positive balances, plus keyless QMDB operation logs over MMR for activity and payouts. A fourth, private compact QMDB stores only bounded local control snapshots: the selected public-store checkpoint, an optional candidate, at most one immutable signing decision, and cleanup state. It uses metadata-only commits, is never included in the root bundle or certificate, is never imported from a peer, and is never rewound with the three shared stores. After a completed update or reopen, native pruning pins its latest control state within one 16-witness section, retaining at most 16 bounded snapshots. Reopen cleans up any older section left by an interrupted update.

The protocol logs are flat--there is no tree per epoch--and proof construction can walk retained native operations on demand. Each activity epoch is exactly a contiguous prefix of account-sorted Row appends, followed by one Entry append per original outgoing entry in payer-row and recipient order, then Commit(None). The certified row count separates direct account proofs from that variable Entry suffix. Positive Entry values uniquely delimit each positive-debit payer's group by summing to the debit in its Row; zero-debit Rows consume no entries. To answer an entry challenge, a validator rebuilds only the requested payer's BMT and checks it against the root stored directly in that Row. The public activity log therefore needs only Rows, Entries, and Commit(None); private signed receipts remain with the wallets that rely on them.

Each payout epoch is exactly its output appends followed by Commit(None). Activity Rows and payout outputs use stable append locations, while the activity Entry suffix and commit gaps are excluded from their certified compact ranges. An opening proves the exact typed append operation at the committed operation count. Even an empty epoch writes both log commits, and Current state batches also use Commit(None). Registration fixes the finalized operation count $s_f$, and every signer uses $s_f-1$ as the floor for descendants of that registration. Local availability may delay physical deletion but cannot change the signed floor.

The private control QMDB records one checkpoint naming the three shared roots, operation counts, and native recovery boundaries. Before a vote or acknowledgment can leave a validator, the Current, activity, and payout candidates commit durably in parallel. The coherent checkpoint and exact immutable signing decision are then made durable in the private QMDB; completion of that operation is the local publication barrier. Public-store synchronization and pruning run when their own import, retention, or cleanup lifecycles require them, not as extra work before every acknowledgment.

After a mixed crash, the validator recovers the latest durable private checkpoint first, opens the three public stores, and aligns them to its selected common target. Native recovery rebuilds derived Merkle, offset, and bitmap bookkeeping from the durable journals; it does not rescan application balances. While the coherent candidate remains retained, an exact retry reissues the saved vote. Disposal durably selects the canonical parent in the private QMDB before rewinding the public stores; it preserves the signing decision and blocks every further vote for that epoch until canonical advancement. Catch-up imports only an authenticated public triplet from a coherent native replica; peer control state can never authorize local signing. The validator does not keep a full-close corpus merely to redo local state. Finalized activity locations and issued payout locations are never repurposed. Public-store deletion stays behind every protected proof and recovery boundary, and older protected roots are served from retained historical operations rather than by rewinding the live stores.

## Certify the Whole Close

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Every signer checks the complete close, derives the same transitions, and signs the same commitment. A certificate needs $q=2f+1$ signatures.

The canonical dealing bytes also receive a separate $\mathsf{ProposalId}$. It hashes a distinct domain, the authenticated epoch context, and a length-framed encoding of the dealing. The certified transition binds that identifier, the exact predecessor snapshot, all three successor roots, both log counts and epoch ranges, and the outflow totals. This lets the operator check that a certificate belongs to its proposal without rebuilding the validators' cumulative logs.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-full-validation.svg" alt="The operator sends the same dealing to 100 validators. The blue callout expands c's sender record: final sequence 2, a total of 4 to b and 7 to d, each with count 1, bound by c's signature. Four cards show the operator accepting the final payer states of a, b, c, and d, then aggregating those acknowledgments. Validators derive the state root, activity root, and payout root and bind them with the certified close context into one 32-byte commitment. An aggregate signature and signer bitmap form its 67-of-100 certificate. Each validator durably commits the three public candidates in parallel, then durably records its private control-QMDB checkpoint and signing decision before acknowledging. The certified candidate contains only the three shared roots.">
```

::: {.image-caption}
Figure 5: Every validator derives the same state, activity, and payout roots before signing one close commitment. Before its vote leaves, it durably commits the three public candidates and then its private checkpoint and signing decision.
:::

Once the accepted transition is present in all three durable shared stores and the validator's private checkpoint is durable, validation-only inputs can be retired. Validators keep native Rows and Entry records, payout outputs, log nodes, and QMDB history for every FIFO, challenge, and recovery obligation that can still reach them. Once no live obligation can refer to a prefix, they may prune its rows and nodes while retaining the authenticated prefix hashes needed to continue each log. Pruning saves replica storage without changing the root or global positions; it does not make proofs shorter. A new validator synchronizes the three shared native stores from an authenticated boundary and checks the resulting roots and counts; private signer state is initialized locally, never accepted from a peer.

Proof availability can outlive a hot validator's retention window. Roots authenticate data without supplying it, so a user, operator, or proof service can run the same native QMDB replicas with longer retention and serve old balance, activity, receipt, and payout openings. Native state synchronization transfers the proof-bearing records; no parallel Bajillion proof archive or full-close copy is required. Hot-validator pruning is not pinned by the oldest unclaimed output or by an offline optional replica, and consensus does not require every validator to retain lifetime history. If every longer-retention replica discards a needed prefix, its proof is unavailable, but that absence neither expires the entitlement nor proves that a request was never carried.

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator signed header and certificate are 101 bytes. The validator-derived root bundle is 184 bytes; adding the eight-byte withdrawal total makes its descriptor 192 bytes, or 293 bytes together before chain transaction framing. These values are separate from the operator's dealing.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. Candidate log storage may already contain a pending descendant, but a successful challenge discards that logical suffix. Discarded outputs never advance the finalized payout root or create unclaimed claim intervals.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out.

Consider two executions with the same public close $\mathcal D_e$ and certificate, proof, or attestation $\zeta$. In $\Xi_0$, the operator signs only the acknowledgments represented by the close. In $\Xi_1$, it also delivers a valid private acknowledgment $R^+$. The verifier sees the same evidence in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A committee, TEE, or SNARK/STARK can verify the published inputs. Certifying those inputs cannot rule out an additional private receipt.

The certified activity Row prefix records one final activity value for every disclosed account. A missing payer counts as zero debit, so a proof of absence can challenge an omitted payment. For a nonempty prefix, absence is proved by MMR membership for the adjacent full Rows at adjacent positions, or by membership at the left or right edge. A certified row count of zero proves that the prefix is empty. Strict key ordering and uniqueness make these cases exhaustive.

Receipt holders can prove three kinds of contradiction:

1. **Debit mismatch.** For example, the close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Because certification has checked the accounting and signed payer states, a receipt holder can prove a contradiction with signatures, an activity-MMR opening, and any signed payer-vector BMT opening in one onchain call, without an interactive dispute game. Every receipt a user relies on needs an honest holder who retains the private receipt, obtains the public openings from a sufficiently retained native replica, and gets a challenge included by $\Delta_e$. No replica can reconstruct a private receipt nobody saved.

Suppose $b$ has already served the API response, but the operator leaves $a$'s payment of 20 out of the close. The receipt and a public proof of the omission let $b$ prove operator fault without the operator's cooperation. That is what makes the receipt binding. An application could use this evidence to compensate $b$ from an onchain insurance fund, permanently exclude the operator, or support offchain resolution. The recipient can seek a remedy beyond simply deciding not to use that operator again (unlike other approaches that offer only best-effort preconfirmations).

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain, even during an active epoch. The next registration must include it.

Once a withdrawal request is queued onchain or included in an admitted close, its carrying close must finalize before the signed deadline $T_w$ to avoid a hard fault. With challenge deadline $\Delta_e$,

$$
\boxed{\Delta_e<t_{\mathrm{finalize}}<T_w.}
$$

An exact withdrawal releases its amount if the epoch's final balance covers it. An account close sweeps that balance. Every derived withdrawal output, including a zero-valued one, is appended to one payout MMR at a stable global index. An MMR opening binds that index to the output's destination and amount. It has no claim deadline and its index is never recycled. A zero-valued output must still be consumable, even when its reserve is zero, so it cannot keep an interval alive forever.

Pending closes have candidate payout roots and counts, but their outputs are not yet claimable. When the carrying close reaches FIFO finality, the chain advances its distinct finalized payout root and count, reserves the exact outflow, and adds the newly finalized index interval to a direct map of unclaimed intervals. A challenged or invalidated suffix advances none of them.

A claim supplies the output, an MMR opening against the current finalized payout root and count, and the start key $s$ of the current unclaimed interval $[s,t)$ containing its index $i$. The opening proves that the payout exists; the interval proves that it remains unclaimed. The map stores only $t$ under $s$. The chain checks $s\le i<t$, then removes the interval and inserts the nonempty pieces $[s,i)$ and $[i+1,t)$. This split, the reserve reduction, and the payout happen atomically. A replay finds no interval containing $i$, even though the old MMR membership proof is still valid.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-payout-ranges.svg" alt="Four steps show one payout MMR root and output 12 opening remaining unchanged while the end-exclusive unclaimed ranges collapse. The initial range 10 through 15 contains indices 10, 11, 12, 13, and 14. Claiming interior index 12 atomically splits it into 10 through 12 and 13 through 15, reduces the reserve, and pays the destination. Claiming edge indices 10 and 14 shrinks the ranges to singleton intervals 11 through 12 and 13 through 14. Claiming 11 and 13 deletes those last ranges. Replaying output 12 is rejected because its index is in no unclaimed interval, even though its MMR proof remains valid. No claimed set is stored and no MMR leaf is deleted.">
```

::: {.image-caption}
Figure 6: The payout MMR proves output 12; the unclaimed-range map makes it claimable once. An interior claim splits a range, edge claims shrink it, and claiming its last item deletes it. Ranges are end-exclusive.
:::

The map has at most one range per outstanding output even under adversarial claim order, so claim state is $O(U)$ for $U$ unclaimed outputs in the worst case, not proportional to all claims ever made. It is not another authenticated claim tree. The full settlement state consists of the three principal tree roots and their counts, timing-window-bounded pending-close metadata, pooled and reserved custody, registration and fault controls, and these unclaimed intervals.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable, with no expiry, and refund unadmitted deposits. Accounts recover their balances with QMDB proofs against the frozen root, and each account can claim only once. Payments in a never-admitted or invalidated close do not debit that state or promote its candidate payout suffix.

Recovery needs a correct, live settlement chain and independently available balance and payout openings even when the operator disappears. Commitment roots alone cannot serve those witnesses; longer-retention native replicas do. A fault freezes the last surviving finalized payout root and count, against which later claims refresh their openings.

## Streamlined Epoch Transitions

A payment reaches finality through an admitted close, after the challenge deadline fixed at epoch registration. Shorter epochs with earlier deadlines can reduce that wait, but require more frequent preparation and certification.

Once epoch $e$'s close is admitted, the operator can register $e+1$ against its $\mathsf{StateRoot}$ and start payments before $e$ finalizes. Registration fixes deposits and signed withdrawal authorizations before the first payment is acknowledged.

For accounts without deposits or withdrawals, new payments can overlap credit imports. The preserved head $\widetilde B_a$ is the starting balance minus accepted predecessor debits plus credits already imported. The remaining predecessor credit is $\rho_a$:

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad \rho_a\ge0.}
$$

The preserved head is safe to spend against. Importing credit adds $\rho_a$ to the live balance, preserving any successor debits already accepted.

In the running example, $a\xrightarrow{20}b$ leaves the preserved head at 80 while the not-yet-imported $d\xrightarrow{5}a$ credit makes the exact close 85. If $a$ spends 20 and then 15 in the successor while the missing credit arrives between them,

$$
80-20+5-15=50=(85)-20-15.
$$

```{=html}
<div id="clearing-fig-rollover" class="clearing-loop" role="img" aria-label="Animated credit reconciliation for account a after predecessor admission and successor registration. An epoch-e send leaves a preserved head of 80. Two connected rails branch from that 80. The admitted predecessor balance is 85. The live successor rail spends 20 to reach 60, imports the remaining credit to reach 65, and spends 15 to reach 50. One vertical marker identifies the same predecessor credit of 5 in both calculations. The admitted balance never overwrites the live head.">
  <noscript>After predecessor admission and successor registration, the admitted balance is 80 plus 5, or 85. The live head is 80 minus 20 plus the same 5 minus 15, or 50. Reconciliation adds the remaining credit without installing 85 over the live head.</noscript>
</div>
```

::: {.image-caption}
Figure 7: Both calculations include the same predecessor credit. Importing it adds to the live balance, preserving payments already accepted in the successor epoch.
:::

Accounts with deposits or withdrawals must resolve their full admitted outcome before spending in the successor epoch.

## The Close Follows Accounts and Edges

We measured the native flat-log extension of the [initial implementation](https://github.com/commonwarexyz/monorepo/pull/4664) with one million live accounts. The size fixtures vary the number of active payers $A$, the recipient pool $B$, and outgoing recipients per payer $K$. The operator Dealing encoding modeled in Figures 8 and 12 is unchanged: ProposalId and the three resulting roots belong to the validator-derived close descriptor, not the operator's payload.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Encoded item</th>
      <th colspan="4" style="text-align:center;">One million live accounts</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 1</th>
      <th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 8</th>
      <th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 8, <em>K</em> = 8</th>
      <th style="text-align:right;"><em>A</em> = 1M<br><em>B</em> = 512, <em>K</em> = 1</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Operator Dealing</td>
      <td style="text-align:right;">105,267 B</td>
      <td style="text-align:right;">132,147 B</td>
      <td style="text-align:right;">126,003 B</td>
      <td style="text-align:right;">102,750,004 B</td>
    </tr>
    <tr>
      <td>Root bundle</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
    </tr>
    <tr>
      <td>Root-and-outflow descriptor</td>
      <td style="text-align:right;">192 B</td>
      <td style="text-align:right;">192 B</td>
      <td style="text-align:right;">192 B</td>
      <td style="text-align:right;">192 B</td>
    </tr>
    <tr>
      <td>Signed commitment + certificate</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
    </tr>
    <tr>
      <td>Descriptor + signed commitment</td>
      <td style="text-align:right;">293 B</td>
      <td style="text-align:right;">293 B</td>
      <td style="text-align:right;">293 B</td>
      <td style="text-align:right;">293 B</td>
    </tr>
  </tbody>
</table>
</div>
```

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">CPU preparation</th><th colspan="3" style="text-align:center;">One million live accounts</th></tr>
    <tr><th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 1</th><th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 8</th><th style="text-align:right;"><em>A</em> = 1M<br><em>B</em> = 512, <em>K</em> = 1</th></tr>
  </thead>
  <tbody>
    <tr><td>Prepare encoded Dealing</td><td style="text-align:right;">1.16 ms</td><td style="text-align:right;">3.30 ms</td><td style="text-align:right;">1.61 s</td></tr>
  </tbody>
</table>
</div>
```

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">Durable acknowledgment</th><th colspan="3" style="text-align:center;">One million live accounts</th></tr>
    <tr><th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 1</th><th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 512, <em>K</em> = 8</th><th style="text-align:right;"><em>A</em> = 1,024<br><em>B</em> = 8, <em>K</em> = 8</th></tr>
  </thead>
  <tbody>
    <tr><td>Seal through durable validator acknowledgment</td><td style="text-align:right;">276 ms</td><td style="text-align:right;">1.152 s</td><td style="text-align:right;">1.153 s</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 8: Exact encoded sizes, arithmetic-mean preparation times over 20 retained CPU samples, and durable-acknowledgment means over three actual runs with no warmup. $A$ is active payers, $B$ is the recipient pool, and $K$ is recipients per payer. Preparation starts from decoded close inputs and constructs the encoded operator Dealing. Acknowledgment starts from that encoding and runs production sealing and validation through concurrent durable state, activity, and payout commits, then private checkpoint and signing-decision durability; setup and reopen verification are outside the timer, and all nine measured runs reopened successfully.

Measurements ran on one AWS c8a.4xlarge with 16 AMD EPYC vCPUs and 32 GiB of RAM, using a 160 GiB gp3 EBS SSD provisioned for 6,000 IOPS and 250 MiB/s under ext4. Validation and the three public stores shared one 16-thread Rayon pool; the runtime used two I/O workers, and each public store had sixteen 1,024-byte native cache pages. The measured acknowledgment fixtures fit in RAM, while their commits still crossed the filesystem durability barriers to gp3. The root bundle, descriptor, and signed commitment are validator-derived and submitted at chain intake; transport framing is excluded. The fixtures use expanded benchmark-only limits, so their local encoded Dealings are not claims about deployed terminal RPC or frame capacity.
:::

Repeated payments between the same pairs reuse these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots show modeled bytes per payment as one million to one billion unit payments pass between fixed pairs. The left shows one validator's keyed update for four account counts, including growing cumulative counters. The right shows the 101-byte commitment and certificate.">
```

::: {.image-caption}
Figure 9: Operator Dealing model. Every account repeatedly pays one unit to its next neighbor. Counters grow, while more payments share the byte cost of one validator's update and the 100-validator committee's certificate. The validator-derived 192-byte root-and-outflow descriptor is separate from the unchanged Dealing; the plotted 101 bytes are its signed header and certificate.
:::

### Native Proof Sizes and Verification

Activity challenges open the certified Row prefix in the cumulative native log. The first table varies the current close's Row count $R$ with no prior rows ($H=0$). The second fixes $R=128$ and varies the rows $H$ in one earlier close. Both use one million live accounts. Native operation counts also include any Entry records and each close's Commit, so distributing the same $H$ across a different history can change the operation count, floor, topology, and proof size. An empty range needs no MMR opening. Presence includes the full Row; an interior exclusion includes the two adjacent Rows. Signed receipts and payer-vector BMT openings are separate and unchanged.

```{=html}
<div class="clearing-benchmark-table clearing-proof-table">
<table>
  <caption>Current close size · no prior rows (<em>H</em> = 0)</caption>
  <thead>
    <tr>
      <th style="text-align:left;">Activity lookup</th>
      <th style="text-align:right;">Current rows (<em>R</em>)</th>
      <th style="text-align:right;">Size / verification</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="text-align:left;">Empty absence</td><td style="text-align:right;">0</td><td style="text-align:right;">4 B<br><small>8.03 ns</small></td></tr>
    <tr><td style="text-align:left;">Presence</td><td style="text-align:right;">1</td><td style="text-align:right;">124 B<br><small>427 ns</small></td></tr>
    <tr><td style="text-align:left;">Adjacent absence</td><td style="text-align:right;">2</td><td style="text-align:right;">239 B<br><small>679 ns</small></td></tr>
    <tr><td style="text-align:left;">Presence</td><td style="text-align:right;">128</td><td style="text-align:right;">317 B<br><small>973 ns</small></td></tr>
    <tr><td style="text-align:left;">Adjacent absence</td><td style="text-align:right;">128</td><td style="text-align:right;">400 B<br><small>1.14 µs</small></td></tr>
    <tr><td style="text-align:left;">Presence</td><td style="text-align:right;">1,024</td><td style="text-align:right;">413 B<br><small>1.27 µs</small></td></tr>
    <tr><td style="text-align:left;">Adjacent absence</td><td style="text-align:right;">1,024</td><td style="text-align:right;">496 B<br><small>1.43 µs</small></td></tr>
    <tr><td style="text-align:left;">Presence</td><td style="text-align:right;">1,000,000</td><td style="text-align:right;">702 B<br><small>2.11 µs</small></td></tr>
    <tr><td style="text-align:left;">Adjacent absence</td><td style="text-align:right;">1,000,000</td><td style="text-align:right;">785 B<br><small>2.25 µs</small></td></tr>
  </tbody>
</table>
</div>

<div class="clearing-benchmark-table clearing-proof-table">
<table>
  <caption>Prior history · 128 current rows (<em>R</em> = 128)</caption>
  <thead>
    <tr>
      <th style="text-align:left;">Prior rows (<em>H</em>)</th>
      <th style="text-align:right;">Presence</th>
      <th style="text-align:right;">Adjacent absence</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="text-align:left;">0</td><td style="text-align:right;">317 B<br><small>973 ns</small></td><td style="text-align:right;">400 B<br><small>1.14 µs</small></td></tr>
    <tr><td style="text-align:left;">1,024</td><td style="text-align:right;">349 B<br><small>1.11 µs</small></td><td style="text-align:right;">464 B<br><small>1.32 µs</small></td></tr>
    <tr><td style="text-align:left;">65,536</td><td style="text-align:right;">350 B<br><small>1.10 µs</small></td><td style="text-align:right;">465 B<br><small>1.31 µs</small></td></tr>
    <tr><td style="text-align:left;">1,000,000</td><td style="text-align:right;">510 B<br><small>1.54 µs</small></td><td style="text-align:right;">625 B<br><small>1.76 µs</small></td></tr>
  </tbody>
</table>
</div>
```

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">Complete challenge</th><th colspan="3" style="text-align:center;">One million live accounts</th></tr>
    <tr><th style="text-align:right;"><em>A</em> = 1,024<br><em>K</em> = 1</th><th style="text-align:right;"><em>A</em> = 1,024<br><em>K</em> = 8</th><th style="text-align:right;"><em>A</em> = 1M<br><em>K</em> = 1</th></tr>
  </thead>
  <tbody>
    <tr><td>Debit mismatch</td><td style="text-align:right;">654 B <small>present</small><br>657 B <small>omitted</small></td><td style="text-align:right;">718 B <small>present</small><br>753 B <small>omitted</small></td><td style="text-align:right;">943 B <small>present</small><br>978 B <small>omitted</small></td></tr>
    <tr><td>Entry mismatch</td><td style="text-align:right;">705 B</td><td style="text-align:right;">961 B</td><td style="text-align:right;">994 B</td></tr>
    <tr><td>Acknowledgment fork</td><td style="text-align:right;">417 B</td><td style="text-align:right;">417 B</td><td style="text-align:right;">417 B</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 10: Exact native activity lookup and complete challenge encodings. The smaller values below lookup sizes are arithmetic means of the 20 retained per-sample, per-iteration CPU verification times, starting from decoded inputs. $H$ and $R$ exclude native Entry and Commit operations. Each lookup cell includes its Row or adjacent Rows and opening; the certified 48-byte log head and Row-prefix range are separate. The challenge fixtures use a 512-account recipient pool. The three challenge families are debit mismatch, entry mismatch, and acknowledgment fork. Omitted payer is the absence case of debit mismatch. Edge exclusions use one Row and can be smaller. Sizes vary with position and MMR topology, so these samples are not upper bounds.
:::

A payout opens at a stable global index under the current finalized payout root and count. The proof must be refreshed as that root advances. Its MMR path follows cumulative log topology, not just the current close's output count $W$, and physical prefix pruning does not shorten it. The first table varies $W$ with no prior outputs. The second adds one output after different amounts of history and compares its claim with a refreshed claim for an older output.

```{=html}
<div class="clearing-benchmark-table clearing-proof-table">
<table>
  <caption>Current close size · no prior outputs (<em>H</em> = 0)</caption>
  <thead>
    <tr>
      <th style="text-align:left;">Payout proof</th>
      <th style="text-align:right;">New outputs (<em>W</em>)</th>
      <th style="text-align:right;">Size / verification</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="text-align:left;">Commit proof</td><td style="text-align:right;">0</td><td style="text-align:right;">46 B<br><small>285 ns</small></td></tr>
    <tr><td style="text-align:left;">Current claim</td><td style="text-align:right;">1</td><td style="text-align:right;">105 B<br><small>402 ns</small></td></tr>
    <tr><td style="text-align:left;">Middle current claim</td><td style="text-align:right;">1,024</td><td style="text-align:right;">394 B<br><small>1.23 µs</small></td></tr>
    <tr><td style="text-align:left;">Middle current claim</td><td style="text-align:right;">500,000</td><td style="text-align:right;">651 B<br><small>2.04 µs</small></td></tr>
    <tr><td style="text-align:left;">Middle current claim</td><td style="text-align:right;">1,000,000</td><td style="text-align:right;">683 B<br><small>2.15 µs</small></td></tr>
  </tbody>
</table>
</div>

<div class="clearing-benchmark-table clearing-proof-table">
<table>
  <caption>Prior history · one new output (<em>W</em> = 1)</caption>
  <thead>
    <tr>
      <th style="text-align:left;">Prior outputs (<em>H</em>)</th>
      <th style="text-align:right;">New output claim</th>
      <th style="text-align:right;">Older output, refreshed</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="text-align:left;">1,024</td><td style="text-align:right;">138 B<br><small>525 ns</small></td><td style="text-align:right;">394 B<br><small>1.25 µs</small></td></tr>
    <tr><td style="text-align:left;">65,536</td><td style="text-align:right;">139 B<br><small>543 ns</small></td><td style="text-align:right;">587 B<br><small>1.82 µs</small></td></tr>
    <tr><td style="text-align:left;">1,000,000</td><td style="text-align:right;">331 B<br><small>1.06 µs</small></td><td style="text-align:right;">683 B<br><small>2.07 µs</small></td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 11: Exact native payout-log encodings. The smaller values below sizes are arithmetic means of the 20 retained per-sample, per-iteration CPU verification times, starting from decoded inputs. Nonempty artifacts are complete claims with a 30-byte output; $W=0$ is an opening plus the Commit operation, not a claim. $H$ and $W$ exclude Commit markers, and the 48-byte current finalized head is separate. Current-output claims use a middle output except where labeled. Position, floor, and MMR topology affect size; these samples are not upper bounds.
:::

QMDB proofs authenticate balances for forced withdrawal intake and recovery. A recovery claim opens the account's balance at the frozen finalized root. Current Ordered with MMB remains the balance design. The following exact encodings use one million live accounts and compare the predecessor with sparse and dense successors.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">QMDB proof payload</th><th colspan="3" style="text-align:center;">One million live accounts</th></tr>
    <tr><th style="text-align:right;">Predecessor</th><th style="text-align:right;">Sparse successor<br><em>A</em> = 1,024, <em>K</em> = 1</th><th style="text-align:right;">Dense successor<br><em>A</em> = 1M, <em>K</em> = 1</th></tr>
  </thead>
  <tbody>
    <tr><td>Account present</td><td style="text-align:right;">819 B</td><td style="text-align:right;">819 B</td><td style="text-align:right;">853 B</td></tr>
    <tr><td>Account absent</td><td style="text-align:right;">852 B</td><td style="text-align:right;">852 B</td><td style="text-align:right;">886 B</td></tr>
    <tr><td>Recovery balance opening</td><td style="text-align:right;">850 B</td><td style="text-align:right;">850 B</td><td style="text-align:right;">884 B</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 12: Exact Current Ordered proof encodings for a middle account and a missing key. The sparse successor changes 1,024 accounts; the dense successor changes all one million. SHA-256/MMB uses 32-byte bitmap chunks and 8-byte balances. Lookup rows omit the known account key, while recovery includes it. All omit the trusted root and chain framing. Sizes vary with history and proof position.
:::

Adjust the workload and committee size below to estimate the operator's traffic.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive calculator for keyed validator dealings. Sliders set live accounts, average recipients per account, and validators. Results show one modeled update per validator, its composition, total operator egress, and a dotted reference for the encoded account records.">
  <noscript>Each validator retains the complete account state and receives one compact update per close. Total operator egress is the update size multiplied by the validator count. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 13: Modeled operator Dealing per validator, with total direct operator egress in parentheses. Dotted: all live account records (40 bytes each), before database overhead and retained evidence. Both axes are logarithmic. Encoder fixtures match the model across sparse, compact-length-boundary, and dense workloads. The separate certified descriptor, transport, and other messages are excluded.

Each sender signs one batch of unit payments. Recipients per account is averaged over all live accounts. Below an average of one, the first senders pay the last recipients in key order. Otherwise, every account pays its next neighbors cyclically. All accounts stay live, with no deposits or withdrawals. Estimates beyond the prototype's per-close limits extrapolate the same encoding.
:::

## A Bajillion Payments, One Settlement

Send a million payments without paying for a million onchain transactions.

That makes small exchanges practical, like an agent buying a single API response. Recipients can deliver the goods now, knowing the operator has made a binding commitment to the payment. If the operator later omits or contradicts that payment, the signed receipt gives them the evidence to challenge the close.

The settlement chain keeps the current balance commitment, finalized issuance, and outstanding claims--not a lifetime record of every payment or claim.
