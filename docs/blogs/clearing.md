---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-16T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/16/26): Operators can process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain the account state, activity, payouts, and local signing decisions in [QMDB](https://docs.rs/commonware-storage/latest/commonware_storage/qmdb/) databases and apply only the changes at each settlement.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a \~100-byte certified commitment that most chains can process. Binding receipts arrive in one round trip and provide the evidence to hold the operator accountable. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery onchain without its cooperation. And the protocol requires only signatures and Merkle openings.

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
    table-layout: fixed;
  }
  .clearing-benchmark-table th[rowspan] {
    width: 32%;
  }
  .clearing-benchmark-table .clearing-role-divider td {
    border-top: 2px dotted #999;
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

To send $x>0$, $a$ advances $b$'s entry and signs the updated epoch-local sequence number $n_a$, cumulative debit, and vector's Merkle root. The operator countersigns this updated payer state:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

For this payment, $n_a=1$, $D_a=20$, and $V_a=\{b:(20,1)\}$.

The wallet durably saves each request before sending it, retries the same bytes if the response is lost, and retains the verified acknowledgment and openings.

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

$b$'s three incoming payments remain in their payers' vectors:

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

Summing across accounts cancels payments, so the total balance changes from $L_e$ to $L_{e+1}$ only through deposits $F_e$ and withdrawals $W_e$:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

Without deposits or withdrawals, $L_{e+1}=L_e=200$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-netting.svg" alt="100 million payments across six directed pairs net into balance changes for four active accounts. Account a sends $30 and receives $10, moving from $100 to $80. Account b sends $25 and receives $55, moving from $40 to $70. Account c sends $20 and receives $25, moving from $25 to $30. Account d sends $25 and receives $10, moving from $35 to $20. The close retains six cumulative entries and four account records.">
```

::: {.image-caption}
Figure 2: A separate epoch with 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

## Keep the State, Send the Changes

Every validator retains the complete account state in [QMDB's Current Ordered variant](https://docs.rs/commonware-storage/latest/commonware_storage/qmdb/current/ordered/), an authenticated key-value store that keeps each live account's balance under its public key, committed by $\mathsf{StateRoot}$. Deposits and payments can add accounts, and a zero balance removes the record.

When a payment names a new public key, the operator records a balance for it without an onchain registration transaction. The recipient can spend the balance after the close is admitted, or let payments from many senders accumulate across multiple closes before authorizing a sweep.

At each close, the operator publishes one shared settlement record (the dealing): active account keys, senders' terminal signed payer states, and cumulative payment entries. Recipients are identified by position in the account list. A CDN can cache this shared dealing for efficient distribution.

Each validator checks the payer signatures and the operator's countersignatures, derives incoming credits, and combines them with its stored balances and the deposits and withdrawals fixed at epoch registration.

From these results, every validator derives three roots, all backed by QMDB:

- The **state root** commits the current positive balances.
- The **activity root** commits the cumulative log of account Rows and payment Entries.
- The **payout root** commits the cumulative log of external payout outputs.

Activity and payouts use [Keyless QMDBs](https://docs.rs/commonware-storage/latest/commonware_storage/qmdb/keyless/) backed by flat Merkle mountain ranges (MMRs).

Each close appends its sorted account Rows, then its payment Entries grouped by payer. A Row records the account's final debit, sequence number, and outgoing-payment binary Merkle tree (BMT) root. The certified row range includes zero-net participants, so their receipts remain challengeable even when their balances do not change. A proof server can read the Entries directly from QMDB to reconstruct the payer's signed BMT.

A 32-byte close commitment binds these results to the operator's dealing and the epoch's context. Validators already hold the balances needed to compute the new state, so the dealing needs no state-change proof.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-trees.svg" alt="A close commitment binds three validator-derived QMDB roots: state, activity, and payout. State uses Current Ordered QMDB, while activity and payouts use Keyless QMDB. The activity strip shows earlier closes followed by this close's four sorted Rows and payment Entries grouped by payer. The highlighted Row for c contains debit 11, sequence 2, and the outgoing-payment BMT root signed by c. Its two leaves pay 4 to b and 7 to d, one payment each. The state database retains the resulting balances. This close creates no payouts.">
```

::: {.image-caption}
Figure 3: The close binds three validator-derived roots. The activity log appends this close's Rows and original Entries after those from earlier closes. Below, $c$'s Row names the BMT root that $c$ signs, and its two entries sum to the Row's debit of 11.
:::

The settlement chain keeps these commitments and counts, bounded pending-close metadata, custody and timing controls, and claimed payout ranges. Replicas store the underlying account and log records.

## Certify the Whole Close

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Every signer checks the complete close, derives the same transitions, and signs the same commitment. A certificate needs $q=2f+1$ signatures.

The dealing's $\mathsf{ProposalId}$ hashes its canonical bytes with the authenticated epoch context. The certified close binds that identifier, the exact predecessor snapshot, all three successor roots, both log counts and epoch ranges, and the withdrawal total. This lets the operator check that a certificate belongs to its proposal without rebuilding the validators' logs.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-full-validation.svg" alt="The operator sends the same dealing to 100 validators. The blue callout expands c's sender record: final sequence 2, a total of 4 to b and 7 to d, each with count 1, bound by c's signature. Four cards show the operator accepting the final payer states of a, b, c, and d, then aggregating those acknowledgments. Validators derive the Current Ordered QMDB state root and the two Keyless QMDB roots for activity and payouts, then bind them with the certified close context into one 32-byte commitment. An aggregate signature and signer bitmap form its 67-of-100 certificate. Each validator durably commits the three public candidates in parallel, then durably records its private control-QMDB checkpoint and signing decision before acknowledging. The certified candidate contains the three shared roots.">
```

::: {.image-caption}
Figure 4: Every validator derives the same three QMDB roots before signing one close commitment.
:::

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked at committee registration. Including the 32-byte commitment and an eight-byte bitmap-length prefix, the total for 100 validators is 101 bytes. The validator-derived root bundle is 184 bytes. Adding the eight-byte withdrawal total makes its descriptor 192 bytes, or 293 bytes together before chain transaction framing. These values are separate from the operator's dealing.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. A successful challenge invalidates that close and any pending descendants, whose outputs never enter the finalized payout root and cannot be claimed.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out. This limitation applies equally to Bajillion, ZK rollups, payment channels, and any other system offering binding preconfirmations.

Consider two executions with the same public close $\mathcal D_e$ and certificate, proof, or attestation $\zeta$. In $\Xi_0$, the operator signs only the acknowledgments represented by the close. In $\Xi_1$, it also delivers a valid private acknowledgment $R^+$. The verifier sees the same evidence in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A committee, TEE, or SNARK/STARK can verify the published inputs. Certifying those inputs cannot rule out an additional private receipt.

Each close's certified account range records the final activity of every disclosed account. A missing payer counts as zero debit, so a proof of absence can challenge an omitted payment. For a nonempty range, an MMR proof opens the neighboring Rows, or the Row at either end of the range. A certified row count of zero proves that the range is empty. Strict key ordering and uniqueness make these cases exhaustive.

Receipt holders can prove three kinds of contradiction:

1. **Debit mismatch.** The close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Because validators have already checked the accounting and signed payer states, a receipt holder can prove a contradiction in one onchain call using signatures and any required Merkle openings. Every receipt a user relies on needs an honest holder who retains it, obtains the public openings from a replica, and gets a challenge included by $\Delta_e$.

Suppose $b$ has already served the API response, but the operator leaves $a$'s payment of 20 out of the close. The receipt and a public proof of the omission let $b$ prove operator fault without the operator's cooperation. An application could use this evidence to compensate $b$ from an onchain insurance fund, permanently exclude the operator, or support offchain resolution.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain, even during an active epoch. The next registration must include it.

Once a withdrawal request is queued onchain or included in an admitted close, the close that carries it must finalize before the signed deadline $T_w$ to avoid a hard fault. With challenge deadline $\Delta_e$,

$$
\boxed{\Delta_e<t_{\mathrm{finalize}}<T_w.}
$$

An exact withdrawal releases its amount if the epoch's final balance covers it. An account close sweeps that balance. Every derived withdrawal output, including a zero-valued one, is appended to one payout MMR at a stable global index. An MMR opening binds that index to the output's destination and amount. The output has no claim deadline, and its index is never recycled.

Pending outputs become claimable only when the close that carries them reaches finality. The chain then advances its finalized payout root and count and reserves the exact outflow. A challenged or invalidated suffix advances neither root nor count and reserves no outflow.

A claim supplies the output and an MMR opening against the current finalized payout root and count. The chain tracks paid indices in an ordered map of disjoint **claimed ranges**, storing the exclusive end under each range's start. It rejects a claim if its index $i$ is already covered. Otherwise it inserts $[i,i+1)$ and merges any touching neighbors. Recording the claim, reducing the reserve, and paying the destination happen atomically. A replay is rejected even though its membership opening remains valid.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-payout-ranges.svg" alt="Only finalized payout indices 10 through 14 are shown. Other claimed-map records are outside this illustration. Claimed ranges record paid outputs. Claiming 12 creates [12,13). Claiming 10 and 14 adds [10,11) and [14,15). Claiming 11 joins the first two ranges into [10,13), and claiming 13 merges all five paid outputs into [10,15). Replaying output 12 is rejected because that range already contains it, even though the same MMR opening remains valid. Each claim atomically records its index, reduces the reserve, and pays.">
```

::: {.image-caption}
Figure 5: The MMR proves that a payout exists. Claimed ranges prevent paying it twice. Filling a gap merges neighboring ranges, so these five claims occupy one record. Only payout indices 10–14 are shown. Ranges are end-exclusive.
:::

Each claim checks only its neighboring ranges. Non-payout log positions are included in claimed ranges so close boundaries do not prevent merging. Fully paid history collapses to one range. With $U$ outstanding outputs, at most $U+1$ ranges remain, even under adversarial claim order.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable, with no expiry, and refund unadmitted deposits. Accounts recover their balances with QMDB proofs against the frozen root, and each account can claim only once. A close that was never admitted or was invalidated changes neither the recoverable balances nor the finalized payouts.

Even if the operator disappears, recovery depends on a correct, live settlement chain and independently available balance and payout openings. The fault also freezes the last finalized payout root and count, against which later claims refresh their openings.

## Streamlined Epoch Transitions

A payment reaches finality through an admitted close, after the challenge deadline fixed at epoch registration. Shorter epochs with earlier deadlines can reduce that wait, but require more frequent preparation and certification.

Once epoch $e$'s close is admitted, the operator can register $e+1$ against its $\mathsf{StateRoot}$ and start payments before $e$ finalizes. Registration fixes deposits and signed withdrawal authorizations before the first payment is acknowledged.

For accounts without deposits or withdrawals, successor payments can proceed while predecessor credits are still being imported. The preserved head $\widetilde B_a$ is the starting balance minus accepted predecessor debits plus credits already imported. The remaining predecessor credit is $\rho_a$:

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad \rho_a\ge0.}
$$

The account can spend from the preserved head. Importing credit adds $\rho_a$ to the live balance, preserving any successor debits already accepted.

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
Figure 6: Both calculations include the same predecessor credit. Importing it adds to the live balance, preserving payments already accepted in the successor epoch.
:::

Deposits fixed at registration are available immediately. A new account funded only by incoming credit must wait for that close to be admitted before spending. A wallet with a live withdrawal authorization waits until its signed deadline before signing another payment.

## Collecting Fees

Because one signature can advance several recipients in a batch, an operator can require the payer to include a payment to a designated fee recipient, such as the operator's own account. It checks the requested payments and the fee increment before countersigning. If the fee is insufficient, it rejects the entire batch. For an accepted batch, it returns one acknowledgment containing an opening for each advanced entry. The payer authorizes the fee alongside the other payments, and the operator's acknowledgment binds them together.

The operator can price each transfer type or payer independently, including volume discounts or negotiated rates. Validators net the fee entry like any other payment, and settlement uses the same commitments and proofs. The fee schedule stays with the operator, so changing it requires no protocol change.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-fees.svg" alt="Payer a signs one batch paying 20 to b, 7 to c, and the operator's quoted fee of 2. The signed state binds the epoch, sequence 1, cumulative debit 29, and payment root. Recipient b's receipt contains the operator-countersigned payer state and an opening for b's entry, with amount 20 and payment count 1.">
```

::: {.image-caption}
Figure 7: The fee shares the same signed payment root as the recipient payments. Recipient $b$ receives the countersigned payer state and an opening for its own entry.
:::

## The Cost of Settlement

We benchmarked the Commonware Library's [reference implementation](https://github.com/commonwarexyz/monorepo/pull/4664) with one million live accounts, a fixed recipient pool of $B=512$, and one recipient per payer $K=1$. We vary active payers $A$. The operator sends the dealing to validators, who derive the close descriptor and certify its commitment.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Measurement</th>
      <th colspan="4" style="text-align:center;">One million live accounts</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>A</em> = 1,000</th>
      <th style="text-align:right;"><em>A</em> = 10,000</th>
      <th style="text-align:right;"><em>A</em> = 100,000</th>
      <th style="text-align:right;"><em>A</em> = 1,000,000</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Operator: dealing</td><td style="text-align:right;">103 KB</td><td style="text-align:right;">1.03 MB</td><td style="text-align:right;">10.3 MB</td><td style="text-align:right;">103 MB</td></tr>
    <tr><td>Operator: prepare</td><td style="text-align:right;">1.15 ms</td><td style="text-align:right;">12.1 ms</td><td style="text-align:right;">140 ms</td><td style="text-align:right;">1.60 s</td></tr>
    <tr class="clearing-role-divider"><td>Validator: durable vote</td><td style="text-align:right;">14.0 ms</td><td style="text-align:right;">70.7 ms</td><td style="text-align:right;">581 ms</td><td style="text-align:right;">6.14 s</td></tr>
  </tbody>
</table>
</div>
```

The close descriptor is 192 B, and the commitment with its 100-validator certificate is 101 B.

::: {.image-caption}
Figure 8: Means of three runs with no warmup. The validator timer covers validation, sealing, signing, and durable writes to the public and private QMDBs. It starts with an encoded dealing and an open, durable predecessor. Setup and reopen checks are excluded. Sizes use decimal KB and MB.

AWS c8a.4xlarge: 16 AMD EPYC vCPUs, 32 GiB RAM, and a 160 GiB gp3 EBS SSD (6,000 IOPS, 250 MiB/s, ext4). Votes wait for filesystem durability barriers to network-attached EBS. Validation and the three public databases share 16 workers, with two I/O workers. The shared cache is 1 GiB with 4 KiB pages. State/activity write buffers are 256 MiB, other write and replay buffers 8 MiB. Full state/activity sections occupy 2.1–2.3 GiB, Merkle blobs about 2 GiB. Fixtures fit in RAM. All fixtures use benchmark limits, since one million accounts exceed the deployed genesis bound.
:::

Repeated payments between the same pairs reuse these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots show modeled bytes per payment as one million to one billion unit payments pass between fixed pairs. The left shows one validator's keyed update for four account counts, including growing cumulative counters. The right shows the 101-byte commitment and certificate.">
```

::: {.image-caption}
Figure 9: Every account repeatedly pays one unit to its next neighbor. More payments share the byte cost of the operator's dealing and the 100-validator committee's certificate. The right plot includes the 101-byte commitment and certificate. The 192-byte close descriptor is separate.
:::

### Proof Sizes and Verification

Complete challenges include the signed receipts and any required Merkle openings. These fixtures use one million live accounts, a 512-account recipient pool, and one recipient per payer. Sizes are encoded bytes.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Complete challenge</th>
      <th colspan="4" style="text-align:center;">Active payers</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>A</em> = 1,000</th>
      <th style="text-align:right;"><em>A</em> = 10,000</th>
      <th style="text-align:right;"><em>A</em> = 100,000</th>
      <th style="text-align:right;"><em>A</em> = 1,000,000</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Debit mismatch</td><td style="text-align:right;">622 B <small>present</small><br>657 B <small>omitted</small></td><td style="text-align:right;">751 B <small>present</small><br>786 B <small>omitted</small></td><td style="text-align:right;">847 B <small>present</small><br>882 B <small>omitted</small></td><td style="text-align:right;">943 B <small>present</small><br>978 B <small>omitted</small></td></tr>
    <tr><td>Entry mismatch</td><td style="text-align:right;">673 B</td><td style="text-align:right;">802 B</td><td style="text-align:right;">898 B</td><td style="text-align:right;">994 B</td></tr>
    <tr><td>Acknowledgment fork</td><td style="text-align:right;">417 B</td><td style="text-align:right;">417 B</td><td style="text-align:right;">417 B</td><td style="text-align:right;">417 B</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 10: All measured challenges fit in 1 KB. An omitted payer is the absence case of debit mismatch.
:::

A payout proof opens one output under the current finalized root.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Payout proof</th>
      <th colspan="4" style="text-align:center;">Payouts</th>
    </tr>
    <tr>
      <th style="text-align:right;">1</th>
      <th style="text-align:right;">1,024</th>
      <th style="text-align:right;">500,000</th>
      <th style="text-align:right;">1,000,000</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Payout claim</td><td style="text-align:right;">105 B<br><small>402 ns</small></td><td style="text-align:right;">394 B<br><small>1.23 µs</small></td><td style="text-align:right;">651 B<br><small>2.04 µs</small></td><td style="text-align:right;">683 B<br><small>2.15 µs</small></td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 11: Each proof includes a 30-byte output and its MMR opening, measured at the middle payout. Verification starts from decoded inputs, with times averaged over 20 samples. The trusted root and transaction framing are separate.
:::

Balance proofs authenticate withdrawal requests and recovery claims. With one million live accounts, all three measured payloads are under 1 KB.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th style="text-align:left; width:32%;">Balance proof</th><th style="text-align:right;">One million live accounts</th></tr>
  </thead>
  <tbody>
    <tr><td>Account present</td><td style="text-align:right;">853 B</td></tr>
    <tr><td>Account absent</td><td style="text-align:right;">886 B</td></tr>
    <tr><td>Recovery claim</td><td style="text-align:right;">884 B</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 12: Current Ordered QMDB proofs after updating all one million balances. Recovery includes the account identity as well as its balance proof. The trusted root and transaction framing are separate.
:::

Adjust the workload and committee size below to estimate the operator's traffic.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive calculator for keyed validator dealings. Sliders set live accounts, average recipients per account, and validators. Results show one modeled update per validator, its composition, total operator egress, and a dotted reference for the encoded account records.">
  <noscript>Each validator retains the complete account state and receives one compact update per close. Total operator egress is the update size multiplied by the validator count. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 13: Modeled operator dealing per validator, with total operator traffic in parentheses. The dotted line shows all live account records at 40 bytes each, before database overhead and retained evidence. Both axes are logarithmic. The model excludes the close descriptor, certificate, and transport framing.

Each sender signs one batch of unit payments. Recipients per account is averaged over all live accounts. Below an average of one, the first senders pay the last recipients in key order. Otherwise, every account pays its next neighbors cyclically. All accounts stay live, with no deposits or withdrawals. Estimates beyond the prototype's per-close limits extrapolate the same encoding.
:::

## A Bajillion Payments, One Settlement

Send a million payments without paying for a million onchain transactions.

Recipients can deliver the goods as soon as they verify a binding receipt, with evidence to challenge any payment the operator later omits or contradicts. Sharing settlement costs makes small exchanges practical, down to an agent buying a single API response.

The settlement chain keeps compact commitments and merged claimed ranges, a small fraction of the total activity.
