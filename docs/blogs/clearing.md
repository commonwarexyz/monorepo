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

*Update (9/15/26): Operators can process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain the account state in QMDB and apply only the changes at each settlement.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a \~100-byte certified commitment that most chains can process. Binding receipts arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery onchain without its cooperation. And the protocol requires only signatures and Merkle openings.

One payment or a bajillion, each account settles once.

## Payments as Fast as Browsing the Web

If an API responds in milliseconds, no one will wait seconds to pay for it.

With Bajillion, a user can pay an API provider without waiting for settlement. Their chosen payment operator returns a binding receipt in one round trip. The user sends it with the API request, or the operator delivers it directly to save a hop. The provider can serve the response knowing it holds evidence to challenge any operator settlement that omits or contradicts the payment. The operator later nets payments across accounts without separate channels or funded routes, dramatically reducing the data needed for settlement.

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

Each row records the account's activity, including its last signed endpoint if it sent payments. Every validator derives the resulting balances and checks the epoch's gross debit $D_e$ and credit $C_e$:

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
Figure 2: A separate epoch with 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

QMDB Current Ordered with MMB stores each live account's balance under its public key, committed by $\mathsf{StateRoot}$. Deposits and payments can add accounts, and a zero balance removes the record. Payment totals and counts belong to the epoch's evidence.

When a payment names a new public key, the operator records a balance for it without an onchain registration transaction. The recipient can spend the balance after the close is admitted, or let payments from many senders accumulate across multiple closes before authorizing a sweep.

## Keep the State, Send the Changes

Every validator retains the complete account state in QMDB. At each close, the operator publishes one dealing for all of them: active account keys, senders' terminal signed endpoints, and cumulative payment entries. Recipients are identified by position in the account list. A CDN can cache this shared dealing for efficient distribution.

Each validator checks the payer signatures and the operator's countersignatures, derives incoming credits, and combines them with its stored balances and the deposits and withdrawals fixed at epoch registration.

From these results, the validator builds the activity and withdrawal binary Merkle trees (BMTs) and computes the next QMDB state root. The activity tree includes accounts whose payments leave their balances unchanged, so those receipts remain challengeable. QMDB updates the balance tree incrementally, without rebuilding it over every live account.

All three roots are results of validation. A 32-byte commitment binds them to the epoch, prior state, and withdrawal total. Validators already hold the balances needed to compute the new state, so the dealing needs no state-change proof. They install the candidate state once the close is admitted.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-trees.svg" alt="Each validator derives the balance, activity, and withdrawal roots bound by the commitment. QMDB carries balances of a: 85, b: 58, c: 26, and d: 31 into the next epoch. Account c's activity record shows 11 sent, final batch sequence 2, no withdrawal, and a link to its payment tree: one payment of 4 to b and one of 7 to d. No withdrawals were requested. The withdrawal panel shows the destination and amount a claim would prove.">
```

::: {.image-caption}
Figure 3: The commitment links the three roots. Expanding $c$'s activity record shows its final payment totals for $b$ and $d$.
:::

The settlement chain holds pooled custody and the certified state root. Validators keep the account records and evidence available for challenges and recovery.

The operator can also keep a QMDB replica to serve current and historical balance proofs directly. Preparing the dealing does not depend on that replica.

## Certify the Whole Close

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Every signer checks the complete close, retains its evidence, and signs the same commitment. A certificate needs $q=2f+1$ signatures.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-full-validation.svg" alt="The operator sends the same dealing to 100 validators. The blue callout expands c's sender record: final sequence 2, a total of 4 to b and 7 to d, each with count 1, bound by c's signature. Four acknowledgment cards show the operator's signatures accepting the final endpoints of a, b, c, and d. The c card is highlighted. An Aggregate arrow leads to the single aggregate signature included in the dealing. Validators derive the final commitment. The green callout shows the state, activity, and withdrawal roots bound to the epoch, prior state, and zero withdrawal total by a 32-byte commitment. An aggregate signature and signer bitmap form its 67-of-100 certificate.">
```

::: {.image-caption}
Figure 4: Each validator derives the three roots from the shared dealing. One aggregate signature and signer bitmap show that 67 of 100 validators signed the resulting commitment.
:::

An honest signer retains the close and its predecessor state durably before publishing its vote. It keeps predecessor and successor proofs available while the close is pending and through its challenge deadline $\Delta_e$, and retains the last finalized state for recovery. A new validator replays the retained updates and checks the resulting state root.

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator certified commitment is 101 bytes. Admission also supplies the three roots and withdrawal total, another 104 bytes.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. A successful challenge blocks that close and its pending descendants.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out.

Consider two executions with the same public close $\mathcal D_e$ and certificate, proof, or attestation $\zeta$. In $\Xi_0$, the operator signs only the acknowledgments represented by the close. In $\Xi_1$, it also delivers a valid private acknowledgment $R^+$. The verifier sees the same evidence in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A committee, TEE, or SNARK/STARK can verify the published inputs. Certifying those inputs cannot rule out an additional private receipt.

The activity tree records each active account's terminal position. A missing payer counts as zero debit, so a proof of absence can challenge an omitted payment. Receipt holders can prove three kinds of contradiction:

1. **Debit mismatch.** For example, the close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Because certification has checked the accounting and signed terminal positions, a receipt holder can prove a contradiction with signatures and Merkle openings in one onchain call, without an interactive dispute game. Every receipt a user relies on needs an honest holder who retains the evidence, obtains the public openings, and gets a challenge included by $\Delta_e$. Validators retain the public corpus but cannot reconstruct a private receipt nobody saved.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain, even during an active epoch. The next registration must include it.

Once a withdrawal request is queued onchain or included in an admitted close, its carrying close must finalize before the signed deadline $T_w$ to avoid a hard fault. With challenge deadline $\Delta_e$,

$$
\boxed{\Delta_e<t_{\mathrm{finalize}}<T_w.}
$$

An exact withdrawal releases its amount if the epoch's final balance covers it. An account close sweeps that balance. Once the carrying close finalizes, the user claims the certified payout with an opening in that close's withdrawal-output BMT. Each output can be claimed only once.

Custody remains onchain throughout. Finalization reserves withdrawals, and individual claims reduce the reserve and the chain's assets together. A challenged or invalidated close creates no payout reserve.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable and refund unadmitted deposits. Accounts recover their balances with QMDB proofs against the frozen root, and each account can claim only once. Payments in a never-admitted or invalidated close do not debit that state.

Recovery needs a correct, live settlement chain and available claim openings even when the operator disappears.

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
Figure 5: Both calculations include the same predecessor credit. Importing it adds to the live balance, preserving payments already accepted in the successor epoch.
:::

Accounts with deposits or withdrawals must resolve their full admitted outcome before spending in the successor epoch.

## The Close Follows Accounts and Edges

We benchmarked the Commonware Library's [initial implementation](https://github.com/commonwarexyz/monorepo/pull/4664) with each account sending one unit payment to one of 512 recipients. All 100 validators receive the same update.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Measurement</th>
      <th colspan="4" style="text-align:center;">Live accounts (<em>N</em>), all sending</th>
    </tr>
    <tr>
      <th style="text-align:right;">1,024</th>
      <th style="text-align:right;">10,000</th>
      <th style="text-align:right;">100,000</th>
      <th style="text-align:right;">1,000,000</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Validator dealing</td>
      <td style="text-align:right;">105 KB<br><small>8.03 ms</small></td>
      <td style="text-align:right;">1.03 MB<br><small>57.7 ms</small></td>
      <td style="text-align:right;">10.3 MB<br><small>566 ms</small></td>
      <td style="text-align:right;">103 MB<br><small>6.54 s</small></td>
    </tr>
    <tr>
      <td>Commitment + certificate</td>
      <td style="text-align:right;">101 B<br><small>672 µs</small></td>
      <td style="text-align:right;">101 B<br><small>672 µs</small></td>
      <td style="text-align:right;">101 B<br><small>672 µs</small></td>
      <td style="text-align:right;">101 B<br><small>672 µs</small></td>
    </tr>
  </tbody>
  <tbody>
    <tr><th colspan="5" style="text-align:left;">Processing phases</th></tr>
    <tr>
      <td style="text-align:left;">Operator: prepare and apply</td>
      <td style="text-align:right;">5.61 ms</td>
      <td style="text-align:right;">28.7 ms</td>
      <td style="text-align:right;">333 ms</td>
      <td style="text-align:right;">4.09 s</td>
    </tr>
    <tr>
      <td style="text-align:left;">Validator: decode</td>
      <td style="text-align:right;">0.726 ms</td>
      <td style="text-align:right;">6.73 ms</td>
      <td style="text-align:right;">74.3 ms</td>
      <td style="text-align:right;">907 ms</td>
    </tr>
    <tr>
      <td style="text-align:left;">Validator: verify and sign</td>
      <td style="text-align:right;">6.95 ms</td>
      <td style="text-align:right;">48.9 ms</td>
      <td style="text-align:right;">472 ms</td>
      <td style="text-align:right;">5.36 s</td>
    </tr>
    <tr>
      <td style="text-align:left;">Validator: apply balances</td>
      <td style="text-align:right;">0.234 ms</td>
      <td style="text-align:right;">2.07 ms</td>
      <td style="text-align:right;">19.7 ms</td>
      <td style="text-align:right;">275 ms</td>
    </tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 6: Measured on an AWS c8a.4xlarge with 16 workers, 32 GiB RAM, and a 100 GiB EBS gp3 SSD (3,000 IOPS, 125 MiB/s). Table timings use in-memory storage and exclude durable commit and networking. Certificate verification uses one thread. The SSD run uses a 4 MiB QMDB cache; the full dataset fits in RAM.
:::

With only 1,024 of a million live accounts paying the same 512 recipients, each validator processes a 105 KB update in 8.69 ms in memory, or 20.5 ms including SSD commit.

Repeated payments between the same pairs reuse these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots show modeled bytes per payment as one million to one billion unit payments pass between fixed pairs. The left shows one validator's keyed update for four account counts, including growing cumulative counters. The right shows the 101-byte commitment and certificate.">
```

::: {.image-caption}
Figure 7: Every account repeatedly pays one unit to its next neighbor. Counters grow, while more payments share the byte cost of one validator's update and the 100-validator committee's certificate.
:::

### Proof Sizes and Verification

The tables below show encoded proof sizes, with verification times beneath them. Times are medians of ten samples on one CPU thread of the same host, starting from decoded proofs.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">Challenge</th><th colspan="4" style="text-align:center;">Active accounts, all sending</th></tr>
    <tr><th style="text-align:right;">1,024</th><th style="text-align:right;">10,000</th><th style="text-align:right;">100,000</th><th style="text-align:right;">1,000,000</th></tr>
  </thead>
  <tbody>
    <tr><td>Debit mismatch</td><td style="text-align:right;">588 B<br><small>224 µs</small></td><td style="text-align:right;">716 B<br><small>215 µs</small></td><td style="text-align:right;">812 B<br><small>223 µs</small></td><td style="text-align:right;">908 B<br><small>213 µs</small></td></tr>
    <tr><td>Entry mismatch</td><td style="text-align:right;">639 B<br><small>225 µs</small></td><td style="text-align:right;">767 B<br><small>216 µs</small></td><td style="text-align:right;">863 B<br><small>223 µs</small></td><td style="text-align:right;">959 B<br><small>214 µs</small></td></tr>
    <tr><td>Acknowledgment fork</td><td style="text-align:right;">417 B<br><small>220 µs</small></td><td style="text-align:right;">417 B<br><small>212 µs</small></td><td style="text-align:right;">417 B<br><small>219 µs</small></td><td style="text-align:right;">417 B<br><small>218 µs</small></td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 8: BMT challenges for payers included in the close, with Ed25519 receipts and one-entry vectors. Sizes exclude the separately supplied close and chain transaction framing.
:::

A normal withdrawal opens a certified output in its close's BMT. Its proof grows with the number of withdrawal outputs $W$, independently of the live account database.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Measurement</th>
      <th colspan="5" style="text-align:center;">Withdrawal outputs in the close (<em>W</em>)</th>
    </tr>
    <tr>
      <th style="text-align:right;">1</th>
      <th style="text-align:right;">1,024</th>
      <th style="text-align:right;">10,000</th>
      <th style="text-align:right;">100,000</th>
      <th style="text-align:right;">1,000,000</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Withdrawal-output claim</td>
      <td style="text-align:right;">39 B<br><small>0.314 µs</small></td>
      <td style="text-align:right;">359 B<br><small>1.18 µs</small></td>
      <td style="text-align:right;">487 B<br><small>1.52 µs</small></td>
      <td style="text-align:right;">583 B<br><small>1.79 µs</small></td>
      <td style="text-align:right;">679 B<br><small>2.05 µs</small></td>
    </tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 9: Withdrawal outputs with a 21-byte destination and maximum-depth BMT paths. Verification checks inclusion under a supplied root. Chain transaction framing is excluded.
:::

QMDB proofs authenticate balances for forced withdrawal intake and recovery. A recovery claim opens the account's balance at the frozen finalized root.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">QMDB proof payload</th><th colspan="4" style="text-align:center;">Live accounts</th></tr>
    <tr><th style="text-align:right;">1,024</th><th style="text-align:right;">10,000</th><th style="text-align:right;">100,000</th><th style="text-align:right;">1,000,000</th></tr>
  </thead>
  <tbody>
    <tr><td>Account present</td><td style="text-align:right;">497 B<br><small>1.53 µs</small></td><td style="text-align:right;">593 B<br><small>1.83 µs</small></td><td style="text-align:right;">691 B<br><small>2.14 µs</small></td><td style="text-align:right;">819 B<br><small>2.58 µs</small></td></tr>
    <tr><td>Account absent</td><td style="text-align:right;">530 B<br><small>1.53 µs</small></td><td style="text-align:right;">626 B<br><small>1.83 µs</small></td><td style="text-align:right;">724 B<br><small>2.14 µs</small></td><td style="text-align:right;">852 B<br><small>2.59 µs</small></td></tr>
    <tr><td>Recovery balance opening</td><td style="text-align:right;">528 B<br><small>1.53 µs</small></td><td style="text-align:right;">624 B<br><small>1.83 µs</small></td><td style="text-align:right;">722 B<br><small>2.15 µs</small></td><td style="text-align:right;">850 B<br><small>2.56 µs</small></td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 10: Current Ordered proofs after the initial insertion batch, using a middle account and a missing key. SHA-256/MMB, 32-byte bitmap chunks, and 8-byte balances. Lookup rows omit the known account key, while recovery includes it. All omit the trusted root and chain framing. Sizes vary with history and proof position.
:::

Adjust the workload and committee size below to estimate the operator's traffic.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive calculator for keyed validator dealings. Sliders set live accounts, average recipients per account, and validators. Results show one modeled update per validator, its composition, total operator egress, and a dotted reference for the encoded account records.">
  <noscript>Each validator retains the complete account state and receives one compact update per close. Total operator egress is the update size multiplied by the validator count. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 11: Modeled keyed update per validator, with total operator egress in parentheses. Dotted: all live account records (40 bytes each), before database overhead and retained evidence. Both axes are logarithmic. Sizes exclude certificates, transport, and other messages.

Each sender signs one batch of unit payments. Recipients per account is averaged over all live accounts. Below an average of one, the first senders pay the last recipients in key order. Otherwise, every account pays its next neighbors cyclically. All accounts stay live, with no deposits or withdrawals. Estimates beyond the prototype's per-close limits extrapolate the same encoding.
:::

## A Bajillion Payments, One Settlement

Send a million payments without paying for a million onchain transactions.

That makes small exchanges practical, like an agent buying a single API response. Recipients can deliver the goods now, knowing the operator has made a binding commitment to the payment. If the operator later omits or contradicts that payment, the signed receipt gives them the evidence to challenge the close.

The settlement chain only keeps the change.
