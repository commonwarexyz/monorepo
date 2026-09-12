---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-11T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/11/26): Operators can process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain the account state in QMDB and apply only the changes at each close.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a \~100-byte certified commitment that most chains can process. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

One payment or a bajillion, each account settles once.

## Payments as Fast as Browsing the Web

If an API responds in milliseconds, no one will wait seconds to pay for it.

Suppose $a$ has 100 and wants to pay 20 to $b$, who has 40. With Bajillion, $a$ sends its chosen operator a signed request $S$ advancing its running total for $b$. The operator checks the signature and funds, records acceptance, and returns its signed acknowledgment $R$ with a proof of $b$'s entry. In one round trip, $a$ has a receipt to forward to $b$, who can verify it locally and retain it as evidence. The operator can save a hop by sending the receipt directly to $b$. Settlement comes later, netting payments across all accounts using that operator without separate channels or funded routes.

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
Figure 1: The operator verifies, commits, and countersigns locally. The payer verifies and retains the receipt before forwarding it. The dotted path is an optional operator push that reaches the recipient one hop earlier. The entry records total amount and payment count, changing $(0,0)$ to $(20,1)$.
:::

An epoch groups accepted payments into a "close", the settlement package the operator builds when that epoch ends. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

The payer tracks a balance $B_a$ and a cumulative debit $D_a$ that starts at zero each epoch. Its activity within that epoch is one strictly recipient-sorted vector $V_a$ with one cumulative entry per recipient it paid. The entry $(G,J)$ for $b$ is $a$'s cumulative credit to $b$ this epoch and the number of payments behind it. Before the example payment, $a$ holds $B_a=100$ and $D_a=0$, and $V_a$ is empty.

To send $x>0$ from $a$ to $b$, the payer advances $b$'s entry in its own vector and signs the resulting endpoint, its cumulative position after this send: an epoch-local sequence number $n_a$, the cumulative debit, and the vector's Merkle root. The operator's acknowledgment countersigns the same body:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

Here the endpoint is $n_a=1$, $D_a=20$, and the root of $V_a=\{b:(20,1)\}$. The operator checks $S$ and available funds, durably records acceptance, then returns $R$ with an opening of $b$'s entry.

The receipt lets the recipient verify acceptance locally before relying on the payment. The wallet keeps one unacknowledged request in flight, retries it unchanged after response loss, and durably saves the verified acknowledgment and openings before signing the next endpoint. One signature can also advance several recipients in a batch. The operator accepts or rejects the whole batch and returns one acknowledgment with an opening for each advanced entry.

## Optimizing for Hot Accounts

Bajillion defines each payment as an update to the payer's outgoing vector. This lets the operator accept payments from different payers in parallel, even when they share a recipient. Incoming credit stays a promise until the epoch ends. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry in $a$'s vector:

$$
(G_{ab},J_{ab})\longrightarrow(G_{ab}+x,J_{ab}+1),
\qquad
\text{every other entry of every other vector unchanged.}
$$

However many payments an edge carries, the epoch ends with one cumulative entry for it.

Consider accounts $(a,b,c,d)$ that open with balances $(100,40,25,35)$ and the epoch accepts

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

Each payer's last vector of the epoch is its terminal vector. The operator and validators derive incoming credits from these vectors: $b$ receives $20+4+6=30$ across three payments. Each entry is authenticated by its payer's signed vector root.

## One Row per Active Account

Netting each of the four accounts' debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross debit equals gross credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. The six payments change four account rows, one per account.

For each account, the opening and closing balances are $B_a^0$ and $B_a^1$, with debit and credit deltas $d_a$ and $c_a$. Deposits $f_a$, withdrawals $w_a$, and external payouts $p_a$ complete the balance equation:

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

A recipient without a live account can receive a net external payout onchain after finalization. The row validator derives each settlement output from the same balance equation and signed authorizations.

Each row describes the account's activity and, when it sent, its terminal signed endpoint. Every validator derives the resulting balances and checks the epoch's gross debit $D_e$ and credit $C_e$:

$$
\boxed{D_e=C_e.}
$$

Here $D_e=C_e=54$. Summing account balances into $L_e$ and $L_{e+1}$ cancels payments, leaving only deposits $F_e$, withdrawals $W_e$, and external payouts $P_e$:

$$
\boxed{L_{e+1}=L_e+F_e-W_e-P_e.}
$$

With no boundary flows, $L_{e+1}=L_e=200$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-netting.svg" alt="100 million payments across six directed pairs net into balance changes for four active accounts. Account a sends $30 and receives $10, moving from $100 to $80. Account b sends $25 and receives $55, moving from $40 to $70. Account c sends $20 and receives $25, moving from $25 to $30. Account d sends $25 and receives $10, moving from $35 to $20. The close retains six cumulative entries and four account records.">
```

::: {.image-caption}
Figure 2: A separate epoch with 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

QMDB Current Ordered with MMB stores each live account's balance under its public key, committed by $\mathsf{StateRoot}$. Presence means the account is live. Deposits can add accounts, while withdrawals and payments can remove them when their balance reaches zero. Payment totals and counts belong to the epoch's evidence.

## Keep the State, Send the Changes

Every validator retains the complete operator account state. At each close, the operator sends the same compact update to all of them: the sending accounts' terminal signed endpoints, their cumulative payment entries, and the accounts involved. This shared dealing can be cached on a CDN for efficient, inexpensive distribution.

Accounts are named by public key, and payment entries refer to those accounts by their position within the close. Each validator checks the payer signatures and the operator's acceptance, derives every recipient's credit, and applies the deposits and withdrawals fixed at epoch registration.

Validators derive the balance changes and apply the same canonical QMDB batch to the same predecessor database. QMDB updates its authenticated state without rebuilding the tree over every live account. Validators already hold the prior state, so the operator needs no separate state-change proof.

The payer vectors are the common source of truth for both sides of every payment. Validators build a BMT of the epoch's account activity, retaining terminal payment positions and settlement outputs for challenges and claims. This evidence includes accounts whose balances stay unchanged. A 32-byte commitment binds the activity BMT, withdrawal-output BMT, and QMDB state root to the epoch, predecessor, and checked settlement totals.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-trees.svg" alt="The certified close binds QMDB balances, account activity, and withdrawal outputs. Each payer's payment BMT is nested in its activity record. The running example expands account c: its balance is 26, its terminal debit is 11, and its payment tree contains b with amount 4 and count 1 and d with amount 7 and count 1. Withdrawal leaves show the destination and amount format used when withdrawals are requested.">
```

::: {.image-caption}
Figure 3: The close binds the three resulting roots. Each payer's payment tree is nested in its activity record, which remains present even when its payments leave the balance unchanged.
:::

The settlement chain holds pooled custody and the certified state root. Validators keep the account records and evidence available for challenges and recovery.

## Certify the Whole Close

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Every signer checks the complete close, retains its evidence, and signs the same commitment. A certificate needs $q=2f+1$ signatures.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-full-validation.svg" alt="The operator sends the same compact update to every validator. Each validator checks it against the balances it retains in QMDB, derives the account activity and balance changes, and signs the resulting commitment. A quorum of signatures forms the certificate.">
```

::: {.image-caption}
Figure 4: Each validator checks the same update against its complete prior state. With 100 validators and at most 33 faulty members, a 67-signature certificate includes at least 34 honest validators that checked and retain the entire close.
:::

An honest signer retains the close and its predecessor state durably before publishing its vote. It keeps predecessor and successor proofs available while the close is pending and through its challenge deadline $\Delta_e$, and retains the last finalized state for recovery. A new validator replays the retained updates and checks the resulting state root.

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator certified commitment is 101 bytes. Admission also supplies the three roots and two outflow totals, another 112 bytes.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. A successful challenge blocks that close and its pending descendants.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. In $\Xi_0$ the operator countersigns exactly the acknowledgments represented by $\mathcal D_e$. In $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid acknowledgment $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

The close commits each active account's terminal position under $\mathsf{ChangeRoot}_e$. An opening supports receipt challenges and external-payout claims. A payer absent from this BMT has a public debit of zero for the epoch, so a BMT absence proof suffices to challenge an omitted payment. A holder can prove three kinds of contradiction:

1. **Debit mismatch.** For example, the close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Certification has already checked the accounting and signed terminal positions bound by the commitment. Any holder can therefore prove a contradiction with signatures and Merkle openings in one onchain call, without an interactive dispute game. Every receipt a user relies on needs an honest holder who retains the evidence, obtains the public openings, and gets a challenge included by $\Delta_e$. Validators retain the public corpus but cannot reconstruct a private receipt nobody saved.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain between epoch registrations, a path the settlement integration must keep live.

Once a withdrawal request is queued onchain or included in an admitted close, its carrying close must finalize before the signed deadline $T_w$ to avoid a hard fault. With challenge deadline $\Delta_e$,

$$
\boxed{\Delta_e<t_{\mathrm{finalize}}<T_w.}
$$

An exact withdrawal releases its amount if the epoch's final balance covers it. An account close sweeps that balance. Once the carrying close finalizes, the user claims the certified payout with an opening in that close's withdrawal-output BMT. Each output can be claimed only once.

Custody remains onchain throughout. Finalization reserves withdrawals and external payouts, and individual claims reduce the reserve and the chain's assets together. A challenged or invalidated close creates no payout reserve.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable and refund unadmitted deposits. Accounts recover their balances with QMDB proofs against the frozen root, and each account can claim only once. Payments in a never-admitted or invalidated close do not debit that state.

Recovery needs a correct, live settlement chain and available claim openings even when the operator disappears. The settlement integration must apply each claim atomically with its payout.

## Streamlined Epoch Transitions

A payment reaches finality through an admitted close, after the challenge deadline fixed at epoch registration. Shorter epochs can reduce that wait, but mean preparing and certifying closes more often.

Once epoch $e$'s close is admitted, the operator can register $e+1$ against its $\mathsf{StateRoot}$ and start payments before $e$ finalizes. Registration fixes deposits and signed withdrawal authorizations before the first payment is acknowledged.

For accounts without boundary operations, new payments can overlap credit imports. The preserved head $\widetilde B_a$ is the starting balance minus accepted predecessor debits plus credits already imported; $\rho_a$ is the predecessor credit still to come:

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
Figure 5: After predecessor admission and successor registration, the admitted epoch-$e$ balance is $80+\rho_a=85$, while the live epoch-$e+1$ head becomes $80-20+\rho_a-15=50$. Both rails account for the same predecessor credit, $\rho_a=5$. Importing that credit adds to the live head and preserves every successor debit.
:::

Accounts with boundary operations must resolve their full admitted outcome before spending in the successor epoch.

## The Close Follows Accounts and Edges

Each validator receives one complete update per close. It names each active account once, followed by signed endpoints and cumulative payment entries. The update never carries the payment history.

In the [measured workload](https://github.com/commonwarexyz/monorepo/pull/4747), every account sends one unit payment to one of 512 recipients. Each of 100 validators receives the same update.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Per close</th>
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
      <td style="text-align:right;">105 KB</td>
      <td style="text-align:right;">1.03 MB</td>
      <td style="text-align:right;">10.3 MB</td>
      <td style="text-align:right;">103 MB</td>
    </tr>
    <tr>
      <td>Total operator egress</td>
      <td style="text-align:right;">10.5 MB</td>
      <td style="text-align:right;">103 MB</td>
      <td style="text-align:right;">1.03 GB</td>
      <td style="text-align:right;">10.3 GB</td>
    </tr>
    <tr>
      <td>Commitment + certificate</td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Operator</th></tr>
    <tr>
      <td>Prepare and apply</td>
      <td style="text-align:right;">5.61 ms</td>
      <td style="text-align:right;">28.7 ms</td>
      <td style="text-align:right;">333 ms</td>
      <td style="text-align:right;">4.09 s</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Validator</th></tr>
    <tr>
      <td>Decode</td>
      <td style="text-align:right;">0.726 ms</td>
      <td style="text-align:right;">6.73 ms</td>
      <td style="text-align:right;">74.3 ms</td>
      <td style="text-align:right;">907 ms</td>
    </tr>
    <tr>
      <td>Verify and sign</td>
      <td style="text-align:right;">6.95 ms</td>
      <td style="text-align:right;">48.9 ms</td>
      <td style="text-align:right;">472 ms</td>
      <td style="text-align:right;">5.36 s</td>
    </tr>
    <tr>
      <td>Apply balances</td>
      <td style="text-align:right;">0.234 ms</td>
      <td style="text-align:right;">2.07 ms</td>
      <td style="text-align:right;">19.7 ms</td>
      <td style="text-align:right;">275 ms</td>
    </tr>
    <tr>
      <td><strong>Receive and apply</strong></td>
      <td style="text-align:right;"><strong>8.03 ms</strong></td>
      <td style="text-align:right;"><strong>57.7 ms</strong></td>
      <td style="text-align:right;"><strong>566 ms</strong></td>
      <td style="text-align:right;"><strong>6.54 s</strong></td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Retained between closes</th></tr>
    <tr>
      <td>Account records per validator</td>
      <td style="text-align:right;">41.0 KB</td>
      <td style="text-align:right;">400 KB</td>
      <td style="text-align:right;">4.00 MB</td>
      <td style="text-align:right;">40.0 MB</td>
    </tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 6: One signed payment per account, with no boundary flows. Times are medians of ten successive closes after one warmup on an AWS c8a.4xlarge with 16 workers and in-memory storage. Verification includes balance reads and construction of the new QMDB root; the total also includes decoding and application. Durable commit and networking are excluded. Egress assumes 100 direct copies. Account records count 32-byte keys and 8-byte balances, before QMDB indexes, history, and retained evidence.
:::

With a million live accounts but only 1,024 senders paying that same recipient pool, the dealing is still 105 KB and takes 8.69 ms to decode, verify, and apply.

On filesystem storage, the same close takes 20.5 ms from decoding through QMDB commit. This uses a 4 MiB page cache with uncontrolled OS caching and excludes the accepted-close journal and networking.

Repeated payments between the same pairs reuse these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots show modeled bytes per payment as one million to one billion unit payments pass between fixed pairs. The left shows one validator's keyed update for four account counts, including growing cumulative counters. The right shows the 101-byte commitment and certificate.">
```

::: {.image-caption}
Figure 7: More unit payments on the same pairs spread the update and certificate cost. Every account pays its next neighbor, and the model includes growing counter widths. Left: one validator's keyed update. Right: the 101-byte commitment and certificate for 100 validators.
:::

### Proof Sizes and Verification

Verifying the certified commitment takes 0.672 ms for a 100-validator committee. The tables below show encoded proof sizes, with verification times beneath them. Times are medians of ten samples on one CPU thread of the same host, starting from decoded proofs.

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
      <td style="text-align:right;"><strong>39 B</strong><br><small>0.314 µs</small></td>
      <td style="text-align:right;"><strong>359 B</strong><br><small>1.18 µs</small></td>
      <td style="text-align:right;"><strong>487 B</strong><br><small>1.52 µs</small></td>
      <td style="text-align:right;"><strong>583 B</strong><br><small>1.79 µs</small></td>
      <td style="text-align:right;"><strong>679 B</strong><br><small>2.05 µs</small></td>
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
Figure 10: Current Ordered proofs after the initial insertion batch, using a middle account and a missing key. SHA-256/MMB, 32-byte bitmap chunks, and 8-byte balances. Lookup rows omit the known account key; recovery includes it. All omit the trusted root and chain framing. Sizes vary with history and proof position.
:::

Adjust the workload and committee size below to estimate the operator's traffic. Every validator receives the same update; adding validators changes total egress.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive calculator for keyed validator dealings. Sliders set live accounts, average recipients per account, and validators. Results show one modeled update per validator, its composition, total operator egress, and a dotted reference for the encoded account records.">
  <noscript>Each validator retains the complete account state and receives one compact update per close. Total operator egress is the update size multiplied by the validator count. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 11: Modeled keyed update per validator, with total operator egress in parentheses. Dotted: all live account records (40 bytes each), before database overhead and retained evidence. Both axes are logarithmic; certificates, transport, and other messages are excluded.

Each sender signs one batch of unit payments. Recipients per account averages over all live accounts: below one, the first senders pay the last recipients in key order; otherwise, every account pays its next neighbors cyclically. All accounts stay live, with no deposits, withdrawals, or external payouts.
:::

## A Bajillion Payments, One Settlement

Repeated payments between the same pairs share settlement records. Each active account settles its net change across all counterparties.

The payer's receipt arrives in one round trip and gives its holder evidence to challenge a dishonest close. Validators keep the state available so users can recover their funds if the operator disappears.

The settlement chain only keeps the change.
