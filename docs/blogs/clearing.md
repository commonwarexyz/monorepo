---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-10T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/10/26): Operators can now process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain state between closes and receive only account changes, cumulative payment entries, and proofs.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by one 32-byte commitment, 101 bytes with the certificate for a committee of 100 validators. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

Settlement records grow with active accounts and payment pairs, however many payments pass between them.

## Payments as Fast as Browsing the Web

An agent buying an API response should be able to pay and get on with the next request. Bajillion gives the payer an acknowledgment in one round trip to its chosen operator, with a receipt the recipient can verify locally and retain as evidence. Settlement comes later, netting payments across all accounts using that operator, without separate channels or funded routes between counterparties.

Suppose a payer, $a$, has 100 and wants to pay 20 to a recipient, $b$, with 40. The payer signs a request $S$ advancing its running total for that recipient. The operator verifies the signature and available funds, records acceptance, and returns its signed acknowledgment $R$ with a proof of the recipient's entry. The payer verifies and durably saves both, then forwards the resulting receipt to the recipient.

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

An epoch groups accepted payments into a close, the settlement package the operator builds when that epoch ends. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

The payer tracks a balance $B_a$ and a cumulative debit $D_a$. Its activity within an epoch is one strictly recipient-sorted vector $V_a$ with one cumulative entry per recipient it paid. The entry $(G,J)$ for $b$ is $a$'s cumulative credit to $b$ this epoch and the number of payments behind it. Before the example payment, $a$ holds $B_a=100$ and $D_a=0$, and $V_a$ is empty.

To send $x>0$ from $a$ to $b$, the payer advances $b$'s entry in its own vector and signs the resulting endpoint, its cumulative position after this send: an epoch-local sequence number $n_a$, the cumulative debit, and the vector's Merkle root. The operator's acknowledgment countersigns the same body:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

Here the endpoint is $n_a=1$, $D_a=20$, and the root of $V_a=\{b:(20,1)\}$. The operator checks $S$ and available funds, durably records acceptance, then returns $R$ with an opening of $b$'s entry.

This entry receipt proves the operator accepted the payment. The recipient obtains it before relying on the payment and can verify it locally.

The wallet keeps one unacknowledged request in flight and durably saves the verified acknowledgment and openings before signing the next endpoint. It retries that exact request after response loss.

One signature can also advance several recipients in a batch. The operator accepts or rejects the whole batch and returns one acknowledgment with an opening for each advanced entry.

## Optimizing for Hot Accounts

A single incoming counter would serialize every payment to a popular recipient. Bajillion has none: acceptance touches only the payer's side, so recipients have no state to serialize. Incoming credit stays a promise until the epoch ends, when the operator collates it. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry in $a$'s vector:

$$
(G_{ab},J_{ab})\longrightarrow(G_{ab}+x,J_{ab}+1),
\qquad
\text{every other entry of every other vector unchanged.}
$$

Payments to one hot account from different payers live in disjoint vectors and never contend, so the incoming path scales with the payers, not the recipient. However many payments an edge carries, the epoch ends with one cumulative entry for it.

Consider accounts $(a,b,c,d)$ that open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

$b$'s three incoming payments end as the entries $(20,1)$ in $a$'s vector, $(4,1)$ in $c$'s, and $(6,1)$ in $d$'s.

Each payer's last vector of the epoch is its terminal vector. When the epoch ends, the operator sorts the union of terminal entries by recipient, then payer, into the transpose. These are the same entries viewed from the receiving side and committed under $\mathsf{TransposeRoot}_e$. $b$'s three entries sum to $20+4+6=30$. Each entry can be opened separately under its payer's signed vector root and the transpose root.

## One Row per Changed Account

Netting each of the four accounts' debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross debit equals gross credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. The six payments change four account rows, one per account.

For each account, the opening and closing balances are $B_a^0$ and $B_a^1$, with debit and credit deltas $d_a$ and $c_a$. Deposits $f_a$, withdrawals $w_a$, and external payouts $p_a$ complete the balance equation:

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

A recipient without a live account can receive a net external payout onchain after finalization. The row validator derives each settlement output from the same balance equation and signed authorizations.

Each row binds the account's old and new state and, when it sent, its terminal signed endpoint. The rows are sorted by account and carry running totals, so a validator can check that its portion begins where the preceding portion ended. The final row carries the epoch's totals, including gross debit $D_e$ and credit $C_e$:

$$
\boxed{D_e=C_e.}
$$

Here $D_e=C_e=54$. Summing account balances into $L_e$ and $L_{e+1}$ cancels payments, leaving only deposits $F_e$, withdrawals $W_e$, and external payouts $P_e$:

$$
\boxed{L_{e+1}=L_e+F_e-W_e-P_e.}
$$

With no boundary flows, $L_{e+1}=L_e=200$.

These rows update the live account state, a sorted vector of accounts with positive balances committed under $\mathsf{StateRoot}$ in a binary Merkle tree (BMT). Deposits can add accounts, while withdrawals and payments can remove them when their balance reaches zero.

Changed rows and unchanged accounts together determine the next state. The operator rebuilds the full successor tree at each close. Validators retain their assigned state between closes and reconstruct their portions from the changes they receive.

## Slice the Evidence

The evidence is divided into $S$ deterministic account-key slices (256 in the benchmarks). A validator receives at most two contiguous spans of slices, each with its own range proof.

Shared boundaries make these local checks compose. The coverage commitment binds each boundary's position in the old state, new state, changed rows, and payment entries, together with running totals and two accumulator checksums. Each slice must begin where its predecessor ended.

Take $S=2$ with slice 1 holding $\{a,b\}$ and slice 2 holding $\{c,d\}$. The boundary after $b$ carries debit $20+12=32$ and credit $5+30=35$, which need not balance. Slice 2 resumes from those totals and must finish at $54=54$. Each slice checks its own rows against the boundaries on either side.

The checksums verify the transpose piecewise. An order-independent lattice hash accumulates each entry's payer, recipient, cumulative amount, and count, once from the payer vectors and once from the transpose. Each slice resumes both accumulators, $u$ and $v$, from its opening boundary and must reach the values at its closing boundary. At the end,

$$
\boxed{u_S=v_S.}
$$

This equality proves that the two orderings contain the same multiset of directed entries. Every recipient credit is backed by a payer-signed entry, even though one validator need not see both sides of an edge.

The commitment format binds the roots and epoch context in a 32-byte header. Admission also requires a 164-byte root bundle and a terminal coverage proof. The full evidence remains offchain as an authenticated corpus $\mathcal D_e$, retrievable through the challenge deadline $\Delta_e$.

## Seal Every Dealing Up Front

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Each slice is assigned to $q=2f+1$ consecutive validators around a ring, starting at $\lfloor ns/S\rfloor$ for slice $s$. This sliding window gives each validator at most two contiguous spans, so range proofs and accumulator start states travel once per span.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-ring-assignment.svg" alt="Sixteen validators on a ring with eleven-holder windows for slices 0, 5, and 10. Beside the ring, sixteen rows show each validator's assigned slices as one span, or two at the wrap.">
```

::: {.image-caption}
Figure 2: With sixteen validators and sixteen slices, each slice has eleven holders. The holder window slides around the ring (left); each validator's assigned slices form one span, or two at the wrap (right).
:::

A validator authenticates every row, signature, state transition, and boundary check in its assigned spans. It retains the evidence through the challenge deadline before signing the commitment.

The certificate needs $q$ signers, all signing the same commitment. Quorum intersection guarantees that an honest signer authenticated and retains each slice, though that signer may differ by slice. Every slice $j$'s holders share more than $f$ validators with the certificate's signers:

$$
\begin{aligned}
n&=100,\qquad f=33,\qquad q=2f+1=67,\\[0.3em]
|\mathsf{signers}\;\cap\;\mathsf{holders}_j|&\;\ge\;2q-n=34>f.
\end{aligned}
$$

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator certified package is 101 bytes.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. A successful challenge blocks that close and its pending descendants.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. In $\Xi_0$ the operator countersigns exactly the acknowledgments represented by $\mathcal D_e$. In $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid acknowledgment $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

The close commits each changed account's terminal position under $\mathsf{ChangeRoot}_e$. An opening of that position supports receipt challenges and external-payout claims. A holder can prove three kinds of contradiction:

1. **Debit mismatch.** For example, the close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Each challenge is checked in one onchain call using signatures, arithmetic, and Merkle openings. Any holder can submit it. Every receipt a user relies on needs an honest holder who retains the evidence, obtains the public openings, and gets a challenge included by $\Delta_e$. Validators retain the public corpus but cannot reconstruct a private receipt nobody saved.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain between epoch registrations, a path the settlement integration must keep live.

An exact withdrawal releases its amount if enough funds remain at the epoch boundary. An account close sweeps that epoch's final balance. Once the carrying close finalizes, the user claims the certified payout with a Merkle opening. Each output can be claimed only once.

Custody remains onchain throughout. Finalization reserves withdrawals and external payouts, and individual claims reduce the reserve and the chain's assets together. A challenged or invalidated close creates no payout reserve.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable and refund unadmitted deposits. Accounts recover from the frozen state using Merkle openings. Payments in a never-admitted or invalidated close do not debit that state.

Recovery needs a correct, live settlement chain and available claim openings even when the operator disappears. The settlement integration must apply each claim atomically with its payout.

## Streamlined Epoch Transitions

A payment reaches finality through an admitted close, after the challenge deadline fixed at epoch registration. Shorter epochs can reduce that wait, but mean preparing and certifying closes more often.

Payments need not wait for earlier closes to finalize. Once epoch $e$'s close is admitted, the operator can register epoch $e+1$ onchain against the resulting $\mathsf{StateRoot}$. Registration fixes deposits and signed withdrawal authorizations before the new epoch's first payment is acknowledged.

Importing predecessor credits into each account's live balance can also overlap new payments.

For an account with no boundary operations, the operator carries forward its preserved head: everything it started with, minus every accepted debit, plus every credit already imported. With predecessor debits fixed, the remaining credit can only add to that head. Writing $\widetilde B_a$ for the preserved head and $\rho_a$ for the credit in flight,

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
Figure 3: After predecessor admission and successor registration, the admitted epoch-$e$ balance is $80+\rho_a=85$, while the live epoch-$e+1$ head becomes $80-20+\rho_a-15=50$. Both rails account for the same predecessor credit, $\rho_a=5$. Importing that credit adds to the live head and preserves every successor debit.
:::

Accounts affected by deposits or withdrawal authorizations must resolve their full admitted outcome before spending in the successor epoch.

## The Close Follows Accounts and Edges

The [protocol primitives and benchmarks are in #4664](https://github.com/commonwarexyz/monorepo/pull/4664). Applications supply the operator and wallet services, including durable storage, retries, and live credit reconciliation.

Every profile uses 100 validators and 256 slices on an AWS c8a.4xlarge. Prepare, deal, and seal share an adaptive 16-worker pool. Certificate, challenge, and withdrawal-claim checks run on the calling thread.

The first matrix varies the number of live accounts, $N$, from 1,024 to one million. Every account sends one entry, and the same 512 accounts receive. The active sweep holds $N$ at one million and varies how many accounts send, taking senders in key order.

The full proof-slice corpus contains all 256 slices, each with its own proofs. The posted close is a compact update for a reader holding the previous certified state. Each validator uses its retained state to reconstruct its assigned slices from a compact dealing; the table reports the largest such download. The external certified package is the commitment and certificate.

Stages are measured independently, with one entry per batch. Prepare constructs the new roots using a prebuilt predecessor-state proof cache. Deal constructs dealings for the whole committee. Seal verifies and retains the busiest validator's dealing and signs the commitment.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
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
    <tr><th colspan="5" style="text-align:left;">Construction</th></tr>
    <tr>
      <td style="padding-left:20px;">posted close</td>
      <td style="text-align:right;">85.8 KB</td>
      <td style="text-align:right;">730 KB</td>
      <td style="text-align:right;">7.19 MB</td>
      <td style="text-align:right;">71.8 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">full proof-slice corpus</td>
      <td style="text-align:right;">2.07 MB</td>
      <td style="text-align:right;">6.35 MB</td>
      <td style="text-align:right;">48.8 MB</td>
      <td style="text-align:right;">473 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">2.50 ms</td>
      <td style="text-align:right;">17.0 ms</td>
      <td style="text-align:right;">178 ms</td>
      <td style="text-align:right;">1.78 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">deal</td>
      <td style="text-align:right;">2.70 ms</td>
      <td style="text-align:right;">2.89 ms</td>
      <td style="text-align:right;">6.75 ms</td>
      <td style="text-align:right;">42.9 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Certification</th></tr>
    <tr>
      <td style="padding-left:20px;">largest validator dealing</td>
      <td style="text-align:right;">155 KB</td>
      <td style="text-align:right;">1.08 MB</td>
      <td style="text-align:right;">10.3 MB</td>
      <td style="text-align:right;">103 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">10.1 ms</td>
      <td style="text-align:right;">33.2 ms</td>
      <td style="text-align:right;">227 ms</td>
      <td style="text-align:right;">2.21 s</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Settlement</th></tr>
    <tr>
      <td style="padding-left:20px;">commitment</td>
      <td style="text-align:right;"><strong>32 B</strong></td>
      <td style="text-align:right;"><strong>32 B</strong></td>
      <td style="text-align:right;"><strong>32 B</strong></td>
      <td style="text-align:right;"><strong>32 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">external certified package</td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check certified commitment</td>
      <td style="text-align:right;"><strong>0.668 ms</strong></td>
      <td style="text-align:right;"><strong>0.667 ms</strong></td>
      <td style="text-align:right;"><strong>0.668 ms</strong></td>
      <td style="text-align:right;"><strong>0.668 ms</strong></td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Dispute</th></tr>
    <tr>
      <td style="padding-left:20px;">HigherAckDebit challenge</td>
      <td style="text-align:right;"><strong>620 B</strong></td>
      <td style="text-align:right;"><strong>748 B</strong></td>
      <td style="text-align:right;"><strong>844 B</strong></td>
      <td style="text-align:right;"><strong>940 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">HigherAckEntry challenge</td>
      <td style="text-align:right;"><strong>671 B</strong></td>
      <td style="text-align:right;"><strong>799 B</strong></td>
      <td style="text-align:right;"><strong>895 B</strong></td>
      <td style="text-align:right;"><strong>991 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">AckFork challenge</td>
      <td style="text-align:right;"><strong>417 B</strong></td>
      <td style="text-align:right;"><strong>417 B</strong></td>
      <td style="text-align:right;"><strong>417 B</strong></td>
      <td style="text-align:right;"><strong>417 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check HigherAckDebit</td>
      <td style="text-align:right;"><strong>0.218 ms</strong></td>
      <td style="text-align:right;"><strong>0.218 ms</strong></td>
      <td style="text-align:right;"><strong>0.220 ms</strong></td>
      <td style="text-align:right;"><strong>0.217 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check HigherAckEntry</td>
      <td style="text-align:right;"><strong>0.219 ms</strong></td>
      <td style="text-align:right;"><strong>0.219 ms</strong></td>
      <td style="text-align:right;"><strong>0.221 ms</strong></td>
      <td style="text-align:right;"><strong>0.218 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check AckFork</td>
      <td style="text-align:right;"><strong>0.212 ms</strong></td>
      <td style="text-align:right;"><strong>0.215 ms</strong></td>
      <td style="text-align:right;"><strong>0.216 ms</strong></td>
      <td style="text-align:right;"><strong>0.212 ms</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three log-scale plots show measured latency for preparing roots, dealing all evidence slices, and sealing the busiest validator dealing as live accounts increase from 1,024 to one million.">
```

::: {.image-caption}
Figure 4: These are four measured profiles, not an interpolation. Both axes are logarithmic, and each point is labeled with its measured latency. Construction and sealing scale approximately linearly once the fixed costs are amortized.
:::

The next table fixes the live state at one million accounts and varies how many send; its rightmost column is the fully active case above.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
      <th colspan="4" style="text-align:center;">Sending accounts (<em>A</em>) out of 1,000,000 live</th>
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
      <td style="padding-left:20px;">posted close</td>
      <td style="text-align:right;"><strong>74.0 KB</strong></td>
      <td style="text-align:right;"><strong>718 KB</strong></td>
      <td style="text-align:right;"><strong>7.18 MB</strong></td>
      <td style="text-align:right;">71.8 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">largest validator dealing</td>
      <td style="text-align:right;"><strong>182 KB</strong></td>
      <td style="text-align:right;"><strong>1.40 MB</strong></td>
      <td style="text-align:right;"><strong>13.6 MB</strong></td>
      <td style="text-align:right;">103 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">151 ms</td>
      <td style="text-align:right;">166 ms</td>
      <td style="text-align:right;">315 ms</td>
      <td style="text-align:right;">1.78 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">26.1 ms</td>
      <td style="text-align:right;">62.6 ms</td>
      <td style="text-align:right;">360 ms</td>
      <td style="text-align:right;">2.21 s</td>
    </tr>
  </tbody>
</table>
</div>
```

Fewer senders reduce the posted close and the largest validator dealing. Preparation and sealing still process live state.

Additional payments over the same pairs share these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots amortize fixed byte budgets over one million to one billion accepted payments. The left uses the table's rounded proof-slice corpus sizes for four account counts; the right uses the 101-byte external certified package.">
```

::: {.image-caption}
Figure 5: Each line divides a fixed byte budget from the table by the payment count. The corpus curves use rounded table values and hold integer widths fixed. The external certified package stays 101 bytes across profiles.
:::

Challenge proofs grow with their Merkle lookup depths. Withdrawal claims grow with the number of withdrawal outputs $W$ in their close. The separate fixtures below use a 21-byte destination and range from one output to one million, with each claim opening just one leaf. The payment profiles above contain no withdrawals.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
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
      <td style="padding-left:20px;">claim proof</td>
      <td style="text-align:right;"><strong>39 B</strong></td>
      <td style="text-align:right;"><strong>359 B</strong></td>
      <td style="text-align:right;"><strong>487 B</strong></td>
      <td style="text-align:right;"><strong>583 B</strong></td>
      <td style="text-align:right;"><strong>679 B</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

Adjust the workload and committee size below to see how much data the operator sends to validators.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive operator-to-validator dealing calculator. Sliders set live accounts, average recipients per account, and validators. Results show the average dealing per validator with its composition, total operator egress per close, and a full-state size reference.">
  <noscript>At one million accounts each paying its next neighbor, the operator sends an average of 113 MB to each of 100 validators per close, totaling 11.3 GB. The full account state is 129 MB. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 6: Average dealing size per validator per close, with total operator egress in parentheses. The dotted line shows the full account state (leaves and Merkle tree levels) for comparison. Both axes use logarithmic scales.

Each sender signs one batch, and each sender-recipient pair carries one unit payment. All accounts remain live, with no deposits, withdrawals, or external payouts. This workload differs from the measured fixture above, which credits 512 recipients.

Recipients per account is an average over all $N$ live accounts, including those that send nothing. Accounts follow key order across evenly populated slices. Below an average of one, the first $E$ accounts each pay one of the last $E$, giving $E$ sender-recipient pairs and $\min(N,2E)$ accounts with activity. At integer average $k\ge1$, every account pays its next $k$ neighbors cyclically.

Accounts and pairs are limited to $2^{24}$; recipients per sender are capped at $\min(1024,N-1)$. Validator counts follow $n=3f+1$, with $S=\min(256,2^{\lceil\log_2 n\rceil})$ slices (128 for 100 validators). Each validator receives one or two spans, each with one proof. Dealing sizes count the actual spans assigned to each validator, including repeated delivery of slices shared by several validators. They exclude transport overhead and other protocol messages.
:::

## A Bajillion Payments, One Settlement

Payments across many counterparties settle into one net balance change per active account. The close retains the pair entries that let validators check every credit.

Repeated payments across the same network share those records. Their totals and counts may take more bytes as they grow, but the close never carries the payment history.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-netting.svg" alt="100 million payments across six directed pairs net into balance changes for four active accounts. Account a sends $30 and receives $10, moving from $100 to $80. Account b sends $25 and receives $55, moving from $40 to $70. Account c sends $20 and receives $25, moving from $25 to $30. Account d sends $25 and receives $10, moving from $35 to $20. The close retains six cumulative entries and four account rows with their proofs.">
```

::: {.image-caption}
Figure 7: The four-account network carrying 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

The payer gets a receipt in one round trip to the operator, and that same receipt lets its holder prove a fault if the close contradicts it. Keeping the state available for recovery lets users leave even if the operator disappears.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
