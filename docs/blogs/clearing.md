---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-08-20T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (more on this later).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity becomes a \~100-byte certified commitment that most chains can process. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

For a given set of accounts, one payment or a bajillion costs the same to settle.

## Payments as Fast as Browsing the Web

A Bajillion epoch starts from an authenticated account vector and an onchain anchor $\mathcal A_e$. Deposits and user-signed withdrawals are fixed before online payments begin. Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20.

$a$'s persistent state $X_a$ is a balance $B_a$, cumulative debit $D_a$, operator-promised credit $C_a$, a receipt count, and an activity flag. To send $x>0$ from $a$ to $b$, the payer signs the exact next debit, and the operator accepts by advancing the recipient's receive shard $\kappa$ from its current tip $(G,J)$ (which may or may not have been registered with the operator at the start of the epoch):

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;a\xrightarrow{\,x\,}b,\;D_a+x\bigr),
\qquad
R=\mathsf{Sign}_{\mathsf{op}}\bigl(\mathcal A_e,\;\kappa,\;x,\;\mathsf{TxId}(S),\;(G+x,\,J+1)\bigr).
$$

After authenticating $S$ and checking spendability, the operator atomically commits the debit, shard advance, close reservation, replay record, and receipt body. It then signs and returns $R$.

The matching pair $(S,R)$ is the accepted payment and the preconfirmation. The payer verifies and retains it, then forwards it to the recipient (if not forwarded by the operator already). A rejection before the commit changes nothing. If the response is lost, retrying the same request returns the same pair without a second debit.

Figure 1 begins with $a$ at 100, $b$ at 40, and the payment $a\xrightarrow{20}b$.

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
  </style>
</noscript>
<div id="clearing-fig-payment" class="clearing-loop" role="img" aria-label="Animated message-sequence timeline of one accepted payment, with rows for payer a, the operator, and recipient b, and time measured in message delays. Payer a signs request S paying b 20 and sends it to the operator. At one instant, with no network hop, the operator verifies S, commits atomically, moving a from 100 to 80 and receive shard kappa zero from (0,0) to (20,1), and then signs receipt R. The response returns to a, which retains the matching pair of S and R and forwards the same pair directly to recipient b with no operator hop. A dashed line shows the operator could instead relay the same pair to b directly, one hop sooner.">
  <noscript>Account a sends one request to one operator and receives one signed response. Verification, atomic storage, and receipt signing are local operator steps, and the payment is accepted at the operator's commit while the response is still in flight. Afterward, a gives the same matching pair directly to b without another operator hop, and the operator could equally deliver the pair to b one hop sooner.</noscript>
</div>
<script type="module" src="clearing.loops.js"></script>
```

::: {.image-caption}
Figure 1: The payer sends one request and receives one signed response. The operator verifies, commits, and signs locally, adding no network round trip. The commit moves $a$ from 100 to 80 and advances $b$'s receive shard $\kappa_0$ from $(0,0)$ to $(20,1)$ before $R$ exists. Once $R$ returns, $a$ sends the same matching $(S,R)$ directly to $b$ as transferable evidence, and the operator, holding the same pair, could deliver it to $b$ one hop sooner.
:::

## Optimizing for Hot Accounts

A single incoming counter would serialize every payment to a popular recipient. Instead, the operator shards each recipient's incoming payments across a configurable number of receive shards, identified by $(\mathcal A_e,b,\kappa)$. A payment of $x$ assigned to shard $\kappa$ advances only that shard's running credit and receipt count:

$$
(G_\kappa,J_\kappa)\longrightarrow(G_\kappa+x,J_\kappa+1),
\qquad
(G_{\kappa'},J_{\kappa'})\text{ unchanged for every }\kappa'\ne\kappa.
$$

Payments assigned to different shards never contend on recipient state, so a hot account's incoming path scales approximately linearly across parallel workers. When the epoch ends, one terminal signed pair represents each shard, no matter how many payments advanced it (and the sum of all shards is the recipient's credit).

Consider accounts $(a,b,c,d)$ that open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

Suppose the operator assigns each of $b$'s three incoming payments to its own shard. Their tips end at $(20,1)$, $(4,1)$, and $(6,1)$.

A hot recipient can end an epoch with many shards, but proving one tip does not require shipping the rest. Sort the terminal records by shard identifier and commit them as a Merkle tree under $\mathsf{CreditRoot}_e(b)$. The root binds the exact shard count, ordered records, total credit, and total receipt count: here $(h_b,G_b,J_b)=(3,30,3)$.

## One Row per Changed Account

Netting each account's debits and credits gives exact closing balances $(85,58,26,31)$, and gross payment debit equals gross payment credit at 54 (i.e. the changes net to zero). That is all settlement has to publish: not the six payments, but the four accounts they changed, one row each.

Write the opening and closing states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Each row binds both account states, the terminal outgoing pair $\mathsf{Out}_a$ when the account sent, its $\mathsf{CreditRoot}$, and a running total $\mathsf{prefix}_a$ over the sorted rows so far, where $\chi$ flags a withdrawal record and $h$ counts shard heads:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;h_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;\mathsf{CreditRoot}_e(a),\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

Each prefix must extend the preceding prefix exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

$$
\mathbf A_e=(\mathsf{Row}_a,\;\mathsf{Row}_b,\;\mathsf{Row}_c,\;\mathsf{Row}_d),
\qquad a<b<c<d.
$$

## Proving Exact Change

Commit $\mathbf A_e$ under $\mathsf{ChangeRoot}_e$, a Merkle root that binds the exact row count and every row in order:

$$
\mathbf A_e
\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{ChangeRoot}_e.
$$

A $\mathsf{StateRoot}$ commits every field in the complete account-state vector $X$. Suppose the registry holds eight accounts, our four changed ones scattered among four untouched:

$$
X^0=\bigl(X_a^0,\;X_b^0,\;\cdot,\;X_c^0,\;\cdot,\;\cdot,\;X_d^0,\;\cdot\bigr)
\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{StateRoot}_e.
$$

Recomputing that root from scratch would touch all eight accounts, and a real registry holds a million. The paired sparse witness instead collapses each untouched subtree into one digest $\Phi_i$, its Merkle root, no matter how many accounts it covers. The witness then reconstructs both roots in one pass: every changed account supplies its opening and closing leaf while the shared frontier $\Phi_e=(\Phi_1,\Phi_2,\Phi_3)$ fills everything else:

$$
\begin{aligned}
\mathsf{StateRoot}_e&\xleftarrow{\ \mathsf{Merkle}\ }\bigl(X_a^0,\;X_b^0,\;\Phi_1,\;X_c^0,\;\Phi_2,\;X_d^0,\;\Phi_3\bigr),\\[0.3em]
\mathsf{StateRoot}_{e+1}&\xleftarrow{\ \mathsf{Merkle}\ }\bigl(X_a^1,\;X_b^1,\;\Phi_1,\;X_c^1,\;\Phi_2,\;X_d^1,\;\Phi_3\bigr).
\end{aligned}
$$

::: {.image-caption}
Figure 2: One witness recomputes both roots from the same material. Each changed account supplies its paired leaves, $X^0$ on the opening side and $X^1$ on the closing side, while each untouched subtree contributes one shared digest ($\Phi_2$ covers two accounts at once). Identical frontiers on both sides prove every omitted account unchanged.
:::

Successful verification proves every omitted position unchanged and every row position changed to exactly its committed close. An account changes if and only if it has a row. The settlement chain retains only a hash composed of its three ordered roots:

$$
\mathsf{Commitment}_e
=H\!\left(
\mathsf{StateRoot}_e
\parallel \mathsf{ChangeRoot}_e
\parallel \mathsf{StateRoot}_{e+1}
\right).
$$

The totals are the terminal row's prefix: gross debit $D_e$, credit $C_e$, deposits $F_e$, and withdrawals $W_e$, with the row, record, and shard counts alongside. The three roots, shard vectors, changed rows, and paired witness stay offchain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Validate Everything Up Front

Before the chain queues a close for finalization, someone must check all of it. A validator committee verifies the complete public close, every row, every prefix, and the exact state transition, and signs the commitment only when all of it holds. Exhaustive validation keeps malformed or inexact closes out of the finalization queue and reduces any remaining private-receipt dispute to one tagged, non-interactive submission.

Prefix continuity ties the epoch totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the chain-sealed boundary, each withdrawal must cover at least its sealed record, and the totals must respect the close caps and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

The public corpus is partitioned into deterministic, exhaustive account intervals. Every certificate signer signs the same commitment. Each evidence piece is assigned to a quorum of validators who check and retain it. Quorum intersection guarantees that an honest signer checked and retains each piece, though that signer may differ by piece. With $n$ validators, $f$ tolerated faults, and quorum $q$, every piece $j$'s holders share more than $f$ validators with the certificate's signers:

$$
\begin{aligned}
n&=100,\qquad f=33,\qquad q=2f+1=67,\\[0.3em]
|\mathsf{signers}\;\cap\;\mathsf{holders}_j|&\;\ge\;2q-n=34>f.
\end{aligned}
$$

## The Unavoidable Challenge

Validation establishes that the bound corpus satisfies the public relation. However, it cannot establish that the corpus contains every receipt the operator signed and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator signs exactly the receipts represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid receipt $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature. Through the inclusive deadline $t\le\Delta_e$, any holder or watchtower may submit one of four bounded contradictions:

1. **Payer debit contradiction.** A matching acknowledged pair carries a debit above the public debit marker, or the same debit with a different send or receipt body. A bare payer request is insufficient. The receipt proves operator acknowledgement.

2. **Higher receive-shard tip.** Authenticate the public tip $(G^\star,J^\star)$ for one shard, using $(0,0)$ for authenticated absence, and present a matching retained receipt at $(G^+,J^+)$. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Inconsistent receipt range.** For lower and upper pairs in one anchor, recipient, and shard, where each receipt is linked to its own valid send, adjacent receipts must increase credit by exactly the upper payment, and an index gap must leave at least one base unit for each omitted positive payment. A violation is a contradiction.

4. **Receipt fork.** Two distinct linked receipt bodies either reuse one receipt index within a shard or acknowledge the same payer transaction differently. Different signature bytes over one identical receipt body are not a fork.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call.

A successful receipt challenge blocks the challenged slot and every pending descendant from finalizing. Earlier pending slots keep their ordinary challenge windows and may still finalize in order.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but stopping it is not enough: users must still be able to get their funds out. So every account holds a unilateral exit, a signed withdrawal queued directly onchain.

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;x,\;\gamma,\;\tau\bigr).
$$

$Q$ names the finalized root $\mathsf{rt}_z$ it was signed against, a destination $v$, an amount $x$, a full-close flag $\gamma$, and an absolute deadline $\tau$. The operator neither submits nor approves it, and its cooperation decides only whether the withdrawal settles through a clean close or through terminal unwind. Since $v$ may be any destination the asset adapter accepts, paying an unregistered recipient is just a withdrawal to its address.

Queueing proves the withdrawal affordable at every pending root, and each later queued close re-proves it, so whichever root survives can pay it. Deposits need no deadline at all: an unconsumed deposit simply returns in the terminal payout.

What makes the exit credible is that custody never leaves the chain. With finalized liability $L_z$, pending slots $z+1,\ldots,\ell$ carrying boundary flows $(F_i,W_i)$, and deposits not yet included in a pending close $F_\star$:

$$
\boxed{
E=L_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+\sum_{i=z+1}^{\ell}W_i+F_\star.
}
$$

Withdrawals stay inside custody until their own slot finalizes at the queue front, so a speculative descendant can never spend assets out from under an ancestor. The operator can stop serving payments, but it cannot take funds or send them without authorization.

If $Q$ is still unreleased at $t\ge\tau$, the first time-aware onchain call to observe the deadline permanently freezes new work. The pending slots then resolve from the front, each finalizing once its challenge window closes or falling to a challenge, and terminal unwind opens against the last root standing. Queued withdrawals pay to their signed destinations, and every account uses one Merkle proof against that root to claim its remaining balance and any unconsumed deposit.

## Streamlined Epoch Transitions

Closing an epoch is asynchronous: spending continues in epoch $e+1$ while epoch $e$'s close is still being built, certified, and queued onchain. Otherwise every epoch boundary would be a throughput cliff.

What makes this safe is an asymmetry. When an account rolls over, the operator carries forward its preserved head: everything it started with, minus every accepted debit, plus every credit already imported. Debits ended at the rollover, so the predecessor credit still in flight can only add to that head later, never subtract. Writing $\widetilde B_a$ for the preserved head and $\rho_a$ for the credit in flight, the exact predecessor close is

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad \rho_a\ge0.}
$$

The preserved head is a floor, and a floor is safe to spend against: the operator pre-authorizes successor payments on $\widetilde B_a$ before $B_a^1$ is even computed. Reconciliation later adds $\rho_a$ to the live value. It never assigns $B_a^1$ over it, which would erase successor debits already accepted.

In the running example, $a\xrightarrow{20}b$ leaves the preserved head at 80 while the not-yet-imported $d\xrightarrow{5}a$ credit makes the exact close 85. If $a$ spends 20 and then 15 in the successor while the missing credit arrives between them,

$$
80-20+5-15=50=(85)-20-15.
$$

```{=html}
<div id="clearing-fig-rollover" class="clearing-loop" role="img" aria-label="Animated owner-preserved rollover for account a. An accepted epoch-e pair leaves one preserved head of 80 and rotates that head into epoch e plus 1. Two connected rails branch from the same 80. The exact predecessor close reaches 85. The live successor rail spends 20 to reach 60, reconciles to 65, and spends 15 to reach 50. One vertical marker identifies the same missing predecessor credit of 5 in both calculations. The 85 close terminates on its own rail and never overwrites the live head.">
  <noscript>An accepted epoch-e pair leaves one preserved head of 80. The exact-close rail computes 80 plus 5 as 85. The live rail computes 80 minus 20 plus the same 5 minus 15 as 50. Reconciliation adds the shared missing credit without installing 85 over the live head.</noscript>
</div>
```

::: {.image-caption}
Figure 3: Both rails branch from the same preserved 80. The upper rail computes the exact epoch-$e$ close, $80+\rho_a=85$. The lower rail keeps the epoch-$e+1$ head live, $80-20+\rho_a-15=50$. The single vertical $\rho_a=5$ marker is the same predecessor credit in both calculations. The two values serve different roles: 85 is the canonical predecessor close, while 50 is the current live head. Reconciliation adds $\rho_a$ to the live value and preserves every successor debit.
:::

The live balance is not monotone, since successor payments spend it down. The one-sidedness is all on the predecessor's side: completion can add missing credit but can never discover another accepted debit. Boundary operations and shard moves obey the same rule: the live head is only ever adjusted, never overwritten.

Rollover changes only live serving state, without changing the evidence required for finalization. The close still produces the canonical rows, state root, and public corpus, and a challenge against the predecessor invalidates its pending descendants.

## The Close Never Grows (with Payments)

Every profile below runs one fixture: a registry of $N=1{,}000{,}000$ accounts, a 100-validator committee, the evidence divided into 256 slices and dealt among validators, and an eight-thread worker pool (M5 Pro). Every changed account sends, and the same 512 credited accounts receive, spaced evenly among the senders.

The matrix independently varies $A$, the number of changed accounts, and $h$, the number of receive shards on each credited account. No payment count appears because none is needed: rows and shard tips carry fixed-width cumulative totals, so every size in the table is the same for any $T$.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
      <th colspan="2" style="text-align:center;"><em>A</em> = 1,024</th>
      <th colspan="2" style="text-align:center;"><em>A</em> = 1,000,000</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>h</em> = 1</th>
      <th style="text-align:right;"><em>h</em> = 512</th>
      <th style="text-align:right;"><em>h</em> = 1</th>
      <th style="text-align:right;"><em>h</em> = 512</th>
    </tr>
  </thead>
  <tbody>
    <tr><th colspan="5" style="text-align:left;">Construction</th></tr>
    <tr>
      <td style="padding-left:20px;">evidence</td>
      <td style="text-align:right;">2.27 MB</td>
      <td style="text-align:right;">105 MB</td>
      <td style="text-align:right;">629 MB</td>
      <td style="text-align:right;">732 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">0.783 ms</td>
      <td style="text-align:right;">1.08 ms</td>
      <td style="text-align:right;">244 ms</td>
      <td style="text-align:right;">250 ms</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">deal</td>
      <td style="text-align:right;">0.373 ms</td>
      <td style="text-align:right;">3.37 ms</td>
      <td style="text-align:right;">49.6 ms</td>
      <td style="text-align:right;">58.7 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Certification</th></tr>
    <tr>
      <td style="padding-left:20px;">dealing</td>
      <td style="text-align:right;">1.53 MB <span style="color:#666;">(-33%)</span></td>
      <td style="text-align:right;">71.0 MB <span style="color:#666;">(-32%)</span></td>
      <td style="text-align:right;">423 MB <span style="color:#666;">(-33%)</span></td>
      <td style="text-align:right;">492 MB <span style="color:#666;">(-33%)</span></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">2.78 ms</td>
      <td style="text-align:right;">246 ms</td>
      <td style="text-align:right;">1.33 s</td>
      <td style="text-align:right;">1.51 s</td>
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
      <td style="padding-left:20px;">certified commitment</td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
      <td style="text-align:right;"><strong>101 B</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check certified commitment</td>
      <td style="text-align:right;"><strong>0.481 ms</strong></td>
      <td style="text-align:right;"><strong>0.483 ms</strong></td>
      <td style="text-align:right;"><strong>0.487 ms</strong></td>
      <td style="text-align:right;"><strong>0.487 ms</strong></td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Dispute</th></tr>
    <tr>
      <td style="padding-left:20px;">challenge</td>
      <td style="text-align:right;"><strong>1.73 KB</strong></td>
      <td style="text-align:right;"><strong>2.02 KB</strong></td>
      <td style="text-align:right;"><strong>2.05 KB</strong></td>
      <td style="text-align:right;"><strong>2.34 KB</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check challenge</td>
      <td style="text-align:right;"><strong>0.454 ms</strong></td>
      <td style="text-align:right;"><strong>0.447 ms</strong></td>
      <td style="text-align:right;"><strong>0.481 ms</strong></td>
      <td style="text-align:right;"><strong>0.471 ms</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 4: The operator prepares the roots, then deals the evidence into validator-specific pieces. Each validator seals its dealing by checking and retaining those pieces before signing the commitment. A receipt holder with evidence of fraud can dispute the certified commitment with a challenge that the chain checks.
:::

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three interaction plots show benchmark latency for preparing the roots, dealing the evidence into pieces, and sealing the largest of the 100 validator dealings. Blue is 1,024 changed accounts and green is one million. Each series has measured points at one and 512 receive shards per credited account. Connecting lines are visual guides, not interpolated measurements. Each panel uses its own millisecond scale.">
```

::: {.image-caption}
Figure 5: These are four measured profiles, not an interpolation. Each panel has its own millisecond scale. Blue holds $A=1{,}024$ and green holds $A=1{,}000{,}000$ while the horizontal axis changes the receive shards on each credited account from $h=1$ to $h=512$.
:::

Increasing $A$ makes the state transition dense. Increasing $h$ concentrates more authenticated shard leaves and signatures behind each credited row.

Even the largest validator dealing is 32–33% smaller than the full evidence because it contains only that validator's pieces. At $A=1{,}024$ and $h=1$, it is 1.53 MB despite a registry of one million accounts. Distribution follows the changed rows and the shared frontier, not the registry, so it is sublinear in registered accounts as well as in payments.

The offchain evidence is constant for a profile, so accepted payments only divide it. Ten million payments spread the sparse profile's 2.27 MB to about 0.23 offchain bytes per payment; a billion spread it to 0.0023 offchain bytes per payment. The certified commitment includes the 32-byte commitment, signer bitmap, and aggregate signature, for 101 bytes total; it likewise shrinks as $1/T$.

This fixture queues no withdrawals and no full closes, whose re-check and row openings would otherwise add to it. The challenge measurements use one proven higher-tip challenge: its payload grows only with the two lookup depths, and its check verifies two signatures and two openings.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows offchain evidence bytes per payment for the four A-by-h profiles; the right shows the 101-byte certified commitment. Every line falls as 1/T.">
```

::: {.image-caption}
Figure 6: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The offchain evidence (left) depends on $A$ and $h$: shards move the million-account evidence by only $1.2\times$ but the sparse evidence by $46\times$. The certified commitment (right) stays 101 bytes across profiles.
:::

## A Bajillion Payments, One Settlement

The operator's work scales with payments: it verifies, durably commits, and signs every one of the $T$ payments it accepts. The public close has no per-payment term. It carries one row per changed account ($A$), one terminal pair per receive shard ($H$), and one frontier digest per untouched subtree ($|\Phi_e|$):

$$
\text{payments }T
\quad\longrightarrow\quad
\text{rows }A+\text{shards }H+\text{frontier digests }|\Phi_e|.
$$

For repeated activity over a fixed set of accounts and shards, $(A+H+|\Phi_e|)/T\to 0$. Account-level clearing compresses repetition, not change: every changed account still pays for its row and every shard for its terminal pair, but additional payments between them add nothing. No traffic pattern adds a per-payment term to the close either, because acceptance reserves room per account and per shard, never per payment.

And this is as good as the trust model allows. A preconfirmation cannot arrive in less than one round trip to the operator that serializes spending. A close cannot quietly drop a payment: it must agree with every receipt a holder retains, or a single retained pair proves the fault. Settlement cannot make less than the changed state available to users who recover from public data alone, and this close adds only the terminal pairs and the frontier needed to reconstruct the registry around those changes.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
