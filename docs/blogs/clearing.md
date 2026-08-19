---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 14th, 2026"
published-time: "2026-08-14T00:00:00Z"
modified-time: "2026-08-14T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new  recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). A rollup either proves each transaction or publishes every payment so anyone can challenge the state transition. Not to mention, sequencer preconfirmations still need a separate challenge to account for signed payments omitted from the batch (more on this later).

**Bajillion** is an optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity becomes a few-kilobyte commitment that most chains can process. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

Settlement cost depends on the accounts and receive components touched, not the number of payments between them. For a fixed set of both, make one payment or a bajillion: the close remains the same size, without replaying every payment or running an interactive dispute game.

## Payments as Fast as Browsing the Web

A Bajillion epoch starts from an authenticated account vector and an onchain anchor $\mathcal A_e$. Deposits and user-signed withdrawals are fixed before online payments begin. Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20.

$a$'s persistent state $X_a$ is a balance $B_a$, cumulative debit $D_a$, operator-promised credit $C_a$, a receipt count, and an activity flag. To send $x>0$ from $a$ to $b$, the payer signs the exact next debit, and the operator accepts by advancing the recipient's receive component $\kappa$ from its current tip $(G,J)$ (which may or may not have been registered with the operator at the start of the epoch):

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;a\xrightarrow{\,x\,}b,\;D_a+x\bigr),
\qquad
R=\mathsf{Sign}_{\mathsf{op}}\bigl(\mathcal A_e,\;\kappa,\;x,\;\mathsf{TxId}(S),\;(G+x,\,J+1)\bigr).
$$

After authenticating $S$ and checking spendability, the operator atomically commits the debit, component advance, close reservation, replay record, and receipt body. It then signs and returns $R$.

The matching pair $(S,R)$ is the accepted payment and the preconfirmation. The payer verifies and retains it, then forwards it to the recipient (if not forwarded by the operator already). A rejection before the commit changes nothing. If the response is lost, retrying the same request returns the same pair without a second debit, until the payer sends again.

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
<div id="clearing-fig-payment" class="clearing-loop" role="img" aria-label="Animated message-sequence timeline of one accepted payment, with rows for payer a, the operator, and recipient b, and time measured in message delays. Payer a signs request S paying b 20 and sends it to the operator. At one instant, with no network hop, the operator verifies S, commits atomically, moving a from 100 to 80 and component kappa zero from (0,0) to (20,1), and then signs receipt R. The response returns to a, which retains the matching pair of S and R and forwards the same pair directly to recipient b with no operator hop. A dashed line shows the operator could instead relay the same pair to b directly, one hop sooner.">
  <noscript>Account a sends one request to one operator and receives one signed response. Verification, atomic storage, and receipt signing are local operator steps, and the payment is accepted at the operator's commit while the response is still in flight. Afterward, a gives the same matching pair directly to b without another operator hop, and the operator could equally deliver the pair to b one hop sooner.</noscript>
</div>
<script type="module" src="clearing.loops.js"></script>
```

::: {.image-caption}
Figure 1: The payer sends one request and receives one signed response. The operator verifies, commits, and signs locally, adding no network round trip. The commit moves $a$ from 100 to 80 and advances $b$'s component $\kappa_0$ from $(0,0)$ to $(20,1)$ before $R$ exists. Once $R$ returns, $a$ sends the same matching $(S,R)$ directly to $b$ as transferable evidence, and the operator, holding the same pair, could deliver it to $b$ one hop sooner.
:::

## Optimizing for Hot Accounts

A single incoming counter would serialize every payment to a popular recipient. Instead, the operator shards each recipient's incoming payments across a configurable number of receive components, identified by $(\mathcal A_e,b,\kappa)$. A payment of $x$ assigned to component $\kappa$ advances only that component's running credit and receipt count:

$$
(G_\kappa,J_\kappa)\longrightarrow(G_\kappa+x,J_\kappa+1),
\qquad
(G_{\kappa'},J_{\kappa'})\text{ unchanged for every }\kappa'\ne\kappa.
$$

Payments assigned to different components never contend, so a hot account scales approximately linearly across parallel workers. When the epoch ends, one terminal signed pair represents each component, no matter how many payments advanced it (and the sum of all components is the recipient's credit).

Consider accounts $(a,b,c,d)$ that open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

Suppose the operator assigns each of $b$'s three incoming payments to its own component. Their tips end at $(20,1)$, $(4,1)$, and $(6,1)$.

A hot recipient can end an epoch with many components, but proving one tip does not require shipping the rest. Sort the terminal records by component identifier and commit them as a Merkle tree under $\mathsf{CreditRoot}_e(b)$. The root binds the exact component count, ordered records, total credit, and total receipt count: here $(h_b,G_b,J_b)=(3,30,3)$.

## One Row per Changed Account

Netting each account's debits and credits gives exact closing balances $(85,58,26,31)$, and gross payment debit equals gross payment credit at 54 (i.e. the changes net to zero). That is all settlement has to publish: not the six payments, but the four accounts they changed, one row each.

Write the opening and closing states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Each row binds both account states, the terminal outgoing pair $\mathsf{Out}_a$ when the account sent, its $\mathsf{CreditRoot}$, and a running total $\mathsf{prefix}_a$ over the sorted rows so far, where $\chi$ flags a withdrawal record and $h$ counts component heads:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;h_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;\mathsf{CreditRoot}_e(a),\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

Each prefix must extend its predecessor's exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

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

Recomputing that root from scratch would touch all eight accounts, and a real registry holds a million. The paired sparse witness instead collapses each untouched subtree into one digest $\Phi_i$, its Merkle root, no matter how many accounts it covers. Both roots then reconstruct in one pass, every changed account supplying its opening and closing leaf while the shared frontier $\Phi_e=(\Phi_1,\Phi_2,\Phi_3)$ fills everything else:

$$
\begin{aligned}
\mathsf{StateRoot}_e&\xleftarrow{\ \mathsf{Merkle}\ }\bigl(X_a^0,\;X_b^0,\;\Phi_1,\;X_c^0,\;\Phi_2,\;X_d^0,\;\Phi_3\bigr),\\[0.3em]
\mathsf{StateRoot}_{e+1}&\xleftarrow{\ \mathsf{Merkle}\ }\bigl(X_a^1,\;X_b^1,\;\Phi_1,\;X_c^1,\;\Phi_2,\;X_d^1,\;\Phi_3\bigr).
\end{aligned}
$$

::: {.image-caption}
Figure 2: One witness recomputes both roots from the same material. Each changed account supplies its paired leaves, $X^0$ on the opening side and $X^1$ on the closing side, while each untouched subtree contributes one shared digest ($\Phi_2$ covers two accounts at once). Identical frontiers on both sides prove every omitted account unchanged.
:::

Successful verification proves every omitted position unchanged and every row position changed to exactly its committed close. An account changes if and only if it has a row. The settlement chain retains only a header:

$$
\mathsf{Header}_e=\bigl(\mathsf{StateRoot}_e,\;\mathsf{ChangeRoot}_e,\;\mathsf{StateRoot}_{e+1},\;D_e,\;C_e,\;F_e,\;W_e,\;\ldots\bigr).
$$

The totals are the terminal row's prefix: gross debit $D_e$, credit $C_e$, deposits $F_e$, and withdrawals $W_e$, with the row, record, and component counts alongside. To verify them, the chain is handed the terminal row and its Merkle opening once, checks the row against $\mathsf{ChangeRoot}_e$, and retains neither. The component vectors, remaining changed rows, and paired witness stay off the chain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Validate Everything Up Front

Before the chain queues a close for finalization, someone must check all of it. A validator committee (or TEE or SNARK/STARK, if desired) verifies the complete public close, every row, every prefix, and the exact state transition, and signs the header only when all of it holds. Exhaustive validation keeps malformed or inexact closes out of the finalization queue and reduces any remaining private-receipt dispute to one tagged, non-interactive submission.

Prefix continuity ties the header's totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the chain-sealed boundary, each withdrawal must cover at least its sealed record, and the totals must respect the close caps and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

The public corpus is partitioned into deterministic, exhaustive account intervals. Every certificate signer signs the same header. Each evidence piece is assigned to a quorum of validators who check and retain it. Quorum intersection guarantees that an honest signer checked and retains each piece, though that signer may differ by piece. With $n$ validators, $f$ tolerated faults, and quorum $q$, every piece $j$'s holders share more than $f$ validators with the certificate's signers:

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

2. **Higher receive-component tip.** Authenticate the public tip $(G^\star,J^\star)$ for one component, using $(0,0)$ for authenticated absence, and present a matching retained receipt at $(G^+,J^+)$. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Inconsistent receipt range.** For lower and upper pairs in one anchor, recipient, and component, where each receipt is linked to its own valid send, adjacent receipts must increase credit by exactly the upper payment, and an index gap must leave at least one unit for each omitted positive payment. A violation is a contradiction.

4. **Receipt fork.** Two distinct linked receipt bodies either reuse one receipt index within a component or acknowledge the same payer transaction differently. Different signature bytes over one identical receipt body are not a fork.

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

If $Q$ is still unreleased at $t\ge\tau$, one included call permanently freezes new work. The pending slots then resolve from the front, each finalizing once its challenge window closes or falling to a challenge, and terminal unwind opens against the last root standing. Queued withdrawals pay to their signed destinations, and every account uses one Merkle proof against that root to claim its remaining balance and any unconsumed deposit.

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

Every profile below runs one fixture: a registry of $N=1{,}000{,}000$ accounts, a 100-validator committee, a corpus split into 256 pieces for validator assignment, and an eight-thread worker pool. Every changed account sends, and the same 512 credited accounts receive, spaced evenly among the senders.

The matrix independently varies $A$, the number of changed accounts, and $h$, the credits on each credited account. No payment count appears because none is needed: rows and component tips carry fixed-width cumulative totals, so every size in the table is the same for any $T$.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Close stage</th>
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
    <tr><th colspan="5" style="text-align:left;">Operator</th></tr>
    <tr>
      <td style="padding-left:20px;">public corpus</td>
      <td style="text-align:right;">2.07 MB</td>
      <td style="text-align:right;">117 MB</td>
      <td style="text-align:right;">649 MB</td>
      <td style="text-align:right;">764 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">build roots</td>
      <td style="text-align:right;">1.28 ms</td>
      <td style="text-align:right;">54.1 ms</td>
      <td style="text-align:right;">330 ms</td>
      <td style="text-align:right;">403 ms</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">build piece proofs</td>
      <td style="text-align:right;">1.25 ms</td>
      <td style="text-align:right;">41.2 ms</td>
      <td style="text-align:right;">351 ms</td>
      <td style="text-align:right;">406 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Validator</th></tr>
    <tr>
      <td style="padding-left:20px;">assignment</td>
      <td style="text-align:right;">1.39 MB <span style="color:#666;">(67%)</span></td>
      <td style="text-align:right;">79.4 MB <span style="color:#666;">(68%)</span></td>
      <td style="text-align:right;">436 MB <span style="color:#666;">(67%)</span></td>
      <td style="text-align:right;">514 MB <span style="color:#666;">(67%)</span></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check and sign</td>
      <td style="text-align:right;">2.53 ms</td>
      <td style="text-align:right;">204 ms</td>
      <td style="text-align:right;">0.99 s</td>
      <td style="text-align:right;">1.27 s</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Chain</th></tr>
    <tr>
      <td style="padding-left:20px;">commitment</td>
      <td style="text-align:right;"><strong>5.62 KB</strong></td>
      <td style="text-align:right;"><strong>5.62 KB</strong></td>
      <td style="text-align:right;"><strong>5.94 KB</strong></td>
      <td style="text-align:right;"><strong>5.94 KB</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check commitment</td>
      <td style="text-align:right;"><strong>0.275 ms</strong></td>
      <td style="text-align:right;"><strong>0.258 ms</strong></td>
      <td style="text-align:right;"><strong>0.262 ms</strong></td>
      <td style="text-align:right;"><strong>0.260 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">challenge payload</td>
      <td style="text-align:right;"><strong>1.84 KB</strong></td>
      <td style="text-align:right;"><strong>2.34 KB</strong></td>
      <td style="text-align:right;"><strong>2.16 KB</strong></td>
      <td style="text-align:right;"><strong>2.66 KB</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check challenge</td>
      <td style="text-align:right;"><strong>0.127 ms</strong></td>
      <td style="text-align:right;"><strong>0.126 ms</strong></td>
      <td style="text-align:right;"><strong>0.125 ms</strong></td>
      <td style="text-align:right;"><strong>0.126 ms</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three interaction plots show arithmetic-mean latency for the operator's root build, the operator's piece-proof build, and the validator's check-and-sign on the busiest of the 100 assignments. Blue is 1,024 changed accounts and green is one million. Each series has measured points at one and 512 components per credited account. Connecting lines are visual guides, not interpolated measurements. Each panel uses its own millisecond scale.">
```

::: {.image-caption}
Figure 4: These are four measured profiles, not an interpolation. Points are arithmetic means, and each panel has its own millisecond scale. Blue holds $A=1{,}024$ and green holds $A=1{,}000{,}000$ while the horizontal axis changes the components on each credited account from $h=1$ to $h=512$.
:::

Increasing $A$ makes the state transition dense. Increasing $h$ concentrates more authenticated component leaves and signatures behind each credited row.

All four profiles register the same million accounts, yet at $A=1{,}024$ the validator's assignment is 1.39 MB. Distribution follows the changed rows and the shared frontier, not the registry, so it is sublinear in registered accounts as well as in payments.

The offchain public corpus is constant for a profile, so accepted payments only divide it. Ten million payments spread the sparse profile's 2.07 MB to about 0.2 offchain bytes per payment; a billion spread it to 0.002 offchain bytes per payment. The onchain commitment remains 5.62–5.94 KB per epoch across the four profiles: 0.0056–0.0059 bytes per payment at one million, and 0.0000056–0.0000059 at one billion. It carries only the header, quorum certificate, and terminal prefix opening rather than the rows or component leaves.

This fixture queues no withdrawals and no full closes, whose re-check and row openings would otherwise add to it. The challenge rows submit one proven higher-tip challenge: its payload grows only with the two lookup depths, and its check verifies two signatures and two openings.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows offchain public-corpus bytes per payment for the four A-by-h profiles; the right shows onchain commitment bytes per payment for the two A profiles. Blue is 1,024 changed accounts and green is one million; solid is h=1 and dashed is h=512. Every line falls as 1/T.">
```

::: {.image-caption}
Figure 5: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The offchain public corpus (left) depends on $A$ and $h$: components move the million-account corpus by only $1.2\times$ but the sparse corpus by $57\times$. The onchain commitment (right) stays 5.62–5.94 KB across profiles.
:::

The timers cover warm, in-memory close construction and validation on an 18-core Apple M5 Pro with 64 GiB, with the shared worker pool capped at eight threads. They exclude payment acceptance, networking, durable storage, key and registry construction, and custody execution.

Canonical encoding for hashing and signature verification remains included. Corpus bytes count each of the 256 pieces once, before replication to its 67 holders. The validator rows report the busiest of the 100 assignments with its share of the public corpus in parentheses, and the challenge rows target a mid-registry credited account's mid-set component.

The timers ran under a ten-million-payment build of each fixture. The sizes hold for any payment count: rebuilding each fixture at counts from ten thousand (one million where all accounts change) up to ten million reproduced every size in the table, with the corpus and chain payloads identical to the byte.

## A Bajillion Payments, One Close

The operator's work scales with payments: it verifies, durably commits, and signs every one of the $T$ payments it accepts. The public close never grows with $T$. It carries one row per changed account ($A$), one terminal pair per receive component ($H$), and one frontier digest per untouched subtree ($\Phi$):

$$
\text{payments }T
\quad\longrightarrow\quad
\text{rows }A+\text{components }H+\text{frontier }\Phi.
$$

For repeated activity over a fixed set of accounts and components, $(A+H+\Phi)/T\to 0$. Account-level clearing compresses repetition, not change: every changed account still pays for its row and every component for its terminal pair, but additional payments between them add nothing. No traffic pattern adds a per-payment term to the close either, because acceptance reserves room per account and per component, never per payment.

And this is as good as the trust model allows. A preconfirmation cannot arrive in less than one round trip to the operator that serializes spending. A close cannot quietly drop a payment: it must agree with every receipt a holder retains, or a single retained pair proves the fault. Settlement cannot make less than the changed state available to users who recover from public data alone, and this close adds only the terminal pairs and the frontier that splices the change into the registry.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
