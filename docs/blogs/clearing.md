---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-08-25T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Updated (8/25/26): Bajillion now rebuilds a dynamic live-account tree at each close and settles payouts and recovery through independent claims.*

*Update (8/20/26): Bajillion now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (more on this later).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity becomes a \~100-byte certified commitment that most chains can process. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

For a given set of accounts, one payment or a bajillion costs the same to settle.

## Payments as Fast as Browsing the Web

A Bajillion deployment starts from an authenticated account vector, and each epoch uses an onchain anchor $\mathcal A_e$. A pipelined successor can begin serving from its projected opening vector while the preceding epoch closes, then bind that exact opening root before settlement. The deployment fixes the maximum admission-delay increment and the minimum and maximum challenge duration before it accepts funds. Deposits and user-signed withdrawals are fixed before online payments begin. Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20.

$a$'s persistent state $X_a$ is a balance $B_a$, cumulative debit $D_a$, operator-promised credit $C_a$, a receipt count, and an activity flag. To send $x>0$ from $a$ to $b$, the payer signs the exact next debit, and the operator accepts by advancing the recipient's receive shard $\kappa$ from its current tip $(G,J)$ (which may or may not have been registered with the operator at the start of the epoch):

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;a\xrightarrow{\,x\,}b,\;D_a+x\bigr),
\qquad
R=\mathsf{Sign}_{\mathsf{op}}\bigl(\mathcal A_e,\;\kappa,\;x,\;\mathsf{TxId}(S),\;(G+x,\,J+1)\bigr).
$$

After authenticating $S$ and checking spendability, the operator atomically commits the debit, shard advance, close reservation, replay record, and receipt body. It then signs and returns $R$.

The matching pair $(S,R)$ is the accepted payment and the preconfirmation. The payer verifies and durably retains it, advances its local $D_a$ in that atomic local receipt commit, then forwards the pair to any recipient that will rely on it. The wallet keeps at most one unacknowledged send for this payer: it does not sign the next cumulative endpoint until the prior pair is verified and committed. An operator-reported counter is never the payer's authority. A rejection before the operator's commit changes no balance; the wallet retains the exact staged request for retry. If the response is lost, retrying that request returns the same pair without a second debit. This ordering serializes one payer account, not independent payers or a recipient's receive shards.

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
<div id="clearing-fig-payment" class="clearing-loop" role="img" aria-label="Animated message-sequence timeline of one accepted payment, with rows for payer a, the operator, and recipient b, and time measured in message delays. Payer a signs request S paying b 20 and sends it to the operator. At one instant, with no network hop, the operator verifies S, commits atomically, moving a from 100 to 80 and receive shard kappa zero from (0,0) to (20,1), and then signs receipt R. The response returns to a, which retains the matching pair of S and R and forwards the same pair directly to recipient b with no operator hop.">
  <noscript>Account a sends one request to one operator and receives one signed response. Verification, atomic storage, and receipt signing are local operator steps, and the payment is accepted at the operator's commit while the response is still in flight. Afterward, a gives the same matching pair directly to b without another operator hop.</noscript>
</div>
<script type="module" src="clearing.loops.js"></script>
```

::: {.image-caption}
Figure 1: The payer sends one request and receives one signed response. The operator verifies, commits, and signs locally, adding no network round trip. The commit moves $a$ from 100 to 80 and advances $b$'s receive shard $\kappa_0$ from $(0,0)$ to $(20,1)$ before $R$ exists. Once $R$ returns, $a$ sends the same matching $(S,R)$ directly to $b$ as transferable evidence.
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

Netting each account's debits and credits gives exact closing balances $(85,58,26,31)$, and gross payment debit equals gross payment credit at 54 (i.e. the changes net to zero). That is all the payment activity adds to the close: not the six payments, but the four accounts they changed, one row each.

Write the opening and closing states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, and $p_a$ is credit paid externally because the recipient is absent from the live state, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

For an account already in the state, $p_a=0$. For a recipient absent from the opening state with no deposit, $B_a^0=B_a^1=0$ and $p_a=c_a$: the accepted sends become one net external-payout claim when the close finalizes, without creating a zero-balance account. This includes payments made after a close removes an account at the cut: the identity is absent from the successor state, so those sends become claimable external payouts rather than recreating the account.

Each row binds both account states, the terminal outgoing pair $\mathsf{Out}_a$ when the account sent, its $\mathsf{CreditRoot}$, and a running total $\mathsf{prefix}_a$ over the sorted rows so far, where $\chi$ flags a withdrawal record and $h$ counts shard heads:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;p_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;h_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;\mathsf{CreditRoot}_e(a),\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

Each prefix must extend the preceding prefix exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

$$
\mathbf A_e=(\mathsf{Row}_a,\;\mathsf{Row}_b,\;\mathsf{Row}_c,\;\mathsf{Row}_d),
\qquad a<b<c<d.
$$

## Rebuild the Live State

Commit $\mathbf A_e$ under $\mathsf{ChangeRoot}_e$, a Merkle root that binds the exact row count and every row in order:

$$
\mathbf A_e
\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{ChangeRoot}_e.
$$

A $\mathsf{StateRoot}$ commits every field and the exact length of the strictly sorted vector of live accounts. A live leaf has a positive balance; a deposit can insert a new account, a close removes its account from the successor, and any other net balance of zero also leaves no live leaf. There are no permanent zero-balance tombstones.

$$
\mathbf X_e=\bigl((a,X_a^0):B_a^0>0\bigr)_{\text{sorted by }a},
\qquad
\mathbf X_e\xrightarrow{\ \mathsf{BMT}\ }\mathsf{StateRoot}_e.
$$

At a close, the operator merges the changed rows with the unchanged live leaves and rebuilds both state BMTs from the resulting ordered streams:

$$
\begin{aligned}
\mathbf X_e&=\mathsf{merge}\bigl(\mathsf{unchanged}_e,\;(a,X_a^0)_{a\in\mathbf A_e,\ B_a^0>0}\bigr),\\[0.3em]
\mathbf X_{e+1}&=\mathsf{merge}\bigl(\mathsf{unchanged}_e,\;(a,X_a^1)_{a\in\mathbf A_e,\ B_a^1>0}\bigr).
\end{aligned}
$$

This deliberately favors a simple bolt-on to an existing ordered database over maintaining a versioned authenticated trie. When only the root is needed, a known leaf count lets construction stream bounded subtrees through parallel hashing workers while retaining one subtree's working buffers plus a logarithmic frontier. Choosing the subtree size bounds that builder's memory independently of the total account count. Producing the proof slices still requires proof-capable Merkle material for the close.

The evidence is divided into deterministic account-key slices and dealt among validators. Each slice authenticates its exact opening-state, changed-row, and closing-state ranges; one validator's assigned slices form its dealing. A fourth BMT commits the gap-free positions and cumulative prefix at every slice boundary, so insertion or deletion cannot shift a hidden leaf across dealings:

$$
\mathsf{Layout}_e=\bigl((o_j,r_j,c_j,\mathsf{prefix}_j)\bigr)_{j=0}^{s}
\xrightarrow{\ \mathsf{BMT}\ }
\mathsf{LayoutRoot}_e.
$$

::: {.image-caption}
Figure 2: Opening and closing state are rebuilt from sorted live accounts. The layout root binds each slice's exact positions in both state vectors and the change vector, so account insertion and deletion cannot create a gap or overlap between validator dealings.
:::

The settlement commitment is a context-bound hash of the four ordered roots:

$$
\mathsf{Commitment}_e
=H\!\left(
\mathsf{StateRoot}_e
\parallel \mathsf{ChangeRoot}_e
\parallel \mathsf{StateRoot}_{e+1}
\parallel \mathsf{LayoutRoot}_e
\right).
$$

The totals are the terminal boundary's prefix: gross debit $D_e$, credit $C_e$, external payouts $P_e$, deposits $F_e$, and withdrawals $W_e$, with the row, record, and shard counts alongside. One terminal layout opening authenticates those totals without listing their recipients. Admission also consumes the 128-byte root bundle and this terminal opening as witness data. The roots, live leaves, shard vectors, changed rows, and remaining Merkle openings stay offchain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Seal Every Dealing Up Front

Before the chain queues a close for finalization, the operator disseminates each validator's dealing. A validator authenticates every assigned slice, checks every local row and prefix transition, batch-verifies every distinct send and receipt signature in that dealing, retains the evidence through the challenge deadline, and only then seals the shared commitment. No validator needs the complete corpus, but the assignments cover it exactly.

Prefix continuity ties the epoch totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the chain-sealed boundary. Every ordinary withdrawal equals its authorized positive amount, while every close sweeps its authenticated epoch tail. The totals must respect the close caps and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e-P_e.}
$$

Every certificate signer signs the same commitment. Each slice is assigned to a quorum of validators who authenticate and retain it. Quorum intersection guarantees that an honest signer authenticated and retains each slice, though that signer may differ by slice. With $n$ validators, $f$ tolerated faults, and quorum $q$, every slice $j$'s holders share more than $f$ validators with the certificate's signers:

$$
\begin{aligned}
n&=100,\qquad f=33,\qquad q=2f+1=67,\\[0.3em]
|\mathsf{signers}\;\cap\;\mathsf{holders}_j|&\;\ge\;2q-n=34>f.
\end{aligned}
$$

## Fault and Availability Model

The operator is Byzantine: it may halt, censor, equivocate, withhold messages, and propose arbitrary closes, but it cannot forge a payer signature. Bajillion assumes secure hashes and signatures, authenticated validator proofs of possession, at most $f$ Byzantine validators in the exact $n=3f+1$ committee above, and a correct and live settlement chain. Honest validators authenticate and durably retain their assigned dealings before voting. The embedding must keep the root bundle, public corpus, and required Merkle openings retrievable for as long as they can be challenged or claimed.

Sealing is not a totals-only check. Each validator authenticates the exact layout and state ranges in its slices, every changed-account equation, terminal outgoing pair, terminal receive-shard head, boundary contribution, prefix transition, state update, and distinct payment signature in its dealing. The terminal prefix then binds the exact vector lengths, deposits, withdrawals, external payouts, payment conservation, and closing liability. What certification cannot establish is that the operator never signed an additional receipt outside the selected public corpus.

Each payer account is one linear cumulative-debit sequence. A wallet using the base safety guarantee stages one exact send, retries those same bytes after response loss, verifies and durably commits the matching pair, advances its locally owned debit, and only then signs the next endpoint. A later endpoint authorizes the whole debit delta up to that value, while the public row carries only the terminal outgoing pair. If a wallet deliberately signs several cumulative endpoints before obtaining the earlier receipts, an intermediate receipt may be neither held privately nor selected as that terminal pair; that exposure is outside the base guarantee. This per-payer ordering does not limit parallel sends from independent accounts or parallel incoming receive shards.

The linked pair is private, transferable evidence. Any holder may submit a challenge; the chain does not require the caller to be the payer or recipient. Neither role must remain continuously online, but the availability assumption is per receipt: at least one honest holder must obtain and retain the required pair or pairs and get the bounded challenge included by $\Delta_e$. A recipient that wants an independently enforceable preconfirmation obtains the pair before relying on it. Honest validators retain public proof slices, but they cannot reconstruct a private receipt that no independent holder received or retained. This is not a single global observer assumption: different receipts may depend on different holders.

The configured challenge duration therefore trades clean-settlement latency for evidence-holder offline tolerance. A close finalizes only after its inclusive challenge window, and a withdrawal becomes claimable only after the close carrying it reaches the FIFO front and finalizes. Its absolute deadline is a permanent-fault trigger, not a promise of payout at that timestamp. Deposits use a different path: settlement already records the refund account and amount, so an expired unadmitted deposit is directly refundable without private evidence. Hard-fault recovery removes operator cooperation, but claimants still need the relevant authenticated openings and the settlement integration must atomically persist each claim with its custody effect.

## The Unavoidable Challenge

Validation establishes that the bound corpus satisfies the public relation. However, it cannot establish that the corpus contains every receipt the operator signed and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator signs exactly the receipts represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid receipt $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature. Through the inclusive deadline $t\le\Delta_e$, any holder may submit one of four bounded contradictions:

1. **Payer debit contradiction.** A matching acknowledged pair carries a debit above the public debit marker, or the same debit with a different send or receipt body. A bare payer request is insufficient. The receipt proves operator acknowledgement.

2. **Higher receive-shard tip.** Authenticate the public tip $(G^\star,J^\star)$ for one shard, using $(0,0)$ for authenticated absence, and present a matching retained receipt at $(G^+,J^+)$. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Inconsistent receipt range.** For lower and upper pairs in one anchor, recipient, and shard, where each receipt is linked to its own valid send, adjacent receipts must increase credit by exactly the upper payment, and an index gap must leave at least one base unit for each omitted positive payment. A violation is a contradiction.

4. **Receipt fork.** Two distinct linked receipt bodies either reuse one receipt index within a shard or acknowledge the same payer transaction differently. Different signature bytes over one identical receipt body are not a fork.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call.

A successful receipt challenge blocks the challenged slot and every pending descendant from finalizing. Earlier pending slots keep their ordinary challenge windows and may still finalize in order.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but stopping it is not enough: users must still be able to get their funds out. So every account can queue a unilateral signed authorization directly onchain, either to withdraw an exact amount or to close the account.

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;\omega,\;\tau\bigr),
\qquad
\omega\in\bigl\{\mathsf{withdraw}(x)\mid x>0\bigr\}\cup\bigl\{\mathsf{close}\bigr\}.
$$

$Q$ names the finalized root $\mathsf{rt}_z$ it was signed against, a destination $v$, an operation $\omega$, and an absolute deadline $\tau$. An ordinary withdrawal authorizes exactly the positive amount $x$; a close carries no amount. The operator neither submits nor approves it, and its cooperation decides only whether the authorization settles through a clean close or through hard-fault settlement.

There is also a fast path for paying someone who is not registered with the operator. The operator accepts the sends normally and records one absent-recipient row whose account and credit delta identify the recipient and exact net amount. The terminal layout opening authenticates only the aggregate $P_e$. If the close survives its challenge window, each recipient presents that row and, unless it is first, the immediately preceding row under one shared $\mathsf{ChangeRoot}_e$ multiproof. Their cumulative-prefix difference proves that this row contributed the claimed payout. The chain keys replay protection by the finalized batch and row position, so no recipient list or all-payout multiproof enters settlement and no post-deadline crank must fan payments out. From custody's perspective, this is a netted withdrawal; from the sender's perspective, it is an ordinary preconfirmed payment.

Queueing authenticates $Q$ against the finalized root, and every admitted descendant that can survive a cut must carry it forward. The next close commits both its already-onchain signed authorization and its changed account row.

A close does not freeze the account inside that epoch: it can keep sending and receiving until the cut. The cut sweeps its authenticated epoch-tail balance and omits the account from the successor state:

$$
\boxed{w_a=B_a^0+f_a+c_a-d_a,\qquad B_a^1=0.}
$$

After clean finalization, any positive payout is claimed with the authorization's withdrawal-boundary opening and one change-root multiproof over its row and, unless it is first, the immediately preceding row. The difference between adjacent cumulative prefixes gives the exact withdrawal value without retaining a recipient list: an ordinary withdrawal must equal its authorized amount, while a close must equal the authenticated tail above. A zero tail is a valid close and needs no payout claim. No later descendant can outlive that close, so whichever root survives can pay it. Every accepted deposit must enter an admitted close before its settlement-policy deadline. Admission discharges that obligation; expiry permanently tombstones the operator. The settlement queue already fixes the refund account and amount, so anyone can trigger that refund without an operator or state opening.

What makes the exit credible is that custody never leaves the chain early. Let $R_z$ be the reserve for finalized but unclaimed withdrawals and external payouts. With finalized liability $L_z$, pending slots $z+1,\ldots,\ell$ carrying boundary flows $(F_i,W_i,P_i)$, and deposits not yet included in a pending close $F_\star$:

$$
\boxed{
E=L_z+R_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+R_z+\sum_{i=z+1}^{\ell}(W_i+P_i)+F_\star.
}
$$

Withdrawals and external payouts stay in active custody until their slot finalizes at the queue front, then their aggregate value moves into $R_z$. Individual claims reduce that reserve and the chain's assets together. This finalization step touches only totals and roots; its work does not grow with the number of recipients. A challenged or invalidated suffix creates no reserve. The operator can stop serving payments, but it cannot take funds or send them without authorization.

If $Q$ is still unfinalized at $t\ge\tau$, or an accepted deposit remains outside an admitted close through its inclusion deadline, the first time-aware onchain call to observe the deadline permanently freezes new work. Pending deposit refunds remain independently claimable from the settlement queue. The pending slots resolve from the front, each finalizing once its challenge window closes or falling to a challenge, then hard-fault settlement freezes the last finalized state root. Already-finalized claim reserves remain claimable and stay separate. Each survivor consumes one retained state opening against the frozen root: an outstanding authorization routes its amount to the signed destination, and the account receives the residual. These replay-protected claims are independent, so recovery needs neither an all-account scan nor a global payout crank. An opening against the root ultimately frozen must remain available until its position is claimed; the protocol supplies neither a historical witness store nor a terminal-claim deadline.

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

Every profile below uses a 100-validator committee, divides the evidence into 256 slices, and runs construction and verification on one shared eight-thread worker pool (M5 Pro). The matrix varies $N$, the number of live accounts. Every account sends, the same 512 accounts receive, and each recipient uses one receive shard. The fixture therefore holds $A=N$, $B=512$, and $h=1$ while $N$ grows from 1,024 to one million.

No payment count appears because none is needed: rows and shard tips carry fixed-width cumulative totals, so every size in the table is the same for any $T$. Each stage is measured independently. The fixture constructs the opening-state proof cache before measurement. Prepare builds the closing-state, change, and layout roots from the owned close inputs while reusing that cache; deal derives all proof slices from the prepared close; seal checks and retains the busiest validator's dealing, batch-verifies every distinct payment signature in it, and signs the commitment.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
      <th colspan="4" style="text-align:center;">Live accounts (<em>N</em>)</th>
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
      <td style="padding-left:20px;">evidence</td>
      <td style="text-align:right;">1.58 MB</td>
      <td style="text-align:right;">7.34 MB</td>
      <td style="text-align:right;">64.3 MB</td>
      <td style="text-align:right;">633 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">0.422 ms</td>
      <td style="text-align:right;">2.03 ms</td>
      <td style="text-align:right;">21.2 ms</td>
      <td style="text-align:right;">215 ms</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">deal</td>
      <td style="text-align:right;">0.164 ms</td>
      <td style="text-align:right;">0.318 ms</td>
      <td style="text-align:right;">1.81 ms</td>
      <td style="text-align:right;">24.9 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Certification</th></tr>
    <tr>
      <td style="padding-left:20px;">dealing</td>
      <td style="text-align:right;">1.08 MB <span style="color:#666;">(-32%)</span></td>
      <td style="text-align:right;">4.98 MB <span style="color:#666;">(-32%)</span></td>
      <td style="text-align:right;">43.3 MB <span style="color:#666;">(-33%)</span></td>
      <td style="text-align:right;">426 MB <span style="color:#666;">(-33%)</span></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">2.62 ms</td>
      <td style="text-align:right;">14.3 ms</td>
      <td style="text-align:right;">126 ms</td>
      <td style="text-align:right;">1.29 s</td>
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
      <td style="text-align:right;"><strong>0.463 ms</strong></td>
      <td style="text-align:right;"><strong>0.468 ms</strong></td>
      <td style="text-align:right;"><strong>0.459 ms</strong></td>
      <td style="text-align:right;"><strong>0.462 ms</strong></td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Dispute</th></tr>
    <tr>
      <td style="padding-left:20px;">challenge</td>
      <td style="text-align:right;"><strong>1.74 KB</strong></td>
      <td style="text-align:right;"><strong>1.87 KB</strong></td>
      <td style="text-align:right;"><strong>1.96 KB</strong></td>
      <td style="text-align:right;"><strong>2.06 KB</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check challenge</td>
      <td style="text-align:right;"><strong>0.469 ms</strong></td>
      <td style="text-align:right;"><strong>0.458 ms</strong></td>
      <td style="text-align:right;"><strong>0.465 ms</strong></td>
      <td style="text-align:right;"><strong>0.461 ms</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 4: The operator prepares the roots, then deals the evidence into slices. Each validator seals its dealing by checking and retaining its assigned slices before signing the commitment. A receipt holder with evidence of fraud can dispute the certified commitment with a challenge that the chain checks.
:::

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three log-scale plots show measured latency for preparing roots, dealing all evidence slices, and sealing the busiest validator dealing as live accounts increase from 1,024 to one million.">
```

::: {.image-caption}
Figure 5: These are four measured profiles, not an interpolation. Both axes are logarithmic, and each point is labeled with its measured latency. Construction and sealing scale approximately linearly once the fixed costs are amortized.
:::

Even the largest validator dealing is 32–33% smaller than the full evidence because it contains only that validator's assigned slices. At one million live accounts it checks 426 MB rather than the complete 633 MB corpus. This is the explicit cost of the simpler fresh-BMT design: evidence distribution grows with live state, while settlement and disputes remain bounded.

The offchain evidence is constant for a profile, so accepted payments only divide it. Ten million payments spread the one-million-account profile's 633 MB to about 63 offchain bytes per payment; a billion spread it to 0.63 offchain bytes per payment. The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap; proofs of possession were checked when the committee registered. With the 32-byte commitment and this encoding's eight-byte bitmap-length prefix, the 100-validator header-plus-certificate package is 101 bytes total. If the clearing validators are also the settlement chain's validators, inclusion itself supplies the attestation and only the 32-byte commitment need be retained. The admission witnesses described above are not included in that figure. It likewise shrinks as $1/T$.

This fixture queues no withdrawals or closes, whose re-check and row openings would otherwise add to it. Individual payout claims are not part of the certified settlement: both an external-payout claim and a withdrawal claim carry their row and at most one adjacent row under a shared $O(\log A)$ BMT multiproof; the withdrawal also carries its signed request and boundary opening. Both remain a few kilobytes or less in these profiles. The challenge measurements use one proven higher-tip challenge: its 1.74–2.06 KB payload grows only with the two lookup depths, and its check verifies two signatures and two openings. Clean closes submit no fraud challenge at all, so average challenge traffic is smaller still. A challenge targets a commitment whose certificate was already checked at admission, so adjudication does not verify that certificate again.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows offchain evidence bytes per payment for four live-account counts; the right shows the 101-byte certified commitment. Every line falls as one over T.">
```

::: {.image-caption}
Figure 6: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The offchain evidence (left) grows with the live-account count $N$. The certified commitment (right) stays 101 bytes across profiles.
:::

## A Bajillion Payments, One Settlement

The operator's online work scales with payments: it verifies, durably commits, and signs every one of the $T$ payments it accepts. The close has no per-payment term. Writing $U$ for unchanged live leaves, $A$ for changed rows, $H$ for total shard tips, and $M$ for the largest committed vector length, its authenticated corpus carries one state leaf per unchanged account, one larger row per changed account, one terminal pair per receive shard, and the bounded openings needed to divide those vectors into $s$ slices:

$$
\text{payments }T
\quad\longrightarrow\quad
U\text{ state leaves}+A\text{ rows}+H\text{ shard tips}+O(s\log M)\text{ openings}.
$$

For the benchmark's fixed live set, $U=N-A$; account creation, deletion, and external-payout rows need not preserve that identity in general. For repeated activity over a fixed set of accounts and shards, this fixed corpus divided by $T$ tends to zero. Account-level clearing compresses repetition, not state: every unchanged live account contributes a leaf, every changed account contributes a row, and every shard contributes its terminal pair, but additional payments between them add nothing. No traffic pattern adds a per-payment term to the close either, because acceptance reserves room per account and per shard, never per payment.

The fresh tree is intentionally conventional. Root-only construction can stream an existing ordered account database through bounded subtree builders; proof-producing close assembly retains the Merkle levels needed for slice openings. Neither requires maintaining durable authenticated paths for every pending root. In exchange, validators receive evidence for the complete live state rather than only a sparse update. A preconfirmation still cannot arrive in less than one round trip to the operator that serializes spending, and a close cannot quietly drop a payment: it must agree with every receipt a holder retains, or a single retained pair proves the fault.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
