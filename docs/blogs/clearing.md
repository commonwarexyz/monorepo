---
title: "Keep the Change"
description: "Bajillion is an account-level clearing protocol for cheap settlement of many-to-many payments and fast, credible preconfirmations. Each payment takes one operator round trip. At close, accounts settle their net changes instead of publishing every transaction, so public settlement cost per payment approaches zero as activity grows."
date: "August 14th, 2026"
published-time: "2026-08-14T00:00:00Z"
modified-time: "2026-08-14T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet you'll need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching an arbitrary counterparty means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). A rollup either pays a prover per payment or publishes every payment so faults can be disputed. 

[Bajillion](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md) is a simple, optimistic clearing protocol that does just enough to be useful. It provides many-to-many payments and efficiently settles them on any chain that can process a few-kilobyte commitment. Its preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. No SNARKs and no fancy cryptography: just signatures, Merkle openings, and one-shot challenges.

Settlement cost is a function of the accounts that change, not the payments that move them. Make one payment or a bajillion: the close remains the same size. Without expensive incremental processing or complex challenges to police what happened. 

## Payments as Fast as Browsing the Web

A Bajillion epoch starts from an authenticated account vector and an onchain anchor $\mathcal A_e$. Deposits and user-signed withdrawals are fixed before online payments begin. Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20.

$a$'s persistent state $X_a$ is a balance $B_a$, cumulative debit $D_a$, operator-promised credit $C_a$, a receipt count, and an activity flag ([§B of the formal spec](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md#b-deployment-and-chain-state)). To send $x>0$ from $a$ to $b$, the payer signs the exact next debit, and the operator accepts by advancing the recipient's receive component $\kappa$ from its current tip $(G,J)$ (which may or may not have been registered with the operator at the start of the epoch):

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

Payments assigned to different components never contend, so a hot account scales \~linearly across parallel workers. At close, one terminal signed pair represents each component, no matter how many payments advanced it (and the sum of all components is the recipient's credit).

In the same ledger, accounts $(a,b,c,d)$ open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

Their exact closing balances are $(85,58,26,31)$. Gross payment debit equals gross payment credit at 54.

For recipient $b$, sort the terminal records by component identifier and commit them under $\mathsf{HeadRoot}_e(b)$. The root binds the exact component count, ordered records, total credit, and total receipt count. In this example, $b$'s three heads end at $(20,1)$, $(4,1)$, and $(6,1)$, so the root summary is $(h_b,G_b,J_b)=(3,30,3)$.

The account row is the unit of public settlement. Write the opening and closing states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$.

If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Each row binds both account states, the terminal outgoing pair $\mathsf{Out}_a$ when the account sent, its $\mathsf{HeadRoot}$, and the aggregate prefixes needed for conservation:

$$
\mathsf{Row}_a=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;\mathsf{HeadRoot}_e(a),\;\mathsf{prefix}_a\bigr).
$$

The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes.

The $A$ rows form a length-bound $\mathsf{ChangeRoot}$, which authenticates the compact change vector. The paired sparse witness reconstructs the opening and closing roots together over the row positions $\mathcal J_e$. Each row supplies its opening and closing leaf, while every omitted subtree contributes one authenticated digest to both sides, collected as the sparse frontier $\Phi_e$. Successful verification proves every omitted position unchanged and every row position changed to exactly its committed close. An account changes if and only if it has a row.

The settlement chain retains a header $\mathsf{Header}_e$ containing the opening $\mathsf{StateRoot}_e$, $\mathsf{ChangeRoot}_e$, and closing $\mathsf{StateRoot}_{e+1}$, together with the quorum certificate. Admission receives the terminal changed row and its Merkle opening separately, authenticates the row against $\mathsf{ChangeRoot}_e$, checks its aggregate prefixes, and retains neither.

A $\mathsf{StateRoot}$ commits every field in the complete account-state vector $X$. The component vectors, remaining changed rows, and paired exact-update witness stay outside the chain payload as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$. [Spec §D](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md#d-closing-an-epoch) tabulates the evidence lifetimes.

$$
\begin{aligned}
\mathbf Y_b
&=\bigl((\kappa_0,20,1),(\kappa_1,4,1),(\kappa_2,6,1)\bigr),\\
\mathbf Y_b
&\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{HeadRoot}_e(b)
\hookrightarrow \mathsf{Row}_b,\\
\mathbf A_e
&=(\mathsf{Row}_a,\mathsf{Row}_b,\mathsf{Row}_c,\mathsf{Row}_d)
\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{ChangeRoot}_e.
\end{aligned}
$$

Here $\hookrightarrow$ places the head root inside $\mathsf{Row}_b$. The same row vector drives the full-state update:

$$
\underbrace{\mathsf{StateRoot}_e}_{\mathsf{Commit}(X^0)}
\xrightarrow[\displaystyle
  k\notin\mathcal J_e\Rightarrow X_k^1=X_k^0]
{\displaystyle \mathbf A_e,\,\Phi_e}
\underbrace{\mathsf{StateRoot}_{e+1}}_{\mathsf{Commit}(X^1)}.
$$

::: {.image-caption}
Figure 2: Terminal component heads feed exact changed-account rows, which form $\mathsf{ChangeRoot}_e$. Those rows and sparse frontier $\Phi_e$ then transform the opening full-state commitment into the closing one while proving every omitted position unchanged.
:::

Write $T$ for accepted payments, $A$ for changed-account rows, $H=H_e=\sum_a h_a$ for terminal receive-component heads, $\Phi=|\Phi_e|$ for sparse-frontier hashes, and $N$ for registered account positions.

$H$ is the price of receive concurrency. More components remove online contention but enlarge the close. The protocol therefore caps both the number of terminal components and the close size independently of $T$. A payment is accepted only when the operator can reuse a component or reserve room for a new one without exceeding either cap.

## Validate Before Admission

A close cannot enter the pending queue until admission has checked the public data for malformation and exactness. Challenges handle a different problem: contradictions among operator-signed receipts, whether those receipts are private or part of the disclosed corpus.

For sorted rows, the authenticated prefixes telescope to total debit $D_e$, credit $C_e$, deposits $F_e$, and withdrawals $W_e$. The deposit total and withdrawal record count must reproduce the chain-sealed boundary, each withdrawal must cover at least its sealed record, and the totals must respect the close caps and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

The types matter. Deposits and withdrawals come from the chain-sealed boundary. Debits and credits come from signed cumulative debit and credit markers. Equal totals do not let one type impersonate another.

The reference deployment partitions the public corpus into deterministic, exhaustive account intervals. Every certificate signer signs the same header. Each evidence piece is assigned to a quorum of validators who check and retain it.

Quorum intersection guarantees that an honest signer checked and retains each piece, though that signer may differ by piece. At the reference parameters, with 100 validators, 33 tolerated faults, and quorum 67, every piece's holders share at least 34 validators with the certificate. The identical header, exhaustive assignment, and quorum intersection together attest to the complete public relation. Byte availability alone would not.

Admission appends the close as a pending slot without changing custody or the finalized root. Registration has already sealed the epoch's boundary and opened the next. Only an unchallenged queue front can install its root and release its withdrawals:

$$
\mathsf{Serving}_e
\xrightarrow[\text{finalized root and custody unchanged}]{\mathsf{admit},\ t\le\alpha_e}
\underbrace{\mathsf{Pending}_e}_{\mathsf{challengeable}\ t\le\Delta_e}
\xrightarrow[\mathsf{front\ only}]{\mathsf{finalize},\ t>\Delta_e}
\mathsf{Finalized}_e.
$$

::: {.image-caption}
Figure 3: Admission appends the fully validated close to the pending queue, changing neither custody nor the finalized root. An unchallenged slot finalizes only from the queue front, once its window closes.
:::

The admission cutoff $\alpha_e$ precedes the challenge deadline: $\alpha_e<\Delta_e$. The chain may pipeline a bounded number $K$ of consecutive pending slots, but only the front can finalize. This preserves one state lineage even when a later slot's challenge window closes first.

## The One Fact Validation Cannot See

Under the selected validity mode—quorum certification, a validity proof, or a TEE attestation—validation establishes that the bound corpus satisfies the public relation. It cannot establish that the corpus contains every receipt the operator signed and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator signs exactly the receipts represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid receipt $R^+$. The admission verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. Any of the three modes can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

That is the blind spot. A payment is its matching pair, handed to the payer and forwarded to its recipient, so at close the recipient holds every payment it received. Outside the operator being checked, no other party does, and no verifier can do better than the recipient's own record. A receipt delivered to no one has injured no one who relied on it. The protocol puts the completeness check where the complete record already sits.

The challenge window turns a preconfirmation from a promise into evidence. Through the inclusive deadline $t\le\Delta_e$, any holder or watchtower may submit one of four bounded contradictions:

1. **Payer debit contradiction.** A matching acknowledged pair carries a debit above the public debit marker, or the same debit with a different send or receipt body. A bare payer request is insufficient. The receipt proves operator acknowledgement.

2. **Higher receive-component tip.** Authenticate the public tip $(G^\star,J^\star)$ for one component, using $(0,0)$ for authenticated absence, and present a matching retained receipt at $(G^+,J^+)$. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Inconsistent receipt range.** For lower and upper pairs in one anchor, recipient, and component, where each receipt is linked to its own valid send, adjacent receipts must increase credit by exactly the upper payment, and an index gap must leave at least one unit for each omitted positive payment. A violation is a contradiction.

4. **Receipt fork.** Two distinct linked receipt bodies either reuse one receipt index within a component or acknowledge the same payer transaction differently. Different signature bytes over one identical receipt body are not a fork.

[Spec §E](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md#e-receipt-challenges) gives the exact checked-arithmetic and fork predicates.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call. The fraud proof is about receipts, not arbitrary execution, which is what keeps that surface small.

The higher-tip challenge combines three sources in one bounded onchain call. The settlement chain provides the admitted header and its $\mathsf{ChangeRoot}$. The availability service provides the authenticated account and component lookups that open $b$ and then $\kappa_0$. The recipient provides the signed pair it retained privately.

$$
\begin{aligned}
\mathsf{Challenge}^{\mathsf{higher}}_e=\bigl(&
\underbrace{\mathsf{slotId}_e}_{\text{chain reference}},\\[-0.1em]
&\underbrace{P^+_{a\to b,\kappa_0}}_{\text{retained by the recipient}},\\[-0.1em]
&\underbrace{
  \mathsf{AccountLookup}(b),
  \mathsf{ComponentLookup}(\kappa_0)
}_{\text{from the availability service}}
\bigr).
\end{aligned}
$$

The call resolves the two authenticated lookups in sequence:

$$
\begin{aligned}
\mathsf{slotId}_e
&\longmapsto
\mathsf{Header}_e[\mathsf{ChangeRoot}_e],\\
\mathsf{ChangeRoot}_e
&\xrightarrow{\ \mathsf{AccountLookup}(b)\ }
\mathsf{Row}_b[\mathsf{HeadRoot}_e(b)]
\xrightarrow{\ \mathsf{ComponentLookup}(\kappa_0)\ }
(G^\star,J^\star)=(20,1),\\
P^+_{a\to b,\kappa_0}
&\xrightarrow{\ \mathsf{Verify}(\mathcal A_e,b,\kappa_0)\ }
(G^+,J^+)=(23,2).
\end{aligned}
$$

$$
\bigl(G^+>G^\star\bigr)\lor\bigl(J^+>J^\star\bigr)
\;\Longleftrightarrow\;
(23>20)\lor(2>1)
\;\Longrightarrow\;
\mathsf{HigherTip}.
$$

::: {.image-caption}
Figure 4: The first display identifies the challenge inputs and the source of each one. The second authenticates the committed component tip by following $\mathsf{ChangeRoot}_e\to \mathsf{Row}_b\to\mathsf{HeadRoot}_e(b)\to\kappa_0$, then verifies the retained pair in the same scope. Either strict coordinate inequality proves the contradiction. If row $b$ were absent, the account lookup would instead carry the neighboring-row openings that prove its ordered absence.
:::

There is no fifth challenge for boundary omissions. Deposits and withdrawals were serialized by the settlement chain before the epoch, so wrong roots, totals, signatures, or account effects are public registration or admission failures.

A successful receipt challenge blocks the challenged slot and every admitted descendant from finalizing. Earlier admitted slots keep their ordinary challenge windows and may still finalize in order. The challenge itself provides neither reimbursement nor slashing. Collateral, insurance, and repair allocation are deployment policy.

## A Deadline to Exit

Blocking a contradicted close matters only if users can still recover their funds. The exit path starts with chain-sealed deposits and signed withdrawals.

A deposit has no deadline. A finalized deposit immediately raises custody, and its record enters the next boundary that admits it. If terminal unwind begins before that boundary's slot finalizes, the deposit returns in the terminal payout. A stalled deposit alone can neither trigger deployment unwind nor claim a bounded exit.

A withdrawal is signed against an existing finalized root $\mathsf{rt}_z$ and names no future epoch or anchor:

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;x,\;\gamma,\;\tau\bigr),
$$

with an eligible destination $v$, amount $x$, full-close flag $\gamma$, and absolute deadline $\tau$. Since $v$ may be any destination the asset adapter accepts, paying an unregistered recipient is just a withdrawal to its address: the funds arrive at release, with no preconfirmation in between. Queueing is a direct, permissionless chain call. The operator neither submits nor approves it. Operator cooperation decides only whether the withdrawal settles through a clean close or through terminal unwind.

If the admitted pipeline extends $\mathsf{rt}_z$ through $\mathsf{rt}_\ell$, where $\ell-z\le K$, queueing must prove the withdrawal affordable at each of those roots. Every later admission that does not carry it re-proves it at the new root, so every possible survivor root is covered. A full close must exhaust the balance at the pipeline tail, and the deadline must leave the configured notice $\eta>0$ after queueing.

Queueing changes neither custody nor a state root. Clean front finalization atomically releases withdrawals, consumes deposits, advances the finalized root, and decrements custody.

The operator can stop serving payments, but it cannot unilaterally spend deployment funds.

[Spec §F](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md#f-settlement-transitions-exit-and-terminal-unwind) gives the complete queueing and terminal-payout predicates.

Let $E$ be current custody. For admitted slots $z+1,\ldots,\ell$, let $F_i$ be the unfinalized deposits carried by slot $i$, and let $F_\star$ contain the deposits not yet carried by an admitted slot. Custody can be read either from finalized liability or from the pipeline tail:

$$
\boxed{
E=L_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+\sum_{i=z+1}^{\ell}W_i+F_\star.
}
$$

Withdrawals remain inside custody until their own slot reaches the front and finalizes. Admission can therefore be pipelined without letting a speculative descendant spend assets out from under an ancestor.

The signed deadline $\tau$ is a fence, not a payout promise. If an included valid call observes an unreleased $Q$ at $t\ge\tau$, it permanently blocks new work but does not erase already-admitted slots. Those slots remain challengeable and resolve from the front in order. Only an unadmitted registration is discarded.

A pure timeout unwinds only after every admitted slot resolves. A successful challenge cuts the pipeline at the faulted slot and unwinds once every clean slot ahead of it resolves in order. Terminal unwind then authenticates the complete $N$-account state vector at the surviving finalized root, pays each signed withdrawal, and returns each residual balance together with any deposit never consumed by a surviving slot.

The canonical payout must sum to $E$. One atomic transition then pays it, zeroes custody and liability, consumes every remaining record, and makes the deployment permanently unwound.

Recovery is unilateral but deliberately coarse. One expired withdrawal kills the affected deployment. Terminal unwind requires an $O(N)$ scan of the complete survivor state. In the reference path, aggregating a dense invalid suffix can raise worst-case work to $O(KN\log(N+1))$ and retained boundary data to $O(KN)$. The guarantee also depends on including valid timeout, finalization, and unwind calls and keeping the complete state preimage available.

## Close Without Pausing Payments

Closing an epoch is asynchronous. Spending continues while the final payer debit markers and receive-component tips are authenticated and admitted. Otherwise, account-level compression would create a throughput cliff at every epoch boundary.

Rollover happens independently for each payer. Before an account can send in epoch $e+1$, its final epoch-$e$ debit marker and preserved spendable balance are fixed. Accounts that do not send are fixed when the predecessor epoch seals.

The key invariant applies immediately before any successor deposit or withdrawal is applied. Let $\widetilde B_a$ be the preserved guarded balance after every accepted predecessor debit and every predecessor credit already imported for spending. Let $B_a^1$ be the exact predecessor closing balance. Then

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad \rho_a\ge0,}
$$

where $\rho_a$ is the total unimported predecessor credit. The live head is the payer's safe spendable balance. The authenticated predecessor close is computed separately.

Successor debits continue on the same head, so reconciliation adds $\rho_a$ to the live value. Assigning $B_a^1$ over it would erase those debits. In the running example, $a\xrightarrow{20}b$ leaves the preserved head at 80 while the not-yet-imported $d\xrightarrow{5}a$ credit makes the exact predecessor close 85. If $a$ spends 20 and then 15 in the successor while the missing credit arrives between them,

$$
80-20+5-15=50=(85)-20-15.
$$

```{=html}
<div id="clearing-fig-rollover" class="clearing-loop" role="img" aria-label="Animated owner-preserved rollover for account a. An accepted epoch-e pair leaves one preserved head of 80 and rotates that head into epoch e plus 1. Two connected rails branch from the same 80. The exact predecessor close reaches 85. The live successor rail spends 20 to reach 60, reconciles to 65, and spends 15 to reach 50. One vertical marker identifies the same missing predecessor credit of 5 in both calculations. The 85 close terminates on its own rail and never overwrites the live head.">
  <noscript>An accepted epoch-e pair leaves one preserved head of 80. The exact-close rail computes 80 plus 5 as 85. The live rail computes 80 minus 20 plus the same 5 minus 15 as 50. Reconciliation adds the shared missing credit without installing 85 over the live head.</noscript>
</div>
```

::: {.image-caption}
Figure 5: Both rails branch from the same preserved 80. The upper rail computes the exact epoch-$e$ close, $80+\rho_a=85$. The lower rail keeps the epoch-$e+1$ head live, $80-20+\rho_a-15=50$. The single vertical $\rho_a=5$ marker is the same predecessor credit in both calculations. The two values serve different roles: 85 is the canonical predecessor close, while 50 is the current live head. Reconciliation adds $\rho_a$ to the live value and preserves every successor debit.
:::

The live balance is not monotone: successor payments spend it down. Only predecessor completion is one-sided, because it can add missing credit but cannot discover another accepted debit.

Successor boundary operations and shard moves must preserve the same rule: the live head is only ever adjusted, never overwritten. [Spec §G](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md#g-overlapped-epochs) gives the one-time application and authenticated-snapshot conditions.

Rollover changes only live serving state. The ordinary close still produces the canonical rows, state root, and public corpus, which go through the same validity and admission checks. A challenge against the predecessor invalidates its admitted descendants.

## The Close Never Grows with Payments

The asymptotics say what stops growing. A controlled benchmark shows what still costs time.

Each profile below fixes $N=1{,}000{,}000$ registered accounts, 512 credited accounts, 256 deterministic pieces, a 100-validator committee with quorum 67, and an eight-thread worker pool. Every changed account sends. The same 512 accounts receive in every profile, evenly spaced among the accounts that change.

The matrix independently varies $A$, the number of changed accounts, and $h$, the number of component heads on each credited account. No payment count appears because none is needed: rows and heads carry fixed-width cumulative totals, so every size in the table is the same for any $T$. A bajillion is not a number, and the close never asks for one.

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
      <td style="padding-left:20px;">admission payload</td>
      <td style="text-align:right;"><strong>5.62 KB</strong></td>
      <td style="text-align:right;"><strong>5.62 KB</strong></td>
      <td style="text-align:right;"><strong>5.94 KB</strong></td>
      <td style="text-align:right;"><strong>5.94 KB</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check admission</td>
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
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three interaction plots show arithmetic-mean latency for the operator's root build, the operator's piece-proof build, and the validator's check-and-sign on the busiest of the 100 assignments. Blue is 1,024 changed accounts and green is one million. Each series has measured points at one and 512 heads per credited account. Connecting lines are visual guides, not interpolated measurements. Each panel uses its own millisecond scale.">
```

::: {.image-caption}
Benchmark chart: These are four measured profiles, not an interpolation. Points are arithmetic means, and each panel has its own millisecond scale. Blue holds $A=1{,}024$ and green holds $A=1{,}000{,}000$ while the horizontal axis changes the heads on each credited account from $h=1$ to $h=512$.
:::

Increasing $A$ makes the state transition dense. Increasing $h$ concentrates more authenticated component leaves and signatures behind each credited row. Neither cost disappears behind the phrase “one row per account.”

All four profiles register the same million accounts, yet at $A=1{,}024$ the validator's assignment is 1.39 MB. Distribution follows the changed rows and the shared frontier, not the registry, so it is sublinear in registered accounts as well as in payments.

The corpus is constant for a profile, so accepted payments only divide it. Ten million payments spread the sparse profile's 2.07 MB to about 0.2 bytes of public settlement each. A billion would leave 0.002. The chain payload remains nearly flat because it carries the header, quorum certificate, and terminal prefix opening rather than the rows or component leaves.

This fixture queues no withdrawals and no full closes, whose re-check and row openings would otherwise add to it. The challenge rows submit one proven higher-tip challenge: its payload grows only with the two lookup depths, and its check verifies two signatures and two openings.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Log-log plot of public corpus bytes per accepted payment against payments accepted in the epoch, from one million to one billion payments, with four lines for the four table profiles. With 1,024 changed accounts, one head per credited account falls from about 2 bytes per payment to 0.002, and 512 heads from 117 to 0.12. With one million changed accounts the two head counts nearly coincide, falling from about 649 and 764 bytes to 0.65 and 0.76. Each line is its profile's constant corpus divided by the payment count.">
```

::: {.image-caption}
Bytes-per-payment chart: fixed-width rows keep each profile's corpus constant in $T$, so each line is that profile's corpus from the table over the payment count and falls exactly as $1/T$. The two $A=1{,}000{,}000$ lines nearly coincide because heads move that corpus by only $1.2\times$, while at $A=1{,}024$ they separate it by $57\times$.
:::

The timers cover warm, in-memory close construction and validation on an 18-core Apple M5 Pro with 64 GiB, with the shared worker pool capped at eight threads. They exclude payment acceptance, networking, durable storage, key and registry construction, and custody execution.

Canonical encoding for hashing and signature verification remains included. Corpus bytes count each of the 256 pieces once, before replication to its 67 holders. The validator rows report the busiest of the 100 assignments with its share of the public corpus in parentheses, and the challenge rows target a mid-registry credited account's mid-set component.

The timers ran under a ten-million-payment build of each fixture. The sizes hold for any payment count: rebuilding each fixture at counts from ten thousand (one million where all accounts change) up to ten million reproduced every size in the table, with the corpus and chain payloads identical to the byte.

## What Clearing Trades

### Channels

Payment channels pursue the same two goals, but draw the settlement boundary around a pair. A bilateral channel compresses repeated transfers between two parties while preserving bilateral self-custody. A routed network such as the one in the [original Lightning paper](https://lightning.network/lightning-network-paper.pdf) extends that pairwise guarantee across a path, reserving directional liquidity and individually enforceable timed state at every hop.

Bajillion draws the boundary around an account. It relies on one operator for online payment service during normal operation, while the settlement chain holds custody and enforces withdrawals. It then nets every sender and recipient under one account-wide close. Reaching a new counterparty needs only its registered account. There is no channel to open, route to find, or liquidity to lock. There is no routed-hop state. The deployment maps payments into bounded receive components, and the close carries one terminal head per component used.

That broader netting boundary is why a cycle can be cheap. If $a\to b$, $b\to c$, and $c\to a$ repeat 100,000 times, the epoch contains $T=300{,}000$ payments but only $A=3$ changed accounts. With one component per recipient, it also has $H=3$.

Gross debit still equals gross credit, but the public close carries three rows, three heads, and their sparse frontier rather than 300,000 payment records. A channel network would carry the same flow on three funded links whose liquidity the cycle merely shuffles.

### Rollups

A rollup picks between two costs. A validity rollup can commit only state diffs, bringing its settlement data close to this design's rows, but it proves every payment it executes, expensive at this scale even with recent advances. An optimistic rollup drops the prover, but its faults are proven against published inputs, so every payment must land in data availability, and a one-shot ZK fault proof shrinks the dispute, not the log. Bajillion also touches every payment, but with a signature instead of a proof, and it publishes neither a log nor a trace: the dispute object is a signed receipt already in its holder's hands.

Under either flavor, the chain settles whatever the operator chose to execute, and an undisclosed promise is exactly the one fact validation cannot see. A sequencer could sign its preconfirmations and answer a challenge for dropping one, but that concedes the point: binding a preconfirmation takes a challenge protocol under any proof system. Bajillion starts there. Its signed receipt is the preconfirmation, and a one-shot challenge with no prover in the loop binds it.

### Plasma

Plasma makes a different choice about what users can reconstruct. The [original Plasma construction](https://plasma.io/plasma.pdf) commits roots of an ordered child-chain history to a parent while users retain the data needed to exit. Validity-proven [generalized Plasma](https://vitalik.eth.limo/general/2024/10/17/futures2.html#generalized-plasma) can prove general state transitions and let a user act from an available proven branch.

Bajillion deliberately discards the payment history as a settlement object. It orders only real conflicts, namely successive sends from one payer and receipts within one component, then authenticates their terminal effects through a payment-specific relation.

### What It Gives Up

That narrower relation buys compression by giving up generality. Bajillion is an account-wide netting protocol, not a general execution environment or a reconstructible payment history.

Its privacy benefit is data minimization: superseded pairs can stay out of ordinary public settlement. Every payment remains known to its payer, recipient, and operator, as well as any watchtower they involve. The persistent chain state contains commitments. The retrievable public corpus reveals the exact changed-account states, each account's terminal outgoing pair when it sent, and each receive component's terminal pair.

For an accepted pair in a conforming close, ordinary disclosure is exact: the pair appears in the public corpus if and only if it is one of those terminals. A holder challenge may reveal a superseded pair later. The public account deltas, receipt counts, and terminal pairs still leak activity, and the protocol provides no anonymity or amount hiding.

The reference deployment binds one asset. Supporting more requires separate deployments or an asset-indexed extension.

No validity mode removes the availability assumptions. The public corpus must stay retrievable, and holders must retain their own evidence through the challenge window. Retained receipts police the close, while recovering custody needs only publicly retained data: the corpus and the survivor state preimage. Enforcement begins at admission, so preconfirmation holders bear operator default until their epoch admits.

Users keep the unilateral withdrawal path, but failure containment is coarse. A proven receipt contradiction or expired withdrawal kills the affected deployment, and terminal unwind needs the complete authenticated survivor state. Users receive no separate enforceable exit object for every payment, route, or account branch. In return, the close nets across counterparties and follows changed account state. General-purpose rollup execution and per-payment channel exits are outside its scope.

## A Bajillion Payments, One Close

The operator still performs $O(T)$ payment work. It verifies $T$ requests, commits $T$ durable updates, and signs $T$ receipts. Public settlement counts something else:

$$
\text{payments }T
\quad\longrightarrow\quad
\text{rows }A+\text{heads }H+\text{frontier }\Phi.
$$

A close must pass complete public validation. An included call that observes an overdue queued withdrawal fences new work. The admitted prefix must still resolve, and terminal unwind requires the complete survivor state.

For repeated activity over a fixed changed-account and component footprint, $(A+H+\Phi)/T\to 0$. Unchanged subtrees cost one frontier digest apiece no matter how many accounts they hold, and receive components keep a hot recipient from becoming a shared online counter. Every changed account and represented component still contributes to the close. Account-level clearing compresses repetition, not change.

Within one operator-backed service and chain custody, and for users recovering from public data alone, these are the trust model's floors. A preconfirmation cannot arrive in less than one round trip to the operator that serializes spending. A close cannot quietly drop a payment: it must agree with every receipt a holder retains, or a single retained pair proves the fault.

Cheap settlement bottoms out at the changed state itself, since no design whose users recover from public data alone can make less available. This close adds only each account's terminal pairs: the outgoing pair when it sent and one per receive component. It also adds the frontier that splices the change into the registry.

Sign every payment. Settle each changed account once.

Bajillion has not yet been peer-reviewed or uploaded to arXiv. The complete formal specification—model, close relation, challenge predicates, settlement transitions, and main theorems—lives in the [Commonware monorepo](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/bajillion/README.md).
