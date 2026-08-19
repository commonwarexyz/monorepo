---
title: "Keep the Change"
description: "Account-level clearing makes millions of tiny payments economical by settling account changes instead of publishing every transaction. At internet scale, digital signatures and Merkle trees make its public settlement cost per payment effectively zero."
date: "August 14th, 2026"
published-time: "2026-08-14T00:00:00Z"
modified-time: "2026-08-14T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

A \$0.000001 payment costs more to settle onchain than it is worth.

More blockspace, bandwidth, and storage let a network carry more payment records. The economic question is whether every payment needs one.

That depends on the guarantee. Direct onchain settlement publishes each payment and gives it public finality. A payment channel keeps enforceable state between two parties and settles only its latest state. A routed channel links those states across a path, with liquidity and claims at every hop. A general-purpose rollup validates arbitrary execution. These designs ask the chain to settle a payment, a channel state, or a general state transition.

At this scale, the payer and recipient can accept an operator's signed preconfirmation now and wait for public finality. The signature gives them evidence they can retain immediately, while finality arrives later as part of a larger close.

Account-level clearing applies that trade within one operator and custody system. It makes the account the unit of settlement. The operator accepts payments throughout an epoch. At close, each changed account contributes one row that commits its exact opening and closing state. Repeated payments over the same set of accounts share those rows even when the pairings differ.

The operator still verifies and durably records every payment. Users trust it for custody and online service. The savings appear in public settlement when many payments reuse the same accounts.

That choice defines the rest of the design. The close must prove exact account changes without replaying a public payment log. A privately delivered receipt must still constrain settlement. Users need a recovery path if the operator stops, and closing one epoch should not halt payments in the next.

The construction starts with the signed evidence for one accepted payment.

## One Signed Payment

An epoch begins from an authenticated account vector and a chain-sealed anchor $\mathcal A_e$, with deposits and user-signed withdrawals fixed before its online payments begin. Suppose account $a$ opens with 100 and wants to pay account $b$ 20. The persistent state $X_a$ of an account is its balance $B_a$, its cumulative debit $D_a$ and operator-promised credit $C_a$, a receipt count, and an activity flag (Appendix B).

To send $x>0$ from $a$ to $b$, the payer signs the exact next debit, and the operator accepts by advancing one epoch-local receive component $\kappa$ from its current tip $(G,J)$:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;a\xrightarrow{\,x\,}b,\;D_a+x\bigr),
\qquad
R=\mathsf{Sign}_{\mathsf{op}}\bigl(\mathcal A_e,\;\kappa,\;x,\;\mathsf{TxId}(S),\;(G+x,\,J+1)\bigr).
$$

$\mathsf{TxId}$ hashes only the canonical request body, so signature bytes never affect it, and a payer-signed $S$ is still only a request until the operator acknowledges it.

That acceptance is transactional. After authenticating $S$ and checking spendability, freshness, and room in the close, the operator atomically commits the debit, the component advance, the close reservation, the replay record, and the receipt body, and only then signs and returns $R$.

The matching pair $(S,R)$ is the accepted payment. The payer verifies and retains it, then forwards it to the recipient. Rejection before the commit changes nothing, and until the payer sends again, an exact retry of a lost response returns the same pair without a second debit.

Figures 1–5 use one registry with $N=8$ positions. Figure 1 begins with $a$ at 100, $b$ at 40, and the payment $a\xrightarrow{20}b$.

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

Because the operator commits state before signing, every accepted debit is already counted in the payer's live balance. A recipient can spend incoming credit only after importing the authenticated component tip that contains it. A delayed import may understate spendable balance, but cannot overstate it.

Compression comes from cumulative totals. The close carries each payer's final debit and the final credit and receipt count for each receive component. Intermediate payments can be omitted.

## One Exact Account Close

A single incoming counter would serialize every payment to a popular recipient. The operator instead scopes each receive component by $(\mathcal A_e,b,\kappa)$. A payment of $x$ assigned to component $\kappa$ advances only that component's running credit and receipt count:

$$
(G_\kappa,J_\kappa)\longrightarrow(G_\kappa+x,J_\kappa+1),
\qquad
(G_{\kappa'},J_{\kappa'})\text{ unchanged for every }\kappa'\ne\kappa.
$$

Payments assigned to different components therefore do not contend on the same counter.

A recipient still has one account balance. Components exist only as epoch-local concurrency domains feeding that balance. At close, one terminal signed pair represents each component, no matter how many payments advanced it.

In the same ledger, accounts $(a,b,c,d)$ open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

Their exact closing balances are $(85,58,26,31)$ and total payment debit equals total payment credit at 54.

For recipient $b$, sort the terminal records by component identifier and commit them under $\mathsf{HeadRoot}_e(b)$. The root binds the exact component count, ordered records, total credit, and total receipt count. In the running example, $b$'s three heads end at $(20,1)$, $(4,1)$, and $(6,1)$, so the root summary is $(h_b,G_b,J_b)=(3,30,3)$.

The account row is the unit of public settlement. Write opening and closing states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$.

If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Each row binds both account states, the terminal outgoing pair $\mathsf{Out}_a$ when the account sent, its $\mathsf{HeadRoot}$, and the aggregate prefixes needed for conservation:

$$
\mathsf{Row}_a=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;\mathsf{HeadRoot}_e(a),\;\mathsf{prefix}_a\bigr).
$$

The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes.

The $A$ rows form a length-bound $\mathsf{ChangeRoot}$, which authenticates the compact change vector. The paired sparse witness below uses that vector to derive the new account-state root.

The paired sparse witness reconstructs the opening and closing roots together over the row positions $\mathcal J_e$: each row supplies its opening and closing leaf, and every omitted subtree contributes one authenticated digest to both sides, collected as the sparse frontier $\Phi_e$. Successful verification proves every omitted position unchanged and every row position changed to exactly its committed close, so an account changes if and only if it has a row.

The settlement chain retains a header $\mathsf{Header}_e$ containing the opening $\mathsf{StateRoot}_e$, $\mathsf{ChangeRoot}_e$, and closing $\mathsf{StateRoot}_{e+1}$, together with the quorum certificate. Admission also receives the terminal changed row and its Merkle opening, authenticates the row against $\mathsf{ChangeRoot}_e$, checks its aggregate prefixes, and retains none of it. A $\mathsf{StateRoot}$ commits every field in the complete account-state vector $X$. The component vectors, remaining changed rows, and paired exact-update witness stay outside the chain payload as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$. Appendix D tabulates the evidence lifetimes.

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

Here $\hookrightarrow$ places the head root inside $\mathsf{Row}_b$. The row vector also drives the full-state update:

$$
\underbrace{\mathsf{StateRoot}_e}_{\mathsf{Commit}(X^0)}
\xrightarrow[\displaystyle
  k\notin\mathcal J_e\Rightarrow X_k^1=X_k^0]
{\displaystyle \mathbf A_e,\,\Phi_e}
\underbrace{\mathsf{StateRoot}_{e+1}}_{\mathsf{Commit}(X^1)}.
$$

::: {.image-caption}
Figure 2: The first derivation builds $\mathsf{ChangeRoot}_e$ from terminal component heads, each committed as its terminal signed pair and shown here by that pair's marker, and exact changed-account rows. The second uses those rows and sparse frontier $\Phi_e$ to transform the opening full-state commitment into the closing one while proving every omitted position unchanged.
:::

Write $T$ for accepted payments, $A$ for changed-account rows, $H=H_e=\sum_a h_a$ for terminal receive-component heads, $\Phi=|\Phi_e|$ for sparse-frontier hashes, and $N$ for registered account positions.

$H$ is the price of receive concurrency. More components remove online contention but enlarge the close. The protocol therefore caps both the number of terminal components and the close size independently of $T$. A payment is accepted only when the operator can reuse a component or reserve room for a new one without exceeding either cap.

## Validate Before Admission

Admission fully validates the public close before it becomes pending, rejecting anything malformed or inexact. Challenges cover contradictions among operator-signed receipts, whether retained privately or drawn from the disclosed corpus.

For sorted rows, the authenticated prefixes telescope to total debit $D_e$, credit $C_e$, deposits $F_e$, and withdrawals $W_e$. Those totals must reproduce the chain-sealed boundary, respect the close caps, and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

This is typed conservation. Deposits and withdrawals come from the chain-sealed boundary. Debits and credits come from signed cumulative debit and credit markers. Equal totals do not let one type impersonate another.

The reference deployment partitions the public corpus into deterministic, exhaustive account intervals. Every certificate signer signs the same header, and each evidence piece is assigned to a quorum of validators who check and retain it. Quorum intersection guarantees that an honest signer checked and retains each piece: at the reference parameters of 100 validators, 33 tolerated faults, and quorum 67, every piece's holders share at least 34 validators with the certificate.

The honest signer may differ by piece. Together, the identical header, exhaustive assignment, and quorum intersection attest to the complete public relation, which byte availability alone would not. Admission appends the close as a pending slot without changing custody or the finalized root, while registration has already sealed the epoch's boundary and opened the next. Only an unchallenged queue front can install its root and release its withdrawals:

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

Here $\alpha_e<\Delta_e$. The chain may pipeline a bounded number $K$ of consecutive pending slots, but only the front can finalize. This preserves one state lineage even when a later slot's challenge window closes first.

## The One Fact Validation Cannot See

Under the selected mode's validity assumptions, validation establishes that the exact bound corpus satisfies the public relation. It cannot prove that the corpus contains every receipt the operator signed and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator signs exactly the receipts represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid receipt $R^+$. The admission verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. The argument is independent of whether $\zeta$ is a quorum certificate, a zero-knowledge proof, or a TEE attestation. Each can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

Through the inclusive deadline $t\le\Delta_e$, any holder or watchtower may submit one of four bounded contradictions:

1. **Payer debit contradiction.** A matching acknowledged pair carries a debit above the public debit marker, or the same debit with a different send or receipt body. A bare payer request is insufficient. The receipt proves operator acknowledgement.

2. **Higher receive-component tip.** Authenticate the public tip $(G^\star,J^\star)$ for one component, using $(0,0)$ for authenticated absence, and present a matching retained receipt at $(G^+,J^+)$. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Inconsistent receipt range.** For linked lower and upper pairs in one anchor, recipient, and component, adjacent receipts must increase credit by exactly the upper payment, and an index gap must leave at least one unit for each omitted positive payment. A violation is a contradiction.

4. **Receipt fork.** Two distinct linked receipt bodies either reuse one receipt index within a component or acknowledge the same payer transaction differently. Different signature bytes over one identical receipt body are not a fork.

Appendix E gives the exact checked-arithmetic and fork predicates.

The higher-tip challenge below combines three sources. The settlement chain already has the admitted header and its $\mathsf{ChangeRoot}$. The availability service supplies the authenticated account and component lookups needed to open $b$ and then $\kappa_0$. The recipient supplies the signed pair it retained privately. Those lookups and that pair become one bounded onchain challenge call.

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

The challenge call resolves the two authenticated lookups in sequence:

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

Boundary omissions do not need a fifth challenge. Deposits and withdrawals were serialized by the settlement chain before the epoch, so wrong roots, totals, signatures, or account effects are public registration or admission failures.

A successful receipt challenge prevents the challenged slot and every admitted descendant from finalizing. Earlier admitted slots keep their ordinary challenge windows and may still finalize in order. The challenge itself provides neither reimbursement nor slashing. Collateral, insurance, and repair allocation are deployment policy.

## A Deadline to Exit

Blocking a contradicted close matters only if users can still recover custody. The exit path begins with chain-sealed deposits and signed withdrawals.

A deposit has no deadline. A finalized deposit immediately raises custody, its record enters the next boundary that admits it, and if terminal unwind begins before that boundary's slot finalizes, the deposit returns in the terminal payout. A stalled deposit alone can neither trigger deployment unwind nor claim a bounded exit.

A withdrawal is signed against an existing finalized root $\mathsf{rt}_z$ and names no future epoch or anchor:

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;x,\;\gamma,\;\tau\bigr),
$$

with an eligible destination $v$, amount $x$, full-close flag $\gamma$, and absolute deadline $\tau$. Queueing is a direct, permissionless chain call: the operator neither submits nor approves it, and operator cooperation decides only whether the withdrawal settles through a clean close or through terminal unwind.

If the admitted pipeline extends $\mathsf{rt}_z$ through $\mathsf{rt}_\ell$, where $\ell-z\le K$, queueing must prove the withdrawal affordable at each of those roots, and every later admission that does not carry it re-proves it at the new root, so every possible survivor root is covered. A full close must exhaust the balance at the pipeline tail, and the deadline must leave the configured notice $\eta>0$ after queueing. Queueing changes neither custody nor a state root. Clean front finalization atomically releases withdrawals, consumes deposits, advances the finalized root, and decrements custody.

Appendix F gives the complete queueing and terminal-payout predicates.

Let $E$ be current custody. For admitted slots $z+1,\ldots,\ell$, let $F_i$ be the unfinalized deposits carried by slot $i$, and let $F_\star$ contain the deposits not yet carried by an admitted slot. Custody can be read either from finalized liability or from the pipeline tail:

$$
\boxed{
E=L_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+\sum_{i=z+1}^{\ell}W_i+F_\star.
}
$$

Withdrawals remain inside custody until their own slot reaches the front and finalizes. This is why admission can be pipelined without letting a speculative descendant spend assets out from under an ancestor.

The signed deadline $\tau$ is a fence, not a payout promise. If an included valid call observes an unreleased $Q$ at $t\ge\tau$, it permanently blocks new work but does not erase already-admitted slots. Those slots remain challengeable and resolve from the front in order. Only an unadmitted registration is discarded.

A pure timeout unwinds only after every admitted slot resolves, while a successful challenge cuts the pipeline at the faulted slot and unwinds once every clean slot ahead of it resolves in order. Terminal unwind then authenticates the complete $N$-account state vector at the surviving finalized root, pays each signed withdrawal, and returns each residual balance together with any deposit never consumed by a surviving slot.

The canonical payout must sum to $E$. One atomic transition then pays it, zeroes custody and liability, consumes every remaining record, and makes the deployment permanently unwound.

Recovery is unilateral but deliberately coarse. One expired withdrawal kills the affected deployment. Terminal unwind requires an $O(N)$ scan of the complete survivor state. In the reference path, aggregating a dense invalid suffix can raise worst-case work to $O(KN\log(N+1))$ and retained boundary data to $O(KN)$. The guarantee also depends on inclusion of valid timeout, finalization, and unwind calls and availability of that complete state preimage.

## Close Without Pausing Payments

Closing an epoch is asynchronous. Spending continues while the final payer debit markers and receive-component tips are authenticated and admitted. Otherwise, account-level compression would create a throughput cliff at every epoch boundary.

Rollover happens independently for each payer. Before an account can send in epoch $e+1$, its final epoch-$e$ debit marker and preserved spendable balance are fixed. Accounts that do not send are fixed when the predecessor epoch seals.

The key invariant applies immediately before any successor deposit or withdrawal is applied. Let $\widetilde B_a$ be the preserved guarded balance after every accepted predecessor debit and every predecessor credit already imported for spending. Let $B_a^1$ be the exact predecessor closing balance. Then

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad \rho_a\ge0,}
$$

where $\rho_a$ is the total unimported predecessor credit. The live head is the payer's safe spendable balance. The authenticated predecessor close is computed separately.

Because successor debits continue on the same head, reconciliation adds $\rho_a$ to the live value. Assigning $B_a^1$ over it would erase those debits. In the running example, $a\xrightarrow{20}b$ leaves the preserved head at 80 while the not-yet-imported $d\xrightarrow{5}a$ credit makes the exact predecessor close 85. If $a$ spends 20 and then 15 in the successor while the missing credit arrives between them,

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

Successor boundary operations and shard moves must preserve the same rule: the live head is only ever adjusted, never overwritten. Appendix G gives the one-time application and authenticated-snapshot conditions.

Rollover changes only live serving state. The ordinary close still produces the canonical rows, state root, and public corpus, which go through the same validity and admission checks. A challenge against the predecessor invalidates its admitted descendants.

## The Close Never Grows with Payments

The asymptotics say what stops growing. A controlled benchmark shows what still costs time.

Each profile below fixes $N=1{,}000{,}000$ registered accounts, 512 credited accounts, 256 deterministic pieces, a 100-validator committee with quorum 67, and an eight-thread worker pool. Every changed account sends. The same 512 accounts receive in every profile, evenly spaced among the accounts that change. The matrix independently varies $A$, the number of changed accounts, and $h$, the number of component heads on each credited account. No payment count appears because none is needed: rows and heads carry fixed-width cumulative totals, so every size in the table is the same for any $T$.

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

Increasing $A$ makes the state transition dense. Increasing $h$ concentrates more authenticated component leaves and signatures behind each credited row. Neither disappears behind the phrase “one row per account.” All four profiles register the same million accounts, yet at $A=1{,}024$ the validator's assignment is 1.39 MB: distribution follows the changed rows and the shared frontier, not the registry, so it is sublinear in registered accounts as well as in payments. The corpus is a constant of the footprint, so accepted payments only divide it: ten million spread the sparse profile's 2.07 MB to about 0.2 bytes of public settlement each, and a billion would leave 0.002. The chain payload remains nearly flat because it carries the header, quorum certificate, and terminal prefix opening—not the rows or component leaves. This fixture queues no withdrawals and no full closes, whose re-check and row openings would otherwise add to it. The challenge rows submit one proven higher-tip challenge: its payload grows only with the two lookup depths, and its check verifies two signatures and two openings.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Log-log plot of public corpus bytes per accepted payment against payments accepted in the epoch, from one million to one billion payments, with four lines for the four table profiles. With 1,024 changed accounts, one head per credited account falls from about 2 bytes per payment to 0.002, and 512 heads from 117 to 0.12. With one million changed accounts the two head counts nearly coincide, falling from about 649 and 764 bytes to 0.65 and 0.76. Each line is its profile's constant corpus divided by the payment count.">
```

::: {.image-caption}
Bytes-per-payment chart: fixed-width rows keep each profile's corpus constant in $T$, so each line is that profile's corpus from the table over the payment count and falls exactly as $1/T$. The two $A=1{,}000{,}000$ lines nearly coincide because heads move that corpus by only $1.2\times$, while at $A=1{,}024$ they separate it by $57\times$.
:::

The timers cover warm, in-memory close construction and validation on an 18-core Apple M5 Pro with 64 GiB, with the shared worker pool capped at eight threads. They exclude payment acceptance, networking, durable storage, key and registry construction, and custody execution. Canonical encoding for hashing and signature verification remains included. Corpus bytes count each of the 256 pieces once, before replication to its 67 holders, the validator rows report the busiest of the 100 assignments with its share of the public corpus in parentheses, and the challenge rows target a mid-registry credited account's mid-set component. The timers ran under a ten-million-payment build of each fixture. The sizes hold for any payment count: re-building each fixture at payment counts from ten thousand (one million where all accounts change) up to ten million reproduced every size in the table, with the corpus and chain payloads identical to the byte.

## The Account-Level Trade

Payment channels attack the same economic problem with a different settlement boundary. A bilateral channel compresses repeated transfers between two parties while preserving bilateral self-custody. A routed network such as the one in the [original Lightning paper](https://lightning.network/lightning-network-paper.pdf) extends that guarantee across a path, which means reserving directional liquidity and individually enforceable timed state at every hop. This construction instead trusts one operator and custody system during normal operation, then nets every sender and recipient under one account-wide close. It has no routed-hop state: the close carries only the terminal head of each receive component used, and the deployment chooses how payments map into those bounded concurrency domains.

That broader netting boundary is why a cycle can be cheap. If $a\to b$, $b\to c$, and $c\to a$ repeat 100,000 times, the epoch contains $T=300{,}000$ payments but only $A=3$ changed accounts. With one component per recipient, it also has $H=3$. Gross debit still equals gross credit, but the public close carries three rows, three heads, and their sparse frontier rather than 300,000 payment records.

Plasma makes a different choice about what users can reconstruct. The [original Plasma construction](https://plasma.io/plasma.pdf) commits roots of an ordered child-chain history to a parent while users retain the data needed to exit. Validity-proven [generalized Plasma](https://vitalik.eth.limo/general/2024/10/17/futures2.html#generalized-plasma) can prove general state transitions and let a user act from an available proven branch. This design deliberately discards the payment history as a settlement object. It orders only real conflicts—successive sends from one payer and receipts within one component—then authenticates their terminal effects through a payment-specific relation.

That narrower relation buys compression by giving up generality. The result is an account-wide netting protocol. Arbitrary execution and reconstructible payment history are outside its scope. Its privacy benefit is data minimization: superseded pairs can stay out of ordinary public settlement. Every payment remains known to its payer, recipient, and operator, as well as any watchtower they involve. The persistent chain state contains commitments, while the retrievable public corpus reveals the exact changed-account states, each account's terminal outgoing pair when it sent, and each receive component's terminal pair. For an accepted pair in a conforming close, ordinary disclosure is therefore exact: the pair appears in the public corpus when and only when it is one of those terminals. A holder challenge may reveal a superseded pair later, and the public account deltas, receipt counts, and terminal pairs still leak activity. The protocol provides no anonymity, amount hiding, or privacy from the operator and counterparties.

The reference deployment binds one asset. Supporting more requires separate deployments or an asset-indexed extension.

No validity mode removes the availability assumptions: the public corpus must stay retrievable and holders must retain their own evidence through the challenge window.

A user retains a unilateral path: queue a signed withdrawal, prove that it is affordable at the finalized root and every admitted successor, and permanently fence new work if it remains unreleased at its deadline. But failure containment is coarse. A proven receipt contradiction or expired withdrawal kills the affected deployment, and terminal unwind needs the complete authenticated survivor state. Users receive no separate enforceable exit object for every payment, route, or account branch.

The normal path relies on operator custody, and exceptional failures affect the entire deployment. In return, the close nets across counterparties and follows changed account state. General-purpose rollup execution and per-payment channel exits are outside its scope.

## Sublinear Payments

The operator still performs $O(T)$ payment work: it verifies $T$ requests, commits $T$ durable updates, and signs $T$ receipts. The public settlement record follows a different quantity:

$$
\text{payments }T
\quad\longrightarrow\quad
\text{rows }A+\text{heads }H+\text{frontier }\Phi.
$$

Admission validates the complete public close. The challenge window covers what no validity mode can establish: that the operator's signed receipts, disclosed or not, contain no contradiction. Holders retain the signed evidence needed to expose a concrete contradiction. An included call that observes an overdue queued withdrawal fences new work. The admitted prefix must still resolve, and terminal unwind requires the complete survivor state.

For repeated activity over a fixed changed-account and component footprint, $(A+H+\Phi)/T\to 0$. Unchanged subtrees cost one frontier digest apiece no matter how many accounts they hold, and receive components keep a hot recipient from becoming a shared online counter. Every changed account and represented component still contributes to the close. Account-level clearing compresses repetition, not change.

Sign every payment. Settle each changed account once.

The construction has not yet been peer-reviewed or uploaded to arXiv.

## Appendix: Formal Specification

- **A.** Model: participants, timing, cryptographic primitives, and the adversary.
- **B.** Deployment, registry, boundaries, and chain state.
- **C.** Payments: sends, receipts, acceptance, and import.
- **D.** The epoch close, its certification, and availability.
- **E.** Receipt challenges: the four predicates, soundness, and completeness.
- **F.** Settlement-chain transitions, exit, and terminal unwind.
- **G.** Overlapped epochs and rollover.
- **H.** Assumptions, security properties, and the main theorems.

Deployment creation opens the first boundary once. Every epoch then runs the same lifecycle, and adjacent epochs overlap: registration seals epoch $e$'s boundary, starts its service, and opens epoch $e+1$'s boundary, so each epoch collects while its predecessor serves and serves while its predecessor closes and settles.

$$
\begin{aligned}
&\mathsf{Open}_e
\xrightarrow{\mathsf{seal+register}}
\mathsf{Serving}_e
\xrightarrow{\mathsf{close+certify+admit}}
\mathsf{Pending}_e,\\[0.3em]
&\mathsf{Pending}_e
\begin{cases}
\xrightarrow[\ t>\Delta_e]{\mathsf{unchallenged\ queue\ front}}
\mathsf{Finalized}_e,\\[0.5em]
\xrightarrow[\ t\le\Delta_e]{\mathsf{valid\ receipt\ challenge}}
\mathsf{Faulted}
\xrightarrow{\mathsf{resolve\ admitted\ prefix}}
\mathsf{Unwound}.
\end{cases}
\end{aligned}
$$

- **Open.** The epoch's boundary collects deposit and withdrawal records on the settlement chain while its predecessor serves (Section B.3).
- **Serving.** Registration seals that boundary into the epoch's anchor $\mathcal A_e$ and opens its successor's (Section B.4). While the registration is outstanding, the operator accepts the epoch's payments (Section C), fixes the terminal markers at the hard seal (Section G), and builds and certifies the close (Section D). A registration never admitted expires at $t>\Delta_e$, returning its records to the open boundary (Section F.1).
- **Pending.** Admission verifies the close's validity and availability evidence at $t\le\alpha_e$ and appends it as an admitted, unfinalized slot (Section F.1). Through $t\le\Delta_e$, any holder may submit a receipt challenge against it (Section E).
- **Finalized.** An unchallenged slot that reaches the queue front finalizes once its window closes: the closing root installs, withdrawals release, and deposits consume (Section F.1).
- **Faulted and Unwound.** A valid challenge, or an overdue withdrawal observed from any stage, permanently faults the deployment. Earlier admitted slots keep their windows and resolve from the front, and once the front reaches the fault cut, terminal unwind pays the complete survivor state and zeroes custody (Sections F.3 and F.4).

### A. Model

#### A.1 Participants

An **account** is a public-key identity registered with one deployment. An account may act as payer, recipient, or both.

The **operator** is a single logical server. It serves online payments, maintains mutable execution state, signs receipts, and constructs each epoch close. The protocol trusts the operator for custody and service during normal operation and for nothing at settlement.

The **settlement chain** is an append-only state machine trusted for safety and liveness. It is authoritative for the account registry, custody, epoch boundaries, committed roots, deadlines, and transition order. It exposes a monotone authenticated time $t$, and it executes each included call atomically: a call either performs its complete effect or leaves state unchanged. Every transition of Section F is permissionless: any party that supplies the required inputs may invoke it. The chain's own consensus is outside this model.

A **deployment** is one settlement-chain instance of the protocol. It binds an immutable profile $\Pi$ (Section B.1), a registry, an operator key, and an asset adapter, and it owns custody $E$, the slot pipeline, and a lifecycle flag among live, faulted, and unwound.

A **validity checker** certifies the public close relation of Section D. Depending on the deployment's mode it is a committee of $n_{\mathsf{val}}=3f_{\mathsf{val}}+1$ validators of which at most $f_{\mathsf{val}}$ are faulty, a proof system for the relation, or a trusted execution environment (TEE).

The **availability service** stores the public close data and answers authenticated lookups, under the obligations of Definition D.5.

A **holder** is any party retaining signed protocol evidence: payers, recipients, and any watchtower they share evidence with. Holders submit the challenges of Section E.

#### A.2 Time and inclusion

All deadlines are values of chain time $t$. The model has one inclusion parameter $\delta_{\mathsf{incl}}$: a valid call submitted by an honest party at time $t$ is included and executed by $t+\delta_{\mathsf{incl}}$. Operator liveness is never assumed. Every guarantee for holders is stated against an operator that may stop or misbehave at any point.

#### A.3 Cryptographic primitives

The deployment profile fixes a signature scheme, a hash family, and a commitment scheme, all used with strict canonical encoding: every signed or hashed object has exactly one valid byte encoding, decoding rejects any other bytes, and all protocol arithmetic is checked in profile-fixed integer domains, with overflow treated as failure. Security statements hold except with probability negligible in the profile's security parameter.

**Assumption SIG.** The signature scheme is existentially unforgeable under chosen-message attack. Verification is a deterministic predicate over canonical encodings. Distinct signature bytes over one identical body carry no protocol meaning: every rule below keys on canonical bodies, never on signature bytes.

**Assumption CR.** The hash family is collision-resistant, and every use is domain-separated by purpose.

**Definition A.1 (authenticated vector).** An authenticated vector scheme commits a context string and an ordered vector $v=(v_0,\ldots,v_{m-1})$ to a digest $\mathsf{root}=\mathsf{Commit}(\mathsf{ctx},v)$ and supports four proof kinds:

1. **Membership.** A proof that position $k$ of the committed vector holds value $v_k$.
2. **Ordered absence.** For a vector whose entries are strictly ordered by a key, a proof that no entry has key $x$, given by the adjacent committed entries or vector ends that bracket $x$.
3. **Aggregate.** When entries carry an additive summary, the root binds the exact vector total of that summary.
4. **Length.** The root binds the exact length $m$.

**Assumption BIND.** No feasible adversary produces a root together with two accepting proofs of contradictory statements: two memberships at one position with different values, a membership and an absence for one key, two aggregate totals, or two lengths. A domain-separated Merkle tree over canonical leaf encodings, with leaf and internal nodes separated by domain and with the length and additive summary bound into every node, satisfies this under Assumption CR, and its internal digests bind their subtree's contents, positions, and height.

The paired opening below is defined over that Merkle instantiation, whose subtree digests carry the binding just stated.

**Definition A.2 (paired sparse opening).** Fix two roots $\mathsf{root}^0,\mathsf{root}^1$ over one context and length $m$, a strictly ordered position set $\mathcal J\subseteq\{0,\ldots,m-1\}$, claimed value pairs $(u_k^0,u_k^1)$ for $k\in\mathcal J$, and a frontier $\Phi$: the vector holding one digest for each maximal subtree that contains no position of $\mathcal J$, in canonical order. The opening verifies when recomputing both roots from the claimed values and the **same** frontier digests on both sides succeeds, and $u_k^0\ne u_k^1$ for every $k\in\mathcal J$.

**Lemma A.1 (exact difference).** Under Assumption BIND, if a paired sparse opening verifies for $(\mathsf{root}^0,\mathsf{root}^1,\mathcal J,\{u_k^0,u_k^1\},\Phi)$ and $\mathsf{root}^0=\mathsf{Commit}(\mathsf{ctx},v^0)$, then $\mathsf{root}^1$ commits exactly one vector $v^1$, and

$$
v^1_k=
\begin{cases}
u^1_k\ne v^0_k,&k\in\mathcal J,\\
v^0_k,&k\notin\mathcal J.
\end{cases}
$$

*Proof.* The recomputation of $\mathsf{root}^0$ is a membership proof of $u_k^0$ at each $k\in\mathcal J$, so $u_k^0=v_k^0$ by Assumption BIND. The recomputation of $\mathsf{root}^1$ authenticates a vector that holds $u_k^1$ at each $k\in\mathcal J$ and, over every omitted subtree, the same digest that authenticates $v^0$ there. Because subtree digests bind contents, positions, and height, a vector committed by $\mathsf{root}^1$ that differed from $v^0$ at an omitted position would open that shared digest to two different subvectors, contradicting Assumption BIND. The inequality checks give $v^1_k\ne v^0_k$ on $\mathcal J$. $\square$

#### A.4 Adversary and scope

The adversary controls the operator, any subset of accounts, and at most $f_{\mathsf{val}}$ validators in quorum mode, all statically corrupted, and it schedules message delivery on the user-operator channels, which are asynchronous and lossy. It cannot break Assumptions SIG, CR, or BIND, corrupt the settlement chain, or delay an honest call beyond $\delta_{\mathsf{incl}}$. Guarantees for a specific honest party additionally require that party to follow its own discipline (Definition E.2) and the availability obligations to hold (Definition D.5). Denial of payment service by the operator is outside the guarantees: the remedy for a censored account is exit (Section F), not service. The protocol provides no anonymity or amount privacy, binds one asset per deployment, and assigns blame without compensation: a proven fault stops settlement and unwinds custody, and reimbursement beyond the unwind payout is deployment policy.

### B. Deployment and chain state

#### B.1 Deployment profile

Fix one deployment and one asset. Asset amounts are nonnegative integers. The immutable profile $\Pi$ fixes the canonical encodings, signature and hash schemes, domain-separation tags, checked arithmetic domains, a totally ordered component-identifier domain, an asset adapter, a total order on account identities, a canonical asset-layer destination for every registrable account identity, and the resource limits $\Lambda$, including the terminal-component cap $H_{\max}$, a payment-row cap $A_{\max}\le N$, a per-boundary deposit quota $F_{\mathsf{cap}}$, and bounds on every decoded input and on per-call work. The asset adapter authenticates finalized inbound transfers, validates destinations, and executes outbound transfers, and every destination it accepts, including each identity's canonical destination, is assumed payable. Different profiles are different deployments. Inputs are strictly decoded and length-checked before allocation, and a failed precondition leaves state unchanged. We write $\bot$ for absence.

#### B.2 Registry and account state

The registry is the ordered vector of $N$ account identities $\mathcal R=(a_0,\ldots,a_{N-1})$ with $a_0<\cdots<a_{N-1}$, committed as an authenticated vector under $\mathsf{RegistryRoot}$. $\mathsf{pos}(a)$ is the registry position of $a$.

Each account has persistent state

$$
X_a=(B_a,D_a,C_a,i_a,\mathit{active}_a),
$$

where $B_a$ is balance, $D_a$ is cumulative debit, $C_a$ is cumulative operator-promised credit, $i_a$ counts operator-promised receipts, and $\mathit{active}_a$ gates participation. An inactive account has zero balance and can neither send nor receive payments. Boundary deposits may still target it and reactivate it (Definition D.1). $\mathsf{StateRoot}$ commits the registry-aligned authenticated vector $\mathbf S=((a_0,X_{a_0}),\ldots,(a_{N-1},X_{a_{N-1}}))$ with the balance sum as its bound aggregate. Superscripts $X_a^0,X_a^1$ and $\mathbf S_k^0,\mathbf S_k^1$ denote opening and closing values for one epoch.

#### B.3 Chain state, pipeline, and boundaries

The settlement chain tracks custody $E$, the asset units the adapter holds for the deployment, and an ordered pipeline of slots. Write $\mathsf{rt}_i$ for the account-state root installed by slot $i$ and $L_i$ for the balance sum bound by $\mathsf{rt}_i$. Let $z$ index the latest finalized slot, so $(\mathsf{rt}_z,L_z)$ is the finalized root and liability. Slots $z+1,\ldots,\ell$ may be admitted but unfinalized, at most $K$ at once. Slot $i$ carries the deposit and withdrawal totals $(F_i,W_i)$ of the boundary it consumed, and $L_i=L_{i-1}+F_i-W_i$. Only the front slot $z+1$ may finalize. Slot indices are assigned at admission, in registration order.

While the deployment is live, exactly one **open boundary** collects deposit and withdrawal records. Registration seals the open boundary for the registering epoch and opens the next, so collection never pauses. A **deposit record** binds a unique identifier, an external source, a registered account, and a positive amount. It is **unconsumed** from acceptance until the slot that carries it finalizes, which consumes it, or until terminal unwind, which returns it through the terminal payout (Section F.4). **Withdrawal records** are defined in Section F.

Within one boundary an account never carries both kinds of record, and at most $F_{\mathsf{cap}}$ deposit records enter one boundary. Every record movement maintains this: a deposit that would join a boundary holding the account's withdrawal record, or exceed the quota, is instead **held** and assigned to the next boundary that admits it, queueing a withdrawal re-holds the account's deposit records out of the open boundary, and the expiration merge of Section F re-applies the same rules. Withdrawal records always enter the open boundary and are never held or capped, so nothing can crowd out an exit, and one unreleased withdrawal per account bounds them by $N$.

At creation the deployment commits the genesis vector, every account inactive with all-zero state, so $\mathsf{rt}_0$ binds $L_0=0$, custody is zero, the pipeline is empty, one boundary is open, and epochs number from one. A first deposit activates its account (Definition D.1). The registry is fixed at creation, and changing it is outside this specification.

$F_\star$ denotes the total of all accepted deposits not yet carried by an admitted slot, whether held, in the open boundary, or in a sealed boundary awaiting admission. For account $a$ and one epoch, $f_a$ and $w_a$ are its per-account deposit and withdrawal amounts, equal to the sealed records except a full close's exhausting $w_a$ (Definition D.1), with totals $F_e=\sum_a f_a$ and $W_e=\sum_a w_a$, and $M_e$ counts the boundary's withdrawal records, including a zero-amount full close.

#### B.4 Registration

Before epoch $e$ accepts payments, the chain registers the anchor

$$
\mathcal A_e=\bigl(
\mathsf{deployment},e,\mathsf{RegistryRoot},\mathsf{operatorKey},
\mathsf{Boundary}_e,\mathsf{ValidityConfig}_e,
\alpha_e,\Delta_e,\Pi\bigr),
\qquad
\alpha_e<\Delta_e,
$$

with identifier $\mathsf{AnchorId}_e=\mathcal H_{\mathsf{anchor}}(\mathcal A_e)$. Registration seals the open boundary into $\mathsf{Boundary}_e=(\mathsf{Deposits}_e,\mathsf{Withdrawals}_e)$ and opens a fresh boundary. $\mathsf{operatorKey}$ verifies receipts, and $\mathsf{ValidityConfig}_e$ fixes the validity mode, availability assignment, and resource limits for the epoch. Registration binds no state root: the epoch's opening root is fixed at admission, where the chain checks lineage against the pipeline tail. The operator serves epoch $e$ against the newest state its close can admit on top of: the closing state it proposed for epoch $e-1$ in normal operation, or the pipeline tail $\mathsf{rt}_\ell$ at $e=1$ and after an expiration cascade, re-initializing live serving state per Section B.5. The expiration rule of Section F keeps a dropped predecessor's successor from admitting against anything else. Epochs register in order, at most two registrations may be outstanding at once, and registration requires $t\le\alpha_e$, a live deployment, pipeline capacity, and no doomed registration outstanding. Allowing a second outstanding registration is what lets a successor epoch begin service while its predecessor is closed, certified, and admitted (Section G). Every send, receipt, close, lookup, and challenge for epoch $e$ is scoped to $\mathcal A_e$. Because admission also requires $t\le\alpha_e$, the epoch's execution, close, and certification must all fit between its registration and $\alpha_e$. The profile's schedule must also keep admission feasible under a full pipeline: $\alpha_e$ must exceed the challenge deadline of the slot whose finalization frees the epoch's capacity, so at $K=1$, $\alpha_{e+1}>\Delta_e$ for every $e$.

#### B.5 Live serving state

Between committed snapshots the operator maintains mutable serving state per account: a live balance $B_a^{\mathsf{live}}$ and live debit $D_a^{\mathsf{live}}$ used to accept payments, receive-component markers, and imported-credit markers (Section C). Without an overlapped predecessor, the sealed boundary initializes $B_a^{\mathsf{live}}=B_a^0+f_a-w_a$ and $D_a^{\mathsf{live}}=D_a^0$ exactly once before the account's first payment of the epoch, and sets serving activity to $u_a$ (Definition D.1 item 3). Here a sealed full close contributes its signed amount and freezes the account in both directions (Section G, rule 3), leaving the exhausting sweep to the close. Section G gives the equivalent rule when epochs overlap. Live state is serving state only: settlement commits the snapshots of Section D, never the live values.

#### B.6 Symbols

| Symbol | Meaning |
|:--|:--|
| $N$, $T$ | registered account positions, payments accepted in the epoch |
| $A$, $A_{\max}$ | changed-account rows in the close, and the payment-row cap |
| $F_{\mathsf{cap}}$, $\beta_e$ | per-boundary deposit quota, accounts with sealed records in $\mathsf{Boundary}_e$ |
| $h_a$, $H_e$, $H_{\max}$ | terminal receive components of $a$, their sum, and its cap |
| $\kappa$, $(G,J)$ | receive-component identifier, and its credit and receipt-count marker |
| $D_e$, $C_e$, $F_e$, $W_e$, $M_e$ | epoch totals of debit, credit, deposits, withdrawals, and withdrawal records |
| $\mathcal J_e$, $\mathcal D_e$ | changed registry positions, and the public corpus |
| $\Phi_e$ | shared sparse frontier of the paired opening |
| $K$ | maximum admitted, unfinalized slots |
| $\mathsf{rt}_i$, $z$, $\ell$ | root installed by slot $i$, and the finalized and tail pipeline indices |
| $E$, $L_i$ | custody, and liability under $\mathsf{rt}_i$ |
| $F_i$, $W_i$, $F_\star$ | slot deposit and withdrawal totals, unadmitted deposits |
| $c_\star$, $\ell_{\mathsf{fault}}$ | fault cut, and the tail frozen at fault |
| $\alpha_e$, $\Delta_e$ | inclusive registration-and-admission cutoff, inclusive challenge deadline |
| $\tau$, $\eta$ | withdrawal deadline, minimum notice |
| $\lambda_{\mathsf{DA}}$, $\delta_{\mathsf{incl}}$ | availability-recovery allowance, inclusion bound |

### C. Payments

#### C.1 Sends and receipts

**Definition C.1 (send).** To pay $x>0$ from $a$ to $b$, the payer signs the exact next cumulative debit:

$$
s=(\mathcal A_e,a,b,x,D',e),\qquad
S=(s,\sigma_a),\qquad
D'=D_a^{\mathsf{live}}+x,\qquad
\mathsf{TxId}(s)=\mathcal H_{\mathsf{txid}}(s).
$$

$\mathsf{TxId}$ hashes the canonical send body only, so signature bytes never affect it, and injective encoding makes it collision-free across distinct bodies under Assumption CR.

The operator assigns each accepted payment to one epoch-local **receive component** $\kappa$ of the recipient, an identifier from the profile's ordered domain. Component choice is operator policy within the reservation rule of Definition D.3, and whether self-payments ($a=b$) are accepted is profile policy. Each component starts at marker $(G,J)=(0,0)$, where $G$ is cumulative operator-promised credit and $J$ counts receipts in the component. A component's newest marker is its **tip**. Markers are serving state, separate from $X_b$: their terminal sums determine the epoch change in $C_b$ and $i_b$.

**Definition C.2 (receipt).** If component $(b,\kappa)$ currently ends at $(G,J)$, the receipt for a payment of $x$ with send body $s$ is

$$
r=(\mathcal A_e,b,\kappa,x,\mathsf{TxId}(s),G',J',e),\qquad
R=(r,\sigma_{\mathsf{op}}),\qquad
(G',J')=(G+x,J+1),
$$

signed under $\mathsf{operatorKey}$.

**Definition C.3 (linked and matching pairs).** A pair $P=(S,R)$ is **linked** when both signatures are canonical and valid, both bodies name the same anchor and epoch, the amount and recipient agree, and the receipt names $\mathsf{TxId}(s)$. Write $x(P)$ for its amount and $(G(P),J(P))$ for its receipt marker. A linked pair has an **intrinsic range fault** when $J(P)=0$ or $G(P)<x(P)$. It is **matching** when it is linked, $x(P)>0$, and it has no intrinsic fault. A matching pair is transferable evidence of one operator-acknowledged payment. A bare send $S$ is not: acceptance requires the operator to have committed the receipt body.

**Definition C.4 (range feasibility).** For a lower marker $(G^-,J^-)$ and an upper linked pair $P^+=(S^+,R^+)$ in one $(\mathcal A_e,b,\kappa)$ scope,

$$
\mathsf{RangeOK}((G^-,J^-),P^+)
\Longleftrightarrow
\begin{cases}
G^+=G^-+x^+,&J^+=J^-+1,\\
G^+\ge G^-+x^++(J^+-J^--1),&J^+>J^-+1,\\
\mathsf{false},&J^+\le J^-,
\end{cases}
$$

with all sums checked in the profile's credit domain and any overflow yielding false. Adjacent receipts must advance exactly. Across an index gap, each omitted receipt carries a positive integer amount and therefore contributes at least one unit, so the inequality is necessary. It is not sufficient to prove the omitted receipts exist or are authentic: $\mathsf{RangeOK}$ establishes numeric feasibility, and Section E uses only its violations.

The protocol orders only real conflicts. Sends from one payer form a chain through $D$, and receipts within one component form a chain through $(G,J)$. Payments with different payers and different components are never ordered against each other. The payer chain is itself a serialization: under Definition E.2 one send is outstanding at a time, so per-payer throughput is one accepted payment per operator round trip, and the concurrency domains exist only on the receive side.

#### C.2 Acceptance and import

**Algorithm C.1 (accept).** On input $(S,\kappa)$ the operator:

1. Strictly decodes $S$, verifies the payer signature, and checks that the body names the registered anchor, the current epoch, and registered accounts.

2. Replays and resyncs: if $s$ is byte-identical to the latest committed send of payer $a$, returns the stored receipt without mutation. If $s$ is any other send whose $D'$ is not the exact live successor $D_a^{\mathsf{live}}+x$, rejects it. When the rejected send is novel, the rejection attaches the stored latest committed pair $(S_{\mathsf{last}},R_{\mathsf{last}})$ so a payer that lost its in-flight request can trustlessly resynchronize: the payer authenticates the response by recognizing its own signature on $S_{\mathsf{last}}$. Replays of older committed sends get a bare rejection, so a past counterparty learns nothing new.

3. For a novel request, checks that payer and recipient are active, $x>0$, $B_a^{\mathsf{live}}\ge x$, the component and self-payment policies admit $(b,\kappa)$, and the close reservation of Definition D.3 can account for row $a$, row $b$, and component $(b,\kappa)$. Then it atomically commits

   $$
   B_a^{\mathsf{live}}\leftarrow B_a^{\mathsf{live}}-x,\qquad
   D_a^{\mathsf{live}}\leftarrow D',\qquad
   (G_{b,\kappa},J_{b,\kappa})\leftarrow(G_{b,\kappa}+x,\,J_{b,\kappa}+1),
   $$

   together with the replay record, the canonical receipt body $r$, and the close reservation.

4. Only after that commit, signs and returns $R$.

Rejection before the commit changes nothing. A crash after the commit re-signs the committed body on retry without a second debit: $r$ is a deterministic function of the committed state, and fresh signature bytes over the identical body are the same receipt under Definition C.3.

**Algorithm C.2 (import).** Recipients spend incoming credit only after importing it, and only for components scoped to their own registered identity. Let $(G_0,J_0)$ be the last imported marker for $(b,\kappa)$, initially $(0,0)$. Given a matching pair $P^+$ in that scope: if $(G^+,J^+)\le(G_0,J_0)$ coordinatewise, importing is a no-op. Otherwise import requires $\mathsf{RangeOK}((G_0,J_0),P^+)$ and atomically applies

$$
B_b^{\mathsf{live}}\leftarrow B_b^{\mathsf{live}}+(G^+-G_0),\qquad
(G_0,J_0)\leftarrow(G^+,J^+).
$$

Import is idempotent, and delayed import can only understate spendable balance. Every imported tip is signature-verified in scope, so total imported credit in a component never exceeds the highest cumulative credit the operator ever signed for it.

**Example (one accepted payment).** Account $a$ opens the epoch at $B_a^{\mathsf{live}}=100$ and $D_a^{\mathsf{live}}=0$ and pays $b$ 20 (Figure 1). The payer signs $s=(\mathcal A_e,a,b,20,D',e)$ with $D'=0+20$. The operator assigns component $(b,\kappa_0)$, resting at $(0,0)$, and Algorithm C.1 atomically commits $B_a^{\mathsf{live}}=80$, $D_a^{\mathsf{live}}=20$, and $(G_{b,\kappa_0},J_{b,\kappa_0})=(20,1)$ together with the replay record, the close reservation, and the receipt body $r=(\mathcal A_e,b,\kappa_0,20,\mathsf{TxId}(s),20,1,e)$, then signs and returns $R$. The matching pair $(S,R)$ is the payment's transferable evidence, an exact retry of $S$ returns the same receipt without a second debit, and the 20 becomes spendable for $b$ once it imports the tip under Algorithm C.2.

#### C.3 Honest-operator invariants

The challenge-soundness proof needs exactly what an honest operator's signing history looks like.

**Lemma C.1 (serving invariants).** In any execution in which the operator follows Algorithm C.1, all of the following hold at every point, per registered anchor, except with negligible probability:

1. **Payer chains.** For each payer $a$, the committed send bodies have strictly increasing debits forming the exact chain $D_a^0+x_1,\ D_a^0+x_1+x_2,\ \ldots$, ending at $D_a^{\mathsf{live}}$, and at most one committed send body exists per debit value.

2. **Component chains.** For each component $(b,\kappa)$, the committed receipt bodies have markers $(x_1,1),(x_1+x_2,2),\ldots$, ending at the live marker, at most one committed receipt body exists per index $J$, and at most one committed receipt body exists per $\mathsf{TxId}$ across all components.

3. **Signing discipline.** Every receipt body the operator ever signs is committed: signatures exist only over stored bodies (step 4 and the replay path of step 2).

4. **Range.** Every committed receipt satisfies $J\ge1$ and $G\ge x$, and in each component $\mathsf{RangeOK}$ holds from $(0,0)$ to every committed pair and from every lower committed marker to every higher committed pair.

5. **Balances.** $B_a^{\mathsf{live}}\ge0$, and $B_a^{\mathsf{live}}=B_a^0+f_a-w_a-(D_a^{\mathsf{live}}-D_a^0)+\iota_a$, where $w_a$ is the boundary-applied amount, a full close contributing its signed floor (Section B.5), and $\iota_a$ is the total credit imported by Algorithm C.2. Every accepted debit is therefore already counted against the payer's live balance before its receipt exists.

*Proof.* Induction over committed operations. Step 3 of Algorithm C.1 admits a novel send only at the exact successor debit and commits the debit, marker advance, and receipt body in one transaction, which extends both chains by one and preserves uniqueness per debit value, per component index, and per $\mathsf{TxId}$: a repeated $\mathsf{TxId}$ is a byte-identical body by injective canonical encoding under Assumption CR, hence a replay, hence returns the stored receipt. Step 4 signs only committed bodies. Exact chains give item 4 directly: adjacent committed receipts advance by exactly the upper amount, the first receipt in a component has $(G,J)=(x,1)$, and across a gap each omitted committed amount is a positive integer. Item 5 holds because step 3 checks $B^{\mathsf{live}}\ge x$ before subtracting, the boundary applies once (Section B.5), and Algorithm C.2 adds exactly the marker difference it records as imported. $\square$

### D. Closing an epoch

#### D.1 Terminal evidence and rows

The close retains only terminal evidence. For recipient $b$, let $h_b$ be the number of components used during the epoch and collect their final accepted pairs in strict component order:

$$
\mathbf Y_b=(Y_{b,0},\ldots,Y_{b,h_b-1}),\qquad
Y_{b,m}=(\kappa_m,S_m^\star,R_m^\star),\qquad
\kappa_0<\cdots<\kappa_{h_b-1}.
$$

Its aggregate commitment is $\mathsf{HeadRoot}_e(b)$: the authenticated-vector root of $\mathbf Y_b$, binding the exact length $h_b$ and the aggregate $(G_b,J_b)$, the coordinate sums of the terminal markers.

For each account define the checked epoch deltas

$$
d_a=D_a^1-D_a^0,\qquad
c_a=C_a^1-C_a^0,\qquad
j_a=i_a^1-i_a^0,
$$

and let $\chi_a,\gamma_a\in\{0,1\}$ record the presence of a sealed withdrawal and its full-close flag.

**Definition D.1 (valid row).** A changed-account row

$$
\mathsf{Row}_a=\bigl(a,X_a^0,X_a^1,\mathsf{Out}_a,\mathsf{HeadRoot}_e(a),\mathsf{prefix}_a\bigr)
$$

is valid against $(\mathcal A_e,\mathsf{StateRoot}_e)$, with $\mathsf{prefix}_a$ the running-total field defined in Section D.2, when:

1. **Domains.** The cumulative fields are monotone, the deltas fit the configured domains, and $X_a^1\ne X_a^0$.

2. **Boundary binding.** $(f_a,w_a,\chi_a,\gamma_a)$ equal the sealed per-account records of $\mathsf{Boundary}_e$, which the verifier reads from the registered anchor, an account with no sealed record contributing zeros. A full close is the one exception: its $w_a$ is the exhausting amount $B_a^0+c_a-d_a+f_a$, at least its sealed signed amount.

3. **Eligibility.** $u_a=\mathit{active}_a^0\lor(f_a>0)$ holds, $\mathit{active}_a^1=u_a\land\neg\gamma_a$, and an inactive closing account has $B_a^1=0$.

4. **Balance.** The exact account equation holds:

   $$
   \boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
   $$

5. **Outgoing terminal.** $\mathsf{Out}_a=\bot$ exactly when $d_a=0$. Otherwise $\mathsf{Out}_a$ is a matching pair from payer $a$ scoped to $\mathcal A_e$ whose send debit is exactly $D_a^1$, whose amount satisfies $x(\mathsf{Out}_a)\le d_a$, and whose receipt satisfies $\mathsf{RangeOK}((0,0),\mathsf{Out}_a)$.

6. **Incoming terminals.** $\mathbf Y_a$ is empty exactly when $(c_a,j_a)=(0,0)$. Otherwise its component identifiers are strictly ordered, every entry is a matching pair scoped to $(\mathcal A_e,a,\kappa)$, every entry satisfies $\mathsf{RangeOK}((0,0),\cdot)$, and the bound aggregate satisfies $(G_a,J_a)=(c_a,j_a)$.

#### D.2 The public close

Rows are strictly ordered by account, one row for every and only changed account. $\mathsf{prefix}_a$ is the inclusive running total of $(d,c,f,w,\chi,h)$ over rows up to $a$, checked row by row: each prefix equals its predecessor's plus the row's own contributions. The terminal prefix carries

$$
D_e=\sum_a d_a,\quad C_e=\sum_a c_a,\quad F_e=\sum_a f_a,\quad
W_e=\sum_a w_a,\quad M_e=\sum_a\chi_a,\quad H_e=\sum_a h_a,
$$

all within the checked domains. Let $\mathbf A_e$ be the row vector, $A=|\mathbf A_e|$, and $\mathsf{ChangeRoot}_e$ its authenticated commitment, length-bound and ordered by account. Let $\mathcal J_e=\{\mathsf{pos}(a):\mathsf{Row}_a\in\mathbf A_e\}$, and let $(\mathcal J_e,\{(X_a^0,X_a^1)\},\Phi_e)$ be a paired sparse opening of $(\mathsf{StateRoot}_e,\mathsf{StateRoot}_{e+1})$ in the sense of Definition A.2.

The close's header binds

$$
\mathsf{Header}_e=\bigl(
\mathsf{AnchorId}_e,\mathsf{StateRoot}_e,\mathsf{ChangeRoot}_e,\mathsf{StateRoot}_{e+1},
A,D_e,C_e,F_e,W_e,M_e,H_e,\Delta_e\bigr).
$$

The **public corpus** $\mathcal D_e$ contains the rows, the terminal component vectors behind each $\mathsf{HeadRoot}$, the paired sparse opening, and the membership openings needed to check each piece of it.

**Definition D.2 (public validity).** $\mathsf{PublicValid}_e(\mathsf{Header}_e,\mathcal D_e)$ is the conjunction of:

1. **Context.** Strict decoding, and the header names the registered $\mathsf{AnchorId}_e$ and its $\Delta_e$, with the resource limits read from that anchor.

2. **Rows.** Every row is valid (Definition D.1), rows are strictly ordered by account with consistent prefixes, and $\mathsf{ChangeRoot}_e$ commits exactly this vector.

3. **Boundary coverage.** Every account with a sealed record in $\mathsf{Boundary}_e$ has a row, the terminal prefix totals $F_e$ and $M_e$ equal the sealed boundary totals, and $W_e$ is the row sum, each row's $w_a$ bound by item 2 of Definition D.1.

4. **Exact update.** The paired sparse opening verifies from $\mathsf{StateRoot}_e$ to $\mathsf{StateRoot}_{e+1}$ over exactly the row positions $\mathcal J_e$, using each row's $(X_a^0,X_a^1)$.

5. **Limits and conservation.** The configured resource limits hold, $A\le A_{\max}+\beta_e$ with $\beta_e$ the number of accounts carrying sealed records in $\mathsf{Boundary}_e$, $M_e\le A$, $H_e\le H_{\max}$, and $D_e=C_e$.

Boundary coverage is both checkable and necessary. It is checkable because $\mathsf{Boundary}_e$ is bound inside the registered anchor, so every verifier holds the sealed per-account records. It is necessary because a sealed record forces a state change: within one boundary an account carries deposits or a withdrawal, never both (Section B.3), so its balance equation cannot cancel, and a zero-amount full close flips the active flag. Without item 3, a close could satisfy every total while silently reassigning one account's sealed deposit to another row.

**Lemma D.1 (exact difference of the close).** Under Assumption BIND, if $\mathsf{PublicValid}_e$ holds and $\mathsf{StateRoot}_e$ commits $\mathbf S^0$, then $\mathsf{StateRoot}_{e+1}$ commits the unique $\mathbf S^1$ with

$$
k\in\mathcal J_e\Longleftrightarrow\mathbf S_k^1\ne\mathbf S_k^0,
$$

and $\mathbf S_k^1=X_a^1$ for each row account $a$ at position $k$.

*Proof.* Lemma A.1 applied to item 4 of Definition D.2, with the inequality direction on $\mathcal J_e$ given by Definition D.1 item 1. $\square$

Lemma D.1 speaks only about committed state. An operator whose live state changed can still commit an unchanged value by omitting the row and the receipts behind it. That omission is invisible to every public check and is exactly what the challenge window of Section E covers.

**Lemma D.2 (typed conservation).** Under the conditions of Lemma D.1, with $L_e=\sum_kB^0_k$ and $L_{e+1}=\sum_kB^1_k$,

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

*Proof.* Positions outside $\mathcal J_e$ contribute equal balances to both sums by Lemma D.1 and carry no sealed boundary record by item 3 of Definition D.2. Summing the balance equation of Definition D.1 over rows gives $L_{e+1}-L_e=(C_e-D_e)+(F_e-W_e)$, with the prefix consistency of item 2 identifying the row sums with the header totals, and item 5 cancels the payment terms. The conservation is typed: $F_e$ and $W_e$ come from the chain-sealed boundary and $D_e$, $C_e$ from signed cumulative markers, so equal totals cannot let one type impersonate the other. $\square$

For $A=0$ the canonical close has an empty $\mathsf{ChangeRoot}$, zero totals, and $\mathsf{StateRoot}_{e+1}=\mathsf{StateRoot}_e$.

**Example (one changed row).** Accounts $(a,b,c,d)$ open at balances $(100,40,25,35)$ with zero cumulative fields, and the epoch accepts $a\xrightarrow{20}b$, $b\xrightarrow{12}c$, $c\xrightarrow{7}d$, $d\xrightarrow{5}a$, $c\xrightarrow{4}b$, and $d\xrightarrow{6}b$ over an empty boundary (Figure 2). Recipient $b$'s three components end at $(20,1)$, $(4,1)$, and $(6,1)$, so $\mathsf{HeadRoot}_e(b)$ binds $h_b=3$ and $(G_b,J_b)=(30,3)$, and $\mathsf{Row}_b$ closes at $B_b^1=58$: the balance equation reads $58+12+0=40+30+0$. All four accounts change, the terminal prefix carries $D_e=C_e=54$, and Lemma D.2 gives $L_{e+1}=L_e=200$.

**Definition D.3 (close reservation).** The operator accepts a payment only when the resulting close still fits $\Lambda$: rows for the payer and recipient and a terminal slot for the chosen component either already exist or can be reserved without exceeding $A_{\max}$ or $H_{\max}$. Boundary-forced rows sit above the cap through $\beta_e$, so a sealed boundary can never make the close unsatisfiable, however large an expiration merge grows it. This makes $A$ and $H_e$ independent of $T$ and guarantees that acceptance never strands a payment the close cannot represent.

**Lemma D.3 (honest validity).** A close built by an operator following Algorithm C.1, the boundary rules of Section B, and the seal discipline of Section G from its committed terminal state satisfies $\mathsf{PublicValid}_e$.

*Proof sketch.* Each accepted payment adds $x$ to exactly one payer debit and the same $x$ to exactly one component credit, so the terminal sums satisfy $D_e=C_e$, with Definition D.1 item 6 equating component sums with credit deltas. Monotonicity and the balance equation per row are Lemma C.1 items 1 and 5 read at the hard seal, with reconciliation closing the imported-credit gap (Lemma G.1). Boundary binding and coverage hold because the operator applies its own sealed boundary exactly once per account. The caps hold by Definition D.3's reservation. The paired opening recomputes both roots from the operator's own committed vectors. $\square$

The close separates its evidence lifetimes:

| Artifact | Contents | Required lifetime |
|:--|:--|:--|
| Chain record | Header and validity evidence | Persistent |
| Admission check | Terminal row and its $\mathsf{ChangeRoot}$ opening, or the canonical empty close, plus one row opening per full-close record, withdrawal re-check openings, and any mode-required availability evidence | Admission only |
| Public corpus $\mathcal D_e$ | Rows, component vectors, paired opening, lookup material | Retrievable through $t\le\Delta_e$ |
| Survivor preimages | Complete state vector of each root that may survive (Definition D.5) | Until its successor slot finalizes or unwind completes |

#### D.3 Certification

Validity concerns the complete relation $\mathsf{PublicValid}_e$, never isolated pieces.

**Definition D.4 (quorum certification).** $\mathsf{ValidityConfig}_e$ fixes a deterministic partition of $(\mathsf{Header}_e,\mathcal D_e)$ into pieces $\mathcal P_{e,0},\ldots,\mathcal P_{e,p-1}$ by contiguous account interval, together with each piece's validator assignment, both public functions of the header and the validator set, so the prover cannot route data away from its checkers. How validators obtain the corpus is transport, outside this specification. Each piece carries its interval's rows, component vectors, and opening segments, together with seam context: the predecessor interval's terminal row and prefix, the ordering edge to the successor, and the frontier digests bordering the interval's state subtrees. Piece predicates $\pi_j$ check row validity, ordering, prefix continuity, and the interval's share of the paired opening locally. Every validator additionally checks the **spine**: the header totals against the terminal prefix, the sealed boundary, the caps, $D_e=C_e$, and the top-level assembly of interval subtree roots into the three header roots. The assignment must be **composition-sound**:

$$
\Bigl(\bigwedge_{j}\pi_j(\mathcal P_{e,j})\Bigr)\land\mathsf{spine}
\Longleftrightarrow\mathsf{PublicValid}_e,
$$

with the pieces jointly covering all $A$ rows and all $N$ registry positions. Each piece is assigned to a set $\mathcal V_{e,j}$ of $q=2f_{\mathsf{val}}+1$ validators. An honest validator signs $\mathsf{Header}_e$ only after the spine and every piece assigned to it pass, and it retains those pieces through $\Delta_e$. The certificate is $q$ distinct validator signatures on $\mathsf{Header}_e$.

**Lemma D.4 (certified validity and retention).** In quorum mode with at most $f_{\mathsf{val}}$ faulty validators, a certificate on $\mathsf{Header}_e$ implies $\mathsf{PublicValid}_e$, and every piece is retained through $\Delta_e$ by at least one honest certificate signer.

*Proof.* Let $\mathcal Q_e$ be the signer set, $|\mathcal Q_e|=q$. For each piece, $|\mathcal Q_e\cap\mathcal V_{e,j}|\ge|\mathcal Q_e|+|\mathcal V_{e,j}|-n_{\mathsf{val}}=2q-n_{\mathsf{val}}=f_{\mathsf{val}}+1$, so some honest validator both signed the header and was assigned piece $j$. That validator checked $\pi_j$ and the spine and retains $\mathcal P_{e,j}$. All predicates passing implies $\mathsf{PublicValid}_e$ by composition soundness. The honest signer may differ per piece, which suffices: the identical header, exhaustive assignment, and quorum intersection jointly attest the complete relation, which byte availability alone would not. $\square$

A validity proof or TEE attestation may certify $\mathsf{PublicValid}_e$ instead. It must bind the deployment, registered anchor, header, exact corpus digest, profile, and deadline.

**Definition D.5 (availability obligations).** Through $t\le\Delta_e$, the availability service returns, for the admitted close: the bound corpus $\mathcal D_e$, authenticated row membership or ordered-absence proofs for any account, opening-state membership proofs under $\mathsf{StateRoot}_e$ for accounts without rows, and component membership or ordered-absence proofs under any row's $\mathsf{HeadRoot}$. An operator-controlled location or an unaccompanied digest does not satisfy this. Validator retention (Lemma D.4) covers the corpus and its openings, and proof and TEE modes require equivalent availability evidence at admission, in the format $\mathsf{ValidityConfig}_e$ fixes. The frontier digests cannot produce opening-state proofs for accounts inside omitted subtrees, so those proofs and the complete state preimage of every root that may become the survivor root of Section F need full state vectors, whose retention $\mathsf{ValidityConfig}_e$ assigns explicitly, until the root stops being a possible survivor: its successor slot finalizes, or unwind completes. Every mode requires the recovery allowance

$$
\alpha_e+\lambda_{\mathsf{DA}}\le\Delta_e,
$$

where $\lambda_{\mathsf{DA}}$ budgets corpus retrieval, holder detection, and challenge inclusion after the latest possible admission.

### E. Receipt challenges

#### E.1 Why challenges exist

**Proposition E.1 (admission blindness).** Fix any admission verifier $V$, deterministic or randomized, whose input is a header, corpus, and accepting evidence $(\mathsf{Header}_e,\mathcal D_e,\zeta)$ together with any availability responses. For every execution $\Xi_0$ in which the operator signs exactly the receipts represented in $\mathcal D_e$, there is an execution $\Xi_1$ in which it additionally signs one more valid receipt and delivers it off-protocol, such that $V$'s input distribution is identical in both. Hence $\Pr[V\ \mathrm{accepts}\ \Xi_1]=\Pr[V\ \mathrm{accepts}\ \Xi_0]$.

*Proof.* Construct $\Xi_1$ from $\Xi_0$ by having the operator sign one extra receipt body after producing $(\mathcal D_e,\zeta)$ and deliver it on a channel $V$ does not read. No part of $V$'s input changes, and $V$'s acceptance is a function of its input and coins. The argument is independent of whether $\zeta$ is a quorum certificate, a validity proof, or an attestation: each certifies a relation over presented inputs, and none can certify the nonexistence of an additional signature. $\square$

Receipt completeness therefore cannot be an admission property under any validity mode. It is enforced by holders during the challenge window, and every guarantee about undisclosed receipts in Section H is conditioned on timely disclosure. Proposition E.1 shows no public-view verifier detects the extra receipt. It does not make the receipt unenforceable: enforcement is exactly Theorem E.2. One limit is sharper still: challenges name admitted slots, so evidence scoped to an anchor whose epoch never admits is outside the challenge system, and preconfirmation holders bear operator default until their epoch admits.

#### E.2 Public reference values

Every challenge names one admitted slot and authenticates all public values from that slot's header under Assumption BIND. An **account lookup** for $a$ proves row membership or ordered absence under $\mathsf{ChangeRoot}_e$, and for an absent row additionally proves $X_a^0$ under $\mathsf{StateRoot}_e$. It yields the public closing debit and terminal pair

$$
(D^\star,O^\star)=
\begin{cases}
(D_a^1,\mathsf{Out}_a),&\text{row present},\\
(D_a^0,\bot),&\text{row absent}.
\end{cases}
$$

A **component lookup** for $(b,\kappa)$ continues from a present row's $\mathsf{HeadRoot}_e(b)$ and proves the entry with identifier $\kappa$ or its ordered absence, yielding the public tip

$$
(G^\star,J^\star)=
\begin{cases}
\bigl(G(P^\star),\,J(P^\star)\bigr),&\text{entry present, with terminal pair }P^\star,\\
(0,0),&\text{entry or row absent}.
\end{cases}
$$

The higher-tip challenge needs only the absence forms, while the payer-debit challenge on an absent row needs the opening state for $D^\star$. Definition D.5 keeps all of these obtainable through $\Delta_e$.

#### E.3 The four predicates

**Definition E.1 (receipt challenges).** A challenge is valid when it names an admitted slot, is included at $t\le\Delta_e$, every signed pair it carries is scoped to that slot's anchor and epoch, its lookups verify, and its predicate holds. Dot notation reads signed-body fields, so $S^+.D'$ is the retained send's debit and $(R^+.G,R^+.J)$ its receipt marker. All comparisons use checked arithmetic.

| Challenge | Evidence | Predicate |
|:--|:--|:--|
| Payer debit | matching pair $P^+$ from payer $a$, account lookup | $S^+.D'>D^\star$, or $S^+.D'=D^\star$ with $P^+$'s canonical bodies differing from $O^\star$'s |
| Higher receive-component tip | matching pair $P^+$ for $(b,\kappa)$, account and component lookups | $R^+.G>G^\star\ \lor\ R^+.J>J^\star$, coordinates compared independently |
| Inconsistent range | linked upper pair $P^+$, and a linked lower pair $P^-$ in the same scope or the canonical origin $(0,0)$ | an endpoint has an intrinsic range fault, or $J(P^-)<J(P^+)$ and $\mathsf{RangeOK}$ fails from the lower marker to $P^+$ |
| Receipt fork | two linked pairs with distinct canonical receipt bodies | the bodies share $(\mathcal A_e,b,\kappa,J)$ or share $(\mathcal A_e,\mathsf{TxId})$ |

Distinct signature bytes over one identical body are one receipt, never a fork. The range predicate demands strictly increasing indices between its endpoints: presenting one pair twice, or two pairs in reversed order, is not a contradiction, and genuinely conflicting equal indices are the fork predicate's job. A bare send is not evidence: every predicate requires operator-signed receipts, which is what makes a valid challenge attributable to the operator. The pairs may be retained privately or drawn from the disclosed corpus, so a retained pair can be played against a published terminal. Malformed public rows, prefixes, boundary totals, or sparse openings are not challenge kinds: they are admission failures under Definition D.2.

A valid challenge at slot $j$ permanently faults the deployment, prevents slot $j$ and every admitted descendant from finalizing, and sets or lowers the fault cut of Section F to $j$. Earlier admitted slots keep their windows and resolve in order. The challenge assigns blame, not compensation.

The division of labor between the payer-debit and credit-side challenges is deliberate. A retained pair whose debit sits strictly below $D^\star$ is not a debit contradiction even if the close committed a different payment at that marker: the divergence is caught in the receive component, by the higher-tip or fork predicate, using the same retained pair.

**Example (higher-tip challenge).** Continuing the running example, suppose the operator signs one more receipt in $(b,\kappa_0)$ for a payment of 3, advancing that component's tip to $(23,2)$, delivers it privately, and admits the close with terminal $(20,1)$ anyway, indistinguishable at admission by Proposition E.1 (Figure 4). The recipient's account and component lookups authenticate $(G^\star,J^\star)=(20,1)$ under the admitted slot, its retained pair carries $(R^+.G,R^+.J)=(23,2)$, and either strict inequality satisfies the higher-tip predicate. The slot and its admitted descendants can no longer finalize, and the fault cut falls to it.

#### E.4 Soundness

**Theorem E.1 (challenge soundness).** Under Assumptions SIG, CR, and BIND, if the operator follows Algorithm C.1, closes each epoch per Section D, and observes the seal discipline of Section G, so that no novel epoch-scoped payment is accepted after that scope's markers are fixed for the close, then no valid challenge exists against any of its admitted slots, except with negligible probability.

*Proof.* A valid challenge carries at least one receipt with a verifying operator signature. By Assumption SIG every such receipt body was signed by the operator, hence committed by Algorithm C.1 (Lemma C.1 item 3), and by Assumption BIND the challenge's lookups yield the operator's actual close values. The honest close publishes each payer's terminal committed pair and each component's terminal committed pair with exact aggregates, and the seal discipline makes those terminals final. It remains to check each predicate against Lemma C.1.

*Payer debit.* Committed send debits of payer $a$ end at $D^\star$ (item 1), so no acknowledged $S^+.D'$ exceeds $D^\star$. At most one committed body exists per debit value and the close publishes the terminal one, so equality with different canonical bodies is impossible. If the row is absent, the honest operator accepted no send from $a$, so no matching pair from $a$ exists at all (Lemma C.1 item 3), and the challenge cannot supply its required evidence.

*Higher tip.* Committed markers of $(b,\kappa)$ end at the published tip (item 2), so every signed receipt in the component is coordinatewise dominated. If the account or component is absent from the close, no receipt was committed there, and the reference $(0,0)$ dominates the empty set.

*Range.* A presentation with $J(P^-)\ge J(P^+)$ fails the predicate's ordering requirement, and item 4 covers the rest: committed receipts have no intrinsic fault, and $\mathsf{RangeOK}$ holds from $(0,0)$ and between every ordered committed pair.

*Fork.* Item 2: one committed body per component index and per $\mathsf{TxId}$. Two distinct bodies sharing either key would need a signature over an uncommitted body, contradicting item 3 under Assumption SIG. $\square$

#### E.5 Discipline and completeness

**Definition E.2 (holder discipline).** An honest **payer** durably persists each signed request before transmitting it, keeps one send outstanding at a time at the exact successor debit, retains the matching pair, forwards it to the recipient, and advances its acknowledged marker only after the receipt verifies. It derives its debit marker only from evidence bearing its own signature, as the coordinatewise maximum over its retained acknowledged pairs, its persisted outstanding send, and any resync pair returned by Algorithm C.1 step 2, so a stale resync pair never regresses the marker. It never signs a second distinct body at a debit value it has already signed until a finalized close shows the first unaccepted, and when an epoch expires unadmitted it discards markers acknowledged under that anchor and re-derives from the last admitted closing state before signing under a newer anchor. At close it compares its last acknowledged pair against $(D^\star,O^\star)$. An honest **recipient** verifies it is the registered identity named by each receipt, retains every delivered pair tied to value it gave up, even pairs it rejects locally, and at close checks against the public terminals: higher tips, forks, and every adjacent range in each of its components from $(0,0)$ through the public tip. Either may delegate retention and checking to a watchtower. Detected contradictions must be submitted within the recovery allowance of Definition D.5.

**Theorem E.2 (challenge completeness).** Suppose epoch $e$ is admitted, Definition D.5 holds, and a holder retains signed evidence scoped to $\mathcal A_e$ such that either

1. a matching pair $P^+$ from payer $a$ has $S^+.D'>D^\star$, or $S^+.D'=D^\star$ with bodies differing from the public terminal, or
2. a matching pair $P^+$ credits component $(b,\kappa)$ with $(R^+.G,R^+.J)\not\le(G^\star,J^\star)$ coordinatewise, or
3. its linked pairs, alone or against the disclosed terminals, witness an intrinsic fault, an ordered $\mathsf{RangeOK}$ violation, or a fork as in Definition E.1.

Then that holder can construct the corresponding challenge and have it included by $\Delta_e$.

*Proof.* Cases 1 and 2 need the account lookup, and case 2 the component lookup, obtainable through $\Delta_e$ by Definition D.5, including the absence and opening-state forms. Case 3 additionally draws disclosed terminal pairs from the retrievable corpus. The retained pairs supply the signed evidence and the predicate holds by hypothesis. The recovery allowance $\alpha_e+\lambda_{\mathsf{DA}}\le\Delta_e$ budgets retrieval, detection, and the call's inclusion after the latest possible admission, so the challenge lands by the deadline. $\square$

Theorems E.1 and E.2 make the challenge window exact: an honest operator is never faulted, and any operator whose private signatures exceed its public close in the sense above is faulted by any harmed holder who follows Definition E.2.

### F. Settlement transitions, exit, and terminal unwind

#### F.1 The transition system

The chain state of Section B.3 evolves only through the guarded transitions below, each invocable by any party. Every transition first executes $\mathsf{Timeout}$. A guard failure leaves state unchanged. Inclusive deadlines follow one convention: equality belongs to registration, admission, and challenge, never to finalization.

**Deposit.** Guard: deployment live, the asset adapter authenticates a finalized inbound transfer with a fresh identifier to a registered account, and the account has no unreleased full-close withdrawal. Effect: $E\mathrel{+}=x$, the identifier is permanently consumed, and the record enters the open boundary, or is held when the open boundary carries the account's withdrawal record or a full deposit quota (Section B.3). A deposit has no deadline and no independent exit guarantee: if terminal unwind occurs before its slot finalizes, it is returned through the terminal payout (F.4).

**Withdrawal.** Defined in F.2.

**Register.** Guard: $t\le\alpha_e$, deployment live, $e$ follows the last registered epoch, at most one registration already outstanding, no outstanding registration doomed, fewer than $K$ slots pending. Effect: seal the open boundary into $\mathcal A_e$ and open a fresh boundary. No custody or root change. The chain derives every anchor field from deployment state and the profile's epoch schedule, checking $\alpha_e<\Delta_e$ and $\alpha_e+\lambda_{\mathsf{DA}}\le\Delta_e$: the caller supplies only the invocation.

**Admit.** Guard:

1. the deployment is live, $t\le\alpha_e$, and $e$ is the oldest outstanding registration and is not doomed;
2. the submitted header names $\mathsf{AnchorId}_e$ and opening root $\mathsf{StateRoot}_e=\mathsf{rt}_\ell$;
3. the validity evidence verifies (Definition D.4 or the proof/TEE form) and the availability evidence meets $\mathsf{ValidityConfig}_e$;
4. the admission payload opens the terminal row prefix under $\mathsf{ChangeRoot}_e$ (or is the canonical empty close) with totals matching the header and with $F_e$ and $M_e$ matching the sealed boundary, plus one row opening per full-close record proving its exhausting amount;
5. the pipeline has capacity and the checked liability $L_{\ell+1}=L_\ell+F_e-W_e$ is computable;
6. every queued unreleased withdrawal not carried by $\mathsf{Boundary}_e$ is proven still affordable and its account active under $\mathsf{rt}_{\ell+1}$, by openings supplied with the call.

Effect: append slot $\ell+1$ carrying $(\mathsf{Header}_e,F_e,W_e)$ and each full-close record's proven exhausting amount, persisting what Section E's challenges authenticate against and what Finalize's payout split needs, and clear the registration. Custody, $\mathsf{rt}_z$, and $L_z$ are unchanged.

**Challenge.** Guard: $t\le\Delta_e$ for the named slot and Definition E.1 holds. Effect: permanent fault, cut update per F.3.

**Finalize.** Guard: the front slot $z+1$ is unchallenged and $t>\Delta_{z+1}$. Effect: install $\mathsf{rt}_{z+1}$ as finalized, release its withdrawal records through the asset adapter, a full close routing the signed amount to $v$ and the exhausting excess to the account's canonical destination, consume its deposit records, decrement custody, $E\mathrel{-}=W_{z+1}$, and advance $z$. As in the terminal payout, zero amounts are omitted and their records are still consumed. A descendant never finalizes before its ancestor, even when its own window closes first. Deadlines of different slots need not be ordered, and front-only finalization is what preserves one state lineage regardless.

**Expiration.** Guard: deployment live, $t>\Delta_e$ for the oldest outstanding registration, never admitted. Effect: discard the registration as work, merge its sealed records into the open boundary under the assignment rule of Section B.3, and mark every younger outstanding registration **doomed**. A doomed registration can only expire, and Register is blocked while one is outstanding, so recovery is a single bounded expiration cascade. This is what keeps an epoch served on top of a dropped predecessor's proposed state from admitting against a different opening: without it, a close rebuilt from the tail could debit honest payers' epoch-spanning markers while routing the dropped epoch's credits elsewhere. No custody or root change.

**Timeout.** Guard: some queued withdrawal is unreleased at $t\ge\tau$. Effect: permanent fault (F.3), recording the minimum $(\tau_a,\mathsf{pos}(a))$ among overdue requests as the fault trigger: the permanent record of what faulted the deployment. A repeated observation after fault changes nothing.

**Unwind.** Guard: deployment faulted and the front has reached the fault cut, $z+1=c_\star$. Inputs and effect: Section F.4.

#### F.2 Withdrawals

A withdrawal is the account-signed object

$$
q_a^{\mathsf{wd}}=(\mathsf{deployment},\mathsf{rt}_z,a,v,x,\gamma,\tau),\qquad
Q=(q_a^{\mathsf{wd}},\sigma_a^{\mathsf{wd}}),
$$

where $v$ is a destination the asset adapter accepts, $\gamma$ requests a full close, and $\tau$ is an absolute deadline. It names the finalized root at signing, never a future epoch or anchor.

**Withdrawal.** Guard, evaluated at queueing time $t_q$ with pipeline $(z,\ldots,\ell)$:

1. the deployment is live;
2. the signature verifies and $\mathsf{rt}_z$ is the current finalized root;
3. $a$ is active and $x\le B_a$ under every admitted root $\mathsf{rt}_z,\ldots,\mathsf{rt}_\ell$, proven by openings supplied with the call;
4. $x>0$, or $x=0$ with $\gamma=1$ and $B_a=0$ at every such root, and a full close requires the exact balance $x=B_a$ at $\mathsf{rt}_\ell$;
5. $a$ has no other unreleased withdrawal, and for $\gamma=1$ no unconsumed deposit;
6. $\tau\ge t_q+\eta$, with $\eta>0$ fixed in $\Pi$.

Effect: the record enters the open boundary, the account's deposit records there are re-held (Section B.3), and the canonical withdrawal identifier $\mathcal H_{\mathsf{wd}}(q_a^{\mathsf{wd}})$ is permanently consumed. A profile sets $\eta$ above the worst-case release latency of a cleanly operating deployment, including one registration-expiration cascade, or a slow release turns into a fault. A full close is best-effort: unconsumed third-party deposits defer it, and a $\gamma=0$ withdrawal of the full balance is the guaranteed value exit. Its signed amount is a floor, not the row value: the close exhausts the account with $w_a\ge x$ (Definition D.1 item 2), and release and unwind route $x$ to $v$ and the excess to the account. No custody or root change. The withdrawal is **released** when the slot carrying its boundary finalizes, and **unreleased** until then. Guard 3 covers the roots admitted so far, and the Admit re-check covers every later root except the carrying slot's own, which can never be the survivor root while the withdrawal is unreleased, so together they cover every possible survivor root (Lemma F.1). There is no operator withdrawal path: queueing is permissionless like every transition, its openings are obtainable from the retention of Definition D.5, and the operator's cooperation determines only whether release comes from a clean close or from the terminal payout. The signed $\tau$ is a fence, not a payout promise: the challenge windows and the ordered pipeline stand between queueing and payout, and Theorem F.2 states exactly what $\tau$ buys.

#### F.3 Faults and the fault cut

The deployment enters permanent fault at the first valid challenge or timeout observation. Fault fences all new work: deposits, withdrawal queueing, registrations, admissions, registration expiration, and the routing changes of Section G. Freeze $\ell_{\mathsf{fault}}$ as the tail at that moment. The **fault cut** $c_\star$ is the first slot barred from finalizing, and it only moves toward the front, never away:

$$
c_\star=
\begin{cases}
\ell_{\mathsf{fault}}+1,&\text{fault entered by timeout},\\
j,&\text{fault entered by a challenge at slot }j,
\end{cases}
\qquad
c_\star\leftarrow\min(c_\star,j)\ \text{on each later valid challenge}.
$$

A timeout entry bars no admitted slot, and later timeout observations change nothing. Slots before $c_\star$ keep their challenge windows and resolve from the front in order: each front slot finalizes after its window or is itself challenged, lowering the cut. Resolution ends when the front reaches $c_\star$, leaving survivor root $\mathsf{rt}_{c_\star-1}$.

**Example (resolution).** With slots $z+1$, $z+2$, and $z+3$ admitted, a valid challenge against slot $z+2$ faults the deployment and sets $c_\star=z+2$. Slot $z+1$ keeps its window and finalizes once it closes, the front reaches the cut, and terminal unwind pays the complete state under the survivor root $\mathsf{rt}_{z+1}$, with the deposits of slots $z+2$ and $z+3$ returned through the terminal payout.

#### F.4 Terminal unwind

Let $F_{\mathsf{term}}$ collect the deposits of every unfinalized slot and every unadmitted or held record, so $F_{\mathsf{term}}=F_\star+\sum_{i=c_\star}^{\ell_{\mathsf{fault}}}F_i$ after resolution. Terminal unwind authenticates the complete registry-ordered state vector committed by $\mathsf{rt}_{c_\star-1}$, whose bound aggregate is $L_{c_\star-1}$, together with every unfinalized boundary record. For each account let $w_a^{\mathsf{term}}$ be its unreleased signed withdrawal amount or zero, $f_a^{\mathsf{term}}$ its terminal deposit total, and $B_a^{\mathsf{surv}}$ its balance under the survivor root. The chain rechecks $w_a^{\mathsf{term}}\le B_a^{\mathsf{surv}}$, which Lemma F.1 shows cannot fail, and computes the residual

$$
r_a=B_a^{\mathsf{surv}}-w_a^{\mathsf{term}}+f_a^{\mathsf{term}}.
$$

In registry order the payout emits the positive withdrawal amount to its signed destination $v$ (a full close emits the signed amount to $v$ and the residual to $a$), then the positive residual to the account's canonical destination fixed by $\Pi$. Deposit refunds inside $f_a^{\mathsf{term}}$ ride the residual, except that a record whose account is inactive under the survivor root follows its bound source. Zero amounts are omitted, equal destinations remain separate, and a zero-amount full close is still consumed. One atomic chain-and-asset transition executes the complete payout, consumes every remaining record, zeroes custody and liability, and marks the deployment permanently unwound. A failed transfer changes nothing.

#### F.5 Custody and exit theorems

**Theorem F.1 (custody invariant).** Under assumptions 1–3 of Section H.1, except with negligible probability, every reachable chain state satisfies

$$
\boxed{
E=L_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+\sum_{i=z+1}^{\ell}W_i+F_\star,
}
$$

where $F_\star$ sums all accepted deposits not yet carried by an admitted slot.

*Proof.* The two forms agree by telescoping $L_i=L_{i-1}+F_i-W_i$. Induction over transitions from the base state $E=L_0=0$ with an empty pipeline and boundary. *Deposit* adds $x$ to both $E$ and $F_\star$. *Withdrawal*, *Register*, *Expiration*, *Challenge*, and *Timeout* change no term: sealing, holding, and merging move records within $F_\star$. *Admit* moves the sealed boundary's $F_e$ from $F_\star$ into the pipeline sum, and Lemma D.2 gives $L_{\ell+1}=L_\ell+F_e-W_e$, preserving the second form. *Finalize* decreases $E$ by $W_{z+1}$, advances $L_z$ by $F_{z+1}-W_{z+1}$, and removes slot $z+1$ from the sum, so both sides fall by $W_{z+1}$. The induction establishes the invariant at every pre-unwind state, which is what Lemma F.2 consumes, and *Unwind* then zeroes custody, liability, and every record by construction, so the post-unwind state satisfies it trivially. Withdrawals stay inside custody until their own slot finalizes, which is why admission can be pipelined without a speculative descendant spending assets out from under an ancestor. $\square$

**Lemma F.1 (survivor-root coverage).** If terminal unwind pays an unreleased withdrawal $Q$ of account $a$, then $w_a^{\mathsf{term}}\le B_a^{\mathsf{surv}}$ and $a$ is active under $\mathsf{rt}_{c_\star-1}$.

*Proof.* Let $\ell_q$ be the tail when $Q$ was queued. If $c_\star-1\le\ell_q$, the queueing guard checked $\mathsf{rt}_{c_\star-1}$ directly. Otherwise slot $c_\star-1$ was admitted after $t_q$ while $Q$ was queued. $Q$ is unreleased at unwind, so the slot carrying its boundary never finalized, and since slots finalize from the front in order, that carrying slot lies at or beyond $c_\star$. Slot $c_\star-1$ therefore did not carry $Q$, and its Admit guard re-proved affordability and activity under $\mathsf{rt}_{c_\star-1}$. Committed roots are immutable, so the checked facts still hold at unwind. Held and merged records preserve this: merging only moves $Q$'s boundary to a later slot, which the same argument covers. $\square$

**Lemma F.2 (payout exhaustion).** The terminal payout's amounts sum exactly to $E$, and unwind zeroes custody.

*Proof.* By Lemma F.1 every residual is nonnegative, so the payout is well formed. Summing over accounts, withdrawals cancel: $\sum_a(w_a^{\mathsf{term}}+r_a)=\sum_aB_a^{\mathsf{surv}}+\sum_af_a^{\mathsf{term}}=L_{c_\star-1}+F_{\mathsf{term}}$, using the survivor root's bound balance aggregate and the unique assignment of every unconsumed deposit to exactly one $f_a^{\mathsf{term}}$. After resolution finalizes every slot before $c_\star$, Theorem F.1 reads $E=L_{c_\star-1}+\sum_{i=c_\star}^{\ell_{\mathsf{fault}}}F_i+F_\star=L_{c_\star-1}+F_{\mathsf{term}}$. $\square$

**Theorem F.2 (conditional exit).** Operator liveness is not assumed. If an honest account queues $Q$ and it is unreleased at $t\ge\tau$, then: the first included call permanently fences new work, the admitted prefix resolves from the front in order, and once the front reaches the fault cut, terminal unwind pays $w_a^{\mathsf{term}}$ to the signed destination, with affordability from Lemma F.1 and exhaustion from Lemma F.2. Every needed call is permissionless, so the exiting account can submit the observation, finalization, and unwind calls itself, and each lands within $\delta_{\mathsf{incl}}$. The guarantee is conditional on atomic asset execution and on availability of the survivor preimage (Definition D.5). It is not a payout at $\tau$: resolution takes at most the maximum remaining challenge window of the at most $K$ admitted slots, plus $O(K)$ inclusion delays, plus the terminal transition.

*Proof.* $\mathsf{Timeout}$ precedes every transition, so the first call included after $\tau$ faults the deployment and freezes $\ell_{\mathsf{fault}}$. Fault fences every transition that creates new state, so the pipeline is a fixed finite deque. Each front slot either finalizes once its window closes, by a permissionless call included within $\delta_{\mathsf{incl}}$, or is validly challenged by its own deadline, which lowers the cut and shortens the deque. Both steps strictly advance the front toward the cut, so resolution terminates within the stated bound. The unwind guard is then satisfiable with the survivor preimage, and Lemmas F.1 and F.2 give the payout. $\square$

### G. Overlapped epochs

Closing must not pause payments. Let epoch $e$ be the predecessor and $e+1$ the successor. Because registration binds no root and two registrations may be outstanding (Section B.4), $\mathcal A_{e+1}$ exists while epoch $e$ is still being closed, certified, and admitted, so the two epochs serve concurrently during **draining**, the period from $\mathcal A_{e+1}$'s registration to the hard seal. The **cut** of an account is the first event fixing its final predecessor debit, and the **hard seal** is the operator action that cuts every remaining account, ends predecessor acceptance in every component, and must complete before close construction begins. An **execution shard** owns the mutable serving state of a contiguous account range, rollover is per account, and each shard seals its owned accounts before the close is built from any of them.

**Rules.**

1. **Cut.** For each account, either its first novel successor send atomically fixes its final predecessor debit and moves it to successor service, or the hard seal does so for accounts that never send. After the cut, novel predecessor sends from that account are stale, and exact retries return their original disposition.

2. **Seal discipline.** The hard seal ends predecessor acceptance in every component. After an account's cut no novel epoch-$e$ send is accepted from it, and after the hard seal no novel epoch-$e$ payment is accepted at all, so the close's terminal markers dominate every epoch-$e$ body the operator ever signs, with exact retries returning already-committed bodies.

3. **One-time boundary application.** The successor's sealed per-account adjustment $(f_a,w_a)$ applies exactly once to successor serving state, before the account's first successor send and never to predecessor commitments. An exact replay is a no-op, and conflicting bytes are rejected. From the operator's observation of a queued non-closing withdrawal, the account's outgoing sends freeze until the withdrawn amount is subtracted from its live balance, and a sealed full close freezes the account in both directions, which keeps its exhausting amount near the signed floor. Chain observation lags: a send accepted inside the lag can leave a close unable to satisfy the Admit re-check, and the operator restores affordability with a payment from an operator-controlled funded account before sealing.

4. **Reconciliation.** Let $\widetilde B_a$ be the preserved guarded balance after every accepted predecessor debit and every predecessor credit already imported, and for each predecessor component let $G^{\mathsf{term}}_{\kappa}$ and $G^{\mathsf{imp}}_{\kappa}$ be terminal and imported credit. The remaining predecessor credit is $\rho_a=\sum_\kappa G^{\mathsf{term}}_\kappa-\sum_\kappa G^{\mathsf{imp}}_\kappa\ge0$. Reconciliation atomically adds $\rho_a$ to $B_a^{\mathsf{live}}$ and sets every predecessor imported marker to its terminal, so it applies at most once and every later predecessor import is a no-op under Algorithm C.2's coordinatewise rule. It never assigns the predecessor close over the live head, which would erase accepted successor debits.

5. **Ownership moves.** The old owner is authoritative through hard seal. A new owner initializes from an authenticated, boundary-adjusted snapshot of the account's serving state. Routing changes are split-only: ranges may divide, and accounts are never remapped or merged across live owners.

**Lemma G.1 (exact close under overlap).** For every account, from its cut until its reconciliation, the canonical predecessor closing balance satisfies

$$
\boxed{B_a^1=\widetilde B_a+\rho_a,\qquad\rho_a\ge0,}
$$

except that a full close ends at $B_a^1=0$, its exhausting $w_a=x+\widetilde B_a+\rho_a$ absorbing the residue above its signed amount $x$.

*Proof.* At the cut, Lemma C.1 item 5 gives $\widetilde B_a=B_a^0+f_a-w_a-d_a+\sum_\kappa G^{\mathsf{imp}}_\kappa$, and $c_a=\sum_\kappa G^{\mathsf{term}}_\kappa$ is fixed by the seal discipline, so $\widetilde B_a+\rho_a$ equals the balance equation's $B_a^1$. For a full close, item 5's boundary-applied amount is the signed $x$ while the row's $w_a$ is the exhausting amount, so the same substitution closes the account at $B_a^1=0$ with $w_a=x+\widetilde B_a+\rho_a$. A later predecessor import moves one component's amount from $\rho_a$ into $\widetilde B_a$ without changing the sum, and successor events touch only successor state. Predecessor completion is one-sided: it can add unimported credit but can never discover another accepted debit, because debits end at the cut. Nonnegativity of $\rho_a$ holds because Algorithm C.2 imports only signature-verified tips, which the honest chain bounds by the terminal (Lemma C.1 item 2). A dishonest operator can break $\rho_a\ge0$ only by signing above its own published terminal, which is precisely the higher-tip challenge, not a serving invariant. $\square$

**Example (reconciliation).** At its cut, account $a$ has accepted one predecessor debit of 20 from an opening 100, so $\widetilde B_a=80$, while an accepted credit of 5 remains unimported, $\rho_a=5$, and the canonical close binds $B_a^1=85$ (Figure 5). The successor spends 20, reconciliation then adds $\rho_a$ for a live head of 65, and a further spend of 15 leaves $50=85-20-15$, with every successor debit preserved.

**Theorem G.1 (rollover equivalence).** An overlapped execution produces the same rows, roots, corpus, public-validity decision, and settlement transition for epoch $e$ as the serialized execution that accepts the same predecessor payments, seals the same boundary, and then serves the successor. A successful challenge against the predecessor invalidates its admitted descendants exactly as in Section F.

*Proof sketch.* Epoch-$e$ close values are a per-account function of the opening state, the sealed boundary, the accepted predecessor debit sequence, and the terminal component markers. Rule 1 fixes each account's debit terminal at a definite cut and rejects later predecessor mutations, rule 2 fixes the component terminals at hard seal, rule 3 keeps successor boundary effects out of predecessor inputs, and rule 4 only moves already-promised predecessor credit into the live head. Successor sends debit $B^{\mathsf{live}}$ below the predecessor close (Lemma G.1) and never touch predecessor markers, so adjacent successor events and predecessor close events operate on disjoint fields and commute. Rule 5 preserves one authoritative copy of every account's serving state across moves. Induction on exchanges of adjacent commuting events transforms any overlapped schedule into the serialized one with identical per-account inputs, hence an identical close. $\square$

### H. Assumptions, properties, and main theorems

#### H.1 Assumption summary

1. **Cryptography.** Assumptions SIG, CR, BIND (Section A.3).
2. **Chain and assets.** Authenticated state and time, ordered execution atomic across the chain and the asset layer, permissionless calls, inclusion within $\delta_{\mathsf{incl}}$ (Section A.2), and an asset adapter whose accepted destinations are payable (Section B.1).
3. **Validity.** The admitted evidence certifies $\mathsf{PublicValid}_e$: Lemma D.4 in quorum mode with at most $f_{\mathsf{val}}$ faulty validators, or a sound proof system or uncompromised TEE binding the objects of Section D.3.
4. **Availability.** Definition D.5, including the recovery allowance and the survivor-preimage lifetime.
5. **Discipline.** Per-party guarantees require that party to follow Definition E.2, and exit guarantees require the signed objects of Section F.
6. **Not assumed.** Operator liveness or honesty, honesty of any counterparty, or challenge-time cooperation from the operator.

Call evidence **timely disclosed** for epoch $e$ when it reaches the public corpus or the chain by $\Delta_e$.

#### H.2 Security properties

**Definition H.1 (security properties).** The protocol targets, per deployment:

1. **Exact settlement.** A finalized close changes exactly the committed row accounts, each to its committed closing state, and conserves liability against the sealed boundary.
2. **Payer debit safety.** No finalized close debits an account beyond a marker that account signed, even when the operator, all counterparties, and all faulty validators collude.
3. **Receipt coverage.** A finalized close dominates all timely-disclosed acknowledged evidence: public payer debits and component tips are coordinatewise upper bounds, with no intrinsic fault, infeasible range, or fork among committed and disclosed receipts.
4. **Solvency.** Custody always covers finalized liability plus every pipelined and pending boundary flow (Theorem F.1).
5. **Bounded exit.** An honest account can unilaterally force the deployment onto the terminal path and be paid its signed withdrawal from custody within a bound set by the pending windows (Theorem F.2).

**Theorem H.1 (clean finalization).** Under assumptions 1–4, if epoch $e$'s slot finalizes, then except with negligible probability:

1. $k\in\mathcal J_e\Longleftrightarrow\mathbf S_k^1\ne\mathbf S_k^0$, each row account closes at its committed $X_a^1$, and $L_{e+1}=L_e+F_e-W_e$.
2. Each account's closing debit is its opening marker or a payer-signed marker, and for an account following Definition E.2 it equals the maximum of its opening marker, the operator-acknowledged markers it retains, and the publicly committed terminal.
3. Each public component tip is coordinatewise no lower than every timely-disclosed tip retained by a holder following Definition E.2.
4. The committed and timely-disclosed receipt set contains no intrinsic fault, fork, or infeasible range that any party following Definition E.2 checks.

Items 2–4 are conditioned on assumption 5 for the holders of the evidence concerned: the guarantees cover exactly the disclosed evidence some disciplined party checks.

*Proof.* Admission verified the validity evidence, so $\mathsf{PublicValid}_e$ holds by assumption 3, and item 1 is Lemmas D.1 and D.2. For item 2's upper bound, any closing debit above the opening marker requires $\mathsf{Out}_a$ to be a matching pair whose send ends exactly at $D_a^1$ (Definition D.1 item 5), and matching requires the payer's signature, unforgeable under Assumption SIG. That terminal pair is itself operator-acknowledged and publicly committed, so the maximum in item 2 is attained, and a closing debit at the opening marker attains it trivially. For the lower bound and items 3 and 4: finalization implies no valid challenge was included by $\Delta_e$. By Theorem E.2 every violation a disciplined party detects yields a constructible, includable challenge, and Definition E.2 obligates that party to submit it, so no such violation existed. $\square$

Item 2's restriction to retained evidence is exactly Proposition E.1's limit: no validity mode proves the nonexistence of an additional private signature, so a receipt the operator never delivered to any holder sits outside every guarantee.

**Theorem H.2 (exit).** Under assumptions 1–5, bounded exit holds: Theorem F.2, with affordability from Lemma F.1 and exhaustion from Lemma F.2.

#### H.3 Costs

**Proposition H.1 (compression).** With row, pair, and digest sizes fixed by the profile:

1. $|\mathcal D_e|=\Theta(A+H_e+|\Phi_e|)$ with $|\Phi_e|=O(A\log(N/A))$ for $1\le A\le N$, all independent of $T$. For repeated payments over a fixed changed-account and component footprint, $(A+H_e+|\Phi_e|)/T\to0$.
2. The persistent chain record is the header, certificate, per-slot full-close amounts, and the consumed deposit- and withdrawal-identifier sets, the last linear in lifetime record count. The admission payload adds one terminal row opening, one row opening per full-close record, and the withdrawal re-check openings, $O(\log A)$ each plus $O(\log N)$ per queued withdrawal, of which at most one exists per account.
3. A challenge carries at most two signed pairs and lookups of $O(\log A+\log h_b+\log N)$ digests.
4. Terminal unwind authenticates $\Theta(N)$ records in one registry scan. Aggregating a dense invalid suffix costs $O(KN\log(N+1))$ work and $O(KN)$ retained boundary data in the worst case.

*Proof sketch.* Counting. Each changed account contributes one row, each terminal component one pair, and the paired opening one frontier digest per maximal omitted subtree, of which at most $O(A\log(N/A))$ exist for $A$ marked leaves in a balanced tree over $N$. Definition D.3 caps $A$ and $H_e$ independently of $T$. The unwind suffix bound covers recomputing per-slot boundary effects across at most $K$ unfinalized slots. $\square$

Two costs sit outside the proposition. Definition D.5's survivor-preimage obligation holds the complete $\Theta(N)$ state vector of each of the up to $K+1$ possible survivor roots throughout normal operation, distinct from item 4's unwind-time boundary data. Because withdrawals are never capped, a mass exit drives $\beta_e$, and with it the close, its corpus, and the per-full-close admission openings, to $\Theta(N)$, and concentrates up to $\Theta(N)$ released transfers into the single atomic Finalize and Unwind transitions covered by assumption 2 of Section H.1.

**Proposition H.2 (ordinary disclosure).** In a conforming close, an accepted pair appears in the public corpus if and only if it is its payer's terminal outgoing pair $\mathsf{Out}_a$ or the terminal entry of its receive component in $\mathbf Y_b$, directly from Definition D.1 items 5 and 6. Superseded pairs stay out of ordinary settlement, though a challenge may disclose retained pairs later, and the public deltas, receipt counts, and terminal pairs still reveal activity.
