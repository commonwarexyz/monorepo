---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-02T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/2/26): Each payer now signs one cumulative endpoint per epoch that covers every recipient it pays (many of which can now be paid at once). The close shrinks to one row per changed account and one entry per edge (each entry lives in its payer's own vector, so payments to a popular recipient never contend). Validators retain their slices of the state across closes and are dealt only the delta.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by one 32-byte commitment, 101 bytes with its certificate. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

For a given set of accounts, one payment or a bajillion costs the same to settle.

## Payments as Fast as Browsing the Web

Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

$a$'s persistent state $X_a$ is a balance $B_a$, a lifetime cumulative debit $D_a$, the cumulative credit $C_a$ the operator has promised it, the receipt count behind that credit, and a flag for whether the account is present in the live state. Credit stays a promise until the epoch ends, when the operator collates it (the next section explains why). $a$'s epoch activity is one strictly recipient-sorted vector $V_a$ with one cumulative entry per recipient it paid this epoch. The entry $(G,J)$ for $b$ is $a$'s cumulative credit to $b$ this epoch and the number of payments behind it. Before the payment, $a$ holds $B_a=100$ and $D_a=0$, and $V_a$ is empty.

To send $x>0$ from $a$ to $b$, the payer advances $b$'s entry in its own vector and signs the resulting endpoint, its cumulative position after this send: an epoch-local sequence number $n_a$, the lifetime cumulative debit, and the vector's Merkle root. The operator accepts by countersigning the same body:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

Here the endpoint is $n_a=1$, $D_a=20$, and the root of $V_a=\{b:(20,1)\}$. After authenticating $S$ and checking spendability, the operator atomically commits the debit, the entry advance, a close reservation, a replay record, and the acknowledgment body. The close is the settlement package the operator builds when the epoch ends, and the reservation holds room in it for this account's row and this edge's entry. The replay record lets a retried request return the same acknowledgment. The operator then countersigns and returns $R$ with one Merkle opening per advanced entry. It countersigns twice: an ordinary signature for the acknowledgment the payer holds, and an aggregable one the close later combines across many rows.

A send may batch entries: one signature advances strictly recipient-sorted, unique entries $(b_i,x_i)$ under one cumulative endpoint:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+\textstyle\sum_i x_i,\;\mathsf{root}(V_a\text{ with every }b_i\text{ advanced})\bigr).
$$

The operator accepts or rejects the batch as a whole and returns one acknowledgment covering every entry. A single payment is a batch of one.

The countersigned endpoint $R$ is the accepted payment. The preconfirmation for one recipient is an entry receipt: $R$ plus the opening of that recipient's entry under the acknowledged vector root. The payer verifies and durably retains $R$ and every opening, advances its local $D_a$ in the same atomic commit, then forwards each entry receipt to any recipient that will rely on it.

The wallet keeps at most one unacknowledged send in flight: it does not sign the next endpoint until the prior acknowledgment is verified and committed, and an operator-reported counter is never its authority. A rejection before the operator's commit changes no balance, and the wallet retains the staged request for retry. If the response is lost, retrying returns the same acknowledgment without a second debit. A later endpoint authorizes the whole debit delta up to its value, and the close carries only the payer's terminal endpoint, its last of the epoch. If a wallet signs several endpoints before obtaining the earlier acknowledgments, an intermediate acknowledgment may be neither held nor selected as that terminal, and that exposure is outside the base guarantee. This ordering serializes one payer account, not independent payers or recipients.

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
  .clearing-calculator {
    border: 1px solid #d6d6d6;
    border-radius: 6px;
    margin: 28px 0 6px;
    min-height: 560px;
    padding: 18px 20px 10px;
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
      border-left: 2px solid #d9251c;
      border-radius: 0;
      color: gray;
      min-height: auto;
      padding: 0 0 0 12px;
    }
  </style>
</noscript>
<div id="clearing-fig-payment" class="clearing-loop" role="img" aria-label="Animated message-sequence timeline of one accepted payment, with rows for payer a, the operator, and recipient b, and time measured in message delays. Payer a signs endpoint S paying b 20 and sends it to the operator. At one instant, with no network hop, the operator verifies S, commits atomically, moving a from 100 to 80 and the a-to-b vector entry from (0,0) to (20,1), and then countersigns acknowledgment R. The response returns to a, which retains R with the entry opening and forwards that entry receipt directly to recipient b with no operator hop.">
  <noscript>Account a sends one signed vector endpoint to one operator and receives one countersigned response. Verification, atomic storage, and countersigning are local operator steps, and the payment is accepted at the operator's commit while the response is still in flight. Afterward, a gives the acknowledgment and its entry opening directly to b without another operator hop.</noscript>
</div>
<script type="module" src="clearing.loops.js"></script>
```

::: {.image-caption}
Figure 1: The payer sends one request and receives one countersigned response. The operator verifies, commits, and signs locally, adding no network round trip. The commit moves $a$ from 100 to 80 and advances the $a\rightarrow b$ entry in $a$'s vector from $(0,0)$ to $(20,1)$ before $R$ exists. Once $R$ returns, $a$ sends the entry receipt, $R$ plus $b$'s entry opening, directly to $b$ as transferable evidence.
:::

## Optimizing for Hot Accounts

A single incoming counter would serialize every payment to a popular recipient. Bajillion has none: acceptance touches only the payer's side, so recipients have no state to serialize. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry in $a$'s vector:

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

Credit is collated at the close instead of per payment. Each payer's vector as it stands when the epoch ends is its terminal vector (terminal means end-of-epoch throughout). The operator re-sorts the union of terminal entries by recipient and then payer into the transpose, the same entries viewed recipient-major and committed under $\mathsf{TransposeRoot}_e$, where each recipient's entries form one contiguous range. $b$'s range holds those three entries, and its sum is $b$'s credit delta: $20+4+6=30$ over 3 payments. Proving one edge never requires shipping the rest: the payer-side entry opens under its payer's signed vector root, and the recipient-side image under the transpose root.

## Epochs, Closes, and the Queue

An epoch ends at a cut. Everything accepted before the cut belongs to epoch $e$, and the operator builds epoch $e$'s close: one row per changed account, a handful of Merkle roots over the rows and the resulting state, and the proofs that let validators check it. Later sections build that close. This one covers how it reaches the chain.

The operator is Byzantine: it may halt, censor, equivocate, withhold messages, and propose arbitrary closes, but it cannot forge a payer signature. Bajillion assumes secure hashes and signatures, authenticated validator proofs of possession, at most $f$ Byzantine validators in a committee of exactly $n=3f+1$, and a correct and live settlement chain. Honest validators authenticate and durably retain their assigned share of each close before voting for it. The embedding, the chain-side integration that hosts a deployment, must keep the root bundle, public corpus, and required Merkle openings retrievable for as long as they can be challenged or claimed.

A deployment starts from an authenticated account vector, and each epoch uses an onchain anchor $\mathcal A_e$. Before acknowledging any payment of epoch $e$, the operator must register the epoch onchain against the exact predecessor $\mathsf{StateRoot}$, the root the previous close produced. Registration also seals the epoch's boundary: the deposits and signed withdrawal authorizations the chain fixes for this epoch, which the close must consume exactly. An accepted registration is one immutable admission obligation. Construction, certification, and admission may retry against it through the inclusive deadline, but the first later observation permanently faults the deployment. The $\mathsf{OPEN}$ registration slot has no heartbeat. A successor epoch can be registered and prepared while its predecessor remains challengeable.

Admission checks the certificate over the close's 32-byte commitment, consuming a 164-byte root bundle and one compact terminal proof as witness data, then places the close in a FIFO queue of pending slots. Each slot waits through an inclusive challenge window ending at its deadline $\Delta_e$, and slots finalize in order from the front. A proven challenge blocks the challenged slot and every pending descendant from finalizing, while earlier pending slots keep their windows and may still finalize in order. A withdrawal carried by a close becomes claimable only after that close reaches the front and finalizes.

The deployment fixes the maximum admission-delay increment and the minimum and maximum challenge duration before it accepts funds, while deposits and user-signed withdrawals carry their own deadlines. Every accepted deposit must enter an admitted close before its deadline. Settlement records each deposit's refund account and amount, so an expired unadmitted deposit is refundable by anyone without an operator, a state opening, or private evidence. A missed admission, an expired withdrawal or deposit, or a proven challenge permanently faults the deployment, freezing new work and moving every account to the recovery path in [Hard Fault](#hard-fault).

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
<div id="clearing-fig-rollover" class="clearing-loop" role="img" aria-label="Animated owner-preserved rollover for account a. An accepted epoch-e send leaves one preserved head of 80 and rotates that head into epoch e plus 1. Two connected rails branch from the same 80. The exact predecessor close reaches 85. The live successor rail spends 20 to reach 60, reconciles to 65, and spends 15 to reach 50. One vertical marker identifies the same missing predecessor credit of 5 in both calculations. The 85 close terminates on its own rail and never overwrites the live head.">
  <noscript>An accepted epoch-e send leaves one preserved head of 80. The exact-close rail computes 80 plus 5 as 85. The live rail computes 80 minus 20 plus the same 5 minus 15 as 50. Reconciliation adds the shared missing credit without installing 85 over the live head.</noscript>
</div>
```

::: {.image-caption}
Figure 2: Both rails branch from the same preserved 80. The upper rail computes the exact epoch-$e$ close, $80+\rho_a=85$. The lower rail keeps the epoch-$e+1$ head live, $80-20+\rho_a-15=50$. The single vertical $\rho_a=5$ marker is the same predecessor credit in both calculations. The two values serve different roles: 85 is the canonical predecessor close, while 50 is the current live head. Reconciliation adds $\rho_a$ to the live value and preserves every successor debit.
:::

The live balance is not monotone, since successor payments spend it down. The one-sidedness is all on the predecessor's side: completion can add missing credit but can never discover another accepted debit. Boundary operations and credit imports obey the same rule: the live head is only ever adjusted, never overwritten.

Rollover changes only live serving state, without changing the evidence required for finalization. The close still produces the canonical rows, state root, and public corpus, and a challenge against the predecessor still invalidates its pending descendants.

## One Row per Changed Account

Netting each of the four accounts' debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross debit equals gross credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. That is all the payments add to the close: not six payments, but the four accounts they changed, one row each.

Write the predecessor and successor states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. The sealed boundary assigns $a$ a deposit $f_a$ and a withdrawal $w_a$, and $p_a$ is credit paid externally because the recipient is absent from the live state. The exact balance relation is

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

For an account already in the state, $p_a=0$. For a recipient absent from the predecessor state with no deposit, $B_a^0=B_a^1=0$ and $p_a=c_a$: the accepted sends become one net external-payout claim when the close finalizes, without creating a zero-balance account. This is how someone not registered with the operator gets paid. The operator accepts the sends normally and records one row whose output names the recipient and net amount. Had $a$ also paid an unregistered $e$ 10, $e$'s row would carry $c_e=p_e=10$ with both balances zero, and $e$ would claim the 10 from the chain once the close finalizes. The same holds for payments to an account after its close removes it at the cut: the identity is absent from the successor state, so those sends become external payouts rather than recreating the account. To custody this is a netted withdrawal. To the sender it is an ordinary preconfirmed payment.

Each row also carries a settlement output $o_a$ that validators recompute from the same authenticated effect. An account close, the signed exit in [A Deadline to Exit](#a-deadline-to-exit), has a withdrawal output even when its epoch-tail balance is zero, so the leaf still authenticates the close action while releasing no funds:

$$
o_a=
\begin{cases}
\mathsf{withdrawal}(w_a), & \text{if the row consumes a withdrawal record},\\
\mathsf{external}(p_a), & \text{if }p_a>0,\\
\mathsf{none}, & \text{otherwise.}
\end{cases}
$$

The withdrawal outputs form their own Merkle tree under $\mathsf{WithdrawalOutputRoot}_e$, and a claim later opens one leaf of it and nothing else.

The row binds both account states and, exactly when the account sent, the terminal payer-signed endpoint $\mathsf{Out}_a$. It also carries a running total $\mathsf{prefix}_a$ over the sorted rows so far, with three counters beside the value totals: $\chi$ flags a withdrawal record, $\varepsilon$ counts the row's vector entries, and $\iota$ counts its transpose entries. The prefix is what lets a validator check one slice of rows without seeing the others:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;p_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;\varepsilon_{a'},\;\iota_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;o_a,\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

The signed vector root rides inside $\mathsf{Out}_a$, so a sending row carries its whole epoch fan-out under one signature. The operator's acceptance is not stored per row: its aggregable countersignatures combine into one per slice, checked at sealing.

Each prefix must extend the preceding prefix exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

$$
\mathbf A_e=(\mathsf{Row}_a,\;\mathsf{Row}_b,\;\mathsf{Row}_c,\;\mathsf{Row}_d),
\qquad a<b<c<d.
$$

Prefix continuity ties the epoch totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the sealed boundary. Every withdrawal releases its authorized amount exactly when the row tail covers it and nothing otherwise, and every account close sweeps its epoch tail. The totals must respect the deployment's close limits (maximum rows, entries, and value totals) and conserve payments:

$$
\boxed{D_e=C_e.}
$$

Here $D_e=C_e=54$. Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e-P_e.}
$$

With no boundary flows, $L_{e+1}=L_e=200$.

## Rebuild the Live State

A $\mathsf{StateRoot}$ commits every field and the exact length of the strictly sorted vector of live accounts in a binary Merkle tree (BMT). A live leaf has a positive balance: a deposit can insert an account, an account close removes one, and any other zero balance also leaves no leaf. There are no zero-balance tombstones.

$$
\mathbf X_e=\bigl((a,X_a^0):B_a^0>0\bigr)_{\text{sorted by }a},
\qquad
\mathbf X_e\xrightarrow{\ \mathsf{BMT}\ }\mathsf{StateRoot}_e.
$$

Writing only the balances, the example has $\mathbf X_e=((a,100),(b,40),(c,25),(d,35))$ and $\mathbf X_{e+1}=((a,85),(b,58),(c,26),(d,31))$.

At a close, the operator merges the changed rows with the unchanged live leaves and rebuilds both state BMTs from the resulting ordered streams:

$$
\begin{aligned}
\mathbf X_e&=\mathsf{merge}\bigl(\mathsf{unchanged}_e,\;(a,X_a^0)_{a\in\mathbf A_e,\ B_a^0>0}\bigr),\\[0.3em]
\mathbf X_{e+1}&=\mathsf{merge}\bigl(\mathsf{unchanged}_e,\;(a,X_a^1)_{a\in\mathbf A_e,\ B_a^1>0}\bigr).
\end{aligned}
$$

Both roots are rebuilt fresh rather than maintained as a versioned authenticated trie, a trade weighed at the end of the post.

Beside the two state roots, the close commits one compact guard per row under $\mathsf{ChangeRoot}_e$. Challenges and external-payout claims open this tree rather than the full rows, so it exposes only what they need ([The Unavoidable Challenge](#the-unavoidable-challenge) gives its contents).

## Slice the Evidence

Validators do not each check the whole close. The evidence is divided into $S$ deterministic account-key slices (256 in the benchmarks) and dealt among validators. A span is the contiguous slices one validator holds, a proof slice is the evidence for one span with its openings, and a validator's dealing is its one or two proof slices.

Authenticating each slice alone would not prove their union has no gaps or overlaps, so $\mathsf{CoverageRoot}_e$ commits their shared boundaries. For $S$ slices, $S+1$ boundaries fix where each cut falls in the predecessor state ($\alpha_j$), the change vector ($\beta_j$), and the successor state ($\gamma_j$), plus the cumulative prefix and two running accumulator checksums $u_j$ and $v_j$ at the cut:

$$
\mathsf{Coverage}_e=\bigl((\alpha_j,\beta_j,\gamma_j,\mathsf{prefix}_j,u_j,v_j)\bigr)_{j=0}^{S}
\xrightarrow{\ \mathsf{BMT}\ }
\mathsf{CoverageRoot}_e.
$$

Take $S=2$ with slice 1 holding $\{a,b\}$ and slice 2 holding $\{c,d\}$. The boundary between them carries the prefix after $b$: debit $20+12=32$ and credit $5+30=35$, which need not balance. Slice 2 resumes from that prefix, adds $c$ and $d$, and must land on the terminal prefix, where $54=54$ must hold. Each slice checks its rows against the boundaries on either side and needs none of the others' rows.

The checksums let the committee verify the transpose piecewise. Every terminal edge folds one canonical key (payer, recipient, cumulative credit, count) into an order-independent lattice-hash multiset accumulator: $u$ over the vector entries in payer-major order and $v$ over the transpose entries in recipient-major order. Here $u$ folds the six edges in payer order, $a\rightarrow b$, $b\rightarrow c$, $c\rightarrow b$, $c\rightarrow d$, $d\rightarrow a$, $d\rightarrow b$, while $v$ folds the same six in recipient order, $d\rightarrow a$, $a\rightarrow b$, $c\rightarrow b$, $d\rightarrow b$, $b\rightarrow c$, $c\rightarrow d$. Same multiset, same value. Each slice resumes both accumulators from its opening boundary, folds its own entries, and must land exactly on its closing boundary. Terminal equality $u_S=v_S$ then proves the transpose is a permutation of the union of the payer vectors, so every promised credit is backed by exactly one payer-signed entry: double-entry bookkeeping as a multiset equation, verified without any validator seeing both sides of an edge.

A proof slice covers a contiguous span of slices and opens every boundary in the span under one range opening, so the span is gap-free against its neighbors. Every holder checks each internal boundary in full: the rows and leaves before it advance the committed positions exactly, and the running prefix and checksums land on it. The withdrawal, vector-entry, and transpose-entry counts in the same prefixes select the span's exact ranges under $\mathsf{WithdrawalOutputRoot}_e$ and $\mathsf{TransposeRoot}_e$. A terminal coverage proof authenticates the final counts and totals.

The coverage root thus binds each slice's exact positions in both state vectors, the change vector, and the transpose, so account insertion and deletion cannot create a gap or overlap between dealings.

The predecessor state root belongs to $\mathsf{CloseContext}_e$, with the deployment, epoch, anchor, operator, sealed boundary roots, predecessor liability, deadlines, and close limits. Five roots and the transpose length form the 164-byte root bundle, the admission witness the chain checks but does not retain. The 32-byte header binds every root in its contextual role:

$$
\begin{aligned}
\mathsf{RootBundle}_e
&=\bigl(\mathsf{ChangeRoot}_e,\;\mathsf{WithdrawalOutputRoot}_e,\;\mathsf{StateRoot}_{e+1},\\
&\qquad\;\mathsf{CoverageRoot}_e,\;\mathsf{TransposeRoot}_e,\;\ell_e\bigr),\\[0.3em]
\mathsf{Commitment}_e=\mathsf{Header}_e
&=H\!\bigl(\mathsf{CloseContext}_e\parallel\mathsf{ChangeRoot}_e\parallel\mathsf{WithdrawalOutputRoot}_e\parallel\mathsf{StateRoot}_{e+1}\\
&\qquad\;\parallel\mathsf{CoverageRoot}_e\parallel\mathsf{TransposeRoot}_e\parallel\ell_e\bigr).
\end{aligned}
$$

The transpose length $\ell_e$ closes a wedge: slice openings prove membership but cannot see past their own range, so without it a certified transpose could carry trailing leaves no slice opens. The terminal boundary requires $\ell_e$ to equal its transpose-entry count. The terminal prefix carries gross debit $D_e$, credit $C_e$, external payouts $P_e$, deposits $F_e$, and withdrawals $W_e$, with the row, withdrawal-record, and entry counts alongside, and one terminal coverage proof authenticates those totals without listing their recipients. Neither the root bundle nor the terminal proof counts toward the 32-byte commitment figure. The live leaves, vectors, rows, withdrawal outputs, and remaining openings stay offchain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Seal Every Dealing Up Front

Before the chain queues a close for finalization, the operator disseminates each validator's dealing. Slice $s$ of $S$ is held by the $q$ consecutive validators starting at $\lfloor ns/S\rfloor$ around the validator ring, so the window slides with the slice index. A validator's slices therefore form one contiguous span, or two when the window wraps past the last slice, and the accumulator start states and range openings travel once per span rather than once per slice.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-ring-assignment.svg" alt="Left: sixteen validators on a ring with three quorum windows of eleven drawn as arcs for slices 0, 5, and 10; each window starts one validator later than the previous slice's. Right: a grid of slices against validators in which every column has eleven holders and every row is one contiguous span, or two when the window wraps past the last slice.">
```

::: {.image-caption}
Figure 3: Slice holders slide around the validator ring. With $n=S=16$ validators and a quorum of $q=11$, slice $s$ is held by the eleven validators starting at $\lfloor 16s/16\rfloor = s$, so consecutive slices share most of their holders (left). Seen per validator (right), every row is one contiguous span of slices, or two when the window wraps past the last slice, and every column still has exactly eleven holders.
:::

Sealing is not a totals-only check. A validator authenticates every assigned span: the coverage and state ranges in its slices, every changed-account equation and settlement output, every terminal payer-signed endpoint and vector, its transpose interval, and the accumulator, prefix, and state transitions at every covered boundary. It verifies each slice's combined operator countersignature and every distinct payer authorization across the dealing in one randomized batch. The terminal boundary then binds the vector lengths, deposits, withdrawals, external payouts, payment conservation, the multiset equality between the two edge orderings, and successor liability. Having checked all of that, the validator retains the evidence through the challenge deadline and only then seals the shared commitment. No validator needs the complete corpus, but the assignments cover it exactly.

Every certificate signer signs the same commitment. Each slice is assigned to a quorum of validators who authenticate and retain it. Quorum intersection guarantees that an honest signer authenticated and retains each slice, though that signer may differ by slice. With $n$ validators, $f$ tolerated faults, and quorum $q$, every slice $j$'s holders share more than $f$ validators with the certificate's signers:

$$
\begin{aligned}
n&=100,\qquad f=33,\qquad q=2f+1=67,\\[0.3em]
|\mathsf{signers}\;\cap\;\mathsf{holders}_j|&\;\ge\;2q-n=34>f.
\end{aligned}
$$

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator certified package is 101 bytes. If the validators are also the settlement chain's, inclusion itself supplies the attestation and only the 32-byte commitment need be retained.

## Fault and Availability Model

Certification establishes that the bound corpus satisfies the public relation: every row, boundary, signature, and total checks out. It cannot establish that the operator never countersigned an endpoint outside that corpus. The next section shows why no verifier can, and what a holder does about it.

The entry receipt is private, transferable evidence. Any holder may challenge, not only the payer or recipient, and neither must stay continuously online. The availability assumption is per acknowledgment: at least one honest holder must retain the acknowledgment or entry receipt and get the bounded challenge included by $\Delta_e$. A recipient that wants an independently enforceable preconfirmation obtains its entry receipt before relying on it. Honest validators retain the public proof slices but cannot reconstruct private evidence no holder received. This is not a single global observer assumption: different edges may depend on different holders. The configured challenge duration therefore trades clean-settlement latency against how long a holder may stay offline.

## The Unavoidable Challenge

This is the omission problem from the introduction, and no certifier solves it. Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator countersigns exactly the acknowledgments represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid acknowledgment $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

So the close must expose exactly what a holder needs to contradict it. That is the guard committed per row under $\mathsf{ChangeRoot}_e$:

$$
\begin{aligned}
\mathsf{ChangeValue}_a
&=\bigl(o_a,\;D_a^1,\;n_a,\;\mathsf{OutDigest}_a,\;\mathsf{root}(V_a)\bigr),\\
\mathsf{ChangeGuard}_a
&=\bigl(a,\;H(\textsf{change-value}\parallel\mathsf{encode}(\mathsf{ChangeValue}_a))\bigr),\\
\mathbf C_e
&=\bigl(\mathsf{ChangeGuard}_a\bigr)_{\mathsf{Row}_a\in\mathbf A_e},\\
\mathbf C_e
\xrightarrow{\ \mathsf{Merkle}\ }
\mathsf{ChangeRoot}_e.
\end{aligned}
$$

The $\mathsf{ChangeValue}$ is the settlement output, terminal debit, terminal sequence number, endpoint-body digest, and terminal vector root, where $\mathsf{OutDigest}_a$ binds the unsigned terminal endpoint body (or a distinguished absence). Together they pin the exact acknowledged terminal a challenger contradicts. Validators still check the complete row in the proof-slice corpus, but the change tree commits only this projection, and its digested guard keeps range boundaries compact.

Every retained acknowledgment in challenge evidence carries both payer and operator signatures over one endpoint body. Through the inclusive deadline $t\le\Delta_e$, any holder may submit one of three bounded contradictions. In the example, $a$'s public terminal is $n_a=1$, $D_a=20$, and the entry $b:(20,1)$.

1. **Higher acknowledged debit** ($\mathsf{HigherAckDebit}$). A retained dual-signed endpoint carries a cumulative debit above the public terminal debit, a different countersigned body at the committed terminal sequence number, or an equal endpoint at a strictly later sequence. A retained $R$ at $n_a=2$ with $D_a=35$ is one. A bare payer authorization is insufficient, since only the countersignature proves operator acknowledgment.

2. **Higher acknowledged entry** ($\mathsf{HigherAckEntry}$). Authenticate the public terminal entry $(G^\star,J^\star)$ for one edge under the sender row's committed vector root, using $(0,0)$ for authenticated absence, and present a retained entry $(G^+,J^+)$ opened under its own acknowledged root. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction. A retained opening of $b:(30,2)$ under $a$'s acknowledged root contradicts the public $(20,1)$.

3. **Acknowledgment fork** ($\mathsf{AckFork}$). Two distinct operator-countersigned endpoint bodies at one payer sequence number, such as two countersigned bodies at $n_a=1$. Only the operator countersignatures need to verify, since a fork is the operator's fault whatever produced the payer halves. Different signature bytes over one identical body are not a fork.

Every challenge compares one retained acknowledgment against one terminal opening, so no challenge has to range over intermediate receipts.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. So every account can queue a unilateral signed authorization directly onchain, either to withdraw an exact amount or to close the account. The queue is only the censorship fallback: an uncensored user hands the same authorization to the operator, which carries it inside the next close's sealed boundary, so the happy-path exit costs one onchain transaction, the claim.

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;\omega,\;\tau\bigr),
\qquad
\omega\in\bigl\{\mathsf{withdraw}(x)\mid x>0\bigr\}\cup\bigl\{\mathsf{close}\bigr\}.
$$

$Q$ names the finalized root $\mathsf{rt}_z$ it was signed against, where $z$ indexes the last finalized close, a destination $v$, an operation $\omega$, and an absolute deadline $\tau$. A withdrawal settles all or nothing: it releases exactly $x$ when the epoch tail covers it and otherwise releases nothing and leaves the balance in the account. A close carries no amount. The operator neither submits nor approves $Q$, and its cooperation decides only whether the authorization settles through a clean close or through hard-fault settlement.

Queueing authenticates $Q$ against the finalized root, and every pending close that could still finalize must carry it forward. The next close commits both the already-onchain signed authorization and the changed account row.

An operator-carried authorization enters the sealed boundary at registration instead. It is validated against the same finalized root, destination rules, and notice window (the deployment's bounds on how far ahead $\tau$ may sit), plus one predecessor-root opening proving the account can cover it, and its replay identity is consumed at admission. It needs no proofs against every root that can still finalize, because it binds one specific close and settles all or nothing there.

An account close does not freeze the account: it keeps sending and receiving until the cut, which sweeps its epoch-tail balance and omits it from the successor state:

$$
\boxed{w_a=B_a^0+f_a+c_a-d_a,\qquad B_a^1=0.}
$$

Had $a$ closed its account in epoch $e$, the sweep would be $w_a=100+0+5-20=85$ with $B_a^1=0$.

After clean finalization, $\mathsf{withdraw}(x)$ and $\mathsf{close}$ use the same claim: the validator-derived $\{\mathsf{destination},\mathsf{amount}\}$ plus one opening under $\mathsf{WithdrawalOutputRoot}_e$, without retransmitting the signed request. For $\mathsf{close}$, validators derive the amount from the epoch tail, so $a$'s claim would be $\{v,85\}$ plus one opening. External payouts, the $p_a$ rows, claim the same way: each recipient presents its $\{\mathsf{account},\mathsf{ChangeValue}\}$ projection and $\mathsf{ChangeRoot}_e$ opening. The chain keys replay protection by finalized batch and row position, so no recipient list or all-payout multiproof enters settlement and no post-deadline crank fans payments out. Claim size is the destination plus the amount and one logarithmic opening, measured below.

What makes the exit credible is that custody never leaves the chain early. Let $R_z$ be the reserve for finalized but unclaimed withdrawals and external payouts. With finalized liability $L_z$, pending slots $z+1,\ldots,m$ carrying boundary flows $(F_i,W_i,P_i)$, and deposits not yet included in a pending close $F_\star$:

$$
\boxed{
E=L_z+R_z+\sum_{i=z+1}^{m}F_i+F_\star
=L_m+R_z+\sum_{i=z+1}^{m}(W_i+P_i)+F_\star.
}
$$

Withdrawals and external payouts stay in active custody until their slot finalizes at the queue front, when their aggregate value moves into $R_z$. Individual claims reduce that reserve and the chain's assets together. Finalization touches only totals and roots, so its work does not grow with the number of recipients, and a challenged or invalidated suffix creates no reserve. The operator can stop serving payments, but it cannot take funds or send them without authorization.

## Hard Fault

If a registered close misses admission, $Q$ is still unfinalized at $t\ge\tau$, an accepted deposit remains outside an admitted close past its deadline, or a challenge is proven, the first time-aware onchain call permanently freezes new work. This is the hard fault.

Pending deposit refunds remain independently claimable. The pending prefix resolves from the front, finalizing eligible clean slots, while a challenged or invalidated suffix never finalizes. Hard-fault settlement then freezes the last finalized state root.

Acknowledged sends that existed only in a never-admitted registration or invalidated suffix do not debit that root. Each sender recovers its finalized balance exactly once through a replay-protected state opening. An outstanding authorization the frozen balance covers routes its amount to the signed destination and returns the residual to the account, while one it cannot cover returns the whole balance. Reserves from earlier clean finalizations remain separately claimable, so recovery needs neither an all-account scan nor a global payout crank.

Hard-fault recovery needs no operator, but claimants still need their openings against the frozen root, which must remain available until each position is claimed, and the settlement integration must atomically persist each claim with its custody effect. The protocol supplies neither a historical witness store nor a terminal-claim deadline.

## The Close Never Grows (with Payments)

Every profile below uses a 100-validator committee and 256 slices. Prepare, deal, seal, and challenge checks share one adaptive eight-worker pool (AWS c8a.4xlarge), while certificate and withdrawal-claim checks are scalar calling-thread measurements. The first matrix varies $N$, the number of live accounts: every account sends one entry and the same 512 accounts receive, so with $A$ changed accounts and $B$ distinct recipients the fixture holds $A=N$ and $B=512$ as $N$ grows from 1,024 to one million. A second matrix holds $N$ at one million while the active accounts shrink.

Four quantities appear in the tables. The posted close is what a reader holding the previous certified state must download: live accounts ride as one-or-two-byte rank gaps, and the transpose, both states, and prefixes are derived rather than shipped. The proof-slice corpus is the complete evidence, the union of all 256 proof slices with every row, both state leaf sets, and every opening. The largest dealing is the busiest validator's share of it, one proof slice per span with no unchanged leaves, since every validator retains its key interval across closes and hydrates each dealing against it. The external certified package is the commitment and certificate.

No payment count appears because none is needed: rows and vector entries carry cumulative totals, so every size in the table is the same for any $T$. Every fixture send is a batch of one entry. Each further entry in a terminal batch adds 48 bytes to its committed vector (and its transpose image to the dealt slices), still independent of $T$.

Each stage is measured independently and follows the pipeline: the operator prepares the roots and deals the evidence into slices, each validator seals its dealing by checking and retaining its slices before signing the commitment, and a holder with evidence of fraud disputes the certified commitment with a challenge the chain checks. The fixture builds the predecessor-state proof cache before measurement. Prepare builds the change, withdrawal-output, successor-state, coverage, and transpose roots from the close inputs, reusing that cache. Deal produces every validator's dealing: each slice's rows, entries, and transpose entries are encoded once as a chunk, and each span's dealing is a small witness plus references to its chunks, so the measured time covers every chunk and every witness. The network path sends those buffers without copying. Seal checks and retains the busiest validator's dealing, verifies its countersignatures and payer authorizations in one randomized batch, and signs the commitment. Percentages in the certification rows are relative to the proof-slice corpus.

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
      <td style="padding-left:20px;">posted close</td>
      <td style="text-align:right;">85.8 KB</td>
      <td style="text-align:right;">730 KB</td>
      <td style="text-align:right;">7.19 MB</td>
      <td style="text-align:right;">71.8 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">proof-slice corpus</td>
      <td style="text-align:right;">2.07 MB</td>
      <td style="text-align:right;">6.35 MB</td>
      <td style="text-align:right;">48.8 MB</td>
      <td style="text-align:right;">473 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">2.51 ms</td>
      <td style="text-align:right;">20.4 ms</td>
      <td style="text-align:right;">183 ms</td>
      <td style="text-align:right;">1.88 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">deal</td>
      <td style="text-align:right;">4.66 ms</td>
      <td style="text-align:right;">4.91 ms</td>
      <td style="text-align:right;">8.21 ms</td>
      <td style="text-align:right;">46.1 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Certification</th></tr>
    <tr>
      <td style="padding-left:20px;">largest dealing</td>
      <td style="text-align:right;">155 KB <span style="color:#666;">(-92.5%)</span></td>
      <td style="text-align:right;">1.08 MB <span style="color:#666;">(-83.0%)</span></td>
      <td style="text-align:right;">10.3 MB <span style="color:#666;">(-78.8%)</span></td>
      <td style="text-align:right;">103 MB <span style="color:#666;">(-78.3%)</span></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">17.7 ms</td>
      <td style="text-align:right;">63.0 ms</td>
      <td style="text-align:right;">493 ms</td>
      <td style="text-align:right;">5.78 s</td>
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
      <td style="text-align:right;"><strong>0.278 ms</strong></td>
      <td style="text-align:right;"><strong>0.273 ms</strong></td>
      <td style="text-align:right;"><strong>0.269 ms</strong></td>
      <td style="text-align:right;"><strong>0.271 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check HigherAckEntry</td>
      <td style="text-align:right;"><strong>0.332 ms</strong></td>
      <td style="text-align:right;"><strong>0.326 ms</strong></td>
      <td style="text-align:right;"><strong>0.322 ms</strong></td>
      <td style="text-align:right;"><strong>0.324 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check AckFork</td>
      <td style="text-align:right;"><strong>0.324 ms</strong></td>
      <td style="text-align:right;"><strong>0.323 ms</strong></td>
      <td style="text-align:right;"><strong>0.320 ms</strong></td>
      <td style="text-align:right;"><strong>0.318 ms</strong></td>
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

The busiest validator's dealing is 78 to 93% smaller than the proof-slice corpus even though it holds two thirds of the slices. The corpus carries every row with both states and its prefix plus both state leaf sets, about 473 bytes per row at one million accounts. The dealt wire carries the movers and edges, one witness (accumulator start states and range openings) per span, and no unchanged leaves, about 155 bytes per row the busiest validator holds. At one million live accounts it checks 103 MB rather than the 473 MB corpus. That is the every-account-sends worst case, and it hides the real lever: dealings travel without unchanged state. When every account changes there is nothing to strip. When the movers are a fraction of the account set, the posted close and the dealt wire follow the movers:

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Stage</th>
      <th colspan="4" style="text-align:center;">Active accounts (<em>A</em>) at <em>N</em> = 1,000,000</th>
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
      <td style="padding-left:20px;">largest dealing</td>
      <td style="text-align:right;"><strong>182 KB</strong></td>
      <td style="text-align:right;"><strong>1.40 MB</strong></td>
      <td style="text-align:right;"><strong>13.6 MB</strong></td>
      <td style="text-align:right;">103 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">168 ms</td>
      <td style="text-align:right;">199 ms</td>
      <td style="text-align:right;">338 ms</td>
      <td style="text-align:right;">1.88 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">191 ms</td>
      <td style="text-align:right;">553 ms</td>
      <td style="text-align:right;">1.61 s</td>
      <td style="text-align:right;">5.78 s</td>
    </tr>
  </tbody>
</table>
</div>
```

The posted close is about 72 bytes per active account plus its edges, whatever the account set holds: at 1,024 movers among one million accounts it is 74.0 KB, a thousandth of the every-account column. The dealt wire keeps one span witness and its slices' row evidence but no unchanged leaves, so the busiest dealing falls from 103 MB to 182 KB across the same sweep. Prepare keeps a fixed cost in $N$ (the state BMTs are rebuilt over all live leaves), while deal and seal follow the movers: deal encodes only changed rows and edges, and signature verification dominates seal.

The proof-slice corpus is constant for a profile, so accepted payments only divide it. Ten million payments spread the one-million-account profile's 472,797,104 bytes to 47.3 offchain bytes per payment, and its 71,762,697-byte posted close to 7.2. A billion payments spread them to 0.473 and 0.072. The 101-byte certified package and the 164-byte root bundle shrink the same way, as $1/T$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows proof-slice corpus bytes per payment for four live-account counts; the right shows the 101-byte external certified package. Every line falls as one over T.">
```

::: {.image-caption}
Figure 5: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The proof-slice corpus (left) grows with the live-account count $N$. The external certified package (right) stays 101 bytes across profiles.
:::

The higher-acknowledged-debit and higher-acknowledged-entry challenges carry one retained acknowledgment plus one changed-row lookup, so they grow with opening depth: 620 to 940 and 671 to 991 bytes across the matrix, checking in 0.269 to 0.332 ms. The acknowledgment fork carries two countersigned endpoints and no state opening, so it holds at 417 bytes for every $N$ and checks in about 0.321 ms. Adjudication is signature-dominated, and the evidence is one fixed-size acknowledgment plus at most one entry opening: an endpoint commits its whole batch through the vector root, so an entry from a larger batch changes nothing about the witness or its check. Clean closes submit no challenge at all, so average challenge traffic is smaller still. A challenge targets a commitment whose certificate was already checked at admission, so adjudication does not verify it again.

Withdrawal claims scale with the claimed close's own withdrawal count $W$, never $N$, because each opens only that close's withdrawal-output tree, and an external-payout claim likewise opens one leaf of its change tree. The certified close above queues no withdrawals, so separate fixtures use a 21-byte destination, once with a single withdrawal output and once with a surge in which all $N$ accounts exit through one close. At $W=1$ a $\mathsf{withdraw}$ or $\mathsf{close}$ claim is 39 bytes and verifies in 0.313 µs on the same c8a.4xlarge. The opening adds one 32-byte sibling per doubling of $W$, so a surge barely moves it: 359 bytes when 1,024 accounts exit together and 679 bytes when one million do, with verification adding only the twenty path hashes.

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

## A Bajillion Payments, One Settlement

The operator's online work scales with payments: it verifies, durably commits, and signs every one of the $T$ payments it accepts. The close has no per-payment term. Writing $U$ for unchanged live leaves, $A$ for changed rows, $E$ for edge entries, $W$ for withdrawal outputs, $S$ for proof slices, and $M$ for the largest committed vector length, its authenticated corpus is

$$
\text{payments }T
\quad\longrightarrow\quad
U\text{ state leaves}+A\text{ rows}+E\text{ vector entries}+E\text{ transpose entries}
+W\text{ withdrawal outputs}+(S+1)\text{ coverage boundaries}+O(S\log M)\text{ openings},
$$

and the posted close omits $U$, the transpose, and every derivable column. For the benchmark's fixed live set, $U=N-A$, though account creation, deletion, and external-payout rows break that identity in general. For repeated activity over a fixed set of accounts and edges, this corpus divided by $T$ tends to zero. Account-level clearing compresses repetition, not state: every unchanged account contributes a leaf to the corpus and nothing to the posted close, every changed account a row, and every edge one cumulative entry on each side, but additional payments between them add nothing. No traffic pattern adds a per-payment term, because acceptance reserves room per account and per edge, never per payment.

Figure 6 prices these terms live. It is the codec, not a fit: every byte follows the encodings above at one varint byte per amount and count, including the Merkle range openings, and fed the benchmark's per-slice counts it reproduces the measured matrix to the byte. Its readouts map onto the tables by name: certified is the posted close, busiest dealing is the largest dealing, and dealt is every proof slice once in the dealt wire, smaller than the proof-slice corpus because unchanged leaves and derivable columns are stripped. The calculator spreads accounts, senders, and edges evenly over the slices, uses the smallest power of two at or above the committee size (128 for 100 validators, where the tables used 256), and assumes every edge credits a distinct account, so its defaults sit above the tables, whose fixture credits 512 recipients.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive wire-size calculator. Sliders set the account count, the mean out-degree, and the committee size, which also fixes the slice count. Readouts give the certified close, the dealt corpus, the busiest validator's dealing, and the operator's egress per close.">
  <noscript>With JavaScript enabled this figure is a live calculator over the encodings above. At one million accounts each sending one entry to a distinct account, the certified close is 73 MB, the dealt corpus 170 MB, the busiest validator's dealing 114 MB, and the operator's egress 11.3 GB across 100 validators.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 6: The encodings, live. Below mean out-degree one, only $E$ accounts send (one entry each) to $E$ distinct recipients, so $2E$ accounts change. At one and above every account sends and receives. The certified close carries no term in the unchanged-account count, so it keeps falling with activity and pays roughly 4 to 5 bytes per additional edge once every account is a mover. The busiest dealing is the largest validator's share (two contiguous spans at $n=3f+1$, about two thirds of the slices, with accumulator start states and range openings once per span), and operator egress ships one dealing to each validator. Committee sizes snap to $n=3f+1$ and the slice count to the smallest power of two at or above $n$, so every validator's ring window starts on its own slice boundary, and each extra slice costs one boundary and one operator aggregate per holder. Tap a size for its byte breakdown.
:::

The fresh tree is intentionally conventional. Both state roots are rebuilt from ordered streams, a simple bolt-on to an existing ordered database, rather than maintained as a versioned authenticated trie. When only the root is needed, a known leaf count lets construction stream bounded subtrees through parallel hashing workers while holding one subtree's buffers plus a logarithmic frontier, so the subtree size bounds the builder's memory independently of the account count. Proof-producing close assembly retains the Merkle levels needed for slice openings. Neither maintains durable authenticated paths for every pending root. In exchange, validators receive evidence for the complete live state rather than a sparse update. A preconfirmation still cannot arrive in less than one round trip to the operator that serializes spending, and a close cannot quietly drop a payment: it must agree with every acknowledgment a holder retains, or a single retained entry receipt proves the fault.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
