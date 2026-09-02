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

*Revised 9/2/26. The walkthrough describes the current design. Earlier revisions are listed in the [Changelog](#changelog) at the end.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by one 32-byte commitment, 101 bytes with its certificate. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

For a given set of accounts, one payment or a bajillion costs the same to settle.

## Payments as Fast as Browsing the Web

Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

$a$'s persistent state $X_a$ is a balance $B_a$, a lifetime cumulative debit $D_a$, the cumulative credit $C_a$ the operator has promised it, the receipt count behind that credit, and a flag for whether the account is present in the live state. Credit stays a promise until the epoch ends, because the operator collates it then rather than per payment (the next section explains why). $a$'s epoch activity is one strictly recipient-sorted vector $V_a$ of cumulative entries, one per recipient it paid this epoch. The entry $(G,J)$ for recipient $b$ carries $a$'s epoch-cumulative credit to $b$ and the number of payments behind it. Before the payment, $a$ holds $B_a=100$ and $D_a=0$, and $V_a$ is empty.

To send $x>0$ from $a$ to $b$, the payer advances $b$'s entry inside its own vector and signs the exact resulting endpoint: an epoch-local sequence number $n_a$, the lifetime cumulative debit, and the vector's Merkle root. The endpoint is the payer's cumulative position after this send. The operator accepts by countersigning the identical body:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

For our payment the endpoint is $n_a=1$, $D_a=20$, and the root of $V_a=\{b:(20,1)\}$. After authenticating $S$ and checking spendability, the operator atomically commits the debit, the entry advance, a close reservation, a replay record, and the acknowledgment body. The close is the settlement package the operator builds when the epoch ends, and the reservation holds room in it for this account's row and this edge's entry. The replay record lets a retried request return the same acknowledgment. The operator then countersigns and returns $R$ with one Merkle opening per advanced entry. It actually countersigns the body twice: an ordinary signature for the acknowledgment the payer holds, and an aggregable one that the close later combines across many rows (see [Seal Every Dealing Up Front](#seal-every-dealing-up-front)).

A send may also batch entries. One signature advances strictly recipient-sorted, unique entries $(b_i,x_i)$ under a single cumulative endpoint:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+\textstyle\sum_i x_i,\;\mathsf{root}(V_a\text{ with every }b_i\text{ advanced})\bigr).
$$

The operator accepts or rejects the batch as a whole and returns one acknowledgment covering every entry. A single payment is a batch of one.

The countersigned endpoint $R$ is the accepted payment, and the preconfirmation for one recipient is an entry receipt: $R$ plus the Merkle opening of that recipient's cumulative entry under the acknowledged vector root. The payer verifies and durably retains the acknowledgment and every opening, advances its local $D_a$ in that atomic local commit, then forwards each entry receipt to any recipient that will rely on it.

The wallet keeps at most one unacknowledged send per payer: it does not sign the next cumulative endpoint until the prior send's acknowledgment is verified and committed. An operator-reported counter is never the payer's authority. A rejection before the operator's commit changes no balance, and the wallet retains the exact staged request for retry. If the response is lost, retrying that request returns the same acknowledgment without a second debit. A later endpoint authorizes the whole debit delta up to its value, while the close carries only the payer's terminal endpoint, its last of the epoch. If a wallet deliberately signs several cumulative endpoints before obtaining the earlier acknowledgments, an intermediate acknowledgment may be neither held privately nor selected as that terminal, and that exposure is outside the base guarantee. This ordering serializes one payer account, not independent payers or recipients.

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
Figure 1: The payer sends one request and receives one countersigned response. The operator verifies, commits, and signs locally, adding no network round trip. The commit moves $a$ from 100 to 80 and advances the $a\rightarrow b$ entry in $a$'s own vector from $(0,0)$ to $(20,1)$ before $R$ exists. Once $R$ returns, $a$ sends the entry receipt, $R$ plus $b$'s entry opening, directly to $b$ as transferable evidence.
:::

## Optimizing for Hot Accounts

A single incoming counter would serialize every payment to a popular recipient. Bajillion has no incoming counter at all: acceptance touches only the payer's side, and recipients have no acceptance-path state to serialize. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry inside $a$'s own vector:

$$
(G_{ab},J_{ab})\longrightarrow(G_{ab}+x,J_{ab}+1),
\qquad
\text{every other entry of every other vector unchanged.}
$$

Payments to one hot account from different payers live in disjoint payer vectors and never contend on shared state, so the incoming path scales with the payers, not the recipient. However many payments an edge carries, the epoch ends with one cumulative entry for it.

Consider accounts $(a,b,c,d)$ that open with balances $(100,40,25,35)$ and the epoch accepts

$$
a\xrightarrow{20}b,\quad b\xrightarrow{12}c,\quad
c\xrightarrow{7}d,\quad d\xrightarrow{5}a,\quad
c\xrightarrow{4}b,\quad d\xrightarrow{6}b.
$$

$b$'s three incoming payments end as the entries $(20,1)$ in $a$'s vector, $(4,1)$ in $c$'s, and $(6,1)$ in $d$'s.

Credit is collated lazily, at the close instead of per payment. When the epoch ends, each payer's vector as it then stands is its terminal vector, and terminal means end-of-epoch throughout this post. The operator re-sorts the union of every terminal vector's entries by recipient and then payer into the transpose, the same entries viewed recipient-major, committed under $\mathsf{TransposeRoot}_e$, where each recipient's entries are one contiguous range. $b$'s range holds those three entries, and its sum is $b$'s credit delta: $20+4+6=30$ over 3 payments. Proving one edge never requires shipping the rest: the payer-side entry opens under its payer's signed vector root, and the recipient-side image opens under the transpose root.

## Epochs, Closes, and the Queue

An epoch ends at a cut. Everything accepted before the cut belongs to epoch $e$, and the operator builds epoch $e$'s close: one row per changed account, a handful of Merkle roots over the rows and the resulting state, and the proofs that let validators check it. The next sections build that close. This section fixes how a close reaches the chain first, because its words (registration, admission, the queue, the challenge window, and the boundary) recur everywhere below.

The operator is Byzantine: it may halt, censor, equivocate, withhold messages, and propose arbitrary closes, but it cannot forge a payer signature. Bajillion assumes secure hashes and signatures, authenticated validator proofs of possession, at most $f$ Byzantine validators in a committee of exactly $n=3f+1$, and a correct and live settlement chain. Honest validators authenticate and durably retain their assigned share of each close before voting for it. The embedding, the chain-side integration that hosts a deployment, must keep the root bundle, public corpus, and required Merkle openings retrievable for as long as they can be challenged or claimed.

A Bajillion deployment starts from an authenticated account vector, and each epoch uses an onchain anchor $\mathcal A_e$. Before the operator acknowledges any payment of epoch $e$, it must register the epoch onchain against the exact predecessor $\mathsf{StateRoot}$, the root the previous close produced. Registration also seals the epoch's boundary: the deposits and the signed withdrawal authorizations the chain fixes for this epoch, which the close must consume exactly. An accepted registration creates one immutable admission obligation, and construction, certification, and admission may retry against it through the inclusive deadline, but the first later observation permanently faults the deployment. The $\mathsf{OPEN}$ registration slot has no heartbeat. A pipelined successor epoch can be registered and prepared while its predecessor remains challengeable.

Admission checks the certificate over the close's 32-byte commitment, consuming a 164-byte root bundle and one compact terminal proof as witness data, then places the close in a FIFO queue of pending slots. Each slot waits through an inclusive challenge window ending at its deadline $\Delta_e$, and slots finalize in order from the front. A proven challenge blocks the challenged slot and every pending descendant from finalizing, while earlier pending slots keep their ordinary windows and may still finalize in order. The configured challenge duration therefore trades clean-settlement latency against how long an evidence holder may stay offline. A withdrawal carried by a close becomes claimable only after that close reaches the front of the queue and finalizes.

The deployment fixes the maximum admission-delay increment and the minimum and maximum challenge duration before it accepts funds, while deposits and user-signed withdrawals carry their own deadlines. Every accepted deposit must enter an admitted close before its settlement-policy deadline, and admission discharges that obligation. Settlement already records each deposit's refund account and amount, so an expired unadmitted deposit is refundable by anyone without an operator, a state opening, or private evidence. A missed registered admission, an expired withdrawal or deposit, or a proven challenge permanently faults the deployment. That hard fault freezes new work and moves every account to the recovery path in [Hard Fault](#hard-fault).

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

Rollover changes only live serving state, without changing the evidence required for finalization. The close still produces the canonical rows, state root, and public corpus, and a challenge against the predecessor invalidates its pending descendants, exactly as the queue rules above require.

## One Row per Changed Account

Return to the four accounts. Netting each account's debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross payment debit equals gross payment credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. That is all the payment activity adds to the close: not the six payments, but the four accounts they changed, one row each.

Write the predecessor and successor states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. The chain-sealed boundary from the previous section assigns account $a$ a deposit $f_a$ and a withdrawal $w_a$. If $p_a$ is credit paid externally because the recipient is absent from the live state, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

For an account already in the state, $p_a=0$. For a recipient absent from the predecessor state with no deposit, $B_a^0=B_a^1=0$ and $p_a=c_a$: the accepted sends become one net external-payout claim when the close finalizes, without creating a zero-balance account. This is how someone not registered with the operator gets paid. The operator accepts the sends normally and records one absent-recipient row whose authenticated output identifies the recipient and exact net amount. Had $a$ also paid an unregistered $e$ 10, $e$'s row would carry $c_e=p_e=10$ with both balances zero, and $e$ would claim the 10 from the chain once the close finalizes ([A Deadline to Exit](#a-deadline-to-exit) gives the claim). The same holds for payments made after an account close removes the account at the cut: the identity is absent from the successor state, so those sends become claimable external payouts rather than recreating the account. From custody's perspective, this is a netted withdrawal. From the sender's perspective, it is an ordinary preconfirmed payment.

Each row also carries a settlement output $o_a$ that validators recompute from the same authenticated local effect. An account close, the signed exit described in [A Deadline to Exit](#a-deadline-to-exit), has a withdrawal output even when its epoch-tail balance is zero, so the compact leaf still authenticates the close action. A zero tail releases no funds:

$$
o_a=
\begin{cases}
\mathsf{withdrawal}(w_a), & \text{if the row consumes a withdrawal record},\\
\mathsf{external}(p_a), & \text{if }p_a>0,\\
\mathsf{none}, & \text{otherwise.}
\end{cases}
$$

The withdrawal outputs form their own Merkle tree under $\mathsf{WithdrawalOutputRoot}_e$. A withdrawal claim later opens one leaf of that tree and nothing else.

The row binds both account states and, exactly when the account sent, the terminal payer-signed vector endpoint $\mathsf{Out}_a$. It also carries a running total $\mathsf{prefix}_a$ over the sorted rows so far. Three counters ride in the prefix beside the value totals: $\chi$ flags a withdrawal record, $\varepsilon$ counts the row's vector entries, and $\iota$ counts its transpose entries. The prefix is what lets a validator check one slice of rows without seeing the others, as [Slice the Evidence](#slice-the-evidence) shows:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;p_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;\varepsilon_{a'},\;\iota_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;o_a,\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

The signed vector root rides inside $\mathsf{Out}_a$'s endpoint body, so a sending row carries its whole epoch fan-out through one signature. The operator's matching acceptance is not stored per row: its aggregable countersignatures are combined into one per slice of the evidence, checked at sealing.

Each prefix must extend the preceding prefix exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

$$
\mathbf A_e=(\mathsf{Row}_a,\;\mathsf{Row}_b,\;\mathsf{Row}_c,\;\mathsf{Row}_d),
\qquad a<b<c<d.
$$

Prefix continuity ties the epoch totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the chain-sealed boundary. Every ordinary withdrawal releases its authorized positive amount exactly when the row tail covers it and nothing otherwise, while every account close sweeps its authenticated epoch tail. The totals must respect the deployment's close limits (maximum rows, entries, and value totals) and conserve payments:

$$
\boxed{D_e=C_e.}
$$

In the example, $D_e=C_e=54$. Writing $L_e=\sum_a B_a^0$ and $L_{e+1}=\sum_a B_a^1$, summing the per-account balance equation cancels payments but not boundary flows:

$$
\boxed{L_{e+1}=L_e+F_e-W_e-P_e.}
$$

With no deposits, withdrawals, or external payouts in the example, $L_{e+1}=L_e=200$.

## Rebuild the Live State

A $\mathsf{StateRoot}$ commits every field and the exact length of the strictly sorted vector of live accounts in a binary Merkle tree (BMT). A live leaf has a positive balance. A deposit can insert a new account, an account close removes its account from the successor, and any other net balance of zero also leaves no live leaf. There are no permanent zero-balance tombstones.

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

Both roots are rebuilt fresh from ordered streams rather than maintained as a versioned authenticated trie, a trade weighed at the end of the post. Producing the proof slices still requires proof-capable Merkle material for the close.

Beside the two state roots, the close commits one compact guard per row under $\mathsf{ChangeRoot}_e$. Challenges and external-payout claims open this tree rather than the full rows, so it exposes only what they need, and [The Unavoidable Challenge](#the-unavoidable-challenge) gives its contents.

## Slice the Evidence

Validators do not each check the whole close. The evidence is divided into $S$ deterministic account-key slices (256 in the benchmarks) and dealt among validators. Four words recur from here on: a slice is one account-key range of the evidence, a span is the contiguous slices one validator holds, a proof slice is the evidence for one span with its openings, and a validator's dealing is its one or two proof slices.

Authenticating each slice independently would not prove that their union has no gaps or overlaps, so $\mathsf{CoverageRoot}_e$ commits their shared boundaries. For $S$ slices, exactly $S+1$ boundaries authenticate where each cut falls in the predecessor state ($\alpha_j$), the change vector ($\beta_j$), and the successor state ($\gamma_j$), plus the cumulative prefix at the cut, alongside two running accumulator checksums $u_j$ and $v_j$:

$$
\mathsf{Coverage}_e=\bigl((\alpha_j,\beta_j,\gamma_j,\mathsf{prefix}_j,u_j,v_j)\bigr)_{j=0}^{S}
\xrightarrow{\ \mathsf{BMT}\ }
\mathsf{CoverageRoot}_e.
$$

Take $S=2$ with slice 1 holding $\{a,b\}$ and slice 2 holding $\{c,d\}$. The boundary between them carries the prefix after $b$: debit $20+12=32$ and credit $5+30=35$, which need not balance. Slice 2 resumes from exactly that prefix, adds $c$ and $d$, and must land on the terminal prefix, where $54=54$ must hold. Each slice checks its own rows against the boundaries on either side, and no slice needs the others' rows.

The checksums are what let a committee verify the recipient-major transpose piecewise. Every edge terminal folds one canonical key, the payer, recipient, cumulative credit, and count, into an order-independent lattice-hash multiset accumulator: $u$ over the vector entries in payer-major row order and $v$ over the transpose entries in recipient-major order. In the example, $u$ folds the six edges in payer order, $a\rightarrow b$, $b\rightarrow c$, $c\rightarrow b$, $c\rightarrow d$, $d\rightarrow a$, $d\rightarrow b$, while $v$ folds the same six in recipient order, $d\rightarrow a$, $a\rightarrow b$, $c\rightarrow b$, $d\rightarrow b$, $b\rightarrow c$, $c\rightarrow d$. Same multiset, same value. Each slice resumes both accumulators from its opening boundary, folds its own slice, and must land exactly on its closing boundary. Terminal equality $u_S=v_S$ then proves the transpose is a permutation of the union of the payer vectors, so every promised credit is backed by exactly one payer-signed debit entry: double-entry bookkeeping as a multiset equation, verified without any validator seeing both sides of an edge.

A proof slice covers a contiguous span of slices and opens every boundary in the span under one range opening, so the span is gap-free against its neighbors' dealings. Every holder of the span checks each internal boundary in full: the rows and leaves before it advance the committed positions exactly, and the running prefix and checksums land on it. The withdrawal-count, vector-entry, and transpose-entry positions in the same prefixes select the span's exact contiguous ranges under $\mathsf{WithdrawalOutputRoot}_e$ and $\mathsf{TransposeRoot}_e$. A terminal coverage proof authenticates the final vector counts and aggregate totals.

Opening and successor state are thus rebuilt from sorted live accounts, and the coverage root binds each slice's exact positions in both state vectors, the change vector, and the transpose. Account insertion and deletion cannot create a gap or overlap between validator dealings.

The predecessor state root belongs to $\mathsf{CloseContext}_e$, together with the deployment, epoch, anchor, operator, the sealed boundary roots, the predecessor liability, the deadlines, and the close limits. Five roots and the exact transpose length form the 164-byte root bundle, the admission witness the chain checks but does not retain: the change root, the withdrawal-output root, the successor state root, the coverage root, and the transpose root. The 32-byte header binds every root in its contextual role:

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

The committed transpose length $\ell_e$ closes a wedge: slice openings prove membership but cannot see past their own range, so without it a certified transpose could carry trailing leaves no slice opens. The terminal boundary requires $\ell_e$ to equal its transpose-entry count. The terminal prefix carries gross debit $D_e$, credit $C_e$, external payouts $P_e$, deposits $F_e$, and withdrawals $W_e$, with the row, withdrawal-record, and entry counts alongside. One terminal coverage proof authenticates those totals without listing their recipients. Neither the root bundle nor the terminal proof is included in the 32-byte commitment figure. The live leaves, edge vectors, changed rows, withdrawal outputs, and remaining Merkle openings stay offchain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Seal Every Dealing Up Front

Before the chain queues a close for finalization, the operator disseminates each validator's dealing. Slice $s$ of $S$ is held by the $q$ consecutive validators starting at $\lfloor ns/S\rfloor$ around the validator ring, so the window slides with the slice index. A validator's slices therefore form one contiguous span, or two when the window wraps past the last slice, and its dealing is one proof slice per span. The accumulator start states and the range openings travel once per span rather than once per slice.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-ring-assignment.svg" alt="Left: sixteen validators on a ring with three quorum windows of eleven drawn as arcs for slices 0, 5, and 10; each window starts one validator later than the previous slice's. Right: a grid of slices against validators in which every column has eleven holders and every row is one contiguous span, or two when the window wraps past the last slice.">
```

::: {.image-caption}
Figure 3: Slice holders slide around the validator ring. With $n=S=16$ validators and a quorum of $q=11$, slice $s$ is held by the eleven validators starting at $\lfloor 16s/16\rfloor = s$, so consecutive slices share most of their holders (left). Seen per validator (right), every row is one contiguous span of slices, or two when the window wraps past the last slice, and every column still has exactly eleven holders. A validator's dealing is one proof slice per span, so the accumulator start states and range openings travel once per span instead of once per slice.
:::

Sealing is not a totals-only check. A validator authenticates every assigned span: the exact coverage and state ranges in its slices, every changed-account equation and settlement output, every terminal payer-signed endpoint and outgoing vector, its transpose interval, and the accumulator, prefix, and state transitions at every covered boundary. It verifies each slice's combined operator countersignature, the aggregable signatures from acceptance combined into one, and every distinct payer authorization across the dealing in one randomized batch. The terminal boundary then binds the exact vector lengths, deposits, withdrawals, external payouts, payment conservation, the multiset equality between the two edge orderings, and successor liability. Having checked all of that, the validator retains the evidence through the challenge deadline and only then seals the shared commitment. No validator needs the complete corpus, but the assignments cover it exactly.

Every certificate signer signs the same commitment. Each slice is assigned to a quorum of validators who authenticate and retain it. Quorum intersection guarantees that an honest signer authenticated and retains each slice, though that signer may differ by slice. With $n$ validators, $f$ tolerated faults, and quorum $q$, every slice $j$'s holders share more than $f$ validators with the certificate's signers:

$$
\begin{aligned}
n&=100,\qquad f=33,\qquad q=2f+1=67,\\[0.3em]
|\mathsf{signers}\;\cap\;\mathsf{holders}_j|&\;\ge\;2q-n=34>f.
\end{aligned}
$$

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, and proofs of possession were checked when the committee registered. With the 32-byte commitment and this encoding's eight-byte bitmap-length prefix, the external 100-validator certified package is 101 bytes. If the Bajillion validators are also the settlement chain's validators, inclusion itself supplies the attestation and only the 32-byte commitment need be retained.

## Fault and Availability Model

Certification establishes that the bound corpus satisfies the public relation: every row, every boundary, every signature, and every total in the selected corpus checks out. What it cannot establish is that the operator never countersigned an additional endpoint outside that corpus. The next section shows why no verifier can, and what a holder does about it.

The entry receipt is private, transferable evidence. Any holder may submit a challenge, and the chain does not require the caller to be the payer or recipient. Neither role must remain continuously online, but the availability assumption is per acknowledgment: at least one honest holder must obtain and retain the required acknowledgment or entry receipt and get the bounded challenge included by $\Delta_e$. A recipient that wants an independently enforceable preconfirmation obtains its entry receipt before relying on it. Honest validators retain public proof slices, but they cannot reconstruct private evidence that no independent holder received or retained. This is not a single global observer assumption: different edges may depend on different holders.

The configured challenge duration therefore trades clean-settlement latency for evidence-holder offline tolerance. A close finalizes only after its inclusive challenge window, and a withdrawal becomes claimable only after the close carrying it reaches the FIFO front and finalizes.

## The Unavoidable Challenge

This is the omission problem from the introduction, and no certifier solves it. Validation establishes that the bound corpus satisfies the public relation. It cannot establish that the corpus contains every acknowledgment the operator countersigned and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator countersigns exactly the acknowledgments represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid acknowledgment $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature.

So the close must expose exactly what a holder needs to contradict it. That is the job of the guard committed per row under $\mathsf{ChangeRoot}_e$:

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

The $\mathsf{ChangeValue}$ exposes only the settlement output, terminal debit, terminal sequence number $n_a$, endpoint-body digest, and terminal vector root. $\mathsf{OutDigest}_a$ binds the unsigned terminal endpoint body (or a distinguished absence). Together they pin the exact acknowledged terminal a challenger contradicts. Validators still check the complete row in the proof-slice corpus, but the change tree commits only this public projection. Membership and challenge proofs expose the $\mathsf{ChangeValue}$ rather than the full row, while its digested guard keeps ordered range boundaries compact.

Every retained acknowledgment in challenge evidence carries both its payer and operator signatures over one endpoint body. Through the inclusive deadline $t\le\Delta_e$, any holder may submit one of three bounded contradictions. In the example, $a$'s public terminal is $n_a=1$, $D_a=20$, and the entry $b:(20,1)$.

1. **Higher acknowledged debit** ($\mathsf{HigherAckDebit}$). A retained dual-signed endpoint carries a cumulative debit above the public terminal debit, a countersigned different body at the committed terminal sequence number, or an equal endpoint at a strictly later sequence. A retained $R$ at $n_a=2$ with $D_a=35$ is one. A bare payer authorization is insufficient. The countersignature proves operator acknowledgment.

2. **Higher acknowledged entry** ($\mathsf{HigherAckEntry}$). Authenticate the public terminal entry $(G^\star,J^\star)$ for one payer-recipient edge under the sender row's committed vector root, using $(0,0)$ for authenticated absence, and present a retained entry at $(G^+,J^+)$ opened under its own acknowledged root. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction. A retained opening of $b:(30,2)$ under $a$'s acknowledged root contradicts the public $(20,1)$.

3. **Acknowledgment fork** ($\mathsf{AckFork}$). Two distinct operator-countersigned endpoint bodies at one payer sequence number. Two countersigned bodies at $n_a=1$ are a fork. Only the operator countersignatures need to verify, since a fork is the operator's fault whatever produced the payer halves. Different signature bytes over one identical body are not a fork.

Every challenge compares one retained acknowledgment against one terminal opening, so no challenge has to range over intermediate receipts.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call.

A successful challenge blocks the challenged slot and every pending descendant from finalizing. Earlier pending slots keep their ordinary challenge windows and may still finalize in order.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but stopping it is not enough: users must still be able to get their funds out. So every account can queue a unilateral signed authorization directly onchain, either to withdraw an exact amount or to close the account. The queue is only the censorship fallback. An uncensored user hands the same signed authorization to the operator, which carries it inside the next close's sealed boundary under the same registration rules, so the happy-path exit costs one onchain transaction: the claim.

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;\omega,\;\tau\bigr),
\qquad
\omega\in\bigl\{\mathsf{withdraw}(x)\mid x>0\bigr\}\cup\bigl\{\mathsf{close}\bigr\}.
$$

$Q$ names the finalized root $\mathsf{rt}_z$ it was signed against, where $z$ indexes the last finalized close, a destination $v$, an operation $\omega$, and an absolute deadline $\tau$. An ordinary withdrawal authorizes exactly the positive amount $x$ and settles all or nothing: a covered amount releases exactly $x$, while an amount the epoch tail can no longer cover releases nothing and leaves the balance in the account. An account close carries no amount. The operator neither submits nor approves $Q$, and its cooperation decides only whether the authorization settles through a clean close or through hard-fault settlement.

Queueing authenticates $Q$ against the finalized root, and every pending close that could still finalize must carry it forward. The next close commits both the already-onchain signed authorization and the changed account row.

An operator-carried authorization enters the sealed boundary at registration instead. It is validated against the same finalized root, destination rules, and notice window (the deployment's bounds on how far ahead $\tau$ may sit), plus one predecessor-root opening proving the account can cover it, with its replay identity consumed at admission. The queue's proofs against every root that can still finalize are unnecessary here, because the authorization binds one specific close and spending inside that epoch settles all or nothing at certification.

An account close does not freeze the account inside that epoch: it can keep sending and receiving until the cut. The cut sweeps its authenticated epoch-tail balance and omits the account from the successor state:

$$
\boxed{w_a=B_a^0+f_a+c_a-d_a,\qquad B_a^1=0.}
$$

Had $a$ closed its account in epoch $e$, the sweep would be $w_a=100+0+5-20=85$ with $B_a^1=0$.

After clean finalization, both a $\mathsf{withdraw}(x)$ and an amountless $\mathsf{close}$ use the same claim: the validator-derived $\{\mathsf{destination},\mathsf{amount}\}$ plus one opening under $\mathsf{WithdrawalOutputRoot}_e$. The signed request is not retransmitted. For $\mathsf{close}$, validators derive the amount from the authenticated epoch tail, so $a$'s claim would be $\{v,85\}$ plus one opening, and a $\mathsf{close}$ with a zero tail is valid and releases no funds. External payouts, the $p_a$ rows, claim the same way once the close finalizes: each recipient presents one compact $\{\mathsf{account},\mathsf{ChangeValue}\}$ projection and its $\mathsf{ChangeRoot}_e$ opening. The chain keys replay protection by the finalized batch and row position, so no recipient list or all-payout multiproof enters settlement and no post-deadline crank must fan payments out. Claim size is the destination length plus the amount and one logarithmic opening, measured below.

What makes the exit credible is that custody never leaves the chain early. Let $R_z$ be the reserve for finalized but unclaimed withdrawals and external payouts. With finalized liability $L_z$, pending slots $z+1,\ldots,m$ carrying boundary flows $(F_i,W_i,P_i)$, and deposits not yet included in a pending close $F_\star$:

$$
\boxed{
E=L_z+R_z+\sum_{i=z+1}^{m}F_i+F_\star
=L_m+R_z+\sum_{i=z+1}^{m}(W_i+P_i)+F_\star.
}
$$

Withdrawals and external payouts stay in active custody until their slot finalizes at the queue front, then their aggregate value moves into $R_z$. Individual claims reduce that reserve and the chain's assets together. This finalization step touches only totals and roots, and its work does not grow with the number of recipients. A challenged or invalidated suffix creates no reserve. The operator can stop serving payments, but it cannot take funds or send them without authorization.

## Hard Fault

If a registered close misses admission, $Q$ is still unfinalized at $t\ge\tau$, an accepted deposit remains outside an admitted close through its inclusion deadline, or a challenge is proven, the first time-aware onchain call permanently freezes new work. This is the hard fault.

Pending deposit refunds remain independently claimable from the settlement queue. The pending prefix resolves from the front, finalizing eligible clean slots while a challenged or invalidated suffix can never finalize. Hard-fault settlement then freezes the last finalized state root.

Acknowledged sends that existed only in a never-admitted registration or invalidated suffix do not debit that root. Each sender recovers its finalized balance exactly once through a replay-protected state opening. An outstanding authorization the frozen balance covers routes its amount to the signed destination and returns the residual to the account, while one it cannot cover returns the whole balance. Claim reserves from earlier clean finalizations remain separate and claimable, so recovery needs neither an all-account scan nor a global payout crank.

Hard-fault recovery removes operator cooperation, but claimants still need the relevant authenticated openings, and the settlement integration must atomically persist each claim with its custody effect. An opening against the root ultimately frozen must remain available until its position is claimed. The protocol supplies neither a historical witness store nor a terminal-claim deadline.

## The Close Never Grows (with Payments)

Every profile below uses a 100-validator committee and divides the evidence into 256 slices. Prepare, deal, seal, and challenge checks share one adaptive eight-worker pool (AWS c8a.4xlarge). Certificate and withdrawal-claim checks are scalar calling-thread measurements. The first matrix varies $N$, the number of live accounts. Every account sends one entry, and the same 512 accounts receive. Writing $A$ for changed accounts and $B$ for distinct recipients, the fixture holds $A=N$ and $B=512$ while $N$ grows from 1,024 to one million. A second matrix afterward holds $N$ at one million while the active accounts shrink. Sizes and timings are measured on the current design.

Four quantities appear in the tables. The posted close is what a reader holding the previous certified state must download: live accounts ride as one-or-two-byte rank gaps, and the transpose, predecessor states, successor states, and prefixes are all derived rather than shipped. The proof-slice corpus is the complete evidence, the union of all 256 proof slices with every row, both state leaf sets, and every opening. The largest dealing is the busiest validator's share of it, one proof slice per span with no unchanged leaves, because every validator retains its key interval across closes and hydrates each dealing against it. The external certified package is the commitment and certificate from the sealing section.

No payment count appears because none is needed: rows and vector entries carry cumulative totals, so every size in the table is the same for any $T$. Every fixture send is a batch of one entry. A terminal batch with more entries adds one 48-byte entry to its committed vector (and that entry's transpose image to the dealt slices), still independent of $T$.

Each stage is measured independently and follows the pipeline: the operator prepares the roots, then deals the evidence into slices, each validator seals its dealing by checking and retaining its assigned slices before signing the commitment, and an acknowledgment holder with evidence of fraud can dispute the certified commitment with a challenge that the chain checks. The fixture constructs the predecessor-state proof cache before measurement. Prepare builds the compact change, withdrawal-output, successor-state, coverage, and transpose roots from the owned close inputs while reusing that cache. Deal produces every validator's dealing: each slice's rows, entries, and transpose entries are encoded once as a chunk, and each span's dealing is a small witness plus references to its chunks, so the measured time covers encoding every chunk and every span's witness. The network path sends those buffers without copying them. Seal checks and retains the busiest validator's dealing, verifies each slice's combined operator countersignature and every distinct payer authorization in one randomized batch, and signs the commitment. Percentages in the certification rows are relative to the proof-slice corpus.

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

The busiest validator's dealing is 78–93% smaller than the complete proof-slice corpus even though it holds two thirds of the slices. The corpus carries every row with both account states and its prefix plus both state leaf sets, about 473 bytes per row at one million accounts. The dealt wire carries the movers and edges, one witness (accumulator start states and range openings) per span, and none of the unchanged leaves, about 155 bytes per row the busiest validator holds. At one million live accounts it checks 103 MB rather than the complete 473 MB corpus. That is the every-account-sends worst case, and it hides the design's real lever: dealings travel without unchanged state. When every account changes there is nothing to strip. When the movers are a fraction of the account set, the posted close and the dealt wire follow the movers:

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

The posted close is about 72 bytes per active account plus its edges, whatever the account set holds: at 1,024 movers among one million accounts it is 74.0 KB, a thousandth of the every-account column. The dealt wire keeps one span witness and its slices' row evidence but none of the unchanged leaves, so the busiest dealing falls from 103 MB to 182 KB across the same sweep. Prepare retains a fixed cost in $N$ (the fresh state BMTs are rebuilt over all live leaves), while deal and seal follow the movers: deal encodes only the rows and edges that changed, and signature and countersignature verification dominate seal.

The proof-slice corpus is constant for a profile, so accepted payments only divide it. Ten million payments spread the one-million-account profile's 472,797,104 bytes to 47.3 offchain bytes per payment, and its 71,762,697-byte posted close to 7.2. A billion payments spread them to 0.473 and 0.072. The 101-byte certified package and the 164-byte root bundle shrink the same way, as $1/T$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows proof-slice corpus bytes per payment for four live-account counts; the right shows the 101-byte external certified package. Every line falls as one over T.">
```

::: {.image-caption}
Figure 5: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The proof-slice corpus (left) grows with the live-account count $N$. The external certified package (right) stays 101 bytes across profiles.
:::

The higher-acknowledged-debit and higher-acknowledged-entry challenges carry one retained acknowledgment plus one changed-row lookup, so they grow with opening depth: 620–940 and 671–991 bytes across the matrix, checking in 0.269–0.332 ms. The acknowledgment-fork contradiction carries two countersigned endpoints and no state opening, so it holds at 417 bytes for every $N$ and checks in about 0.321 ms. Adjudication is signature-dominated, and challenge evidence is one fixed-size acknowledgment plus at most one entry opening: an acknowledged endpoint commits its whole batch through the vector root, so representing an entry of a larger batch changes nothing about the witness or its check. Clean closes submit no fraud challenge at all, so average challenge traffic is smaller still. A challenge targets a commitment whose certificate was already checked at admission, so adjudication does not verify that certificate again.

Withdrawal and external-payout claims scale with a different variable: the claimed close's own withdrawal count $W$, never $N$, because each claim opens only that close's withdrawal-output tree. The certified close above queues no withdrawals, so separate fixtures use a 21-byte destination, once with a single withdrawal output and once with a withdrawal surge in which all $N$ accounts exit through one close. The identical $\mathsf{withdraw}$ and $\mathsf{close}$ claim proofs carry only the validator-derived destination and amount plus one $\mathsf{WithdrawalOutputRoot}$ opening. At $W=1$ either claim is 39 bytes and verifies in 0.313 µs on the same c8a.4xlarge. The opening adds one 32-byte sibling per doubling of $W$, so a surge barely moves it: 359 bytes when 1,024 accounts exit together and 679 bytes when one million do, with verification adding only the twenty path hashes.

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

and the posted close omits $U$, the transpose, and every derivable column outright. For the benchmark's fixed live set, $U=N-A$. Account creation, deletion, and external-payout rows need not preserve that identity in general. For repeated activity over a fixed set of accounts and edges, this fixed corpus divided by $T$ tends to zero. Account-level clearing compresses repetition, not state. Every unchanged live account contributes a leaf to the dealt evidence and nothing to the posted close, every changed account contributes a row, and every edge contributes one cumulative entry on each side, but additional payments between them add nothing. No traffic pattern adds a per-payment term to the close either, because acceptance reserves room per account and per edge, never per payment.

Figure 6 prices these terms live. It is the codec, not a fit: every byte follows the encodings above at one varint byte per amount and count, including the Merkle range openings, and fed the benchmark's per-slice counts it reproduces the measured matrix to the byte. Its readouts map onto the tables by name. Certified is the posted close, the data the certified commitment represents. Busiest dealing is the largest dealing. Dealt is every proof slice once in the dealt wire, smaller than the proof-slice corpus because unchanged leaves and derivable columns are stripped. The calculator spreads accounts, senders, and edges evenly over the 256 slices and assumes every edge credits a distinct account, so its defaults sit above the tables, whose fixture credits 512 recipients.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive wire-size calculator. Sliders set the account count, the mean out-degree, and the committee size. Readouts give the certified close, the dealt corpus, the busiest validator's dealing, and the operator's egress per close.">
  <noscript>With JavaScript enabled this figure is a live calculator over the encodings above. At one million accounts each sending one entry to a distinct account, the certified close is 73 MB, the dealt corpus 171 MB, the busiest validator's dealing 114 MB, and the operator's egress 11.3 GB across 100 validators.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 6: The encodings, live. Below mean out-degree one, only $E$ accounts send (out-degree one each) to $E$ distinct recipients, so $2E$ accounts change. At one and above every account sends and receives. The certified close carries no term in the unchanged-account count, so it keeps falling with activity and pays roughly 4 to 5 bytes per additional edge once every account is a mover. The dealt corpus is every slice once, the busiest dealing is the largest validator's share (two contiguous spans at $n=3f+1$, about two thirds of the slices, with the accumulator start states and range openings once per span), and operator egress ships one dealing to each validator. Committee sizes snap to $n=3f+1$. Tap a size for its byte breakdown.
:::

The fresh tree is intentionally conventional. Both state roots are rebuilt from ordered streams, a simple bolt-on to an existing ordered database, rather than maintained as a versioned authenticated trie. When only the root is needed, a known leaf count lets construction stream bounded subtrees through parallel hashing workers while retaining one subtree's working buffers plus a logarithmic frontier, so choosing the subtree size bounds the builder's memory independently of the total account count. Proof-producing close assembly retains the Merkle levels needed for slice openings. Neither requires maintaining durable authenticated paths for every pending root. In exchange, validators receive evidence for the complete live state rather than only a sparse update. A preconfirmation still cannot arrive in less than one round trip to the operator that serializes spending, and a close cannot quietly drop a payment: it must agree with every acknowledgment a holder retains, or a single retained entry receipt proves the fault.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.

## Changelog

*Update (8/20/26): Bajillion now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

*Update (8/27/26): Bajillion sends now batch entries. One signature and one cumulative endpoint pay many recipients, acknowledged atomically with one receipt per entry. Withdrawals now settle all or nothing and can ride the close directly, so an uncensored exit costs one onchain transaction: the claim. Admission and close coverage are stronger, and finalized claims and paired challenge evidence are more compact.*

*Update (9/2/26): Dealing encodes each slice's rows, entries, and transpose entries once and shares those chunks across every validator span, so the operator's deal cost follows the corpus rather than its egress, and coverage boundary fields ride as varints. All timings are re-measured on this design.*

*Update (9/1/26): Bajillion's close is now a sender vector. Each sending row carries one payer-signed cumulative vector endpoint instead of per-edge receipts, the operator's acceptance is aggregated into one countersignature per slice, and three acknowledgment challenges replace the four receipt challenges. The posted close ships movers and edges only against reader-held state, and validators retain their key intervals so dealings travel without unchanged leaves. Each validator's slices are contiguous and dealt as one proof slice per span, so the accumulator start states and range openings ship once per validator, and sequence numbers, amounts, counts, and coverage boundary fields ride as varints. The walkthrough above describes this design. Sizes and timings are re-measured on it, including a new matrix that varies the active accounts under a fixed account set.*
