---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-01T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (8/27/26): Bajillion sends now batch entries. One signature and one cumulative endpoint pay many recipients, acknowledged atomically with one receipt per entry. Withdrawals now settle all or nothing and can ride the close directly, so an uncensored exit costs one onchain transaction: the claim. Admission and close coverage are stronger, and finalized claims and paired challenge evidence are more compact.*

*Update (9/1/26): Bajillion's close is now a sender vector. Each sending row carries one payer-signed cumulative vector endpoint instead of per-edge receipts, the operator's acceptance is aggregated into one countersignature per slice interval, and three acknowledgment challenges replace the four receipt challenges. The posted close ships movers and edges only against reader-held state, and validators retain their key intervals so dealings travel without unchanged leaves. Each validator's intervals are contiguous and dealt as one proof slice per run, so the accumulator start states and range openings ship once per validator, and sequence numbers, amounts, and counts ride as varints. The walkthrough below describes this design. Sizes are re-measured on it, including a new matrix that varies the active accounts under a fixed account set; the timings predate the contiguous dealing and varint changes and are re-measured next.*

*Update (8/20/26): Bajillion now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (more on this later).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a 101-byte header plus certificate; admission also carries a 164-byte root bundle and one compact terminal proof. Preconfirmations arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery through the settlement chain alone. And the protocol requires only signatures and Merkle openings.

For a given set of accounts, one payment or a bajillion costs the same to settle.

## Payments as Fast as Browsing the Web

A Bajillion deployment starts from an authenticated account vector, and each epoch uses an onchain anchor $\mathcal A_e$. A pipelined successor can be prepared while its predecessor remains challengeable, but registration must succeed onchain against the exact predecessor $\mathsf{StateRoot}$ before the operator acknowledges any payment. An accepted registration creates one immutable admission obligation: construction, certification, and admission may retry against it through the inclusive deadline, but the first later observation permanently faults the deployment. The $\mathsf{OPEN}$ registration slot has no heartbeat. The deployment fixes the maximum admission-delay increment and the minimum and maximum challenge duration before it accepts funds, while deposits and user-signed withdrawals carry their own deadlines. Let's suppose account $a$ opens with 100 and wants to pay account $b$ 20.

$a$'s persistent state $X_a$ is a balance $B_a$, cumulative debit $D_a$, operator-promised credit $C_a$, a receipt count, and an activity flag. $a$'s epoch activity is one strictly recipient-sorted vector $V_a$ of cumulative entries, one per recipient it paid this epoch, where the entry $(G,J)$ for recipient $b$ carries $a$'s epoch-cumulative credit to $b$ and the number of payments behind it. To send $x>0$ from $a$ to $b$ (who may or may not have been registered with the operator at the start of the epoch), the payer advances $b$'s entry inside its own vector and signs the exact resulting endpoint: an epoch-local sequence number $n_a$, the lifetime cumulative debit, and the vector's Merkle root. The operator accepts by countersigning the identical body:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

After authenticating $S$ and checking spendability, the operator atomically commits the debit, entry advance, close reservation, replay record, and acknowledgment body. It then countersigns and returns $R$ with one Merkle opening per advanced entry. It actually countersigns the body twice: an ordinary signature for the acknowledgment the payer holds, and an aggregable one so the close can later carry one combined countersignature per proof slice instead of one per row.

A send may also batch entries. One signature advances strictly recipient-sorted, unique entries $(b_i,x_i)$ under a single cumulative endpoint:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+\textstyle\sum_i x_i,\;\mathsf{root}(V_a\text{ with every }b_i\text{ advanced})\bigr).
$$

The operator accepts or rejects the batch as a whole and returns one acknowledgment covering every entry. A single payment is a batch of one.

The countersigned endpoint $R$ is the accepted payment, and the preconfirmation for one recipient is an entry receipt: $R$ plus the Merkle opening of that recipient's cumulative entry under the acknowledged vector root. The payer verifies and durably retains the acknowledgment and every opening, advances its local $D_a$ in that atomic local commit, then forwards each entry receipt to any recipient that will rely on it. The wallet keeps at most one unacknowledged send for this payer: it does not sign the next cumulative endpoint until the prior send's acknowledgment is verified and committed. An operator-reported counter is never the payer's authority. A rejection before the operator's commit changes no balance; the wallet retains the exact staged request for retry. If the response is lost, retrying that request returns the same acknowledgment without a second debit. This ordering serializes one payer account, not independent payers or recipients.

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

A single incoming counter would serialize every payment to a popular recipient. Bajillion has no incoming counter at all: acceptance touches only the payer's side. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry inside $a$'s own vector:

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

Credit is collated lazily, at the close instead of per payment. The operator re-sorts the union of every terminal vector's entries by recipient and then payer into the transpose, committed under $\mathsf{TransposeRoot}_e$, where each recipient's entries are one contiguous range. $b$'s range holds those three entries, and its sum is $b$'s credit delta: $20+4+6=30$ over 3 payments. Proving one edge never requires shipping the rest: the payer-side entry opens under its payer's signed vector root, and the recipient-side image opens under the transpose root.

## One Row per Changed Account

Netting each account's debits and credits gives exact successor balances $(85,58,26,31)$, and gross payment debit equals gross payment credit at 54 (i.e. the changes net to zero). That is all the payment activity adds to the close: not the six payments, but the four accounts they changed, one row each.

Write the predecessor and successor states as $X_a^0$ and $X_a^1$, with checked debit and credit deltas $d_a=D_a^1-D_a^0$ and $c_a=C_a^1-C_a^0$. If the chain-sealed boundary assigns deposit $f_a$ and withdrawal $w_a$, and $p_a$ is credit paid externally because the recipient is absent from the live state, the exact balance relation is

$$
\boxed{B_a^1+d_a+w_a+p_a=B_a^0+c_a+f_a.}
$$

For an account already in the state, $p_a=0$. For a recipient absent from the predecessor state with no deposit, $B_a^0=B_a^1=0$ and $p_a=c_a$: the accepted sends become one net external-payout claim when the close finalizes, without creating a zero-balance account. This includes payments made after a close removes an account at the cut: the identity is absent from the successor state, so those sends become claimable external payouts rather than recreating the account.

Each row also carries a settlement output $o_a$ that validators recompute from the same authenticated local effect. A close has a withdrawal output even when its tail is zero, so the compact leaf still authenticates the close action; a zero tail releases no funds:

$$
o_a=
\begin{cases}
\mathsf{withdrawal}(w_a), & \text{if the row consumes a withdrawal record},\\
\mathsf{external}(p_a), & \text{if }p_a>0,\\
\mathsf{none}, & \text{otherwise.}
\end{cases}
$$

The row binds both account states, the terminal payer-signed vector endpoint $\mathsf{Out}_a$ exactly when the account sent, and a running total $\mathsf{prefix}_a$ over the sorted rows so far, where $\chi$ flags a withdrawal record, $\varepsilon$ counts the row's vector entries, and $\iota$ counts its transpose entries:

$$
\begin{aligned}
\mathsf{prefix}_a&=\sum_{a'\le a}\bigl(d_{a'},\;c_{a'},\;p_{a'},\;f_{a'},\;w_{a'},\;\chi_{a'},\;\varepsilon_{a'},\;\iota_{a'}\bigr),\\[0.3em]
\mathsf{Row}_a&=\bigl(a,\;X_a^0,\;X_a^1,\;\mathsf{Out}_a,\;o_a,\;\mathsf{prefix}_a\bigr).
\end{aligned}
$$

The signed vector root rides inside $\mathsf{Out}_a$'s endpoint body, so a sending row carries its whole epoch fan-out through one signature. The operator's matching acceptance is not stored per row: each proof slice carries one combined aggregable countersignature over its rows' endpoint bodies.

Each prefix must extend the preceding prefix exactly, so the terminal row alone carries the epoch's totals. The rows are strictly sorted by account, with exactly one for every account whose authenticated state changes:

$$
\mathbf A_e=(\mathsf{Row}_a,\;\mathsf{Row}_b,\;\mathsf{Row}_c,\;\mathsf{Row}_d),
\qquad a<b<c<d.
$$

## Rebuild the Live State

Commit one compact guard per row under $\mathsf{ChangeRoot}_e$:

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

The $\mathsf{ChangeValue}$ exposes only the settlement output, terminal debit, terminal sequence number $n_a$, endpoint-body digest, and terminal vector root. $\mathsf{OutDigest}_a$ binds the unsigned terminal endpoint body (or a distinguished absence). Together they pin the exact acknowledged terminal a challenger contradicts: a retained acknowledgment above it in debit, at its sequence with a different body, or equal-valued at a later sequence is fraud evidence, and any of the batch's entry receipts opens against the committed root. Validators still check the complete row in the proof-slice corpus, but the change tree commits only this public projection. Membership and challenge proofs expose the $\mathsf{ChangeValue}$ rather than the full row, while its digested guard keeps ordered range boundaries compact.

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

The evidence is divided into deterministic account-key slices and dealt among validators. Authenticating each interval independently would not prove that their union has no gaps or overlaps, so $\mathsf{CoverageRoot}_e$ commits their shared boundaries. For $S$ slices, exactly $S+1$ boundaries authenticate the predecessor-state, change, and successor-state positions plus the cumulative prefix at each cut, alongside two running accumulator checksums $u_j$ and $v_j$:

$$
\mathsf{Coverage}_e=\bigl((o_j,r_j,c_j,\mathsf{prefix}_j,u_j,v_j)\bigr)_{j=0}^{S}
\xrightarrow{\ \mathsf{BMT}\ }
\mathsf{CoverageRoot}_e.
$$

The checksums are what let a committee verify the recipient-major transpose piecewise. Every edge terminal folds one canonical key, the payer, recipient, cumulative credit, and count, into an order-independent lattice-hash multiset accumulator: $u$ over the vector entries in payer-major row order and $v$ over the transpose entries in recipient-major order. Each slice resumes both accumulators from its opening boundary, folds its own interval, and must land exactly on its closing boundary. Terminal equality $u_S=v_S$ then proves the transpose is a permutation of the union of the payer vectors, so every promised credit is backed by exactly one payer-signed debit entry: double-entry bookkeeping as a multiset equation, verified without any validator seeing both sides of an edge.

A proof slice covers a contiguous run of these intervals and opens every boundary in the run under one range opening, so its intervals are gap-free across neighboring dealings and each internal boundary is checked in full by every holder of the run: the rows and leaves before it advance the committed positions exactly, and the running prefix and checksums land on it. The withdrawal-count, vector-entry, and transpose-entry positions in the same prefixes select the run's exact contiguous intervals under $\mathsf{WithdrawalOutputRoot}_e$ and $\mathsf{TransposeRoot}_e$. A terminal coverage proof authenticates the final vector counts and aggregate totals.

::: {.image-caption}
Figure 2: Opening and successor state are rebuilt from sorted live accounts. The coverage root binds each slice's exact positions in both state vectors, the change vector, and the transpose, so account insertion and deletion cannot create a gap or overlap between validator dealings.
:::

The predecessor state root belongs to $\mathsf{CloseContext}_e$. The five other roots and the exact transpose length form the admission witness, and the 32-byte header binds every root in its contextual role:

$$
\begin{aligned}
\mathsf{RootBundle}_e
&=\bigl(\mathsf{ChangeRoot}_e,\;\mathsf{WithdrawalOutputRoot}_e,\;\mathsf{StateRoot}_{e+1},\;\mathsf{CoverageRoot}_e,\;\mathsf{TransposeRoot}_e,\;\ell_e\bigr),\\
\mathsf{Commitment}_e=\mathsf{Header}_e
&=H\!\left(\mathsf{CloseContext}_e\parallel\mathsf{ChangeRoot}_e\parallel\mathsf{WithdrawalOutputRoot}_e\parallel\mathsf{StateRoot}_{e+1}\parallel\mathsf{CoverageRoot}_e\parallel\mathsf{TransposeRoot}_e\parallel\ell_e\right).
\end{aligned}
$$

The committed transpose length $\ell_e$ closes a wedge: slice openings prove membership but cannot see past their own interval, so without it a certified transpose could carry trailing leaves no slice opens. The terminal boundary requires $\ell_e$ to equal its transpose-entry count. The terminal prefix carries gross debit $D_e$, credit $C_e$, external payouts $P_e$, deposits $F_e$, and withdrawals $W_e$, with the row, withdrawal-record, and entry counts alongside. One terminal coverage proof authenticates those totals without listing their recipients. Admission also consumes the 164-byte $\mathsf{RootBundle}$ and terminal proof as witness data; neither is included in the 32-byte commitment figure. The live leaves, edge vectors, changed rows, withdrawal outputs, and remaining Merkle openings stay offchain as an authenticated corpus $\mathcal D_e$ that must remain retrievable through the challenge deadline $\Delta_e$.

## Seal Every Dealing Up Front

Before the chain queues a close for finalization, the operator disseminates each validator's dealing. Each interval is held by one quorum window of the validator ring, and the window slides with the interval index, so a validator's intervals form one contiguous run (two when the window wraps past the last interval) and its dealing is one proof slice per run: the accumulator start states and the range openings travel once per run rather than once per interval. A validator authenticates every assigned run, checks every local row, prefix transition, and accumulator transition at every covered boundary, verifies each interval's combined operator countersignature and every distinct payer authorization across the dealing in one randomized batch, retains the evidence through the challenge deadline, and only then seals the shared commitment. No validator needs the complete corpus, but the assignments cover it exactly.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-ring-assignment.svg" alt="Left: sixteen validators on a ring with three quorum windows of eleven drawn as arcs for slices 0, 5, and 10; each window starts one validator later than the previous slice's. Right: a grid of slices against validators in which every column has eleven holders and every row is one contiguous run, or two when the window wraps past the last slice.">
```

::: {.image-caption}
Figure 4: Slice holders slide around the validator ring. With $n=16$ validators and a quorum of $q=11$, slice $s$ is held by the eleven validators starting at $\lfloor 16s/16\rfloor = s$, so consecutive slices share most of their holders (left). Seen per validator (right), every row is one contiguous run of slices, or two when the window wraps past the last slice, and every column still has exactly eleven holders. A validator's dealing is one proof slice per run, so the accumulator start states and range openings travel once per run instead of once per slice.
:::

Prefix continuity ties the epoch totals to the rows beneath them. The deposit total and withdrawal record count must reproduce the chain-sealed boundary. Every ordinary withdrawal releases its authorized positive amount exactly when the row tail covers it and nothing otherwise, while every close sweeps its authenticated epoch tail. The totals must respect the close caps and conserve payments:

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

Sealing is not a totals-only check. Each validator authenticates the exact coverage and state ranges in its slices, every changed-account equation and settlement output, terminal payer-signed endpoint, outgoing vector, transpose interval, accumulator transition, boundary contribution, prefix transition, state update, combined operator countersignature, and distinct payer signature in its dealing. The terminal boundary then binds the exact vector lengths, deposits, withdrawals, external payouts, payment conservation, the multiset equality between the two edge orderings, and successor liability. What certification cannot establish is that the operator never countersigned an additional endpoint outside the selected public corpus.

Each payer account is one linear cumulative-debit sequence over one epoch-cumulative outgoing vector, and a batch advances both by exactly its total. A wallet using the base safety guarantee stages one exact send, retries those same bytes after response loss, verifies and durably commits the acknowledgment and every entry opening, advances its locally owned debit, and only then signs the next endpoint. A later endpoint authorizes the whole debit delta up to that value, while the public row carries only the terminal endpoint. If a wallet deliberately signs several cumulative endpoints before obtaining the earlier acknowledgments, an intermediate acknowledgment may be neither held privately nor selected as that terminal; that exposure is outside the base guarantee. This per-payer ordering does not limit parallel sends from independent accounts, and recipients have no acceptance-path state to serialize at all.

The entry receipt is private, transferable evidence. Any holder may submit a challenge; the chain does not require the caller to be the payer or recipient. Neither role must remain continuously online, but the availability assumption is per acknowledgment: at least one honest holder must obtain and retain the required acknowledgment or entry receipt and get the bounded challenge included by $\Delta_e$. A recipient that wants an independently enforceable preconfirmation obtains its entry receipt before relying on it. Honest validators retain public proof slices, but they cannot reconstruct private evidence that no independent holder received or retained. This is not a single global observer assumption: different edges may depend on different holders.

The configured challenge duration therefore trades clean-settlement latency for evidence-holder offline tolerance. A close finalizes only after its inclusive challenge window, and a withdrawal becomes claimable only after the close carrying it reaches the FIFO front and finalizes. A missed registered admission, an expired withdrawal or deposit, or a proven challenge permanently faults the deployment. Deposits use a different path: settlement already records the refund account and amount, so an expired unadmitted deposit is directly refundable without private evidence. Hard-fault recovery removes operator cooperation, but claimants still need the relevant authenticated openings and the settlement integration must atomically persist each claim with its custody effect.

## The Unavoidable Challenge

Validation establishes that the bound corpus satisfies the public relation. However, it cannot establish that the corpus contains every acknowledgment the operator countersigned and delivered privately.

Fix a public corpus $\mathcal D_e$ and accepting certificate, proof, or attestation $\zeta$. Compare two executions: in $\Xi_0$ the operator countersigns exactly the acknowledgments represented by $\mathcal D_e$, while in $\Xi_1$ it produces the same $(\mathcal D_e,\zeta)$ and privately delivers one more valid acknowledgment $R^+$. The close verifier has the same view in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A validation committee (or TEE or SNARK/STARK) can certify the exact public-validity relation over selected inputs. None proves the nonexistence of an additional private signature. Every retained acknowledgment in challenge evidence carries both its payer and operator signatures over one endpoint body. Through the inclusive deadline $t\le\Delta_e$, any holder may submit one of three bounded contradictions:

1. **Higher acknowledged debit.** A retained dual-signed endpoint carries a cumulative debit above the public terminal debit, a countersigned different body at the committed terminal sequence number, or an equal endpoint at a strictly later sequence. A bare payer authorization is insufficient. The countersignature proves operator acknowledgment.

2. **Higher acknowledged entry.** Authenticate the public terminal entry $(G^\star,J^\star)$ for one payer-recipient edge under the sender row's committed vector root, using $(0,0)$ for authenticated absence, and present a retained entry at $(G^+,J^+)$ opened under its own acknowledged root. Either strict increase, $G^+>G^\star$ or $J^+>J^\star$, is a contradiction.

3. **Acknowledgment fork.** Two distinct operator-countersigned endpoint bodies at one payer sequence number. Only the operator countersignatures need to verify, since a fork is the operator's fault whatever produced the payer halves. Different signature bytes over one identical body are not a fork.

There is no interior receipt range to reason about: every counted value is a terminal opening under a payer-signed vector root.

Each challenge is one-shot. There is no interactive dispute game and no execution trace to bisect: the holder submits the signed pair or pairs and the bounded openings that expose the contradiction, and the chain checks fixed signature, arithmetic, and Merkle predicates in one call.

A successful challenge blocks the challenged slot and every pending descendant from finalizing. Earlier pending slots keep their ordinary challenge windows and may still finalize in order.

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but stopping it is not enough: users must still be able to get their funds out. So every account can queue a unilateral signed authorization directly onchain, either to withdraw an exact amount or to close the account. The queue is only the censorship fallback. An uncensored user hands the same signed authorization to the operator, which carries it inside the next close's sealed boundary under the same registration rules, so the happy-path exit costs one onchain transaction: the claim.

$$
Q=\mathsf{Sign}_a\bigl(\mathsf{deployment},\;\mathsf{rt}_z,\;v,\;\omega,\;\tau\bigr),
\qquad
\omega\in\bigl\{\mathsf{withdraw}(x)\mid x>0\bigr\}\cup\bigl\{\mathsf{close}\bigr\}.
$$

$Q$ names the finalized root $\mathsf{rt}_z$ it was signed against, a destination $v$, an operation $\omega$, and an absolute deadline $\tau$. An ordinary withdrawal authorizes exactly the positive amount $x$ and settles all or nothing: a covered amount releases exactly $x$, while an amount the epoch tail can no longer cover releases nothing and leaves the balance in the account. A close carries no amount. The operator neither submits nor approves it, and its cooperation decides only whether the authorization settles through a clean close or through hard-fault settlement.

There is also a fast path for paying someone who is not registered with the operator. The operator accepts the sends normally and records one absent-recipient row whose authenticated output identifies the recipient and exact net amount. The terminal coverage proof authenticates only the aggregate $P_e$. If the close survives its challenge window, each recipient presents one compact $\{\mathsf{account},\mathsf{ChangeValue}\}$ projection and its $\mathsf{ChangeRoot}_e$ opening. The chain keys replay protection by the finalized batch and row position, so no recipient list or all-payout multiproof enters settlement and no post-deadline crank must fan payments out. From custody's perspective, this is a netted withdrawal; from the sender's perspective, it is an ordinary preconfirmed payment.

Queueing authenticates $Q$ against the finalized root, and every admitted descendant that can survive a cut must carry it forward. The next close commits both its already-onchain signed authorization and its changed account row. An operator-carried authorization enters the same sealed boundary at registration instead, validated against the same finalized root, destination policy, and notice window, plus one predecessor-root opening proving the account can cover it, with its replay identity consumed at admission. The queue's proofs against every root that can survive a cut are unnecessary here because the authorization binds one specific close, and spending inside that epoch settles all or nothing at certification.

A close does not freeze the account inside that epoch: it can keep sending and receiving until the cut. The cut sweeps its authenticated epoch-tail balance and omits the account from the successor state:

$$
\boxed{w_a=B_a^0+f_a+c_a-d_a,\qquad B_a^1=0.}
$$

After clean finalization, both an $\mathsf{Amount}$ withdrawal and an amountless $\mathsf{Close}$ use the same claim: the validator-derived $\{\mathsf{destination},\mathsf{amount}\}$ plus one opening under $\mathsf{WithdrawalOutputRoot}_e$. The signed request is not retransmitted. For $\mathsf{Close}$, validators derive the amount from the authenticated epoch tail; $\mathsf{Close}(0)$ is valid and releases no funds. Claim size is therefore the destination length plus the amount and one logarithmic opening. With one withdrawal output and a 21-byte destination, either claim is 39 bytes. The opening adds one 32-byte sibling per doubling of the epoch's withdrawal count, so a surge barely moves it: if every one of a million accounts exits through one close, each claim is 679 bytes and verification adds only the twenty path hashes. Every accepted deposit must enter an admitted close before its settlement-policy deadline. Admission discharges that obligation; expiry permanently tombstones the operator. The settlement queue already fixes the refund account and amount, so anyone can trigger that refund without an operator or state opening.

What makes the exit credible is that custody never leaves the chain early. Let $R_z$ be the reserve for finalized but unclaimed withdrawals and external payouts. With finalized liability $L_z$, pending slots $z+1,\ldots,\ell$ carrying boundary flows $(F_i,W_i,P_i)$, and deposits not yet included in a pending close $F_\star$:

$$
\boxed{
E=L_z+R_z+\sum_{i=z+1}^{\ell}F_i+F_\star
=L_\ell+R_z+\sum_{i=z+1}^{\ell}(W_i+P_i)+F_\star.
}
$$

Withdrawals and external payouts stay in active custody until their slot finalizes at the queue front, then their aggregate value moves into $R_z$. Individual claims reduce that reserve and the chain's assets together. This finalization step touches only totals and roots; its work does not grow with the number of recipients. A challenged or invalidated suffix creates no reserve. The operator can stop serving payments, but it cannot take funds or send them without authorization.

If a registered close misses admission, $Q$ is still unfinalized at $t\ge\tau$, an accepted deposit remains outside an admitted close through its inclusion deadline, or a challenge is proven, the first time-aware onchain call permanently freezes new work. Pending deposit refunds remain independently claimable from the settlement queue. The pending prefix resolves from the front, finalizing eligible clean slots while a challenged or invalidated suffix can never finalize, then hard-fault settlement freezes the last finalized state root. Acknowledged sends that existed only in a never-admitted registration or invalidated suffix do not debit that root; each sender recovers its finalized balance exactly once through a replay-protected state opening. An outstanding authorization the frozen balance covers routes its amount to the signed destination and returns the residual to the account, while one it cannot cover returns the whole balance. Claim reserves from earlier clean finalizations remain separate and claimable, so recovery needs neither an all-account scan nor a global payout crank. An opening against the root ultimately frozen must remain available until its position is claimed; the protocol supplies neither a historical witness store nor a terminal-claim deadline.

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
Figure 3: Both rails branch from the same preserved 80. The upper rail computes the exact epoch-$e$ close, $80+\rho_a=85$. The lower rail keeps the epoch-$e+1$ head live, $80-20+\rho_a-15=50$. The single vertical $\rho_a=5$ marker is the same predecessor credit in both calculations. The two values serve different roles: 85 is the canonical predecessor close, while 50 is the current live head. Reconciliation adds $\rho_a$ to the live value and preserves every successor debit.
:::

The live balance is not monotone, since successor payments spend it down. The one-sidedness is all on the predecessor's side: completion can add missing credit but can never discover another accepted debit. Boundary operations and credit imports obey the same rule: the live head is only ever adjusted, never overwritten.

Rollover changes only live serving state, without changing the evidence required for finalization. The close still produces the canonical rows, state root, and public corpus, and a challenge against the predecessor invalidates its pending descendants.

## The Close Never Grows (with Payments)

Every profile below uses a 100-validator committee and divides the evidence into 256 slices. Strategy-enabled prepare, deal, seal, and challenge checks share one adaptive eight-worker pool (AWS c8a.4xlarge). Certificate and withdrawal-claim checks are scalar calling-thread measurements. The first matrix varies $N$, the number of live accounts. Every account sends one entry, and the same 512 accounts receive. The fixture therefore holds $A=N$ and $B=512$ while $N$ grows from 1,024 to one million; a second matrix afterward holds $N$ at one million while the active accounts shrink.

No payment count appears because none is needed: rows and vector entries carry fixed-width cumulative totals, so every size in the table is the same for any $T$. Every fixture send is a batch of one entry. A terminal batch with more entries adds one 48-byte entry to its committed vector (and that entry's transpose image to the dealt slices), still independent of $T$. Each stage is measured independently. The fixture constructs the predecessor-state proof cache before measurement. Prepare builds the compact change, withdrawal-output, successor-state, coverage, and transpose roots from the owned close inputs while reusing that cache; deal assembles one proof slice per distinct span the committee is assigned; seal checks and retains the busiest validator's dealing, verifies each interval's combined operator countersignature and every distinct payer authorization in one randomized batch, and signs the commitment. The posted close is the corpus a reader holding the previous certified state needs: live accounts ride as one-or-two-byte rank gaps and the transpose, predecessor states, successor states, and prefixes are all derived rather than shipped. Withdrawal claims are measured from separately constructed fixtures, and the claims table after the matrix scales their own variable, the close's withdrawal count, on its own axis.

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
      <td style="text-align:right;">2.10 MB</td>
      <td style="text-align:right;">6.38 MB</td>
      <td style="text-align:right;">48.9 MB</td>
      <td style="text-align:right;">473 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">2.61 ms</td>
      <td style="text-align:right;">20.5 ms</td>
      <td style="text-align:right;">189 ms</td>
      <td style="text-align:right;">1.85 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">deal</td>
      <td style="text-align:right;">0.219 ms</td>
      <td style="text-align:right;">0.373 ms</td>
      <td style="text-align:right;">4.12 ms</td>
      <td style="text-align:right;">93.6 ms</td>
    </tr>
    <tr><th colspan="5" style="text-align:left;">Certification</th></tr>
    <tr>
      <td style="padding-left:20px;">largest dealing</td>
      <td style="text-align:right;">165 KB <span style="color:#666;">(-92.1%)</span></td>
      <td style="text-align:right;">1.09 MB <span style="color:#666;">(-82.9%)</span></td>
      <td style="text-align:right;">10.3 MB <span style="color:#666;">(-78.8%)</span></td>
      <td style="text-align:right;">103 MB <span style="color:#666;">(-78.3%)</span></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">17.5 ms</td>
      <td style="text-align:right;">57.2 ms</td>
      <td style="text-align:right;">447 ms</td>
      <td style="text-align:right;">4.34 s</td>
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
      <td style="text-align:right;"><strong>0.672 ms</strong></td>
      <td style="text-align:right;"><strong>0.672 ms</strong></td>
      <td style="text-align:right;"><strong>0.672 ms</strong></td>
      <td style="text-align:right;"><strong>0.674 ms</strong></td>
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
      <td style="text-align:right;"><strong>0.280 ms</strong></td>
      <td style="text-align:right;"><strong>0.275 ms</strong></td>
      <td style="text-align:right;"><strong>0.270 ms</strong></td>
      <td style="text-align:right;"><strong>0.271 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check HigherAckEntry</td>
      <td style="text-align:right;"><strong>0.334 ms</strong></td>
      <td style="text-align:right;"><strong>0.329 ms</strong></td>
      <td style="text-align:right;"><strong>0.323 ms</strong></td>
      <td style="text-align:right;"><strong>0.324 ms</strong></td>
    </tr>
    <tr>
      <td style="padding-left:20px;">check AckFork</td>
      <td style="text-align:right;"><strong>0.327 ms</strong></td>
      <td style="text-align:right;"><strong>0.326 ms</strong></td>
      <td style="text-align:right;"><strong>0.323 ms</strong></td>
      <td style="text-align:right;"><strong>0.318 ms</strong></td>
    </tr>
  </tbody>
</table>
</div>
```

Withdrawal and external-payout claims scale with a different variable: the claimed close's own withdrawal count $W$, never $N$, because each claim opens only that close's withdrawal-output tree. Sizes are deterministic, 39 bytes plus one 32-byte sibling per doubling of $W$, and both the $\mathsf{Amount}$ and $\mathsf{Close}$ claims share the shape. Verification recomputes that one path, 0.30 µs at a single output on the same c8a.4xlarge, adding one hash per doubling of $W$.

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

::: {.image-caption}
Figure 5: The operator prepares the roots, then deals the evidence into slices. Each validator seals its dealing by checking and retaining its assigned slices before signing the commitment. An acknowledgment holder with evidence of fraud can dispute the certified commitment with a challenge that the chain checks.
:::

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-benchmark-matrix.svg" alt="Three log-scale plots show measured latency for preparing roots, dealing all evidence slices, and sealing the busiest validator dealing as live accounts increase from 1,024 to one million.">
```

::: {.image-caption}
Figure 6: These are four measured profiles, not an interpolation. Both axes are logarithmic, and each point is labeled with its measured latency. Construction and sealing scale approximately linearly once the fixed costs are amortized.
:::

The busiest validator's dealing is 78–92% smaller than the complete proof-slice corpus. It holds two thirds of the intervals, but they form one or two contiguous runs, so the accumulator start states and range openings travel once per run instead of once per interval, and no unchanged leaves travel at all. At one million live accounts it checks 103 MB rather than the complete 473 MB corpus. That is the every-account-sends worst case, and it hides the design's real lever: dealings travel without unchanged state, because every assignee retains its key interval across closes and hydrates each dealing against it. When every account changes there is nothing to strip. When the movers are a fraction of the account set, the posted close and the dealt wire follow the movers:

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
      <td style="text-align:right;"><strong>192 KB</strong></td>
      <td style="text-align:right;"><strong>1.41 MB</strong></td>
      <td style="text-align:right;"><strong>13.7 MB</strong></td>
      <td style="text-align:right;">103 MB</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">prepare</td>
      <td style="text-align:right;">167 ms</td>
      <td style="text-align:right;">182 ms</td>
      <td style="text-align:right;">305 ms</td>
      <td style="text-align:right;">1.85 s</td>
    </tr>
    <tr>
      <td style="padding-left:20px;">seal</td>
      <td style="text-align:right;">65.6 ms</td>
      <td style="text-align:right;">458 ms</td>
      <td style="text-align:right;">1.84 s</td>
      <td style="text-align:right;">4.34 s</td>
    </tr>
  </tbody>
</table>
</div>
```

The posted close is about 72 bytes per active account plus its edges, whatever the account set holds: at 1,024 movers among one million accounts it is 74.0 KB, a thousandth of the every-account column. The dealt wire keeps one run witness and its intervals' row evidence but none of the unchanged leaves, so the busiest dealing falls from 103 MB to 192 KB across the same sweep. Prepare and deal retain a fixed cost in $N$ (the fresh state BMTs are rebuilt over all live leaves), while seal follows the movers because signature and countersignature verification dominate it.

The proof-slice corpus is constant for a profile, so accepted payments only divide it. Ten million payments spread the one-million-account profile's 472,823,270 bytes to 47.3 offchain bytes per payment, and its 71,762,697-byte posted close to 7.2; a billion payments spread them to 0.473 and 0.072. The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap; proofs of possession were checked when the committee registered. With the 32-byte commitment and this encoding's eight-byte bitmap-length prefix, the external 100-validator certified package is 101 bytes total. If the Bajillion validators are also the settlement chain's validators, inclusion itself supplies the attestation and only the 32-byte commitment need be retained. The 164-byte $\mathsf{RootBundle}$ admission witness and terminal proof are not included in either commitment figure. Each figure likewise shrinks as $1/T$.

The certified close itself queues no withdrawals. Separate fixtures use a 21-byte destination without adding the claims to certification, once with a single withdrawal output and once with a withdrawal surge in which all $N$ accounts exit through one close. The identical $\mathsf{Amount}$ and $\mathsf{Close}$ claim proofs carry only the validator-derived destination and amount plus one $\mathsf{WithdrawalOutputRoot}$ opening. At $W=1$ either claim is 39 bytes and verifies in 0.30 µs. The surge claim grows one 32-byte sibling per doubling of the withdrawal count, reaching 359 bytes when 1,024 accounts exit together and 679 bytes when one million do, and its verification grows only by the path hashes. The $\mathsf{HigherAckDebit}$ and $\mathsf{HigherAckEntry}$ challenges carry one retained acknowledgment plus one changed-row lookup, so they grow with opening depth: 620–940 and 671–991 bytes across the matrix, checking in 0.270–0.334 ms. The $\mathsf{AckFork}$ contradiction carries two countersigned endpoints and no state opening, so it holds at 417 bytes for every $N$ and checks in about 0.32 ms. Adjudication is signature-dominated, and challenge evidence is one fixed-size acknowledgment plus at most one entry opening: an acknowledged endpoint commits its whole batch through the vector root, so representing an entry of a larger batch changes nothing about the witness or its check. Clean closes submit no fraud challenge at all, so average challenge traffic is smaller still. A challenge targets a commitment whose certificate was already checked at admission, so adjudication does not verify that certificate again.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two side-by-side log-log plots divide fixed per-epoch bytes by accepted payments from one million to one billion. The left shows proof-slice corpus bytes per payment for four live-account counts; the right shows the 101-byte external certified package. Every line falls as one over T.">
```

::: {.image-caption}
Figure 7: Each panel divides fixed per-profile bytes from the table by $T$, so every line falls exactly as $1/T$. The proof-slice corpus (left) grows with the live-account count $N$. The external certified package (right) stays 101 bytes across profiles.
:::

## A Bajillion Payments, One Settlement

The operator's online work scales with payments: it verifies, durably commits, and signs every one of the $T$ payments it accepts. The close has no per-payment term. Writing $U$ for unchanged live leaves, $A$ for changed rows, $E$ for edge entries, $W$ for withdrawal outputs, $S$ for proof slices, and $M$ for the largest committed vector length, its authenticated corpus is

$$
\text{payments }T
\quad\longrightarrow\quad
U\text{ state leaves}+A\text{ rows}+E\text{ vector entries}+E\text{ transpose entries}
+W\text{ withdrawal outputs}+(S+1)\text{ coverage boundaries}+O(S\log M)\text{ openings},
$$

and the posted close omits $U$, the transpose, and every derivable column outright. For the benchmark's fixed live set, $U=N-A$; account creation, deletion, and external-payout rows need not preserve that identity in general. For repeated activity over a fixed set of accounts and edges, this fixed corpus divided by $T$ tends to zero. Account-level clearing compresses repetition, not state: every unchanged live account contributes a leaf to the dealt evidence and nothing to the posted close, every changed account contributes a row, and every edge contributes one cumulative entry on each side, but additional payments between them add nothing. No traffic pattern adds a per-payment term to the close either, because acceptance reserves room per account and per edge, never per payment.

Figure 8 prices these terms live. It is the codec, not a fit: every byte follows the encodings above at one varint byte per amount and count, including the Merkle range openings, and fed the benchmark's per-slice counts it reproduces the measured matrix to the byte. The calculator spreads accounts, senders, and edges evenly over the 256 slices and assumes every edge credits a distinct account.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive wire-size calculator. Sliders set the account count, the mean out-degree, and the committee size. Readouts give the certified close, the dealt corpus, the busiest validator's dealing, and the operator's egress per close.">
  <noscript>With JavaScript enabled this figure is a live calculator over the encodings above. At one million accounts each sending one entry to a distinct account, the certified close is 73 MB, the dealt corpus 171 MB, the busiest validator's dealing 114 MB, and the operator's egress 11.3 GB across 100 validators.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 8: The encodings, live. Below mean out-degree one, only $E$ accounts send (out-degree one each) to $E$ distinct recipients, so $2E$ accounts change; at one and above every account sends and receives. The certified close carries no account-count term, so it keeps falling with activity and pays about 5 bytes per edge regardless of skew. The dealt corpus is every slice once, the busiest dealing is the largest validator's share (two contiguous runs at $n=3f+1$, about two thirds of the slices, with the accumulator start states and range openings once per run), and operator egress ships one dealing to each validator. Committee sizes snap to $n=3f+1$.
:::

The fresh tree is intentionally conventional. Root-only construction can stream an existing ordered account database through bounded subtree builders; proof-producing close assembly retains the Merkle levels needed for slice openings. Neither requires maintaining durable authenticated paths for every pending root. In exchange, validators receive evidence for the complete live state rather than only a sparse update. A preconfirmation still cannot arrive in less than one round trip to the operator that serializes spending, and a close cannot quietly drop a payment: it must agree with every acknowledgment a holder retains, or a single retained entry receipt proves the fault.

When the close is clean, those involved keep the receipts. The settlement chain only keeps the change.
