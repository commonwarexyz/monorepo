---
title: "Keep the Change"
description: "$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years."
date: "August 19th, 2026"
published-time: "2026-08-19T00:00:00Z"
modified-time: "2026-09-15T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/clearing"
image: "https://commonware.xyz/imgs/clearing.png"
katex: true
---

*Update (9/15/26): Operators can process payments to the same recipient in parallel across payers, with one signature check covering each payer's batch. Validators retain the account state, activity, payouts, and local signing decisions in native QMDB owners and apply only the changes at each settlement.*

*Update (8/20/26): Clearing now uses a 32-byte commitment and BLS12-381 multisignatures for the commitment certificate.*

\$0.000001 payments cost more to replicate, settle onchain, and index than they're worth. Yet your agent will need to make millions of them over the coming years.

If we can't use blockspace to scale to a billion TPS (or at least don't want to cover the tab of doing so), what else could we do? Payment channels are cheap and instant between two funded parties, but reaching a new recipient means opening a new channel or asking existing ones to route for you (locking their liquidity and risking forced closure along the way). Rollups either prove a batch's state transition or publish enough transaction data for anyone to replay and challenge it. Even then, binding sequencer preconfirmations need a separate challenge for signed payments omitted from the batch (see [The Unavoidable Challenge](#the-unavoidable-challenge)).

**Bajillion** is a new optimistic clearing protocol for many-to-many payments at massive scale. At each settlement, all of that activity is bound by a \~100-byte certified commitment that most chains can process. Binding receipts arrive as fast as browsing the web and double as the evidence that holds the system honest. Payments flow through a non-custodial operator selected by the sender: if the operator disappears or censors an account, senders and recipients alike can force recovery onchain without its cooperation. And the protocol requires only signatures and Merkle openings.

One payment or a bajillion, each account settles once.

## Payments as Fast as Browsing the Web

If an API responds in milliseconds, no one will wait seconds to pay for it.

With Bajillion, a user can pay an API provider without waiting for settlement. Their chosen payment operator returns a binding receipt in one round trip. The user sends it with the API request, or the operator delivers it directly to save a hop. The provider can serve the response knowing the receipt gives it evidence to hold the operator accountable if settlement omits or contradicts the payment. The operator later nets payments across accounts without separate channels or funded routes, dramatically reducing the data needed for settlement.

Suppose a user $a$ has 100 and wants to pay 20 to $b$, who has 40. The operator verifies and records $a$'s signed request $S$, then countersigns it as $R$. Before forwarding the receipt to $b$, $a$ verifies and retains it.

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
Figure 1: The dotted path is an optional operator push that reaches the recipient one hop earlier. The entry accumulates amount and payment count.
:::

Payments are grouped into epochs. Every signature in epoch $e$ binds that epoch's onchain anchor $\mathcal A_e$.

The payer tracks a balance $B_a$ and an epoch's total debit $D_a$, initially zero. It keeps a vector $V_a$ ordered by recipient, with one entry $(G,J)$ recording the cumulative amount and payment count for each. Before the example payment, $B_a=100$, $D_a=0$, and $V_a$ is empty.

To send $x>0$, $a$ advances $b$'s entry and signs the updated epoch-local sequence number $n_a$, cumulative debit, and vector's Merkle root. The operator countersigns this endpoint:

$$
S=\mathsf{Sign}_a\bigl(\mathcal A_e,\;n_a,\;D_a+x,\;\mathsf{root}(V_a\text{ with }b:(G+x,\,J+1))\bigr),
\qquad
R=\mathsf{CounterSign}_{\mathsf{op}}(S).
$$

For this payment, $n_a=1$, $D_a=20$, and $V_a=\{b:(20,1)\}$.

The wallet keeps one unacknowledged request in flight, retries it unchanged after response loss, and durably saves the verified acknowledgment and openings before signing the next endpoint. One signature can also advance several recipients in a batch. The operator accepts or rejects the whole batch and returns one acknowledgment with an opening for each advanced entry.

## Optimizing for Hot Accounts

Bajillion defines each payment as an update to the payer's outgoing vector. This lets the operator accept payments from different payers in parallel, even when they share a recipient. Existing accounts can spend receipt-backed incoming credit within the epoch, before settlement. A payment of $x$ on the edge $a\rightarrow b$ advances only that edge's entry in $a$'s vector:

$$
(G_{ab},J_{ab})\longrightarrow(G_{ab}+x,J_{ab}+1),
\qquad
\text{every other entry of every other vector unchanged.}
$$

However many payments an edge carries, the epoch ends with one cumulative entry for it.

Suppose accounts $(a,b,c,d)$ start with balances $(100,40,25,35)$ and make these payments:

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

## One Row per Active Account

When an epoch ends, the operator builds a **close**, the settlement package that nets its payments into new account balances. Each payer's last vector of the epoch is its terminal vector. The operator and validators derive incoming credits from these vectors: $b$ receives $20+4+6=30$ across three payments. Each entry is authenticated by its payer's signed vector root.

Netting each of the four accounts' debits and credits gives exact successor balances: $a$ ends at $100-20+5=85$, $b$ at $40-12+20+4+6=58$, $c$ at $25-7-4+12=26$, and $d$ at $35-5-6+7=31$. Gross debit equals gross credit at $20+12+7+5+4+6=54$, and the balances still sum to 200. The six payments change four account rows, one per account.

For each account, the opening and closing balances are $B_a^0$ and $B_a^1$, with debit and credit deltas $d_a$ and $c_a$. Deposits $f_a$ and withdrawals $w_a$ complete the balance equation:

$$
\boxed{B_a^1+d_a+w_a=B_a^0+c_a+f_a.}
$$

Every payment credits its recipient's balance. A close creates payouts only for authorized withdrawals.

Each epoch records one row for every disclosed participant, including accounts whose net balance change is zero. The rows are sorted by account key and contain no duplicates. A sender's row includes its last signed payer state. Every validator derives the resulting balances and checks the epoch's gross debit $D_e$ and credit $C_e$:

$$
\boxed{D_e=C_e.}
$$

Here $D_e=C_e=54$. Summing account balances into $L_e$ and $L_{e+1}$ cancels payments, leaving only deposits $F_e$ and withdrawals $W_e$:

$$
\boxed{L_{e+1}=L_e+F_e-W_e.}
$$

Without deposits or withdrawals, $L_{e+1}=L_e=200$.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-netting.svg" alt="100 million payments across six directed pairs net into balance changes for four active accounts. Account a sends $30 and receives $10, moving from $100 to $80. Account b sends $25 and receives $55, moving from $40 to $70. Account c sends $20 and receives $25, moving from $25 to $30. Account d sends $25 and receives $10, moving from $35 to $20. The close retains six cumulative entries and four account records.">
```

::: {.image-caption}
Figure 2: A separate epoch with 100 million payments of \$0.000001, one atomic unit each. Every sender uses its own opening funds. The arrows group independent payments by sender and recipient, with both directions between $b$ and $c$ retained in the close.
:::

QMDB Current Ordered with MMB stores each live account's balance under its public key, committed by $\mathsf{StateRoot}$. Deposits and payments can add accounts, and a zero balance removes the record. Payment totals and counts belong to the epoch's evidence.

When a payment names a new public key, the operator records a balance for it without an onchain registration transaction. The recipient can spend the balance after the close is admitted, or let payments from many senders accumulate across multiple closes before authorizing a sweep.

## Keep the State, Send the Changes

Every validator retains the complete account state in QMDB. At each close, the operator publishes one dealing for all of them: active account keys, senders' terminal signed payer states, and cumulative payment entries. Recipients are identified by position in the account list. A CDN can cache this shared dealing for efficient distribution.

Each validator checks the payer signatures and the operator's countersignatures, derives incoming credits, and combines them with its stored balances and the deposits and withdrawals fixed at epoch registration.

From these results, the validator computes the next QMDB state root and appends two flat logs. The activity MMR receives the epoch's compact, sorted, unique account rows, including zero-net participants so their receipts remain challengeable, followed by one commit containing the original source inputs needed to reconstruct requested proofs. The payout MMR receives every external payout output, currently the validator-derived output for each authorized withdrawal, followed by its own commit. Payer vectors remain BMTs under the users' signed payer states; flattening the public logs does not change those signatures or their openings.

The certified activity interval $[A_e^0,A_e^1)$ identifies exactly the epoch's contiguous account-row positions; its source-metadata commit follows outside that range. The payout interval $[P_e^0,P_e^1)$ identifies exactly the candidate output positions; once those outputs finalize, their global indices are never reused. Its metadata-free commit follows them. An empty epoch certifies equal activity offsets; an epoch without outputs certifies equal payout offsets. QMDB updates positive balance records incrementally and removes an account when its balance reaches zero.

All three roots are results of validation. A 32-byte commitment binds a ProposalId for the canonical dealing bytes, the successor QMDB root, activity-MMR root and count, candidate payout-MMR root and count, and exact certified row and output ranges to the epoch, their predecessor values, and the close's totals. Validators already hold the balances needed to compute the new state, so the dealing needs no state-change proof. They promote the selected candidate state once the close is admitted.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-trees.svg" alt="Each validator derives the three shared protocol roots: the balance root and the cumulative activity-MMR and candidate payout-MMR roots and counts. The commitment binds them to the ProposalId, epoch, predecessor, ranges, and outflow totals. The abbreviated activity-log slice shows prior operations followed by this epoch's contiguous a, b, c, and d rows, then one source-metadata commit outside the certified row range. QMDB carries positive balances of a: 85, b: 58, c: 26, and d: 31 into the next epoch. Account c's activity row shows 11 sent, final batch sequence 2, no withdrawal, and a link to its signed payment BMT: one payment of 4 to b and one of 7 to d. This epoch creates no payouts and appends only the metadata-free payout-log commit. The payout panel shows the stable append location, destination, and amount opened against the current finalized root and count. A private local QMDB that protects the validator's signing decisions is not part of the certified commitment and is not shown.">
```

::: {.image-caption}
Figure 3: The commitment links the three shared protocol roots and log counts to the ProposalId and certified close context. The cumulative activity-log slice brackets this epoch's compact account-row range; its single source-metadata commit follows outside the range. Expanding $c$'s row shows the payer-vector BMT that its signature binds. The validator's private signing-control QMDB is not another certified root.
:::

The settlement chain holds pooled custody, the certified state root, current finalized log heads, bounded pending log metadata, control and boundary state, and a map of unclaimed payout intervals. It does not store every account row, output, claimed index, or finalized epoch descriptor.

Validators own the authenticated state and log construction. The operator only has to collect signed payer and boundary data and propose the dealing; serving payments and preparing a close do not require it to construct QMDB or either MMR. It may run best-effort replicas to serve balance, challenge, and payout openings directly.

The storage target gives each validator three shared native owners: Current Ordered QMDB over MMB for live positive balances, plus keyless QMDB operation logs over MMR for activity and payouts. A fourth, private compact QMDB stores only bounded local control snapshots: the selected public-store checkpoint, an optional candidate, at most one immutable signing decision, and cleanup state. It uses metadata-only commits, is never included in the root bundle or certificate, is never imported from a peer, and is never rewound with the three shared stores. After a completed update or reopen, native pruning pins its latest control state within one 16-witness section, retaining at most 16 bounded snapshots. Reopen cleans up any older section left by an interrupted update.

The protocol logs are flat--there is no tree per epoch--and proof construction can walk retained native operations on demand. Each activity epoch is exactly its contiguous account rows followed by one source-metadata commit. That metadata stores the close context, each row's terminal sequence and original outgoing entries, and the exact signed withdrawal batch. The account key and epoch come from the corresponding row and context; debit totals, payer-vector roots, withdrawal totals, and BMT openings are reconstructed when requested. It stores no duplicate BMT nodes, proof index, full-close body, root bundle, header, or payout head. Private payer receipts remain with the wallets that rely on them.

Each payout epoch is exactly its output appends followed by a metadata-free commit. Account rows and payout outputs use stable append locations, while the commit gaps are excluded from their certified ranges. An opening proves the exact typed append operation at the committed operation count. Even an empty epoch writes both native commits: the certified descriptor authenticates its empty row and output ranges, and each commit authenticates the pruning floor. Registration fixes the finalized operation count $s_f$, and every signer uses $s_f-1$ as the floor for descendants of that registration. Local availability may delay physical deletion but cannot change the signed floor.

The private control QMDB records one checkpoint naming the three shared roots, operation counts, and safe synchronization boundaries. Before a vote or acknowledgment can leave a validator, all three candidate stores are committed and synchronized, then a private metadata-only commit records the coherent candidate checkpoint and exact immutable signing decision. That commit's native prune and synchronization form the local publication barrier; no vote or acknowledgment leaves until they complete.

After a mixed crash, the validator recovers the latest private control commit first and aligns all three shared stores to its selected common target. While the coherent candidate remains retained, an exact retry reissues the saved vote. Disposal durably selects the canonical parent in the private QMDB before rewinding and synchronizing the public stores; it preserves the signing decision and blocks every further vote for that epoch until canonical advancement. Catch-up imports only an authenticated public triplet from a coherent native replica; peer control state can never authorize local signing. The validator does not keep a full-close corpus merely to redo local state. Finalized activity locations and issued payout locations are never repurposed. Public-store deletion stays behind every protected proof and recovery boundary, and older protected roots are served from retained historical operations rather than by rewinding the live stores.

## Certify the Whole Close

A committee of $n=3f+1$ validators tolerates at most $f$ Byzantine members. Every signer checks the complete close, derives the same transitions, and signs the same commitment. A certificate needs $q=2f+1$ signatures.

The canonical dealing bytes also receive a separate $\mathsf{ProposalId}$. It hashes a distinct domain, the authenticated epoch context, and a length-framed encoding of the dealing. The certified transition binds that identifier, the exact predecessor snapshot, all three successor roots, both log counts and epoch ranges, and the outflow totals. This lets the operator check that a certificate belongs to its proposal without rebuilding the validators' cumulative logs.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-full-validation.svg" alt="The operator sends the same dealing to 100 validators. The blue callout expands c's sender record: final sequence 2, a total of 4 to b and 7 to d, each with count 1, bound by c's signature. Four acknowledgment cards show the operator's signatures accepting the final payer states of a, b, c, and d. The c card is highlighted. An Aggregate arrow leads to the single aggregate signature included in the dealing. Validators derive the final commitment. The green callout shows the QMDB state root and the activity and payout MMR roots and counts, bound to the ProposalId, predecessor, epoch ranges, and outflow totals by a 32-byte commitment. An aggregate signature and signer bitmap form its 67-of-100 certificate. Each validator also persists a private control-QMDB decision before acknowledging, but that local root is not part of the certified candidate and is not shown.">
```

::: {.image-caption}
Figure 4: Each validator derives the three candidate roots and log counts from the shared dealing. One aggregate signature and signer bitmap show that 67 of 100 validators signed the resulting commitment. This is the certified pending transition; FIFO finalization separately advances the finalized payout root and count. The private control QMDB gates each validator's acknowledgment but is not another candidate root.
:::

Once the accepted transition is present in all three durable shared stores and the validator's private control commit, validation-only inputs can be retired. Validators keep native rows, source commits, log nodes, and QMDB history for every FIFO, challenge, and recovery obligation that can still reach them. Once no live obligation can refer to a prefix, they may prune its rows and nodes while retaining the authenticated prefix hashes needed to continue each log. Pruning saves replica storage without changing the root or global positions; it does not make proofs shorter. A new validator synchronizes the three shared native stores, including activity commit metadata, from an authenticated boundary and checks the resulting roots and counts; private signer state is initialized locally, never accepted from a peer.

Proof availability can outlive a hot validator's retention window. Roots authenticate data without supplying it, so a user, operator, or proof service can run the same native QMDB replicas with longer retention and serve old balance, receipt, source, and payout openings. Native state synchronization transfers the proof-bearing records; no parallel Bajillion proof archive or full-close copy is required. Hot-validator pruning is not pinned by the oldest unclaimed output or by an offline optional replica, and consensus does not require every validator to retain lifetime history. If every longer-retention replica discards a needed prefix, its proof is unavailable, but that absence neither expires the entitlement nor proves that a request was never carried.

A cold source proof authenticates the complete bounded source-metadata commit under the finalized activity head, paired with the payout head from the same settlement snapshot. It therefore transmits and hashes that whole metadata frame, and locating an old epoch may walk the retained metadata between known boundaries. This is an offchain provenance path for old receipts and requests, separate from the compact onchain challenge and claim proofs checked against admitted or current heads.

The certificate is one 48-byte aggregate signature plus a $\lceil n/8\rceil$-byte signer bitmap, with proofs of possession checked when the committee registered. With the 32-byte commitment and an eight-byte bitmap-length prefix, the 100-validator signed header and certificate are 101 bytes. The validator-derived root bundle is 176 bytes; adding the eight-byte withdrawal total makes its descriptor 184 bytes, or 285 bytes together before chain transaction framing. These values are separate from the operator's dealing.

The settlement chain admits the certified close into an ordered queue. A close can finalize only after its challenge deadline $\Delta_e$ has passed and every earlier close has finalized. Candidate log storage may already contain a pending descendant, but a successful challenge discards that logical suffix. Discarded outputs never advance the finalized payout root or create unclaimed claim intervals.

## The Unavoidable Challenge

A certificate establishes that the disclosed close is internally valid. The operator could still have signed a promise it left out.

Consider two executions with the same public close $\mathcal D_e$ and certificate, proof, or attestation $\zeta$. In $\Xi_0$, the operator signs only the acknowledgments represented by the close. In $\Xi_1$, it also delivers a valid private acknowledgment $R^+$. The verifier sees the same evidence in both:

$$
\mathsf{View}(\Xi_0)=(\mathcal D_e,\zeta)=\mathsf{View}(\Xi_1).
$$

If it accepts $\Xi_0$, it must accept $\Xi_1$. A committee, TEE, or SNARK/STARK can verify the published inputs. Certifying those inputs cannot rule out an additional private receipt.

The certified activity interval records the epoch's terminal row for every disclosed account. A missing payer counts as zero debit, so a proof of absence can challenge an omitted payment. For a nonempty epoch, absence is proved by MMR membership for the adjacent account keys at adjacent positions, or by membership at the left or right edge. Equal certified start and end offsets prove that the epoch is empty. Strict key ordering and uniqueness make these cases exhaustive.

Receipt holders can prove three kinds of contradiction:

1. **Debit mismatch.** For example, the close records a cumulative debit of 20 after the operator acknowledged 35.

2. **Entry mismatch.** A retained entry promises more value or more payments to a recipient than the close records.

3. **Acknowledgment fork.** The operator countersigns different bodies at the same payer sequence number.

Because certification has checked the accounting and signed terminal positions, a receipt holder can prove a contradiction with signatures, an activity-MMR opening, and any signed payer-vector BMT opening in one onchain call, without an interactive dispute game. Every receipt a user relies on needs an honest holder who retains the private receipt, obtains the public openings from a sufficiently retained native replica, and gets a challenge included by $\Delta_e$. No replica can reconstruct a private receipt nobody saved.

Suppose $b$ has already served the API response, but the operator leaves $a$'s payment of 20 out of the close. The receipt and a public proof of the omission let $b$ prove operator fault without the operator's cooperation. That is what makes the receipt binding. An application could use this evidence to compensate $b$ from an onchain insurance fund, permanently exclude the operator, or support offchain resolution. The recipient can seek a remedy beyond simply deciding not to use that operator again (unlike other approaches that offer only best-effort preconfirmations).

## A Deadline to Exit

A successful challenge stops a contested close from finalizing, but users must still be able to get their funds out. Every account can authorize an exact withdrawal or an account close. Normally the operator includes that signed request in the next epoch's boundary. A censored user can instead queue it directly onchain, even during an active epoch. The next registration must include it.

Once a withdrawal request is queued onchain or included in an admitted close, its carrying close must finalize before the signed deadline $T_w$ to avoid a hard fault. With challenge deadline $\Delta_e$,

$$
\boxed{\Delta_e<t_{\mathrm{finalize}}<T_w.}
$$

An exact withdrawal releases its amount if the epoch's final balance covers it. An account close sweeps that balance. Every derived withdrawal output, including a zero-valued one, is appended to one payout MMR at a stable global index. The output binds its index, destination, and amount. It has no claim deadline and its index is never recycled. A zero-valued output must still be consumable, even when its reserve is zero, so it cannot keep an interval alive forever.

Pending closes have candidate payout roots and counts, but their outputs are not yet claimable. When the carrying close reaches FIFO finality, the chain advances its distinct finalized payout root and count, reserves the exact outflow, and adds the newly finalized index interval to a direct map of unclaimed intervals. A challenged or invalidated suffix advances none of them.

A claim supplies the output, an MMR opening against the current finalized payout root and count, and the start key $s$ of the current unclaimed interval $[s,t)$ containing its index $i$. The map stores only $t$ under $s$. The chain checks $s\le i<t$, then removes the interval and inserts the nonempty pieces $[s,i)$ and $[i+1,t)$. This split, the reserve reduction, and the payout happen atomically. A replay finds no interval containing $i$.

The map has at most one range per outstanding output even under adversarial claim order, so claim state is $O(U)$ for $U$ unclaimed outputs in the worst case, not proportional to all claims ever made. It is not another authenticated claim tree. The full settlement state consists of the three principal tree roots and their counts, timing-window-bounded pending-close metadata, pooled and reserved custody, registration and fault controls, and these unclaimed intervals.

### Hard Fault

If the operator misses an admission, deposit, or withdrawal deadline, or a holder proves a fault, the deployment permanently stops new work. Clean pending closes ahead of a disputed close may still finalize. Recovery then freezes the last finalized state root.

The recovery rules keep finalized payouts independently claimable, with no expiry, and refund unadmitted deposits. Accounts recover their balances with QMDB proofs against the frozen root, and each account can claim only once. Payments in a never-admitted or invalidated close do not debit that state or promote its candidate payout suffix.

Recovery needs a correct, live settlement chain and independently available balance and payout openings even when the operator disappears. Commitment roots alone cannot serve those witnesses; longer-retention native replicas do. A fault freezes the last surviving finalized payout root and count, against which later claims refresh their openings.

## Streamlined Epoch Transitions

A payment reaches finality through an admitted close, after the challenge deadline fixed at epoch registration. Shorter epochs with earlier deadlines can reduce that wait, but require more frequent preparation and certification.

Once epoch $e$'s close is admitted, the operator can register $e+1$ against its $\mathsf{StateRoot}$ and start payments before $e$ finalizes. Registration fixes deposits and signed withdrawal authorizations before the first payment is acknowledged.

For accounts without deposits or withdrawals, new payments can overlap credit imports. The preserved head $\widetilde B_a$ is the starting balance minus accepted predecessor debits plus credits already imported. The remaining predecessor credit is $\rho_a$:

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
Figure 5: Both calculations include the same predecessor credit. Importing it adds to the live balance, preserving payments already accepted in the successor epoch.
:::

Accounts with deposits or withdrawals must resolve their full admitted outcome before spending in the successor epoch.

## The Close Follows Accounts and Edges

We benchmarked the native flat-log extension of the [initial implementation](https://github.com/commonwarexyz/monorepo/pull/4664) with 1,024 live accounts and 128 self-payment rows. The matrix varies prior history and a full exit independently: $H$ counts prior account rows and $W$ counts new withdrawal outputs. With $W=0$, the close has 128 activity rows; a full exit has 1,024 because every withdrawing account participates. The operator Dealing encoding modeled in Figures 7 and 11 is unchanged: ProposalId and the three resulting roots belong to the validator-derived close descriptor, not the operator's payload. Full confidence intervals, samples, encoded-byte tables, and reproduction inputs are in the [benchmark artifacts](https://github.com/commonwarexyz/monorepo/blob/1bd5f46162be55ed5858a63adf3e20d78814dc5f/clearing/src/bajillion/benches/results/2026-09-15-flat-mmrs/README.md).

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Measurement</th>
      <th colspan="4" style="text-align:center;">History and new withdrawal outputs</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>H</em> = 0<br><em>W</em> = 0</th>
      <th style="text-align:right;"><em>H</em> = 1,024<br><em>W</em> = 0</th>
      <th style="text-align:right;"><em>H</em> = 0<br><em>W</em> = 1,024</th>
      <th style="text-align:right;"><em>H</em> = 1,024<br><em>W</em> = 1,024</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Operator Dealing</td>
      <td style="text-align:right;">13,107 B</td>
      <td style="text-align:right;">13,107 B</td>
      <td style="text-align:right;">43,571 B</td>
      <td style="text-align:right;">43,571 B</td>
    </tr>
    <tr>
      <td>Root-and-outflow descriptor</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
      <td style="text-align:right;">184 B</td>
    </tr>
    <tr>
      <td>Signed commitment + certificate</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
      <td style="text-align:right;">101 B</td>
    </tr>
  </tbody>
  <tbody>
    <tr><th colspan="5" style="text-align:left;">Processing phases</th></tr>
    <tr>
      <td style="text-align:left;">Prepare three native batches</td>
      <td style="text-align:right;">48.5 µs</td>
      <td style="text-align:right;">46.4 µs</td>
      <td style="text-align:right;">725 µs</td>
      <td style="text-align:right;">717 µs</td>
    </tr>
    <tr>
      <td style="text-align:left;">Decode Dealing</td>
      <td style="text-align:right;">1.98 ms</td>
      <td style="text-align:right;">1.99 ms</td>
      <td style="text-align:right;">15.7 ms</td>
      <td style="text-align:right;">15.7 ms</td>
    </tr>
    <tr>
      <td style="text-align:left;">Validate + prepare state/logs</td>
      <td style="text-align:right;">1.56 ms</td>
      <td style="text-align:right;">1.67 ms</td>
      <td style="text-align:right;">3.39 ms</td>
      <td style="text-align:right;">3.33 ms</td>
    </tr>
    <tr>
      <td style="text-align:left;">Apply state + logs</td>
      <td style="text-align:right;">16.4 µs</td>
      <td style="text-align:right;">22.1 µs</td>
      <td style="text-align:right;">240 µs</td>
      <td style="text-align:right;">269 µs</td>
    </tr>
    <tr>
      <td style="text-align:left;">Commit three shared stores in memory</td>
      <td style="text-align:right;">51.6 µs</td>
      <td style="text-align:right;">73.9 µs</td>
      <td style="text-align:right;">232 µs</td>
      <td style="text-align:right;">261 µs</td>
    </tr>
    <tr>
      <td style="text-align:left;">Decode through apply</td>
      <td style="text-align:right;">3.54 ms</td>
      <td style="text-align:right;">3.73 ms</td>
      <td style="text-align:right;">19.4 ms</td>
      <td style="text-align:right;">19.4 ms</td>
    </tr>
    <tr>
      <td style="text-align:left;">Decode through memory commit</td>
      <td style="text-align:right;">3.63 ms</td>
      <td style="text-align:right;">3.79 ms</td>
      <td style="text-align:right;">19.6 ms</td>
      <td style="text-align:right;">19.6 ms</td>
    </tr>
  </tbody>
</table>
</div>
```

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th style="text-align:left;">Real balance-update phase</th><th style="text-align:right;">1,024 active of 1,024 accounts</th></tr>
  </thead>
  <tbody>
    <tr><td>Operator Dealing</td><td style="text-align:right;">105,267 B</td></tr>
    <tr><td>Operator: prepare Dealing</td><td style="text-align:right;">678 µs</td></tr>
    <tr><td>Validator: receive and apply</td><td style="text-align:right;">7.70 ms</td></tr>
    <tr><td>Validator: sign vote</td><td style="text-align:right;">70.6 µs</td></tr>
    <tr><td>Verify certificate</td><td style="text-align:right;">455 µs</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 6: Native transition matrix for the three shared stores and a separate nonzero-balance update profile. The matrix uses 1,024 live accounts, 128 self-payers, and either no withdrawals or a full 1,024-account exit. The second profile has 1,024 live accounts and senders, with 512 recipients. The descriptor and signed commitment are both submitted at chain intake; transport framing is excluded.
:::

Times are Criterion medians from ten samples on an Apple M5 Pro with 18 logical CPUs and 64 GiB of memory. The native matrix and receive-and-apply use 16 workers and deterministic in-memory storage. Preparing the three native batches starts after state mutations and outputs are derived; validation starts from a decoded Dealing. The complete pipeline rows overlap the individual phases and should not be added to them. Memory commit includes native journal processing, not durable SSD I/O. These timers stop after the three shared state/log stores; the terminal's subsequent private control-QMDB commit and prune, and therefore whole wire-to-acknowledgment durability, are not measured. Fixture construction, signing, rewind, votes, certificates, network transfer, and chain processing are outside the native matrix timers. In the second table, preparation assembles and encodes the Dealing, receive-and-apply decodes and validates it, signs a vote, and applies all three shared stores, while the last two rows sign an already prepared header and check an exact quorum certificate. The host was not isolated from ordinary background processes.

Repeated payments between the same pairs reuse these settlement records, spreading their byte cost over more payments.

```{=html}
<img class="clearing-benchmark-plot" src="/imgs/clearing-bytes-per-payment.svg" alt="Two log-log plots show modeled bytes per payment as one million to one billion unit payments pass between fixed pairs. The left shows one validator's keyed update for four account counts, including growing cumulative counters. The right shows the 101-byte commitment and certificate.">
```

::: {.image-caption}
Figure 7: Operator Dealing model. Every account repeatedly pays one unit to its next neighbor. Counters grow, while more payments share the byte cost of one validator's update and the 100-validator committee's certificate. The validator-derived 184-byte root-and-outflow descriptor is separate from the unchanged Dealing; the plotted 101 bytes are its signed header and certificate.
:::

### Native Proof Sizes and Verification

Activity challenges now open the certified epoch range in the cumulative native log. The table samples complete encoded account lookups across independent historical-row ($H$) and current-row ($R$) dimensions. In these fixtures, $H>0$ occupies one prior close and $H=0$ has no prior close. Each close adds a Commit, so distributing the same $H$ across a different history can change the operation count, floor, topology, and proof size. An empty range needs no MMR opening. Presence includes the activity value; an interior exclusion includes the two adjacent guards. Signed receipts and payer-vector BMT openings are separate and unchanged.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr><th rowspan="2" style="text-align:left; vertical-align:bottom;">Activity lookup</th><th colspan="3" style="text-align:center;">Historical rows (<em>H</em>)</th></tr>
    <tr><th style="text-align:right;">0</th><th style="text-align:right;">1,024</th><th style="text-align:right;">65,536</th></tr>
  </thead>
  <tbody>
    <tr><td>Empty absence, <em>R</em> = 0</td><td style="text-align:right;">4 B<br><small>5.65 ns</small></td><td style="text-align:right;">4 B<br><small>5.66 ns</small></td><td style="text-align:right;">4 B<br><small>5.73 ns</small></td></tr>
    <tr><td>Presence, <em>R</em> = 1</td><td style="text-align:right;">125 B<br><small>360 ns</small></td><td style="text-align:right;">158 B<br><small>415 ns</small></td><td style="text-align:right;">159 B<br><small>419 ns</small></td></tr>
    <tr><td>Adjacent absence, <em>R</em> = 2</td><td style="text-align:right;">207 B<br><small>420 ns</small></td><td style="text-align:right;">240 B<br><small>507 ns</small></td><td style="text-align:right;">241 B<br><small>508 ns</small></td></tr>
    <tr><td>Presence, <em>R</em> = 1,024</td><td style="text-align:right;">414 B<br><small>843 ns</small></td><td style="text-align:right;">446 B<br><small>899 ns</small></td><td style="text-align:right;">447 B<br><small>927 ns</small></td></tr>
    <tr><td>Adjacent absence, <em>R</em> = 1,024</td><td style="text-align:right;">464 B<br><small>934 ns</small></td><td style="text-align:right;">528 B<br><small>987 ns</small></td><td style="text-align:right;">529 B<br><small>1.02 µs</small></td></tr>
  </tbody>
  <tbody>
    <tr><th colspan="4" style="text-align:left;">Complete noninteractive challenges, <em>N</em> = 1,024 and <em>H</em> = 0</th></tr>
    <tr><td>Debit mismatch</td><td colspan="3" style="text-align:right;">623 B<br><small>172 µs</small></td></tr>
    <tr><td>Entry mismatch</td><td colspan="3" style="text-align:right;">674 B<br><small>203 µs</small></td></tr>
    <tr><td>Acknowledgment fork</td><td colspan="3" style="text-align:right;">417 B<br><small>199 µs</small></td></tr>
    <tr><td>Omitted payer</td><td colspan="3" style="text-align:right;">641 B</td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 8: Actual native activity-log encodings and complete challenge encodings, with Criterion medians from 20 samples below each measured size. $H$ and $R$ exclude native Commit markers. Each lookup cell includes the variant and its value or guards and opening; the certified 48-byte log head and epoch range are separate. Compact-proof times verify already-decoded values. Challenge times decode and adjudicate the complete debit, entry, or fork challenge; omitted-payer adjudication was not timed. Edge exclusions use one guard and can be smaller. Sizes vary with position and MMR topology, so these samples are not upper bounds.
:::

A payout opens at a stable global index under the current finalized payout root and count. The proof must be refreshed as that root advances. Its MMR path follows cumulative log topology, not just the current close's output count $W$, and physical prefix pruning does not shorten it.

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Measurement</th>
      <th colspan="3" style="text-align:center;">Historical outputs (<em>H</em>)</th>
    </tr>
    <tr>
      <th style="text-align:right;">0</th>
      <th style="text-align:right;">1,024</th>
      <th style="text-align:right;">65,536</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Commit proof, <em>W</em> = 0</td><td style="text-align:right;">46 B<br><small>187 ns</small></td><td style="text-align:right;">79 B<br><small>232 ns</small></td><td style="text-align:right;">80 B<br><small>293 ns</small></td></tr>
    <tr><td>Current claim, <em>W</em> = 1</td><td style="text-align:right;">105 B<br><small>249 ns</small></td><td style="text-align:right;">138 B<br><small>321 ns</small></td><td style="text-align:right;">139 B<br><small>409 ns</small></td></tr>
    <tr><td>Middle current claim, <em>W</em> = 512</td><td style="text-align:right;">362 B<br><small>742 ns</small></td><td style="text-align:right;">394 B<br><small>778 ns</small></td><td style="text-align:right;">395 B<br><small>994 ns</small></td></tr>
    <tr><td>Middle current claim, <em>W</em> = 1,024</td><td style="text-align:right;">394 B<br><small>748 ns</small></td><td style="text-align:right;">426 B<br><small>1.07 µs</small></td><td style="text-align:right;">427 B<br><small>860 ns</small></td></tr>
    <tr><td>Earliest historical claim, refreshed after <em>W</em> = 1,024</td><td style="text-align:right;">not applicable</td><td style="text-align:right;">426 B<br><small>799 ns</small></td><td style="text-align:right;">587 B<br><small>1.11 µs</small></td></tr>
  </tbody>
</table>
</div>
```

::: {.image-caption}
Figure 9: Actual native payout-log encodings, with 20-sample Criterion median verification time below each size. The verifier starts from the decoded proof. Nonempty artifacts are complete claims with a 30-byte output; $W=0$ is an opening plus the Commit operation, not a claim. $H$ and $W$ exclude Commit markers, and the 48-byte current finalized head is separate. Current rows use a middle output except where labeled. Position, floor, and MMR topology affect size; these samples are not upper bounds.
:::

Cold source provenance is intentionally larger than these compact onchain proofs because it authenticates the epoch's complete bounded source-metadata commit. The same $N=1{,}024$, $R=128$ signed workload gives:

```{=html}
<div class="clearing-benchmark-table">
<table>
  <thead>
    <tr>
      <th rowspan="2" style="text-align:left; vertical-align:bottom;">Cold source artifact</th>
      <th colspan="4" style="text-align:center;">History and new withdrawal outputs</th>
    </tr>
    <tr>
      <th style="text-align:right;"><em>H</em> = 0<br><em>W</em> = 0</th>
      <th style="text-align:right;"><em>H</em> = 1,024<br><em>W</em> = 0</th>
      <th style="text-align:right;"><em>H</em> = 0<br><em>W</em> = 1,024</th>
      <th style="text-align:right;"><em>H</em> = 1,024<br><em>W</em> = 1,024</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Source metadata</td><td style="text-align:right;">7,731 B</td><td style="text-align:right;">7,731 B</td><td style="text-align:right;">206,260 B</td><td style="text-align:right;">206,260 B</td></tr>
    <tr><td>Complete SourceProof</td><td style="text-align:right;">7,809 B<br><small>4.03 ms</small></td><td style="text-align:right;">7,841 B<br><small>4.00 ms</small></td><td style="text-align:right;">206,339 B<br><small>35.8 ms</small></td><td style="text-align:right;">206,339 B<br><small>35.7 ms</small></td></tr>
    <tr><td>Current payout claim</td><td style="text-align:right;">not applicable</td><td style="text-align:right;">not applicable</td><td style="text-align:right;">389 B</td><td style="text-align:right;">389 B</td></tr>
    <tr><td>Verify source + account/claim</td><td style="text-align:right;">4.03 ms</td><td style="text-align:right;">4.01 ms</td><td style="text-align:right;">35.7 ms</td><td style="text-align:right;">35.7 ms</td></tr>
  </tbody>
</table>
</div>
```

The SourceProof includes the full metadata and its native Commit opening; finalized log heads and transaction envelopes are separate. Here the full exit creates 1,024 activity rows and uses the signed workload's 16-byte destination. Figure 9's 394-byte comparison uses a 30-byte raw-output fixture. Both timing rows are Criterion medians from 20 samples. The time below each SourceProof authenticates its complete metadata from a constructed proof. The final row independently times that authentication plus a compact account lookup and, when $W=1{,}024$, the current payout claim. The overlapping estimates are not components to subtract.

QMDB proofs authenticate balances for forced withdrawal intake and recovery. A recovery claim opens the account's balance at the frozen finalized root. Current Ordered with MMB remains the balance design; the following measurements are from the initial implementation on an AWS c8a.4xlarge.

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
Figure 10: Historical Current Ordered proof measurements after the initial insertion batch, using a middle account and a missing key. SHA-256/MMB, 32-byte bitmap chunks, and 8-byte balances. Lookup rows omit the known account key, while recovery includes it. All omit the trusted root and chain framing. Sizes vary with history and proof position.
:::

Adjust the workload and committee size below to estimate the operator's traffic.

```{=html}
<div id="clearing-fig-calculator" class="clearing-calculator" role="region" aria-label="Interactive calculator for keyed validator dealings. Sliders set live accounts, average recipients per account, and validators. Results show one modeled update per validator, its composition, total operator egress, and a dotted reference for the encoded account records.">
  <noscript>Each validator retains the complete account state and receives one compact update per close. Total operator egress is the update size multiplied by the validator count. Enable JavaScript to change the workload.</noscript>
</div>
<script type="module" src="clearing.calculator.js"></script>
```

::: {.image-caption}
Figure 11: Modeled operator Dealing per validator, with total direct operator egress in parentheses. Dotted: all live account records (40 bytes each), before database overhead and retained evidence. Both axes are logarithmic. Encoder fixtures match the model across sparse, compact-length-boundary, and dense workloads. The separate certified descriptor, transport, and other messages are excluded.

Each sender signs one batch of unit payments. Recipients per account is averaged over all live accounts. Below an average of one, the first senders pay the last recipients in key order. Otherwise, every account pays its next neighbors cyclically. All accounts stay live, with no deposits or withdrawals. Estimates beyond the prototype's per-close limits extrapolate the same encoding.
:::

## A Bajillion Payments, One Settlement

Send a million payments without paying for a million onchain transactions.

That makes small exchanges practical, like an agent buying a single API response. Recipients can deliver the goods now, knowing the operator has made a binding commitment to the payment. If the operator later omits or contradicts that payment, the signed receipt gives them the evidence to challenge the close.

The settlement chain keeps the current balance commitment, finalized issuance, and outstanding claims--not a lifetime record of every payment or claim.
