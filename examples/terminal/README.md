# commonware-terminal

Run `commonware-clearing` through three independently owned roles:

- `terminal-agent` runs the wallet agents: p2p-less light clients speaking codec RPC to the
  validators' query servers. Every read they rely on is certified, and every mutation is
  submit-then-prove. Each agent owns one wallet key, verifies returned entry receipts, holds
  as a receiver the receipts crediting it, reconciles them against certified admitted closes,
  and provides the Ratatui UI.
- `terminal-operator` owns one SQLite ledger, accepts signed sends, issues acknowledgments
  and entry receipts, and constructs closes. It runs the validator stack without a consensus engine, as a registered
  p2p secondary of the committee: settlement reads come from its own verified finalized state,
  transaction submission goes out on the settlement transaction channel, and its close pipeline
  disseminates dealings, collects votes, and assembles the admission certificate over the
  settlement DA channel. Several operators run concurrently, each owning one DEPLOYMENT (its
  clearing identity's own accounts, epochs, custody, and fault domain) on the shared chain.
- `terminal-chain` runs the settlement chain: a static committee of validators executing one
  clearing `SettlementChain` per configured deployment as a `glue::stateful` application, with
  block height as the only timer. Execution routes every transaction to exactly one
  deployment's machine and no transaction reads or writes another deployment's records, so one
  operator's fault never touches another's epochs. Each validator seals the dealings it
  receives from any configured operator over the DA channel durably before voting back to that
  operator, and serves deployment-scoped certified reads over its applied state.

Agents exchange one bounded request and response per connection using canonical
`commonware-codec` messages over Commonware's runtime networking traits, with no p2p stack of
their own. The operator and the committee share one authenticated discovery network, where
consensus, block broadcast and backfill, transaction gossip, and settlement DA each ride a
numbered channel. There is no HTTP, protobuf, or generated RPC layer.

## Trust

The chain has one trusted constant: the genesis threshold identity dealt to the committee at
setup. Everything a wallet or an operator relies on is proven against it. The genesis also
fixes the deployment list (one operator clearing key with its configured accounts and initial
balances per deployment; each deployment's digest derives from its operator key) and one
chain-wide epoch timing policy applied to every deployment.

- Every settlement read is a certified read: a finalization certificate over a block, the block
  bytes, and a presence or exclusion proof against that block's canonical state root, verified
  client-side. Absence is a verdict, not a shrug.
- Every block carries a timestamp covered by its digest, so recency is certified too and one
  verified read from a single validator suffices. Window-critical reads (the status height that
  deadline decisions anchor on, and the anchor and admitted records reconciliation adjudicates
  against) reject a read whose certified timestamp lags the client's own clock beyond a shared
  recency threshold, sized from the block cadence plus the bounded timestamp drift validators
  vote under. The client's clock is the recency reference, deadlines remain block heights, and
  a stalled chain is detected as staleness rather than misread as a live tip.
- Mutations are submit-then-prove-by-effect: submission acceptance and the typed dry-run
  advice it carries are both advisory, and a transaction completes only on a certified read
  of its effect record (a deposit's custody record, the registration record, the admitted
  record, a claim's release record, the fault record). Domain-keyed effects are provable;
  rejections are effect-free and diagnosed via the advisory dry-run, so an effect-free
  rejection is indistinguishable from not-yet-included and clients retry the exact bytes
  until the effect appears or a bounded budget ends.
- The operator's follower node verifies every finalization itself before applying it, so its
  local reads carry the same guarantee and its own tip is an honest tip.

Block height is the settlement clock. Every deadline is an absolute block height opened by
the chain at the inclusion of the operator submission that triggers it: a registration's
inclusion assigns its admission and challenge deadlines, an admission opens the challenge
window and the successor epoch's registration eligibility, and deposits and withdrawals carry
their signed deadlines in height units. The registration deadline geometry is fixed at
deployment creation in `genesis.json` (admission offset and challenge duration), execution
assigns the instance heights at inclusion, and the operator chooses nothing about timing,
only when to submit, so it can never squeeze the enforcement window per epoch. A deadline
bounds lateness only, so satisfying an obligation early is always allowed, while finalization
still waits for real heights past the inclusive challenge deadline. An idle deployment has no
live obligations and can never fault by idling. Block timestamps never feed a deadline: they
serve query recency and display alone.

The example is educational rather than a production operator or asset adapter. Wallet keys,
the operator's clearing key, and the validators' clearing committee keys are deterministically
derived demo identities, and setup generates fresh network keys. The SQLite operator and its
close queue survive restarts. Each wallet's cumulative debit, pending signed send,
authenticated receipts, cached payment context, and the exact state-root openings observed on
head reads and before withdrawal authorization are SQLite-backed. Openings are retained by
full root so a later hard fault can freeze an older finalized root. A staged deposit survives
an agent restart and is retried with the same event id, which the chain's custody record
consumes exactly once, so no second custody can move. Withdrawal authorization retries remain
process-local, so that workflow alone does not promise exactly-once behavior across an agent
restart. Replay protection is domain state rather than a history of transaction hashes: every
transaction carries a natural idempotence key (a deposit id, an account queue slot, an epoch,
a claim position), so no account nonces exist, a duplicate inclusion lands on its variant's
guard as a no-op or typed conflict, and response-loss retries complete on the same effect
record. The returned releases model an asset adapter decision, not an external transfer. A
production embedding must durably and atomically commit each transfer with its
replay-protection mutation.

## User flows

```text
PAYMENT

 wallet                    operator                         settlement
   | sign from local SQL alone: the cached (epoch, anchor), the wallet's own
   | durable cumulative debit as the endpoint, affordability prechecked against
   | the cached Merkle-verified floor (a lower bound on spendable balance)
   | persist (root, SendAuthorization S)                          |
   |-------------------------->|                                 |
   |                           | first payment for epoch:        |
   |                           | registration tx, certified ---->|
   |                           |<-- registration record (effect) |
   |                           | countersign the endpoint, open  |
   |                           | one entry per credited recipient|
   |<--------------------------|                                 |
   | verify S and every receipt                                   |
   |-- certified anchor read for the epoch ---------------------->|
   |<----------- proven anchor equals the send's context, or reject|
   | atomically persist (root, receipts); advance wallet-local debit|
   |
   +-- no cached context (fresh wallet, or invalidated by a withdrawal) => one head
       read: context, live state, and a StateOpening verified against settlement's
       exact finalized root, then cached. this fallback also covers a local floor
       that cannot prove affordability, and its live-balance precheck refuses a truly
       unaffordable send before anything is staged
   +-- stale context => typed corrective rejection carrying the operator's live
       (epoch, anchor) and the payer's endpoint as the operator sees it. the wallet
       adopts the corrected context, re-signs the exact intent at its own endpoint,
       and retries once. both sends authorize the same cumulative debit interval, so
       at most one ever debits: a Byzantine "rejection" that keeps the old bytes
       cannot double-pay
   +-- corrective endpoint differs from the wallet's own => never adopted. it is the
       lost-acceptance signal, resolved from settlement's finalized endpoint before
       any retry
   +-- invalid or missing receipt => reject without advancing wallet-local debit
   +-- missing response => acceptance unknown; retry exact persisted S
   +-- admitted close omits an accepted send => the payment did not happen and the payer's
       funds stay, resolved by abandoning against the finalized endpoint. A payer can never be
       over-debited: public validity certifies every committed debit against a payer-signed
       send, so enforcing an omitted credit belongs to the harmed receiver, not the payer

 A send merges one or more strictly recipient-sorted delta entries into the payer's
 cumulative per-recipient vector and signs its root, sequence number, and cumulative debit
 endpoint under one signature. The operator accepts or rejects the batch as a whole and
 returns one dual-signed acknowledgment plus one entry opening per credited recipient, all
 committed in one SQLite transaction. A single payment is a batch of one.

DEPOSIT OR WITHDRAWAL AUTHORIZATION

 deposit: wallet -> settlement custody -> operator observes the finalized record
          -> next exact close boundary

          the wallet's flow ends at the certified custody record. the operator is a
          chain follower and stages every finalized deposit itself, so no wallet report
          exists and a deposit staged by any third party rides the next close. a lost
          chain response retries the exact staged event, and timeout recovery refunds
          the settlement account if no close ever includes the credit

 withdrawal: read settlement's configured, non-faulted finalized root
             -> select the exact retained opening, or fetch, verify, and persist that root
             -> sign against that root -> hand the request to the operator, which carries
                it into its next registered close. settlement validates each carried
                request at registration against that same finalized root: an
                operator-supplied account opening proves it certifiable, and its
                deadline must outlive the close's challenge window

             operator loss returns a pending outcome, and retry uses the exact signed
             request. a censored signer instead queues the exact request at settlement,
             which the operator must then include verbatim. queue expiry enables
             hard-fault recovery

 Amount: wallet signs (state root, destination, exact amount, deadline)
 Close:  wallet signs (state root, destination, deadline); the amountless request sweeps
         the authenticated epoch-tail balance and removes the account

CLEAN CLOSE

operator prepare -> deal -> validators seal every assigned proof slice
          -> certificate -> settlement admit
          -> PENDING through the inclusive challenge deadline
          -> the deadline passes when the chain finalizes a block past it
          -> FINALIZED
                |
                +-- withdrawal output + one opening -> destination, amount
                +-- external payout + one opening   -> receiver, amount
                +-- successor state becomes the next finalized head

 Epochs register and finalize in exact order: e, e+1, e+2. A retry may repeat e,
 but registration, admission, and FIFO finalization cannot jump over it.

OPERATOR FAULT

 missed registered admission | expired deposit/withdrawal | proven challenge
                                  |
                                  v
                         PERMANENT HARD FAULT
                                  |
             finalize only the earlier valid FIFO prefix in order
                                  |
                                  v
                    freeze last finalized state root
                                  |
        challenged/invalidated suffix never finalizes; recover it here
                                  |
       unadmitted/invalidated payments do not debit frozen state
                       /                         \
  StateOpening(account)                          pending deposit account
      |                                                     |
      |                                                     +-- direct refund
      +-- pending Amount -> exact amount to signed destination;
      |                     residual to authenticated account
      +-- pending Close  -> full frozen balance to destination
      +-- no withdrawal  -> full frozen balance to account

 Invalid external sends create no payout reserve; their payer recovers instead.
 Finalized withdrawal and external-payout reserves remain independently claimable.
 Exact retries return the original result; conflicting replays fail closed.
```

Recovery does not recreate unavailable evidence. On every verified head read, balance poll,
and fresh withdrawal, the agent retains its payer opening against settlement's exact finalized
root, and each optimistically staged payment pins one retained opening as its recovery
evidence. Recovery uses an opening only when its full root is later frozen. A carried withdrawal is invisible to
settlement until its close registers, so it gains the deadline-fault guarantee only once that close
is admitted. If the operator disappears or censors first, the signer queues the exact signed
request at settlement instead. The next registered close must then carry the queued request
verbatim, and only an operator that stalls entirely lets the obligation expire into hard-fault
recovery. A frozen root the agent never observed is opened by its slice holders instead: the
validators retaining a sealed dealing at that root serve the leaf, and recovery verifies it against
the frozen state root before claiming. An account reactivated by a current-epoch deposit cannot pay
until it appears in a later epoch-predecessor state, because the current frozen root has no live
payer leaf to retain. Challenges still require the exact retained acknowledgment evidence.

Receiver enforcement flow. A wallet that provides a service is the party an omitted credit harms,
so it enforces its own preconfirmations. It fetches the entry receipts crediting it from the
operator by a durable cursor, verifies each fully (both signatures over the acknowledged endpoint
and the entry's membership opening under the acknowledged vector root), and anchors the receipt's
`(epoch, anchor)` to the context settlement registered for that epoch. A receipt over an
operator-chosen anchor with no settlement obligation is never reliance-grade. Only then does it
durably hold the receipt and gate service on it, so a balance read from the operator's head is an
observation, not reliance. In the background it reconciles held credits against the admitted
close: settlement serves the batch identity and roots it admitted for the epoch, and
committed-side evidence is trusted only when it verifies under those roots. That evidence comes
from the payer's slice holders: the validators retaining the admitted close's sealed dealing
through its challenge window serve the payer's committed terminal entry, or its authenticated
absence, from the slice alone, so the accused operator is never the source of the lookup that
convicts it and can neither withhold nor fabricate coverage while the window is open. Once the
window closes and the dealing is released, the operator's reconstruction is the fallback, and
only there does its retention window apply: a finalized close stays reconstructable until
`RETAINED_EPOCHS` (four) further epochs finalize, so an epoch that finalizes with its evidence
withheld by both sources is surfaced as an alarm and kept retrying, and a refusal for an older
epoch that the validators also cannot serve is recorded durably as unavailable rather than
alarmed as withholding. When a held per-edge entry exceeds the anchored committed terminal entry
inside the admission-to-finalization window, the wallet convicts the close with one
`HigherAckEntry` challenge and stops, because one proven challenge invalidates the whole close. The operator is the receipt-delivery channel, and withholding a
receipt only degrades to the acceptance gate: an unheld credit is never relied upon and so harms
no one. Wallets file `HigherAckEntry` only, and the authenticated-absence form covers even a
sender the close omits entirely. `HigherAckDebit` exists for a payer whose acknowledged endpoint
the committed terminal understates, and the acknowledgment fork requires operator equivocation
the honest demo never produces. Settlement adjudicates all three.

Registration confirmation is a certified anchor read. The anchor commits the entire epoch
context, the boundary, the predecessor liability, and the chain-assigned absolute deadlines,
and anchor records persist for the life of the deployment, so a certified anchor equal to the
send's context proves settlement registered exactly that payment context. A receipt whose
context the chain never registered has no close to adjudicate against and is never recorded.

Each wallet flow draws on four sources: the operator's RPC (the fast path, never trusted on its
own), the validators' query servers (certified reads and submit-then-prove effects), the slice
holders' evidence (openings and claims from the validators retaining a close's sealed dealing
through its challenge window, every one verified against a certified root before use), and the
wallet's own SQLite state. The operator may answer first, and every enforcement flow completes
without it.

| Flow | Operator RPC (fast path) | Validator query servers (certified) | Validator evidence (slice holders) | Local state |
| --- | --- | --- | --- | --- |
| Pay | `accept_send`, `payment_head` for a fresh stage, and an optional `accepted_batch` receipts fetch once a lost acceptance resolves against the finalized endpoint | `anchor` for the send's epoch, `status` to stage or resolve, and `registration` for the signing context when the operator serves no usable head | the wallet's leaf at the certified head when the operator's head is unreachable or fails verification: the affordability floor for staging, the endpoint for resolution | cached (epoch, anchor), cumulative debit, staged send, held receipts |
| Balance and head opening | `payment_head` | `status`, whose finalized state root the served opening is verified against | the wallet's leaf at the certified head when the operator's head is unreachable or fails verification | the opening retained by root, the signing context re-cached from an operator head |
| Withdraw | `withdrawal_opening` only when no opening for the head root is retained, then `apply_withdrawal` | `recent_status` | the head opening when the operator serves none | retained head opening, the pending signed request |
| Escalate | none | `deliver` QueueWithdrawal, `withdrawal` record | none | the pending signed request and its locally retained opening |
| Claims | `withdrawal_evidence` or `external_payout_evidence` only when no admitted close is inside its window, then a courtesy `acknowledge_*` the claim never waits on | `status`, `registration`, and `admitted` for the open windows, `claim_roots`, `deliver` claim, `withdrawal_release` or `payout_release` record | the withdrawal output or external payout claim from the admitted close's holders inside its window, verified against the admitted roots and cached | cached evidence and the claim intent slot |
| Receipt intake | `incoming_payments` | `anchor` per receipt epoch | none | held receipts and the durable cursor |
| Reconcile | `committed_entry` only when every holder declines | `status`, `admitted`, `deliver` Challenge, `fault` record | the payer's committed terminal entry from the payer's slice holders, verified against the admitted change root | held receipts, the durable per-epoch outcome |
| Deposit, refund, hard-fault claim | none | `deliver` plus the `deposit`, `refund`, `fault`, and `hard_fault` records | the wallet's leaf at the frozen root when none is retained | the staged deposit, and for the hard-fault claim an opening retained for the frozen root |
| Registration and settlement status | none (the operator status panel is the operator's own uncertified report) | `registration`, `status` | none | none |

## Close certification and data availability

Distributed certification runs over the settlement DA channel. An operator sends each
validator exactly its assigned proof slices, one per assigned span (a contiguous range of
slices) and stripped of their unchanged state: every slice travels as a `DealtSlice`, and the
validator hydrates it against the key interval it retains for that span at the registered
close's predecessor root. The operator never materializes a slice per span: it encodes every
slice's chunk (its rows against the retained predecessor leaves, its senders' entries, and its
transpose range) once, computes one witness per distinct span, and sends each dealing as the
witness followed by the covered chunks, so dealing costs one pass over the close however many
validators share a slice. Intervals are retained one record per slice, so a future re-grouping
of slices a validator already holds into different spans needs no re-sync. A slice it never
held or already pruned (a validator that missed a close, or one starting from an empty
directory) is fetched when the next dealing arrives: the validator asks the slice's other
holders through their query servers (`EvidenceLookup::Interval`), one at a time from a
deterministic offset with a bounded wait per holder, rotating past routing advice, garbage,
and silence, verifies the served range against the registered close's predecessor root (which
consensus certified, so nothing the holder sends is trusted) and the slice bounds, retains it,
and only then hydrates and seals, while still answering evidence requests. A dealing whose
interval no holder serves is skipped with a warning naming the slice and every decline. This is
the mechanism a rotated-in validator needs, but a true validator-set change also needs the
settlement chain to accept a committee schedule (it pins one committee commitment today),
which is a separate protocol change. Genesis seeds each deployment's intervals from its
configured accounts, every sealed close advances them under the successor root, and the
advanced intervals are made durable together with the sealed dealing before the vote leaves
the validator, so dealing bytes scale with the movers rather than the account set. The
validator routes each dealing by the sending operator's network identity to the deployment
that operator runs and seals it with clearing `seal` against THAT deployment's
chain-registered close from its
own applied state, never against operator-supplied context material. The sealed dealing
lands in that deployment's own prunable archive (the partition folds the deployment digest,
so two deployments' closes never contend for one deadline slot), keyed by the close's batch
id (deployment-unique by construction: the header commits the payment anchor, which folds
the deployment digest) and sectioned by its challenge deadline height, and it is synced
there before the vote returns to the sending operator: the vote attests to availability the
validator must be able to honor, so a validator killed between seal and vote still holds its
dealing on restart. The record carries the registered close context it sealed against, so a
restarted validator keeps serving challenge and claim evidence for a close the chain has
already admitted (and so no longer names as registered) through its challenge window.
Sections are pruned only when they lie strictly below the certified
finalized height, where every challenge window they cover is closed, never on wall clock. A
record is never overwritten: a replayed dealing re-votes from the stored bytes, and a
conflicting dealing for an occupied slot is refused, in the interval store as in the dealing
archive (a differing close for an epoch whose advanced intervals are already retained is
refused before sealing, closing the crash window between the two syncs). Dealings and votes are recoverable
off-chain traffic, resent until quorum, and only the finalized admission is durable protocol
state. The operator verifies every returned vote, assembles the exact-quorum certificate,
submits the admission transaction, and completes only once its own certified state finalized
the exact batch.

## Keys

| Key | Held by | Purpose |
| --- | --- | --- |
| Consensus threshold share (BLS) | each validator's `node.json` | signs simplex votes and certificates under the genesis threshold identity every certified read verifies against |
| Clearing committee key (BLS) | each validator's `node.json` | seals dealings and signs close-admission votes |
| Operator network key (ed25519) | each `operator-<index>/node.json` | authenticates that operator as a registered p2p secondary |
| Operator clearing key (curve25519) | each `operator-<index>/node.json` (a fixed demo protocol constant) | signs the curve25519 half of that operator's receipts and its epoch registrations, and its digest names the deployment the operator runs |
| Operator acknowledgment key (BLS MinSig) | each `operator-<index>/node.json` (a fixed demo protocol constant whose public key `genesis.json` fixes per deployment) | signs the aggregable half of every acknowledgment, combined into one countersignature per proof slice in the close and verified by every sealer against the genesis-fixed key |
| Wallet key (curve25519) | one per agent | signs sends and withdrawal authorizations, and names the account custody and claims resolve to |

## Run

Generate the fixed committee and the operators' node directories, then start each role in its
own terminal. Setup writes `./data/validator-0` through `./data/validator-3` (the committee
size must equal the fixed clearing committee) plus one directory per operator,
`./data/operator-0` and `./data/operator-1` by default (`--operators` chooses the count, one
deployment each):

```bash
cargo run --release -p commonware-terminal --bin terminal-chain -- setup
mprocs "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-0" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-1" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-2" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-3"
```

Start both operators, each on its own RPC address and SQLite database:

```bash
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-0 --bind 127.0.0.1:7001 \
  --database terminal-operator-0.sqlite
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-1 --bind 127.0.0.1:7002 \
  --database terminal-operator-1.sqlite
```

Each agent binds one operator and its deployment at startup: `--operator` names the operator's
RPC address and `--deployment` resolves that operator's deployment from the genesis list
(operator N runs deployment N):

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --identity 0 \
  --operator 127.0.0.1:7001 --deployment 0 \
  --genesis data/validator-0/genesis.json \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
cargo run --release -p commonware-terminal --bin terminal-agent -- --identity 0 \
  --operator 127.0.0.1:7002 --deployment 1 \
  --genesis data/validator-0/genesis.json \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
```

Each operator's node directory carries its network key, its clearing key, and the shared
network and genesis files, and its follower state lives under
`data/operator-<index>/runtime`. The genesis file carries the committee's threshold identity,
which every certified read is verified against, plus the chain creation timestamp, the
deployment list, and the chain-wide epoch timing policy applied to every deployment. The query
addresses name the validators' certified query servers: one suffices, since recency rides the
certified block timestamp, and extra addresses only give failover rotation past stale or
unreachable validators. Every role
is durable, so starting the demo over requires deleting the chain's `./data` directory
(validator and operator storage), every `terminal-operator-*.sqlite`, and every
`terminal-agent-*.sqlite` (or passing fresh paths) before starting again.

Agent identities are `0=Alice`, `1=Bob`, `2=Carol`, `3=Dave`, and `4=Eve (external)`. The first
four are registered accounts in every deployment (setup writes the same demo account set into
each deployment's genesis, but every deployment's balances, epochs, custody, and fault domain
are its own). Eve demonstrates an unregistered receiver claiming an external payout. Run more
agent processes with different identities and deployments to exercise independently owned
wallets. Each identity defaults to `terminal-agent-<deployment>-<identity>.sqlite`; pass
`--database` to choose an explicit wallet database path.

The UI supports payments, deposits, direct pending-deposit refunds with `r`, exact withdrawals,
amountless account Close authorizations, withdrawal claims, payer-state hard-fault recovery with
`h`, and epoch closure. A per-wallet receiver-ledger line shows the verified incoming credit and
the last reconciled epoch, updated on the heartbeat, and enforcement events, convictions,
reconciliations, and alarms, are logged into the activity feed as they happen. When a signed
withdrawal cannot be carried because the operator is unreachable, `x` escalates the exact request
into settlement's queue. The next registered close must carry the queued request verbatim, and
the deadline expiring into hard-fault recovery is the backstop if the operator stalls entirely.
`p` pays the selected receiver the selected amount. `a` stages the
selected entry into a draft batch and `b` pays every staged entry with one batched send. The
batch is rejected or accepted as a whole, so a failed `b` retries the identical batch. A
pending-deposit refund needs only the wallet account and settlement; it does not contact the
operator. A deposit is one step, placed at settlement, the only ramp in: the chain takes custody
and records a refund path, and the wallet is done. The operator observes the chain like a real
ramp: its follower surfaces every finalized block's deposit transactions, confirms each against
the applied custody record, and stages the credit durably before acknowledging the block, so a
crash between finalization and staging re-delivers the block and the deposit-id dedupe makes the
replay a no-op. Nothing depends on the depositor telling the operator anything, which also
removes the unreported-mint griefing lever: a third party's deposit to a configured account is
staged automatically and rides the next close's boundary instead of wedging the registration.
Demo deposits are effectively mints: the chain models the custody ledger but no funding asset,
so a `Deposit` transaction conjures custody for one of the four configured identities (any other
account is chain-rejected), no faucet is needed, and crediting an account can only help it, so
permissionless submission is harmless. In a real deployment this arm is where the asset ramp
plugs in: a deposit becomes the execution environment's observation of an actual transfer into
the deployment's custody rather than a self-declared credit. A withdrawal is authorized against
the settlement state root, carried by the operator, and included in an epoch close.
Deposits and fresh withdrawal authorizations are accepted only while no payment context is
registered: the epoch's first payment registers the context, and later requests are rejected
until the close's admission opens the successor epoch's eligibility, while its challenge
window still runs. Every validator derives the exact
destination and amount at the request's position under the withdrawal-output root. A finalized
output is independently claimed with that destination, amount, and one Merkle opening. A Close
stays pending and leaves the account usable for the rest of the epoch. Its output is the
predecessor balance plus deposits and incoming credits minus outgoing debits. That tail may be
zero, in which case the Close completes without creating payout work.

Payments to an absent identity become claimable external payouts rather than receiver-sized
settlement output. This includes Eve and a configured account removed by Close until a later
deposit reactivates it. Each receiver claims independently with `e`.

Before returning an epoch's first operator-signed receipt, the operator submits an
operator-signed registration transaction containing exactly the boundary material it
legitimately chooses: the epoch, predecessor liability, deposit boundary, and withdrawal
boundary. Execution assigns the absolute block-height deadlines from the registration's
inclusion height under the genesis timing policy and derives the payment anchor itself, so
the operator learns both by reading its own certified registration record back before any
receipt is issued. Adopting the assigned deadlines moves the payment anchor, so the send that
triggered the registration earns one corrective rejection and is re-signed, which the
wallet's bounded corrective retry already handles. Registration is one-shot rather than a
heartbeat: an idle open slot has no deadline, but an activated context must admit its matching
certified close by its inclusive admission-deadline height or the deployment permanently
hard-faults. A registered context has a three-hundred-block admission runway from its
inclusion height (the generated genesis default, sized so an operator restart inside the
window can still resume the cut) and an admitted close remains pending for one inclusive
challenge block; block production
itself observes every deadline, so no heartbeat is needed to make an expired obligation
permanent.
Deposit and withdrawal deadlines are independent: if one expires while a clean admitted close
remains challengeable, the fault is recorded, the clean FIFO front still finalizes after its
window, and terminal recovery preserves both its claim reserves and its successor state.

SQLite atomically derives every pending Close tail, projects those historical rows inactive at zero
balance while retaining their counters and payment evidence, adjusts live liability, records the
close job, and opens the successor under a root-independent payment context. The cut is proportional
to Close authorizations rather than all accounts, and unchanged account versions remain
copy-on-write. A background worker rebuilds the predecessor BMTs, deals each validator its proof
slices over the DA channel, collects the committee's votes into the exact-quorum certificate, and
submits the certified close to settlement. The chain opens the successor epoch's registration
window at the predecessor's admission, while that close's challenge window still runs, so a
successor's first payment retries only until the predecessor's close is admitted; the Bajillion
settlement primitive itself supports a bounded admitted pipeline. Close retries remain
bound to their original epoch, so a lost response cannot cut the active successor. Finalization
prunes only the balance versions that epochs below the retention window still needed, so every
finalized close inside that window reconstructs exactly for receiver reconciliation.

For a terminal-free walkthrough, start the validators and operators as above, then run (the
scripted walkthrough stays on operator-0 and deployment 0; pass `--operator 127.0.0.1:7002
--deployment 1` to run the same arc on operator-1's deployment instead):

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --scripted \
  --operator 127.0.0.1:7001 \
  --genesis data/validator-0/genesis.json \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
```

The walkthrough deposits and waits for the operator's observed credit to show in the verified
balance, hands the operator a withdrawal to carry, pays an internal receiver,
pays a two-receiver batch under one signature, and pays an external receiver. A receiver then
durably intakes and settlement-anchors its incoming pairs and gates service on that held evidence
before the epoch is cut, the walkthrough starts an asynchronous close certified by the live
committee, claims the finalized withdrawal and external payout, and reconciles the receiver's
finalized credit as evidence-backed. It then opens the registered successor with one payment,
closes that epoch inside its admission runway, and proves with a certified read that no live
obligation outlasts the run, so the deployment idles safely afterward. It ends with a
self-contained fraud arc on a throwaway in-process single-validator chain with locally
simulated certification: the assembled omitting close is registered and admitted as real
transactions, the omitted receiver's held receipt convicts it with a real `HigherAckEntry`
challenge transaction, and the proven verdict, the fault record, and the hard-faulted status are
read back certified through the light client. The operator binary stays honest, and the fraud is
assembled only in the scripted walkthrough.

## Limits

The demo cuts corners a production deployment must not:

- Setup is a trusted dealer writing plaintext threshold shares and clearing keys into
  `node.json`, which is demo-grade key handling. Continuous resharing and a real DKG bootstrap
  are drop-ins from the reshare example: replace the constant scheme provider and the direct
  simplex engine with its orchestrator, probe, and reshare actors.
- Peer QMDB state sync is a documented no-op pending a glue extension: a late joiner replays
  finalized blocks through marshal backfill, and the reshare example's qmdb resolver actor is
  the drop-in server.
- Marshal's finalization and block archives are never pruned.
