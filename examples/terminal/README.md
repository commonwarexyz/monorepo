# commonware-terminal

Run `commonware-clearing` through three independently owned roles:

- `terminal-agent` runs the wallet agents: p2p-less light clients speaking codec RPC to the
  validators' query servers. Every read they rely on is certified, and every mutation is
  submit-then-prove. Each agent owns one wallet key, verifies returned entry receipts, holds
  as a receiver the receipts crediting it, reconciles them against certified admitted closes,
  and provides the Ratatui UI.
- `terminal-operator` owns a SQLite ledger and a QMDB balance replica, accepts signed sends, issues acknowledgments
  and entry receipts, and constructs closes. It runs the validator stack without a consensus engine, as a registered
  p2p secondary of the committee: settlement reads come from its own verified finalized state,
  transaction submission goes out on the settlement transaction channel, and its close pipeline
  disseminates dealings, collects votes, and assembles the admission certificate over the
  settlement DA channel. Several operators run concurrently, each owning one DEPLOYMENT (its
  clearing identity's own accounts, epochs, custody, and fault domain) on the shared chain.
- `terminal-chain` runs the settlement chain: a fixed committee maintains a native asset,
  an operator registry, and one clearing `SettlementChain` per deployment. Operators can
  register while the network runs. Deposits debit native accounts; finalized claims credit
  them or atomically fund another deployment. Each deployment has independent custody,
  epochs, deadlines, and faults. Validators retain each validated dealing before voting and
  serve certified state and authenticated evidence.

Agents exchange one bounded request and response per connection using canonical
`commonware-codec` messages over Commonware's runtime networking traits, with no p2p stack of
their own. The operator and the committee share one authenticated discovery network, where
consensus, block broadcast and backfill, transaction gossip, and settlement DA each ride a
numbered channel. There is no HTTP, protobuf, or generated RPC layer.

## Trust

The chain has one trusted constant: the genesis threshold identity dealt to the committee at
setup. Everything a wallet or an operator relies on is proven against it. The genesis also
fixes the native supply, initial deployments, fee and resource policy, and chain-wide timing.
Initial deployment identities bind that configuration and the fresh consensus identity.
Later registrations bind their chain, keys, account roster, and resource reservation.
Their empty QMDB genesis comes from trusted network policy, and they start with zero custody.
Each deployment's registered configuration is immutable.

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
- Mutations complete through certified effects. Ingress qualification and queue acceptance
  are advisory; execution checks the transaction again. A wallet completes a transfer,
  deposit, registration, or claim only after proving its exact effect record. An absent
  effect leaves the intent unresolved, so retries use the same signed bytes.
- The operator's follower node verifies every finalization itself before applying it, so its
  local reads carry the same guarantee and its own tip is an honest tip.

Block height is the settlement clock. Registration inclusion assigns admission and challenge
deadlines; deposit inclusion assigns its obligation deadline. Withdrawals carry a signed deadline
in height units. Admission enables challenges and the successor epoch's registration.
The registration deadline geometry is fixed at
the chain's `genesis.json` (admission offset and challenge duration), execution
assigns the instance heights at inclusion, and the operator chooses nothing about timing,
only when to submit, so it can never squeeze the enforcement window per epoch. A deadline
bounds lateness only, so satisfying an obligation early is always allowed, while finalization
still waits for real heights past the inclusive challenge deadline. An idle deployment has no
live obligations and can never fault by idling. Block timestamps never feed a deadline: they
serve query recency and display alone.

The example uses an internal native asset. Wallet keys, initial operator keys, and clearing
committee keys are deterministic demo identities. Network keys and keys for newly registered
operators are fresh. The SQLite operator and its
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
record. Claims credit native balances in the same chain transition that consumes their replay
identity. An external asset bridge would need its own transfer and finality contract.

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

operator prepare -> deal -> validators validate the complete dealing
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
recovery. A frozen root the agent never observed is opened by the committee instead: the
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
from the committee: the validators retaining the admitted close's sealed dealing
through its challenge window serve the payer's committed terminal entry, or its authenticated
absence, from retained close evidence, so the accused operator is never the source of the lookup that
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
own), the validators' query servers (certified reads and submit-then-prove effects), the committee's evidence (openings and claims from the validators retaining a close's sealed dealing
through its challenge window, every one verified against a certified root before use), and the
wallet's own SQLite state. The operator may answer first, and every enforcement flow completes
without it.

| Flow | Operator RPC (fast path) | Validator query servers (certified) | Validator evidence (committee) | Local state |
| --- | --- | --- | --- | --- |
| Pay | `accept_send`, `payment_head` for a fresh stage, and an optional `accepted_batch` receipts fetch once a lost acceptance resolves against the finalized endpoint | `anchor` for the send's epoch, `status` to stage or resolve, and `registration` for the signing context when the operator serves no usable head | the wallet's leaf at the certified head when the operator's head is unreachable or fails verification: the affordability floor for staging, the endpoint for resolution | cached (epoch, anchor), cumulative debit, staged send, held receipts |
| Balance and head opening | `payment_head` | `status`, whose finalized state root the served opening is verified against | the wallet's leaf at the certified head when the operator's head is unreachable or fails verification | the opening retained by root, the signing context re-cached from an operator head |
| Withdraw | `withdrawal_opening` only when no opening for the head root is retained, then `apply_withdrawal` | `recent_status` | the head opening when the operator serves none | retained head opening, the pending signed request |
| Escalate | none | `deliver` QueueWithdrawal, `withdrawal` record | none | the pending signed request and its locally retained opening |
| Claims | `withdrawal_evidence` or `external_payout_evidence` only when no admitted close is inside its window, then a courtesy `acknowledge_*` the claim never waits on | `status`, `registration`, and `admitted` for the open windows, `claim_roots`, `deliver` claim, `withdrawal_release` or `payout_release` record | the withdrawal output or external payout claim from the admitted close's holders inside its window, verified against the admitted roots and cached | cached evidence and the claim intent slot |
| Receipt intake | `incoming_payments` | `anchor` per receipt epoch | none | held receipts and the durable cursor |
| Reconcile | `committed_entry` only when every holder declines | `status`, `admitted`, `deliver` Challenge, `fault` record | the payer's committed terminal entry from the committee, verified against the admitted change root | held receipts, the durable per-epoch outcome |
| Native balance and transfer | none | native balance, `deliver` transfer, and the exact transfer effect | none | the staged signed transfer |
| Operator selection | none | the selected immutable registry entry | none | full deployment ID and deployment-scoped wallet database |
| Deposit, refund, hard-fault claim | none | `deliver` plus the `deposit`, `refund`, `fault`, and `hard_fault` records | the wallet's leaf at the frozen root when none is retained | the staged deposit, and for the hard-fault claim an opening retained for the frozen root |
| Registration and settlement status | none (the operator status panel is the operator's own uncertified report) | `registration`, `status` | none | none |

## Close certification and data availability

Distributed certification sends the same complete dealing to every committee member. The
header commits the epoch payment anchor, the activity root, the withdrawal-output root,
the successor QMDB balance root, and the withdrawal and payout totals. Validators derive
these commitments from the keyed inputs and their own predecessor state, then validate the
whole dealing before voting. Balance storage contains only positive current balances;
zero balances are authenticated absence. The separate settlement-record QMDB continues to
certify chain custody, admissions, deadlines, and claims.

DA messages identify the full deployment. Validators check the authenticated peer and
registered byte reservation before decoding the dealing. One network peer may host several
deployments; each has its own balance replica and evidence archives. A pending recovery for
one deployment leaves the actor free to handle the others.

Each validator durably records the validated dealing, canonical mutations, and evidence
before returning its vote. Votes and chain-selected history have separate archives: signing
one candidate does not authorize advancing the balance replica along that branch. Before
sealing a successor or serving an admitted balance root, the validator follows the actual
chain admission. A missed close is fetched from the other validators through
`EvidenceLookup::Dealing`, checked against the certified batch and roots, and fully validated
before replay. Invalid responses and timeouts advance to the next holder. The canonical
record is synced before applying and committing its QMDB mutations. Restart opens the native
QMDB head and compares it with the accepted archive frontier. It applies only a missing
canonical tail whose archive record became durable before the QMDB update completed;
already applied mutations are not replayed. Mutable storage failures stop the owning service.

The initial retention policy keeps complete activity evidence and canonical balance history.
Validators can serve Current membership and absence proofs at genesis, predecessor, pending,
finalized, and frozen recovery roots after the operator fails. Historical Current proofs use
an on-demand, read-only view of the same QMDB. They neither maintain a second database nor
rewind the live replica. A pending root remains
available even after its own challenge deadline because earlier FIFO windows can delay its
finalization. Catch-up and historical proof cost depend on the missing closes and requested
historical view; no bounded history pruning policy is implemented yet.

Setup generates each deployment's genesis root and operation count through native batch
preparation, writes them into the trusted genesis configuration, and removes its temporary
QMDB files. Followers consume that configuration without creating a separate genesis
database. Live balance replicas check their prepared genesis against the configured
commitment before exposing it.

The operator persists the completed close, certificate, and mutations before committing its
QMDB state, then waits for the exact certified admission. Its existing journal supplies the
result for retries after restart. It can accept
root-independent payments for the next epoch while closing the prior epoch; a successor
balance opening becomes available once that predecessor close has been applied. Every
validator partition is scoped by the full deployment digest, so concurrent deployments
keep independent balance and evidence ownership.

## Keys

| Key | Held by | Purpose |
| --- | --- | --- |
| Consensus threshold share (BLS) | each validator's `node.json` | signs simplex votes and certificates under the genesis threshold identity every certified read verifies against |
| Clearing committee key (BLS) | each validator's `node.json` | seals dealings and signs close-admission votes |
| Operator network key (ed25519) | each `operator-<index>/node.json` | authenticates that operator as a registered p2p secondary |
| Operator clearing key (curve25519) | operator `node.json` | signs the curve25519 half of receipts and epoch registrations; the registered configuration binds it to the deployment |
| Operator acknowledgment key (BLS MinSig) | operator `node.json` | signs the aggregable half of acknowledgments, verified against the registered public key |
| Wallet key (curve25519) | one per agent | signs sends and withdrawal authorizations, and names the account custody and claims resolve to |

## Run

Four validators, two operators, and any number of wallet agents run as separate processes on one
machine. Start them in this order, each in its own terminal (or under a multiplexer such as
`mprocs`). Build once first so the four validators do not compile concurrently:

```bash
cargo build --release -p commonware-terminal
```

| Role | Process | Default addresses |
|---|---|---|
| validators | `terminal-chain validator` | p2p `127.0.0.1:3000` to `3003`, query servers `3200` to `3203` |
| operators | `terminal-operator` | p2p `127.0.0.1:3400` and `3401`, RPC `--bind` (use `7001` and `7002`) |
| agents | `terminal-agent` | no listener, dial the operator RPC and the validator query servers |

**1. Set up.** Writes `./data/validator-0` to `./data/validator-3` and `./data/operator-0` and
`./data/operator-1`, each with its keys plus the shared `network.json` and `genesis.json`. The
validator count is fixed at four by the clearing committee, so keep the default `--peers 4`.
`--operators` chooses how many operators (one deployment each), and every other flag only moves
ports or the host (`terminal-chain setup --help`).

```bash
cargo run --release -p commonware-terminal --bin terminal-chain -- setup
```

**2. Start the four validators.** They form the consensus network, execute one settlement
machine per deployment, seal dealings, and answer certified reads and evidence requests on their
query servers.

```bash
mprocs "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-0" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-1" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-2" \
       "cargo run --release -p commonware-terminal --bin terminal-chain -- validator --node-dir ./data/validator-3"
```

**3. Start the operators.** Each joins the validators' network as a secondary, so start them after
the validators. Give each its own RPC address and SQLite database:

```bash
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-0 --bind 127.0.0.1:7001 \
  --database terminal-operator-0.sqlite
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-1 --bind 127.0.0.1:7002 \
  --database terminal-operator-1.sqlite
```

**4. Start wallet agents.** `--identity` picks the wallet (`0` Alice, `1` Bob, `2` Carol, `3` Dave,
`4` Eve, who is unregistered and only receives), `--operator` names the operator's RPC address,
and `--deployment` selects its genesis index or full registered deployment ID.
`--query` takes one or more validator query servers; one suffices and more give failover.
The defaults are operator `127.0.0.1:7001`, deployment `0`, identity `0`, and the genesis at
`data/validator-0/genesis.json`, so the smallest command is the first one below. Run Alice and
Bob on the same deployment to watch a payment land on the receiving side, and a wallet on
deployment `1` to see the second operator's independent ledger:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --query 127.0.0.1:3200
cargo run --release -p commonware-terminal --bin terminal-agent -- --identity 1 \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
cargo run --release -p commonware-terminal --bin terminal-agent -- --identity 0 \
  --operator 127.0.0.1:7002 --deployment 1 \
  --genesis data/validator-0/genesis.json \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
```

**Keys in the agent UI.** Left and Right select the receiver, `+` and `-` change the amount by
one and PageUp and PageDown by ten, and `q` or Esc quits. `p` pays the selected receiver the
selected amount, `a` stages the selected entry into a draft batch and `b` sends every staged
entry as one batched payment, `d` deposits the selected amount, `w` signs a withdrawal of the
selected amount for the operator to carry and `f` signs an amountless account Close, `x`
escalates a signed withdrawal into settlement's queue when the operator will not carry it, `s`
starts the epoch close, `c` claims a finalized withdrawal, `e` claims an external payout, `r`
refunds an expired pending deposit, and `h` runs hard-fault recovery. The activity feed logs
every enforcement event as it happens.

**Reset.** Every role is durable. To start over, stop everything and delete the chain's `./data`
directory (validator and operator storage), every `terminal-operator-*.sqlite`, and every
`terminal-agent-*.sqlite`, or pass fresh paths. Wallet and sealed-dealing layouts change on
this branch without migration, so a reset is also required after pulling a new revision.

**Walkthrough without a terminal UI.** With the validators and operators running, the scripted
walkthrough drives the whole arc on operator-0 and deployment 0 (pass `--operator
127.0.0.1:7002 --deployment 1` for the other operator) and exits when it completes:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --scripted \
  --query 127.0.0.1:3200 --query 127.0.0.1:3201
```

The rest of this section explains what each role does with those inputs.

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
replay a no-op. The depositor needs no separate notification to the operator.

Genesis allocates finite native balances to demo wallets and initial operators. A deposit
signs its chain, deployment, event ID, account, and amount. Execution debits native
funds and records custody atomically. Finalized withdrawal and payout claims, deposit refunds,
and hard-fault releases return funds to that native ledger.

A withdrawal is authorized against a certified state root and carried into an epoch close.
The operator durably freezes new withdrawal intake before publishing its registration;
exact retries remain possible. Deposits confirmed before registration still enter that
boundary. Admission opens the successor registration slot while the predecessor remains
challengeable. Every validator derives the exact
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

SQLite atomically derives every pending Close tail, projects closed accounts inactive at zero
balance, records the close job, and opens the successor under a root-independent payment
context. The cut visits Close authorizations rather than all accounts, and unchanged SQL
balance versions remain shared. A background worker prepares the close against its persisted
QMDB predecessor, distributes the complete dealing, collects the exact-quorum certificate,
and submits admission. The chain opens the successor registration window at admission while
the predecessor remains challengeable. Close retries remain bound to their original epoch,
so a lost response cannot cut the active successor. Finalization can prune obsolete SQL
projections; the independent QMDB history and close evidence remain available for proofs and
receiver reconciliation.

The scripted walkthrough deposits and waits for that credit to enter finalized state,
hands the operator a withdrawal to carry, pays an internal receiver,
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

## Add an operator to the running network

Prepare a directory using the running chain's configuration:

```bash
cargo run --release -p commonware-terminal --bin terminal-chain -- operator \
  --node-dir ./data/operator-new --genesis ./data/validator-0/genesis.json \
  --network ./data/validator-0/network.json --listen 127.0.0.1:3500
```

The command creates fresh keys, saves the signed registration, and prints the deployment ID,
funding account, and fees. Fund that account from a demo wallet, then register and start it:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- \
  --query 127.0.0.1:3200 --transfer-to <printed-native-account> --amount 1000000
cargo run --release -p commonware-terminal --bin terminal-chain -- register \
  --node-dir ./data/operator-new
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-new --bind 127.0.0.1:7003 \
  --database terminal-operator-new.sqlite
```

Validators discover the immutable registration in certified chain state and authorize its
network key. A bounded directory lists deployments; wallets prove the selected configuration
through its own record. Retrying registration uses the saved request and completes from the
exact certified entry.

Select the new operator with `--deployment <printed-deployment-ID>` and
`--operator 127.0.0.1:7003`. It starts with the demo account roster and no clearing balances.
Deposit native funds with `d`; the operator observes the finalized deposit and closes the
funding epoch. Payments become available after that credit enters finalized account state.

To change operators, claim a finalized withdrawal into the native account, then deposit at
the destination. `--native-balance` reads the certified native balance without contacting the
operator. Wallet databases remain scoped to a deployment because its receipts and recovery
evidence belong there. The chain also supports an atomic finalized-claim-and-deposit
transaction; a rejected destination leaves the source claim available. Optimistic receipts
do not authorize destination funding.

## Limits

The demo cuts corners a production deployment must not:

- A forced withdrawal needs an open registration boundary and current safety proofs.
  Continuous registrations can leave no intake window; permissionless submission alone
  does not guarantee eventual intake. Finalized claims and timely challenges remain
  independent of that boundary.
- Setup is a trusted dealer writing plaintext threshold shares and clearing keys into
  `node.json`, which is demo-grade key handling. Continuous resharing and a real DKG bootstrap
  are drop-ins from the reshare example: replace the constant scheme provider and the direct
  simplex engine with its orchestrator, probe, and reshare actors.
- Peer QMDB state sync is a documented no-op pending a glue extension: a late joiner replays
  finalized blocks through marshal backfill, and the reshare example's qmdb resolver actor is
  the drop-in server.
- Marshal's finalization and block archives are never pruned.
