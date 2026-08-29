# commonware-terminal

Run `commonware-clearing` through three independently owned roles:

- `terminal-settlement` owns custody, close admission, challenge timing, finalization, hard-fault
  recovery, and claim replay protection.
- `terminal-operator` owns the SQLite ledger, accepts signed sends, issues receipts, and constructs
  closes.
- `terminal-agent` owns one wallet key, verifies returned receipts, holds as a receiver
  the pairs crediting it, reconciles them against admitted closes, and provides the Ratatui UI.

The processes exchange one bounded request and response per connection using canonical
`commonware-codec` messages over Commonware's runtime networking traits. There is no HTTP,
protobuf, or generated RPC layer.

The example is educational rather than a production operator or asset adapter. Wallet,
operator, and validator keys are deterministically derived. The settlement process applies every
state-bearing input in memory and appends it to a SQLite log before responding, so a restarted
settlement replays the log back into the identical state. The SQLite operator and its close queue
also survive restarts. Each wallet's cumulative debit, pending signed send, authenticated
receipts, and the exact state-root openings observed before payment and withdrawal authorization
are SQLite-backed.
Openings are retained by full root so a later hard fault can freeze an older finalized root.
A staged deposit survives an agent restart and is retried with the same event id, which
settlement and the operator both deduplicate. Withdrawal authorization retries remain
process-local, so that workflow alone does not promise exactly-once behavior across an agent
restart. Settlement keeps bounded
in-memory replay windows for admission, challenge, terminal-state claims, and pending-deposit
refunds. Successful finalized withdrawal and external-payout claims retain their exact results for
the deployment lifetime, allowing response-loss retries and mandatory operator
acknowledgements after any number of later valid claims. The returned releases model an asset
adapter decision, not an external transfer. A production embedding must durably and atomically
commit each transfer with its replay-protection mutation.

## User flows

```text
PAYMENT

 wallet                    operator                         settlement
   |-- read payer head ------->|                                 |
   |<-- context, state root, StateOpening                        |
   |-- read status --------------------------------------------->|
   |<-- deployment, exact finalized state root, fault status ----|
   | verify live payer opening; persist exact root + opening      |
   | sign and persist (root, SignedSend S)                        |
   |-------------------------->|                                 |
   |                           | first payment for epoch:        |
   |                           | register exact context -------->|
   |                           |<------------------------- accept|
   |                           | sign one linked receipt per entry|
   |<--------------------------|                                 |
   | verify S and every receipt                                   |
   |-- confirm (epoch, anchor, predecessor root) ---------------->|
   |<--------------------------- exact live registration or reject|
   | atomically persist (root, receipts); advance wallet-local debit|
   |
   +-- invalid or missing receipt => reject without advancing wallet-local debit
   +-- missing response => acceptance unknown; retry exact persisted S
   +-- admitted close omits an accepted send => the payment did not happen and the payer's
       funds stay, resolved by abandoning against the finalized endpoint. A payer can never be
       over-debited: public validity certifies every committed debit against a payer-signed
       send, so enforcing an omitted credit belongs to the harmed receiver, not the payer

 A send names one or more strictly recipient-sorted entries under one signature and one
 cumulative debit endpoint. The operator accepts or rejects the batch as a whole and
 returns one receipt per entry, all committed in one SQLite transaction. A single payment
 is a batch of one.

DEPOSIT OR WITHDRAWAL AUTHORIZATION

 deposit: wallet -> settlement custody -> operator credit -> next exact close boundary

          once settlement accepts custody, operator loss returns a pending outcome;
          retry uses the exact event, and timeout recovery refunds the settlement account

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
          -> any later settlement request observes now > deadline
          -> FINALIZED
                |
                +-- withdrawal output + one opening -> destination, amount
                +-- external payout + one opening   -> receiver, amount
                +-- successor state becomes the next finalized head

 Epochs register and finalize in exact order: e, e+1, e+2. A retry may repeat e,
 but registration, admission, and FIFO finalization cannot jump over it.

OPERATOR FAULT

 missed registered admission | expired deposit/withdrawal | proven receipt challenge
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

Recovery does not recreate unavailable evidence. Before staging each new payment or fresh
withdrawal, the agent retains its payer opening against settlement's exact finalized root;
recovery uses it only when that full root is later frozen. A carried withdrawal is invisible to
settlement until its close registers, so it gains the deadline-fault guarantee only once that close
is admitted. If the operator disappears or censors first, the signer queues the exact signed
request at settlement instead. The next registered close must then carry the queued request
verbatim, and only an operator that stalls entirely lets the obligation expire into hard-fault
recovery. This covers roots the agent observed while online, not an unobserved root reached while
it was offline. An account reactivated by a current-epoch deposit cannot pay until it appears in a
later epoch-predecessor state, because the current frozen root has no live payer leaf to retain.
Receipt challenges still require the exact linked send/receipt pair. The example supplies no
data-availability network or third-party opening retrieval.

Receiver enforcement flow. A wallet that provides a service is the party an omitted credit harms,
so it enforces its own preconfirmations. It fetches the pairs crediting it from the operator by a
durable cursor, verifies each fully (payer send signature once per transaction, operator receipt
signature, exact linkage, and its own recipient), and anchors the pair's `(epoch, anchor)` to the
context settlement registered for that epoch. A receipt over an operator-chosen anchor with no
settlement obligation is never reliance-grade. Only then does it durably hold the pair and gate
service on it, so a balance read from the operator's head is an observation, not reliance. In the
background it reconciles held credits against the admitted close: settlement serves the batch
identity and change root it admitted for the epoch, and operator-served committed-side evidence is
trusted only when it matches that anchor exactly, so the operator can withhold a lookup but can
never fabricate coverage. Withholding has no settlement-clock backstop once a close is admitted,
so an epoch that finalizes while its lookup is still withheld is surfaced as an alarm and kept
retrying. When a held receipt exceeds the anchored committed tip inside the admission-to-
finalization window, the wallet convicts the close with one `HigherShardTip` challenge and stops,
because one proven challenge invalidates the whole close. The operator is the pair-delivery
channel, and withholding a pair only degrades to the acceptance gate: an unheld credit is never
relied upon and so harms no one. Wallets file `HigherShardTip` only, and the
authenticated-absence form covers even a receiver the close omits entirely.
`LatestAcknowledgedSend` exists for a holder whose held pair no committed shard tip contradicts,
proving the omission through the payer-row angle instead, and the receipt-range and receipt-fork
families require operator equivocation the honest demo never produces. Settlement adjudicates
all four.

Registration confirmation is live rather than historical. A registered context remains
confirmable while its matching close is challengeable, but finalization, expiry, or a proven fault
ends that authority. A late receipt therefore cannot rely on an old registration merely because a
later epoch has the same state root; accepting after finalization would require authenticated
inclusion evidence, which this example does not provide.

## Run

Start each role in its own terminal:

```bash
cargo run --release -p commonware-terminal --bin terminal-settlement
```

```bash
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --database terminal-operator.sqlite
```

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --identity 0
```

Every role is durable, so starting the demo over requires deleting
`terminal-settlement.sqlite`, `terminal-operator.sqlite`, and every `terminal-agent-*.sqlite`
(or passing fresh `--database` paths) before starting the trio again.

Agent identities are `0=Alice`, `1=Bob`, `2=Carol`, `3=Dave`, and `4=Eve (external)`. The first
four are registered operator accounts. Eve demonstrates an unregistered receiver claiming an
external payout. Run more agent processes with different identities to exercise independently
owned wallets. Each identity defaults to `terminal-agent-<identity>.sqlite`; pass `--database` to
choose an explicit wallet database path.

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
operator. A deposit is placed at settlement, the only ramp in: settlement takes custody and
records a refund path, and the operator then loads the balance, crediting only after settlement
reports the deposit recorded. A withdrawal is authorized against the settlement state root,
carried by the operator, and included in an epoch close.
Deposits and fresh withdrawal authorizations are accepted only while no payment context is
registered: the epoch's first payment registers the context, and later requests are rejected
until the successor epoch opens after the close finalizes. Every validator derives the exact
destination and amount at the request's position under the withdrawal-output root. A finalized
output is independently claimed with that destination, amount, and one Merkle opening. A Close
stays pending and leaves the account usable for the rest of the epoch. Its output is the
predecessor balance plus deposits and incoming credits minus outgoing debits. That tail may be
zero, in which case the Close completes without creating payout work.

Payments to an absent identity become claimable external payouts rather than receiver-sized
settlement output. This includes Eve and a configured account removed by Close until a later
deposit reactivates it. Each receiver claims independently with `e`.

Before returning an epoch's first operator-signed receipt, the operator sends settlement an
operator-signed registration containing the exact epoch, predecessor liability, deposit boundary, and
withdrawal boundary. Settlement derives and registers that exact payment context. Registration is
one-shot rather than a heartbeat: an idle open slot has no deadline, but an activated context must
admit its matching certified close by its inclusive admission deadline or the deployment
permanently hard-faults. For the demo, one logical settlement time unit is 30 seconds of monotonic
process time. A registered context has ten admission ticks, and an admitted close remains pending
for one inclusive challenge tick. Settlement observes elapsed time on later requests and status
reads; it need not run a background heartbeat to make an expired obligation permanent. Deposit and
withdrawal deadlines are independent: if one expires while a clean admitted close remains
challengeable, the fault is recorded, the clean FIFO front still finalizes after its window, and
terminal recovery preserves both its claim reserves and its successor state.

SQLite atomically derives every pending Close tail, projects those historical rows inactive at zero
balance while retaining their counters and payment evidence, adjusts live liability, records the
close job, and opens the successor under a root-independent payment context. The cut is proportional
to Close authorizations rather than all accounts, and unchanged account versions remain
copy-on-write. A background worker rebuilds the predecessor BMTs, deals proof slices, has validators
seal their dealings, and submits the certificate to settlement. This educational adapter registers
only one context at a time, so a successor's first payment retries until its predecessor finalizes;
the Bajillion settlement primitive itself supports a bounded admitted pipeline. Close retries remain
bound to their original epoch, so a lost response cannot cut the active successor. Finalization
prunes balance versions that are no longer challengeable.

For a terminal-free walkthrough, start settlement and operator as above, then run:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --scripted
```

The walkthrough deposits, hands the operator a withdrawal to carry, pays an internal receiver,
pays a two-receiver batch under one signature, and pays an external receiver. A receiver then
durably intakes and settlement-anchors its incoming pairs and gates service on that held evidence
before the epoch is cut, the walkthrough starts an asynchronous close, opens the registered
successor after finalization, reconciles the receiver's finalized credit as evidence-backed, and
claims the finalized withdrawal and external payout. It closes with a self-contained fraud arc:
an assembled omitting close is admitted, the omitted receiver's held receipt convicts it with a
proven `HigherShardTip` challenge through the real dispatch, and the fraudulent operator is fenced.
The operator binary stays honest, and the fraud is assembled only in the scripted walkthrough.
