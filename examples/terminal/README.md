# commonware-terminal

Run `commonware-clearing` through three independently owned roles:

- `terminal-settlement` owns custody, close admission, challenge timing, finalization, hard-fault
  recovery, and claim replay protection.
- `terminal-operator` owns the SQLite ledger, accepts signed sends, issues receipts, and constructs
  closes.
- `terminal-agent` owns one wallet key, verifies returned receipts, and provides the Ratatui UI.

The processes exchange one bounded request and response per connection using canonical
`commonware-codec` messages over Commonware's runtime networking traits. There is no HTTP,
protobuf, or generated RPC layer.

The example is educational rather than a production operator or asset adapter. Wallet,
operator, and validator keys are deterministically derived. The settlement process is intentionally
in-memory; restarting it is unsupported, while the SQLite operator and its close queue survive
restarts. Each wallet's cumulative debit, pending signed send, authenticated receipts, and the
exact state-root openings observed before payment and withdrawal authorization are SQLite-backed.
Openings are retained by full root so a later hard fault can freeze an older finalized root.
Deposit and withdrawal authorization retries remain process-local, so those
workflows do not promise exactly-once behavior across an agent restart. Settlement keeps bounded
in-memory replay windows for admission, challenge, terminal-state claims, and pending-deposit
refunds. Successful finalized withdrawal and external-payout claims retain their exact results for
the settlement process lifetime, allowing response-loss retries and mandatory operator
acknowledgements after any number of later valid claims. The returned releases model an asset
adapter decision, not an external transfer. A production embedding must durably and atomically
commit each transfer with its replay-protection mutation.

## User flows

```text
PAYMENT

 wallet                    operator                         settlement
   |-- quote payer ----------->|                                 |
   |<-- context, state root, StateOpening                        |
   |-- read status --------------------------------------------->|
   |<-- deployment, exact finalized state root, fault status ----|
   | verify live payer opening; persist exact root + opening      |
   | sign and persist (root, SignedSend S)                        |
   |-------------------------->|                                 |
   |                           | first payment for epoch:        |
   |                           | register exact context -------->|
   |                           |<------------------------- accept|
   |                           | sign linked receipt R            |
   |<--------------------------|                                 |
   | verify S + R                                                 |
   |-- confirm (epoch, anchor, predecessor root) ---------------->|
   |<--------------------------- exact live registration or reject|
   | atomically persist (root, pair); advance wallet-local debit  |
   |
   +-- invalid R => reject without advancing wallet-local debit
   +-- missing response => acceptance unknown; retry exact persisted S
   +-- admitted close omits/conflicts with S + R => challenge by its deadline

DEPOSIT OR WITHDRAWAL AUTHORIZATION

 deposit: wallet -> settlement custody -> operator credit -> next exact close boundary

          once settlement accepts custody, operator loss returns a pending outcome;
          retry uses the exact event, and timeout recovery refunds the settlement account

 withdrawal: read settlement's configured, non-faulted finalized root
             -> select the exact retained opening, or fetch, verify, and persist that root
             -> sign and queue at settlement -> ask the operator to apply

             once settlement accepts the queue, operator loss returns a pending outcome;
             retry uses the exact signed request, and expiry enables hard-fault recovery

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
                +-- external payout + one opening   -> recipient, amount
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
recovery uses it only when that full root is later frozen. Queueing precedes operator application,
so a queued withdrawal can expire into hard-fault recovery even if the operator disappears before
applying it. This covers roots the agent observed while online, not an unobserved root reached while
it was offline. An account reactivated by a current-epoch deposit cannot pay until it appears in a
later epoch-predecessor state, because the current frozen root has no live payer leaf to retain.
Receipt challenges still require the exact linked send/receipt pair. The example supplies no
data-availability network or third-party opening retrieval.

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

Agent identities are `0=Alice`, `1=Bob`, `2=Carol`, `3=Dave`, and `4=Eve (external)`. The first
four are registered operator accounts. Eve demonstrates an unregistered recipient claiming an
external payout. Run more agent processes with different identities to exercise independently
owned wallets. Each identity defaults to `terminal-agent-<identity>.sqlite`; pass `--database` to
choose an explicit wallet database path.

The UI supports payments, deposits, direct pending-deposit refunds with `r`, exact withdrawals,
amountless account Close authorizations, withdrawal claims, payer-state hard-fault recovery with
`h`, and epoch closure. A pending-deposit refund needs only the wallet account and settlement; it
does not contact the operator. A deposit first becomes settlement custody and is then
credited by the operator. A withdrawal is authorized against the settlement state root and
included in an epoch close. Every sealer derives the exact destination and amount at the request's
position under the withdrawal-output root. A finalized output is independently claimed with that
destination, amount, and one Merkle opening. A Close stays pending and leaves the account usable
for the rest of the epoch. Its output is the predecessor balance plus deposits and incoming credits
minus outgoing debits. That tail may be zero, in which case the Close completes without creating
payout work.

Payments to an absent identity become claimable external payouts rather than recipient-sized
settlement output. This includes Eve and a configured account removed by Close until a later
deposit reactivates it. Each recipient claims independently with `e`.

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

The walkthrough deposits, queues a withdrawal, pays an internal and external recipient, starts an
asynchronous close, opens the registered successor after finalization, and claims the finalized
withdrawal and external payout.
