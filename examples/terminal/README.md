# commonware-terminal

Run `commonware-clearing` through three independently owned roles:

- `terminal-settlement` owns custody, close admission, finalization, and claim replay protection.
- `terminal-operator` owns the SQLite ledger, accepts signed sends, issues receipts, and constructs
  closes.
- `terminal-agent` owns one wallet key, verifies returned receipts, and provides the Ratatui UI.

The processes exchange one bounded request and response per connection using canonical
`commonware-codec` messages over Commonware's runtime networking traits. There is no HTTP,
protobuf, or generated RPC layer.

The example is educational rather than a production operator or asset adapter. Wallet,
operator, and validator keys are deterministically derived. The settlement process is intentionally
in-memory; the SQLite operator and its close queue survive restarts. Each wallet's cumulative
debit, pending signed send, and authenticated receipts are SQLite-backed. Deposit, withdrawal, and
claim retries remain process-local, so those workflows do not promise exactly-once behavior across
an agent restart. Settlement keeps a bounded in-memory acknowledgement window; older admission and
claim retries fail closed instead of executing again.

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

The UI supports payments, deposits, exact withdrawals, amountless account Close authorizations,
withdrawal claims, and epoch closure. A deposit first becomes settlement custody and is then
credited by the operator. A withdrawal is authorized against the settlement state root, included
in an epoch close, and later claimed from its bounded ChangeRoot proof. An exact withdrawal is
applied immediately. A Close stays pending and leaves the account usable for the rest of the
epoch. Its finalized payout is the opening balance plus deposits and incoming credits minus
outgoing debits. That tail may be zero, and the exact value is reported only by finalized claim
evidence when positive. A zero tail completes without creating payout work.

Payments to an absent identity become claimable external payouts rather than recipient-sized
settlement output. This includes Eve and a configured account removed by Close until a later
deposit reactivates it. Each recipient claims independently with `e`.

Closing is pipelined. SQLite atomically derives every pending Close tail, projects those historical
rows inactive at zero balance while retaining their counters and payment evidence, adjusts live
liability, records the close job, and opens the successor under a root-independent payment context.
The cut is proportional to Close authorizations rather than all accounts, and unchanged account
versions remain copy-on-write. The operator can accept successor payments while a background
worker rebuilds the predecessor BMTs, deals proof slices, has validators seal their dealings, and
submits the certificate to settlement. Close retries remain bound to their original epoch, so a
lost response cannot cut the active successor. Finalization prunes balance versions that are no
longer challengeable.

For a terminal-free walkthrough, start settlement and operator as above, then run:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- --scripted
```

The walkthrough deposits, queues a withdrawal, pays an internal and external recipient, starts an
asynchronous close, proves that the successor epoch accepts another payment, and claims the
finalized withdrawal and external payout.
