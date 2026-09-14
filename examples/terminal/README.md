# commonware-terminal

Pay through a Bajillion operator and settle on a local four-validator chain.
Use the wallets to send payments, receive receipts, and move funds between an
operator balance and the chain's native asset.

```text
      Wallets                              Operator
   terminal-agent <-------------------> terminal-operator
         |         payments / receipts        |
         |                                    |
         | deposits, claims,                  | closes
         | certified reads                    |
         v                                    v
   +-----------------------------------------------------+
   |       Settlement chain: 4 x terminal-chain          |
   |         native balances, custody, finality          |
   +-----------------------------------------------------+
```

## Start here

Install [mprocs 0.9.6 or newer](https://github.com/pvolok/dekit/blob/v0.9.6/README.md#installation).
From the **repository root**, build all three binaries, create a fresh network,
and open the interactive launcher:

```bash
cargo build --release -p commonware-terminal
cargo run --release -p commonware-terminal --bin terminal-chain -- setup --operators 1
mprocs --config ./data/mprocs-wallets.yaml
```

To resume an existing network, run only the `mprocs` command. The four validators
and one operator start automatically. Wallets wait for you:

1. Select **Operator 0** and wait for **Operator ready**.
2. Select **Alice 0** in the process list and press `s` to start her wallet.
3. Press `Ctrl-a` to focus the wallet. Use its on-screen key guide to pay Bob 5.
4. Press `Ctrl-a` to return to the process list. Start **Bob 0** with `s`, then
   focus his wallet to see the incoming receipt.

Give the wallet at least 80 columns by 24 rows. `Ctrl-a` switches focus between
the process list and the wallet. In the process list, `z` zooms the selected pane
and `q` stops the whole demo.

On a fresh network, Alice, Bob, Carol, and Dave each have **100 with the
operator** and **1,000,000,000 native units**. Eve has neither. Pay Eve to create
her operator balance without a deposit or an onchain account. She can start
paying once that close is admitted; her first withdrawal request must wait for
it to finalize.

**With operator** and **Onchain** are your two balances. **Verified incoming**
tracks receipt-backed incoming value; **Checked epoch** tracks reconciliation
against admitted closes. The settlement panel's **Custody** and **Claimable**
amounts cover the whole deployment, not just your wallet.

### Prefer a scripted walkthrough?

Stop the interactive launcher, then open:

```bash
mprocs --config ./data/mprocs.yaml
```

Wait for **Operator ready**, select **Walkthrough 0**, and press `s`.

```text
  Fund --> Pay --> Settle --> Withdraw --> Challenge
            |                                 |
            +-- one payment                   +-- separate, throwaway chain
            +-- a two-recipient batch
            +-- Eve's first balance
```

The first four stages use the live network. The last demonstrates an omitted
payment and its challenge on an in-process single-validator chain with simulated
certification. It leaves the live operator and balances untouched. The run ends
with **Walkthrough complete.**

Both launchers use the same services and wallet databases. Run only one at a
time, and let the walkthrough finish before switching back to manual wallets.

## Follow the money

### A payment is accepted before it settles

```text
  Alice                      Operator                       Bob
    |                           |                            |
    |--- signed payment ------->|                            |
    |<-- signed receipt --------|                            |
    | verify + save             |<-- fetch incoming receipts -|
    |                           |--- receipt --------------->|
    |                           |                verify + save
    |                           |                            |
    |                      close the epoch                   |
    |                           |                            |
    |                   validators certify it                |
    |                   chain admits the close               |
    |                           |          check held receipts
    |                           |          against that close
```

The operator registers the epoch onchain before issuing its first receipt.
Wallets verify receipts against that registered context and retain them in
SQLite. A batch uses one payer signature for several recipients and is accepted
or rejected as a whole. If the response is lost, the wallet retries the saved request.

Once a close is admitted, the next epoch can accept payments while earlier closes
await finality. There is no fixed limit on how many admitted closes can be pending.

Recipients fetch their receipts from the operator and verify them locally. A
balance report alone is not proof of a payment. The wallet checks its retained
receipts against admitted closes and submits a challenge if a close omits a
credit. This requires the holder to stay online, or return in time to obtain the
public evidence and have a challenge included before the deadline.

Payments move value within the operator's balances. They do not move native
assets onchain. Existing eligible accounts can reuse incoming credit during an
epoch; a new account waits for its first close's admission. Balances can remain
with the operator across many closes before their owner requests a withdrawal.

### Deposits and withdrawals cross the custody boundary

```text
  DEPOSIT
  Native balance --> Chain custody --> Credit at an epoch boundary

  WITHDRAWAL (an exact amount or an account close)
  Operator balance --> Withdrawal in a close --> Close finalizes
                                                      |
                                                     claim
                                                      |
                                                      v
                                                 Native balance
```

The chain debits a deposit and records custody atomically. The operator observes
that finalized record itself and includes the credit in an epoch boundary; the
wallet does not need to notify it separately.

A withdrawal request is not a payout. Wait for the carrying epoch in the
activity log to finalize, then claim it. The chain pays the certified output
and consumes its claim in one transition. An account close sweeps the
balance at the end of its epoch; later payments can create a balance again.

### Closes advance while blocks pass

A close commits the net effects of an epoch's payments. Validators check its
evidence, then the chain **admits** it for settlement. Admission permits the
next epoch to register while the previous close remains challengeable:

```text
  epoch e:    register -- payments -- cut -- certify -- admit ... finalize
                                                        |
  epoch e+1:                                            register -- ...

  blocks:     [H] ---> [H+1] ---> [H+2] ---> ... (including empty blocks)
```

With the generated defaults, the operator schedules a cut four blocks after
registration, or sooner when the epoch fills. The wallet can request an earlier cut.
Validator panes show finalized block heights, hashes, and transaction counts.
Empty blocks advance deadlines too.

Deadlines are fixed when an epoch registers. The generated defaults allow 300
blocks for admission and one further block for challenges. A close registered
at height `H` cannot finalize before `H + 302`, even if admitted early. Earlier
closes must finalize first. An idle deployment with no registered work or
pending obligations has no timer to miss.

## What each process keeps

| Process | Owned state |
| --- | --- |
| Wallet | SQLite payment intents, receipts, and authenticated balance openings. |
| Operator | SQLite live payments and close jobs, plus a QMDB balance replica. |
| Validator | Certified chain state, one complete QMDB balance replica per deployment, and retained close evidence. |

Every validator receives the same dealing: the inputs needed to check a close
against its existing balances. It derives credits from signed payments, checks
the resulting commitments, and stores the evidence before voting. Its canonical
balance replica follows the close actually admitted by the chain. Restart
applies only a missing canonical suffix; historical proofs use the same QMDB.

Wallets verify chain reads against the threshold identity in `genesis.json`.
They complete chain transactions by proving their effects, and retain unresolved
signed requests for retry. Operator status shown in the UI is advisory.

If a proven fault or missed obligation stops a deployment, earlier clean closes
can still finalize before recovery freezes the surviving state root. Finalized
withdrawals remain claimable, pending deposits have a refund path, and balance
recovery uses an opening against that frozen root. Recovery depends on the chain
and the required evidence remaining available. Validators can serve public
openings; they cannot recreate a private receipt no wallet saved.

## Files, restarts, and multiple operators

```text
  data/
  |-- mprocs-wallets.yaml       interactive wallets
  |-- mprocs.yaml               scripted walkthroughs
  |-- validator-0/ ... validator-3/
  |   |-- *.json               keys, genesis, network configuration
  |   `-- runtime/             chain state and retained evidence
  `-- operator-0/
      |-- *.json               keys and chain configuration
      |-- runtime/             follower state
      |-- operator.qmdb/       balance replica and its close journal
      `-- *.sqlite             operator ledger and wallet databases
```

The launchers contain absolute paths to the generated files and the binaries
beside `terminal-chain`. They work when Cargo redirects its target directory;
there is no need to locate `target/release` yourself. Restart with the same
launcher to keep balances, pending requests, and receipts.

Setup refuses a nonempty directory. To start fresh, stop the old launcher and
run setup with `--node-dir ./data-new`, then use that directory's launcher.
Stored formats on this experimental branch may change without migration.

Use `setup --operators 2` in a fresh directory to run two deployments on the same
chain. **Alice 0 / Bob 0 / Eve 0** use operator 0; the corresponding **1** wallets
use operator 1. Native balances are shared across deployments, but operator
balances, custody, epochs, and faults are independent. Each wallet database is
bound to one full deployment ID.

| Service | Default ports |
| --- | --- |
| Four validators | P2P `3000`-`3003`; query `3200`-`3203` |
| Operator 0 | P2P `3400`; wallet RPC `7001` |
| Operator 1, if configured | P2P `3401`; wallet RPC `7002` |

All addresses default to `127.0.0.1`. A new directory alone does not change ports.
For concurrent networks, use `--base-port`, `--base-query-port`, `--operator-port`,
and `--operator-rpc-port`; `--host` changes the advertised host. The committee
size in this example must remain four.

### Run a wallet directly

With the services running, stop the launcher-managed Alice wallet before using
her same database from another terminal:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- \
  --identity 0 --deployment 0 --operator 127.0.0.1:7001 \
  --genesis ./data/validator-0/genesis.json --query 127.0.0.1:3200 \
  --database ./data/operator-0/alice.sqlite
```

Add `--scripted` to run the walkthrough directly, with both Alice and Eve's
interactive wallets stopped. Identity numbers are `0=Alice`, `1=Bob`, `2=Carol`,
`3=Dave`, and `4=Eve`; use a separate database for each wallet. Add
`--native-balance` for a one-shot certified read instead of opening the UI.

### Add an operator without restarting the chain

<details>
<summary>Prepare, fund, register, and connect a new operator</summary>

These commands use the network above. Keep its validators running, but stop
Alice's wallet and any walkthrough while the funding command uses her database.
Prepare a new operator directory:

```bash
cargo run --release -p commonware-terminal --bin terminal-chain -- operator \
  --node-dir ./data/operator-new --genesis ./data/validator-0/genesis.json \
  --network ./data/validator-0/network.json --listen 127.0.0.1:3500
```

The command prints a native funding account, the full deployment ID, and fees.
Replace `FUNDING_ACCOUNT` below with that printed account. Funding uses Alice's
existing deployment and wallet; the new deployment is not registered yet.

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- \
  --identity 0 --deployment 0 --operator 127.0.0.1:7001 \
  --genesis ./data/validator-0/genesis.json --query 127.0.0.1:3200 \
  --database ./data/operator-0/alice.sqlite \
  --transfer-to FUNDING_ACCOUNT --amount 1000000
cargo run --release -p commonware-terminal --bin terminal-chain -- register \
  --node-dir ./data/operator-new --query 127.0.0.1:3200
cargo run --release -p commonware-terminal --bin terminal-operator -- \
  --node-dir ./data/operator-new --bind 127.0.0.1:7003 \
  --database ./data/operator-new/operator.sqlite
```

After **Operator ready**, open another terminal. Replace `DEPLOYMENT_ID` with the
full printed ID, and use a new wallet database for this deployment:

```bash
cargo run --release -p commonware-terminal --bin terminal-agent -- \
  --identity 0 --deployment DEPLOYMENT_ID --operator 127.0.0.1:7003 \
  --genesis ./data/validator-0/genesis.json --query 127.0.0.1:3200 \
  --database ./data/operator-new/alice.sqlite
```

The deployment starts with no operator balances. Deposit native funds from the
wallet, then wait for the funding close before paying. Adding an operator does
not regenerate the launchers. To move funds between operators through the UI,
withdraw and claim into the native account, then deposit with the other operator.

</details>

## Implementation and tests

Start with [wallets](src/agent/), [the operator](src/operator/), and
[the chain](src/chain/). The [Bajillion protocol](../../clearing/src/bajillion/mod.rs)
explains the signed records and settlement rules; the
[Stateright models](../../clearing/stateright/README.md) exercise certification,
settlement, challenges, and claims, including implementation refinement checks.

```bash
just test -p commonware-terminal
```

To explore a model in the browser while the demo runs, choose a different port
from the validator's default `3000`:

```bash
cargo run -p commonware-clearing --example bajillion_model -- settlement 127.0.0.1:8088
```

## Limits

- This is a local demo with an internal native asset, deterministic wallet keys,
  and trusted committee setup. Shares and operator keys are stored in plaintext.
  Committee rotation and DKG are separate work; see the [reshare example](../reshare/).
- Forced withdrawal intake needs an open registration boundary. Continuous
  registrations can prevent intake, so queuing a request is not an unconditional
  exit guarantee. Finalized claims and timely challenges do not need that boundary.
- Each epoch allows at most 1,024 payment entries, 1,024 deposits, and 1,024
  withdrawals, touching at most 4,096 accounts. Dormant balances do not consume
  that capacity. The 1,024-account genesis limit applies only to initial allocations.
- Late peers catch up by replaying finalized blocks. Peer QMDB state sync is not
  wired up, and its current 4 MiB message framing cannot carry every valid journal
  operation. Block archives and canonical balance history are not pruned.
