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
   |       Settlement chain: 4 x terminal-chain           |
   |         native balances, custody, finality           |
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

**With operator** and **Onchain** are your two balances. The settlement panel's
**Custody** and **Claimable** amounts cover the whole deployment.

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

The first four stages use the live network. The challenge runs on a separate
in-process chain with simulated certification, leaving your live balances
untouched. The run ends with **Walkthrough complete.**

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

The recipient's wallet checks its receipts against admitted closes and challenges
omitted credits. It must be online in time to obtain the evidence and get a
challenge included before the deadline.

Payments move value within the operator's balances. Those balances can accumulate
across many closes before their owner chooses to withdraw to the chain.

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

The operator observes finalized deposits and includes their credits at an epoch
boundary.

For a withdrawal, wait for the carrying epoch in the activity log to finalize,
then claim it. The chain pays each certified output once. An account close
sweeps the balance at the end of its epoch. Later payments can create a balance
again.

### Closes advance while blocks pass

A close records the net effects of an epoch's payments. Validators certify it,
then the chain **admits** it for settlement. Payments continue in the next epoch
while earlier closes await finality:

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

The generated defaults allow 300 blocks for admission and one further block for
challenges. These deadlines are fixed at registration: a close registered at
height `H` cannot finalize before `H + 302`, even if admitted early. Earlier
closes must finalize first.

## What each process keeps

| Process | Owned state |
| --- | --- |
| Wallet | SQLite payment intents, receipts, and authenticated balance openings. |
| Operator | SQLite live payments and close jobs, plus one QMDB replica for balance proofs. |
| Validator | Certified chain state, one complete QMDB balance replica per deployment, and retained close evidence. |

Every validator checks the same dealing against its stored balances and saves
the evidence before voting. Balance replicas follow admitted closes and serve
historical proofs from the same QMDB. Activity and withdrawal proofs use
individually stored leaves and shared Merkle nodes. The operator's proof replica
advances independently of preparing the next dealing.

Wallets authenticate chain reads using `genesis.json` and keep unresolved signed
requests for retry. After a deployment fault, they can claim finalized withdrawals,
refund unadmitted deposits, and recover balances once the surviving state is frozen.
Keep the wallet databases and validators running so receipts and public proofs
remain available.

## Files, restarts, and multiple operators

```text
  data/
  |-- mprocs-wallets.yaml       interactive wallets
  |-- mprocs.yaml               scripted walkthroughs
  |-- validator-0/ ... validator-3/
  |   |-- *.json               keys, genesis, network configuration
  |   `-- runtime/             chain state and retained evidence
  `-- operator-0/
      |-- *.json                keys and chain configuration
      |-- runtime/              follower state
      |-- operator.sqlite.qmdb/ balance replica and retained proof history
      `-- *.sqlite              operator ledger and wallet databases
```

The launchers contain absolute paths to the generated files and built binaries.
Restart with the same launcher to keep balances, pending requests, and receipts.

Setup refuses a nonempty directory. To start fresh, stop the old launcher and
run setup with `--node-dir ./data-new`, then use that directory's launcher.
Stored formats may change without migration.

Use `setup --operators 2` in a fresh directory to run two deployments on the same
chain. Wallet labels identify their operator: **Alice 0** and **Alice 1** share a
native account but have separate operator balances and wallet databases.

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

```bash
just test -p commonware-terminal
```

Start with [wallets](src/agent/), [the operator](src/operator/), and
[the chain](src/chain/). See the [withdrawal model](stateright/README.md) for
lifecycle tests and the [protocol documentation](../../clearing/src/bajillion/mod.rs)
for settlement rules.

This local demo uses deterministic wallet keys and trusted committee setup, with
keys stored in plaintext. Peers catch up by replaying blocks, and stored history
is not pruned. Each epoch supports up to 1,024 payment entries, 1,024 deposits,
and 1,024 withdrawals, touching at most 4,096 accounts.
