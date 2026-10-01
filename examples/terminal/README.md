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

This alpha demo does not migrate existing data across protocol state or wire
format changes. Create a fresh network when upgrading those formats.

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

A signed withdrawal can enter settlement only while its deadline lies within the
notice window. When that window closes before a registration carries it or the
chain queues it, the wallet discards it. Payments resume, and a later withdrawal
signs a new request.

### Closes advance while blocks pass

A close records the net effects of an epoch's payments. Validators certify it,
then the chain **admits** it for settlement. The operator registers the next epoch
while continuing to accept payments in the current one. Once registration is
confirmed onchain, it switches payments and builds the previous epoch's close:

```text
  epoch e:    register -- payments ------------ end -- build -- certify -- admit ... finalize
                                                |
  epoch e+1:              register onchain -----+-- payments -- end -- ...

  blocks:     [H] ---> [H+1] ---> [H+2] ---> ... (including empty blocks)
```

With the generated defaults, the operator starts registering the next epoch four
blocks after the current epoch's registration, or sooner when the epoch fills.
The wallet can request an earlier transition. Transitions do not wait for
earlier closes, so closes can queue. Empty registered epochs follow the same
schedule. Every epoch registration pays the epoch fee, which scales with the
deployment's dealing reservation. The operator closes an epoch only after its
successor registers, so an operator that cannot pay its successor's epoch fee
never closes the registered live epoch, and the deployment hard-faults once that
epoch's admission deadline passes. Deposits wait in the settlement chain's
inbox, and a registration must pull each one within 400 blocks. A registration
pulls only intake recorded before its block. From then on a deposit follows its
epoch to admission, or to a refund if the deployment faults first, however long
the closes queued ahead of it take. Validator panes show finalized block
heights, hashes, and transaction counts. Empty blocks advance deadlines too.

Each payment in epoch `e+1` also signs the root where the payer's vector ended
in `e`, and validators reject a close that carries a payment bound to another
root. An unaccepted payment from `e` that arrives after the epoch ends is
rejected as stale with the payer's final state in `e` and the root `e+1`
requires. The operator keeps that state until `e+1` finalizes. The wallet then
signs the remaining payments again in `e+1` against that root and keeps the
originals as superseded copies until an admitted close decides them. A request
that gets no response is resent unchanged, never treated as excluded. If the
operator acknowledged a payment that no close can carry, the wallet keeps that
receipt and challenges the admitted close that omits it until that close
finalizes.

The generated defaults allow 300 blocks for admission and 300 further blocks for
challenges. An epoch receives these deadlines once every earlier epoch is
admitted, either at its registration or at its predecessor's admission. A close
whose deadlines start at height `H` cannot finalize before `H + 601`, even if
admitted early. Earlier closes must finalize first.

## Getting your money out

The settlement chain holds every obligation and its deadline, so funds leave
without the operator. [The chain module](src/chain/mod.rs) describes the
lifecycle, and [the transaction table](src/chain/tx.rs) lists each
transaction's checks.

A registration **pulls** deposits and queued withdrawals from the chain's inbox
in recording order and **carries** the requests it includes for its epoch's
close. That close must credit or carry everything pulled. A missed deadline or a
proven challenge **hard-faults** the deployment, and the settlement panel shows
**HARD FAULT**. Each account then recovers its balance at the **frozen root**,
which is the state after the last close that finalizes. The first accepted `h`
from any account starts **terminal settlement**.

`w` signs an **Amount** request for the draft amount, and `f` signs a **Close**
request for your whole balance. A lower-case **close** is an epoch's certified
result. An **opening** proves a balance at a state root. **Onchain** is your
native account.

Keys: `R` retry saved payment, `p` send this payment, `w` withdraw, `f` Close
account, `x` escalate, `c` claim withdrawal, `h` recover state, `r` refund
deposit, `d` deposit, and `t` fund operator. `x`, `h`, `r`, and `c` pay no fee,
so they work without native units. They can take up to a minute to report, and
the wallet does not redraw meanwhile.

The settlement panel's **Height** counts blocks, which have no fixed pace, and
**finalized** shows the latest finalized epoch. In the operator panel,
**FENCED** means the operator reports a fault and **UNAVAILABLE** means it does
not answer. If either persists, follow these steps.

### If your operator stops serving you

1. Whenever the settlement panel shows **HARD FAULT**, follow
   [After a hard fault](#after-a-hard-fault).
2. If the payment draft shows **Saved payment awaiting confirmation**, press
   `R`. If it logs "Payment still unresolved", go on to step 3.
3. Press `f`, then `x`, even if the operator accepted the request. Whenever
   `x` is rejected, press `f` again, then `x`.
4. Each time **finalized** advances, press `c` until it logs "withdrawal
   claimed".

### Every failure and its exit

| The operator | On the chain | You press | You get |
| --- | --- | --- | --- |
| Refuses or ignores your payment, or sends a report the wallet cannot use | Nothing lands. Nothing faults while closes continue. | `R`. On "Payment still unresolved", `f`, then `x`. | Your balance at the end of the carrying epoch, less any pending payment a close carried by then. |
| Carries your payment in epoch `e` and withholds the receipt | The close of `e` settles it. | `R` each time **finalized** advances. If still pending, as above. | The payment settles once. The rest exits as above. |
| Ignores your withdrawal, or accepts it and never carries it | `x` queues it. The registration that pulls it, or an earlier one, must carry it. The deployment faults at the signed deadline unless its close has finalized. | `x` right after `w` or `f`. Then `c`. | See Amount and Close below. |
| Never pulls your deposit | Fault 400 blocks after the deposit. | [Hard-fault steps](#after-a-hard-fault). | `r` returns deposits no admitted close carried. `h` pays your operator balance. |
| Stops closing, crashes, or disappears | Fault at most 301 blocks after its last registration or admission. With no epoch awaiting admission, nothing faults until a deposit or queued withdrawal expires. Admitted closes still finalize. | [Hard-fault steps](#after-a-hard-fault). If the settlement panel still shows ONLINE 301 blocks after the operator stopped, nothing faults on its own. `d` forces a fault 400 blocks later, or `f`, then `x`, 1,301 blocks after signing. | `h`, `r`, and `c` pay out. Payments in epochs that never finalize stay with the payers. |
| Cannot pay the epoch fee | The registration fails at no charge, and the epoch stalls as above. | `t` sends the draft amount from Onchain to the operator's native account for good. It helps only while the operator runs and lacks one epoch fee, which the wallet does not show. Otherwise as above. | As above. |
| Admits a close that omits or understates your payment | Your wallet challenges with its receipts by the challenge deadline. A proven challenge invalidates that close and every later admitted close, and faults. | Keep the wallet running through the challenge deadline. It challenges on its own and logs the conviction. A recipient's wallet can stop after "epoch N reconciled" for the receipt's epoch. | `h` pays your balance at the last close before the challenged one. The payer keeps the payment. A missed challenge finalizes the close, a recipient's wallet logs an ALARM, and the credit is lost. |
| Carries your withdrawal in a close that fails | A dropped registration returns a request you queued with `x` to the inbox and discards one carried without it. An invalidated close keeps its withdrawals for terminal settlement. | `h`, and `c` if the close finalized. | Your frozen balance through `h`, or the payout through `c` and the rest through `h`. |
| Carries your deposit in a registration a fault drops, or in a close a challenge invalidates | The deposit stays refundable. | `r` after the fault if dropped, or once terminal settlement starts if invalidated. | The deposit, to Onchain. |
| Withholds or forges proofs, openings, or receipts | Nothing. | Nothing. The wallet asks the validators for any opening or proof the operator withholds or forges. | Every exit completes without operator proofs. A recipient missing incoming receipts cannot challenge an omission and keeps the credit that finalized closes carry. |
| Is gone after your payout finalized | The payout never expires. | `c` promptly, because proofs can lapse. | The payout, to Onchain. |

**Payments.** `w` refuses while a payment is pending, and `f` still signs. A
payment that stays undecided blocks `p` on this wallet for good. `R` can
conclude a payment from the chain only after its epoch finalizes and before two
more epochs finalize. That window can last only a few blocks, and the wallet
never checks on its own.

**Escalation.** `x` needs a finalized balance that covers an Amount or is
positive for a Close. It changes nothing and logs "withdrawal escalation
rejected" after about a minute if a registration already carries the request
or the 100-block escalation window has closed. Then repeat the same request
(`f`, or `w` with the same amount), then `x`. The wallet offers the same request while it stands. If
the window closes before `x` or a registration enters it, the wallet discards
it without a log line, and the next `f` or `w` signs a new one.

**Amount and Close.** A Close pays your balance at the end of the carrying
epoch. An Amount pays in full if that balance covers it and nothing otherwise,
and your operator balance keeps the rest. An Amount that pays nothing still
blocks `f` until its deadline.

### After a hard fault

Start once the settlement panel shows **HARD FAULT**. Anyone may land these
transactions, each is safe to repeat, and none expires. Only `h`, `r`, and `c`
move funds out of the deployment, and `w` and `f` refuse with "settlement is
permanently hard-faulted".

1. `h` pays your balance at the frozen root. While an admitted close that no
   challenge invalidated awaits finalization, `h` logs "hard-fault recovery
   rejected: terminal settlement never certifiably began". Press it again
   until it succeeds, within about 600 blocks of the fault plus one block per
   pending close. It pays a withdrawal that is queued or in an invalidated
   close first when the frozen balance covers it, all to Onchain, and logs
   "hard-fault recovery released X (residual Y)" with Y the rest. A pending
   payment does not block `h`.
2. `r` refunds deposits that no admitted close carried. After terminal
   settlement starts it also refunds those of invalidated closes, so press it
   again after `h` succeeds. With nothing left, it logs "deposit refund
   rejected: the refund claim earned no certified release" after about a
   minute. A repeated `r` in the same phase reports the earlier refund again
   and pays nothing more.
3. `c` claims one finalized payout, including one finalized after the fault.
   After `h` succeeds, press `c` until it logs "claim rejected: no unspent
   wallet-owned payout is available". Every payout is then claimed.

### Deadlines

Empty blocks count. Settlement accepts a withdrawal only while its deadline
lies 1,201 to 1,301 blocks ahead, which leaves the 100-block escalation
window.

| Window | Blocks | At its end |
| --- | --- | --- |
| Admission | 300 after deadlines start | The next block faults unless the close was admitted |
| Challenge | 300 more | The close may finalize 601 blocks after deadlines start |
| Deposit pull | 400 after the deposit | Fault unless a registration pulled it |
| Escalation | 100 after signing | Settlement refuses the request |
| Withdrawal | 1,301 after signing | Fault if the request is queued or admitted and unfinalized. Until then the wallet signs no payment or other withdrawal, unless it discarded the request. |

### What you still depend on

- A live settlement chain that includes your transactions. The operator is a
  non-signing node and cannot keep your transaction out of a block.
- One source for each proof: the wallet database, its operator, or any
  genesis validator.
- Your wallet running from a close's admission through its challenge deadline,
  to challenge an omission.
- Prompt claims. Validators without `--retain-native-history` prune old payout
  history, so after the operator leaves an old payout needs a genesis
  validator that kept it. A proof that `c` holds stays valid once the admitted
  closes finalize after a fault.

## What each process keeps

| Process | Owned state |
| --- | --- |
| Wallet | SQLite payment intents, receipts, superseded copies of re-signed payments, receipts of abandoned payments until their close finalizes, one exact active withdrawal authorization, its retirement deadline, and an optional verified payout claim. |
| Operator | SQLite live payments and certified close jobs, with an optional balance QMDB and two native log replicas for proofs. |
| Validator | Certified chain state; per deployment, a Current Ordered MMB balance QMDB, cumulative activity and payout MMRs, and a local compact keyless QMDB for checkpoints and saved votes. |

Validators derive all three commitments from the same dealing before voting.
The terminal requires at least three signatures from its four-validator committee
for close admission and local recovery, matching the settlement consensus quorum.
This stronger policy preserves a unique certified close across retired admission records.
The clearing primitive permits a minimum of `f + 1` signatures for embeddings that
authenticate the exact onchain close throughout recovery.
The three protocol databases become durable before the local QMDB records their
checkpoint and the validator's vote in Commit metadata. Native pruning makes that
record durable and bounds its history before the vote is sent. The local decision
survives rollback of the protocol databases and is never part of their certified
roots or imported from another validator.

Each payout has a sparse native log position; commit markers are never payouts.
The chain retains the current finalized activity and payout heads and ordered claimed ranges
whose values are only their end positions. Finalization inserts each trailing commit marker as
claimed, and a successful payout inserts its position while merging adjacent ranges. A
zero-valued output still consumes its position.

Wallets authenticate the current payout head and claimed-range result under the same
certified block. Range absence is not issuance: the wallet also verifies the exact payout
opening against that head through the operator or configured holders. Proposers verify the
opening against the latest finalized head again when finalization advances before execution.
The exact active authorization remains independent of the cached payout claim.
The claim retains its native position across proof replacement and restart. After a deployment fault, finalized payouts remain claimable without a
new vote, alongside deposit refunds and recovery from the frozen balance root.

Validators prune native history behind the current challenge and recovery boundaries.
Run a validator with `--retain-native-history` to keep older native operations for
proof serving through its ordinary query endpoint. Longer retention is a local
choice. An offline replica does not delay other validators' pruning. Wallets
request payout proofs only from their operator and the genesis validators, so
claim payouts promptly (see [Getting your money out](#getting-your-money-out)).
Adjacent claimed positions coalesce, so fully settled history and intervening commit markers
collapse into one range; fragmented claims still require proportional range state. Each finalization
retires the admission and anchor two epochs back. The chain keeps the two latest
finalized descriptors and the live pending suffix, and validators keep the
activity rows of both finalized closes. A wallet that returns after an epoch's
successor finalizes can therefore still decide the payments it signed in both
epochs. The bound is fixed. A wallet away until
the epoch after that finalizes decides a payment only through its saved
receipts. Without them the payment stays undecided and blocks the wallet's
later payments and `w` for good. `f` still signs a Close of the whole balance.
The fixed admission and challenge windows bound the pending suffix.
Proof servers walk retained native rows and payment entries for activity proofs,
and native payout outputs for claims under the current finalized payout head.
Public Commit operations carry no metadata. Unavailable operations make reads
retryable rather than proving absence. Native transaction and deposit idempotency
records are retained for replay protection.

Run `terminal-operator --node-dir <operator-directory> --no-proof-replica` to
accept payments, propose closes, and accept certificates without constructing any
operator native trees or creating `operator.sqlite.qmdb`. Proof RPCs then report
unavailability, and wallets use the configured holders. The default enables this
best-effort replica; its certified replay precedes onchain admission.

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
      |-- operator.sqlite.qmdb/ optional balance, activity, and payout replicas
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
keys stored in plaintext. Chain followers retain block history; native balance and
log replicas can recover from authenticated checkpoints and prune history older than
their protected boundaries. Each epoch supports up to 1,024 payment entries and
1,024 withdrawals, touching at most 4,096 accounts. The deployment supports up to
1,024 deposit IDs over its lifetime.
