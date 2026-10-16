# commonware-log-multimmit

[![Crates.io](https://img.shields.io/crates/v/commonware-log-multimmit.svg)](https://crates.io/crates/commonware-log-multimmit)

Commit to a secret log across concurrent producer chains with Multimmit.

This is [commonware-log](https://docs.rs/commonware-log) rebuilt on
`commonware_consensus::multimmit`. In Simplex, one leader per view proposes one payload, so the
log advances one block at a time. In Multimmit, each configured producer owns a chain and appends
to it without waiting for a turn.

- Consensus agrees on block header digests and finalizes the tips of every producer chain.
- Marshal stores complete blocks, fetches missing ones from peers, and delivers every finalized
  block in one total order.
- The application builds blocks of junk bytes and checks the blocks other producers propose.
- The terminal UI shows each producer chain's progress and the total order.

## Terminal UI

The terminal UI uses one screen:

- **Node status**: whether the local engine is responsive, the age of its last inspection, and the
  machine's view, newest resolved view, artifact cache, outbox, and outstanding jobs.
- **Producer chain tips**: every configured producer's final height, the height a quorum
  endorses, and the locally accepted height. A dynamically scaled trailing histogram shows the
  accepted progress beyond finality, and the local chain is bold when this validator is a
  producer.
- **Total order**: marshal's bounded, scrolling stream of finalized blocks in delivery order. Each
  row shows the marshal-local output index, producer chain, producer height, and full block digest,
  with the newest delivery at the top.

Press the arrows to scroll the total order and `esc` to quit.

## Persistence

All consensus data is persisted to disk in the `--storage-dir` directory. If you shut down
(whether cleanly or not), consensus resumes where it left off when you restart.

## Key Material

Multimmit uses one ordinary BLS12-381 key per validator, checked by proof of possession and
aggregated into certificates. This example derives every key deterministically from the participant
list so every node computes the same committee with no setup. It takes that material
from `commonware_consensus::multimmit::mocks`, so it depends on the consensus `mocks` feature. A
real deployment runs a distributed key generation instead and never shares private material.

## Payloads

Consensus asks each producer for its next block once every production interval. The producer
builds deterministic junk bytes in a background task, wraps them in a transaction block,
stages the block with marshal, and returns the body digest to consensus. Without offered load
every block carries a full body. With `--offered-bytes-per-second`, input is cut into batches of
exactly one body, each submitted when its last byte arrives; each block carries the oldest
submitted batch, and a producer with none queued builds an empty block, which still takes a
height. Latency samples start at a batch's submission, so every sample stands for one full batch
of transactions. Consensus builds
later blocks while marshal writes earlier ones, but each block must be on disk before consensus
signs it. Only then does the application broadcast the complete block
through `commonware-broadcast`. A validator verifying another producer's block waits for marshal to
receive and store it. A validator that accepts a block on its endorsers' word without verifying it
lets marshal fetch the body through `commonware-resolver` backfill before delivery. Set the body
size with `--body-size` (1 KiB by default).

## Ordered Delivery

Consensus reports its agreement to marshal: each view's final chain tips and the leader
certificates that pin them. Marshal archives those certificates and complete producer blocks,
orders the blocks of every chain into one sequence, and sends that
sequence to an application reporter that must acknowledge each block. In terminal mode the
reporter keeps each block's coordinates and digest for the total-order pane; headless mode
acknowledges without keeping them.

## Network

Every node runs one authenticated `commonware-p2p` network. Separate channels carry producer
headers, leader proposals and vote updates, certificates, artifact recovery, complete-block broadcast, and
body backfill. Each channel has its own quota; all channels share each peer's priority queues and
TCP connection. Blocking a peer disconnects all its channels.

## Usage (Run at Least 6 to Make Progress)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

### All at Once

With [mprocs](https://github.com/pvolok/mprocs) installed, one command runs the whole committee,
one participant per pane:

```bash
cargo build --release
mprocs
```

Storage persists under `/tmp/commonware-log-multimmit`, so stopping and restarting a pane resumes
that node where it left off.

### One at a Time

#### Participant 0 (Bootstrapper)

```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/0
```

#### Participant 1

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/1
```

#### Participant 2

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/2
```

#### Participant 3

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/3
```

#### Participant 4

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/4
```

#### Participant 5

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 5@3005 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/5
```

Participant keys are labels: each node's committee material comes from its key's position in
`--participants`, so the keys only need to be unique. `--producers` lists producer keys in chain
order and defaults to every participant.

## Options

`--help` lists every option. The ones that change behavior most:

- `--headless`: run without the terminal UI and emit structured JSON logs, including one
  `progress` line per second. Besides chain heights it reports the measured delay and
  production interval (`delta_hat_ms`, `theta_hat_ms`), how many views ended on count, at
  `t_max`, or by another declaration, their mean length since startup (`mean_view_ms`) and
  over the last second (`view_ms_interval`), the chains each declaration rule declared
  (including the split rule), and this producer's mean build-to-signature and
  build-to-ordered-delivery latencies. With offered load it also reports, for this producer's
  batches, the mean time from header signature to first finality and to ordered delivery
  (`signed_to_final_ms`, `signed_to_ordered_ms`), the share final within
  `2 * delta_hat + eta` of signing (`final_within_goal_pct`), the share final in the view their
  block was signed in (`final_in_signing_view_pct`), and the mean views they waited
  (`views_waited_x100`, in hundredths of a view). The full field list is documented on
  `progress::Summary::log`.
- `--debug`: include debug events in headless logs.
- `--trace-endpoint <url>`: with `--headless`, export every trace to an OTLP HTTP endpoint.
- `--trace-file <path>`: without `--headless`, write the terminal UI's debug tracing events to a
  file as JSON lines.
- `--body-size <bytes>`: junk bytes in every block body (1 KiB by default).
- `--offered-bytes-per-second <rate>`: pace each producer with synthetic input arriving at this
  rate instead of filling every block.
- `--window-cap <blocks>`: the window `N`: how many blocks of a chain one view finalizes (12 by
  default; the flow bound is `6N`).
- `--compute-threads` and `--critical-threads`: size the bulk verification pool and the separate
  pool for signing, certificate assembly, and the verdicts a view waits on. The critical pool
  defaults to one thread per eight validators, and at least two.

Consensus asks for one block every `theta`, which it derives from the measured one-way delay
`delta_hat`: `max(3 delta_hat / N, (2 delta_hat + eta) / (N - 1))`, and no slower than the chains it
measures. A block carries whatever input has arrived, possibly none: every chain, idle or loaded,
fills its window in about three one-way delays, the length of a view's leader round.

## Remote Deployment

Generate a six-node AWS bundle with the bundled Grafana dashboard:

```bash
cargo run --release -- deploy \
  --output-dir deploy \
  --producers 0,1 \
  --regions us-west-2,us-east-1 \
  --instance-type c8g.xlarge \
  --monitoring-instance-type c8g.4xlarge \
  --storage-size 50 \
  --monitoring-storage-size 75 \
  --worker-threads 2 \
  --compute-threads 2 \
  --body-size 1048576
```

The six nodes are assigned round-robin across the two regions, placing three in `us-west-2` and
three in `us-east-1`. `deploy` accepts the node options above and writes them into every node's
configuration. `--nodes` changes the committee size (six is the minimum), `--producers` selects
producer keys in chain order (and defaults to every validator), while `--bootstrappers`, storage
IOPS and throughput, marshal cache budgets, profiling, trace sampling, the P2P port (`--port`),
dashboard, and binary filename can also be overridden. The generated `config.yaml` opens that port
in the validator security group. The command creates node configs, `dashboard.json`, and the
deployer's `config.yaml`. Validator gp3 volumes default to 16,000 IOPS and 1,250 MiB/s; the
monitoring volume remains independently configurable. The command does not create cloud resources.

For 512 KiB throughput runs on 64 GiB validators, an 8 GiB live cache retains roughly 16,000
blocks while a 2 GiB materialized cache bounds cold delivery and promotion work independently:

```bash
--marshal-live-cache-bytes 8589934592 \
--marshal-materialized-cache-bytes 2147483648
```

Build the stripped Linux/ARM64 binary and its matching profiling symbols directly into the
generated bundle, then create the deployment:

```bash
just build
cd deploy
deployer aws create --config config.yaml
```

The build also writes `deploy/commonware-log-multimmit-debug`. Keep that unstripped binary locally
and use it to symbolize an on-demand profile from any deployed validator:

```bash
cd deploy
deployer aws profile \
  --config config.yaml \
  --instance 0 \
  --binary commonware-log-multimmit-debug
```

The build recipe accepts an alternate Docker platform as its first argument and deployment
directory as its second. See
[`assets/docker`](https://github.com/commonwarexyz/monorepo/tree/main/examples/log-multimmit/assets/docker)
for the underlying container build.

The monitoring instance exposes Grafana only to the IP that created the deployment. Destroy the
deployment with `deployer aws destroy --config config.yaml` when it is no longer needed.
