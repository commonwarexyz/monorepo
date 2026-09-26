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
  machine's view, finality floor, artifact cache, outbox, and outstanding jobs.
- **Producer chain tips**: every configured producer's finalized, DA-certified, and locally known
  height. A dynamically scaled trailing histogram shows the locally known progress beyond
  finality, and the local chain is bold when this validator is a producer.
- **Total order**: marshal's bounded, scrolling stream of finalized blocks in delivery order. Each
  row shows the marshal-local output index, producer chain, producer height, and full block digest,
  with the newest delivery at the top.

Press the arrows to scroll the total order and `esc` to quit.

## Persistence

All consensus data is persisted to disk in the `--storage-dir` directory. If you shut down
(whether cleanly or not), consensus resumes where it left off when you restart.

## Key Material

Multimmit uses one ordinary BLS12-381 roster plus two independent threshold sharings, one for data
availability and one for nullification. This example derives all of it deterministically from the
participant list so every node computes the same committee with no setup. It takes that material
from `commonware_consensus::multimmit::mocks`, so it depends on the consensus `mocks` feature. A
real deployment runs a distributed key generation instead and never shares private material.

## Payloads

Each producer builds a configurable number of deterministic junk bytes in a background task, wraps
them in a transaction block, stages the block with marshal, and returns the body digest to
consensus. Consensus may prepare later blocks while marshal writes earlier ones, but the block must
be on disk before consensus signs it. Only then does the application broadcast the complete block
through `commonware-broadcast`. A validator verifying another producer's block waits for marshal to
receive and store it; if broadcast missed it, certified data availability triggers
`commonware-resolver` backfill. Set the body size with `--body-size` (1 KiB by default).

## Ordered Delivery

Consensus reports its activity to marshal. Marshal archives the finalized leader certificates and
complete producer blocks, orders the blocks of every chain into one sequence, and sends that
sequence to an application reporter that must acknowledge each block. In terminal mode the
reporter keeps each block's coordinates and digest for the total-order pane; headless mode
acknowledges without keeping them.

## Network

Every node runs one authenticated `commonware-p2p` network. Separate channels carry data
availability, consensus artifacts, certificates, artifact recovery, complete-block broadcast, and
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
  `progress` line per second.
- `--debug`: include debug events in headless logs.
- `--trace-endpoint <url>`: with `--headless`, export every trace to an OTLP HTTP endpoint.
- `--trace-file <path>`: without `--headless`, write the terminal UI's debug tracing events to a
  file as JSON lines.
- `--body-size <bytes>`: junk bytes in every block body (1 KiB by default).
- `--offered-bytes-per-second <rate>`: pace each producer with synthetic input arriving at this
  rate instead of building as fast as possible.
- `--production-interval-ms <ms>`: minimum time between two blocks built by one producer (zero by
  default, which builds as fast as block custody admits).
- `--pipeline-depth <blocks>`: how many blocks a producer builds above its latest DA certificate
  (32 by default).
- `--extension-bound <blocks>`: how many fresh blocks one vote extension carries per chain (16 by
  default); zero disables extensions. Leaders propose only their certified anchors, so extensions
  carry every newer block.
- `--compute-threads` and `--critical-threads`: size the bulk verification pool and the separate
  pool for signing, certificate assembly, and the verdicts a view waits on. The critical pool
  defaults to one thread per eight validators, and at least two.

The pipeline depth and extension bound are time windows in blocks: they must cover the
DA-certificate lag at the configured block rate, so smaller bodies at the same byte throughput
need proportionally larger values.

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
