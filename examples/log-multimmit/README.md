# commonware-log-multimmit

[![Crates.io](https://img.shields.io/crates/v/commonware-log-multimmit.svg)](https://crates.io/crates/commonware-log-multimmit)

Commit to a secret log across concurrent producer chains with Multimmit.

This is [commonware-log](../log) rebuilt on `commonware_consensus::multimmit`. In Simplex one
leader per view proposes one payload, so the log advances one block at a time. In Multimmit each
configured producer owns a chain and appends to it without waiting for a turn. Consensus agrees on
canonical transaction-block header digests and authenticates sparse ordering checkpoints;
Multimmit marshal retains complete blocks and reconstructs the dense application stream.

The terminal UI uses one screen:

- **Node status**: whether the local engine is responsive, the age of its last inspection, and the
  machine's view, finality floor, artifact cache, outbox, and outstanding jobs.
- **Producer chain tips**: every configured producer's finalized, DA-certified, and locally known
  height. A dynamically scaled trailing histogram shows the locally known progress
  beyond finality, and the local chain is bold when this validator is a producer.
- **Total order**: marshal's bounded, scrolling stream of densely ordered finalized blocks. Each
  row shows the marshal-local output index, producer chain, producer height, and full block digest,
  with the newest delivery at the top.

Press the arrows to scroll the total order and `esc` to quit.

# Key Material

Multimmit uses one ordinary BLS12-381 roster plus two independent threshold sharings, one for data
availability and one for nullification. This example derives all of it deterministically from the
participant list so every node computes the same committee with no setup. A real deployment runs a
distributed key generation instead and never shares private material.

The automaton constructs a configurable number of deterministic junk bytes in a background task,
wraps them in the canonical transaction block, stages it with marshal, and returns the body digest
to consensus. Consensus may prepare subsequent blocks while marshal coalesces durability, but it
cannot sign a prepared header until the exact block is crash-recoverable. Relay broadcasts the
block through `commonware-broadcast` only after that custody fence. A validator subscribes to an
exact remote block and makes it durable before reporting successful verification; accepted
data-availability evidence activates `commonware-resolver` backfill if buffered broadcast missed
it. Set the body size with `--body-size` (1 KiB by default).

Consensus reports authenticated activity to marshal on a best-effort basis. Marshal archives the
finalized LQCs and complete producer blocks, reconstructs their dense offset-major order, and sends
the resulting stream to an application reporter. In terminal mode the reporter retains compact
coordinates and digests for the total-order pane, then acknowledges every `Exact`; headless mode
acknowledges without retaining the stream.

# Usage (Run at Least 6 to Make Progress)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

## All at Once

With [mprocs](https://github.com/pvolok/mprocs) installed, one command runs the whole committee,
one participant per pane:

```bash
cargo build --release
mprocs
```

Storage persists under `/tmp/commonware-log-multimmit`, so stopping and restarting a pane resumes
that node where it left off.

## One at a Time

### Participant 0 (Bootstrapper)

```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/0
```

### Participant 1

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/1
```

### Participant 2

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/2
```

### Participant 3

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/3
```

### Participant 4

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/4
```

### Participant 5

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 5@3005 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/5
```

# Remote Deployment

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
three in `us-east-1`. `--nodes` changes the committee size (six is the minimum), `--producers`
selects producer keys in chain order (and defaults to every validator), while `--bootstrappers`,
storage IOPS and throughput, marshal cache budgets, profiling, trace sampling, P2P port,
dashboard, and binary filename can also be overridden. `--body-size` controls the complete junk
payload generated for every producer block. The command creates node configs, `dashboard.json`,
and the deployer's `config.yaml`. Validator gp3 volumes default to 16,000 IOPS and 1,250 MiB/s;
the monitoring volume remains independently configurable. The command does not create cloud
resources.

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
directory as its second. See [`assets/docker`](assets/docker/README.md) for the underlying container
build.

The monitoring instance exposes Grafana only to the IP that created the deployment. Destroy the
deployment with `deployer aws destroy --config config.yaml` when it is no longer needed.
