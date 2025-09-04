# Epocher

Continuously simulate epochs with a small local network.

- Each epoch is 100 blocks
- There are 10 total validators (keys 1..10); exactly 4 are active each epoch
- Active validators are chosen by shuffling the validator set using RNG seeded by the block hash of the last block of the epoch two epochs ago (epochs 1 and 2 use the genesis hash)
- Each block contains: parent digest, block height, and a random u64

## Usage

To run this example, you must first install Rust.

You can run an indexer and all 10 validators either by opening multiple terminals or with a single command.

### One command (recommended)

This starts one indexer (port 4001), one bootstrapper (key 1 on port 3001), then launches keys 2..10 on ports 3002..3010, all in the background, and tears them down cleanly on Ctrl-C.

```bash
bash -c '
  set -euo pipefail
  trap "kill 0" EXIT INT TERM
  export RUST_LOG=info
  # Start indexer
  cargo run -p commonware-epocher --release --bin commonware-epocher-indexer -- --me 1@4001 &
  # Start validators (bootstrapper + joiners) and point to indexer
  cargo run -p commonware-epocher --release --bin commonware-epocher -- --me 1@3001 --indexer http://127.0.0.1:4001 --storage-dir /tmp/commonware-epocher/1 &
  sleep 1
  for i in {2..10}; do
    sleep 1
    port=$((3000 + i))
    cargo run -p commonware-epocher --release --bin commonware-epocher -- --me ${i}@${port} --bootstrappers 1@127.0.0.1:3001 --indexer http://127.0.0.1:4001 --storage-dir /tmp/commonware-epocher/${i} &
  done
  wait
'
```

Notes:
- Use unique ports for each node on localhost; the snippet uses 3001..3010.
- All 10 validators run continuously; only 4 are selected to participate in consensus each epoch.
- Logs will show finalized blocks (e.g., `finalized-delivered-to-app`) and epoch transitions as engines restart per-epoch.

### Manual (10 terminals)

Open terminals and start one indexer, one bootstrapper, then nine joiners.

Indexer
```bash
cargo run -p commonware-epocher --release --bin commonware-epocher-indexer -- --me 1@4001
```

Validator 1 (Bootstrapper)
```bash
cargo run -p commonware-epocher --release --bin commonware-epocher -- --me 1@3001 --indexer http://127.0.0.1:4001
```

...

Validator 10
```bash
cargo run -p commonware-epocher --release --bin commonware-epocher -- --me 10@3010 --bootstrappers 1@127.0.0.1:3001 --indexer http://127.0.0.1:4001
```

You should see logs indicating finalized blocks (e.g., `finalized-delivered-to-app`) and epoch transitions.

## Options

- `--me KEY@PORT`: required. KEY must be an integer in 1..10. Binds to `127.0.0.1:PORT` and derives the node key from `KEY`.
- `--bootstrappers KEY@HOST:PORT[,KEY@HOST:PORT...]`: optional. One or more known peers to initially connect to (use `1@127.0.0.1:3001` for local runs).
 - `--indexer URL[,URL...]`: optional. One or more indexer base URLs to POST finalized `(Finalization, Block)` tuples to (e.g., `http://127.0.0.1:4001`).
 - `--storage-dir PATH`: required. Storage directory for persisting state across restarts.

### Indexer endpoints

- Start an indexer:
  ```bash
  cargo run -p commonware-epocher --release --bin commonware-epocher-indexer -- --me 1@4001
  ```
- Point validators at the indexer(s):
  ```bash
  cargo run -p commonware-epocher --release --bin commonware-epocher -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001 --indexer http://127.0.0.1:4001
  ```
- Indexer API:
  - `POST /upload` body is `(Finalization<MinSig, Sha256>, Block)` encoded as `application/octet-stream`
  - `GET /latest` returns up to two most recent finalizations by epoch

### Chaos restarts (random validator restarts)

To simulate validators independently going offline/online and catching up via marshal + poller, use the chaos runner. It keeps the indexer and bootstrap validator (key 1) running, and randomly restarts validators 2..10 with independent 0–10 minute up/down cycles.

```bash
./examples/epocher/chaos.sh
```

Notes:
- Uses ports 3001..3010 for validators and 4001 for the indexer, matching the defaults above.
- Logs will show validators rejoining and resuming epochs; finalized blocks should continue progressing.
- Stop with Ctrl-C; all child processes are cleaned up.

