# Epocher

Continuously simulate epochs with a small local network.

- Each epoch is 100 blocks
- There are 10 total validators (keys 1..10); exactly 4 are active each epoch
- Active validators are chosen by shuffling the validator set using RNG seeded by the block hash of the last block of the epoch two epochs ago (epochs 1 and 2 use the genesis hash)
- Each block contains: parent digest, block height, and a random u64

## Usage

To run this example, you must first install Rust.

You can run all 10 validators either by opening multiple terminals or with a single command.

### One command (recommended)

This starts one bootstrapper (key 1 on port 3001), then launches keys 2..10 on ports 3002..3010, all in the background, and tears them down cleanly on Ctrl-C.

```bash
bash -c '
  set -euo pipefail
  trap "kill 0" EXIT INT TERM
  export RUST_LOG=info
  cargo run -p commonware-epocher --release -- --me 1@3001 &
  sleep 1
  for i in {2..10}; do
    sleep 1
    port=$((3000 + i))
    cargo run -p commonware-epocher --release -- --me ${i}@${port} --bootstrappers 1@127.0.0.1:3001 &
  done
  wait
'
```

Notes:
- Use unique ports for each node on localhost; the snippet uses 3001..3010.
- All 10 validators run continuously; only 4 are selected to participate in consensus each epoch.
- Logs will show finalized blocks (e.g., `finalized-delivered-to-app`) and epoch transitions as engines restart per-epoch.

### Manual (10 terminals)

Open ten terminals and start one bootstrapper, then nine joiners.

Validator 1 (Bootstrapper)
```bash
cargo run -p commonware-epocher --release -- --me 1@3001
```

Validator 2
```bash
cargo run -p commonware-epocher --release -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001
```

...

Validator 10
```bash
cargo run -p commonware-epocher --release -- --me 10@3010 --bootstrappers 1@127.0.0.1:3001
```

You should see logs indicating finalized blocks (e.g., `finalized-delivered-to-app`) and epoch transitions.

## Options

- `--me KEY@PORT`: required. KEY must be an integer in 1..10. Binds to `127.0.0.1:PORT` and derives the node key from `KEY`.
- `--bootstrappers KEY@HOST:PORT[,KEY@HOST:PORT...]`: optional. One or more known peers to initially connect to (use `1@127.0.0.1:3001` for local runs).

