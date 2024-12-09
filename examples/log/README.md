# commonware-log

[![Crates.io](https://img.shields.io/crates/v/commonware-log.svg)](https://crates.io/crates/commonware-log)

Generate secret logs and agree on their hash.

# Usage (Run at Least 3 to Make Progress)

## Participant 0 (Bootstrapper)

```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3 --storage-dir /tmp/log/0
```

## Participant 1

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3 --storage-dir /tmp/log/1
```

# Participant 2

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3 --storage-dir /tmp/log/2
```

# Participant 3

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3 --storage-dir /tmp/log/3
```