# commonware-log

[![Crates.io](https://img.shields.io/crates/v/commonware-log.svg)](https://crates.io/crates/commonware-log)

Commit to a secret log and agree to its hash.

# Usage (Run at Least 3 to Make Progress)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

## Participant 0 (Bootstrapper)

```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/0
```

## Participant 1

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/1
```

## Participant 2

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/2
```

## Participant 3

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/3
```
