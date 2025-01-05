# commonware-vrf

[![Crates.io](https://img.shields.io/crates/v/commonware-vrf.svg)](https://crates.io/crates/commonware-vrf)
[![Docs.rs](https://docs.rs/commonware-vrf/badge.svg)](https://docs.rs/commonware-vrf)

Generate bias-resistant randomness with untrusted contributors using [commonware-cryptography](https://crates.io/crates/commonware-cryptography) and [commonware-p2p](https://crates.io/crates/commonware-p2p).

# Usage (3 of 4 Threshold)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._

## Arbiter
```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3,4 --contributors 1,2,3,4
```

## Contributor 1
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
```

## Contributor 2
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
```

## Contributor 3
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
```

## Contributor 4 (Rogue)

_Send invalid shares to other contributors._

```bash
cargo run --release -- --rogue --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
```

## Contributor 4 (Lazy)

_Only send `t-1` shares._

```bash
cargo run --release -- --lazy --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
```

## Contributor 4 (Forger)

_Forge acknowledgements from contributors._

```bash
cargo run --release -- --forge --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
```