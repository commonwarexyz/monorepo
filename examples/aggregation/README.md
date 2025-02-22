# commonware-aggregation

Aggregate signatures from multiple contributors over the BN254 curve.

# Usage (3 of 4 Threshold)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._

## Orchestrator
```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3,4 --contributors 1,2,3,4
```

## Contributor 1
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
```

## Contributor 2
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
```

## Contributor 3
```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
```

## Contributor 4

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --orchestrator 0 --contributors 1,2,3,4
```