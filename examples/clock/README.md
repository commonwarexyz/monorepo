# commonware-clock 

[![Crates.io](https://img.shields.io/crates/v/commonware-clock.svg)](https://crates.io/crates/commonware-clock)

TBD

# Usage (3 of 4 Threshold)

```bash
cargo run --release -- --me 0@3000 --participants 0,1,2,3
```

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3
```

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3
```

```bash
cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3
```