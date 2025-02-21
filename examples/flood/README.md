# commonware-flood

## Setup

```bash
cargo run --bin setup -- --peers 5 --bootstrappers 2 --regions us-west-2,us-east-1 --instance-type t2.micro --dashboard dashboard.json --output assets
```

## Build Binary

```bash
cargo install cross
```

```bash
cross build --release --bin flood --target x86_64-unknown-linux-gnu
```

## Run

```bash