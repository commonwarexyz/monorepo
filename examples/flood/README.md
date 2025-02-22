# commonware-flood

## Setup

```bash
cargo run --bin setup -- --peers 4 --bootstrappers 2 --regions us-west-2,us-east-1 --instance-type t4g.micro --storage-size 10 --storage-class gp2 --dashboard dashboard.json --output assets
```

## Build Binary

_TODO: Docker pre-requisite._

```bash
docker build -t flood-builder .
```

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```

Emitted binary `flood` is placed in `assets`.

## Run

```bash