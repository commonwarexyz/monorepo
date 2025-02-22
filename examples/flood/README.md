# commonware-flood

## Setup

```bash
cargo run --bin setup -- --peers 5 --bootstrappers 2 --regions us-west-2,us-east-1 --instance-type t2.micro --dashboard dashboard.json --output assets
```

## Build Binary

_TODO: Docker pre-requisite._

```bash
docker build -t flood-builder .
```

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```

Emitted binary is called `flood` and it is located in the same directory.

## Run

```bash