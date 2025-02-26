# commonware-flood

## Setup

### Create Artifacts

```bash
cargo run --bin setup -- --peers 2 --bootstrappers 1 --regions us-west-2,us-east-1 --instance-type t4g.micro --storage-size 10 --storage-class gp2 --dashboard dashboard.json --output assets
```

### Build Flood Binary

_TODO: Docker pre-requisite._

```bash
docker build -t flood-builder .
```

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```

Emitted binary `flood` is placed in `assets`.

### Build Deployer Binary

_Done from deployer directory._

```bash
cargo build --release && mv ../target/release/commonware-deployer ~/.cargo/bin/
```

## Run

### Deploy Infrastructure

```bash
cd assets;
commonware-deployer setup --config config.yaml;
```

### Check Metrics

TODO

### Teardown Infrastructure

```bash
commonware-deployer teardown --config config.yaml --tag <tag>
```