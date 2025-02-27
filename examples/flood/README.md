# commonware-flood

## Setup

### Create Artifacts

```bash
cargo run --bin setup -- --peers 2 --bootstrappers 1 --regions us-west-2,us-east-1 --instance-type t4g.small --storage-size 10 --storage-class gp2 --dashboard dashboard.json --output assets
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
cd ../../deployer
cargo build --release && mv ../target/release/deployer ~/.cargo/bin/
```

## Run

### Deploy Infrastructure

```bash
cd assets
deployer ec2 create --config config.yaml
```

### Check Metrics

TODO

### Teardown Infrastructure

```bash
deployer ec2 destroy --config config.yaml
```