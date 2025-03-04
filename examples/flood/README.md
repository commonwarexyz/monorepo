# commonware-flood

## Setup

### Create Artifacts

```bash
cargo run --bin setup -- --peers 3 --bootstrappers 1 --regions us-west-2,us-east-1,eu-west-1 --instance-type c7g.large --storage-size 10 --storage-class gp3 --message-size 1024 --message-backlog 1024 --mailbox-size 1024 --dashboard dashboard.json --output assets
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

Visit `http://<monitoring-ip>:3000` (anonymous login is already enabled, so you don't need to enter a password)

### [Optional] Update Flood Binary

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```


```bash
deployer ec2 update --config config.yaml
```

### Teardown Infrastructure

```bash
deployer ec2 destroy --config config.yaml
```

## Debugging

### EC2 Throttling

```bash
ethtool -S ens5 | grep "allowance"
```

If throttled, you'll see a non-zero value for some item:
```txt
bw_in_allowance_exceeded: 0
bw_out_allowance_exceeded: 14368
pps_allowance_exceeded: 0
conntrack_allowance_exceeded: 0
linklocal_allowance_exceeded: 0
```