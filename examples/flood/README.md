# commonware-flood

[![Crates.io](https://img.shields.io/crates/v/commonware-flood.svg)](https://crates.io/crates/commonware-flood)
[![Docs.rs](https://docs.rs/commonware-flood/badge.svg)](https://docs.rs/commonware-flood)

Flood peers [deployed to AWS EC2](https://docs.rs/commonware-deployer/latest/commonware_deployer/ec2/index.html) with
random messages.

## Setup

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [Docker](https://www.docker.com/get-started/)._

### Install `commonware-deployer`

```bash
cargo install commonware-deployer
```

### Create Deployer Artifacts

```bash
cargo run --bin setup -- --peers 3 --bootstrappers 1 --regions us-west-2,us-east-1,eu-west-1 --instance-type c7g.medium --storage-size 10 --storage-class gp3 --message-size 1024 --message-backlog 1024 --mailbox-size 16384 --dashboard dashboard.json --output assets
```

### Build Flood Binary

#### Build Cross-Platform Compiler

```bash
docker build -t flood-builder .
```

#### Compile Binary for ARM64

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```

_Emitted binary `flood` is placed in `assets`._

### Deploy Flood Binary

```bash
cd assets
deployer ec2 create --config config.yaml
```

## Check Metrics

Visit `http://<monitoring-ip>:3000`

_anonymous login is already enabled, so you don't need to enter a password_

## [Optional] Update Flood Binary

### Re-Compile Binary for ARM64

```bash
docker run -it -v ${PWD}/../..:/monorepo flood-builder
```

### Restart Flood Binary on EC2 Instances

```bash
deployer ec2 update --config config.yaml
```

## Destroy Infrastructure

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