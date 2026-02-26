# commonware-reshare

[![Crates.io](https://img.shields.io/crates/v/commonware-reshare.svg)](https://crates.io/crates/commonware-reshare)

Reshare a threshold secret over an epoched log.

## Overview

`commonware-reshare` demonstrates how to build an application that employs [commonware_consensus::simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html)
and [commonware_cryptography::bls12381::dkg](https://docs.rs/commonware-cryptography/latest/commonware_cryptography/bls12381/dkg/index.html)
to periodically reshare a BLS12-381 threshold secret across epochs with a dynamic validator set.

The system starts by bootstrapping consensus with Ed25519 signatures (non-threshold) and executes a distributed key
generation (DKG) protocol to establish threshold shares. Once the DKG completes, consensus transitions to BLS12-381
threshold signing. At each subsequent epoch boundary, the secret is reshared to accommodate validator set changes.

Key features:
- Two startup modes: trusted setup (pre-generated shares) or DKG (distributed share generation).
- Epoch-based consensus with dynamic dealer selection per epoch.
- Persistent DKG state via [commonware_storage](https://docs.rs/commonware-storage) journals for crash recovery.
- Byzantine fault tolerance using the Simplex consensus protocol with an N3f1 threshold.
- Authenticated peer-to-peer networking via [commonware_p2p](https://docs.rs/commonware-p2p) with 6 muxed channels for votes, certificates, resolver, broadcast, marshal, and DKG messages.

## Setup

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [`mprocs`](https://github.com/pvolok/mprocs)._

## Usage (Trusted Setup)

First, set up the network participants:

```sh
# Default configuration (4 active participants, 2 inactive participants)
cargo run --bin commonware-reshare setup

# With configuration:
cargo run --bin commonware-reshare setup [--num-peers <n>] [--num-bootstrappers <n>] [--datadir <path>] [--base-port <port>]
```

Then, run the `mprocs` command emitted by the setup procedure to start all participants simultaneously.

## Usage (DKG Setup)

First, set up the network participants:

```sh
# Default configuration (4 active participants, 2 inactive participants)
cargo run --bin commonware-reshare setup --with-dkg

# With configuration:
cargo run --bin commonware-reshare setup --with-dkg [--num-peers <n>] [--num-bootstrappers <n>] [--datadir <path>] [--base-port <port>]
```

Then, run the first `mprocs` command emitted by the setup procedure to start all participants simultaneously, kicking off the initial DKG.

Once the DKG is complete amongst all participants, shut down the participants and run the second `mprocs` command emitted by the setup procedure
to start all participants again, this time with the distributed threshold secret established.

### Troubleshooting

If you see an error like `unable to append to journal: Runtime(BlobOpenFailed("engine-consensus", "00000000000000ee", Os { code: 24, kind: Uncategorized, message: "Too many open files" }))`,
you may need to increase the maximum number of open files. You can do this by running:

```bash
ulimit -n 65536
```

_MacOS defaults to 256 open files, which is too low for the default settings (where 1 journal file is maintained per recent view)._
