# commonware-reshare

[![Crates.io](https://img.shields.io/crates/v/commonware-reshare.svg)](https://crates.io/crates/commonware-reshare)

Reshare a threshold secret over an epoched log.

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
