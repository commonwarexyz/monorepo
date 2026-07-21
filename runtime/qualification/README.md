# Runtime storage qualification

`volume-crash-fuzz` drives the production Tokio volume through deterministic
append, sparse-write, overwrite, resize, prune, and atomic-batch histories. It
records each transaction in a stable intent journal before mutation and records
the acknowledgement only after the volume commit returns. Recovery must match
the last acknowledged state or the single in-flight intent exactly.

Build and initialize a new qualification directory:

```sh
cargo build --release -p commonware-runtime-crash-fuzz --bin volume-crash-fuzz
target/release/volume-crash-fuzz init /qualification/volume 1 100663296
```

On Linux, build with `--features iouring` to qualify the io_uring storage
backend used by that deployment.

Run a local process-kill campaign:

```sh
target/release/volume-crash-fuzz campaign /qualification/volume 1000 20 1
```

SIGKILL does not discard the kernel page cache or volatile device cache. For
power-loss qualification, run `worker` on the device under test, cut VM or
machine power at the flushed `CUT` markers, and run `verify` after reboot:

```sh
target/release/volume-crash-fuzz worker /qualification/volume
target/release/volume-crash-fuzz verify /qualification/volume
```

The default oracle is `/qualification/volume/oracle.journal`. That is useful for
filesystem crash testing, but it cannot detect a device that loses both the
volume commit and its later oracle acknowledgement after reporting both flushes
successful. For controller/device-cache qualification, put the oracle on an
independent trusted failure domain and export the same full path for `init`,
`worker`, `verify`, and `campaign`:

```sh
export COMMONWARE_VOLUME_FUZZ_ORACLE=/trusted-control/volume-oracle.journal
```

Run separate campaigns for every deployed filesystem, mount/barrier mode,
kernel, controller/firmware, sector-size, and volatile-write-cache setting. A
successful local campaign is process-crash evidence, not power-loss evidence.
