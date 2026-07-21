# Runtime storage qualification

`volume-crash-fuzz` drives the production Tokio volume through deterministic
append, sparse-write, overwrite, resize, prune, atomic-batch, recovery-crash,
and concurrent-commit histories. It records each transaction in a stable intent
journal before mutation and records the acknowledgement only after the volume
commit returns.

The sequential oracle accepts exactly the last acknowledged state or the
single in-flight intent. The concurrent oracle derives the allowed outcomes
from six durability groups: three direct writers, a two-blob batch, a second
batch published over those same members while the first sync is pending, and a
remove/recreate batch with a sibling write. Any recovered group union is
allowed except one containing the second overlapping batch without the first.
Partial outcomes are adopted into the stable oracle before another epoch runs.
`OUTCOME` lines report the adopted mask: bits 0-2 are direct writers, bit 3 is
the first two-blob batch, bit 4 is its overlapping successor, and bit 5 is the
namespace batch. The model rejects bit 4 unless bit 3 is also set.

Before production recovery starts, `worker` and `verify` also run an independent
read-only parser over the raw volume file. It shares the CRC32C primitive but
does not call the production volume layout, decoder, recovery, paging, or read
code. It validates table semantics and non-overlapping allocations, verifies
every checksum-ref guard, scrubs every backed chunk, reconstructs partial
frontiers from their shadows, and requires production recovery to return the
same complete logical contents and floors.

Build and initialize a new qualification directory:

```sh
cargo build --release -p commonware-runtime-crash-fuzz --bin volume-crash-fuzz
target/release/volume-crash-fuzz init /qualification/volume 1 100663296
```

The journal format is `CVF2`; directories initialized by the earlier
three-blob `CVF1` harness must be reinitialized rather than silently reused.

On Linux, build with `--features iouring` to qualify the io_uring storage
backend used by that deployment.

Run a local process-kill campaign:

```sh
target/release/volume-crash-fuzz campaign /qualification/volume 1000 20 1
```

Repeatedly kill during startup and recovery, before normal mutations begin:

```sh
target/release/volume-crash-fuzz recovery-campaign /qualification/volume 1000 5 2000 2
```

This mode is most valuable after a block fault or power cut has left a commit
for recovery to repair. A clean local filesystem can still exercise repeated
startup interruption, but it cannot manufacture torn shadows or interrupted
slot-zeroing by itself.

Exercise concurrent writers, `start_sync`, sync coalescing, overlapping
batches, selective commit outcomes, and remove/recreate:

```sh
target/release/volume-crash-fuzz concurrent-campaign /qualification/volume 1000 2000 3
```

The lower-level entry points are `concurrent-worker` and `worker`. External
power controllers should kill only after `phase=concurrent-started` when they
want every modeled durability request to have been issued.

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

## Linux block-fault stack

`scripts/block-fault-stack.sh` creates a safety-limited stack using only sparse
files and loop devices:

```text
filesystem -> dm-log-writes -> dm-flakey -> loop-backed data image
                                  |
                             loop-backed write log
```

Run it only in a disposable Linux VM. It requires root, refuses physical block
devices, creates a new work directory, and leaves the images intact on
`destroy` for analysis.

```sh
sudo scripts/block-fault-stack.sh create /var/lib/volume-fault 16
# Format and mount the printed data_device, then initialize the fuzzer there.
sudo scripts/block-fault-stack.sh mark /var/lib/volume-fault initialized
```

The available modes are:

- `io-error`: fail all I/O during the down interval, including flushes.
- `error-writes`: fail writes while reads continue.
- `drop-writes`: acknowledge and silently discard writes.
- `corrupt-byte`: replace the first byte in every write bio.
- `random-corrupt`: corrupt one random byte in every write bio.
- `progress-error`: alternate one second healthy and one second failing writes.
  Large operations spanning a boundary exercise the case where earlier bios
  make progress before a later bio returns an error.

Every fault table starts with a one-second healthy interval. For a steady fault,
wait at least one second before starting the worker. For `progress-error`, start
workers throughout both halves of the cycle and retain both their exit status
and the external oracle.

An I/O or flush error is expected to make the current storage instance fatal.
Do not ask that process to verify its own state. Hard-reset the VM, restore the
loop/mapping stack in healthy mode, mount the filesystem, and run a fresh
`verify` process:

```sh
sudo scripts/block-fault-stack.sh restore /var/lib/volume-fault
sudo scripts/block-fault-stack.sh mode /var/lib/volume-fault healthy
# Mount the newly printed data_device.
COMMONWARE_VOLUME_FUZZ_ORACLE=/trusted-control/volume-oracle.journal \
  target/release/volume-crash-fuzz verify /mnt/qualification/volume
```

For dropped or corrupted writes, use a QEMU hard power cut rather than a clean
unmount. A clean unmount can write back or otherwise change the state being
tested. Keep the oracle on a separate virtual disk with a different failure
domain. After restoration, combine `recovery-campaign` with `verify` so repair
itself is repeatedly interrupted.

The dm-log-writes image records durability-ordered writes and supports marks:

```sh
sudo scripts/block-fault-stack.sh mark /var/lib/volume-fault before_epoch_42
```

The log image is provisioned at four times the data-image size, but it records
cumulative traffic rather than live data. Monitor `block-fault-stack.sh status`
and rotate evidence images before the log fills.

Use `replay-log` on copies of the data and log images to replay through each
mark, each flush/FUA boundary, and selected write prefixes. Generate additional
images that omit, reorder, or sector-split writes between durability barriers,
then boot each image and run `verify`. Never replay into the only evidence copy.
The stack captures the source trace but intentionally does not choose which
illegal device guarantees to simulate; that campaign matrix belongs in the
deployment qualification record.

QEMU's `blkdebug` layer should be a separate campaign for write and flush
failures at specific block events. `blkdebug/flush-error.conf` fails the first
host cache flush, while `blkdebug/second-write-error.conf` lets one write make
progress and fails the next. Attach either configuration in front of a raw test
image using QEMU's `blkdebug:<config>:<image>` filename syntax. Run each
deployed QEMU cache configuration, including a volatile write-back cache. An
ignore-flush or unsafe-cache configuration is a negative control: the oracle
should detect acknowledged data lost by a hard power cut, and that configuration
must not qualify.

## Barrier propagation

`scripts/trace-barriers.sh` records block request issue/completion events on a
selected leaf device while it runs one command. Pass `--storage-path` to bind
the trace to a read-only profile containing the exact kernel, filesystem, mount
options, block stack, controller and firmware identifiers, sector geometry,
and guest-visible write-cache/FUA settings. For example, run a one-epoch worker
against the mounted device and trace the underlying loop or deployment device:

```sh
sudo scripts/trace-barriers.sh /dev/loop0 /var/log/volume-barriers \
  --storage-path /mnt/qualification/volume -- \
  env COMMONWARE_VOLUME_FUZZ_ORACLE=/trusted-control/volume-oracle.journal \
  target/release/volume-crash-fuzz worker /mnt/qualification/volume 1
```

The script fails if no request carrying the block trace `F` marker reaches the
selected leaf device and preserves both the raw `trace-cmd` data and the
filtered report. It also records the shell-escaped workload, its exit status,
request counts, and SHA-256 digests for the complete evidence directory. Inspect
the report to distinguish pure flush requests from FUA writes and archive it
with the exact filesystem, mount, kernel, controller, and cache configuration.
Some drivers complete or transform flush flags above the leaf device, so a
missing leaf marker requires tracing each layer rather than assuming the
filesystem did nothing. This is supporting evidence only; it does not replace
a hard power cut.

Capture the deployment matrix without tracing or writing a workload with:

```sh
sudo scripts/capture-storage-profile.sh /path/to/storage /var/log/storage-profile
```

Treat profiles as distinct qualification cells whenever any recorded kernel,
filesystem, mount option, block-stack layer, controller/firmware, sector size,
or cache/FUA value differs. A profile identifies the cell; it does not qualify
it until the barrier trace, fault campaign, and hard-power-cut campaign all pass
on that same configuration.

The deployment matrix is the cross-product of the runtime storage backend
(`tokio` or `iouring`), the exact binary build, and each observed storage
profile. The AWS deployer can produce three storage topologies:

- The AMI root filesystem on the configured EBS volume when the instance type
  has no instance store. The filesystem and mount options come from the AMI and
  must be observed rather than inferred from the EBS class.
- One EC2 instance-store NVMe device formatted as ext4 and mounted with the
  kernel defaults.
- Multiple EC2 instance-store NVMe devices combined as md RAID0, formatted as
  ext4, and mounted with the kernel defaults.

Qualify every topology that is actually deployed for each distinct profile
digest. Record the source revision, binary SHA-256, enabled runtime features,
and profile `SHA256SUMS` digest in the matrix row. Track barrier tracing, block
faults, and hard power cuts as separate results; a row passes only when all
required campaigns pass. Configuration files establish requested EBS class and
runtime features, but they cannot substitute for the observed filesystem,
firmware, and cache behavior.

## Mutation gate

Run the implementation-level negative controls after changing commit, recovery,
or checksum paging:

```sh
runtime/qualification/scripts/mutation-gate.sh
```

The gate separately removes the commit fsync, accepts a checksum page read from
a superseded ref, and suppresses the fatal poison latch after a commit I/O
failure. Each mutated build must compile, run its targeted witness, and fail the
test. A surviving mutation fails the gate.
