# Durable validator ACK benchmark

Build the example-owned adapter with:

```sh
cargo bench --locked -p commonware-terminal --bench durable_ack --features bench --no-run --message-format=json
```

Run the emitted `durable_ack` executable directly. For example:

```sh
durable_ack --storage-directory /opt/bajillion-db \
  --accounts 1000000 --senders 1000 --recipients 512 --out-degree 1 \
  --withdrawals 0 --history 0 --samples 3 --warmup 0 \
  --runtime-workers 2 --workers 16 --benchmark-limits
```

The storage directory must be on the filesystem being measured. Each sample copies a fully
durable predecessor into a fresh, isolated directory before opening it. Copied files, nested
directories, and the containing sample directory are synchronized before measurement. The
predecessor is durable and remains page-cached. Initialization,
history, copies, and recovery checks are outside the timed interval. The private signer
decision is never reset to reuse an existing validator instance.

The adapter defaults to three samples without warmup. It uses one shared 1 GiB native cache,
4,096-byte physical pages, and 256 MiB state/activity write buffers to hold the largest
million-payer batch. Payout/private write buffers and all replay buffers are 8 MiB. The logical
page payload comes from `page_size(4096)`. Normal terminal stores use a shared 16 MiB cache and
8 MiB buffers. Public journals hold 33,554,432 operations per section and 67,108,864 Merkle
nodes per blob, about 2 GiB for the measured workload. Variable section bytes depend on record
sizes. All capacities are emitted in the metadata. Changing them requires fresh storage.

One monotonic wall interval starts with encoded posted-Dealing bytes and a prepared registered
context. It includes production decoding, validation, native batch preparation, signing,
Ballot validation, and `persist_candidate`. The latter applies and durably commits Current,
activity, and payout QMDBs before publishing the private checkpoint and Ballot QMDB. The
interval ends when that private durability barrier returns. Public store futures are polled
concurrently. Validation and all three public stores share the production adaptive Rayon
strategy, so offloaded CPU work and independent I/O can overlap. One worker pool is retained
across warmup and measured samples; its placement policy is not forced. The private metadata
QMDB retains its small sequential owner. Tokio workers and Rayon workers are recorded separately.

The adapter calls the production persistence function. It rejects a retained candidate or
Ballot at sample start, checks actual mutation/deletion counts and all three advancing
operation counts, and then reopens all four owners. Raw recovered heads and the exact encoded
private Manifest must match before application recovery can rewind anything. Fresh native
owners reopen within the sample's existing runtime, so a second runtime's startup filesystem
flush cannot intervene. Native initialization recovers derived state from the committed
journals. The runtime stops its storage work before the sample directory is deleted and the
next sample starts. Full exits must delete every live account in every sample. Native
durability gates also test that the reported wall interval includes time waiting for the
private durability barrier; reopening alone cannot establish
where the stopwatch stopped.

`--benchmark-limits` explicitly selects large local fixture contexts. Activity originals are
individually bounded native records; all three public QMDBs use metadata-free Commits.
These are local processing measurements through the production ACK owner.
The flag does not change the terminal's deployed network limits or its 8 MiB RPC frame. Without
it, fixture dimensions must fit the terminal's bootstrap and per-close limits. The shared
workload builder is exported only by the clearing crate's `bench` feature.

Output is JSONL: one `ack_metadata` record followed by `ack_sample` records, including warmups.
Each sample contains a direct `ns` duration, logical work counts, public/private hashes,
`reopen_verified`, and Linux process telemetry where available. Hashes must agree across
fixed-predecessor samples. The collector records the source and binary fingerprints, exact
SSD/filesystem configuration, CPU tick frequency, and raw samples before producing summaries.
