# Runtime fuzz harness: storage differential, storage faults, iobuf and shared reads

Status: `storage_differential`, `iobuf` and `storage_faults` are implemented in
`runtime/fuzz/fuzz_targets/storage_differential.rs`, `runtime/fuzz/fuzz_targets/iobuf.rs` and
`runtime/fuzz/fuzz_targets/storage_faults.rs`. Divergences found so far are in
`runtime/fuzz/FINDINGS.md`. `storage_faults` is specified in
[Target `storage_faults`](#target-storage_faults); its input is the intents file
`runtime/fuzz/INTENTS-storage-faults.md`. `shared_reads` is specified in
[Target `shared_reads`](#target-shared_reads); its input is the intents file
`runtime/fuzz/INTENTS-shared-reads.md`.

## Goals

The runtime crate ships three implementations of one trait set (`runtime/src/lib.rs`):
`deterministic` (memory storage, simulated network), `tokio` (filesystem storage, TCP), and
`iouring` (Linux only). Every existing fuzz target in the workspace runs on `deterministic`,
while production binaries (`examples/`) run on `tokio`. Code that passes on the deterministic
runtime can therefore still misbehave on the runtime that ships.

This iteration adds two targets that aim at low-hanging bugs:

- `storage_differential`: run one sequence of `Storage`/`Blob` operations on the deterministic
  runtime and on the tokio runtime, judge each run against a contract model, and compare the
  two runs with each other.
- `iobuf`: drive `IoBufMut`, `IoBuf`, `IoBufs`, `IoBufsMut` and `Builder` against a `Vec<u8>`
  model. This is the densest `unsafe` code in the crate (`runtime/src/iobuf/`) and has no fuzzer.

The next iteration adds a third target, for faults and recovery (Future work rows 5 and 6):

- `storage_faults`: run one sequence of `Storage`/`Blob` operations on the deterministic runtime
  only, with injected operation failures and simulated crashes, and judge every run against a
  model of the public `Storage` and `Blob` contract. Its goals are SF-G1 to SF-G4 in
  [Target `storage_faults`](#target-storage_faults).

A fourth target is for the concurrent readers of the page cache (Future work rows 4 and 20):

- `shared_reads`: several readers on the deterministic runtime read one sealed paged blob
  through one small shared cache, while `MigratingReadBlob` keeps each backend read in flight
  for one poll, so that readers join the page reads of others and some cancel a pending read.
  Its goals are SR-G1 to SR-G3 in [Target `shared_reads`](#target-shared_reads).

## Non-goals for this iteration

- The `iouring` runtime, its storage and network, and its internal state machines.
- The network traits (`Network`, `Listener`, `Sink`, `Stream`).
- Oracles for the existing paged-buffer targets (`buffer`, `blob_integrity`).
- Any change under `runtime/src`, including `cfg(fuzzing)` hooks. Every target uses public API
  only.
- Fault and crash testing on tokio. `storage_faults` runs the deterministic runtime only.
- Concurrency in storage, and crashes inside an operation. The operations of
  `storage_differential` and `storage_faults` are sequential, and a crash happens between two
  operations. The one exception is `shared_reads`: concurrent readers of the page cache over one
  immutable blob, with no write and no crash (SR-X1 to SR-X3). History: until 2026-11-24 this
  item excluded all concurrency in storage; the concurrent readers of the page cache were Future
  work rows 4 and 20.
- A strict mode that disables the allowlist of `storage_differential`.

Every choice that narrows coverage is listed, with a way to lift it, in [Future work](#future-work).

## Placement and build

All four targets live in `runtime/fuzz` next to `buffer`, `blob_integrity` and `blob_creation`.

slow.yml fuzzes every `runtime/fuzz` target whose `required-features` are on by default
(`.github/scripts/fuzz_targets.py`). The new targets run on fuzzcorp only, so each is gated by a
non-default feature:

```toml
[features]
default = []
storage-differential = []
storage-faults = []
shared-reads = []
iobuf = []
runtime-all = [ "iobuf", "shared-reads", "storage-differential", "storage-faults" ]

[[bin]]
name = "storage_differential"
path = "fuzz_targets/storage_differential.rs"
required-features = ["storage-differential"]
test = false
doc = false

[[bin]]
name = "storage_faults"
path = "fuzz_targets/storage_faults.rs"
required-features = ["storage-faults"]
test = false
doc = false
bench = false

[[bin]]
name = "shared_reads"
path = "fuzz_targets/shared_reads.rs"
required-features = ["shared-reads"]
test = false
doc = false
bench = false

[[bin]]
name = "iobuf"
path = "fuzz_targets/iobuf.rs"
required-features = ["iobuf"]
test = false
doc = false
```

The `shared-reads` feature and the `shared_reads` entry are added when the target is built.

Build and run (toolchain pin read from `nightly` under `[tools]` in `.github/toolchains.toml`,
currently `nightly-2026-11-12`):

```bash
cargo +nightly-2026-11-12 fuzz build --fuzz-dir runtime/fuzz --features runtime-all
cargo +nightly-2026-11-12 fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_differential
cargo +nightly-2026-11-12 fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_faults
cargo +nightly-2026-11-12 fuzz run --fuzz-dir runtime/fuzz --features runtime-all shared_reads
cargo +nightly-2026-11-12 fuzz run --fuzz-dir runtime/fuzz --features runtime-all iobuf
```

A build without features must keep producing only the three existing targets.

Environment:

- `COMMONWARE_RUNTIME_FUZZ_DIR` (optional): base directory for tokio storage. Defaults to
  `std::env::temp_dir()`. Point it at a disk-backed filesystem on Linux to reach the O_DIRECT,
  native AIO and `RWF_DONTCACHE` paths, which fall back silently on filesystems that reject them.
  Keep the base path short, under about 450 characters. The longest names the harness treats as
  valid on tokio (a 255-character partition plus the 254-character hex form of a 127-byte name)
  produce paths of about 540 characters below the base. A longer base pushes them past the
  platform's path limit (1024 on macOS), and the oracle then reports those opens as failures.
  The harness also assumes the usual 255-byte limit per path component. A filesystem with a
  smaller limit (eCryptfs allows 143) gives the same false reports for the long-but-valid names.

`storage_faults` and `shared_reads` use no environment variable and no file system.

Platforms: all four targets build and smoke-run on macOS. Campaigns run on Linux through fuzzcorp,
deployed by the maintainer. Hangs are left to libFuzzer's `-timeout`.

## Shared input decoding

Both targets decode their input with the scheme of `glue/fuzz/fuzz_targets/transfers_invariants.rs`,
with a fixed-size stream (see below), so that libFuzzer's short early inputs still produce whole
operation sequences:

1. The first `SEED_BYTES` of the input seed a `FuzzRng` that fills a fixed-size stream.
2. The rest of the input overwrites the stream from its start.
3. The stream's tail becomes an `Entropy` for
   `deterministic::Config::new().with_rng(FuzzRng::from(entropy))`.
4. The operation sequence is sampled from the remaining stream with `Unstructured`.

The stream is always `STREAM_BYTES` long: input past it is ignored, so the entropy always comes
from the same stream bytes. Both targets share this decoder (`decode` in `runtime/fuzz/src/lib.rs`).
`storage_faults` uses the same decoder, unchanged. So does `shared_reads` (SR-R5).

Both targets run under `deterministic::Runner`. The tokio side of `storage_differential` uses no
RNG: everything it does comes from the decoded sequence.

## Target `storage_differential`

### Execution

The decoded sequence is split at its `Restart` operations into sessions. Each session is one
runner start on each backend.

1. Deterministic run. The first session uses `deterministic::Runner::new(cfg)`. Every later
   session uses `deterministic::Runner::from(checkpoint)`, where `checkpoint` comes from the
   previous session's `start_and_recover`. The checkpoint keeps only what the memory storage made
   durable.
2. Tokio run. Each input gets a fresh directory `<base>/commonware_runtime_fuzz_<pid>_<counter>`; the
   harness removes any stale one and tokio creates it. Each session starts a new `tokio::Runner` on
   that directory, configured with:
   - `with_storage_directory(dir)`
   - `with_storage_blob_layouts(range)`, where `range` is chosen per session (see `Restart`)
   - `with_worker_threads(1)`
   - `with_catch_panics(false)`

   After the last session the directory is removed, before any oracle failure is reported.
   Campaigns run with `-fork` and `-ignore_crashes`, so keeping the directory of every failing
   input would leave one directory per finding. The failure report prints the full operation trace
   instead. A panic raised while a backend is running unwinds past the cleanup and leaves its
   directory behind.
3. Each run records a trace: one observation per operation (the `Ok` value or the `Err`).
4. Each trace is checked against its own model, then the two traces are compared.

Operations within a session are sequential: each is awaited before the next starts. All open
handles are dropped before a session's root task returns, so no blob outlives its runner (a
leaked tokio blob keeps the directory's `flock` hold and blocks the next start).

### Operation set

At most 64 operations per input. Handles live in 4 slots. An operation that names an empty slot
is skipped on both backends. A slot can be open on one backend and empty on the other (for
example after a layout mismatch on tokio only). Such an operation then runs only where the slot
is open, and is not compared across backends.

| Operation | Parameters | Call |
|---|---|---|
| `Open` | slot, partition, name, version range `lo..=hi` with `lo <= hi` drawn from `{0, 1, 2}` | `open_versioned` |
| `Write` | slot, offset, chunk lengths (1 to 4 chunks), `SYNC`, `DONT_CACHE` | `write_at` |
| `ReadAt` | slot, offset, len, `DONT_CACHE` | `read_at` |
| `ReadAtBuf` | slot, offset, len, extra capacity, chunk shape | `read_at_buf` (capacity always at least `len`) |
| `ReadMany` | slot, up to 8 ranges, `DONT_CACHE` | `read_many`, collected |
| `StartReadMany` | slot, up to 8 ranges, await or drop the handle | `start_read_many` |
| `Resize` | slot, len | `resize` |
| `Sync` | slot | `sync` |
| `StartSync` | slot, await or drop the handle | `start_sync` |
| `Remove` | partition, optional name | `remove` |
| `Scan` | partition | `scan` |
| `Drop` | slot | drop the handle |
| `Restart` | layout range for the next tokio session: `V0`, `V1` or `V0..=V1` (the first session accepts `BlobLayout::ALL`) | end the session |

`Open` on a slot that is already open first drops the old handle. A second `Open` of a blob whose
handle is still alive in another slot is how `BlobAlreadyOpen` is reached.

Written bytes are a function of the operation index and the byte position, never zero. That way
a read can tell data apart from zero fill, and each write's bytes apart from every other write's.

`BlobLayout::V0` is `#[deprecated]`, so the code that names it needs `#[allow(deprecated)]`.

Excluded because the contract forbids them:

- `read_at_buf` with buffer capacity below `len` (documented panic).
- Empty version ranges (`versions` must be non-empty).
- Partition names that differ only by letter case (`runtime/src/lib.rs`, `Storage`
  "Partition Names": "partition names that differ only by letter case must not both be used").

### Names

- Partitions: `p0`, `p1`. Edge partitions: the empty string, `a/b` (invalid character), a
  255-character name, a 256-character name.
- Blob names: `a`, `b`. Edge names: the empty name, a 127-byte name, a 128-byte name, the
  non-UTF-8 name `[0xff, 0x00]`.

Most draws come from the plain pool so that operations collide on the same blobs. Edge names are
expected to diverge quickly. For example, tokio maps a name to `hex(name)` as a filename, so names
over 127 bytes exceed the 255-byte filename limit while memory accepts them.

### Sizes

- `Write`, `Resize` and the offset of an empty `Write`: offsets up to 1 MiB, biased toward 0,
  4095, 4096, 4097 and the slot's current size plus or minus a few bytes.
- Lengths: up to 64 KiB, biased toward 0, 1, 4095, 4096 and 4097.
- Reads may also use overflow-edge offsets: `u64::MAX`, `i64::MAX`, `i64::MAX - 4096` and
  `i64::MAX - 8`, with lengths of 16 bytes or less. These reach the checked-arithmetic paths
  without allocating.

Memory storage allocates up to `offset + len` on writes and resizes, and every read allocates
`len` before any check. The caps keep allocation aborts from being reported as bugs.

### Faults

None. The deterministic storage fault configuration stays at its default (no faults), and tokio
has no fault hooks.

### Model

Each backend gets its own model. They are driven by the same operation stream, but may legitimately
drift apart after a reopen or restart. A model tracks, for each blob identity (partition, name,
and a generation that increments when the blob is removed):

- `len`: the exact logical size while a handle is open.
- `bytes[i]`: either `Known(v)` or `Unknown`.
- `stable`: byte ranges known to be durable, meaning covered by a completed `sync` or `SYNC` write
  and not mutated since.
- `synced_len`: `Some(n)` when no size-changing operation has run since the last completed
  `sync`, otherwise `None`. `size_candidates` is the set of sizes the blob held since that sync,
  including the synced size.
- The blob version and, on the tokio side, the layout recorded at creation.

Update rules:

- `Write`: the written range becomes `Known`. It is removed from `stable` unless the write is
  `SYNC`, in which case it is added to `stable`. Growth extends `len` and sets `synced_len` to
  `None`.
- `Resize`: shrinking drops the bytes past the new length. Growing appends `Known(0)` bytes. Either
  sets `synced_len` to `None` and adds the new size to `size_candidates`.
- `Sync` (awaited) and an awaited `StartSync` handle: every byte becomes stable and
  `synced_len = Some(len)`. A dropped `StartSync` handle changes nothing in the model.
- `Drop` followed by `Open`, and `Restart` followed by `Open`: the contract allows unsynced changes
  to be lost or torn. If `synced_len` is `Some(n)`, the reopened size must be `n`. Otherwise it
  must lie between the minimum and maximum of `size_candidates`. The model then adopts the
  observed size. Bytes inside `stable` and below that size stay `Known`; every other byte becomes
  `Unknown`. All bytes below the observed size are now durable, because data readable when a reopen
  returns is crash-durable (`Storage` "Durability").
- A successful read adopts durable bytes whose value the model does not know yet. Each backend
  adopts into its own model, and only under these conditions:
  - the read is on a checked blob, through a handle whose blob has not been removed and whose layout
    is known;
  - the returned length of the range matches the request;
  - the byte is durable but `Unknown`, which is only true for bytes first exposed by a reopen;
  - the byte lies inside the model's length.

  The read records the byte's value, and the byte becomes `Known` and stays durable. A later read,
  reopen or restart is then judged against it. A write or resize clears the durable mark, so an
  adopted value can never go stale. Bytes exposed by a reopen and not read before the next restart
  stay `Unknown`.
- `Remove`: the identity is unlinked. Handles opened before the removal keep reading the removed
  blob's contents (documented). A mutation through such a handle is unspecified, so the handle is
  marked unchecked and later results through it are not asserted.
- `Open` of a missing blob creates it with version `hi` and, on tokio, the session's latest layout.
  The trait docs do not say which version a new blob gets. The harness asserts `hi` because the
  shared header code picks `versions.end()` (`runtime/src/storage/header.rs`), so this checks
  implementation behaviour.
  An existing blob opens with its recorded version.
- A failed `Write`, `Resize`, `Sync` or awaited `StartSync` marks the blob unchecked: its later
  results are not asserted and not compared.

Uncertain names: each backend's model keeps a set of names whose creation failed with an
undocumented error. Such a failure may still have left state behind: a partition directory, or in
principle a header with any version or layout. On tokio this is reachable only through the RF-3
edge names; the blob-level cases need fault injection. For an uncertain name:

- The next `Open` skips the new-blob check, adopts the version it returns, and leaves the layout
  unknown, so no layout outcome is predicted. That open is not compared across backends.
- `Scan` of a partition holding uncertain names must return every modeled name and may return
  extra names only from that partition's uncertain set. Such a scan is not compared across
  backends.
- `Remove` of an uncertain name, or of a partition holding one, is not compared across backends.
- A successful `Open` or `Remove` resolves the name, and strict checking resumes. A blob adopted by
  that `Open` keeps an unknown layout until it is removed, so its later opens are still not
  compared and its bytes are not adopted. This case needs fault injection to reach.

### Oracle

A target fails on:

1. Any panic, abort or sanitizer report.
2. A model violation on either backend:
   - A read returns bytes that differ from `Known` model bytes.
   - A successful read returns a range whose length differs from the requested length. This is
     checked even on unchecked blobs.
   - A read inside `len` fails, or a read past `len` succeeds (zero-length reads excepted; see
     below).
   - A reopened size falls outside the allowed range. A reopen also returns a version other than the
     recorded one, or a new blob does not open with size 0 and version `hi`.
   - `scan` disagrees with the set of live identities in the partition (compared as sets), or the
     scan of an existing partition fails.
   - A documented error is missing or replaced:
     - `BlobAlreadyOpen` for a second open while a handle is alive and the blob has not been
       removed since.
     - `BlobVersionMismatch` when the recorded version is outside `lo..=hi`.
     - `PartitionNameInvalid` for a partition with characters outside `[A-Za-z0-9_-]` or an empty
       partition.
     - On tokio only, `BlobLayoutMismatch` when the recorded layout is outside the session's range.
   - A documented error is returned although the model rules out its precondition, for example
     `BlobVersionMismatch` for a new blob or an in-range recorded version, or `BlobAlreadyOpen`
     for a blob that is not open.
   - An operation the model expects to succeed fails with an undocumented error:
     - an `Open` of a valid partition and a name that is neither uncertain nor an unchecked blob.
       On tokio, names past its filesystem limits are exempt and handled as uncertain: a partition
       over 255 characters, the empty name, and a name over 127 bytes (the RF-3 classes);
     - a `Write`, `Resize`, `Sync` or awaited `StartSync` through a live, checked handle of a blob
       that has not been removed;
     - a `Remove` of a target the model holds (a current name, or an existing partition when no name
       is given) in a valid partition with no uncertain names.

     Faults are off and sizes are capped, so no such failure is expected. A full disk would show up
     here as an environment failure.
   - `read_at_buf` does not return the caller's buffers: the total capacity of the nonzero input
     chunks, single-chunk shape, readable chunk lengths and each chunk's start address must match.
     The front-to-back filling of chunks is implementation behaviour (`IoBufsMut::set_len`).
   - `read_many` yields a range twice, yields an out-of-range index, or ends without an error while
     ranges are missing. `start_read_many` returns a different number of buffers than ranges.
3. A cross-backend mismatch:
   - Blob operations. When both models hold the same `len` for the blob and the slot is open on both
     backends, the operation must succeed on both or fail on both. Its returned bytes must be equal
     wherever both models hold `Known` bytes. In practice the byte part never fires on its own:
     a byte both models know is already judged by each backend's model, so this rule adds the
     Ok/Err agreement.
   - Namespace operations (`Open`, `Remove`, `Scan`). When both models hold the same state for the
     operation, it must succeed on both or fail on both. For `Open` that state is the existing
     blob's version and whether it is open. For `Remove` it is whether the partition and the name
     exist. For `Scan` it is the partition's set of names. These operations are not compared while
     a name involved is uncertain, or when a tokio layout mismatch is predicted or possible. This
     is the rule behind the RF-3 reports.

Behaviour the contract permits is not reported:

- Unsynced data visible on one backend and lost on the other after a reopen or restart.
- `scan` order.
- Mutations of removed blobs.
- Different error variants when both backends fail where the model allows failure, for example
  `Io(UnexpectedEof)` on tokio against `BlobInsufficientLength` on memory for the same
  out-of-bounds read.
- Errors through unchecked blobs and uncertain names (see the Model section).
- `BlobLayoutMismatch` on tokio while memory opens the same blob, when the session's layout range
  predicts it. Memory reads every layout by design.

Zero-length reads past the end of a blob have no specified outcome. They are judged only by the
cross-backend Ok/Err rule, which is how such divergences surface (RF-1, now allowlisted; see
"Allowlist").

An empty write is a no-op in the model. `write_at` writes "every remaining byte in `bufs`", and the
shared conformance suite asserts that an empty `SYNC` write does not extend the blob, so a backend
whose blob grows from an empty write is reported as a model violation (RF-2, now allowlisted for
the deterministic backend; see "Allowlist").

A failure panics with the operation index, the operation, both observations and the relevant model
state.

### Failure classes

Each failure panics from a `#[cold] #[inline(never)]` function named after its class, and its
message starts with the same `[class]` tag, so stack-based and message-based crash dedup put
different classes in different buckets. The earliest failing op decides the class. Within that op,
deterministic model violations come first, then tokio model violations, then the cross-backend
mismatch, and the first line gives the class. The class depends only on which check fired and on
the op kind, never on data. Every class reports the same "panicked at" source location (the macro
that generates the functions), so dedup must key on the top function frame or on the tag, not on
the location alone.

| Class | Meaning |
|---|---|
| `cross_backend_open` | An open's Ok/Err differs across backends (RF-3, now allowlisted) |
| `cross_backend_remove` | A remove's Ok/Err differs |
| `cross_backend_scan` | A scan's Ok/Err differs |
| `cross_backend_read` | A read's Ok/Err, or bytes both models know, differ (RF-1, now allowlisted) |
| `cross_backend_mutation` | A write, resize, sync or `start_sync`'s Ok/Err differs |
| `model_read_bytes` | A read returned bytes that differ from known model bytes |
| `model_read_len` | A read succeeded past the size, failed inside it, or returned the wrong length (RF-2, now allowlisted) |
| `model_read_many` | `read_many` or `start_read_many` did not yield each range exactly once |
| `model_layout` | `read_at_buf` did not return the caller's buffers with their layout |
| `model_open_error` | An open failed or succeeded against the model's prediction |
| `model_reopen` | A reopen returned a size or version the model rules out (RF-2 after a sync, now allowlisted) |
| `model_create` | A creation returned a size or version other than a new blob's |
| `model_scan` | A scan disagreed with the model |
| `model_remove` | A remove disagreed with the model |
| `model_mutation_failed` | A mutation through a live, checked handle failed |
| `allowlist_stale` | A backend no longer shows an allowlisted divergence, so its issue may be fixed and the entry should be removed |

### Allowlist

`runtime/src` cannot be changed, so a confirmed divergence would fail every run and hide new
findings. Each divergence the maintainer confirms gets a narrow, named entry in the `ALLOWLIST`
`const` in `storage_differential.rs`. Entries are added only with the maintainer's approval. Each
one carries its name, the upstream issue, the operation, the trigger and the modeled behaviour, and
refers to its entry in `runtime/fuzz/FINDINGS.md`. Remove an entry once its issue is fixed.

An entry names one operation kind and the condition that triggers the divergence. Divergences that
change state surface at later operations, not at their trigger. So an entry does not just accept
one pair of outcomes; from the trigger onward, it switches the affected backend's model to the
behaviour the maintainer confirmed. When no exact model behaviour can be stated, the entry marks the
affected blob or partition unchecked and uncompared from the trigger onward. This is weaker, and
the entry says so.

Current entries, all reported in https://github.com/commonwarexyz/monorepo/issues/5752:

| Entry | Operation | Trigger | Modeled behaviour |
|---|---|---|---|
| RF-1 | `read_at`, `read_at_buf`, `read_many`, `start_read_many` | a zero-length range starts past the end of the blob | tokio `Ok` against memory `Err(BlobInsufficientLength)` is accepted; neither model judges the range |
| RF-2 | `write_at` | an empty non-`SYNC` write starts past the end of the blob | the deterministic model grows the blob to the offset with known zero bytes |
| RF-3 | `open` | a partition over 255 characters, an empty name, or a name over 127 bytes | the tokio model expects `PartitionCreationFailed` (long partition) or `BlobOpenFailed` (name), and for a name over 127 bytes records the partition directory the failed open created; these opens are not compared |

When #5752 is fixed upstream, the entries do not fail silently:

- **RF-1:** memory succeeding on a trigger read is reported as `allowlist_stale`, naming the entry.
  tokio failing on one is tolerated as agreement.
- **RF-3:** tokio succeeding, or failing with a different error, is reported as `allowlist_stale`.
  So is memory rejecting such a name.
- **RF-2:** the fix only shows at a later read or reopen of the grown blob, so it cannot be detected
  exactly. Every violation on an affected blob says that the blob is affected by allowlist entry
  RF-2 (#5752).

### Divergences expected from code reading

These were seen while reading the code, before the targets existed. The first three are now
confirmed as RF-2, RF-1 and RF-3 in `runtime/fuzz/FINDINGS.md`. The fourth is never reported, because
both outcomes are errors:

- `write_at(offset, empty)` without `SYNC` grows a memory blob to `offset`
  (`runtime/src/storage/memory/mod.rs`, `Blob::write_at`). On tokio it is a no-op
  (`runtime/src/storage/tokio/blob.rs`, the empty-write early return in `Blob::write_at`).
- A zero-length read past the end succeeds on tokio (`tokio/blob.rs`, the zero-length early
  return in `Blob::read_at_buf`) and fails with
  `BlobInsufficientLength` on memory.
- An empty blob name, a blob name over 127 bytes, and a partition over 255 characters fail to open
  on tokio (filesystem limits) and succeed on memory. A failed tokio open has already created the
  partition directory, so a later `scan` returns `Ok([])` instead of an error.
- `remove(partition, Some(name))` on a missing partition fails with `PartitionMissing` on memory and
  `BlobMissing` on tokio. Both are errors, so this is not reported unless one side succeeds.

## Target `storage_faults`

Status: built. The input is `runtime/fuzz/INTENTS-storage-faults.md`. A number in
square brackets, such as [11], names the intent a rule comes from. Ids in this part: `SF-G` goals,
`SF-R` requirements, `SF-I` invariants, `SF-X` exceptions to API coverage, `SF-C` choices this
spec makes where the intents file leaves one open.

No rule waits for a decision. The two questions the first draft raised were decided on
2026-11-18, and intents 13 and 17 hold the answers: a failed fused write has two kinds (SF-R16,
SF-R17), and the trigger of RF-2 is a named coverage exception (SF-X5).

### Definitions

| Term | Meaning |
|---|---|
| Session | One start of a `deterministic::Runner`. The first session starts from a `deterministic::Config`, every later one from the checkpoint of the session before it |
| Crash | The end of a session that another session follows. The root task returns with every handle dropped, `start_and_recover` returns the checkpoint, and the next session starts with `deterministic::Runner::from(checkpoint)`. The runtime decides at this point what happens to every unsynced mutation (`runtime/src/deterministic.rs`, `Runner::run`, the storage `crash()` call at the end of a session) |
| Baseline operation | One of the four fixed operations every run starts with (SF-R3) |
| Input operation | An operation decoded from the fuzz input |
| Verification operation | An open, read or scan that the oracle issues by itself, to learn the state. It is never decoded from the input |
| Armed | An input operation is armed when the input gives it a fault (SF-R6) |
| Fault window | The time during which the storage fault configuration differs from `FaultConfig::default()`. It covers exactly one armed input operation |
| Injected failure | `Err(Error::Io(_))` returned by an armed input operation |
| Image | A length and that many bytes |
| Blob generation | One life of a (partition, name) pair: from the open that creates the blob to the remove that unlinks it. A name that is created again starts a new generation |
| View | The image that reads through one handle must return |
| Base | The image of a blob generation at its last durability cut |
| Log | The mutations issued to a blob generation since its last durability cut, in issue order |
| Durability cut | An event after which the base equals the view and the log is empty |
| Reachable image | An image in `Reach_crash` or `Reach_reopen` of a base and a log (see Model) |
| Seam | The point where the harness receives the `Storage` it drives (SF-R20). A negative control plants its fault there |

### Goals

- **SF-G1.** Find faults-and-recovery bugs in the runtime's own storage contract: what `Storage`
  and `Blob` promise when operations fail and when the process crashes, with no consumer on top
  [1, 3].
- **SF-G2.** Cover every public deterministic `Storage` and `Blob` entry point, both sync styles,
  and all seven fault kinds of the deterministic fault injection, in one run that combines
  failures and crashes [4, 5].
- **SF-G3.** Every failure replays: a fixed input gives the same run every time [20].
- **SF-G4.** A run is short enough for FuzzCorp: 50 ms per input as a measured target [21].

### Execution

- **SF-R1.** The target MUST run on the deterministic runtime only. It MUST use public API only
  and MUST NOT change anything under `runtime/src` [2, 18].
- **SF-R2.** Session 0 MUST start from
  `deterministic::Config::new().with_rng(FuzzRng::from(entropy))` with
  `with_storage_fault_config(FaultConfig::default())`, where `entropy` comes from the shared
  decoder. Faults MUST be armed through `Context::storage_fault_config()`
  (`runtime/src/deterministic.rs`, `Context::storage_fault_config`) and MUST NOT be set in the
  start configuration.
- **SF-R3.** A run MUST be, in this order:
  1. The four baseline operations, unarmed: `Open` slot 0 on partition `p0`, name `a`, versions
     `0..=0`; `Write` slot 0, offset 0, `BASELINE_LEN` = 64 bytes in one chunk, no `SYNC`;
     `ReadAt` slot 0, offset 0, 64 bytes; `Sync` slot 0. They MUST be judged like every other
     operation. Slot 0 stays open for the input operations.
  2. The input operations, in order. A `Crash` operation is a crash. At most
     `MAX_EXTRA_CRASHES` = 3 `Crash` operations take effect; a later one MUST be skipped.
  3. The mandatory crash, after the last input operation.
  4. The final check: the recovery verification (SF-R10) of the last session. Then the run ends.

  So a run has between 2 and 5 sessions and between 1 and 4 crashes [8]. A session that follows a
  crash MUST start with the recovery verification. Its input operations MAY be armed again [8].
- **SF-R4.** Operations MUST be sequential: each call MUST be awaited to its result before the
  next one starts. A crash MUST happen only between two operations [7]. All handles MUST be
  dropped before the root task of a session returns.
- **SF-R5.** The empty input (no bytes) MUST decode to no input operation. Its run is the four
  baseline operations, the mandatory crash and the final check, with no armed operation and no
  fault window. This is the full no-fault cycle: open, write, read, sync, crash and restart, scan,
  reopen and read [10]. Every other input, also one shorter than `SEED_BYTES`, MUST decode
  through the shared decoder to at least one input operation and run a whole run: the input adds
  operations and fault windows on top of the same cycle [10]. The baseline operations come first,
  so no input gives a run without operations.

### Operation set

No input operation for the empty input, and between 1 and `MAX_OPS` = 48 input operations for
every other input (SF-R5). Handles live in `SLOTS` = 4 slots, each
held in an `Arc`, so every blob call goes through the `Arc<B>` forwarding implementation
(`runtime/src/lib.rs`, `impl<B: Blob> Blob for Arc<B>`). An operation that names an empty slot is
skipped. `Open` on an occupied slot first drops the old handle, also when the open then fails.

| Operation | Parameters | Call | Fault it may carry |
|---|---|---|---|
| `Open` | slot, partition, name, version range `lo..=hi` with `lo <= hi` drawn from `{0, 1, 2}` | `open_versioned` | open |
| `OpenDefault` | slot, partition, name | `open` | open |
| `Write` | slot, offset, 1 to 4 chunks with a total of 0 to `MAX_WRITE` bytes, `SYNC`, `DONT_CACHE` | `write_at` | write; sync (only with `SYNC`) |
| `ReadAt` | slot, offset, len, `DONT_CACHE` | `read_at` | read |
| `ReadAtBuf` | slot, offset, len, extra capacity, chunk shape | `read_at_buf` (capacity always at least `len`) | read |
| `ReadMany` | slot, 1 to `MAX_RANGES` ranges, `DONT_CACHE` | `read_many`, collected | read |
| `StartReadMany` | slot, 1 to `MAX_RANGES` ranges, await or drop the handle | `start_read_many` | read |
| `Resize` | slot, len | `resize` | resize |
| `Sync` | slot | `sync` | sync |
| `StartSync` | slot, await or drop the handle | `start_sync` | sync |
| `Remove` | partition, optional name | `remove` | remove |
| `Scan` | partition | `scan` | scan |
| `Drop` | slot | drop the handle | none |
| `Crash` | none | end the session (SF-R3) | none |

Written bytes come from the shared `value(index, position)`: a function of the operation's index
in the run (baseline operations count) and the byte position, never zero.

- **SF-R30.** The bytes of a failing write MUST differ from the view. For a `Write` that carries
  a write fault with `failure_rate` 1, the byte submitted at each position below the view length
  MUST differ from the view's byte there: where `value(index, position)` equals the view's byte,
  the harness MUST submit `value(index, position) % 255 + 1` instead, which is also never zero.
  So after the failure the positions that changed are exactly the positions the injector kept
  (SF-R16).

### Names

- Partitions: `p0`, `p1`. Edge partitions, 1 draw in 16: the empty string and `a/b`. Both are
  invalid: an open, remove or scan on them must fail (SF-I3c to SF-I3e).
- Blob names: `a`, `b`, `c`.

At most 6 blobs are live at one time.

### Sizes

All bounds are constants at the top of the harness. None depends on time [21].

| Constant | Value | Bounds |
|---|---|---|
| `MAX_OPS` | 48 | input operations per input (0 for the empty input, else 1 to 48) |
| `MAX_EXTRA_CRASHES` | 3 | `Crash` operations that take effect, on top of the mandatory crash |
| `SLOTS` | 4 | open handles |
| `MAX_OFFSET` | 2048 | offset of a `Write` |
| `MAX_WRITE` | 256 | total bytes of a `Write` |
| `MAX_SIZE` | 2304 (`MAX_OFFSET + MAX_WRITE`) | length of a `Resize`, and so the length of every blob |
| `MAX_READ` | 512 | `len` of a read or of one range |
| `MAX_RANGES` | 4 | ranges of `ReadMany` and `StartReadMany` |
| `BASELINE_LEN` | 64 | bytes of the baseline write |

- Offsets and lengths are biased toward 0, 1, the bound, and the slot's current view length plus
  or minus a few bytes.
- Read offsets go up to `MAX_SIZE + 8`. Reads may also use the overflow-edge offsets `u64::MAX`,
  `i64::MAX` and `i64::MAX - 8` with a length of 1 to 16 bytes. These must fail.
- An empty `Write` without `SYNC` has its offset lowered to the view length when it is larger, so
  it never starts past the end of the blob (SF-X5) [17].

The bounds follow from the 50 ms target. They are derived, and how they are checked, in
[Run time](#run-time).

### Faults

- **SF-R6.** A fault is one of the values below. Just before an armed input operation the harness
  MUST write the fault into the configuration returned by `Context::storage_fault_config()`.
  When the operation has returned, the harness MUST write `FaultConfig::default()` back. No other
  code MAY change the configuration [9].

  | Fault | Configuration | Carried by |
  |---|---|---|
  | open | `open_rate` = 1 | `Open`, `OpenDefault` |
  | read | `read_rate` = 1 | `ReadAt`, `ReadAtBuf`, `ReadMany`, `StartReadMany` |
  | sync | `sync_rate` = 1 | `Sync`, `StartSync`, and a `Write` with `SYNC` |
  | remove | `remove_rate` = 1 | `Remove` |
  | scan | `scan_rate` = 1 | `Scan` |
  | write | `write_rate = WriteConfig { failure_rate, retention_rate, mode }` with `failure_rate` 0 or 1, `retention_rate` one of 0, 25, 50, 75, 100 percent, `mode` `Prefix` or `Subset` | `Write` |
  | resize | `resize_rate = ResizeConfig { failure_rate, partial_rate }` with `failure_rate` 50 or 100 percent and `partial_rate` 0, 50 or 100 percent | `Resize` |

  A `Write` with `SYNC` MAY carry a write fault, a sync fault, or both.
- **SF-R7.** The harness MUST treat a write fault with `failure_rate` 0 as the crash policy of a
  write that succeeds, not as a failure. The backend keeps bytes of an unsynced write at a crash
  only when the write was issued under a `WriteConfig` with a retention rate above zero
  (`runtime/src/storage/faulty.rs`, `Oracle::check_write_fault` and the pending-write selection
  in `Blob::write_at`), so this fault lets the write be torn at a later crash. The same holds for
  the resize fault at 50 percent: the resize may succeed, and a success may be kept at a later
  crash (`faulty.rs`, `Oracle::check_resize_fault`).
- **SF-R8.** Decoding MUST keep the success path common: an operation that may carry a fault MUST
  carry one in 1 draw of 4, and a `Write` that carries a write fault MUST have `failure_rate` 1
  in 1 draw of 2. The two draws MUST be made by two public samplers of the library module
  (SF-R19), in the style of the samplers of `storage_differential`, so that a test can call them
  with fixed bytes:
  - `sample_armed(u: &mut Unstructured<'_>) -> arbitrary::Result<bool>` MUST draw one selector
    with `u.int_in_range(0..=3)`, MUST make no other draw, and MUST return `true` exactly when
    the selector is 3. The decoder MUST call it once for every decoded operation that may carry
    a fault (the column "Carried by" of SF-R6), and the operation MUST carry a fault exactly
    when it returns `true`.
  - `sample_write_fails(u: &mut Unstructured<'_>) -> arbitrary::Result<bool>` MUST draw one
    selector with `u.int_in_range(0..=1)`, MUST make no other draw, and MUST return `true`
    exactly when the selector is 1. The decoder MUST call it once for every `Write` that carries
    a write fault, and that fault MUST have `failure_rate` 1 exactly when it returns `true`, and
    0 otherwise.

  The decoder MUST NOT decide either point in any other way. Fixed bytes: on
  `Unstructured::new(&[b])`, `sample_armed` returns `false` for `b` = 0, 1 and 2 and `true` for
  `b` = 3; `sample_write_fails` returns `false` for `b` = 0 and `true` for `b` = 1; each call
  reads the one byte. On `Unstructured::new(&[])` both return `false`, so a decoder that ran out
  of bytes arms nothing. This follows from `Unstructured::int_in_range` of `arbitrary` 1.4.2:
  for these ranges it reads one byte and reduces it modulo the size of the range, and with no
  byte left it gives the start of the range.

  History: this spec was accepted on 2026-11-18 with the two rates only. The samplers and
  their fixed bytes were added the same day, because no fixed input could be written for the
  two rates from the spec text alone. The rates did not change, and nothing that
  was detected before is lost (SF-C11).
- **SF-R9.** Every verification operation MUST run while the configuration equals
  `FaultConfig::default()`. The configuration MUST also equal the default at every crash, so
  every session starts without faults (the checkpoint carries the configuration,
  `runtime/src/deterministic.rs`, `Runner::run`, where `storage_fault_cfg` is read at the crash)
  [9].
- **SF-R10.** Recovery verification. At the start of every session after a crash, before any
  input operation, the oracle MUST:
  1. scan `p0` and `p1`. For a partition the model holds, the scan must succeed and return
     exactly the model's live names of that partition, each once. For a partition the model does
     not hold, the scan may fail; when it succeeds it must return no name (all SF-I14b);
  2. open every live name with `open_versioned(partition, name, 0..=2)`, in the order of
     (partition, name). The open must succeed (SF-I14b). The checks after an open of SF-R11 run.
     The image must be in `Reach_crash` of the generation's base and log; SF-R13a names the
     invariant when it is not (SF-I7 to SF-I11, SF-I13). Then the base becomes that image, the
     log becomes empty, the history of SF-R13a is dropped, and the handle is dropped.
- **SF-R11.** Verification reads, and their bounds. A verification read MUST NOT be longer than
  `MAX_SIZE` and MUST NOT start past `MAX_SIZE`. A size or length that the storage reports MUST
  NOT be used for a read, a conversion or an allocation before it was checked against
  `MAX_SIZE`. The oracle MUST learn a blob's state in these three ways, and SF-R31 says which
  invariant each difference names:
  1. Checks after an open, for every successful open (baseline, input or verification) with
     returned size `n`, in this order: the version (SF-I3f for a new blob, SF-I3g for an existing
     one); `n` is at most `MAX_SIZE`, else the run fails at once, before any read (SF-I18a); a
     1-byte read at `n` fails and, when `n > 0`, a 1-byte read at `n - 1` succeeds (SF-I18b); for
     a new blob, `n` is 0 (SF-I3h); for an existing blob with `n > 0`, one read of `n` bytes at 0
     succeeds (SF-I18b) and gives the image (SF-I12 in a session, SF-R10 at recovery).
  2. Length search, after an injected failure of a `Write` to the range `o..o+k` or of a `Resize`
     from `a` to `b`. Let `u` be the larger of the old length and `o + k`, or the larger of `a`
     and `b`; `u` is at most `MAX_SIZE`. A 1-byte read at `u` must fail. Then a binary search
     over `0..=u` with 1-byte reads finds the length (a 1-byte read at `x` succeeds exactly when
     `x` is below the length). The search MUST NOT use more than 12 reads. Then one read gives
     the whole blob. So this check costs at most 14 reads.
  3. Unchanged check, after an injected failure of a `Sync`, an awaited `StartSync` or a read
     operation: a 1-byte read at the view length must fail, a 1-byte read just below it must
     succeed, and one read of the whole view must return it. After an injected failure of an
     `Open`, `Remove` or `Scan` on a valid partition the oracle MUST scan that partition
     instead; the scan follows the rules of SF-R10 item 1.

### Model

The model is the public contract of `Storage` and `Blob` (`runtime/src/lib.rs`, the `Storage` and
`Blob` traits), with the failure and crash rules of the intents on top. It holds:

- which partitions exist, and the live names of each;
- for each blob generation: its version, its base, its log, and whether it was removed; and,
  only to name a violated invariant, its history (SF-R13a);
- for each open handle: its generation, its view, and whether it is still checked.

A live generation has at most one open handle (`Storage::open_versioned`, "Uniqueness"). The
namespace part and the view transitions come from the shared model (SF-R21). The base, the log and
the two reach sets are added by this target [19].

#### Log entries and reach sets

| Entry | Recorded for | Replay |
|---|---|---|
| `Torn(offset, bytes)` | a successful `Write` without `SYNC`; a fused `Write` that failed by a sync fault (SF-R17) | any subset of the bytes is written, from none to all |
| `Kept(offset, bytes, mask)` | a successful `Write` with `SYNC`, where the mask marks every byte; a `Write` that failed by a write fault, as one entry for the whole write, where the mask marks the positions that changed (SF-R16) | every marked byte is written |
| `MaybeResize(len)` | a successful `Resize` | applied or skipped |
| `ForcedResize(len)` | the intermediate length of a failed `Resize` (SF-R18) | applied |

Replay rules:

- Writing a set of bytes at their positions: when the highest written position is at or past the
  end of the image, the image grows to that position plus one. Every position that enters the
  image without being written is zero.
- A resize cuts the image to `len`, or extends it to `len` with zeros.

A write or a resize adds at most one entry to a log, whatever its fault and its result.

`Reach_crash(base, log)` is the set of images that replaying the whole log over the base can give,
entry by entry in issue order, over every combination of choices [11]. `Reach_reopen(base, log)`
is the same set with one more freedom: each `ForcedResize` may also be skipped (SF-C4). So
`Reach_crash` is a subset of `Reach_reopen`.

- **SF-R12.** The oracle MUST NOT use the retention rate or mode of a write to narrow the set. An
  image MUST be accepted exactly when it is in the reach set [11].
- **SF-R13.** The membership test MUST be exact: it MUST accept every image in the set and reject
  every other image. It MUST be a public function of the library (SF-R19), and the regression
  suite checks it against a brute-force enumeration (SF-R23). Its input is bounded by the sizes
  above; its cost per call depends on the algorithm, which this spec leaves open (Run time). A
  note on one algorithm, not a rule: for a fixed sequence of lengths after each entry, the positions
  are independent, so a search over (entry, length) pairs with a check per position is enough.
- **SF-R13a.** Naming the invariant a crash image breaks. The model MUST keep a history for each
  generation: every base and log that a durability cut closed since the generation was created
  or last recovered, with the kind of the cut (sync or reopen), and for each `Kept` entry whether
  a failed write or a `SYNC` write made it. The history is used only here. When the image found
  by the recovery verification is not in `Reach_crash(base, log)`, the run MUST fail, and the
  violated invariant MUST be the first of these that explains the image. Each step keeps the
  relaxations of the steps before it:
  1. SF-I10, when the image is reachable once every `ForcedResize` may also be skipped;
  2. SF-I9, when it is reachable once every `Kept` entry of a failed write replays as `Torn`;
  3. SF-I8, when it is reachable once every `Kept` entry of a `SYNC` write replays as `Torn`;
  4. SF-I7, when it is reachable once the sync cuts after the last reopen cut (or, with no
     reopen cut, since the creation or last recovery) are undone: the replay starts from the
     base before the first of them and runs the logs they closed, then the current log;
  5. SF-I11, when it is reachable once every cut since the creation or last recovery is undone
     the same way;
  6. SF-I13 otherwise.

  The steps run only after a violation, so a correct run pays for one membership test per blob.

#### Transitions of operations that succeed

| Event | Effect on the model |
|---|---|
| `Open` or `OpenDefault` of a name that is not live | A new generation. The returned version must lie in the requested range (`0` for `OpenDefault`) and is recorded as the generation's version (SF-I3f); the contract does not say which version of the range a new blob gets. The blob must be empty (SF-I3h). Base and view empty, log empty. The partition exists from now on |
| `Open` or `OpenDefault` of a live name with no open handle (a reopen) | The returned version must be the recorded one (SF-I3g), and the returned size must be the blob's length (SF-I18). The image read after the open (SF-R11) must be in `Reach_reopen` (SF-I12). Then a durability cut: base and view become that image, the log becomes empty [12] |
| `Write`, not empty, without `SYNC` | The view takes the bytes, growing with a zero gap when needed. The log gets `Torn` |
| `Write`, not empty, with `SYNC` | The view takes the bytes. The log gets `Kept` [15] |
| `Write`, empty | Nothing |
| `Resize(len)` | The view is cut or extended with zeros. The log gets `MaybeResize(len)` |
| `Sync`; `StartSync` whose awaited handle returns `Ok`; `StartSync` that is not armed and whose handle is dropped (SF-C2) | A durability cut: the base becomes the view, the log becomes empty. This also holds after an earlier failed sync, with no rewrite [15] |
| `Drop`, and the drop done by `Open` on an occupied slot | The handle and its view are gone. Base and log stay |
| `Remove` of a name | The name is unlinked and its generation ends: base and log are dropped. Open handles of that generation stay, with their views [16] |
| `Remove` of a partition | Every name of the partition is unlinked as above, and the partition no longer exists [16] |
| `Remove` of a name or a partition the model does not hold, on a valid partition | It may succeed or fail: the contract promises neither. Nothing changes either way |
| `Scan` | Nothing. A scan of a valid partition the model does not hold may fail, or succeed with no name |
| Crash | For every live generation the image found by the recovery verification must be in `Reach_crash`. Then a durability cut with that image. Every handle is gone |

Reads never change the model. Their rules are SF-I1 and SF-I2.

A handle whose generation was removed stays checked for reads (SF-I15). The first mutation through
it (`Write`, `Resize`, `Sync`, `StartSync`) makes it unchecked: the contract leaves such a
mutation unspecified (`runtime/src/lib.rs`, `Storage::remove`: "Mutating a removed blob [...] is
unspecified"), so its result and every later result through
that handle are not judged, except the length of returned buffers (SF-X8).

#### Transitions of injected failures

- **SF-R14.** An armed operation that returns `Err(Error::Io(_))` MUST be treated as an injected
  failure and follow the rules below. An armed operation that returns anything else MUST be
  judged as if it were not armed (SF-C7).
- **SF-R15.** After an injected failure of `Open`, `OpenDefault`, `ReadAt`, `ReadAtBuf`,
  `ReadMany`, `StartReadMany` (awaited), `Sync`, `StartSync` (awaited), `Remove` or `Scan`, the
  oracle MUST check that nothing the storage shows has changed: no view, no length, no name and
  no partition (SF-I6) [15, 16]. The model MUST leave the base and the log as they were. For the
  base and the log this is an assumption, not a check: a failure that performs its durable effect
  and then returns the error (a sync that syncs, an open that takes its reopen cut) only removes
  crash choices, and every image it leaves is still in the reach set. The target cannot detect it
  ([Limits of the proof](#limits-of-the-proof)). An armed `StartSync` or `StartReadMany` whose
  handle is dropped MUST change nothing in the model, and for `StartSync` the model MUST NOT take
  a durability cut.
- **SF-R16.** An injected failure of a `Write` that carries a write fault with `failure_rate` 1.
  The length search and whole-blob read of SF-R11 give the new view. It MUST satisfy SF-I4a to
  SF-I4c. When at least one position changed, the whole write MUST be recorded as one
  `Kept(offset, bytes, mask)` entry whose mask marks the positions that changed: these bytes are
  durable at once and get no later keep-or-lose choice. This is the first kind of failed write
  of [13], the write fault. By SF-R30 every submitted byte differs from the byte it would
  replace, and a byte past the old end is never zero, so the changed positions are exactly the
  kept positions and no kept byte is left out of the log.
- **SF-R17.** An injected failure of a `Write` with `SYNC` that carries a sync fault and no write
  fault with `failure_rate` 1. This is the second kind of failed write of [13], the sync fault in
  a fused write: all bytes are applied, none is durable, and the caller still gets an error
  (`runtime/src/storage/faulty.rs`, the sync-fault branch of `Blob::write_at`; unit tests
  `test_faulty_storage_write_at_sync_failure_is_not_durable` and
  `test_sync_failure_journals_the_successful_inner_write` in the same file). The
  length search and whole-blob read of SF-R11 give the new view. It MUST satisfy SF-I4a to
  SF-I4c, and every byte in the write's range MUST be the submitted byte (SF-I4d). The log MUST
  get `Torn(offset, bytes)` for the whole write: these bytes may tear at a crash like an unsynced
  write. It is a failed write in the sense of [15]. The oracle checks that the bytes are applied.
  It cannot check that none is durable: a fused write that made its bytes durable and then
  returned the error leaves an image that `Torn` also allows
  ([Limits of the proof](#limits-of-the-proof)).
- **SF-R18.** An injected failure of a `Resize`. The length search and whole-blob read of SF-R11
  give the new view. It MUST satisfy SF-I5. When the length changed, the log MUST get
  `ForcedResize(new length)` [14].

### Oracle

A run fails on the first violation of an invariant below. There is no allowlist [17]:

- **SF-R22.** `storage_faults` MUST NOT have an allowlist. RF-1 to RF-3 stay in `storage_differential`
  only. Any exception needs a separate decision and a narrow entry in this spec first. The
  one decision so far is not an allowlist entry: the trigger of RF-2 is never issued (SF-X5) [17].

Behaviour that is not judged, because the contract leaves it open:

- A zero-length read that starts past the end of the blob (the trigger of RF-1).
- Results through an unchecked handle (SF-X8).
- Which error variant an operation returns when the model expects a failure, beyond the two
  documented variants of SF-I3a and SF-I3b (Future work 9).
- Whether a remove of a target the model does not hold, or a scan of a partition the model does
  not hold, succeeds or fails on a valid partition. `Storage::remove` and `Storage::scan` promise
  no error there (`runtime/src/lib.rs`, `Storage::remove` and `Storage::scan`). Only invented
  names and a changed namespace are violations.
- Which version of the requested range a new blob gets. The contract does not choose one
  (`runtime/src/lib.rs`, `Storage::open_versioned` "Versions").
- Whether an armed operation fails (SF-C7).

### Invariants

Each row is one invariant with exactly one check. Rows that share a number come from one rule and
differ by a letter; a number without a letter, such as SF-I4, means all its rows. A violation
names the row that failed (SF-R19).

- **SF-R31.** Which row a difference names. SF-I1a, SF-I1b, SF-I14a and SF-I16 MUST be measured
  at baseline and input operations only. A verification operation MUST NOT be judged by those
  rows: a difference it shows MUST name the row of the check it belongs to, as one observation of
  that check:
  1. the checks after an open (SF-R11 item 1) name, in this order, SF-I3f or SF-I3g, SF-I18a,
     SF-I18b (also when the whole-blob read fails), SF-I3h, and then SF-I12 for a reopen in a
     session or, at recovery, the crash row that SF-R13a gives;
  2. the length search and whole-blob read after an injected failed `Write` or `Resize` name the
     first row of SF-I4 or SF-I5 that the observed length and bytes break; a probe or read that
     contradicts the search (the read at the bound succeeds, the whole-blob read fails) names
     SF-I4c or SF-I5a;
  3. the unchanged check names SF-I6b or SF-I6c for any difference: a probe result, a read error
     or a byte;
  4. the scan after an injected failed open, remove or scan names SF-I6a, SF-I6d or SF-I6e for any
     difference: a scan that fails on a partition the model holds, or names that differ;
  5. the scans and opens of the recovery verification name SF-I14b: a scan that fails on a
     partition the model holds, names that differ, or a live name that does not open.
- **SF-R32.** When a row counts as measured. A row MUST enter `measured` (SF-R19) only when the
  condition of its "Measured when" cell occurred in the run and the row's check ran on it and
  passed. A run in which the condition never occurs has not measured the row, and MUST NOT count
  it as passed. In particular a recovery verification alone measures none of SF-I7 to SF-I13:
  each needs the history its cell names.

| Id | What must hold | Measured when | Source | Class |
|---|---|---|---|---|
| SF-I1a | A read through a checked handle that succeeds returns the view's bytes of its range | every unarmed baseline or input read operation through a checked handle of a live generation that succeeds | `Blob` "Concurrency" (`runtime/src/lib.rs`) | `read_bytes` |
| SF-I1b | A read of 1 byte or more through a checked handle succeeds exactly when it ends at or before the view length. A zero-length read that starts at or before the view length succeeds. A read at an overflow-edge offset fails | every unarmed baseline or input read operation through a checked handle of a live generation | `Blob::read_at`: "Read exactly `len` bytes" (`runtime/src/lib.rs`) | `read_len` |
| SF-I2a | A successful `read_at_buf` returns the caller's buffers: capacity, chunk shape and start addresses, as in `storage_differential` | every unarmed `ReadAtBuf` that succeeds | `Blob::read_at_buf` (`runtime/src/lib.rs`) | `buffer_layout` |
| SF-I2b | `read_many` yields every range index exactly once and no other index, unless it yields an error | every unarmed `ReadMany` | `Blob::read_many` (`runtime/src/lib.rs`) | `read_many` |
| SF-I2c | An awaited `start_read_many` that succeeds returns exactly one buffer per range | every unarmed `StartReadMany` whose handle is awaited and succeeds | `Blob::start_read_many` (`runtime/src/lib.rs`) | `read_many` |
| SF-I3a | An open that is valid in every other way (valid partition, recorded version inside the range) returns `BlobAlreadyOpen` while a handle of the live generation is alive | every unarmed open of a live name on a valid partition while a handle of its generation is alive and its recorded version is inside the range | `open_versioned` "Uniqueness" (`runtime/src/lib.rs`) | `open_error` |
| SF-I3b | An open of a live name whose recorded version is outside the requested range returns `BlobVersionMismatch` | every unarmed open of a live name whose recorded version is outside the requested range | `open_versioned` "Versions" (`runtime/src/lib.rs`) | `open_error` |
| SF-I3c | An open on an invalid partition fails | every unarmed open on an invalid partition | `Storage` "Partition Names" (`runtime/src/lib.rs`) | `open_error` |
| SF-I3d | A remove on an invalid partition fails | every unarmed `Remove` on an invalid partition | `Storage` "Partition Names" | `partition_name` |
| SF-I3e | A scan on an invalid partition fails | every unarmed `Scan` on an invalid partition | `Storage` "Partition Names" | `partition_name` |
| SF-I3f | A blob opened under a name that is not live gets a version inside the requested range (`0` for `OpenDefault`) | every successful open of a name that is not live | `open_versioned` "Versions" | `create` |
| SF-I3g | An open of a live name returns the version recorded when the generation was created | every successful open of a live name: a reopen in a session, and the opens of the recovery verification | `open_versioned` "Versions"; "An Ok result indicates the blob is durably created" (`runtime/src/lib.rs`, `open_versioned` "Durability") | `open_version` |
| SF-I3h | A blob opened under a name that is not live is empty, whatever an earlier generation of that name held | every successful open of a name that is not live | `Storage::remove`: a removed name opens as "a new, independent blob" (`runtime/src/lib.rs`) | `create` |
| SF-I4a | After an injected failed `Write`: every byte below the old length and outside the write's range is unchanged | every injected failed `Write`, on the length search and whole-blob read after it (SF-R11) | [13], `Blob` "Durability" (`runtime/src/lib.rs`) | `failed_write` |
| SF-I4b | After an injected failed `Write`: every byte inside the write's range is the submitted byte, or the old byte when the position is below the old length, or zero when the position is at or past the old length | every injected failed `Write`, on the same reads | [13] | `failed_write` |
| SF-I4c | After an injected failed `Write`: the length is the old length, or the highest position that holds its submitted byte plus one when that is larger; every position at or past the old length that does not hold its submitted byte is zero; the blob is never longer than the write's end or the old length | every injected failed `Write`, on the same reads | [13] | `failed_write` |
| SF-I4d | After a sync fault in a fused write (SF-R17): every byte in the write's range is the submitted byte | every injected failed fused `Write` with a sync fault (SF-R17), on the same reads | [13], second kind | `failed_write` |
| SF-I5a | After an injected failed `Resize` from length `a` to target `b`: the length is `a`, or one length strictly between `a` and `b` | every injected failed `Resize`, on the length search and whole-blob read after it (SF-R11) | [14] | `failed_resize` |
| SF-I5b | After an injected failed `Resize`: every byte below the smaller of the old and the new length is unchanged | every injected failed `Resize` where the smaller of the old and the new length is above 0 | [14] | `failed_resize` |
| SF-I5c | After an injected failed `Resize`: every byte added is zero | every injected failed `Resize` that left the blob longer than before | [14] | `failed_resize` |
| SF-I6a | An injected failure of an open changes nothing the storage shows: no name, no partition, no blob | every injected failed open on a valid partition, on the scan after it (SF-R11) | SF-C3 | `failed_op_effect` |
| SF-I6b | An injected failure of a read operation changes nothing the storage shows: the length and bytes of the view are the same | every injected failed read operation, on the unchanged check after it (SF-R11) | SF-C3 | `failed_op_effect` |
| SF-I6c | An injected failure of a `Sync` or of an awaited `StartSync` changes nothing the storage shows: the length and bytes of the view are the same. Whether it made data durable cannot be seen (SF-R15) | every injected failed `Sync` or awaited `StartSync`, on the unchanged check after it | [15], SF-C3 | `failed_op_effect` |
| SF-I6d | An injected failure of a remove changes nothing the storage shows: the names are the same | every injected failed `Remove` on a valid partition, on the scan after it | [16] | `failed_op_effect` |
| SF-I6e | An injected failure of a scan changes nothing the storage shows: the names are the same | every injected failed `Scan` on a valid partition, on the scan after it | SF-C3 | `failed_op_effect` |
| SF-I7 | A completed sync is a durability cut: everything written and resized before it survives a crash, also when an earlier sync failed | the recovery verification of a generation whose history since its creation or last recovery holds a sync cut that closed a log with at least one entry | `Blob::sync` (`runtime/src/lib.rs`), [15] | `crash_image` |
| SF-I8 | The bytes of a successful `Write` with `SYNC` survive a crash | the recovery verification of a generation whose log or history holds a `Kept` entry of a successful `SYNC` write | `WriteOptions::SYNC` (`runtime/src/lib.rs`), [15] | `crash_image` |
| SF-I9 | The bytes a `Write` left in the view after a write fault survive a crash | the recovery verification of a generation whose log or history holds a `Kept` entry of a failed write with at least one marked byte | [13], first kind | `crash_image` |
| SF-I10 | The intermediate length of a failed `Resize` is replayed at a crash | the recovery verification of a generation whose log or history holds a `ForcedResize` | [14] | `crash_image` |
| SF-I11 | A successful reopen is a durability cut: the image read after the reopen survives a later crash, and no mutation issued before the reopen can change it at that crash | the recovery verification of a generation whose history holds a reopen cut | `Storage` "Durability" (`runtime/src/lib.rs`), [12] | `crash_image` |
| SF-I12 | The image a reopen shows is in `Reach_reopen` | every successful reopen in a session of a generation whose log holds at least one entry, on the image read after it | `Blob`: "When a blob is dropped, any unsynced changes may be discarded" (`runtime/src/lib.rs`), SF-C5 | `reopen_image` |
| SF-I13 | Unsynced mutations tear only by the replay rules: an image after a crash that no undoing of SF-I7 to SF-I11 explains is a violation of this row | the recovery verification of a generation whose log holds at least one `Torn` or `MaybeResize` entry | [11], `Blob` "Durability" | `crash_image` |
| SF-I14a | A scan inside a session that succeeds returns exactly the model's live names of the partition, each once. For a partition the model does not hold it returns no name | every unarmed input `Scan` on a valid partition that succeeds | `Storage::scan` (`runtime/src/lib.rs`), [16] | `scan` |
| SF-I14b | After a crash the namespace is the model's: a scan of a partition the model holds succeeds and returns exactly its live names, each once; a scan of a partition the model does not hold fails or returns no name; every live name opens. So every blob whose open returned `Ok` exists, and no blob whose remove returned `Ok` does | the scans and opens of every recovery verification | `open_versioned` "Durability", `remove`: "An Ok result indicates the blob is durably removed" (`runtime/src/lib.rs`), [16] | `crash_namespace` |
| SF-I15 | A read through a handle opened before a remove of its blob follows SF-I1a and SF-I1b against that handle's view, unsynced bytes included | every unarmed read operation through a checked handle of a removed generation | `Storage::remove` "Read-after-remove" (`runtime/src/lib.rs`), [16] | `removed_read` |
| SF-I16a | An unarmed open on a valid partition succeeds, unless SF-I3a or SF-I3b names an error | every unarmed baseline or input open on a valid partition for which SF-I3a and SF-I3b name no error | fuzzing guide: unexpected errors panic | `unexpected_error` |
| SF-I16b | An unarmed `Write` through a checked handle of a live generation succeeds | every unarmed baseline or input `Write` through a checked handle of a live generation | same | `unexpected_error` |
| SF-I16c | An unarmed `Resize` through a checked handle of a live generation succeeds | every unarmed `Resize` through a checked handle of a live generation | same | `unexpected_error` |
| SF-I16d | An unarmed `Sync` through a checked handle of a live generation succeeds | every unarmed baseline or input `Sync` through a checked handle of a live generation | same | `unexpected_error` |
| SF-I16e | The awaited handle of an unarmed `StartSync` through a checked handle of a live generation returns `Ok` | every unarmed awaited `StartSync` through a checked handle of a live generation | same | `unexpected_error` |
| SF-I16f | An unarmed remove of a name or a partition the model holds succeeds | every unarmed `Remove` of a name or a partition the model holds | `Storage::remove` | `unexpected_error` |
| SF-I16g | An unarmed scan of a partition the model holds succeeds | every unarmed input `Scan` of a partition the model holds | `Storage::scan` | `unexpected_error` |
| SF-I17 | No panic, abort or sanitizer report | the whole run | fuzzing guide | none (the panic itself) |
| SF-I18a | The size an open returns is at most `MAX_SIZE`. The check fails before any read or allocation that uses the size | every successful open, baseline, input or verification | `open_versioned` "Returns" (`runtime/src/lib.rs`); no operation of the run makes a longer blob | `open_size` |
| SF-I18b | The size an open returns is the blob's length: a 1-byte read at the size fails, a 1-byte read just below it succeeds, and the read of the whole blob at that size succeeds | every successful open, on the two 1-byte reads and the whole-blob read after it (SF-R11) | `open_versioned` "Returns" | `open_size` |

A read inside the view that fails is SF-I1b, not SF-I16. For a handle of a removed generation it is
SF-I15.

### Failure classes

Each class panics from a `#[cold] #[inline(never)]` function named after it, and the message
starts with the same `[class]` tag, as in `storage_differential`. The first violating operation
decides the class. The class depends only on which check fired, never on data. The message gives
the invariant id, the session, the operation index, the operation with its fault, the observation
and the model state of the blob.

| Class | Meaning | Invariants |
|---|---|---|
| `read_bytes` | A read returned bytes that differ from the view | SF-I1a |
| `read_len` | A read succeeded past the view length, failed inside it, or returned the wrong length | SF-I1b |
| `read_many` | `read_many` or `start_read_many` did not yield each range exactly once | SF-I2b, SF-I2c |
| `buffer_layout` | `read_at_buf` did not return the caller's buffers | SF-I2a |
| `open_error` | An open did not return the error the model names | SF-I3a to SF-I3c |
| `partition_name` | A remove or scan on an invalid partition succeeded | SF-I3d, SF-I3e |
| `create` | A new blob had a version outside the requested range, or was not empty | SF-I3f, SF-I3h |
| `open_version` | An existing blob opened with a version other than the recorded one | SF-I3g |
| `open_size` | An open returned a size above `MAX_SIZE`, or a size that is not the blob's length | SF-I18 |
| `scan` | A scan inside a session returned names that differ from the model | SF-I14a |
| `removed_read` | A read through a handle of a removed blob disagreed with its view | SF-I15 |
| `failed_write` | An injected failed write broke SF-I4 | SF-I4 |
| `failed_resize` | An injected failed resize broke SF-I5 | SF-I5 |
| `failed_op_effect` | An injected failure that must change nothing changed something | SF-I6 |
| `reopen_image` | A reopen showed an image outside `Reach_reopen` | SF-I12 |
| `crash_image` | After a crash a blob had an image outside `Reach_crash` | SF-I7 to SF-I11, SF-I13 |
| `crash_namespace` | After a crash a scan returned names that differ from the model | SF-I14b |
| `unexpected_error` | An unarmed operation that must succeed failed | SF-I16 |

### Expected findings

Written from reading `runtime/src/storage/faulty.rs`, `runtime/src/storage/memory/mod.rs`,
`runtime/src/storage/memory/open.rs` and the storage part of `runtime/src/deterministic.rs`,
before the target exists.

No in-scope finding is expected. The reading found no place where the deterministic backend
breaks one of the invariants above. Three things look like findings and are not:

- RF-2 (#5752). Known and open, and left out of this target by SF-X5 [17].
- The planted fault of SF-R27. Deliberate, and never applied in the repository tree (SF-R28).
- A reopen that drops the intermediate length of a failed resize. Allowed by SF-C4.

If the target finds something, the most intricate code is the most likely place, though nothing
there is suspected: the bookkeeping of durable ranges over pending writes and resizes
(`faulty.rs`, `Blob::record_durable_range`), the crash replay order (`faulty.rs`, `Storage::crash`),
and the retirement of pending outcomes at remove and reopen (`faulty.rs`, `Storage::retire_names`,
`Storage::remove_retired` and `Storage::admit`).

### API coverage and its exceptions

Covered [5]: `Storage::open`, `open_versioned`, `remove` by name and by partition, `scan`;
`Blob::read_at`, `read_at_buf`, `read_many`, `start_read_many` (handle awaited and dropped),
`write_at` (with and without `SYNC` and `DONT_CACHE`, 1 to 4 chunks, empty), `resize`, `sync`,
`start_sync` (handle awaited and dropped) [6], dropped handles, the `Arc<B>` forwarding
implementation, `ReadOptions::DONT_CACHE`; on the fault side all seven rates of `FaultConfig`,
both `PartialWriteMode` values and both fields of `ResizeConfig`.

| Id | Not covered | Reason |
|---|---|---|
| SF-X1 | `read_at_buf` with buffer capacity below `len` | Documented panic (`runtime/src/lib.rs`, `Blob::read_at_buf` "Panics": "Panics if `len` exceeds the total capacity of `bufs`") |
| SF-X2 | Empty version ranges | The contract forbids them: `versions` must be non-empty (`runtime/src/lib.rs`, `Storage::open_versioned` "Versions") |
| SF-X3 | Partition names that differ only by letter case | The contract forbids using both (`runtime/src/lib.rs`, `Storage` "Partition Names") |
| SF-X4 | Dropping the future of an operation before it completes (`Storage` "Cancellation") | A crash inside an operation is out of scope [7]. Dropped `start_sync` and `start_read_many` handles are covered: they are handles, not operation futures |
| SF-X5 | An empty `write_at` without `SYNC` that starts past the end of the blob. Such a write is issued only at offsets inside the blob | A named coverage exception [17]. The call triggers RF-2 (#5752, open) on the deterministic backend alone, and with no allowlist every campaign would stop on it within seconds. `storage_differential` keeps covering it under its RF-2 entry |
| SF-X6 | `write_at` and `resize` past `MAX_SIZE`, overflow-edge offsets included | The memory backend allocates up to `offset + len` before any check, so the process would abort (Future work 7 and 8) |
| SF-X7 | A crash in the middle of an accepted `start_sync` | Not reachable: the memory backend finishes the sync before `start_sync` returns its handle (`runtime/src/storage/memory/mod.rs`, `Blob::start_sync`). A recorded limit [6] |
| SF-X8 | The results of mutations through a handle of a removed blob | The calls are issued, for SF-I17. Their results are unspecified by the contract (`runtime/src/lib.rs`, `Storage::remove`: "Mutating a removed blob [...] is unspecified") |
| SF-X9 | `Context::logical_blob` and the raw-image accessors of the memory storage | Test utilities, not part of `Storage` or `Blob`. The oracle must see only what a caller of the public contract sees |

### What the recovery targets of `storage/fuzz` do, and what this target adds

The ten targets, all in `storage/fuzz/fuzz_targets`: `archive_immutable_recovery`,
`archive_prunable_recovery`, `freezer_recovery`, `journal_contiguous_recovery`,
`journal_oversized_recovery`, `journal_segmented_variable_recovery`, `merkle_full_recovery`,
`metadata_recovery`, `qmdb_current_recovery`, `queue_recovery` [3]. Each runs one storage consumer
(an archive, a freezer, a journal, a Merkle tree, the metadata store, a QMDB, a queue) under
faults, crashes it, and checks the consumer's own recovery guarantees.

Reused from them:

- the crash recipe: `start_and_recover`, then `deterministic::Runner::from(checkpoint)`;
- arming at run time through `Context::storage_fault_config()`, and resetting it to
  `FaultConfig::default()` before every crash and before every check
  (`storage/fuzz/src/lib.rs`, `faulted_recovery`);
- a bounded chain of crash and recovery cycles (their chain is 1 to 4; ours is 1 to 4 crashes);
- a clean final check after the last crash.

Not reused: `faulted_recovery` and `recovery_fault_config` themselves. They draw the faults from
the runtime's RNG for a whole recovery attempt. This target takes each fault from the input and
arms it around one operation [9].

Checked here and by none of the ten:

- a byte-level model of raw `Storage` and `Blob` results. The ten judge decoded consumer records;
- the result of a failed write and of a failed resize, byte by byte (SF-I4, SF-I5);
- a reopen as a durability cut at the blob level (SF-I11);
- `write_at`, `resize`, `sync`, `start_sync`, `Storage::remove`, `read_many` and `read_at_buf`
  called directly. The ten reach them only through a consumer;
- `open_rate`, `read_rate` and `scan_rate`, which none of the ten ever sets.

### Shared model

- **SF-R21.** The operation vocabulary and the backend-neutral model MUST move from
  `runtime/fuzz/fuzz_targets/storage_differential.rs` into a new library module
  `runtime/fuzz/src/storage_model.rs` [19]. The boundary:

  | Moves to `storage_model` | Stays in `storage_differential.rs` |
  |---|---|
  | The operation types and their decoding: the size and count constants, `PartitionName`, `BlobName`, `Offset`, `Layouts`, `Op`, the samplers, `impl Arbitrary for Op`, `FuzzInput` and its `Arbitrary`, `value` | The fuzz entry: `fuzz` and `fuzz_target!` |
  | The model: the byte flags, `BlobModel` and its transitions (write, resize, sync, reopen, expected read), `Model` and its namespace transitions (create, close, unlink), `Kind`, `Documented`, `Expect`, `read_expect`, `runs`, `valid_partition` and the display helpers | The allowlist: `Allowed`, `RF1` to `RF3`, `ALLOWLIST`, the RF-3 helpers, and every rule that reads them. Where a moved item reads the allowlist today, the caller passes the answer in |
  | | Execution and judgement: `Backend`, `Value`, `Outcome`, `Compare`, `Record`, the failure classes, the cross-backend comparison, the report, the tokio directory handling |

  `storage_faults` MUST use the moved model with `Kind::Deterministic` for the namespace and the
  view. It has its own operation type and decoding, because its operations carry faults and its sizes
  are smaller, and it adds the base, the log and the reach sets.
- **SF-R21a.** The move MUST NOT change `storage_differential`: the same input bytes decode to
  the same operations and give the same run, so its corpus keeps its meaning [19]. The commit
  before the move is `9cfc5fb66ed0c21d340ee5d1e86f871372bcac45`, and the commit that holds the
  move is `75c3d69a694397e440524e7cac5a9725172060e4`. Five checks, all required:
  1. Decoding. For the fixed inputs of [Run time](#run-time), the `Debug` text of the decoded
     `FuzzInput` is the same before and after the move. The values from before the move are taken
     once, in a disposable worktree at the commit before the move, and pinned in a test of the
     library.
  2. An order-preserving move. After normalization (leading white space, visibility keywords,
     `use` lines, comments and blank lines removed), the old file MUST be an exact interleaving
     of the new `storage_differential.rs` and the new `storage_model.rs`: every old line has its
     place in one of the two, and each of the two keeps the old order of its lines. So a moved
     item cannot lose, gain or reorder a statement. The check is the script of V6. It reads the
     old file from the commit before the move and both new files from the commit that holds the
     move, so it gives the same result in every clone. A line that had to change is listed, in
     its old and its new form, in the script of V6, which holds the whole list. The list MUST
     hold only these lines: the allowlist note `rf2_note`, which read the allowlist and now
     takes the answer from the caller, with its callers; and the continuation lines of the
     `use` statements that changed, which the normalization does not remove. Each row names
     the file, the number of times the line occurs in it, and the line. The check MUST fail
     when a listed line occurs any other number of times in any of the three files, so one
     of two identical lines cannot be lost.
  3. The same model behaviour. For fixed sequences of model transitions, the text the model
     prints for its state (`BlobModel::summary`, `Model::partition_summary`) and the result of
     every query (`allowed_sizes`, `expected`, `read_expect`) after every step is the same before
     and after the move. The values from before the move are taken once, in the same disposable
     worktree, by a throwaway test added there to the old target file, and pinned in a test of
     the library. The sequences MUST together use every moved transition and query at least
     once, and MUST include: a resize followed by a reopen at each allowed size and at one size
     outside the range; a write, a sync, a `SYNC` write and an unsynced write followed by a
     reopen and by expected reads; and the creation of two names, a close, an unlink of one
     name, a second creation of that name, and an unlink of the partition.
  4. The same target results. The old binary, built in the disposable worktree, and the new
     binary run the fixed inputs of [Run time](#run-time). For every input both MUST end the
     same way: both pass, or both fail with the same `[class]` tag.
  5. A 10-minute smoke run of `storage_differential` from an empty corpus after the move: no
     failure class that the target did not report before.

  History: this spec was accepted on 2026-11-18 with `HEAD` as the commit before the move, the
  two new files read from the work tree, and the list of changed lines in a file outside the
  repository. That held only until the move was committed. 2026-11-22: this rule names the two
  commits, and the script of V6 reads the three files from them and holds the list. The list
  now gives each line with its file and its count: before, a listed line was dropped wherever
  it occurred, so the loss of one of two identical callers would have passed. Nothing that
  was detected before is lost. A later change to one of the two new files is not judged by
  this check.

### Library entry points and the seam

The target file `runtime/fuzz/fuzz_targets/storage_faults.rs` holds only the typed entry
`fuzz_target!(|input: FuzzInput| { fuzz(input); });`. Everything else is in the library module
`runtime/fuzz/src/storage_faults.rs` (crate `commonware-runtime-fuzz`), so that tests can call it.

- **SF-R19.** The module MUST export these items with these contracts:

  | Item | Contract |
  |---|---|
  | `FuzzInput { ops: Vec<Op>, entropy: Entropy }` | Public fields. Its hand-written `Arbitrary` uses the shared `decode`, never fails on any input length, and keeps the default `size_hint`, so the typed entry rejects no short input. For an input with no bytes, `ops` is empty and `entropy` is what the shared decoder gives for no bytes (SF-R5) |
  | `Op` and the fault types | Public, with public fields, so a test can write a run by hand. A hand-written `ops` list is taken as it is; values past the bounds of Sizes are a test error |
  | `fuzz(input: FuzzInput)` | Runs `run` with the identity seam and `Verify::Once`, and on a violation panics through the class function |
  | `run(input: &FuzzInput, seam: impl Fn(deterministic::Context) -> S, verify: Verify) -> Outcome` with `S: Storage` | Runs the whole run. It does not panic on a violation: it stops at the first one and returns it. A panic raised by the storage passes through |
  | `Outcome { trace: Trace, violation: Option<Violation>, measured: BTreeSet<Invariant> }` | `Invariant` has one value per row of the Invariants table. `Violation` holds the invariant that failed, its class, the session and the operation index. `measured` holds the invariants that count as measured by SF-R32 |
  | `Trace` | `PartialEq` and `Debug`. One record per storage call the harness made, in call order: the session, the origin (baseline, input, verification), the call with its resolved parameters, the fault written to the configuration for it, and the result (`Ok` with the size and version of an open, the bytes of a read, the sorted names of a scan; or the error variant) |
  | `Verify::{Once, Twice}` | `Twice` issues every verification operation twice in a row. It exists for SF-R25 |
  | `Entry`, `Rule::{Crash, Reopen}`, `reachable(base: &[u8], log: &[Entry], rule: Rule, image: &[u8]) -> bool` | The membership test of SF-R13 |
  | `sample_armed`, `sample_write_fails` | The two decoding samplers of SF-R8 |

- **SF-R20.** The seam. `run` MUST call `seam` once per session with that session's
  `deterministic::Context`, after it has taken the fault configuration handle from the context,
  and MUST issue every storage call of the session through the returned `Storage`. `fuzz` MUST
  pass the identity. A negative control passes a wrapper that deviates from the contract at one
  point. A wrapper MAY read and write the fault configuration for its own extra calls. `run` promises
  nothing about a seam that keeps state from one call of `run` to the next (SF-R24).

### Determinism

- **SF-R24.** For every input, two calls of `run` with the identity seam and the same `Verify`
  value MUST return equal `Outcome` values: the same operation trace, injected results, crash images
  and oracle result [20]. The same holds for a test seam when each call of `run` gets a new seam
  value, built the same way, that carries no state from an earlier call. A seam that keeps state
  from one call of `run` to the next is outside this requirement.
- **SF-R25.** Verification operations MUST NOT change the fault schedule: for every input, with
  the identity seam, `run(.., Verify::Once)` and `run(.., Verify::Twice)` MUST give the same
  records of
  baseline and input operations and the same images at every recovery verification [20]. This
  holds because verification runs under `FaultConfig::default()`, and a rate of 0 draws nothing
  from the RNG (`runtime/src/storage/faulty.rs`, the test
  `test_probability_endpoints_do_not_consume_randomness`).
- **SF-R26.** The harness MUST NOT read the wall clock or OS randomness, and no result MAY depend
  on the iteration order of a hash map or on task timing [20, 21].

### Regression suite

- **SF-R23.** The suite MUST be a set of `#[test]` functions in the `runtime/fuzz` crate, outside
  the fuzz target file. It is written from this spec, not from the target's code [23]. It MUST hold:
  1. The empty input and the 8-byte inputs of [Run time](#run-time) decode and run with no
     violation. The empty input decodes to no input operation, and its trace holds exactly these
     storage calls, in this order, every one under `FaultConfig::default()` (SF-R5). Session 0:
     the open of `p0`/`a` returning size 0 and version 0, a 1-byte read at 0 that fails, the write
     of 64 bytes at 0, the read of 64 bytes at 0, the sync. Session 1: the scan of `p0` returning
     the name `a`, the scan of `p1`, the open of `p0`/`a` with `0..=2` returning size 64 and
     version 0, a 1-byte read at 64 that fails, a 1-byte read at 63 that succeeds, and the read of
     64 bytes at 0 that returns the bytes of the baseline write.
  2. A set of fixed-input scenarios with the identity seam that return no violation and together
     list every invariant except SF-I17 in `measured`. By SF-R32 a scenario lists a row only when
     it ran the row's condition: for SF-I7 a sync after a write, for SF-I8 a successful `SYNC`
     write, for SF-I9 a failed write that kept at least one byte, for SF-I10 a failed resize with
     an intermediate length, for SF-I11 a reopen, for SF-I13 an unsynced write or resize, each
     followed by a crash. The suite MUST also check that the empty input lists none of SF-I8 to
     SF-I13 in `measured`.
  3. For every invariant, the negative control of the table below: the run returns a violation
     whose invariant is the row's id and whose class is the class of that invariant (for SF-I17:
     the panic passes through).
  4. Determinism: SF-R24 and SF-R25 over the fixed inputs and over the scenarios of item 2. For
     SF-R24 with a test seam, the test builds a new seam value for each of the two calls.
  5. The fault window: with a seam that records the fault configuration at every call, each
     record of a verification or baseline call saw `FaultConfig::default()`, and each record of
     an input call saw exactly the fault of that operation (SF-R6, SF-R9).
  6. The membership test (SF-R13), against a brute-force enumeration of all choices, for both
     rules, over two explicit finite domains. Images judged: every image of length 0 to 4 over
     the bytes 0, 1, 2, 3 and 9 (781 images). Bases: every image of length 0 to 2 over the bytes
     0 and 9 (7 bases). The entry at place `i` of a log (1, 2 or 3) writes the byte `i` at each
     of its positions.
     - Domain A: every log of 0, 1 or 2 entries from this set of 28: `Torn` with offset 0, 1 or 2
       and length 1 or 2; `Kept` with the same offsets and lengths and every non-empty mask;
       `MaybeResize` and `ForcedResize` with length 0, 1, 2, 3 or 4. That is 813 logs.
     - Domain B: every log of exactly 3 entries from this set of 14: `Torn` with offset 0 or 2
       and length 2; `Kept` with the same offsets and length and every non-empty mask;
       `MaybeResize` and `ForcedResize` with length 0, 1 or 3. That is 2744 logs.

     For every base, log and rule (11382 cases in A, 38416 in B), `reachable` MUST return true
     for exactly the images the enumeration gives, out of the 781. The domains are small on
     purpose and cover every replay rule: each entry kind; none, some and all bytes of a `Torn`;
     a partial mask; growth with a zero gap; a cut and a later extension; the order of two and of
     three entries; a forced resize under both rules.
  7. The pinned decoding and the pinned model behaviour of SF-R21a (items 1 and 3).
  8. The plant input of SF-R28 runs with no violation in the repository tree.
  9. The bytes of a failing write (SF-R30): in a scenario where `value(index, position)` of a
     failing write equals the view's byte at a position below the view length (the test finds
     such a pair of operation indexes by search), the trace shows a submitted byte that differs
     from the view's byte at every such position, and with a retention of 100 percent the model
     logs the whole write as `Kept`.
  10. Bounded reads (SF-R11): no record of any trace of this suite holds a read longer than
      `MAX_SIZE` or a read that starts past `MAX_SIZE`, the overflow-edge reads of input
      operations excepted.
  11. The samplers of SF-R8, on the fixed bytes that SF-R8 names: every selector value of both
      samplers, and the empty input.

Negative controls. "Baseline" means the state after the baseline operations: slot 0 holds `p0`/`a`
with 64 synced bytes and version 0. Each control uses the shortest input that reaches its point;
"any" means the control fires on the baseline or the final check, whatever the input operations
are. "Disarmed" means the wrapper sets `FaultConfig::default()` for its own call and restores the
configuration after. "Returns the error" means the wrapper returns the `Error::Io` of the injected
failure. A differing byte is a byte other than the one at that position.

| Invariant | Input operations after the baseline | Fault planted at the seam |
|---|---|---|
| SF-I1a | any | Every successful read result has the lowest bit of its first byte flipped |
| SF-I1b | any | Every read of 64 bytes at offset 0 returns `Error::Closed` without calling the storage |
| SF-I2a | `ReadAtBuf` slot 0, offset 0, 16 bytes, one chunk | The wrapper returns a new buffer that holds the same bytes |
| SF-I2b | `ReadMany` slot 0, ranges `(0, 8)` and `(8, 8)` | `read_many` yields range 0 twice |
| SF-I2c | `StartReadMany` slot 0, ranges `(0, 8)` and `(8, 8)`, handle awaited | The handle returns only the first buffer |
| SF-I3a | `Open` slot 1, `p0`/`a`, `0..=0` | `BlobAlreadyOpen` is replaced by `Error::Closed` |
| SF-I3b | `Open` slot 0, `p0`/`a`, `1..=2` | `BlobVersionMismatch` is replaced by `Error::Closed` |
| SF-I3c | `Open` slot 1, partition `a/b`, name `a`, `0..=0` | The wrapper opens `p1`/`a` instead and returns that blob |
| SF-I3d | `Remove` partition `a/b`, no name | The wrapper returns `Ok` without calling the storage |
| SF-I3e | `Scan` partition `a/b` | The wrapper returns `Ok` with no name without calling the storage |
| SF-I3f | `Open` slot 1, `p0`/`b`, `1..=2` | The returned version is replaced by 0 |
| SF-I3g | `Open` slot 0, `p0`/`a`, `0..=2` (a reopen) | The returned version is replaced by 1 |
| SF-I3h | `Remove` `p0`/`a`; `Open` slot 1, `p0`/`a`, `0..=0` | On that open the wrapper writes 4 bytes at offset 0 without `SYNC` and returns size 4 |
| SF-I4a | `Write` slot 0, offset 8, 8 bytes, write fault (fail, 100, `Prefix`) | After the injected failure the wrapper writes one differing byte at offset 32, disarmed, and returns the error |
| SF-I4b | `Write` slot 0, offset 8, 8 bytes, write fault (fail, 0, `Prefix`) | After the injected failure the wrapper writes at offset 8, disarmed, one byte that is neither the old byte nor the submitted byte, and returns the error |
| SF-I4c | `Write` slot 0, offset 100, 8 bytes, write fault (fail, 0, `Prefix`) | After the injected failure the wrapper resizes to 80, disarmed, and returns the error |
| SF-I4d | `Write` slot 0, offset 0, 8 bytes, `SYNC`, sync fault | The wrapper does not call the storage and returns `Error::Io` |
| SF-I5a | `Resize` slot 0 to 128, resize fault (100, partial 0) | After the injected failure the wrapper resizes to 200, disarmed, and returns the error |
| SF-I5b | `Resize` slot 0 to 128, resize fault (100, partial 0) | After the injected failure the wrapper writes one differing byte at offset 0, disarmed, and returns the error |
| SF-I5c | `Resize` slot 0 to 128, resize fault (100, partial 100) | After the injected failure the wrapper writes one nonzero byte at offset 64, disarmed, and returns the error |
| SF-I6a | `Open` slot 1, `p0`/`b`, `0..=0`, open fault | The wrapper performs the open, disarmed, drops the blob, and returns `Error::Io` |
| SF-I6b | `ReadAt` slot 0, offset 0, 16 bytes, read fault | After the injected failure the wrapper writes one differing byte at offset 0, disarmed, and returns the error |
| SF-I6c | `Sync` slot 0, sync fault | After the injected failure the wrapper resizes to 10, disarmed, and returns the error |
| SF-I6d | `Remove` `p0`/`a`, remove fault | The wrapper performs the remove, disarmed, and returns `Error::Io` |
| SF-I6e | `Scan` `p0`, scan fault | After the injected failure the wrapper removes `p0`/`a`, disarmed, and returns the error |
| SF-I7 | any | Every `sync` returns `Ok` without calling the storage |
| SF-I8 | `Write` slot 0, offset 0, 8 bytes, `SYNC` | The wrapper clears `SYNC` before it forwards the write |
| SF-I9 | `Write` slot 0, offset 0, 8 bytes, write fault (fail, 100, `Prefix`) | The wrapper does not forward the call. Disarmed, it writes the same bytes without `SYNC`, and returns `Error::Io` |
| SF-I10 | `Resize` slot 0 to 128, resize fault (100, partial 100) | The wrapper does not forward the call. Disarmed, it resizes to 96, and returns `Error::Io` |
| SF-I11 | `Write` slot 0, offset 0, 8 bytes, no fault; `Open` slot 0, `p0`/`a`, `0..=0` | On that reopen the wrapper, disarmed, writes the 8 bytes of the earlier write again without `SYNC` before it returns the handle |
| SF-I12 | `Write` slot 0, offset 0, 8 bytes, no fault; `Open` slot 0, `p0`/`a`, `0..=0` | On that reopen the wrapper, disarmed, overwrites byte 20 with a differing byte without `SYNC` before it returns the handle |
| SF-I13 | `Write` slot 0, offset 0, 8 bytes, write fault (no fail, 50, `Subset`) | In the session after the crash, the whole-blob read of `p0`/`a` has byte 40 changed |
| SF-I14a | `Scan` `p0`, no fault | The wrapper adds the name `zz` to the result |
| SF-I14b | `Remove` `p0`/`a`, no fault | The wrapper returns `Ok` without calling the storage |
| SF-I15 | `Remove` `p0`/`a`, no fault; `ReadAt` slot 0, offset 0, 16 bytes | After a successful remove, every read through an older handle returns `Error::Closed` |
| SF-I16a | any | Every open returns `Error::Closed` without calling the storage |
| SF-I16b | any | Every `write_at` returns `Error::Closed` without calling the storage |
| SF-I16c | `Resize` slot 0 to 32, no fault | Every `resize` returns `Error::Closed` without calling the storage |
| SF-I16d | any | Every `sync` returns `Error::Closed` without calling the storage |
| SF-I16e | `StartSync` slot 0, handle awaited, no fault | The handle returns `Error::Closed` |
| SF-I16f | `Remove` `p0`/`a`, no fault | The wrapper returns `Error::Closed` without calling the storage |
| SF-I16g | `Scan` `p0`, no fault | The wrapper returns `Error::Closed` without calling the storage |
| SF-I17 | `Scan` `p0` | `scan` panics. The panic passes through `run` |
| SF-I18a | any | In the session after the crash, the open of `p0`/`a` returns the size `u64::MAX`. The trace holds no read after that open |
| SF-I18b | `Open` slot 0, `p0`/`a`, `0..=0` (a reopen) | The returned size is 63 instead of 64 |

### The planted runtime fault

- **SF-R27.** One fault MUST be planted in a copy of `runtime/src` (SF-R28) to show that the target finds a bug in the
  runtime itself and not only at the seam [25]. The patch is the diff below, in this rule, and
  this rule holds its only copy. It removes the retirement of pending crash outcomes
  from `Context::open_versioned` (`runtime/src/deterministic.rs`, `impl crate::Storage for
  Context`, the `admit` call and the `drop(retired)` after it), so a successful reopen is no
  longer a durability cut: a write that was unsynced before the reopen can still land at the
  next crash and change bytes the reopen had shown. It breaks
  SF-I11 and looks like a real omission. None of the ten recovery targets checks this rule at the
  blob level. The removed call is the only caller of the faulty storage's `admit`
  (`runtime/src/storage/faulty.rs`, `Storage::admit`), and the workspace denies warnings
  (`Cargo.toml`, `[workspace.lints.rust]`: `warnings = "deny"`), so without more the plant build
  stops on `dead_code` before the target runs. The patch MUST
  therefore also add one line, `#[allow(dead_code)]`, directly above that method, and MUST NOT
  add any other line. The attribute changes no behaviour. It is part of the plant, so SF-R28
  keeps it out of `runtime/src` in the repository tree and in the delivered diff. The plant build
  MUST NOT relax lints in any other way: no `RUSTFLAGS`, no `--cap-lints`.

  The patch. Its line numbers, and the line numbers this rule names, are those of the tree on
  2026-11-22. It is the only fenced `diff` block of this spec, and the script of V9 reads it
  from this file (SF-C12):

  ```diff
  diff --git a/runtime/src/deterministic.rs b/runtime/src/deterministic.rs
  --- a/runtime/src/deterministic.rs
  +++ b/runtime/src/deterministic.rs
  @@ -1577,9 +1577,7 @@ impl crate::Storage for Context {
               name,
               self.storage.open_versioned(partition, name, versions),
           )?;
  -        let retired = self.storage.inner().inner().admit(partition, name);
           let opened = opened.finish();
  -        drop(retired);
           Ok(opened)
       }

  diff --git a/runtime/src/storage/faulty.rs b/runtime/src/storage/faulty.rs
  --- a/runtime/src/storage/faulty.rs
  +++ b/runtime/src/storage/faulty.rs
  @@ -504,6 +504,7 @@ impl Storage<crate::storage::memory::Storage> {
       /// Retire crash evidence excluded from the durable snapshot admitted by a successful open.
       /// The caller holds the logical namespace guard through admission and retirement.
  +    #[allow(dead_code)]
       pub(crate) fn admit(
           &self,
           partition: &str,
           name: &[u8],
  ```

  The same change by function and call, so that the diff can be written again when the code
  around it has changed:

  1. In `runtime/src/deterministic.rs`, in `impl crate::Storage for Context`, in the method
     `open_versioned`: delete the statement
     `let retired = self.storage.inner().inner().admit(partition, name);` and the statement
     `drop(retired);`. Every other statement of the method stays, `let opened = opened.finish();`
     between the two included.
  2. In `runtime/src/storage/faulty.rs`, in `impl Storage<crate::storage::memory::Storage>`: add
     the line `#[allow(dead_code)]` between the doc comment of `pub(crate) fn admit` and its
     signature.

  `git apply` places a hunk by its context lines, so a shift of the line numbers alone needs no
  change. When a context line or a changed line no longer matches, `git apply` refuses the
  patch. The diff and the line numbers of this rule MUST then be written again from the two
  steps above, in this spec, before V9 is run.

  History: this spec was accepted on 2026-11-18 with the patch in a file outside the repository.
  A clone does not get that file, so V9 could run only in the one tree that held it. Decision,
  2026-11-22: the text of the patch is part of this rule [25], and V9 reads it from here. The
  planted fault, its failing input and the worktree rule of SF-R28 did not change, and nothing
  that was detected before is lost. SF-R28 and the Expected findings said that the plant is
  never in the repository; since the same day they say that it is never applied there. Future
  work 31 proposed more patch files outside the repository; it now proposes more diffs in this
  spec.
- **SF-R28.** The patch MUST be applied only in a disposable git worktree, the target MUST fail
  there with `[crash_image]` and invariant SF-I11, and the worktree MUST then be removed. The
  repository tree and the delivered diff MUST NOT hold the applied plant: under `runtime/src`
  they hold no change at all (SF-R1), the `#[allow(dead_code)]` line of SF-R27 included [25].
  The text of the diff in SF-R27 is not an applied plant. The shortest failing run is the
  baseline plus two input operations:
  a `Write` on slot 0 without `SYNC` that carries a write fault with `failure_rate` 0 and
  `retention_rate` 100, then `Open` slot 0 on `p0`/`a`. The same input must pass in the repository
  tree. The steps are in [Validation](#validation-after-implementation).

### Run time

- **SF-R29.** 50 ms per input is a performance target, measured on a named host over fixed
  inputs. The harness MUST meet it with the count and size bounds of Sizes only, and MUST NOT
  measure time itself [21].

How the bounds follow from the target. The work of one run is bounded by counts, all from Sizes:

- Storage calls. An input operation makes 1 call of its own and at most 14 verification reads
  (SF-R11 item 2: the read at the bound, a binary search of at most 12 reads, one whole-blob
  read). The baseline makes 5 calls. A recovery verification makes 2 scans and, for each of at
  most 6 blobs, 1 open and 3 reads. So a run makes at most 48 x 15 + 5 + 4 x 26 = 829 storage
  calls, in at most 5 runner starts.
- Bytes. At most 48 writes of 256 bytes, and at most 48 + 4 x 6 whole-blob reads of at most 2304
  bytes each: below 180 KiB of copies and audit hashing.
- Log size. A write or a resize adds at most one entry (a failed write is one `Kept` entry with
  a mask, SF-R16), so all logs of a run together hold at most 49 entries.
- Membership tests. At most one per successful reopen and one per blob per recovery
  verification: at most 48 + 4 x 6 = 72 calls, each over at most 49 entries, 2305 lengths and
  2304 positions. The cost of one call depends on the algorithm, which SF-R13 leaves open. It
  is the one term this derivation does not fix.

The storage part is small: about 830 in-memory calls and 180 KiB. The membership test is the open
term, so the heavy inputs of rule M2 load it, and each verification path, to the bounds. All of
this is an estimate from reading the code: nothing was built for this spec. If a measurement
below fails, the bounds are lowered in this spec first, `MAX_OPS` before `MAX_SIZE`.

The measurement:

- Acceptance host: a macOS build host, Apple M4 Max (`Mac16,5`), 16 cores, 48 GB, macOS
  26. Every smoke run of this spec is done there. A result from another host is reported with the
  host's name and is not the acceptance result.
- Fixed inputs: the empty input, and the 256 inputs of 8 bytes that hold `i` as a little-endian
  `u64`, for `i` from 0 to 255. Each seeds a whole run through the shared decoder.
- Rule M1, on the fuzz binary: each fixed input file is run 100 times in one libFuzzer process
  (`-runs=100` with the file as argument). The line `Executed <file> in <T> ms` must show `T` at
  or below 5000 for every file, which is a mean of 50 ms per run.
- Rule M2, on five heavy inputs. Each is a hand-written `FuzzInput` of `MAX_OPS` operations on
  top of the baseline. "A torn write" below is a `Write` of `MAX_WRITE` bytes without `SYNC`
  that carries a write fault with `failure_rate` 0, `retention_rate` 50 and `Subset`, at an
  offset that alternates between 0 and `MAX_OFFSET`.
  - H1, the longest log: 48 torn writes on slot 0 and no `Crash`. The final check runs one
    membership test over 49 entries.
  - H2, fragmented failed writes: 48 `Write` operations on slot 0 of `MAX_WRITE` bytes at
    `MAX_OFFSET` that carry a write fault with `failure_rate` 1, `retention_rate` 50 and
    `Subset`. Each runs the length search, a whole-blob read, and adds a `Kept` entry with a
    broken-up mask.
  - H3, failed resizes: 48 `Resize` operations on slot 0 whose target alternates between 0 and
    `MAX_SIZE`, with a resize fault of 100 percent and `partial_rate` 100. Each runs the length
    search with the bound `MAX_SIZE` and a whole-blob read, and adds a `ForcedResize`.
  - H4, a reopen over the longest log: 47 torn writes on slot 0, then `Open` slot 0 on
    `p0`/`a`. The reopen runs one membership test under `Rule::Reopen` over 48 entries.
  - H5, many blobs and crashes: 3 `Crash` operations at even distances; each session opens the
    four slots on `p0`/`a`, `p0`/`b`, `p0`/`c` and `p1`/`a` (slot 0 is open already in session
    0) and fills the rest with torn writes over the four slots in turn.

  An ignored test runs each of the five 11 times in a release build and prints each time. The
  median of each MUST be at or below 50 ms.
- The measured numbers and the host go into the build report.

### Choices made

Choices the intents file leaves open, each stated as it is.

| Id | Choice | Reason | What it costs |
|---|---|---|---|
| SF-C1 | Failure rates are 0 or 1, except the resize fault at 50 percent. Retention rates are 0, 25, 50, 75, 100 | The input, not the RNG, decides which operation fails, so the fuzzer steers failures directly. The resize needs 50 percent, because the backend keeps a successful resize at a crash only by the same rate (`faulty.rs`, `Oracle::check_resize_fault`) | Whether a resize armed at 50 percent fails is decided by the runtime RNG, which the input also sets |
| SF-C2 | An unarmed `start_sync` whose handle is dropped counts as a completed sync | The memory backend finishes the sync before it returns the handle (`memory/mod.rs`, `Blob::start_sync`; `faulty.rs`, the test `test_dropped_completed_start_sync_clears_the_crash_epoch`). This asserts implementation behaviour: the contract only says the sync continues | On a backend with a delayed sync this rule would have to wait for the completion |
| SF-C3 | An injected failure of an open, a read, a scan or a sync changes nothing | The injector fails these before it touches the storage (`faulty.rs`: the `should_fail` checks at the start of `Storage::open_versioned`, `Storage::scan`, `Blob::read_at` and `Blob::sync`). Intent [16] says it for remove; this extends it | A future injector that fails after a partial effect would be reported, and this spec would then change first |
| SF-C4 | A reopen may drop the intermediate length of a failed resize; a crash may not | The backend replays it only at a crash (`faulty.rs`, `Blob::resize` and `Storage::admit`). Intent [14] speaks of the crash only | None for a crash. A reopen that loses it is accepted |
| SF-C5 | The image a reopen shows must be in `Reach_reopen` | The contract lets a drop discard unsynced changes and promises nothing else (`runtime/src/lib.rs`, `Blob`: "When a blob is dropped, any unsynced changes may be discarded"). The intents fix what a reopen makes durable [12], not what it may show | None |
| SF-C6 | The mandatory crash is the last crash, after all input operations. Extra crashes come from `Crash` operations, at most 3 | Every run ends with a crash check of whatever the input left unsynced, and the empty input still runs the full cycle [8, 10]. The chain of 1 to 4 matches the recovery targets | None |
| SF-C7 | An armed operation that does not fail is judged as unarmed. The target does not assert that the injector injects | The target tests the storage contract, not the dice of the injector. Some armed calls must not fail, for example an empty `SYNC` write | An injector that stops injecting is not reported. The lineage coverage of `faulty.rs` shows it |
| SF-C8 | The target is behind the feature `storage-faults` and runs on FuzzCorp only | The rule this spec already has for `storage_differential` and `iobuf` [26] | It does not run in `slow.yml` |
| SF-C9 | Small sizes: blobs up to 2304 bytes | The 50 ms target and whole-blob checks after every reopen, failure and crash | Large blobs under faults are not explored (Future work 26) |
| SF-C10 | The planted fault is the missing reopen cut (SF-R27) | It needs three steps in order that only a fuzzer-chosen sequence gives, it is not caught by the empty input, and the ten recovery targets cannot see it | One plant proves one path. The negative controls cover the other invariants |
| SF-C11 | The two draws of SF-R8 are public samplers with a fixed selector, not pinned input bytes | A sampler that takes an `Unstructured` is the existing decoding style (`storage_differential` samples every field this way), and a test can call it with one byte. Pinned bytes for a whole input would fix the order of every draw of the decoder, which the spec leaves open. The selectors are chosen so that exhausted input arms nothing | That the decoder calls the samplers, and decides these two points nowhere else, is checked by reading the source of the decoder, not shown by a fixed-input test |
| SF-C12 | The script of V9 reads the patch from the `diff` block of SF-R27 and holds no second copy of it (2026-11-22) | Two copies drift apart, and every clone has this file | V9 needs this file at `runtime/fuzz/SPEC.md`, and the block inside SF-R27, indented by two spaces. The script refuses a spec that holds a second block of that form, and a patch whose files, or whose counts of added and removed lines per file, differ from SF-R27. It does not check which two lines of `deterministic.rs` the patch removes |

### Limits of the proof

The definition of done [22 to 26] shows the deterministic fault model only. It does not show a
real disk, tokio under faults, or the absence of every bug. In addition:

- A crash falls between two operations, never inside one, and never inside an accepted
  `start_sync` (SF-X4, SF-X7).
- The images seen are the ones the injector produces. The contract allows more: for example the
  injector tears only writes issued under a write fault, and drops every other unsynced write
  whole.
- A fuzz run measures an invariant only when its measurement point occurs. The regression suite,
  not the smoke run, proves that each invariant can fire.
- The oracle can show that data which must survive was lost. It cannot show that data which may
  be lost was made durable too early: every such image is inside the reach set. So three
  failures are not detected: an injected failed `Sync` or `StartSync` that performs the sync and
  then returns the error, an injected failed open that takes its reopen cut, and a fused write
  with a sync fault that makes its bytes durable (SF-R15, SF-R17). Seeing them needs a view of
  the durable image without a crash, which the public contract does not give (Future work 32).

## Target `iobuf`

### Execution

The operations run inside the root task of `deterministic::Runner`, which is required for every
target in this repo even though this code is pure CPU. No operation awaits.

### Objects

Up to 8 live objects, each paired with a model:

- `IoBufMut`: content `Vec<u8>`, capacity, and the requested alignment.
- `IoBuf`: content `Vec<u8>` and a sharing group. Clones, slices and the two halves of a
  `split_to` from the same allocation share a group.
- `IoBufs`: content as one concatenated `Vec<u8>`.
- `IoBufsMut`: content, plus a flag set by the first read. Once the flag is set, write operations
  on it are skipped, because writing after reading is outside the `IoBufsMut` contract
  (`runtime/src/iobuf/bufs.rs`, `IoBufsMut` "Capacity retention": "Interleaving writes after reads
  is outside this contract").
- `Builder`: the inline capacity left, and the expected output as an ordered list of inline and
  pushed segments.

### Operations

- `IoBufMut`: `with_capacity`, `with_alignment`, `zeroed`, `zeroed_with_alignment`, and `From` a
  `Vec<u8>`; `put_slice`, `put_bytes` and `put_u8` up to the remaining capacity; overwrite through
  `as_mut`; `truncate`; `clear`; `advance`; `copy_to_bytes`; `freeze`.
- `IoBuf`: `copy_from_slice`; `From` a `Vec<u8>` with spare capacity, `Bytes`, `BytesMut` with spare
  capacity, and `&'static [u8]`; `clone`; `slice`; `split_to`; `advance`; `copy_to_bytes`;
  `try_into_mut`; conversion back to `Vec<u8>` and `Bytes`; wrapping into `IoBufs`; drop.
- `IoBufs`: build from 1 to 5 buffers, which reaches every internal shape (single, pair, triple,
  chunked) and includes empty buffers; `clone`; `prepend`; `append`; `split_to`; `advance`;
  `copy_to_bytes`; `coalesce`; `try_into_single`; `chunk_count` and `chunk_at`. The model keeps
  each non-empty chunk with its provenance, plus the owner of a drained single chunk.
- `IoBufsMut`: build from 1 to 5 `IoBufMut` chunks, including zero-capacity chunks;
  `copy_from_slice` and `BufMut` writes; `advance`, `copy_to_bytes` and `copy_to_slice` reads;
  `freeze`; `coalesce`; `try_into_single`.
- `Builder`: `new(capacity)`; inline writes up to the remaining inline capacity; `push` of an
  `IoBuf`, `Bytes`, `&'static [u8]` or `Vec<u8>`; `finish`.

### Sizes

Capacities up to about 256 KiB, biased toward 0, small values, and 128 KiB plus or minus a few
bytes. On 64-bit targets the descriptor keeps the spare tail in 17 bits, so freezing a buffer with
more than 128 KiB of spare capacity takes the record fallback (`runtime/src/iobuf/owner.rs`).
Alignments are powers of two from 1 to 4096. Builds are 64-bit only.

### Oracle

After every operation:

- Every live object's content equals its model, read through `as_ref` or chunk iteration.
- `len` matches the model and `capacity() >= len()`.
- An aligned allocation with nonzero capacity starts at an address that is a multiple of the
  requested alignment.
- A mutation through one object is never visible through another live object.
- `try_into_mut` must succeed in two cases:
  - an empty view that has no owner (detached, or static);
  - a view of a native allocation (heap, adopted `Vec`, `copy_from_slice`, multi-chunk `coalesce`,
    builder inline buffer, frozen `IoBufMut` or `IoBufsMut` chunks) when no other live object holds
    that allocation. Holders include empty views that kept their owner, such as an `IoBuf` advanced
    to its end or a single-chunk `IoBufs` drained by `advance`. The `IoBufs` case is implementation
    behaviour (the single-chunk arm of `IoBufs::advance` does not canonicalize), not documented.

  It must fail on non-empty static views and on views of `Bytes`. Either outcome is accepted when
  the view's owner is unknown. On success, no other live object may hold the allocation, and the
  recovered capacity must run from the view's start to the end of the allocation.
- `IoBufs` chunks concatenate to the model, and `chunk_count` matches the number of nonempty
  chunks.
- Conversions to `Vec<u8>` and `Bytes` preserve content.

ASan, which cargo-fuzz enables by default, catches out-of-bounds accesses, use-after-free and
double free in the `unsafe` paths.

Each failure panics from a `#[cold] #[inline(never)]` function named after its check, under
`iobuf::oracle`, and its message starts with the same `[class]` tag. The class depends only on the
check, never on data:

| Class | Meaning |
|---|---|
| `content_mismatch` | A live object's bytes or chunks differ from its model |
| `conversion_content` | The bytes an operation returns differ from the model |
| `len_or_capacity` | A length, remaining count or capacity differs, or capacity is below length |
| `chunk_shape` | Chunk count, chunk access, single-chunk shape or `try_into_single` outcome differs |
| `pointer_identity` | A documented zero-copy operation copied, or an address differs from base plus offset |
| `alignment` | An aligned allocation's base is not a multiple of its alignment |
| `alias_overlap` | An exclusive region overlaps another live region |
| `try_into_mut_success_with_holders` | `try_into_mut` succeeded while another live object holds the allocation |
| `try_into_mut_success_non_native` | `try_into_mut` succeeded on a `Bytes` view or a non-empty static view |
| `try_into_mut_refused` | `try_into_mut` failed on an ownerless empty view or the only handle to a native allocation |
| `bufsmut_freeze_unmapped` | A frozen chunk lies outside the allocations its `IoBufsMut` was built from |

## Target `shared_reads`

Status: specified. The input is the intents file `runtime/fuzz/INTENTS-shared-reads.md`. In this
part a number in square brackets, such as [11], names an item of that file. Ids in this part:
`SR-G` goals, `SR-R` requirements, `SR-P` properties, `SR-I` invariants, `SR-B` behaviours the
reach check needs, `SR-F` planted faults, `SR-X` cases left out, `SR-C` choices this spec makes
where the intents file leaves one open.

### Definitions

| Term | Meaning |
|---|---|
| Page | A logical page of the page cache: `PAGE_SIZE` bytes. Page `p` holds the logical offsets `p * PAGE_SIZE .. (p + 1) * PAGE_SIZE` |
| Physical page | Page `p` as stored in the blob: `PAGE_SIZE + CHECKSUM_SIZE` bytes at offset `p * (PAGE_SIZE + CHECKSUM_SIZE)` (`runtime/src/utils/buffer/paged/mod.rs`, `physical_page`) |
| Sealed blob | The `Sealed` handle (`runtime/src/utils/buffer/paged/sealed.rs`) that the construction (SR-R3) returns. Every reader reads through a clone of it |
| Read | One call of `Sealed::read_at`, `Sealed::read_into` or `Sealed::read_ranges_into`, and the future it returns |
| Form | Which of the three calls a read is |
| Operation | One read as the input describes it: a form, its ranges, and a drop flag |
| Drop flag | A flag of an operation. A flagged read is polled once by its task and dropped when that poll is pending [6] |
| Cancelled read | A read whose future was polled exactly once, returned pending, and was dropped without another poll [6] |
| Completes | A read completes when its future returns `Ok`. It fails when it returns `Err` |
| Opening | The first phase of every run: two reads of one page, driven by the root task in a fixed order (SR-R9) [11] |
| Free phase | The second phase: the reader tasks, each running its operations in order (SR-R10) |
| Hot page | The page `h` where the first operation of every reader starts (SR-R6) |
| Reader | One task of the free phase |
| Read phase | The opening and the free phase together. It starts after the construction |
| Deadline | `DEADLINE` of simulated time, counted from the start of the read phase (SR-R12) [9] |
| Model | The function `value` of SR-R3: the byte the blob holds at each logical offset |
| Backend read | One call of `read_at` or `read_at_buf` that reaches the storage blob under the mock. It is counted once for every physical page its range touches (SR-R13) |
| Standalone fetch | The cache's read of one page by `read_after_page_fault`, shared by its waiters (`runtime/src/utils/buffer/paged/cache.rs`, `CacheRef::read_after_page_fault`) |
| Batch | The cache's read of several pages with one `Blob::read_many` call, started by `read_after_misses` (`cache.rs`, `CacheRef::read_after_misses`) |
| Waiter | A read registered on a standalone fetch |
| Starter, joiner | The read that started a batch, and a read that selected pages of a batch it did not start |
| Fetch generation | One standalone fetch of a page, from the read that installs it until it completes or its last waiter is dropped (`cache.rs`, `PageFetchEntry`) |

### Goals

- **SR-G1.** Find faults in the shared reads of the page cache: a read that gets wrong bytes, a
  reader that never finishes because a wakeup was lost, and a cancelled read that takes a live
  fetch away from the reads that joined it [1].
- **SR-G2.** Reach the code no other target reaches: a read that joins a standalone fetch or a
  batch that another read has in flight, and the cleanup when such a read is cancelled. The
  `buffer` target awaits one operation at a time, and on the plain memory blob a read never
  stays in flight, so a second read never finds one to join (background of the intents file).
- **SR-G3.** Every failure replays: a fixed input gives the same run every time [16].

### Construction

- **SR-R1.** The target MUST run on the deterministic runtime only, MUST use the public API of
  `commonware-runtime` with its `test-utils` feature, and MUST NOT change anything under
  `runtime/src` [3, 19]. The two `test-utils` items it uses are `mocks::MigratingReadBlob`
  (`runtime/src/mocks.rs`) and `CacheRef::clear` (`cache.rs`).
- **SR-R2.** Every run MUST start one `deterministic::Runner` from
  `deterministic::Config::new().with_rng(FuzzRng::from(entropy))`, where `entropy` comes from
  the shared decoder (Shared input decoding). The configuration keeps its default cycle of 1 ms,
  no runtime timeout, and `catch_panics` off, so a panic in any task ends the run.
- **SR-R3.** Construction, once per run, before the read phase [4]:
  1. Open the blob `blob` in the partition `shared_reads`. Its size must be 0.
  2. Wrap it as `MigratingReadBlob::new(Counter(blob), false)`, where `Counter` is the counting
     wrapper of SR-R13. Every later call reaches the storage through these two wrappers.
  3. Create `CacheRef::new(PAGE_SIZE, cache_pages)`. Create `Writer::new(blob, 0, 2 * PAGE_SIZE,
     cache)` (`runtime/src/utils/buffer/paged/writer.rs`, `Writer::new`), append the model bytes of
     `pages` full pages in one `append` call, call `seal()`
     (`writer.rs`, `Writer::seal`), and await the sync handle it returns. The sealed blob's
     `size()` must be `pages * PAGE_SIZE`.
  4. Call `CacheRef::clear()`, so that no page is cached when the read phase starts. The writer
     caches pages as it flushes them (`writer.rs`, the `cache` call in `Writer::append_owned` and
     the `cache_pages` call in `Writer::flush_internal`), and `clear` may be called only
     with no read in flight, which holds here.
  5. Reset the counts of SR-R13 to zero.

  The model is `value(o) = ((o / PAGE_SIZE) * 37 + o % PAGE_SIZE) % 255 + 1`, as a byte, for a
  logical offset `o`. No byte is zero, so a byte that a read never filled differs from the
  model. Two different pages differ at every offset inside the page, because 37 and 255 have no
  common factor and there are fewer than 255 pages: a wrong page never compares equal by
  accident [4]. An error or a size other than the one named in any step MUST end the run with a
  panic.
- **SR-R4.** Every read MUST lie inside `0 .. pages * PAGE_SIZE` and MUST have a length of at
  least 1 byte for each of its ranges [4, 20]. The ranges of one `read_ranges_into` MUST be sorted
  and MUST NOT overlap [5].

### Input

Bounds, all constants at the top of the harness [7]:

| Constant | Value | Bounds |
|---|---|---|
| `PAGE_SIZE` | 64 | logical bytes of a page (fixed, SR-C2) |
| `MIN_PAGES`, `MAX_PAGES` | 2, 16 | pages of the sealed blob |
| cache pages | 1 to `pages - 1` | capacity of the cache, so the blob always has more pages than the cache (SR-C3) |
| `MIN_READERS`, `MAX_READERS` | 2, 6 | readers of the free phase |
| `MIN_OPS`, `MAX_OPS` | 1, 8 | operations of one reader |
| `MAX_SPAN` | 4 | consecutive pages that the ranges of one read may touch |
| `MAX_RANGES` | 4 | ranges of one `read_ranges_into` |
| `DEADLINE` | 10 s | simulated time for the read phase (SR-R12) |

- **SR-R5.** `FuzzInput` MUST have a hand-written `Arbitrary` that runs the shared `decode`
  (`runtime/fuzz/src/lib.rs`), unchanged, and samples every field from the stream it returns
  with `Unstructured`. So the runtime's entropy comes from the first `SEED_BYTES` of the input,
  and `FuzzRng` fills what a short input does not hold [7]. It MUST NOT fail on any input length
  and MUST keep the default `size_hint`, so the typed entry rejects no input. Every count MUST be
  drawn with `int_in_range` over its bounds, so a stream with no bytes left gives the lower
  bounds, which are a whole run.
- **SR-R6.** The decoder MUST draw one hot page `h`: a page of the blob other than the opening's
  page `p0`. It MUST give every free-phase operation:
  1. a form, `read_at`, `read_into` or `read_ranges_into`;
  2. a window of 1 to `MAX_SPAN` pages that ends at the blob's end at the latest. For the first
     operation of every reader the window MUST start at page `h`; for every later operation it
     starts at any page of the blob;
  3. ranges inside the window: one range for `read_at` and `read_into`, which may cross page
     ends; 1 to `MAX_RANGES` sorted ranges that do not overlap for `read_ranges_into`. For the
     first operation of every reader the first range MUST start inside page `h`;
  4. a drop flag, drawn by `sample_drop`.

  So the first operations of all readers touch page `h`, and every reader's reads overlap the
  pages of the other readers' reads [5]. Page `h` is not cached when the free phase starts,
  because only page `p0` was read before it and the cache was cleared after the construction.
  The readers are first polled in the same cycle (SR-R10), so their first operations contend on
  one page that is cold when that cycle starts: the earliest of them can start or join a read of
  page `h` in flight, and a later one in the same cycle may find the page already cached,
  because a joiner of a standalone fetch completes it in the turn it joins (SR-C4). The
  operations after the first ones may use any pages.
- **SR-R7.** Two public samplers of the library module draw the flags, so that a test can call
  them with fixed bytes:
  - `sample_drop(u: &mut Unstructured<'_>) -> arbitrary::Result<bool>` MUST draw one selector
    with `u.int_in_range(0..=3)`, MUST make no other draw, and MUST return `true` exactly when
    the selector is 3. The decoder MUST call it once for every free-phase operation, and the
    operation MUST be flagged exactly when it returns `true`.
  - `sample_opening_drop(u: &mut Unstructured<'_>) -> arbitrary::Result<bool>` MUST draw one
    selector with `u.int_in_range(0..=1)`, MUST make no other draw, and MUST return `true`
    exactly when the selector is 1. The decoder MUST call it once, for read A of the opening,
    and read A MUST be flagged exactly when it returns `true`.

  Fixed bytes: on `Unstructured::new(&[b])`, `sample_drop` returns `true` only for `b` = 3 among
  0 to 3, and `sample_opening_drop` returns `true` for `b` = 1 and `false` for `b` = 0. On
  `Unstructured::new(&[])` both return `false`. This follows from `int_in_range` of `arbitrary`
  1.4.2, as in SF-R8.
- **SR-R8.** The empty-corpus and minimal-decodable baseline has, by construction, an opening
  with two reads of one uncached page of which at least one survives (SR-R9), and at least two
  readers that each run at least one operation over a blob with more pages than the cache [4, 7].

### Run structure

- **SR-R9.** The opening, in every run [11]. The input gives a page `p0` of the blob and two
  operations on it:
  - read A: form `read_at` or `read_into`, one range inside page `p0`, flagged by
    `sample_opening_drop`;
  - read B: any of the three forms, ranges inside page `p0` (one range, or one or two for
    `read_ranges_into`), never flagged.

  The root task MUST, in this order and with no await in between: create read A's future and
  poll it once; create read B's future and poll it once; then, if read A's poll was pending and
  read A is flagged, drop read A's future (a cancellation). Then it MUST await read B and, when
  it was not dropped, read A. A read that was ready on its first poll is checked at once. The
  opening ends when both are resolved or dropped.

  Why this arranges the case of [11]: page `p0` is not cached, and read A's form reads it through
  a standalone fetch, so read A's first poll installs that fetch and, with the read held by the
  mock, returns pending. Read B's first poll then registers read B on the same fetch generation.
  So both are registered before any cancellation, and read B survives (SR-C5).

  Read A's first poll MUST be pending. It always is under SR-R3: page `p0` is cold, and the mock
  returns pending on the first poll of every backend read, whatever the read below it returns
  (`runtime/src/mocks.rs`, `MigratingReadBlob::read_at_buf`). When read A's first poll is ready,
  the arrangement of this rule no longer holds, and the run MUST end with a panic that says so.
  It is not a violation
  and not a run that leaves SR-I3 unmeasured. History: this spec was accepted on 2026-11-24 with
  a ready first poll of read A counted as a run that does not measure SR-I3. The construction
  makes that case unreachable, so no test could exercise it. Since the same day it is a failed
  precondition. Nothing detected before is lost.
- **SR-R10.** The free phase, after the opening ends [2, 5, 6]. The root task MUST spawn every
  reader in one turn, before it awaits any of them, and then await them all. A reader runs its
  operations in order. For each operation:
  - not flagged: it creates the read's future and awaits it;
  - flagged: it creates the read's future and polls it exactly once. When the poll is ready, the
    result is checked. When it is pending, the future is dropped and counted as a cancellation.

  Then the reader goes on with its next operation. A reader MUST NOT poll a read again after it
  returned ready, and MUST NOT poll a flagged read a second time in the same turn.
- **SR-R11.** Every read that completes MUST be checked at once against the model (SR-I1), and
  every read that fails MUST be reported at once (SR-I2b). The run MUST stop at the first
  violation and report it (SR-R14).
- **SR-R12.** The deadline [9]. The read phase MUST run as one future that the root task races
  against `context.sleep(DEADLINE)`. When the sleep wins, the run MUST report SR-I2a with the
  deadline location of SR-R14. The deadline covers the opening too.
- **SR-R13.** Backend reads. `Counter` is a `Blob` wrapper of the fuzz side. Every `read_at` and
  `read_at_buf` it receives MUST add one to the count of each physical page its range touches,
  and then forward the call. Every other call MUST be forwarded unchanged. The mock's default
  `read_many` issues one `read_at` per range (`runtime/src/lib.rs`, `read_each`), so the reads of a
  batch are counted too. The counts are reset at the end of the construction (SR-R3) and read at
  the end of the opening and at the end of the run.
- **SR-R14.** A violation MUST name its invariant, its class and its location, and MUST say
  whether a read of the run was cancelled before it. The location is one of four kinds, and a
  violation carries only the fields of its kind:
  1. a read of the opening, for SR-I1 and SR-I2b: `A` or `B`, its form and ranges, and for `A`
     its drop flag;
  2. a read of the free phase, for SR-I1 and SR-I2b: the reader index, the operation index, the
     form, the ranges and the drop flag;
  3. the opening as a whole, for SR-I3: the page `p0` and the counts of `opening_reads`;
  4. the read phase at the deadline, for SR-I2a: whether the opening had ended, the opening reads
     still pending (`A`, `B` or both), and for each reader `not started` (the free phase had not
     started), `finished`, or the index of the operation it was on.

  For SR-I1 the violation also gives the first offset whose byte differs, with the expected and
  the observed byte. A panic is not a violation: it passes through `run` with its own message
  (SR-I4), whether it is raised in the construction, by a stall, or by a task.

### Properties

- **SR-P1.** Every read that completes returns exactly the model's bytes [8]. Checked by SR-I1.
- **SR-P2.** Every read that is not cancelled, and every reader, finishes before the deadline,
  with `Ok`, and the runtime does not stall [9, 20]. Checked by SR-I2a, SR-I2b and SR-I4.
- **SR-P3.** A cancellation changes nothing for the other reads: SR-P1 and SR-P2 still hold for
  them [10]. Checked by SR-I1, SR-I2a and SR-I2b on every run that has a cancellation, and by the
  planted fault SR-F2.
- **SR-P4.** When two waiters on one uncached page are both registered before any cancellation
  and at least one of them survives, the page is read from the blob once [11]. Checked by SR-I3.

### Invariants

Each row is one check. A violation names its row (SR-R14).

| Id | What must hold | Measured when | Source | Class |
|---|---|---|---|---|
| SR-I1 | A read that completes returns exactly the model's bytes of its ranges: for `read_at` the returned buffers in order, for `read_into` the buffer, for `read_ranges_into` the buffer, which holds the ranges back to back | every read that completes, in the opening and in the free phase | [8]; `Sealed::read_at`, `read_into`, `read_ranges_into` (`sealed.rs`) | `read_bytes` |
| SR-I2a | Every read that is not cancelled, and every reader, finishes before the deadline | every run, at the end of the read phase | [9] | `read_incomplete` |
| SR-I2b | No read that is not cancelled returns `Err`. Storage never fails in this target, and every range is valid | every read that is not cancelled | [9, 20]; fuzzing guide: unexpected errors panic | `read_error` |
| SR-I3 | In the opening, the physical page of `p0` is read from the blob exactly once | every run, at the end of the opening (read A is always pending after its first poll, SR-R9) | [11]; a fetch generation "reads and validates the logical page exactly once" for all its waiters (`cache.rs`, `PageFetchEntry::fetch`) | `single_fetch_count` |
| SR-I4 | No panic, abort, sanitizer report or runtime stall (`runtime stalled`, `runtime/src/deterministic.rs`, `Executor::wake_until_progress`) | the whole run | [9]; fuzzing guide | none (the panic itself) |

- **SR-R15.** When a row counts as measured. A row MUST enter `measured` (SR-R16) only when the
  condition of its "Measured when" cell occurred in the run and its check ran and passed. SR-I3
  is measured in every run that reaches the end of the opening (SR-R9). `Outcome::cancellations`
  gives the number of cancelled reads, so that a test can tell the runs that measured SR-P3.

Not judged, because the intents leave it out or the contract does not promise it:

- The backend read counts of the free phase. A page may be read from the blob more than once
  there, for four reasons that the intents and the cache's code allow [12, 22]:
  1. Eviction. The cache always holds fewer pages than the blob (SR-C3). A page that was evicted
     is read again by a later read that misses it.
  2. A cancelled sole standalone waiter. Dropping the only waiter of a standalone fetch removes
     the fetch (`cache.rs`, `impl Drop for PageFetchGuard`), so a later read of the page starts
     a new fetch, although the dropped one had already read the page [22].
  3. A cancelled batch starter. A flagged starter is dropped in the turn it started its batch,
     so the batch ends, and a later read reads its pages again (SR-X7).
  4. The lock window. A read that examines its misses over several holds of the cache lock can
     miss a page that another read registers in between (`cache.rs`, the module docs: "another
     reader that misses one of those pages in between starts its own read of it"; the docs of
     `MISSES_PER_LOCK`). A read here touches at most 4 pages, fewer than the 64 misses of one
     hold (`MISSES_PER_LOCK`), so
     this reason is not expected at these bounds.

  What no reason allows: one read reads each page it touches from the blob at most once.
  `read_after_miss` reads its missing pages one at a time, `read_after_misses` reads the pages
  it does not join with one batch of its own, and a read that joins a fetch or a batch issues no
  backend read (`cache.rs`, `CacheRef::read_after_miss`, `CacheRef::read_after_misses` and
  `CacheRef::read_after_page_fault`). So the free-phase count of a page is
  at most the number of free-phase reads whose ranges touch it, cancelled reads included. The
  counts are recorded in the trace and held to this bound in the acceptance evidence only
  (SR-V10); they are not an invariant of the target [12]. The one strict count is SR-I3, in the
  opening [11].

  History: this spec was accepted on 2026-11-24 with two reasons, the lock window and a
  cancelled batch starter. The build measured duplicates from eviction and from a cancelled
  sole standalone waiter, also with every drop flag cleared, through eviction alone. [12] and
  [22] allow both. Since the same day the four reasons and the bound above hold. Nothing
  detected before is lost: the counts were never an invariant.
- The number `read_ranges_into` returns (the ranges served without a blob read). It depends on
  the cache's state at the call, which the target does not model (SR-C10).
- Which page the cache evicts. Only the bytes of a read are judged [21].

### Failure classes

Each class panics from a `#[cold] #[inline(never)]` function named after it, and the first line
of the message starts with the same `[class]` tag followed by the invariant id, as in
`storage_differential`. The class depends only on the check that fired.

| Class | Meaning | Invariants |
|---|---|---|
| `read_bytes` | A read that completed returned bytes that differ from the model | SR-I1 |
| `read_incomplete` | A read or a reader did not finish before the deadline | SR-I2a |
| `read_error` | A read that was not cancelled returned an error | SR-I2b |
| `single_fetch_count` | The opening read its page from the blob a number of times other than one | SR-I3 |

### Files and interfaces

| File | Role |
|---|---|
| `runtime/fuzz/fuzz_targets/shared_reads.rs` | New. Only imports and `fuzz_target!(|input: FuzzInput| { fuzz(input); });` |
| `runtime/fuzz/src/shared_reads.rs` | New library module: input, decoding, samplers, `Counter`, the run, the oracle |
| `runtime/fuzz/src/lib.rs` | Declares the module. The shared `decode` is used unchanged |
| `runtime/fuzz/tests/shared_reads_acceptance.rs` | New. The regression suite of SR-R18 |
| `runtime/fuzz/Cargo.toml` | The feature and the bin entry of Placement and build |
| `runtime/src/utils/buffer/paged/{cache,sealed,writer,view}.rs` | Code under test, unchanged: `Sealed` reads, `Writer::new`, `append`, `seal`, `CacheRef::new`, `CacheRef::clear` |
| `runtime/src/mocks.rs` | `MigratingReadBlob`, unchanged |

- **SR-R16.** The module MUST export these items with these contracts:

  | Item | Contract |
  |---|---|
  | `FuzzInput { pages: u64, cache_pages: usize, opening: Opening, readers: Vec<Vec<Op>>, entropy: Entropy }` | Public fields. `Arbitrary` as SR-R5. A hand-written value is taken as it is; values past the bounds or against SR-R4 are a test error |
  | `Opening { page: u64, first: Op, second: Op }` | Read A is `first`, read B is `second` (SR-R9) |
  | `Op { form: Form, ranges: Vec<(u64, usize)>, drop: bool }` and `Form::{ReadAt, ReadInto, ReadRangesInto}` | One operation. For `ReadAt` and `ReadInto` `ranges` holds one range |
  | `fuzz(input: FuzzInput)` | Runs `run` with the identity seam, and on a violation panics through the class function |
  | `run<S: Blob>(input: &FuzzInput, seam: impl FnOnce(Counter) -> S) -> Outcome` | Runs the whole run with `MigratingReadBlob::new(seam(Counter(blob)), false)` as the blob of SR-R3. It does not panic on a violation: it stops at the first one and returns it. A panic raised by the code under test or by the seam passes through |
  | `Counter` | The counting wrapper of SR-R13. Public, so that a seam can wrap it |
  | `Outcome { trace: Trace, violation: Option<Violation>, measured: BTreeSet<Invariant>, cancellations: usize, opening_reads: BTreeMap<u64, usize>, run_reads: BTreeMap<u64, usize> }` | `Invariant` has one value per row SR-I1 to SR-I3. `Violation` holds the invariant, the class, whether a read was cancelled before it, and the location of SR-R14 as an enum with one variant per kind, each with only its own fields. `opening_reads` holds the counts at the end of the opening, `run_reads` the counts of the free phase at the end of the run, by physical page |
  | `Trace` | `PartialEq` and `Debug`. One record per read that completes, fails, or is cancelled, in the order this happens: the location of the read (kind 1 or 2 of SR-R14), the form, the ranges, the drop flag, and the result: cancelled, failed with the error, or completed with its bytes. A read still pending when the deadline wins has no record; the SR-I2a violation names it (SR-R14, kind 4). Dropping the read phase at the deadline is not a cancellation and does not count in `cancellations` |
  | `sample_drop`, `sample_opening_drop` | The samplers of SR-R7 |

- **SR-R17.** Determinism [16]. For every input, two calls of `run` with the identity seam MUST
  return equal `Outcome` values. The harness MUST NOT read the wall clock or OS randomness, and
  no result may depend on the iteration order of a hash map. The order in which the runtime polls
  the readers comes from its RNG, which the input seeds.

### Regression suite

- **SR-R18.** The suite MUST be a set of `#[test]` functions in `runtime/fuzz/tests/
  shared_reads_acceptance.rs`, written from this spec. It MUST hold:
  1. The fixed inputs of SR-V6 (the empty input and the 256 inputs of 8 bytes) decode and run
     with no violation. Every one has `measured` equal to SR-I1, SR-I2a, SR-I2b and SR-I3, at
     least two readers, and a blob with more pages than the cache. The empty input's opening
     shows read A pending after its first poll (SR-I3 measured) [7]. In every decoded fixed
     input the first operations of all readers touch one common page other than the opening's
     page, and the first range of each starts in that page (SR-R6) [5].
  2. Replay: every fixed input run twice gives equal `Outcome` values (SR-R17) [16].
  3. For every invariant, the negative control of the table below: the run returns a violation
     whose invariant is the row's id and whose class is the row's class, and it is the first
     violation of the run. For SR-I4 the panic passes through `run`.
  4. The samplers on the fixed bytes of SR-R7.
  5. The two plant inputs of SR-F1 and SR-F2 run with no violation in the repository tree. These
     are the tests `plant_f1_input_runs_clean` and `plant_f2_input_runs_clean`. On a violation
     they panic with a message whose first line holds the violation's `[class]` tag and
     invariant id.
  6. An ignored test `batch_read_counts` that prints, for every fixed input, `run_reads`, the
     number of free-phase reads whose ranges touch each page, the pages read more than once,
     and the number of cancellations. It fails when the count of a page is above the number of
     free-phase reads that touch it ("Not judged", the bound). It is the evidence of SR-V10 [12].

Negative controls. "Plain input" means a hand-written `FuzzInput` with 8 pages, 4 cache pages,
an opening on page 1 with read A `ReadAt (64, 64)` not flagged and read B `ReadAt (64, 64)`, two
readers each with one `ReadAt (64, 64)` not flagged, and the entropy of the 8-byte fixed input 0.
The seam wraps `Counter`.

| Invariant | Input | Seam |
|---|---|---|
| SR-I1 | plain input | A read of the physical range of page 1 returns, instead, the bytes of the physical range of page 2, read through `Counter`. Their checksum is valid, so the cache accepts them |
| SR-I2a | plain input | A read of the physical range of page 1 never resolves (it awaits `futures::future::pending()`) |
| SR-I2b | plain input | A read of the physical range of page 1 returns `Err(Error::ReadFailed)` |
| SR-I3 | plain input | A read of the physical range of page 1 is forwarded through `Counter` twice, and the second result is returned |
| SR-I4 | plain input | `start_sync` returns a handle that never resolves, so the construction waits with no sleeper and the runtime panics with `runtime stalled` |

### Reach

- **SR-R19.** A short run from an empty corpus MUST reach these four behaviours of `cache.rs`
  [14]. The step SR-V7 measures them by line coverage. The script there finds each line by its
  text, so this spec names code, not line numbers; the line numbers are in the evidence only.

  | Id | Behaviour | Seen in the coverage when |
  |---|---|---|
  | SR-B1 | A read joins a standalone fetch | the `Entry::Occupied` arm of `read_after_page_fault` (`let entry = o.into_mut();`) or the joined-fetch arm of `read_after_misses` (`let fetch = PageFetchGuard::new(&self.cache, key, entry.fetch.clone());`) has a hit |
  | SR-B2 | A read joins a batch and gets a page from it | `Subscription::joining` (`state.inboxes.push(Some(VecDeque::new()));`) has a hit, and the delivery to a joiner in `Batch::publish` (`inbox.push_back((tag, result.clone()));`) has a hit |
  | SR-B3 | A cancelled standalone waiter with a survivor: a waiter is cancelled after a second waiter registered on the same fetch generation and completed it | in `PageFetchGuard::drop`, the `return;` right after `let Entry::Occupied(mut current) = cache.page_fetches.entry(self.key) else {` has a hit: an armed guard found its fetch already removed |
  | SR-B4 | A cancelled batch subscriber with a survivor: a joiner is cancelled with pages still undelivered, and the batch goes on for the others | in `Batch::publish`, `if let Some(inbox) = &mut inboxes[reader] {` has more hits than the delivery inside it: the batch published a page to a joiner that was gone |

  Decision, 2026-11-24 [22]: SR-B3 is read as above. With a read held for one poll, a cancelled
  standalone waiter never leaves a second waiter pending on the same fetch, because the second
  waiter drives the fetch to completion in the turn it joins (SR-C4). The case of a standalone
  fetch kept alive for a pending survivor is a limit of this proof and future work (Future work
  33).

### Planted faults

Each planted fault is a patch of `runtime/src/utils/buffer/paged/cache.rs`, applied only in a
disposable worktree (SR-V8). Its text is in this spec, in a fenced `diff` block at column 0 under
its rule; the script of SR-V8 reads it from here. The line numbers of the patches are those of
the tree on 2026-11-24. When a context line no longer matches, `git apply` refuses the patch, and
the diff MUST be written again from the description by function and expression, in this spec,
before SR-V8 runs. Each plant proves only its named check [15].

- **SR-F1.** A wrong page delivered to a joiner. In `Batch::publish`, the delivery to each joiner
  pushes the tag `0` instead of the tag the joiner selected the page with: the expression
  `(tag, result.clone())` becomes `(0, result.clone())`. The loop binding `tag` becomes `_tag`
  only so that the build passes, because the workspace denies the unused-variable warning; that
  rename changes nothing else. A joiner that selected two or more pages of one batch then copies
  every page into the pieces of its first page.

  Trace: `pages` 8, `cache_pages` 4; the opening on page 0, read A `ReadAt (0, 64)` not flagged,
  read B `ReadAt (0, 64)`; two readers, each with one operation `ReadRangesInto [(128, 192)]`
  (pages 2 to 4), not flagged; the entropy of the 8-byte fixed input 0. Both readers are first
  polled in the same cycle; the one polled first starts the batch, the other joins all three of
  its pages. So the trace triggers the fault whatever order the runtime picks. Must fail: SR-I1,
  class `read_bytes`, on the joiner's read. In the repository tree it runs with no violation.

The patch of SR-F1:

```diff
diff --git a/runtime/src/utils/buffer/paged/cache.rs b/runtime/src/utils/buffer/paged/cache.rs
--- a/runtime/src/utils/buffer/paged/cache.rs
+++ b/runtime/src/utils/buffer/paged/cache.rs
@@ -255,9 +255,9 @@
             cache.cache(self.blob_id, page.as_ref(), self.pages[index]);
         }
         drop(cache);
-        for (tag, reader) in joiners {
+        for (_tag, reader) in joiners {
             if let Some(inbox) = &mut inboxes[reader] {
-                inbox.push_back((tag, result.clone()));
+                inbox.push_back((0, result.clone()));
             }
         }
         if let Some(inbox) = &mut inboxes[STARTER] {
```

- **SR-F2.** A cancelled joiner takes the starter's pages: the lost fetch of [15], in the batch
  path [22]. In `Drop for Subscription`, the expression `inboxes[self.reader]` becomes
  `inboxes[STARTER]`. A joiner that goes away then takes the starter's inbox, and the starter's
  read fails with `ReadFailed` once the batch ends without delivering its pages.

  Trace: `pages` 8, `cache_pages` 4; the opening as in SR-F1; two readers, each with one operation
  `ReadRangesInto [(128, 256)]` (pages 2 to 5), reader 0 not flagged and reader 1 flagged. The
  batch has four pages, so a joiner stays pending after its first poll. The test uses the first
  entropy `i` from 0 to 255 (the 8-byte fixed input `i`) whose run, in the repository tree, has
  `run_reads` equal to one read of each of the physical pages 2 to 5 and one cancellation: in
  that run reader 1 joined reader 0's batch and was cancelled. When the runtime polls reader 1
  first, it starts the batch and is cancelled in the same turn, and reader 0 reads pages 2 and 3
  again; those entropies are skipped. Must fail: SR-I2b, class `read_error`, on reader 0's read.
  In the repository tree it runs with no violation.

  The patch also breaks a joiner that completes and goes away before the starter, with no
  cancellation (SR-C14). Its trace is a cancellation; the proof is about the check, SR-I2b, not
  about the cancellation path alone.

The patch of SR-F2:

```diff
diff --git a/runtime/src/utils/buffer/paged/cache.rs b/runtime/src/utils/buffer/paged/cache.rs
--- a/runtime/src/utils/buffer/paged/cache.rs
+++ b/runtime/src/utils/buffer/paged/cache.rs
@@ -450,7 +450,7 @@
 impl Drop for Subscription {
     fn drop(&mut self) {
         // Stop deliveries to this reader, and free those it never took after unlocking.
-        let inbox = self.batch.state.lock().inboxes[self.reader].take();
+        let inbox = self.batch.state.lock().inboxes[STARTER].take();
         drop(inbox);
     }
 }
```

### Cases left out

| Id | Not covered | Reason |
|---|---|---|
| SR-X1 | Real threads, and the tokio and io_uring runtimes | [19]. The deterministic runtime runs one task at a time |
| SR-X2 | Several blobs sharing one cache, partial tail pages, live writes, `Writer` reads and snapshots | [2, 20]. One immutable sealed blob of full pages |
| SR-X3 | Corruption, read errors and other storage failures | [2, 20]. Storage never fails, so every read error is a violation (SR-I2b) |
| SR-X4 | Invalid, out-of-range and zero-length reads | [20]; SR-R4, SR-C9; Future work 46 |
| SR-X5 | `read_up_to`, `read_many_into`, the synchronous cache-only reads, replay and prefetch | [20] |
| SR-X6 | A standalone fetch kept alive for a pending survivor (the `waiters -= 1` arm of `PageFetchGuard::drop`) | Not reachable with a read held for one poll [22]; SR-C4 |
| SR-X7 | A batch whose starter is cancelled while joiners wait | Not reachable: a starter creates its batch in its first poll, and a flagged starter is dropped in that same turn, before any other read can join (SR-R10) |
| SR-X8 | An exact count of backend reads in the free phase | [12]. Recorded, and held only to the bound of one read per touching read in the evidence (SR-V10) |

### Choices made

| Id | Choice | Reason | What it costs |
|---|---|---|---|
| SR-C1 | The target is `shared_reads`, behind the feature `shared-reads`, in `runtime-all`, and runs on FuzzCorp only | The rule this spec has for the other new targets (SF-C8) | It does not run in `slow.yml` |
| SR-C2 | `PAGE_SIZE` is fixed at 64 | Small pages give many pages in a small blob, so reads cross pages and share them often. The intents fuzz the counts, not the page size [7] | Other page sizes, and pages that do not align with blob pages, are not explored |
| SR-C3 | The cache always holds fewer pages than the blob | [4] asks this of the baseline; keeping it for every input means every run can evict | A run where the whole blob fits in the cache is not explored |
| SR-C4 | SR-B3 and SR-F2 as decided on 2026-11-24 [22] | With a hold of one poll, the second waiter of a standalone fetch drives it to completion in the turn it registers: the mock's read yields once and wakes the shared future, and the next clone that polls a woken idle future polls it again (`runtime/src/mocks.rs`, `MigratingReadBlob::read_at_buf`; `utils/src/futures/shared.rs`, `Future for Shared::poll` and `ArcWake for Inner::wake_by_ref`). A batch is different. Its reads run in a `FuturesUnordered`, which yields once two of its reads woke themselves in one poll (`futures-util` 0.3.34, `src/stream/futures_unordered/mod.rs`, `FuturesUnordered::poll_next`: "If a future yields, we respect it and yield here."). So the starter's first drive starts two reads, and a joiner that drives the batch in the same cycle first polls the reads not started yet. With four pages or more, that drive starts two more reads and yields: the joiner stays pending, can be cancelled, and the starter survives (the trace of SR-F2). With three pages, the same drive finishes the batch, and the joiner completes (the trace of SR-F1). A joiner that joins later can stay pending in other schedules too | SR-X6: a fault in the standalone "keep the fetch for the others" branch is not detected |
| SR-C5 | The opening's read A is `read_at` or `read_into`, flagged in 1 draw of 2; read B is never flagged | Read A must install a standalone fetch, which only these two forms do: `read_ranges_into` never starts a standalone fetch, it starts or joins batches and joins standalone fetches (`cache.rs`, `CacheRef::read_after_misses`). Read B must survive [11] | None for the forms: `read_ranges_into` is covered as a joiner of the opening's fetch (read B) and as a starter and joiner of batches in the free phase. Read B is never cancelled, but it completes on its first poll in every run the prototype made, so a flag would not cancel it |
| SR-C6 | The free phase starts after the opening ends | SR-I3 counts the reads of the opening alone | The readers never overlap with the opening's two reads |
| SR-C7 | One deadline of 10 s of simulated time for the whole read phase | A prototype of this scenario at these bounds took at most 12 ms of simulated time over 2,000 random runs, and 5 ms with every count at its maximum. Time advances 1 ms per cycle and skips to the next sleeper when no task is ready (`runtime/src/deterministic.rs`, `Executor::advance_time`, `Executor::skip_idle_time` and `Executor::wake_until_progress`), so a lost wakeup reaches the deadline at once and a busy loop reaches it after 10,000 cycles | A reader that is only slow, but finishes after 10 s, is reported |
| SR-C8 | A free-phase operation is flagged in 1 draw of 4 | Most reads complete and are checked; cancellations are still common | Runs with many cancellations are rarer |
| SR-C9 | Every range has at least 1 byte, and the ranges of one read touch at most 4 pages | Zero-length ranges are left out [20]. `MAX_SPAN` = 4 admits batches of four pages, the size at which a joiner of the same cycle stays pending (SR-C4), which SR-B4 and the trace of SR-F2 need | Batches of more than four pages are not explored (Future work 39), and zero-length ranges are never issued (Future work 46) |
| SR-C10 | The number `read_ranges_into` returns is not judged | It depends on the cache state at the call, which the target does not model | A wrong count of served ranges is not detected |
| SR-C11 | The counting wrapper sits between the mock and the storage blob, and counts per physical page | [11] needs the count of one page while other pages are read; the mock counts all reads together (`MigratingReadBlob::reads`) | None |
| SR-C12 | The patches of SR-F1 and SR-F2 are fenced `diff` blocks at column 0 | The script of V9 refuses a second `diff` block indented by two spaces (SF-C12) | The two scripts read different block forms of one file |
| SR-C13 | SR-F1 also renames the loop binding `tag` to `_tag` | The workspace denies warnings, and the plant leaves `tag` unused | None: the rename changes no behaviour |
| SR-C14 | SR-F2 is the expression `self.reader` changed to `STARTER` in `Drop for Subscription` | It is one expression, it looks like a real slip, and its trace is a cancelled joiner. A cancellation-only plant would need new code | The patch also breaks a joiner that completes first, so its detection does not show that the cancellation path alone is checked |
| SR-C15 | The first operation of every reader starts in one hot page `h`, other than the opening's page; later operations use any pages (SR-R6) | [5] asks that the pages of one reader's reads overlap those of other readers; one shared page makes it hold for every decoded input, and it makes joins on page `h` common in the first cycle | The first reads of the readers all meet at one page; a free phase whose readers never meet is not explored |

### Expected findings

None. Reading `cache.rs` and running a prototype of this scenario over 2,000 random runs at these
bounds gave no violation. The two planted faults are deliberate and never applied in the
repository tree.

### Limits of the proof

What the steps of SR-V do not show [18]:

- Real-thread races, lock-order bugs, and the tokio and io_uring runtimes (SR-X1) [19].
- A standalone fetch kept alive for a pending survivor, and a batch whose starter is cancelled
  while joiners wait (SR-X6, SR-X7). Faults on those two paths are not detected [22].
- Schedules come only from the runtime's RNG. A schedule that no seed gives is never run, and the
  target cannot ask for one.
- The behaviour reach of SR-B is measured on one short run. It shows that each behaviour occurs,
  not how often, and not every way it can occur.
- Each planted fault proves only its named check. SR-F2 does not show that the cancellation path
  alone is checked (SR-C14). The negative controls show that each invariant can fire, at the seam.
- Batch read counts are not asserted (SR-X8), so a batch that reads a page more often than the
  cache's contract allows is not reported.
- One blob of full pages, successful storage, three read forms (SR-X2 to SR-X5).
- A clean smoke run does not show the absence of faults.

## Validation after implementation

For every target:

1. Build with and without `--features runtime-all` using the pinned nightly. The build without
   features must list only the three existing targets.
2. Smoke-run each new target on macOS for about 10 minutes with `-timeout=60`.
3. Triage every failure. Harness bugs are fixed in the harness. A real divergence is written up in
   `runtime/fuzz/FINDINGS.md` and reported to the maintainer, who decides whether it gets an
   allowlist entry. `storage_faults` has no allowlist (SF-R22).
4. No commits unless asked.

### End-to-end verification of `storage_faults`

All steps below make acceptance [22 to 26]. `N` stands for the pinned nightly, currently
`nightly-2026-11-12`. Commands run from the repo root.

| # | Command or check | Result to see | Proves |
|---|---|---|---|
| V1 | `git status --short runtime/src`, and `git diff --stat 9cfc5fb66ed0c21d340ee5d1e86f871372bcac45 75c3d69a694397e440524e7cac5a9725172060e4 -- runtime/src`: the commit before the build and the commit that holds the build (SF-R21a). For a later change to the target, the commit before that change and the commit that holds it | Both print nothing: no change under `runtime/src` | SF-R1 |
| V2 | Read `runtime/fuzz/fuzz_targets/storage_faults.rs` | Only imports and the typed `fuzz_target!` entry | SF-R19 |
| V3 | `cargo +N fuzz build --fuzz-dir runtime/fuzz --features runtime-all`, then the same without `--features` | Both succeed. The second builds only `buffer`, `blob_integrity` and `blob_creation` | SF-C8, [26] |
| V4 | Clippy with `-D warnings` on `runtime/fuzz/Cargo.toml` with `--all-targets --features runtime-all`, and `rustfmt --check` on the changed files, both with the pins of `.github/toolchains.toml` | Clean | fuzzing guide |
| V5 | `cargo +N test --manifest-path runtime/fuzz/Cargo.toml` | The regression suite of SF-R23 passes, with one negative control per invariant, each naming its invariant | every invariant SF-I1a to SF-I18b, SF-R5, SF-R6, SF-R9, SF-R11, SF-R13, SF-R13a, SF-R24, SF-R25, SF-R30, SF-R31, SF-R32, [23] |
| V6 | The five checks of SF-R21a: the pinned decoding and model behaviour (in V5); the move check below; the old and the new binary over the fixed inputs of V8; `cargo +N fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_differential "$(mktemp -d)" -- -max_total_time=600 -timeout=60` | The pinned values match. The move check prints `MOVE OK` and `CONTROL OK` and exits 0, and its list holds only the lines that SF-R21a item 2 names. Both binaries end the same way on every fixed input. The smoke run shows no failure class that is new | SF-R21, SF-R21a |
| V7 | `cargo +N fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_faults "$(mktemp -d)" -- -max_total_time=600 -timeout=60` | From an empty corpus: no crash, no hang, no out-of-memory, no invariant fires. The executions per second are reported | [24], SF-R5, SF-I17 |
| V8 | Rule M1: write the 257 fixed inputs to files, then for each file `cargo +N fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_faults <file> -- -runs=100`. Rule M2: `cargo +N test --release --manifest-path runtime/fuzz/Cargo.toml -- --ignored run_time` | M1: every `Executed <file> in <T> ms` line has `T` at or below 5000. M2: the median of each of the five heavy inputs is at or below 50 ms. On the acceptance host | SF-R29, SF-G4 |
| V9 | The plant script below, `bash <file> N` | The script prints `PATCH OK` and `PLANT OK` and exits 0: in the worktree the plant input fails with `[crash_image]` and SF-I11, and a fuzz run from an empty corpus fails the same way within 300 seconds and writes one artifact. The artifact passes in the repository tree. The worktree and the temporary directory are removed, and `runtime/src` holds no change | SF-R27, SF-R28, SF-I11, [25] |
| V10 | V3 passed and `storage_faults` is in `runtime-all` | The target is ready for the next FuzzCorp bundle. Uploading is a separate, manual step | [26] |

The fixed inputs of V8:

```bash
D="$(mktemp -d)"; : > "$D/empty"
python3 -c 'import sys,struct
for i in range(256): open(f"{sys.argv[1]}/seed{i:03}","wb").write(struct.pack("<Q",i))' "$D"
```

The move check of V6 (SF-R21a item 2), a script. Copy the block into a file and run the file with `bash` from the repo root. Do not paste
it into an interactive shell: a failed check ends the shell it runs in.
`BASE` is the commit before the move and `MOVE` the commit that holds it. `changed.txt` holds
the lines that had to change, old and new form: the 13 rows below are the whole list. The
script prints `MOVE OK` exactly when every listed line occurs as often as its row says and the
old file is an interleaving of the two new files. It then prints `CONTROL OK` and exits 0
exactly when the same check fails on a copy with one of two identical callers deleted:

```bash
set -euo pipefail                         # a file, run from the repo root: bash <file>
BASE=9cfc5fb66ed0c21d340ee5d1e86f871372bcac45
MOVE=75c3d69a694397e440524e7cac5a9725172060e4
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
git show "${BASE}:runtime/fuzz/fuzz_targets/storage_differential.rs" > "$T/old.rs"
git show "${MOVE}:runtime/fuzz/fuzz_targets/storage_differential.rs" > "$T/stay.rs"
git show "${MOVE}:runtime/fuzz/src/storage_model.rs" > "$T/moved.rs"
# The lines that had to change: the file, how many times the line occurs in it, the line.
cat > "$T/changed.txt" <<'EOF'
old 1 Blob, BlobLayout, BlobVersion, DEFAULT_BLOB_LAYOUT, Error, IoBuf, IoBufMut, IoBufs, IoBufsMut,
old 1 ReadOptions, Runner as _, Storage, WriteOptions, deterministic, tokio,
old 1 ops::RangeInclusive,
old 1 fn rf2_note(&self) -> String {
old 1 format!("; this blob is affected by {}", ALLOWLIST[RF2].note())
old 1 let note = self.model.blobs[&generation].rf2_note();
old 2 let note = model.rf2_note();
stay 1 Blob, BlobLayout, BlobVersion, Error, IoBuf, IoBufMut, IoBufs, IoBufsMut, ReadOptions,
stay 1 Runner as _, Storage, WriteOptions, deterministic, tokio,
stay 1 let note = self.model.blobs[&generation].rf2_note(&ALLOWLIST[RF2].note());
stay 2 let note = model.rf2_note(&ALLOWLIST[RF2].note());
moved 1 fn rf2_note(&self, entry: &str) -> String {
moved 1 format!("; this blob is affected by {entry}")
EOF
cat > "$T/move_check.py" <<'EOF'
import re, sys
from collections import Counter

def norm(path):
    out = []
    for line in open(path):
        line = re.sub(r'^pub(\([a-z]+\))? ', '', line.strip())
        if line and not line.startswith(('use ', '//')):
            out.append(line)
    return out

names = ('old', 'stay', 'moved')
files = dict(zip(names, map(norm, sys.argv[1:4])))
listed = Counter()
for row in open(sys.argv[4]):
    name, count, text = row.rstrip('\n').split(' ', 2)
    listed[name, text] = int(count)
texts = {text for _, text in listed}
ok = True
for name in names:
    for text in sorted(texts):
        seen = files[name].count(text)
        if seen != listed[name, text]:
            print(f'{name}: {seen} of {listed[name, text]}: {text}')
            ok = False
old, a, b = ([line for line in files[name] if line not in texts] for name in names)
ok = ok and len(old) == len(a) + len(b)
if ok:
    reach = {0}
    for i, line in enumerate(old):
        reach = {j + 1 for j in reach if j < len(a) and a[j] == line} | \
                {j for j in reach if i - j < len(b) and b[i - j] == line}
        if not reach:
            print(f'first old line with no place: {i + 1}: {line}')
            break
    ok = bool(reach)
print('MOVE OK' if ok else f'MOVE BROKEN: old {len(old)} lines, stay {len(a)}, moved {len(b)}')
sys.exit(0 if ok else 1)
EOF
python3 -I "$T/move_check.py" "$T/old.rs" "$T/stay.rs" "$T/moved.rs" "$T/changed.txt"
# Control: with one of the two identical callers deleted from the new target file, the check must fail.
awk '/let note = model.rf2_note\(&ALLOWLIST/ && !cut {cut = 1; next} {print}' "$T/stay.rs" > "$T/control.rs"
if python3 -I "$T/move_check.py" "$T/old.rs" "$T/control.rs" "$T/moved.rs" "$T/changed.txt" > "$T/control.log"; then
    echo "CONTROL BROKEN"; exit 1
fi
grep -q '^stay: 1 of 2: let note = model.rf2_note' "$T/control.log"
echo "CONTROL OK"
```

V9 is a script. Copy the block into a file and run the file with `bash` from the repo root. Do not paste
it into an interactive shell: a failed check ends the shell it runs in. Its argument is the
pinned nightly, for example `bash plant.sh nightly-2026-11-12`. It exits 0 and prints `PLANT OK`
exactly when every step below holds. On any other end, an interrupt included, it removes the
worktree and its temporary directory and exits with a failure.

The plant of V9:

```bash
set -euo pipefail                         # a file, run from the repo root: bash <file> <pinned nightly>
N="$1"; T="$(mktemp -d)"; W="$T/plant"; P="$T/plant.patch"
cleanup() { [ ! -e "$W" ] || git worktree remove --force "$W"; rm -rf "$T"; }
trap cleanup EXIT
trap 'echo "V9 FAILED at line $LINENO"' ERR
# SF-R27: the patch is the one fenced diff block of this spec, inside SF-R27, indented by two spaces.
test "$(grep -c '^  ```diff$' runtime/fuzz/SPEC.md)" = 1
awk '/^- \*\*SF-R27\.\*\*/ {rule = 1} /^- \*\*SF-R28\.\*\*/ {rule = 0}
     rule && /^  ```diff$/ {on = 1; next} /^  ```$/ {on = 0} on {print substr($0, 3)}' runtime/fuzz/SPEC.md > "$P"
# Its shape: two lines out of deterministic.rs, one line into faulty.rs, and that line is the attribute.
test "$(git apply --numstat "$P")" = "$(printf '0\t2\truntime/src/deterministic.rs\n1\t0\truntime/src/storage/faulty.rs')"
grep -qx '+    #\[allow(dead_code)\]' "$P"
echo "PATCH OK"
# SF-R28: applied in the disposable worktree only. No RUSTFLAGS, no --cap-lints.
git worktree add --detach "$W" HEAD
rsync -a --exclude target --exclude corpus --exclude artifacts runtime/fuzz/ "$W/runtime/fuzz/"
git -C "$W" apply "$P"
# A command that must fail in the worktree, with [crash_image] and SF-I11 in one line of its output.
caught() {
    if (cd "$W" && "$@") > "$T/log" 2>&1; then echo "not caught: $*"; return 1; fi
    grep -F '[crash_image]' "$T/log" | grep -F 'SF-I11' | cut -c 1-100 || { tail -n 20 "$T/log"; return 1; }
}
caught cargo "+$N" test --manifest-path runtime/fuzz/Cargo.toml plant
mkdir "$T/corpus" "$T/found"
caught cargo "+$N" fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_faults "$T/corpus" \
    -- -max_total_time=300 -artifact_prefix="$T/found/"
test "$(ls "$T/found" | grep -c '^crash-')" = 1                                    # exactly one artifact
# The artifact must pass in the repository tree, where the plant is not applied.
cargo "+$N" fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_faults "$T"/found/crash-*
cleanup
test -z "$(git status --short runtime/src)"                                       # no plant, no annotation
echo "PLANT OK"
```

What these steps do not show is in [Limits of the proof](#limits-of-the-proof).

### End-to-end verification of `shared_reads`

All steps below make acceptance [13 to 18]. `N` stands for the pinned nightly, currently
`nightly-2026-11-12`; SR-V7 also needs its `llvm-tools-preview` component. Commands run from the
repo root.

| # | Command or check | Result to see | Proves |
|---|---|---|---|
| SR-V1 | Record the base revision before the build starts (`git rev-parse HEAD`). At acceptance, with the build uncommitted: `git status --short runtime/src` and `git diff --stat <base> -- runtime/src`. A comparison between two commits after a later commit is extra evidence, not part of acceptance | Both print nothing: no change under `runtime/src`, committed or not, since the base revision | SR-R1 |
| SR-V2 | Read `runtime/fuzz/fuzz_targets/shared_reads.rs` | Only imports and the typed `fuzz_target!` entry | SR-R16 |
| SR-V3 | `cargo +N fuzz build --fuzz-dir runtime/fuzz --features runtime-all`, then the same without `--features` | Both succeed. The second builds only `buffer`, `blob_integrity` and `blob_creation` | SR-C1 |
| SR-V4 | Clippy with `-D warnings` on `runtime/fuzz/Cargo.toml` with `--all-targets --features runtime-all`, and `rustfmt --check` on the changed files, both with the pins of `.github/toolchains.toml` | Clean | fuzzing guide |
| SR-V5 | `cargo +N test --manifest-path runtime/fuzz/Cargo.toml --test shared_reads_acceptance` | The suite of SR-R18 passes: the fixed inputs run clean and measure SR-I1 to SR-I3, each fixed input run twice gives equal outcomes, one negative control per invariant names its invariant, the samplers give their fixed values, and both plant inputs run clean | SR-I1 to SR-I4, SR-R5 to SR-R8, SR-R15, SR-R17, [7, 13, 16] |
| SR-V6 | The fixed inputs: the empty input and the 256 inputs of 8 bytes that hold `i` as a little-endian `u64`, for `i` from 0 to 255. The suite builds them in memory; no file is needed | Used by SR-V5 items 1 and 2, and as the entropies of SR-F2 | SR-R17, [16] |
| SR-V7 | The reach script below, `bash <file> N` | `REACH OK` and exit 0: from an empty corpus, a 300-second run reaches SR-B1 to SR-B4. The script prints the lines and hit counts it used, which go into the evidence | SR-R19, [14] |
| SR-V8 | The plant script below, `bash <file> N F1`, then `bash <file> N F2` | Each prints `PATCH OK` and `PLANT F1 OK` or `PLANT F2 OK` and exits 0: in the worktree the plant test fails with the named class and invariant, a fuzz run from an empty corpus fails the same way within 300 seconds and writes one artifact, the artifact passes in the repository tree, and `runtime/src` holds no change afterwards | SR-F1, SR-F2, SR-I1, SR-I2b, [15] |
| SR-V9 | `cargo +N fuzz run --fuzz-dir runtime/fuzz --features runtime-all shared_reads "$(mktemp -d)" -- -max_total_time=600 -timeout=60` | From an empty corpus: no crash, no hang, no out-of-memory, no invariant fires. The executions per second are reported | SR-I1 to SR-I4, [17] |
| SR-V10 | `cargo +N test --manifest-path runtime/fuzz/Cargo.toml --test shared_reads_acceptance -- --ignored batch_read_counts --nocapture` | The test passes: no page is read more often than the free-phase reads that touch it. The per-page counts of every fixed input go into the build report, with the reasons of "Not judged" that each run admits: eviction in every run, and a cancelled sole standalone waiter or batch starter only in a run with a cancellation. The report does not have to say which reason produced a given duplicate: the public API does not show it | [12], [22] |
| SR-V11 | SR-V3 passed and `shared_reads` is in `runtime-all` | The target is ready for the next FuzzCorp bundle. Uploading is a separate, manual step | SR-C1 |

The reach script of SR-V7. Copy the block into a file and run the file with `bash` from the repo
root. It finds each line of SR-R19 by its text, so it holds no line numbers; when a text is
missing or occurs more than once, it stops, and SR-R19 must then be written again from the
current `cache.rs`.

```bash
set -euo pipefail                         # a file, run from the repo root: bash <file> <pinned nightly>
N="$1"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rm -rf runtime/fuzz/coverage/shared_reads                 # no profile of an earlier run is merged in
mkdir "$T/corpus"
cargo "+$N" fuzz run --fuzz-dir runtime/fuzz --features runtime-all shared_reads "$T/corpus" \
    -- -max_total_time=300 -timeout=60
cargo "+$N" fuzz coverage --fuzz-dir runtime/fuzz --features runtime-all shared_reads "$T/corpus"
BIN="$(find target -path '*/coverage/*/release/shared_reads' -type f)"
test "$(printf '%s\n' "$BIN" | grep -c .)" = 1                       # exactly one coverage binary
COV="$(ls "$(rustc "+$N" --print sysroot)"/lib/rustlib/*/bin/llvm-cov)"
"$COV" export -format=lcov -instr-profile=runtime/fuzz/coverage/shared_reads/coverage.profdata \
    "$BIN" > "$T/all.lcov"
cat > "$T/reach.py" <<'EOF'
import sys
lcov, src = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines()
hits, cur = {}, None
for row in open(lcov):
    row = row.strip()
    if row.startswith('SF:'):
        cur = row[3:].endswith(src)
    elif cur and row.startswith('DA:'):
        n, c = row[3:].split(',')[:2]
        hits[int(n)] = int(c)
assert hits, 'no coverage record of ' + src

def line(text):
    found = [i + 1 for i, l in enumerate(lines) if text in l]
    assert len(found) == 1, f'{len(found)} lines hold: {text}'
    return found[0]

def count(n):
    assert n in hits, f'line {n} is not instrumented'
    return hits[n]

join_fetch = line('let entry = o.into_mut();')
join_fetch_batched = line('let fetch = PageFetchGuard::new(&self.cache, key, entry.fetch.clone());')
joining = line('state.inboxes.push(Some(VecDeque::new()));')
delivery = line('inbox.push_back((tag, result.clone()));')
gone = line('let Entry::Occupied(mut current) = cache.page_fetches.entry(self.key) else {') + 1
assert lines[gone - 1].strip() == 'return;', 'the line after the guard lookup is not `return;`'
inbox = line('if let Some(inbox) = &mut inboxes[reader] {')
checks = {
    'SR-B1': count(join_fetch) > 0 or count(join_fetch_batched) > 0,
    'SR-B2': count(joining) > 0 and count(delivery) > 0,
    'SR-B3': count(gone) > 0,
    'SR-B4': count(inbox) > count(delivery),
}
for name, n in [('join_fetch', join_fetch), ('join_fetch_batched', join_fetch_batched),
                ('joining', joining), ('delivery', delivery), ('gone', gone), ('inbox', inbox)]:
    print(f'{name}: {src}:{n} hits {count(n)}')
for b, ok in checks.items():
    print(b, 'OK' if ok else 'NOT REACHED')
covered = [n for n, c in hits.items() if c > 0 and n < line('mod tests {')]
total = [n for n in hits if n < line('mod tests {')]
print(f'{src}: {len(covered)} of {len(total)} instrumented lines before the test module')
print('REACH OK' if all(checks.values()) else 'REACH FAILED')
sys.exit(0 if all(checks.values()) else 1)
EOF
python3 -I "$T/reach.py" "$T/all.lcov" runtime/src/utils/buffer/paged/cache.rs
```

The plant script of SR-V8. Copy the block into a file and run the file with `bash` from the repo
root. Do not paste it into an interactive shell: a failed check ends the shell it runs in. Its
arguments are the pinned nightly and the plant, `F1` or `F2`. It exits 0 and prints
`PLANT <id> OK` exactly when every step holds. On any other end, an interrupt included, it removes
the worktree and its temporary directory and exits with a failure.

```bash
set -euo pipefail          # a file, run from the repo root: bash <file> <pinned nightly> <F1|F2>
N="$1"; ID="$2"; T="$(mktemp -d)"; W="$T/plant"; P="$T/plant.patch"
case "$ID" in
    F1) CLASS='[read_bytes]'; INV='SR-I1';  TEST=plant_f1_input_runs_clean; ADDED=2; REMOVED=2 ;;
    F2) CLASS='[read_error]'; INV='SR-I2b'; TEST=plant_f2_input_runs_clean; ADDED=1; REMOVED=1 ;;
    *) echo "usage: bash <file> <pinned nightly> F1|F2"; exit 2 ;;
esac
cleanup() { [ ! -e "$W" ] || git worktree remove --force "$W"; rm -rf "$T"; }
trap cleanup EXIT
trap 'echo "SR-V8 FAILED at line $LINENO"' ERR
# The patch is the fenced diff block at column 0 right after the line "The patch of SR-<id>:".
awk -v mark="The patch of SR-$ID:" '$0 == mark {want = 1; next}
     want && /^```diff$/ {on = 1; next} on && /^```$/ {exit} on {print}' runtime/fuzz/SPEC.md > "$P"
test -s "$P"
test "$(git apply --numstat "$P")" = "$(printf '%s\t%s\t%s' "$ADDED" "$REMOVED" runtime/src/utils/buffer/paged/cache.rs)"
echo "PATCH OK"
# Applied in the disposable worktree only. No RUSTFLAGS, no --cap-lints.
git worktree add --detach "$W" HEAD
rsync -a --exclude target --exclude corpus --exclude artifacts --exclude coverage \
    runtime/fuzz/ "$W/runtime/fuzz/"
git -C "$W" apply "$P"
# A command that must fail in the worktree, with the class and the invariant in one line of output.
caught() {
    if (cd "$W" && "$@") > "$T/log" 2>&1; then echo "not caught: $*"; return 1; fi
    grep -F "$CLASS" "$T/log" | grep -F "$INV" | cut -c 1-100 || { tail -n 20 "$T/log"; return 1; }
}
caught cargo "+$N" test --manifest-path runtime/fuzz/Cargo.toml --test shared_reads_acceptance "$TEST"
mkdir "$T/corpus" "$T/found"
caught cargo "+$N" fuzz run --fuzz-dir runtime/fuzz --features runtime-all shared_reads "$T/corpus" \
    -- -max_total_time=300 -artifact_prefix="$T/found/"
test "$(ls "$T/found" | grep -c '^crash-')" = 1                                    # exactly one artifact
# The artifact must pass in the repository tree, where the plant is not applied.
cargo "+$N" fuzz run --fuzz-dir runtime/fuzz --features runtime-all shared_reads "$T"/found/crash-*
cleanup
test -z "$(git status --short runtime/src)"                                       # no plant left
echo "PLANT $ID OK"
```

What these steps do not show is in the limits of `shared_reads` (Limits of the proof, under
Target `shared_reads`).

## Future work

Each choice below narrows coverage or scope. The table records why it was made and how to lift it.

| # | Choice | What it costs | How to lift it |
|---|---|---|---|
| 1 | io_uring excluded | The custom executor and `storage/iouring.rs` / `network/iouring.rs` are never fuzzed | Add `iouring::Runner` as a third backend in `storage_differential` under `cfg(target_os = "linux")`. Run on hosts that allow io_uring (Docker's default seccomp profile blocks it) |
| 2 | Public API only (`runtime/src` off limits) | io_uring internals (`Waiters`, `TimeoutWheel`, `ReadAtRequest` against the simulated kernel in `iouring/request.rs`, `WriteBuffers`) are unreachable, and tokio storage needs a full `Runner::start` | Add `cfg(fuzzing)` entry points one by one with approval, then fuzz those modules directly |
| 3 | Fresh tokio runner per input | Low exec/s. On Linux every start runs `syncfs` over the whole filesystem | Use a persistent runtime thread with a fresh partition per input and forwarded panics, or a standalone storage hook (see 2) |
| 4 | Sequential operations only | Partly lifted: `shared_reads` runs concurrent readers of the page cache over one immutable blob on the deterministic runtime. Still no concurrency: the AIO context pool, blocking-pool contention, `Pending`/`Tracker` races, reads overlapping writes, syncs in flight with writes | Start with concurrent read-only groups on stable ranges and a sync in flight. Then allow concurrent mutations with an oracle relaxed for overlapping ranges. Reproduce failures with a fixed worker count and `rr` |
| 5 | Faults off in `storage_differential`; no faults on tokio | Partly lifted: `storage_faults` exercises failed, partial and torn writes on the deterministic runtime, judged by the model only. On tokio, recovery after a failed or torn write is still never exercised | For tokio, inject faults below the runtime (dm-flakey, FUSE, `LD_PRELOAD`) |
| 6 | tokio restarts are clean | Partly lifted: `storage_faults` simulates crashes with tearing on the deterministic runtime. The page cache survives a tokio restart, so real crash tearing never happens on tokio | Simulate crashes with block-level write logging (dm-log-writes, CrashMonkey style), or kill a child process in the middle of an operation |
| 7 | Size caps (1 MiB offsets, 64 KiB lengths) | Large-file paths are missed: offsets past 4 GiB, `EFBIG` at ext4's 16 TiB limit on the fused `SYNC` write, which poisons the blob across opens | Add a tokio-only large-offset mode on sparse files, judged by the model, with the memory side skipped |
| 8 | Overflow-edge offsets on reads only | Overflow handling in `write_at` and `resize` is not explored | Same tokio-only mode as 7 |
| 9 | Only documented error variants asserted | Variant inconsistencies (`Io(UnexpectedEof)` against `BlobInsufficientLength`) go unreported | Add a strict mode behind a feature, and propose tightening the trait docs upstream |
| 10 | Allowlist | Entries can hide neighbouring bugs | Keep entries narrow and remove them when `runtime/src` is fixed. Add a feature that disables the allowlist for periodic strict runs |
| 11 | Hangs left to libFuzzer's `-timeout` | Hangs (a leaked hold blocking `Runner::start`, a stuck blocking-pool operation) are reported late and without context | Add a per-operation watchdog that panics with the operation index |
| 12 | Small name pool, no case variants, no arbitrary names | Unusual hex names in `scan`, and stray files in partition directories (`.DS_Store` yields `PartitionCorrupt`), are not explored | Add an arbitrary-names mode, and seed stray files into the tokio partition directory before `scan` |
| 13 | No on-disk image seeding on tokio | Header resolution of arbitrary file contents on tokio is untested, including the unchecked `metadata.len() - data_offset` (`storage/tokio/mod.rs`, `Storage::open_versioned`; `storage/tokio/blob.rs`, `Blob::complete`). `blob_creation` covers this for `mocks::Storage` only | Before `Open`, write arbitrary raw bytes to `<dir>/<partition>/<hex(name)>`. This needs no change under `runtime/src` |
| 14 | Filesystem decides the Linux I/O paths | On tmpfs, O_DIRECT, AIO and `RWF_DONTCACHE` may fall back silently | Point `COMMONWARE_RUNTIME_FUZZ_DIR` at ext4 or xfs on fuzzcorp, and check `storage/tokio/blob/aio.rs` in the lineage coverage |
| 15 | One tokio worker thread | Fewer interleavings in the executor and supervision code | Vary `worker_threads` per input once 4 is in place |
| 16 | `iobuf` built for 64-bit only | The 32-bit descriptor (128-byte tail threshold) goes unfuzzed | Add an i686 build where fuzzcorp supports it |
| 17 | No Miri replay | Undefined behaviour that ASan cannot see (uninitialised `&mut [u8]`, provenance) is missed | Replay the corpora under Miri through a test that decodes inputs with the same `Arbitrary` code |
| 18 | `iobuf` single-threaded | Races in clone, drop and promotion (`owner.rs` compare-exchange) are not fuzzed | Add a multi-threaded stress mode or a Shuttle model. Loom already covers parts of `owner.rs` |
| 19 | Network differential deferred | `Sink`/`Stream` semantics on tokio (poisoning after cancel, partial reads, `peek`) are not compared against the deterministic network | Add a target that runs one script over loopback TCP on tokio and over the deterministic network |
| 20 | Paged-buffer oracles deferred | Partly lifted: `shared_reads` checks `Sealed::read_at`, `read_into` and `read_ranges_into` against a model, with concurrent readers of one cache. `recoverable_prefix_len`, the writer's reads and `mocks::ReadGate` stay unchecked. `buffer` discards every result | Add oracles to `buffer` and a paged-writer target with a model |
| 21 | No coverage target | Nothing shows when the targets plateau | Track per-file line coverage for `storage/tokio/*`, `storage/memory/*` and `iobuf/*` from fuzzcorp lineage coverage, and act on the gaps |
| 22 | No sweep of leftover tokio directories | A timeout, out-of-memory kill or backend panic leaves a `commonware_runtime_fuzz_<pid>_<n>` directory that later processes never remove, because their pid differs | Remove stale `commonware_runtime_fuzz_*` directories of dead processes at startup |
| 23 | Linux-only tokio paths checked by reading only | Native AIO `read_many`, O_DIRECT reads, `RWF_DONTCACHE` and the startup `syncfs` have not been executed under the harness; all smoke runs were on macOS | Run a short Docker-Linux smoke run of `storage_differential` before the first fuzzcorp deployment |
| 24 | `storage_faults`: a crash only between two sequential operations (SF-R4, SF-X4) | A crash inside a write, resize or sync, a dropped operation future, and faults under concurrent operations are not explored | Park an operation and crash while it is pending, as `DelayedSyncContext` and `poll_interrupted` do in `storage/fuzz`; then add concurrency as in row 4 |
| 25 | `storage_faults`: no crash inside an accepted `start_sync` (SF-X7) | The pending-sync marker path of the fault injection (`runtime/src/storage/faulty.rs`, `PendingMutation::Sync`, `PendingSync`, and the `PendingMutation::Sync` arm of `Storage::crash`) never sees a sync that is still running at the crash | A backend whose `start_sync` returns before the sync completes: with the parked-sync adapter of row 24, or on tokio with row 6 |
| 26 | `storage_faults`: small sizes (blobs up to 2304 bytes, writes up to 256 bytes) and a small name pool | Large blobs, long logs and unusual names under faults are not explored | Raise `MAX_SIZE` and `MAX_WRITE` once the 50 ms measurement shows the room; names as in row 12 |
| 27 | `storage_faults`: the trigger of RF-2 is not issued (SF-X5) | An empty write past the end is never combined with faults or crashes | Remove the clamp when #5752 is fixed, together with the RF-2 entry of `storage_differential` |
| 28 | `storage_faults`: the oracle accepts any subset of an unsynced write and ignores the armed retention rate and mode (SF-R12) | An injector that keeps bytes outside its own policy, for example a non-prefix under `Prefix`, is not reported | Add a strict injector check behind a feature that also holds each write to its armed mode and to the 0 and 100 percent endpoints |
| 29 | `storage_faults`: an armed operation that does not fail is accepted (SF-C7) | An injector that stops injecting is silent | Track the count of injected failures per kind in a campaign, or check the lineage coverage of `runtime/src/storage/faulty.rs` |
| 30 | `storage_faults`: the images seen are the ones the deterministic injector produces | Images the contract allows but the injector never makes are not seen: it tears only writes issued under a write fault and drops every other unsynced write whole | Extend the injector upstream (a default tearing policy), or lift rows 5 and 6 for tokio |
| 31 | `storage_faults`: one planted runtime fault (SF-R27) | The end-to-end proof on `runtime/src` covers the reopen cut only; the other invariants are proven at the seam | Add more plant diffs to this spec, one per durability rule, each in a rule of its own and with a mark of its own for the script of V9, and run each in a disposable worktree |
| 32 | `storage_faults`: durability is seen only at a crash or a reopen (SF-R15, SF-R17) | A failure that makes data durable too early is not detected: a failed sync that syncs, a failed open that takes its reopen cut, a fused write with a sync fault that persists its bytes | Compare the durable image after every operation through a test accessor such as `Context::logical_blob` (`runtime/src/deterministic.rs`). This leaves the public contract (SF-X9), so it needs a separate decision |
| 33 | `shared_reads`: a backend read is held for one poll (SR-C4, SR-X6) [22] | A standalone fetch is never kept alive for a pending survivor, so a fault in the branch of `PageFetchGuard::drop` that keeps the fetch for the other waiters is not detected | A fuzz-side blob wrapper over `MigratingReadBlob` that holds a read for 1 to k turns, with k from the input. It changes the construction [4, 19], so it needs a separate decision |
| 34 | `shared_reads`: a cancelled read is dropped right after its first poll [6] (SR-X7) | A batch starter is never cancelled while joiners wait | Cancel a read after its n-th poll, with n from the input; together with row 33. Needs a separate decision |
| 35 | `shared_reads`: no read failure and no live writer [2] (SR-X2, SR-X3) | A failed page read with joined readers (`Batch::fail`, the error of a standalone fetch) and reads during appends are not explored | Arm the deterministic read fault around chosen reads as a non-baseline choice, with an oracle that every joined read fails and no page is cached; then reads through a live `Writer` and its snapshots |
| 36 | `shared_reads`: one blob, full pages, three read forms [20] (SR-X2, SR-X5) | Several blobs in one cache, a partial tail, `read_up_to`, `read_many_into`, the synchronous reads, replay and prefetch are not explored | Add them one at a time, each with its model |
| 37 | `shared_reads`: free-phase backend read counts are held only to the bound of one read per touching read, in the evidence (SR-X8, SR-V10) [12] | A page read more often than eviction and the cancellations of the run explain, but still within that bound, is not reported | Model the cache's residency (its Clock2Q+ eviction) and the cancellations of each run, predict the exact count of every page, and assert it |
| 38 | `shared_reads`: schedules come only from the runtime's RNG | A task order that no seed gives is never run | An input-driven task order needs a hook in the deterministic runtime (see row 2) |
| 39 | `shared_reads`: `PAGE_SIZE` 64, at most 16 pages, a cache always smaller than the blob, reads over at most 4 pages (SR-C2, SR-C3, SR-C9) | Other page sizes, a blob that fits in the cache, and longer batches are not explored | Fuzz the page size and raise the bounds after the executions per second of SR-V9 are known |
| 40 | `shared_reads`: deterministic runtime only [19] (SR-X1) | Real-thread races and lock-order bugs of the page cache are not explored | Run the same scenario on tokio with several workers, with the same model; replay failures with a fixed worker count |
| 41 | `shared_reads`: the free phase starts after the opening ends (SR-C6) | Interleavings of the opening's two reads with the free readers are not explored | Spawn the readers before the opening's reads resolve, and count SR-I3 per fetch generation instead of over the opening as a whole |
| 42 | `shared_reads`: the number `read_ranges_into` returns is not judged (SR-C10) | A wrong count of ranges served without a blob read is not detected | Model the cache's contents at the call (the pages resident when the read takes its first lock) and assert the count against it; the eviction policy makes this model the costly part |
| 43 | `shared_reads`: a free-phase operation is flagged in 1 draw of 4, and the opening's read A in 1 draw of 2 (SR-C5, SR-C8) | Runs where most reads are cancelled are rare | Draw the flag rate per run from the input, as one more sampled field |
| 44 | `shared_reads`: the planted fault SR-F2 also fires without a cancellation (SR-C14) | The end-to-end proof does not show that the cancellation path alone is checked | A plant that acts only when a subscription is dropped with pages still undelivered, written as a diff in this spec |
| 45 | `shared_reads`: the first operation of every reader starts in one hot page (SR-C15) | A free phase whose readers never meet is not explored; it reaches no join, so it adds little | Draw per input whether the hot page is used |
| 46 | `shared_reads`: only valid reads of at least one byte inside the blob (SR-X4, SR-C9) [20] | Zero-length ranges, reads that end past the blob, offsets that overflow, and range lists that `read_ranges_into` rejects are never issued, so the paths that refuse them (`validate_read_ranges`, the bounds checks of `View::read_into`) are not reached under concurrent readers | Add these reads as non-baseline operations, judged by their documented results: a zero-length range that starts at or before the blob's end succeeds and counts as served (`Sealed::read_ranges_into`); a read or range that ends past the blob, a zero-length one that starts past it included, returns `BlobInsufficientLength`; an overflowing offset returns `OffsetOverflow` (`runtime/src/utils/buffer/paged/view.rs`, `View::read_into`); a range list returns the same two errors for the same cases (`runtime/src/utils/buffer/paged/mod.rs`, `validate_read_ranges`). Range lists whose ranges overlap stay out: the method documents a panic for them |
