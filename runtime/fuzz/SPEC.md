# Runtime fuzz harness: storage differential and iobuf

Status: implemented in `runtime/fuzz/fuzz_targets/storage_differential.rs` and
`runtime/fuzz/fuzz_targets/iobuf.rs`. Divergences found so far are in `runtime/fuzz/FINDINGS.md`.

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

## Non-goals for this iteration

- The `iouring` runtime, its storage and network, and its internal state machines.
- The network traits (`Network`, `Listener`, `Sink`, `Stream`).
- Oracles for the existing paged-buffer targets (`buffer`, `blob_integrity`).
- Any change under `runtime/src`. Both targets use public API only.

Every choice that narrows coverage is listed, with a way to lift it, in [Future work](#future-work).

## Placement and build

Both targets live in `runtime/fuzz` next to `buffer`, `blob_integrity` and `blob_creation`.

slow.yml fuzzes every `runtime/fuzz` target whose `required-features` are on by default
(`.github/scripts/fuzz_targets.py`). The new targets run on fuzzcorp only, so each is gated by a
non-default feature:

```toml
[features]
default = []
storage-differential = []
iobuf = []
runtime-all = [ "iobuf", "storage-differential" ]

[[bin]]
name = "storage_differential"
path = "fuzz_targets/storage_differential.rs"
required-features = ["storage-differential"]
test = false
doc = false

[[bin]]
name = "iobuf"
path = "fuzz_targets/iobuf.rs"
required-features = ["iobuf"]
test = false
doc = false
```

Build and run (toolchain pin read from `nightly` under `[tools]` in `.github/toolchains.toml`,
currently `nightly-2026-11-12`):

```bash
cargo +nightly-2026-11-12 fuzz build --fuzz-dir runtime/fuzz --features runtime-all
cargo +nightly-2026-11-12 fuzz run --fuzz-dir runtime/fuzz --features runtime-all storage_differential
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

Platforms: both targets build and smoke-run on macOS. Campaigns run on Linux through fuzzcorp,
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
- Partition names that differ only by letter case (`lib.rs:716-718`).

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
  (`runtime/src/storage/memory/mod.rs:469-488`). On tokio it is a no-op
  (`runtime/src/storage/tokio/blob.rs:633`).
- A zero-length read past the end succeeds on tokio (`tokio/blob.rs:511`) and fails with
  `BlobInsufficientLength` on memory.
- An empty blob name, a blob name over 127 bytes, and a partition over 255 characters fail to open
  on tokio (filesystem limits) and succeed on memory. A failed tokio open has already created the
  partition directory, so a later `scan` returns `Ok([])` instead of an error.
- `remove(partition, Some(name))` on a missing partition fails with `PartitionMissing` on memory and
  `BlobMissing` on tokio. Both are errors, so this is not reported unless one side succeeds.

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
  (`runtime/src/iobuf/bufs.rs:770-790`).
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

## Validation after implementation

1. Build with and without `--features runtime-all` using the pinned nightly. The build without
   features must list only the three existing targets.
2. Smoke-run each new target on macOS for about 10 minutes with `-timeout=60`.
3. Triage every failure. Harness bugs are fixed in the harness. A real divergence is written up in
   `runtime/fuzz/FINDINGS.md` and reported to the maintainer, who decides whether it gets an
   allowlist entry.
4. No commits unless asked.

## Future work

Each choice below narrows coverage or scope. The table records why it was made and how to lift it.

| # | Choice | What it costs | How to lift it |
|---|---|---|---|
| 1 | io_uring excluded | The custom executor and `storage/iouring.rs` / `network/iouring.rs` are never fuzzed | Add `iouring::Runner` as a third backend in `storage_differential` under `cfg(target_os = "linux")`. Run on hosts that allow io_uring (Docker's default seccomp profile blocks it) |
| 2 | Public API only (`runtime/src` off limits) | io_uring internals (`Waiters`, `TimeoutWheel`, `ReadAtRequest` against the simulated kernel in `iouring/request.rs`, `WriteBuffers`) are unreachable, and tokio storage needs a full `Runner::start` | Add `cfg(fuzzing)` entry points one by one with approval, then fuzz those modules directly |
| 3 | Fresh tokio runner per input | Low exec/s. On Linux every start runs `syncfs` over the whole filesystem | Use a persistent runtime thread with a fresh partition per input and forwarded panics, or a standalone storage hook (see 2) |
| 4 | Sequential operations only | No concurrency: the AIO context pool, blocking-pool contention, `Pending`/`Tracker` races, reads overlapping writes, syncs in flight with writes | Start with concurrent read-only groups on stable ranges and a sync in flight. Then allow concurrent mutations with an oracle relaxed for overlapping ranges. Reproduce failures with a fixed worker count and `rr` |
| 5 | Faults off | Recovery after failed, partial or torn writes is never exercised | Add a deterministic-only fault mode (`with_storage_fault_config`, `PartialWriteMode`) judged by the model only (synced data survives later failures). For tokio, inject faults below the runtime (dm-flakey, FUSE, `LD_PRELOAD`) |
| 6 | tokio restarts are clean | The page cache survives a tokio restart, so real crash tearing never happens on tokio | Simulate crashes with block-level write logging (dm-log-writes, CrashMonkey style), or kill a child process in the middle of an operation |
| 7 | Size caps (1 MiB offsets, 64 KiB lengths) | Large-file paths are missed: offsets past 4 GiB, `EFBIG` at ext4's 16 TiB limit on the fused `SYNC` write, which poisons the blob across opens | Add a tokio-only large-offset mode on sparse files, judged by the model, with the memory side skipped |
| 8 | Overflow-edge offsets on reads only | Overflow handling in `write_at` and `resize` is not explored | Same tokio-only mode as 7 |
| 9 | Only documented error variants asserted | Variant inconsistencies (`Io(UnexpectedEof)` against `BlobInsufficientLength`) go unreported | Add a strict mode behind a feature, and propose tightening the trait docs upstream |
| 10 | Allowlist | Entries can hide neighbouring bugs | Keep entries narrow and remove them when `runtime/src` is fixed. Add a feature that disables the allowlist for periodic strict runs |
| 11 | Hangs left to libFuzzer's `-timeout` | Hangs (a leaked hold blocking `Runner::start`, a stuck blocking-pool operation) are reported late and without context | Add a per-operation watchdog that panics with the operation index |
| 12 | Small name pool, no case variants, no arbitrary names | Unusual hex names in `scan`, and stray files in partition directories (`.DS_Store` yields `PartitionCorrupt`), are not explored | Add an arbitrary-names mode, and seed stray files into the tokio partition directory before `scan` |
| 13 | No on-disk image seeding on tokio | Header resolution of arbitrary file contents on tokio is untested, including the unchecked `metadata.len() - data_offset` (`storage/tokio/mod.rs:266`, `storage/tokio/blob.rs:262`). `blob_creation` covers this for `mocks::Storage` only | Before `Open`, write arbitrary raw bytes to `<dir>/<partition>/<hex(name)>`. This needs no change under `runtime/src` |
| 14 | Filesystem decides the Linux I/O paths | On tmpfs, O_DIRECT, AIO and `RWF_DONTCACHE` may fall back silently | Point `COMMONWARE_RUNTIME_FUZZ_DIR` at ext4 or xfs on fuzzcorp, and check `storage/tokio/blob/aio.rs` in the lineage coverage |
| 15 | One tokio worker thread | Fewer interleavings in the executor and supervision code | Vary `worker_threads` per input once 4 is in place |
| 16 | `iobuf` built for 64-bit only | The 32-bit descriptor (128-byte tail threshold) goes unfuzzed | Add an i686 build where fuzzcorp supports it |
| 17 | No Miri replay | Undefined behaviour that ASan cannot see (uninitialised `&mut [u8]`, provenance) is missed | Replay the corpora under Miri through a test that decodes inputs with the same `Arbitrary` code |
| 18 | `iobuf` single-threaded | Races in clone, drop and promotion (`owner.rs` compare-exchange) are not fuzzed | Add a multi-threaded stress mode or a Shuttle model. Loom already covers parts of `owner.rs` |
| 19 | Network differential deferred | `Sink`/`Stream` semantics on tokio (poisoning after cancel, partial reads, `peek`) are not compared against the deterministic network | Add a target that runs one script over loopback TCP on tokio and over the deterministic network |
| 20 | Paged-buffer oracles deferred | `Sealed`, `read_ranges_into`, `recoverable_prefix_len` and concurrent cache readers (`mocks::ReadGate`) stay unchecked. `buffer` discards every result | Add oracles to `buffer` and a paged-writer target with a model |
| 21 | No coverage target | Nothing shows when the targets plateau | Track per-file line coverage for `storage/tokio/*`, `storage/memory/*` and `iobuf/*` from fuzzcorp lineage coverage, and act on the gaps |
| 22 | No sweep of leftover tokio directories | A timeout, out-of-memory kill or backend panic leaves a `commonware_runtime_fuzz_<pid>_<n>` directory that later processes never remove, because their pid differs | Remove stale `commonware_runtime_fuzz_*` directories of dead processes at startup |
| 23 | Linux-only tokio paths checked by reading only | Native AIO `read_many`, O_DIRECT reads, `RWF_DONTCACHE` and the startup `syncfs` have not been executed under the harness; all smoke runs were on macOS | Run a short Docker-Linux smoke run of `storage_differential` before the first fuzzcorp deployment |
