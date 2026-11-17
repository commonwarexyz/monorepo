# Runtime fuzz differential fuzzing findings

Divergences and runtime bugs found by the `runtime/fuzz` targets. Each entry is unconfirmed until
the maintainer reviews it. An entry the maintainer confirms may get a narrow allowlist entry in
the harness that refers back to it (see `SPEC.md`, "Allowlist").

RF-1, RF-2 and RF-3 are reported upstream in
https://github.com/commonwarexyz/monorepo/issues/5752. We agreed that all three runtimes (ideally) to
behave the same way, or to agree on a minimal specified contract. Until that issue is fixed,
`storage_differential` allowlists the three divergences so they do not hide new findings. Remove
the entries once the fix lands.

Each reproducer is a crafted input whose literal bytes encode exactly the op trace shown: the first
8 bytes seed the sampling stream and the rest overwrite it from its start. Copies live in
`runtime/fuzz/artifacts/storage_differential/`, which is gitignored, so the bytes are also listed
here as hex. To rebuild a file and replay it:

```bash
echo <hex> | xxd -r -p > /tmp/<file>
cargo +nightly-2026-08-20 fuzz run --fuzz-dir runtime/fuzz --features storage-differential \
  storage_differential /tmp/<file>
```

| File | Hex |
|---|---|
| `rf1_zero_len_read_past_end` | `0000000000000000010000010100000c000107010000` |
| `rf2_empty_write_grows_memory` | `00000000000000000200000101000006000701000000000c000107000100` |
| `rf2_empty_write_grows_memory_reopen` | `000000000000000004000001010000060007010000000017001c00000001010000` |
| `rf3_partition_256_chars` | `00000000000000000000000003010000` |
| `rf3_name_128_bytes` | `00000000000000000000000100020000` |
| `rf3_name_empty_new_partition` | `00000000000000000000000100000000` |
| `rf3_name_empty_existing_partition` | `00000000000000000100000101000000010100000000` |

All entries were found at commit `3deaf6b12` on macOS (APFS).

## RF-1: zero-length read past the end succeeds on tokio and fails on memory

- Status: reported upstream in https://github.com/commonwarexyz/monorepo/issues/5752 (open).
  Allowlisted in `storage_differential` until the issue is fixed (see `SPEC.md`, "Allowlist").
- Target: `storage_differential`
- Backends: deterministic (memory storage) and tokio
- Minimal op trace:
  1. `Open { slot: 0, partition: "p0", name: "a", versions: 0..=0 }` -> both `Ok(size=0)`
  2. `ReadAt { slot: 0, offset: At(1), len: 0, dont_cache: false }`
- Observed:
  - deterministic: `Err(BlobInsufficientLength)`
  - tokio: `Ok([])`
- Also reached through `read_at_buf`, `read_many` and `start_read_many` with a zero-length range
  whose offset is past the end (97 of 236 smoke-run crashes).
- Contract: `Blob::read_at` / `Blob::read_at_buf` (`runtime/src/lib.rs:923-946`) say "Read exactly
  `len` bytes at `offset`" and name no outcome for a zero-length read past the end. Neither backend
  violates the trait docs, but they disagree on Ok/Err for the same call, and the shared
  conformance suite (`runtime/src/storage/mod.rs`, `test_read_zero_length`) only covers offsets
  inside the blob.
- Code:
  - tokio returns before any bound check: `runtime/src/storage/tokio/blob.rs:511` (`read_at_buf`,
    reached from `read_at`) and `runtime/src/storage/tokio/blob.rs:600` (`start_read_many`);
    `read_many` off Linux goes through `read_at` per range.
  - memory checks `offset + len` against the contents first: `runtime/src/storage/memory/mod.rs:456`.
- Failure class: `cross_backend_read`
- Reproducer: `runtime/fuzz/artifacts/storage_differential/rf1_zero_len_read_past_end`
- Verified not a harness artifact: both backends receive the identical call
  (`read_at(1, 0, ReadOptions::default())`) on a freshly created empty blob; only the cross-backend
  Ok/Err rule fires, no model judgement is involved.

## RF-2: an empty non-SYNC write past the end grows a memory blob

- Status: reported upstream in https://github.com/commonwarexyz/monorepo/issues/5752 (open).
  Allowlisted in `storage_differential` until the issue is fixed (see `SPEC.md`, "Allowlist").
- Target: `storage_differential`
- Backends: deterministic (memory storage) against tokio
- Minimal op trace:
  1. `Open { slot: 0, partition: "p0", name: "a", versions: 0..=0 }` -> both `Ok(size=0)`
  2. `Write { slot: 0, offset: At(1), chunks: [0], sync: false, dont_cache: false }` -> both `Ok`
  3. `ReadAt { slot: 0, offset: At(0), len: 1, dont_cache: false }`
- Observed:
  - deterministic: `Ok([00])`, plus a model violation ("read past len 0 succeeded"): the empty
    write extended the blob to 1 byte.
  - tokio: `Err(Io(UnexpectedEof))`: the empty write was a no-op.
- Consequence: code tested on the deterministic runtime can observe a blob size that the
  production runtime never produces. A later `sync` makes the grown size durable on memory, so a
  reopen also returns it.
- Contract: `Blob::write_at` (`runtime/src/lib.rs:977-985`): "Write every remaining byte in `bufs`
  to the blob at `offset`." An empty buffer has no bytes to write. The conformance suite asserts
  the no-growth reading for `SYNC` only (`runtime/src/storage/mod.rs`, `test_write_at_sync`:
  "Empty writes should be accepted without extending the blob").
- Code:
  - memory returns early only for `SYNC` empty writes (`runtime/src/storage/memory/mod.rs:470`),
    then resizes to `offset + 0` (`runtime/src/storage/memory/mod.rs:486`).
  - tokio returns early for every empty write: `runtime/src/storage/tokio/blob.rs:633`.
- Failure classes: `model_read_len` when a read sees the grown size first, and `model_reopen` when
  a `Sync` and a reopen come first (Open, empty `Write{At(1)}`, `Sync`, `Drop`, `Open`: the
  deterministic reopen returns size 1 where the model allows 0, while tokio returns size 0).
- Reproducers: `runtime/fuzz/artifacts/storage_differential/rf2_empty_write_grows_memory`
  (`model_read_len`) and `rf2_empty_write_grows_memory_reopen` (`model_reopen`)
- Verified not a harness artifact: the harness passes an `IoBufs` with no remaining bytes and
  `WriteOptions::default()` to both backends; the model treats an empty write as a no-op, which is
  what tokio does and what the conformance suite asserts for `SYNC`.

## RF-3: names memory accepts fail to open on tokio

- Status: reported upstream in https://github.com/commonwarexyz/monorepo/issues/5752 (open).
  Allowlisted in `storage_differential` until the issue is fixed (see `SPEC.md`, "Allowlist").
- Target: `storage_differential`
- Backends: deterministic (memory storage) against tokio
- Minimal op traces (each a single `Open` into slot 0 with `versions: 0..=0`, except the last):
  1. partition of 256 characters, name `"a"`
  2. partition `"p0"`, name of 128 bytes
  3. partition `"p0"` (not yet created), empty name
  4. `Open("p0", "a")`, then `Open("p0", "")` into slot 1
- Observed (deterministic is `Ok(size=0, version=0)` in every case):
  1. tokio: `Err(PartitionCreationFailed(<partition>))` (ENAMETOOLONG on the directory)
  2. tokio: `Err(BlobOpenFailed("p0", <hex>, InvalidFilename "File name too long"))`: the filename
     is `hex(name)`, 256 characters
  3. tokio: `Err(BlobOpenFailed("p0", "", NotFound))`
  4. tokio: `Err(BlobOpenFailed("p0", "", IsADirectory))`
  The empty name under a 255- or 256-character partition also fails (`NotFound` or
  `InvalidFilename`).
- For the empty name, `storage_directory.join(partition).join(hex(name))` is the partition
  directory itself with a trailing separator, whose `parent()` is the storage root, so tokio
  creates no partition directory and then opens the partition path as a file.
- From code reading: a failed tokio open of a too-long name has already created the partition
  directory (`create_dir_all` runs first), so tokio's `scan` of that partition returns `Ok([])`
  where no blob was ever created.
- Contract: `Storage` "Partition Names" (`runtime/src/lib.rs:712-718`) restricts the character set
  and requires a non-empty partition, but names no length limit. `Storage::open_versioned`
  (`runtime/src/lib.rs:771`) takes any `&[u8]` name and names no limit or rejected value, so
  memory's acceptance and tokio's failure are both within the trait docs; the backends disagree on
  Ok/Err for the same call.
- Code: `runtime/src/storage/tokio/mod.rs:194` (path construction), `:215-216` (`create_dir_all` ->
  `PartitionCreationFailed`), `:225` (`BlobOpenFailed`); `validate_partition_name` in
  `runtime/src/storage/mod.rs` (character set only).
- Failure class: `cross_backend_open`
- Reproducers in `runtime/fuzz/artifacts/storage_differential/`: `rf3_partition_256_chars`,
  `rf3_name_128_bytes`, `rf3_name_empty_new_partition`, `rf3_name_empty_existing_partition`
- Verified not a harness artifact: names are passed unchanged to both backends, the partition
  passes `validate_partition_name`, and a sequence opening a 255-character partition with a
  127-byte name, writing, syncing and scanning, plus a `[0xff, 0x00]` name, passes on both
  backends.
