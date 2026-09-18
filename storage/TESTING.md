# Storage testing

Use the deterministic runtime's storage backend for storage tests. It permits reproducible I/O, crashes, corruption, and recovery without real disk access.

## Basic operations

```rust
#[test]
fn test_storage_operations() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (blob, _) = context
            .open("partition_name", &0u64.to_be_bytes())
            .await
            .expect("open blob");

        blob.write_at(0, vec![1, 2, 3, 4], WriteOptions::default())
            .await
            .expect("write");
        let data = blob
            .read_at(0, 4, ReadOptions::default())
            .await
            .expect("read")
            .coalesce();
        assert_eq!(data.as_ref(), &[1, 2, 3, 4]);
        blob.sync().await.expect("sync");
    });
}
```

## Recovery and corruption

Persist data, drop the database, and initialize it again to test clean recovery. To simulate an interrupted write, resize a blob after writing it; to simulate corruption, overwrite a checksum or truncate data. Reinitialize and verify that replay recovers to the last valid item.

```rust
let (blob, size) = context.open(&partition, &name).await.unwrap();
blob.resize(size - 1).await.unwrap();
blob.sync().await.unwrap();

let journal = Journal::init(context, cfg).await.unwrap();
assert_eq!(journal.size().await.unwrap(), expected_size);
```

## What to cover

- Empty and single-item stores, maximum sizes, and offset overflow.
- Restart after a clean sync and after an unclean shutdown.
- Truncated, corrupted, and missing data.
- Multiple readers or writers and blob pruning.
- Metrics for tracked, synced, and pruned data.
- Hash-based conformance tests for intentionally stable storage formats.

Errors from mutable operations, including `put`, `delete`, and `sync`, are unrecoverable. A caller must not use that database again after such an error.

## Verus proofs

The production [graftable-chunk count](src/qmdb/current/grafting/count.rs) carries inline Verus contracts and proof blocks. This count determines which bitmap chunks have an operations-tree ancestor and can enter QMDB's grafted tree. MMR makes each complete chunk graftable immediately; MMB can leave one complete chunk pending.

For chunk size `C = 2^height` and first-chunk birth `B`, the specification places chunk `k`'s birth at `B + k*C`. The proofs cover every `u64` leaf count, heights `1..=62`, and birth thresholds `C <= B < 2*C`. They establish that:

- The returned count is exactly the prefix of chunks born by the given leaf count.
- At most one complete chunk is pending, with an exact remainder condition for that interval and no pending chunk when `B = C`.
- Appending leaves never decreases the count, and one additional leaf increases it by at most one.
- The machine arithmetic cannot overflow or divide by zero within the stated domain.

Install the official [Verus release `0.2026.08.23.fbbbbcf`](https://github.com/verus-lang/verus/releases/tag/release/0.2026.08.23.fbbbbcf) for your platform and its Rust toolchain, then run:

```sh
rustup toolchain install 1.97.1 --profile minimal
VERUS_BIN=/path/to/verus just test-verus
```

`VERUS_BIN` defaults to `verus` on `PATH`. The command verifies the production source directly with `--no-cheating`, which rejects local `assume`, `admit`, and `external_body` escapes. Verus enables `verus_keep_ghost` for the contracts, proof blocks, and supporting lemmas. Ordinary Cargo builds omit those annotations and use the same executable body, without a Verus dependency. Keep executable statements independent of that configuration.

The [CI workflow](../.github/workflows/verus.yml) pins the release and archive SHA-256 and runs these proofs on pull requests, merge groups, and pushes to `main`.

An exhaustive native test calls the actual MMR and MMB subtree and birth functions at heights `1..=61`, checking `B = C` and `B = C + C/2 - 1`, respectively, along with threshold behavior. It runs in the ordinary storage test suite:

```sh
just test -p commonware-storage test_graftable_chunks_family_thresholds
```

The scalar proof also covers height 62; the native family constructors have a narrower domain. The native test connects those constructors to the arithmetic assumptions. The Verus proof does not establish the families' merge schedules, root authenticity, proof reconstruction, bitmap consistency, pruning, crash recovery, or the threshold condition for custom `Graftable` implementations. Height zero and excessive family heights are outside its contract.
