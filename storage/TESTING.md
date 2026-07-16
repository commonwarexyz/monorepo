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

        blob.write_at(0, vec![1, 2, 3, 4]).await.expect("write");
        let data = blob.read_at(0, 4).await.expect("read").coalesce();
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
