//! Lifecycle checks shared by the filesystem storage backends.

use crate::{
    Blob as _, BufferPool, Error, ReadOptions, WriteOptions, buffer::Write, storage::Pending,
};
use commonware_utils::{NZUsize, channel::oneshot};
use futures::FutureExt as _;
use std::sync::{Arc, mpsc};

/// An untouched creation leaves no debt for a later open.
pub(crate) async fn check_untouched_creation_leaves_no_debt<S: crate::Storage>(
    storage: &S,
    pending: &Pending,
) {
    let before = pending.completions();
    let (blob, _) = storage.open("durable_creation", b"blob").await.unwrap();
    drop(blob);
    let owed = pending.owes("durable_creation", b"blob");

    let (blob, size) = storage.open("durable_creation", b"blob").await.unwrap();
    drop(blob);
    let completions = pending.completions() - before;
    storage.remove("durable_creation", None).await.unwrap();

    assert!(!owed, "successful creation must leave no durability debt");
    assert_eq!(size, 0);
    assert_eq!(completions, 0, "untouched creation needs no reopen flush");
}

/// Failed creation must not expose an unflushed header as a valid blob.
///
/// An incomplete header is recreated on the next open. A complete header retains the
/// creation failure across repeated opens until the name is removed. Failed creation
/// leaves no payload mutations for a later open to flush.
pub(crate) async fn check_failed_creation<S: crate::Storage>(storage: &S, pending: &Pending) {
    let completions = pending.completions();

    // Stop after writing either a partial or complete header.
    for partial in [true, false] {
        *pending.test.fail_creation_after.lock() = Some(if partial { 1 } else { usize::MAX });
        assert!(matches!(
            storage.open("failed_creation", b"blob").await,
            Err(Error::Closed)
        ));

        // Repeated opens must preserve the failure even though the header is parseable.
        if !partial {
            for _ in 0..2 {
                assert!(
                    matches!(
                        storage.open("failed_creation", b"blob").await,
                        Err(Error::Closed)
                    ),
                    "a parseable header must not hide the failed creation barrier"
                );
            }
            storage
                .remove("failed_creation", Some(b"blob"))
                .await
                .unwrap();
        }

        // Both a torn header and an absent name must yield a fresh, empty blob.
        let (blob, size) = storage.open("failed_creation", b"blob").await.unwrap();
        assert_eq!(size, 0);
        drop(blob);
        storage.remove("failed_creation", None).await.unwrap();
    }
    assert_eq!(
        pending.completions(),
        completions,
        "failed creation must not leave debt"
    );
}

/// Unlinking a dirty blob keeps its handles readable and leaves nothing to flush.
///
/// Covers name and partition removal with the last handle dropped before or after the
/// unlink. Removal forgets the name's debt, so a later open creates a fresh blob
/// without flushing a file that no longer exists.
pub(crate) async fn check_remove_live_dirty_owner<S: crate::Storage>(
    storage: &S,
    pending: &Pending,
    pool: &BufferPool,
) {
    for by_name in [true, false] {
        for unlink_first in [false, true] {
            // The write exceeds the buffer capacity and reaches the blob without a
            // sync, leaving dirty data behind the final handle.
            let partition = "remove_live_dirty";
            let name = b"blob";
            let (blob, size) = storage.open(partition, name).await.unwrap();
            let mut writer = Write::new(blob, size, NZUsize!(1), pool.clone());
            writer.write_at(0, b"dirty").await.unwrap();
            writer.wait_for_sync().await.unwrap();
            let completions = pending.completions();
            let target = by_name.then_some(name.as_slice());

            if unlink_first {
                storage.remove(partition, target).await.unwrap();
                assert_eq!(
                    writer.read_at(0, 5).await.unwrap().coalesce().as_ref(),
                    b"dirty",
                );
                drop(writer);
            } else {
                drop(writer);
                storage.remove(partition, target).await.unwrap();
            }
            assert!(
                !pending.owes(partition, name),
                "removal must forget the name's debt"
            );

            // The name is fresh again and nothing is flushed on its behalf.
            let (blob, size) = storage.open(partition, name).await.unwrap();
            assert_eq!(size, 0);
            drop(blob);
            assert_eq!(pending.completions(), completions);
            storage.remove(partition, None).await.unwrap();
        }
    }
}

/// A write whose future was dropped lands before the next open reports the blob's
/// length or exposes its bytes.
///
/// Reopening must wait for any remaining write and sync work after the last handle
/// drops, even though the caller no longer observes the write's result.
pub(crate) async fn check_orphaned_write<S: crate::Storage>(storage: &S) {
    // Poll once to submit the I/O before abandoning its future and final handle.
    let (blob, _) = storage.open("orphaned_write", b"blob").await.unwrap();
    let mut write = Box::pin(blob.write_at(0, b"orphaned", WriteOptions::default()));
    let _ = futures::poll!(write.as_mut());
    drop(write);
    drop(blob);

    let (blob, len) = storage.open("orphaned_write", b"blob").await.unwrap();
    assert_eq!(len, 8);
    let read = blob.read_at(0, 8, ReadOptions::default()).await.unwrap();
    assert_eq!(read.coalesce().as_ref(), b"orphaned");
    drop(blob);
    storage.remove("orphaned_write", None).await.unwrap();
}

/// Successful `SYNC` writes leave nothing for a reopen to flush.
///
/// Mixing plain and durable writes must retain any debt the backend's write barrier
/// did not cover, regardless of the order of those writes.
pub(crate) async fn check_sync_writes<S: crate::Storage>(storage: &S, pending: &Pending) {
    // The cache hint must not change durability or require a flush on reopen.
    for (case, options) in [
        WriteOptions::SYNC,
        WriteOptions::SYNC | WriteOptions::DONT_CACHE,
    ]
    .into_iter()
    .enumerate()
    {
        let before = pending.completions();
        let (blob, _) = storage.open("durable_writes", &[case as u8]).await.unwrap();
        blob.write_at(0, b"first", options).await.unwrap();
        blob.write_at(5, b"second", options).await.unwrap();
        drop(blob);
        let (blob, size) = storage.open("durable_writes", &[case as u8]).await.unwrap();
        assert_eq!(size, 11);
        assert_eq!(
            blob.read_at(0, 11, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"firstsecond"
        );
        drop(blob);
        assert_eq!(
            pending.completions(),
            before,
            "successful durable writes need no reopen flush"
        );
    }

    // A durable write cannot hide an uncovered plain write in either order.
    for plain_first in [false, true] {
        let before = pending.completions();
        let name = [2, u8::from(plain_first)];
        let (blob, _) = storage.open("durable_writes", &name).await.unwrap();
        let (first, second) = if plain_first {
            (WriteOptions::default(), WriteOptions::SYNC)
        } else {
            (WriteOptions::SYNC, WriteOptions::default())
        };
        blob.write_at(0, b"first", first).await.unwrap();
        blob.write_at(5, b"second", second).await.unwrap();
        drop(blob);
        let (blob, size) = storage.open("durable_writes", &name).await.unwrap();
        assert_eq!(size, 11);
        assert_eq!(
            blob.read_at(0, 11, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"firstsecond"
        );
        drop(blob);

        // Linux's per-write sync covers only the durable write's range. Other
        // platforms use a full-file sync, which also covers an earlier plain write.
        let needs_flush = !plain_first || cfg!(target_os = "linux");
        assert_eq!(
            pending.completions() - before,
            u64::from(needs_flush),
            "plain_first={plain_first}"
        );
    }
}

/// Reopening a replacement flushes its debt while another partition remains usable.
///
/// Covers name and partition removal while the old handle remains readable. The
/// replacement's reopen must not return before its own flush completes.
pub(crate) async fn check_recreate_reopen<S: crate::Storage>(storage: &S, pending: &Pending) {
    // Make the independent blob durable so its later open owes nothing.
    let (ready, _) = storage.open("independent", b"ready").await.unwrap();
    ready.sync().await.unwrap();
    drop(ready);
    for remove_name in [true, false] {
        let partition = "recreate_pending";
        let name = b"blob";
        let (old, _) = storage.open(partition, name).await.unwrap();
        old.write_at(0, b"old", WriteOptions::default())
            .await
            .unwrap();
        storage
            .remove(partition, remove_name.then_some(name.as_slice()))
            .await
            .unwrap();
        assert_eq!(
            old.read_at(0, 3, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"old"
        );

        let (current, len) = storage.open(partition, name).await.unwrap();
        assert_eq!(len, 0);
        let current = Arc::new(current);
        let reader = current.clone();
        current
            .write_at(0, b"new", WriteOptions::default())
            .await
            .unwrap();

        // Block the reopen's flush. A shared owner keeps the replacement alive while the
        // removed open drops, so only the replacement may record debt. Dropping the sender
        // also releases the worker if an assertion unwinds.
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *pending.test.before_complete.lock() = Some((entered, gate));
        let completions = pending.completions();
        drop(current);
        drop(old);
        drop(reader);

        let mut reopen = Box::pin(storage.open(partition, name));
        commonware_macros::select! {
            entered = entering => entered.expect("reopen dropped its flush gate"),
            _ = &mut reopen => panic!("reopen completed before its flush"),
        }
        assert!(
            (&mut reopen).now_or_never().is_none(),
            "reopen exposed the replacement before its flush"
        );

        // Waiting for this flush must leave the namespace lock available to unrelated
        // scans and opens.
        let clean_progress = async {
            let names = storage.scan("independent").await?;
            let (blob, len) = storage.open("independent", b"ready").await?;
            drop(blob);
            Ok::<_, Error>((names, len))
        }
        .await;

        // Release the worker before checking outcomes so failures cannot leave it
        // blocked on the gate.
        drop(release);
        let (reopened, len) = reopen.await.unwrap();
        let bytes = reopened
            .read_at(0, 3, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        drop(reopened);
        storage.remove(partition, None).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(bytes.as_ref(), b"new");
        assert_eq!(
            pending.completions() - completions,
            1,
            "the replacement's debt is flushed once"
        );
        let (names, len) = clean_progress.unwrap();
        assert_eq!(names, vec![b"ready".to_vec()]);
        assert_eq!(len, 0);
    }
}

/// A dirty handle to a removed blob records no debt for a clean replacement.
///
/// Covers name and partition removal.
pub(crate) async fn check_recreate_clean<S: crate::Storage>(storage: &S, pending: &Pending) {
    for remove_name in [true, false] {
        let partition = "recreate_clean";
        let name = b"blob";
        let (old, _) = storage.open(partition, name).await.unwrap();
        old.write_at(0, b"old", WriteOptions::default())
            .await
            .unwrap();
        storage
            .remove(partition, remove_name.then_some(name.as_slice()))
            .await
            .unwrap();
        let (current, _) = storage.open(partition, name).await.unwrap();
        current
            .write_at(0, b"new", WriteOptions::SYNC)
            .await
            .unwrap();

        // Drop the removed open while the replacement still owns the name.
        let completions = pending.completions();
        drop(old);
        drop(current);
        let (reopened, len) = storage.open(partition, name).await.unwrap();
        drop(reopened);
        storage.remove(partition, None).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(
            pending.completions(),
            completions,
            "the removed open recorded debt for its replacement"
        );
    }
}
