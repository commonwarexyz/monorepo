//! Family-scoped transactional append-only log storage.
//!
//! Implementations of [`crate::LogStorage`]. A **family** is one transaction
//! domain: a set of append-only **logs** mutated atomically through the
//! family's single write **transaction**. The traits and their contracts live
//! in the crate root ([`crate::LogStorage`], [`crate::LogFamily`],
//! [`crate::Log`], [`crate::LogTransaction`]); this module holds the backends.
//!
//! [`memory`] is the reference backend: the full transactional contract with
//! no durability. [`segment`] is the durable backend, under construction:
//! all logs of a family live as extents inside shared append-only segment
//! files. The conformance suite every backend must pass lives in the test
//! module here.

mod family;
pub mod memory;
pub mod segment;

/// Size bounds enforced on every transaction.
///
/// Backends take these at construction and reject staging that would exceed
/// them with [`crate::Error::TransactionTooLarge`] (or
/// [`crate::Error::InvalidTransaction`] for an oversized name). Bounds apply
/// to the transaction's net state: rewinding staged data refunds its budget.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Maximum net staged payload in one transaction, in bytes.
    pub max_transaction_bytes: u64,
    /// Maximum number of logs one transaction may touch (create, append,
    /// rewind, or remove).
    pub max_transaction_logs: usize,
    /// Maximum log name length, in bytes.
    pub max_log_name_len: usize,
}

impl Default for Bounds {
    /// The frozen format caps (`MAX_TRANSACTION_PAYLOAD`, `MAX_LOGS_TOUCHED`,
    /// `MAX_LOG_NAME_LEN` in the segment backend's format layer), so every
    /// backend accepts the same transactions by default.
    fn default() -> Self {
        Self {
            max_transaction_bytes: 384 << 20,
            max_transaction_logs: 1024,
            max_log_name_len: 256,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Bounds;
    use crate::{Buf, Error, IoBufMut, IoBufsMut, Log, LogFamily, LogStorage, LogTransaction};
    use futures::FutureExt;

    /// Runs the full conformance suite on the provided log storage
    /// implementation.
    ///
    /// `bounds` must be the bounds the storage was constructed with; tests
    /// size their transactions from it, so keep the values small.
    /// `fail_next_commit` is the backend's fault hook: arm the named family
    /// so that its next admitted commit fails, poisoning it.
    pub(crate) async fn run_log_storage_tests<S: LogStorage>(
        storage: S,
        bounds: Bounds,
        fail_next_commit: impl Fn(&str),
    ) {
        test_committed_only_visibility(&storage).await;
        test_read_your_writes(&storage).await;
        test_create_discard_noop(&storage).await;
        test_remove_recreate_new_identity(&storage).await;
        test_rewind_reappend_net_state(&storage).await;
        test_single_writer_blocks(&storage).await;
        test_writer_fairness(&storage).await;
        test_waiter_cancellation(&storage).await;
        test_pipelined_start_commit(&storage).await;
        test_abort_by_drop(&storage).await;
        test_empty_transaction(&storage).await;
        test_independent_families(&storage).await;
        test_scan(&storage).await;
        test_family_name_validation(&storage).await;
        test_read_bounds(&storage).await;
        test_read_at_buf(&storage).await;
        test_create_rejections(&storage, &bounds).await;
        test_remove_touch_conflicts(&storage).await;
        test_rewind_beyond_length(&storage, &bounds).await;
        test_transaction_too_large(&storage, &bounds).await;
        test_stale_and_foreign_targets(&storage).await;
        test_destroy_family(&storage).await;
        test_incarnation(&storage).await;
        test_poisoning_and_recovery(&storage, &fail_next_commit).await;
        test_poisoned_waiter(&storage, &fail_next_commit).await;
    }

    /// Create a log named `name` holding `data` in one committed transaction
    /// and return its handle.
    async fn commit_log<F: LogFamily>(family: &F, name: &[u8], data: &[u8]) -> F::Log {
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(name).unwrap();
        if !data.is_empty() {
            txn.append_draft(&draft, data.to_vec()).unwrap();
        }
        txn.commit().await.unwrap();
        family.open(name).await.unwrap().unwrap()
    }

    /// Read `len` committed bytes at `offset`.
    async fn read<L: Log>(log: &L, offset: u64, len: usize) -> IoBufMut {
        log.read_at(offset, len).await.unwrap().coalesce()
    }

    /// Read `len` bytes at `offset` from the transaction's staged view of
    /// `log`.
    async fn read_txn<T: LogTransaction>(
        txn: &T,
        log: &T::Log,
        offset: u64,
        len: usize,
    ) -> IoBufMut {
        txn.read_at(log, offset, len).await.unwrap().coalesce()
    }

    /// Read `len` bytes at `offset` from the staged data of `draft`.
    async fn read_draft<T: LogTransaction>(
        txn: &T,
        draft: &T::Draft,
        offset: u64,
        len: usize,
    ) -> IoBufMut {
        txn.read_draft_at(draft, offset, len)
            .await
            .unwrap()
            .coalesce()
    }

    /// Base reads see committed state only; drafts and staged mutations are
    /// visible only through their transaction.
    async fn test_committed_only_visibility<S: LogStorage>(storage: &S) {
        let family = storage.open_family("visibility").await.unwrap();

        // Drafts are invisible until commit.
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(b"a").unwrap();
        txn.append_draft(&draft, b"hello").unwrap();
        assert!(family.open(b"a").await.unwrap().is_none());
        assert!(family.scan().await.unwrap().is_empty());
        txn.commit().await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(log.len().unwrap(), 5);
        assert_eq!(read(&log, 0, 5).await, b"hello");
        assert_eq!(family.scan().await.unwrap(), vec![b"a".to_vec()]);

        // Staged mutations to a committed log are invisible until commit.
        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b" world").unwrap();
        assert_eq!(log.len().unwrap(), 5);
        assert_eq!(read(&log, 0, 5).await, b"hello");
        txn.commit().await.unwrap();
        assert_eq!(log.len().unwrap(), 11);
        assert_eq!(read(&log, 0, 11).await, b"hello world");
    }

    /// Transaction reads observe committed state with staged mutations
    /// applied, for committed logs and drafts alike.
    async fn test_read_your_writes<S: LogStorage>(storage: &S) {
        let family = storage.open_family("read-your-writes").await.unwrap();
        let log = commit_log(&family, b"log", b"hello").await;

        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&log, 3).unwrap();
        assert_eq!(txn.append(&log, b"p!").unwrap(), 3);
        assert_eq!(txn.len(&log), 5);
        assert_eq!(read_txn(&txn, &log, 0, 5).await, b"help!");
        assert_eq!(read_txn(&txn, &log, 0, 3).await, b"hel"); // committed only
        assert_eq!(read_txn(&txn, &log, 3, 2).await, b"p!"); // staged only
        assert_eq!(read_txn(&txn, &log, 2, 2).await, b"lp"); // spanning

        let draft = txn.create(b"draft").unwrap();
        assert_eq!(txn.append_draft(&draft, b"xyz").unwrap(), 0);
        assert_eq!(txn.len_draft(&draft), 3);
        assert_eq!(read_draft(&txn, &draft, 1, 2).await, b"yz");
        txn.rewind_draft(&draft, 1).unwrap();
        assert_eq!(txn.len_draft(&draft), 1);
        assert_eq!(txn.append_draft(&draft, b"Q").unwrap(), 1);
        assert_eq!(read_draft(&txn, &draft, 0, 2).await, b"xQ");

        txn.commit().await.unwrap();
        assert_eq!(read(&log, 0, 5).await, b"help!");
        let created = family.open(b"draft").await.unwrap().unwrap();
        assert_eq!(read(&created, 0, 2).await, b"xQ");
    }

    /// A created-then-discarded draft leaves no trace, and frees its name
    /// within the same transaction.
    async fn test_create_discard_noop<S: LogStorage>(storage: &S) {
        let family = storage.open_family("discard").await.unwrap();
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(b"gone").unwrap();
        txn.append_draft(&draft, b"data").unwrap();
        txn.discard(draft).unwrap();
        let draft = txn.create(b"gone").unwrap();
        txn.append_draft(&draft, b"more").unwrap();
        txn.discard(draft).unwrap();
        txn.commit().await.unwrap();
        assert!(family.open(b"gone").await.unwrap().is_none());
        assert!(family.scan().await.unwrap().is_empty());
    }

    /// Committed removal closes every existing handle; recreating the name is
    /// a new log identity.
    async fn test_remove_recreate_new_identity<S: LogStorage>(storage: &S) {
        let family = storage.open_family("remove").await.unwrap();
        let log = commit_log(&family, b"a", b"first").await;
        let clone = log.clone();

        let mut txn = family.transaction().await.unwrap();
        txn.remove(&log).unwrap();
        txn.commit().await.unwrap();
        assert!(matches!(log.len(), Err(Error::Closed)));
        assert!(matches!(clone.len(), Err(Error::Closed)));
        assert!(matches!(log.read_at(0, 1).await, Err(Error::Closed)));
        assert!(family.open(b"a").await.unwrap().is_none());

        let recreated = commit_log(&family, b"a", b"second").await;
        assert!(matches!(log.len(), Err(Error::Closed)));
        assert_eq!(read(&recreated, 0, 6).await, b"second");
    }

    /// Rewind below the committed length plus reappend commits the net state
    /// atomically.
    async fn test_rewind_reappend_net_state<S: LogStorage>(storage: &S) {
        let family = storage.open_family("net-state").await.unwrap();
        let log = commit_log(&family, b"log", b"0123456789").await;

        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&log, 4).unwrap();
        assert_eq!(txn.append(&log, b"ABCD").unwrap(), 4);
        txn.rewind(&log, 6).unwrap();
        assert_eq!(txn.append(&log, b"Z").unwrap(), 6);
        txn.commit().await.unwrap();
        assert_eq!(log.len().unwrap(), 7);
        assert_eq!(read(&log, 0, 7).await, b"0123ABZ");

        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&log, 0).unwrap();
        assert_eq!(txn.append(&log, b"fresh").unwrap(), 0);
        txn.commit().await.unwrap();
        assert_eq!(read(&log, 0, 5).await, b"fresh");
    }

    /// A second `transaction()` call waits until the live transaction commits
    /// or aborts.
    async fn test_single_writer_blocks<S: LogStorage>(storage: &S) {
        let family = storage.open_family("writer").await.unwrap();

        let txn = family.transaction().await.unwrap();
        let mut second = Box::pin(family.transaction());
        assert!((&mut second).now_or_never().is_none());
        drop(txn); // abort releases the writer
        let txn = (&mut second)
            .now_or_never()
            .expect("writer released by abort")
            .unwrap();

        let mut third = Box::pin(family.transaction());
        assert!((&mut third).now_or_never().is_none());
        txn.commit().await.unwrap();
        (&mut third)
            .now_or_never()
            .expect("writer released by commit")
            .unwrap();
    }

    /// Waiters acquire the writer in arrival order.
    async fn test_writer_fairness<S: LogStorage>(storage: &S) {
        let family = storage.open_family("fairness").await.unwrap();

        let txn = family.transaction().await.unwrap();
        let mut first = Box::pin(family.transaction());
        let mut second = Box::pin(family.transaction());
        assert!((&mut first).now_or_never().is_none());
        assert!((&mut second).now_or_never().is_none());

        drop(txn);
        assert!((&mut second).now_or_never().is_none());
        let txn = (&mut first)
            .now_or_never()
            .expect("first waiter acquires first")
            .unwrap();
        assert!((&mut second).now_or_never().is_none());
        drop(txn);
        (&mut second)
            .now_or_never()
            .expect("second waiter acquires next")
            .unwrap();
    }

    /// Cancelling a waiting `transaction()` future, before or after the writer
    /// was handed to it, never affects later waiters.
    async fn test_waiter_cancellation<S: LogStorage>(storage: &S) {
        let family = storage.open_family("cancellation").await.unwrap();

        // Cancelled before handoff: the writer skips to the next waiter.
        let txn = family.transaction().await.unwrap();
        let mut first = Box::pin(family.transaction());
        let mut second = Box::pin(family.transaction());
        assert!((&mut first).now_or_never().is_none());
        assert!((&mut second).now_or_never().is_none());
        drop(first);
        drop(txn);
        let txn = (&mut second)
            .now_or_never()
            .expect("writer skips cancelled waiter")
            .unwrap();

        // Cancelled after handoff: the pending writer passes on.
        let mut third = Box::pin(family.transaction());
        let mut fourth = Box::pin(family.transaction());
        assert!((&mut third).now_or_never().is_none());
        assert!((&mut fourth).now_or_never().is_none());
        drop(txn); // writer handed to third
        drop(third); // never claimed; must pass to fourth
        (&mut fourth)
            .now_or_never()
            .expect("writer passes on from cancelled waiter")
            .unwrap();
    }

    /// `start_commit` admits without blocking on durability; the handle
    /// resolving proves the transaction durable, visible, and the writer free.
    ///
    /// The admission/durability split itself is unobservable against a
    /// backend that commits synchronously; the Phase 1 crash harness pins it.
    async fn test_pipelined_start_commit<S: LogStorage>(storage: &S) {
        let family = storage.open_family("pipelined").await.unwrap();
        let log = commit_log(&family, b"log", b"").await;

        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b"data").unwrap();
        let handle = txn.start_commit().await.unwrap();
        handle.await.unwrap();
        assert_eq!(log.len().unwrap(), 4);
        assert_eq!(read(&log, 0, 4).await, b"data");
        Box::pin(family.transaction())
            .now_or_never()
            .expect("writer released before the handle resolved")
            .unwrap();
    }

    /// Dropping a transaction discards all staged state and frees staged
    /// names.
    async fn test_abort_by_drop<S: LogStorage>(storage: &S) {
        let family = storage.open_family("abort").await.unwrap();
        let log = commit_log(&family, b"log", b"keep").await;

        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b" more").unwrap();
        let draft = txn.create(b"draft").unwrap();
        txn.append_draft(&draft, b"x").unwrap();
        drop(txn);

        assert_eq!(log.len().unwrap(), 4);
        assert_eq!(read(&log, 0, 4).await, b"keep");
        assert!(family.open(b"draft").await.unwrap().is_none());
        commit_log(&family, b"draft", b"y").await;
    }

    /// An empty transaction commits cleanly.
    async fn test_empty_transaction<S: LogStorage>(storage: &S) {
        let family = storage.open_family("empty").await.unwrap();
        let txn = family.transaction().await.unwrap();
        txn.commit().await.unwrap();
    }

    /// Families have independent writers.
    async fn test_independent_families<S: LogStorage>(storage: &S) {
        let a = storage.open_family("independent-a").await.unwrap();
        let b = storage.open_family("independent-b").await.unwrap();
        let _txn_a = a.transaction().await.unwrap();
        Box::pin(b.transaction())
            .now_or_never()
            .expect("families have independent writers")
            .unwrap();
    }

    /// Scans return names in ascending byte order.
    async fn test_scan<S: LogStorage>(storage: &S) {
        let family = storage.open_family("scan").await.unwrap();
        commit_log(&family, b"b", b"2").await;
        commit_log(&family, b"a", b"1").await;
        commit_log(&family, b"c", b"3").await;
        assert_eq!(
            family.scan().await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        let families = storage.scan_families().await.unwrap();
        assert!(families.contains(&"scan".to_string()));
        assert!(families.is_sorted());
    }

    /// Family names must be non-empty ASCII alphanumeric, dash, or underscore.
    async fn test_family_name_validation<S: LogStorage>(storage: &S) {
        for name in ["", "bad/name", "bad name", "bad.name"] {
            assert!(storage.open_family(name).await.is_err());
            assert!(storage.destroy_family(name).await.is_err());
        }
        storage.open_family("ok-name_0").await.unwrap();
    }

    /// Reads past the end of committed, staged, or draft data fail without
    /// filling anything.
    async fn test_read_bounds<S: LogStorage>(storage: &S) {
        let family = storage.open_family("read-bounds").await.unwrap();
        let log = commit_log(&family, b"log", b"hello").await;

        assert!(matches!(
            log.read_at(0, 6).await,
            Err(Error::LogInsufficientLength)
        ));
        assert!(matches!(
            log.read_at(5, 1).await,
            Err(Error::LogInsufficientLength)
        ));
        assert!(matches!(
            log.read_at(u64::MAX, 1).await,
            Err(Error::OffsetOverflow)
        ));
        assert_eq!(read(&log, 5, 0).await, b"");

        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&log, 2).unwrap();
        assert!(matches!(
            txn.read_at(&log, 0, 3).await,
            Err(Error::LogInsufficientLength)
        ));
        let draft = txn.create(b"d").unwrap();
        assert!(matches!(
            txn.read_draft_at(&draft, 0, 1).await,
            Err(Error::LogInsufficientLength)
        ));
    }

    /// `read_at_buf` fills the caller's buffer(s), preserving their storage
    /// and layout, on every read path.
    async fn test_read_at_buf<S: LogStorage>(storage: &S) {
        let family = storage.open_family("read-buf").await.unwrap();
        let log = commit_log(&family, b"log", b"hello world").await;

        let buf = IoBufMut::zeroed(5);
        let ptr = buf.as_ref().as_ptr();
        let out = log.read_at_buf(6, 5, buf).await.unwrap();
        assert_eq!(out.chunk().as_ptr(), ptr);
        assert_eq!(out.coalesce(), b"world");

        let bufs = IoBufsMut::from(vec![IoBufMut::zeroed(3), IoBufMut::zeroed(8)]);
        let out = log.read_at_buf(0, 11, bufs).await.unwrap();
        assert_eq!(out.coalesce(), b"hello world");

        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b"!").unwrap();
        let out = txn
            .read_at_buf(&log, 0, 12, IoBufMut::zeroed(12))
            .await
            .unwrap();
        assert_eq!(out.coalesce(), b"hello world!");
        let draft = txn.create(b"d").unwrap();
        txn.append_draft(&draft, b"abc").unwrap();
        let out = txn
            .read_draft_at_buf(&draft, 1, 2, IoBufMut::zeroed(2))
            .await
            .unwrap();
        assert_eq!(out.coalesce(), b"bc");
    }

    /// Every create rejection: taken names (committed, staged, or removed by
    /// this transaction) and oversized names. Rejections stage nothing.
    async fn test_create_rejections<S: LogStorage>(storage: &S, bounds: &Bounds) {
        let family = storage.open_family("create-rejections").await.unwrap();
        let log = commit_log(&family, b"exists", b"x").await;

        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.create(b"exists"),
            Err(Error::InvalidTransaction(_))
        ));
        let _staged = txn.create(b"staged").unwrap();
        assert!(matches!(
            txn.create(b"staged"),
            Err(Error::InvalidTransaction(_))
        ));
        txn.remove(&log).unwrap();
        assert!(matches!(
            txn.create(b"exists"),
            Err(Error::InvalidTransaction(_))
        ));
        let long = vec![b'x'; bounds.max_log_name_len + 1];
        assert!(matches!(
            txn.create(&long),
            Err(Error::InvalidTransaction(_))
        ));
        let max = vec![b'y'; bounds.max_log_name_len];
        txn.create(&max).unwrap();

        // The transaction survives every rejection.
        txn.commit().await.unwrap();
        assert!(family.open(b"staged").await.unwrap().is_some());
        assert!(family.open(&max).await.unwrap().is_some());
        assert!(family.open(b"exists").await.unwrap().is_none());
    }

    /// A transaction may not touch a log it removed or remove a log it
    /// touched.
    async fn test_remove_touch_conflicts<S: LogStorage>(storage: &S) {
        let family = storage.open_family("remove-conflicts").await.unwrap();
        let a = commit_log(&family, b"a", b"1").await;
        let b = commit_log(&family, b"b", b"2").await;

        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, b"x").unwrap();
        assert!(matches!(txn.remove(&a), Err(Error::InvalidTransaction(_))));
        txn.remove(&b).unwrap();
        assert!(matches!(
            txn.append(&b, b"x"),
            Err(Error::InvalidTransaction(_))
        ));
        assert!(matches!(
            txn.rewind(&b, 0),
            Err(Error::InvalidTransaction(_))
        ));
        assert!(matches!(txn.remove(&b), Err(Error::InvalidTransaction(_))));
        assert!(matches!(
            txn.read_at(&b, 0, 1).await,
            Err(Error::InvalidTransaction(_))
        ));
    }

    /// Rewinding beyond the staged length fails and stages nothing.
    async fn test_rewind_beyond_length<S: LogStorage>(storage: &S, bounds: &Bounds) {
        let family = storage.open_family("rewind-beyond").await.unwrap();
        let log = commit_log(&family, b"log", b"hello").await;

        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.rewind(&log, 6),
            Err(Error::RewindBeyondLength {
                length: 5,
                requested: 6
            })
        ));
        // The rejection staged nothing: every log slot is still free.
        for i in 0..bounds.max_transaction_logs {
            txn.create(format!("slot-{i}").as_bytes()).unwrap();
        }
        drop(txn);

        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b"++").unwrap();
        assert!(matches!(
            txn.rewind(&log, 8),
            Err(Error::RewindBeyondLength {
                length: 7,
                requested: 8
            })
        ));
        txn.rewind(&log, 7).unwrap();
        let draft = txn.create(b"d").unwrap();
        assert!(matches!(
            txn.rewind_draft(&draft, 1),
            Err(Error::RewindBeyondLength {
                length: 0,
                requested: 1
            })
        ));
    }

    /// Transaction bounds reject oversized staging; bounds apply to net state.
    async fn test_transaction_too_large<S: LogStorage>(storage: &S, bounds: &Bounds) {
        let family = storage.open_family("too-large").await.unwrap();
        let log = commit_log(&family, b"log", b"").await;
        let max = bounds.max_transaction_bytes as usize;

        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.append(&log, vec![0u8; max + 1]),
            Err(Error::TransactionTooLarge(_))
        ));
        assert_eq!(txn.len(&log), 0); // the rejection staged nothing
        txn.append(&log, vec![0u8; max]).unwrap();
        assert!(matches!(
            txn.append(&log, vec![0u8; 1]),
            Err(Error::TransactionTooLarge(_))
        ));
        // Rewinding refunds the budget: bounds are on the net state.
        txn.rewind(&log, 0).unwrap();
        txn.append(&log, vec![1u8; max]).unwrap();
        drop(txn);

        let mut txn = family.transaction().await.unwrap();
        for i in 0..bounds.max_transaction_logs {
            txn.create(format!("draft-{i}").as_bytes()).unwrap();
        }
        assert!(matches!(
            txn.create(b"one-more"),
            Err(Error::TransactionTooLarge(_))
        ));
        assert!(matches!(
            txn.append(&log, b"x"),
            Err(Error::TransactionTooLarge(_))
        ));
    }

    /// Closed handles, foreign logs, and drafts from other transactions are
    /// rejected as targets.
    async fn test_stale_and_foreign_targets<S: LogStorage>(storage: &S) {
        let family = storage.open_family("stale").await.unwrap();
        let log = commit_log(&family, b"a", b"x").await;

        let mut txn = family.transaction().await.unwrap();
        txn.remove(&log).unwrap();
        txn.commit().await.unwrap();

        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(txn.append(&log, b"x"), Err(Error::Closed)));
        assert!(matches!(txn.rewind(&log, 0), Err(Error::Closed)));
        assert!(matches!(txn.remove(&log), Err(Error::Closed)));
        assert!(matches!(txn.read_at(&log, 0, 1).await, Err(Error::Closed)));
        drop(txn);

        let other = storage.open_family("stale-other").await.unwrap();
        let foreign = commit_log(&other, b"f", b"y").await;
        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.append(&foreign, b"x"),
            Err(Error::InvalidTransaction(_))
        ));
        drop(txn);

        let mut stray_txn = family.transaction().await.unwrap();
        let stray = stray_txn.create(b"stray").unwrap();
        drop(stray_txn);
        let mut txn = family.transaction().await.unwrap();
        assert!(matches!(
            txn.append_draft(&stray, b"x"),
            Err(Error::InvalidTransaction(_))
        ));
        assert!(matches!(
            txn.rewind_draft(&stray, 0),
            Err(Error::InvalidTransaction(_))
        ));
        assert!(matches!(
            txn.read_draft_at(&stray, 0, 0).await,
            Err(Error::InvalidTransaction(_))
        ));
        assert!(matches!(
            txn.discard(stray),
            Err(Error::InvalidTransaction(_))
        ));
    }

    /// Destruction closes handles, wakes waiting writers, and kills the live
    /// transaction; destroying an absent family succeeds.
    async fn test_destroy_family<S: LogStorage>(storage: &S) {
        let family = storage.open_family("destroy").await.unwrap();
        let log = commit_log(&family, b"a", b"data").await;

        let mut txn = family.transaction().await.unwrap();
        let mut waiter = Box::pin(family.transaction());
        assert!((&mut waiter).now_or_never().is_none());
        storage.destroy_family("destroy").await.unwrap();

        assert!(matches!(
            (&mut waiter).now_or_never(),
            Some(Err(Error::Closed))
        ));
        assert!(matches!(log.len(), Err(Error::Closed)));
        assert!(matches!(log.read_at(0, 1).await, Err(Error::Closed)));
        assert!(matches!(family.open(b"a").await, Err(Error::Closed)));
        assert!(matches!(family.scan().await, Err(Error::Closed)));
        assert!(matches!(family.transaction().await, Err(Error::Closed)));
        assert!(matches!(txn.create(b"x"), Err(Error::Closed)));
        assert!(matches!(txn.append(&log, b"x"), Err(Error::Closed)));
        assert!(matches!(txn.start_commit().await, Err(Error::Closed)));

        storage.destroy_family("destroy").await.unwrap();
        storage.destroy_family("never-existed").await.unwrap();
        assert!(
            !storage
                .scan_families()
                .await
                .unwrap()
                .contains(&"destroy".to_string())
        );
    }

    /// Destroy-then-recreate mints a fresh family identity: handles into the
    /// destroyed incarnation stay dead and can never observe the new one.
    async fn test_incarnation<S: LogStorage>(storage: &S) {
        let family = storage.open_family("incarnation").await.unwrap();
        let log = commit_log(&family, b"a", b"old").await;
        storage.destroy_family("incarnation").await.unwrap();

        let recreated = storage.open_family("incarnation").await.unwrap();
        assert!(recreated.open(b"a").await.unwrap().is_none());
        let new_log = commit_log(&recreated, b"a", b"new").await;
        assert_eq!(read(&new_log, 0, 3).await, b"new");

        assert!(matches!(family.open(b"a").await, Err(Error::Closed)));
        assert!(matches!(family.transaction().await, Err(Error::Closed)));
        assert!(matches!(log.len(), Err(Error::Closed)));
        assert!(matches!(log.read_at(0, 3).await, Err(Error::Closed)));
    }

    /// A failed admitted commit poisons the family; reopening recovers over
    /// the same incarnation with a fresh session, so old handles are dead but
    /// committed state survives.
    async fn test_poisoning_and_recovery<S: LogStorage>(
        storage: &S,
        fail_next_commit: &impl Fn(&str),
    ) {
        let family = storage.open_family("poison").await.unwrap();
        let log = commit_log(&family, b"a", b"hello").await;

        fail_next_commit("poison");
        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b" world").unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));

        // Every fallible operation fails while poisoned.
        assert!(matches!(log.len(), Err(Error::FamilyPoisoned(_))));
        assert!(matches!(
            log.read_at(0, 1).await,
            Err(Error::FamilyPoisoned(_))
        ));
        assert!(matches!(
            family.open(b"a").await,
            Err(Error::FamilyPoisoned(_))
        ));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));
        assert!(matches!(
            family.transaction().await,
            Err(Error::FamilyPoisoned(_))
        ));

        // Recovery: same incarnation, fresh session. The failed transaction's
        // outcome was indeterminate, so recovery may serve the state before
        // or after it -- but never a partial application.
        let recovered = storage.open_family("poison").await.unwrap();
        let log = recovered.open(b"a").await.unwrap().unwrap();
        let recovered_len = log.len().unwrap();
        assert!(
            recovered_len == 5 || recovered_len == 11,
            "recovery must serve a committed prefix, got length {recovered_len}"
        );

        // Old-session handles are dead; the recovered family accepts writes.
        assert!(matches!(family.open(b"a").await, Err(Error::Closed)));
        assert!(matches!(family.transaction().await, Err(Error::Closed)));
        let mut txn = recovered.transaction().await.unwrap();
        txn.append(&log, b"!").unwrap();
        txn.commit().await.unwrap();
        assert_eq!(log.len().unwrap(), recovered_len + 1);
    }

    /// Writers waiting when a commit poisons the family wake with
    /// FamilyPoisoned.
    async fn test_poisoned_waiter<S: LogStorage>(storage: &S, fail_next_commit: &impl Fn(&str)) {
        let family = storage.open_family("poisoned-waiter").await.unwrap();
        fail_next_commit("poisoned-waiter");

        let txn = family.transaction().await.unwrap();
        let mut waiter = Box::pin(family.transaction());
        assert!((&mut waiter).now_or_never().is_none());

        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));
        assert!(matches!(
            (&mut waiter).now_or_never(),
            Some(Err(Error::FamilyPoisoned(_)))
        ));
    }
}
