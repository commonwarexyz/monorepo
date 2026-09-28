//! Logical opens of each blob name and the durability state their dropped handles leave behind.

use crate::Error;
use commonware_formatting::hex;
#[cfg(test)]
use commonware_utils::channel::oneshot::Sender as OneshotSender;
use commonware_utils::{channel::watch, sync::Mutex};
#[cfg(not(target_os = "linux"))]
use std::collections::HashSet;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender};
use std::{
    collections::HashMap,
    ptr,
    sync::{Arc, Weak},
};

/// The live open of each blob name and the durability debt its dropped handles left behind.
///
/// A name has at most one live open. Its identity binds settlement to that open.
/// Dropping a handle performs no I/O. The next open waits for outstanding work and
/// flushes any remaining mutations before it succeeds. Failures remain recorded until
/// the name is removed or recreated.
#[derive(Default)]
pub(crate) struct Pending {
    pub(super) entries: Mutex<HashMap<(String, Vec<u8>), Entry>>,
    /// Names whose first open through this instance has been accounted for: created here, or
    /// an existing blob whose first-open flush debt was recorded in `entries`. There is no
    /// filesystem-wide startup flush here, so the first open of any other existing name owes
    /// a flush before trusting the file. Removing a name drops it: a later open of that name
    /// creates the blob and owes nothing.
    #[cfg(not(target_os = "linux"))]
    pub(super) flushed: Mutex<HashSet<(String, Vec<u8>)>>,
    #[cfg(test)]
    pub(super) test: Hooks,
}

/// Counters and hooks for controlling storage lifecycle tests.
///
/// Each optional hook is consumed by the next matching operation. Paired channels announce
/// arrival, then wait for a release message or for the release sender to be dropped.
#[cfg(test)]
#[derive(Default)]
pub(super) struct Hooks {
    /// Number of flushes an open performed to establish a settled predecessor's debt.
    pub(super) completions: AtomicU64,
    /// Report that the next completion is about to flush the file, then pause it.
    pub(super) before_complete: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
    /// Fail the next flush through a blob handle or an open's completion with this error.
    pub(super) fail_flush: Mutex<Option<Error>>,
    /// Pause namespace dispatch after sending or dropping its result and releasing its lock
    /// and directory hold, before returning to the caller.
    pub(super) after_dispatch: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
    /// Fail header creation with `Error::Closed` after writing this many bytes, capped at the
    /// header length.
    pub(super) fail_creation_after: Mutex<Option<usize>>,
    /// Report the current generation strong count after a liveness check, then pause while
    /// the registry remains locked.
    pub(super) after_identity_observation: Mutex<Option<(MpscSender<usize>, MpscReceiver<()>)>>,
    /// Pause an open after its predecessor settled, before it reads the debt and the file's
    /// length.
    pub(super) before_metadata: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
    /// Pause the next admission before it inspects the name's entry, letting predecessor work
    /// retire.
    pub(super) before_admit: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
}

/// Tracks one name's latest open, outstanding settlement, and retained durability state.
#[derive(Default)]
pub(super) struct Entry {
    /// Liveness checks must not acquire an owner: its destructor locks this registry.
    pub(super) identity: Weak<Generation>,
    /// Fires once every operation issued through the previous open has finished.
    pub(super) settle: Option<Receiver>,
    /// Debt the previous opens left, released by the open that establishes it.
    pub(super) dirty: bool,
    /// A durability failure retained until the name is removed or recreated.
    pub(super) failed: Option<Error>,
}

impl Entry {
    /// Whether the entry carries nothing a later open must observe.
    const fn is_clear(&self) -> bool {
        self.settle.is_none() && !self.dirty && self.failed.is_none()
    }
}

/// The live open of one namespace entry, dropped with the last handle of that open.
pub(crate) struct Generation {
    pub(super) pending: Arc<Pending>,
    pub(super) key: (String, Vec<u8>),
}

impl Generation {
    /// Release the name for a later open, returning the sender that settles this open once
    /// every operation issued through it has finished. `None` once the name was removed or
    /// recreated, or while an earlier open is still settling.
    pub(crate) fn release(&self) -> Option<Sender> {
        self.pending.start(self)
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        let mut entries = self.pending.entries.lock();
        if entries
            .get(&self.key)
            .is_some_and(|entry| ptr::eq(entry.identity.as_ptr(), self) && entry.is_clear())
        {
            entries.remove(&self.key);
        }
    }
}

/// Whether the previous open of a name has settled.
type Receiver = watch::Receiver<bool>;
pub(crate) type Sender = watch::Sender<bool>;

impl Pending {
    /// Admit an open while the backend holds its namespace lock. `existing` reports whether
    /// the file already had a valid header. Without one, the open starts a new incarnation,
    /// discards the name's previous durability state, and detaches any handle left from the
    /// previous incarnation.
    ///
    /// Returns [Error::BlobAlreadyOpen] while a handle from an earlier open of the same
    /// incarnation is alive. Returns the name's retained failure until the name is removed or
    /// recreated. Otherwise returns the open's generation, the receiver that fires once a
    /// still-settling predecessor has finished its operations, and whether the name carries
    /// debt or outstanding work the open must observe through [Self::debt] before trusting
    /// the file. Descriptor metadata must be observed after admission, or after awaiting the
    /// returned receiver.
    pub(crate) fn admit(
        self: &Arc<Self>,
        partition: &str,
        name: &[u8],
        existing: bool,
    ) -> Result<(Arc<Generation>, Option<Receiver>, bool), Error> {
        if !existing {
            self.forget(partition, Some(name));
        }
        #[cfg(test)]
        if let Some((entered, released)) = self.test.before_admit.lock().take() {
            let _ = entered.send(());
            let _ = released.recv();
        }
        let key = (partition.to_owned(), name.to_vec());
        let mut entries = self.entries.lock();
        let entry = entries.entry(key.clone()).or_default();
        let live = entry.identity.strong_count() != 0;
        #[cfg(test)]
        self.observe_identity(&entry.identity);
        if live {
            return Err(Error::BlobAlreadyOpen(partition.to_owned(), hex(name)));
        }
        if let Some(failed) = &entry.failed {
            return Err(failed.clone());
        }
        let generation = Arc::new(Generation {
            pending: self.clone(),
            key,
        });
        entry.identity = Arc::downgrade(&generation);

        // Without a filesystem-wide startup flush, this instance's first open of an existing
        // blob owes a flush of its inherited contents.
        #[cfg(not(target_os = "linux"))]
        if self.flushed.lock().insert(generation.key.clone()) && existing {
            entry.dirty = true;
        }
        let owed = entry.settle.is_some() || entry.dirty;
        Ok((generation, entry.settle.clone(), owed))
    }

    /// Register settlement only while this identity still owns its name and no earlier
    /// open is still settling.
    fn start(&self, generation: &Generation) -> Option<Sender> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(&generation.key)?;
        if !ptr::eq(entry.identity.as_ptr(), generation) || entry.settle.is_some() {
            return None;
        }
        let (sender, receiver) = watch::channel(false);
        entry.settle = Some(receiver);
        Some(sender)
    }

    /// Settle a dropped open once every operation issued through it has finished: record the
    /// debt and any failure it leaves behind, then wake the open waiting for it.
    ///
    /// Debt only accumulates. The open that establishes it releases it through [Self::clear].
    pub(crate) fn settle(
        &self,
        key: &(String, Vec<u8>),
        sender: Sender,
        dirty: bool,
        failure: Option<Error>,
    ) {
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.get_mut(key)
                && entry
                    .settle
                    .as_ref()
                    .is_some_and(|receiver| receiver.same_channel(&sender.subscribe()))
            {
                entry.settle = None;
                entry.dirty |= dirty;
                if failure.is_some() {
                    entry.failed = failure;
                }
                let live = entry.identity.strong_count() != 0;
                #[cfg(test)]
                self.observe_identity(&entry.identity);
                if !live && entry.is_clear() {
                    entries.remove(key);
                }
            }
        }
        let _ = sender.send(true);
    }

    /// Wait for the previous open's operations to finish.
    pub(crate) async fn wait(receiver: Option<Receiver>) -> Result<(), Error> {
        let Some(mut receiver) = receiver else {
            return Ok(());
        };
        receiver
            .wait_for(|settled| *settled)
            .await
            .map(|_| ())
            .map_err(|_| Error::Closed)
    }

    /// The debt the open identified by `identity` must establish before trusting its file,
    /// or the failure retained for its name. Read after the predecessor settled. Nothing is
    /// owed once the name was removed or recreated under this open.
    ///
    /// The identity is weak so a cancelled open's completion neither keeps the name open nor
    /// publishes into a successor's entry.
    pub(crate) fn debt(
        &self,
        key: &(String, Vec<u8>),
        identity: &Weak<Generation>,
    ) -> Result<bool, Error> {
        let entries = self.entries.lock();
        let Some(entry) = entries.get(key) else {
            return Ok(false);
        };
        if !Weak::ptr_eq(&entry.identity, identity) {
            return Ok(false);
        }
        if let Some(failed) = &entry.failed {
            return Err(failed.clone());
        }
        Ok(entry.dirty)
    }

    /// Publish the outcome of establishing the debt read through [Self::debt]: success
    /// releases it and a failure is retained until the name is removed or recreated.
    /// Ignored once the name was removed or recreated under this open.
    pub(crate) fn clear(
        &self,
        key: &(String, Vec<u8>),
        identity: &Weak<Generation>,
        result: &Result<(), Error>,
    ) {
        let mut entries = self.entries.lock();
        let Some(entry) = entries.get_mut(key) else {
            return;
        };
        if !Weak::ptr_eq(&entry.identity, identity) {
            return;
        }
        match result {
            Ok(()) => entry.dirty = false,
            Err(error) => entry.failed = Some(error.clone()),
        }
    }

    /// Retain a creation failure for `generation`'s name until it is removed or recreated.
    pub(crate) fn fail(&self, generation: &Generation, error: Error) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&generation.key)
            && ptr::eq(entry.identity.as_ptr(), generation)
        {
            entry.failed = Some(error);
        }
    }

    /// Detach a removed name, or every name in a removed partition.
    pub(crate) fn forget(&self, partition: &str, name: Option<&[u8]>) {
        if let Some(name) = name {
            let key = (partition.to_owned(), name.to_vec());
            self.entries.lock().remove(&key);
            #[cfg(not(target_os = "linux"))]
            self.flushed.lock().remove(&key);
        } else {
            self.entries
                .lock()
                .retain(|(stored, _), _| stored != partition);
            #[cfg(not(target_os = "linux"))]
            self.flushed
                .lock()
                .retain(|(stored, _)| stored != partition);
        }
    }
}

#[cfg(test)]
impl Pending {
    /// Report the next observed generation's strong count, then wait for release.
    fn observe_identity(&self, identity: &Weak<Generation>) {
        let hook = self.test.after_identity_observation.lock().take();
        if let Some((entered, release)) = hook {
            entered.send(identity.strong_count()).unwrap();
            let _ = release.recv();
        }
    }

    /// Take the injected failure for the next flush, if any.
    pub(crate) fn take_flush_failure(&self) -> Option<Error> {
        self.test.fail_flush.lock().take()
    }

    /// Report that a completion is about to flush, then wait for release.
    pub(crate) fn before_complete(&self) {
        let hook = self.test.before_complete.lock().take();
        if let Some((entered, released)) = hook {
            let _ = entered.send(());
            let _ = released.recv();
        }
    }

    /// Count a completion that established a predecessor's debt.
    pub(crate) fn completed(&self) {
        self.test.completions.fetch_add(1, Ordering::AcqRel);
    }

    /// Number of names whose previous open has not settled yet.
    pub(crate) fn outstanding(&self) -> usize {
        self.entries
            .lock()
            .values()
            .filter(|entry| entry.settle.is_some())
            .count()
    }

    /// Whether `name` carries debt or a retained failure no open has established yet.
    pub(crate) fn owes(&self, partition: &str, name: &[u8]) -> bool {
        self.entries
            .lock()
            .get(&(partition.to_owned(), name.to_vec()))
            .is_some_and(|entry| entry.dirty || entry.failed.is_some())
    }

    /// Number of completions opens performed for settled predecessors.
    pub(crate) fn completions(&self) -> u64 {
        self.test.completions.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread};

    fn key() -> (String, Vec<u8>) {
        ("a".to_owned(), b"1".to_vec())
    }

    fn check_last_generation_drop_during_observation(settle: bool) {
        let pending = Arc::new(Pending::default());
        let (generation, _, _) = pending.admit("a", b"1", false).unwrap();
        let identity = Arc::downgrade(&generation);
        let sender = settle.then(|| generation.release().unwrap());
        let outcome = sender.as_ref().map(|sender| sender.subscribe());
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *pending.test.after_identity_observation.lock() = Some((entered, released));
        let observer = {
            let pending = pending.clone();
            thread::spawn(move || {
                if let Some(sender) = sender {
                    pending.settle(&key(), sender, false, None);
                } else {
                    assert!(matches!(
                        pending.admit("a", b"1", true),
                        Err(Error::BlobAlreadyOpen(partition, name))
                            if partition == "a" && name == "31"
                    ));
                }
            })
        };
        let owners = entering.recv().unwrap();
        let dropper = thread::spawn(move || drop(generation));

        // Release the external owner while the registry is locked. The strong count detects
        // the last drop. Operation completion and an independent admission verify progress.
        while identity.strong_count() == owners {
            thread::yield_now();
        }
        release.send(()).unwrap();
        let independent = {
            let pending = pending.clone();
            thread::spawn(move || {
                drop(pending.admit("independent", b"2", false).unwrap());
            })
        };
        observer.join().unwrap();
        dropper.join().unwrap();
        independent.join().unwrap();
        if let Some(outcome) = outcome {
            assert!(*outcome.borrow());
        }
        assert!(pending.entries.lock().is_empty());
    }

    #[test]
    fn test_last_generation_drop_during_settle() {
        check_last_generation_drop_during_observation(true);
    }

    #[test]
    fn test_last_generation_drop_during_admit() {
        check_last_generation_drop_during_observation(false);
    }

    #[tokio::test]
    async fn test_wait_observes_settling_predecessor() {
        let pending = Arc::new(Pending::default());
        let (generation, wait, owed) = pending.admit("a", b"1", false).unwrap();
        assert!(!owed);
        Pending::wait(wait).await.unwrap();
        let sender = generation.release().unwrap();
        drop(generation);
        let (generation, wait, owed) = pending.admit("a", b"1", true).unwrap();
        assert!(owed);
        let waiter = tokio::spawn(Pending::wait(wait));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        pending.settle(&key(), sender, false, None);
        waiter.await.unwrap().unwrap();
        assert_eq!(pending.outstanding(), 0);
        assert!(!pending.debt(&key(), &Arc::downgrade(&generation)).unwrap());
        drop(generation);
        assert!(pending.entries.lock().is_empty());
    }

    #[test]
    fn test_debt_is_established_by_the_next_open() {
        let pending = Arc::new(Pending::default());
        let (first, _, _) = pending.admit("a", b"1", false).unwrap();
        let sender = first.release().unwrap();
        drop(first);
        pending.settle(&key(), sender, true, None);
        assert!(pending.owes("a", b"1"));

        // Debt accumulates across settled opens until an open establishes it.
        let (second, wait, owed) = pending.admit("a", b"1", true).unwrap();
        assert!(wait.is_none());
        assert!(owed);
        assert!(pending.debt(&key(), &Arc::downgrade(&second)).unwrap());
        let sender = second.release().unwrap();
        drop(second);
        pending.settle(&key(), sender, false, None);
        let (third, _, owed) = pending.admit("a", b"1", true).unwrap();
        assert!(owed);
        assert!(pending.debt(&key(), &Arc::downgrade(&third)).unwrap());
        pending.clear(&key(), &Arc::downgrade(&third), &Ok(()));
        assert!(!pending.debt(&key(), &Arc::downgrade(&third)).unwrap());
        assert!(!pending.owes("a", b"1"));
        drop(third);
        assert!(pending.entries.lock().is_empty());
    }

    #[test]
    fn test_failures_stay_until_forgotten() {
        let pending = Arc::new(Pending::default());

        // A failure published at settlement blocks later opens.
        let (generation, _, _) = pending.admit("a", b"1", false).unwrap();
        let sender = generation.release().unwrap();
        pending.settle(&key(), sender, false, Some(Error::Closed));
        drop(generation);
        for _ in 0..2 {
            assert!(matches!(pending.admit("a", b"1", true), Err(Error::Closed)));
        }
        pending.forget("a", Some(b"1"));

        // A failed completion is retained the same way, and success never overwrites it.
        let (generation, _, _) = pending.admit("a", b"1", false).unwrap();
        pending.clear(
            &key(),
            &Arc::downgrade(&generation),
            &Err(Error::ReadFailed),
        );
        assert!(matches!(
            pending.debt(&key(), &Arc::downgrade(&generation)),
            Err(Error::ReadFailed)
        ));
        pending.clear(&key(), &Arc::downgrade(&generation), &Ok(()));
        assert!(matches!(
            pending.debt(&key(), &Arc::downgrade(&generation)),
            Err(Error::ReadFailed)
        ));
        drop(generation);
        assert!(matches!(
            pending.admit("a", b"1", true),
            Err(Error::ReadFailed)
        ));

        // A creation failure is retained until the name is forgotten.
        pending.forget("a", Some(b"1"));
        let (generation, _, _) = pending.admit("a", b"1", false).unwrap();
        pending.fail(&generation, Error::WriteFailed);
        drop(generation);
        assert!(matches!(
            pending.admit("a", b"1", true),
            Err(Error::WriteFailed)
        ));
        pending.forget("a", Some(b"1"));
        drop(pending.admit("a", b"1", false).unwrap());
        assert!(pending.entries.lock().is_empty());
    }

    #[test]
    fn test_stale_settlement_leaves_a_recreated_name_alone() {
        let pending = Arc::new(Pending::default());
        let (old, _, _) = pending.admit("a", b"1", false).unwrap();
        let stale = old.release().unwrap();
        pending.forget("a", Some(b"1"));
        let (current, _, owed) = pending.admit("a", b"1", false).unwrap();
        assert!(!owed);

        // The removed open's settlement and outcome must not touch the replacement's entry.
        pending.settle(&key(), stale, true, Some(Error::Closed));
        assert!(old.release().is_none());
        pending.clear(&key(), &Arc::downgrade(&old), &Err(Error::Closed));
        assert!(!pending.owes("a", b"1"));
        assert!(!pending.debt(&key(), &Arc::downgrade(&current)).unwrap());
        drop(old);
        let sender = current.release().unwrap();
        drop(current);
        pending.settle(&key(), sender, false, None);
        assert!(pending.entries.lock().is_empty());
    }

    #[test]
    fn test_live_open_refuses_a_second_admit() {
        let pending = Arc::new(Pending::default());
        let (first, _, _) = pending.admit("a", b"1", false).unwrap();
        assert!(matches!(
            pending.admit("a", b"1", true),
            Err(Error::BlobAlreadyOpen(partition, name)) if partition == "a" && name == "31"
        ));
        drop(first);
        drop(pending.admit("a", b"1", true).unwrap());
    }

    #[test]
    fn test_generations_retire_and_release_clean_entries() {
        let pending = Arc::new(Pending::default());
        let (first, _, _) = pending.admit("a", b"1", false).unwrap();
        let sender = first.release().unwrap();
        drop(first);
        assert_eq!(pending.entries.lock().len(), 1);
        pending.settle(&key(), sender, false, None);
        assert!(pending.entries.lock().is_empty());

        for name in 0..128u64 {
            drop(pending.admit("clean", &name.to_be_bytes(), false).unwrap());
            assert!(pending.entries.lock().is_empty());
        }
    }
}
