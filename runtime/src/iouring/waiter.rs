//! Waiter identity and lifecycle state for io_uring in-flight operations.
//!
//! This module owns waiter ids, cancellation identity, and completion state
//! transitions used by the io_uring event loop.

use super::{OpBuffer, OpFd, OpIovecs, Tick, UserData};
use commonware_utils::channel::oneshot;

/// Stable waiter identity packed into SQE/CQE `user_data`.
///
/// Layout:
/// - bits 0..31: slot index
/// - bits 32..62: generation
/// - bit 63: reserved as cancel-tag in completion `user_data`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaiterId(UserData);

impl WaiterId {
    /// Number of low-order bits reserved for the waiter slot index.
    const INDEX_BITS: u32 = 32;
    /// Number of bits reserved for the generation field.
    const GENERATION_BITS: u32 = 31;
    /// Bitmask that extracts the waiter slot index from packed user data.
    const INDEX_MASK: UserData = (1u64 << Self::INDEX_BITS) - 1;
    /// Bitmask that extracts the 31-bit generation from packed user data.
    const GENERATION_MASK: UserData = (1u64 << Self::GENERATION_BITS) - 1;
    /// High-bit tag used to mark cancellation CQE user data.
    const CANCEL_TAG: UserData = 1u64 << 63;

    /// Build a waiter id from slot index and generation components.
    pub const fn new(index: u32, generation: u32) -> Self {
        let index = index as UserData;
        let generation = generation as UserData;
        Self((generation & Self::GENERATION_MASK) << Self::INDEX_BITS | index)
    }

    /// Return the slot index component of this waiter id.
    pub const fn index(self) -> u32 {
        (self.0 & Self::INDEX_MASK) as u32
    }

    /// Return the generation component of this waiter id.
    const fn generation(self) -> u32 {
        ((self.0 >> Self::INDEX_BITS) & Self::GENERATION_MASK) as u32
    }

    /// Return the waiter id for the same slot with incremented generation.
    const fn next_generation(self) -> Self {
        let generation = ((self.generation() as UserData).wrapping_add(1)) & Self::GENERATION_MASK;
        Self::new(self.index(), generation as u32)
    }

    /// Encode this waiter id as `user_data` for the operation SQE/CQE.
    ///
    /// This value contains only the packed waiter identity (slot + generation),
    /// with the cancel tag bit clear.
    pub const fn user_data(self) -> UserData {
        self.0
    }

    /// Encode this waiter id as `user_data` for the cancel SQE/CQE.
    ///
    /// This preserves the waiter identity and sets the high cancel-tag bit so
    /// completion handling can distinguish cancel CQEs from operation CQEs.
    pub const fn cancel_user_data(self) -> UserData {
        self.0 | Self::CANCEL_TAG
    }

    /// Decode `user_data` into waiter identity and cancel-tag state.
    ///
    /// The returned waiter id always has the cancel-tag bit stripped. The
    /// boolean reports whether that bit was set in the input value.
    const fn from_user_data(user_data: UserData) -> (Self, bool) {
        let is_cancel = (user_data & Self::CANCEL_TAG) != 0;
        (Self(user_data & !Self::CANCEL_TAG), is_cancel)
    }
}

/// Lifecycle state of an in-flight waiter across operation and cancellation handling.
#[derive(Clone, Copy, Debug)]
enum WaiterState {
    /// Operation is active in the ring.
    Active {
        /// Absolute wheel tick by which the operation must complete.
        ///
        /// If completion has not been observed by this tick, cancellation is
        /// requested. `None` means this waiter has no timeout deadline.
        target_tick: Option<Tick>,
    },
    /// Cancellation was requested and cancel SQE was submitted.
    CancelRequested,
}

/// State for one in-flight operation.
///
/// Holds the sender used for completion delivery and resources that must remain alive
/// until CQE delivery.
struct Waiter {
    /// Stable identity of this waiter slot instance.
    id: WaiterId,
    /// The oneshot sender used to deliver the operation result and buffer back to the
    /// caller.
    sender: oneshot::Sender<(i32, Option<OpBuffer>)>,
    /// Waiter completion state.
    state: WaiterState,
    /// The buffer associated with this operation, if any.
    buffer: Option<OpBuffer>,
    /// The file descriptor associated with this operation, if any. Used to keep the file
    /// descriptor alive and prevent reuse while the operation is in-flight.
    ///
    /// NOTE: This field is never read since it only exists to keep the FD alive until
    /// operation completion, hence the allow dead code.
    #[allow(dead_code)]
    fd: Option<OpFd>,
    /// The iovec array associated with this operation, if any. Used to keep iovec
    /// storage alive and prevent use-after-free while the operation is in-flight.
    ///
    /// NOTE: This field is never read since it only exists to keep iovecs alive until
    /// operation completion, hence the allow dead code.
    #[allow(dead_code)]
    iovecs: Option<OpIovecs>,
}

/// Waiter resources and metadata returned when a waiter reaches terminal state.
pub struct CompletedWaiter {
    /// Sender used to deliver completion back to the original caller.
    pub sender: oneshot::Sender<(i32, Option<OpBuffer>)>,
    /// Buffer to return to the caller.
    pub buffer: Option<OpBuffer>,
    /// Operation result code.
    pub result: i32,
    /// True when completion happened through cancellation handling.
    pub cancelled: bool,
    /// Scheduled deadline tick, when known.
    ///
    /// `None` means there is no deadline to remove from timeout tracking (either no
    /// deadline was set, or completion was observed after cancellation had already
    /// been requested).
    pub target_tick: Option<Tick>,
}

/// Tracks in-flight operations and the state needed to complete them.
pub struct Waiters {
    /// Waiters indexed by slot index.
    ///
    /// Free slots have no waiter (`None`).
    entries: Vec<Option<Waiter>>,
    /// Stack of reusable waiter ids.
    free: Vec<WaiterId>,
    /// Number of active waiters currently stored in `entries`.
    len: usize,
}

impl Waiters {
    /// Create an empty waiter set that can track at most `capacity` in-flight operations
    /// at once.
    pub fn new(capacity: usize) -> Self {
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);

        let mut free = Vec::with_capacity(capacity);
        free.extend((0..capacity).rev().map(|index| {
            let index = u32::try_from(index).expect("slot index overflow");
            WaiterId::new(index, 0)
        }));

        Self {
            entries,
            free,
            len: 0,
        }
    }

    /// Return the number of currently in-flight waiters.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether there are no in-flight waiters.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a waiter and return its assigned id.
    ///
    /// Panics if no free slot is available.
    pub fn insert(
        &mut self,
        sender: oneshot::Sender<(i32, Option<OpBuffer>)>,
        buffer: Option<OpBuffer>,
        fd: Option<OpFd>,
        iovecs: Option<OpIovecs>,
        target_tick: Option<Tick>,
    ) -> WaiterId {
        let id = self
            .free
            .pop()
            .expect("waiters should not exceed configured capacity");
        let index = id.index() as usize;
        let replaced = self.entries[index].replace(Waiter {
            id,
            sender,
            state: WaiterState::Active { target_tick },
            buffer,
            fd,
            iovecs,
        });
        assert!(replaced.is_none(), "free slot should not contain waiter");
        self.len += 1;
        id
    }

    /// Request cancellation for an active waiter.
    ///
    /// Returns cancellation `user_data` when the waiter exists and is active.
    /// Returns `None` when the waiter id is stale, not present, or already
    /// cancel-requested.
    ///
    /// Panics if `waiter_id` encodes a slot index outside this waiters set capacity.
    pub fn cancel(&mut self, waiter_id: WaiterId) -> Option<UserData> {
        let index = waiter_id.index() as usize;
        let waiter = self.entries[index].as_mut()?;
        if waiter.id != waiter_id {
            return None;
        }
        match waiter.state {
            WaiterState::Active { .. } => {
                waiter.state = WaiterState::CancelRequested;
                Some(waiter_id.cancel_user_data())
            }
            WaiterState::CancelRequested => None,
        }
    }

    /// Process one completion to waiter state.
    ///
    /// Returns a completed waiter when this completion reaches terminal state for
    /// the waiter id, otherwise returns `None`.
    ///
    /// `None` includes stale waiter ids (for example, the slot was reused with a
    /// newer generation).
    ///
    /// Panics if `user_data` decodes to a slot index outside this waiters set
    /// capacity.
    pub fn on_completion(&mut self, user_data: UserData, result: i32) -> Option<CompletedWaiter> {
        let (waiter_id, is_cancel) = WaiterId::from_user_data(user_data);
        let index = waiter_id.index() as usize;

        let waiter = self.entries[index].as_mut()?;
        if waiter.id != waiter_id {
            // Slot was reused, this CQE belongs to an older waiter generation.
            return None;
        }

        if is_cancel {
            // Cancel CQEs acknowledge cancel requests but do not complete waiters.
            return None;
        }

        let (cancelled, target_tick) = match waiter.state {
            WaiterState::Active { target_tick } => (false, target_tick),
            WaiterState::CancelRequested => (true, None),
        };

        let Waiter {
            id, sender, buffer, ..
        } = self.entries[index].take().expect("missing waiter");

        self.free.push(id.next_generation());
        self.len -= 1;

        Some(CompletedWaiter {
            sender,
            buffer,
            result,
            cancelled,
            target_tick,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iobuf::{IoBuf, IoBufs};
    use std::{
        os::unix::net::UnixStream,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Arc,
    };

    #[test]
    fn test_waiter_id_encoding_and_generation_wrap() {
        let wrapped = WaiterId::new(7, (WaiterId::GENERATION_MASK as u32).wrapping_add(5));
        assert_eq!(wrapped.generation(), 4);

        let max = WaiterId::new(7, WaiterId::GENERATION_MASK as u32);
        assert_eq!(max.next_generation().generation(), 0);

        let waiter_id = WaiterId::new(7, 3);
        assert_eq!(waiter_id.index(), 7);
        assert_eq!(waiter_id.generation(), 3);

        let (decoded_op, is_cancel_op) = WaiterId::from_user_data(waiter_id.user_data());
        assert_eq!(decoded_op, waiter_id);
        assert!(!is_cancel_op);

        let (decoded_cancel, is_cancel) = WaiterId::from_user_data(waiter_id.cancel_user_data());
        assert_eq!(decoded_cancel, waiter_id);
        assert!(is_cancel);
    }

    #[test]
    fn test_waiters_lifecycle_and_slot_reuse() {
        let mut waiters = Waiters::new(3);
        assert_eq!(waiters.entries.len(), 3);
        assert_eq!(waiters.len(), 0);
        assert!(waiters.is_empty());

        let (tx0, _rx0) = oneshot::channel();
        let (tx1, _rx1) = oneshot::channel();
        let id0 = waiters.insert(tx0, Some(IoBuf::from(b"hello").into()), None, None, Some(5));
        let id1 = waiters.insert(tx1, Some(IoBuf::from(b"world").into()), None, None, Some(9));
        assert_eq!((id0.index(), id1.index()), (0, 1));
        assert_eq!(waiters.len(), 2);

        // Completion for a stale generation must be ignored.
        let stale = WaiterId::new(id1.index(), id1.generation().wrapping_add(1));
        assert!(waiters.on_completion(stale.user_data(), 0).is_none());

        let completed1 = waiters
            .on_completion(id1.user_data(), 7)
            .expect("missing waiter completion");
        assert_eq!(completed1.result, 7);
        assert!(!completed1.cancelled);
        assert_eq!(completed1.target_tick, Some(9));
        assert!(matches!(
            completed1.buffer.as_ref(),
            Some(OpBuffer::Write(buf)) if buf.as_ref() == b"world"
        ));
        assert_eq!(waiters.len(), 1);

        // Next allocation reuses the freed slot with incremented generation.
        let (tx2, _rx2) = oneshot::channel();
        let id2 = waiters.insert(tx2, None, None, None, Some(11));
        assert_eq!(id2.index(), id1.index());
        assert_eq!(
            id2.generation(),
            id1.generation().wrapping_add(1) & (WaiterId::GENERATION_MASK as u32)
        );

        let _ = waiters.on_completion(id0.user_data(), 1);
        let _ = waiters.on_completion(id2.user_data(), 2);

        // Cover vectored buffers plus fd/iovec keepalive storage.
        let (tx3, _rx3) = oneshot::channel();
        let vectored = IoBufs::from(vec![IoBuf::from(b"ab"), IoBuf::from(b"cd")]);
        let iovecs = OpIovecs::new(
            vec![libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }]
            .into_boxed_slice(),
        );
        assert!(!iovecs.as_ptr().is_null());
        let (sock_left, _sock_right) =
            UnixStream::pair().expect("failed to create unix socket pair");
        let id3 = waiters.insert(
            tx3,
            Some(vectored.into()),
            Some(OpFd::Fd(Arc::new(sock_left.into()))),
            Some(iovecs),
            None,
        );
        let completed3 = waiters
            .on_completion(id3.user_data(), 9)
            .expect("missing vectored completion");
        assert!(matches!(
            completed3.buffer,
            Some(OpBuffer::WriteVectored(_))
        ));
        assert!(waiters.is_empty());
    }

    #[test]
    fn test_waiters_cancel_paths() {
        let mut waiters = Waiters::new(3);

        let (tx, _rx) = oneshot::channel();
        let waiter_id = waiters.insert(tx, None, None, None, Some(2));

        let stale = WaiterId::new(waiter_id.index(), waiter_id.generation().wrapping_add(1));
        assert!(waiters.cancel(stale).is_none());

        let cancel = waiters
            .cancel(waiter_id)
            .expect("cancel should transition active waiter");
        assert_eq!(cancel, waiter_id.cancel_user_data());

        // Cancel CQE does not complete the waiter. The op CQE delivers the result.
        assert!(waiters.on_completion(cancel, -libc::ECANCELED).is_none());
        let completed = waiters
            .on_completion(waiter_id.user_data(), 123)
            .expect("missing completion");
        assert_eq!(completed.result, 123);
        assert!(completed.cancelled);
        assert_eq!(completed.target_tick, None);
        assert!(waiters.is_empty());

        // Late cancel CQE for the already-completed waiter should be ignored.
        assert!(waiters
            .on_completion(waiter_id.cancel_user_data(), -libc::ECANCELED)
            .is_none());
        assert!(waiters.on_completion(0, 1).is_none());
    }

    #[test]
    fn test_waiters_insert_and_cancel_invariants() {
        let mut waiters = Waiters::new(2);

        let (tx0, _rx0) = oneshot::channel();
        let (tx1, _rx1) = oneshot::channel();
        let _ = waiters.insert(tx0, None, None, None, None);
        let _ = waiters.insert(tx1, None, None, None, None);
        let insert_overflow = catch_unwind(AssertUnwindSafe(|| {
            let (tx2, _rx2) = oneshot::channel();
            let _ = waiters.insert(tx2, None, None, None, None);
        }));
        assert!(insert_overflow.is_err());

        let mut waiters = Waiters::new(2);
        let (tx, _rx) = oneshot::channel();
        let no_deadline = waiters.insert(tx, None, None, None, None);
        let cancel = waiters
            .cancel(no_deadline)
            .expect("cancel should support active waiter without deadline");
        assert_eq!(cancel, no_deadline.cancel_user_data());

        let (tx, _rx) = oneshot::channel();
        let active = waiters.insert(tx, None, None, None, Some(3));
        let _ = waiters.cancel(active);
        assert!(waiters.cancel(active).is_none());
    }
}
