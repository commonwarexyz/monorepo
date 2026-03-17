//! Waiter identity and lifecycle state for io_uring in-flight requests.
//!
//! This module manages waiter IDs and request lifecycle transitions.
//! It is the source of truth for in-flight request completion state.

use super::{request::ActiveRequest, Tick, UserData};
use tracing::warn;

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
    pub const fn from_user_data(user_data: UserData) -> (Self, bool) {
        let is_cancel = (user_data & Self::CANCEL_TAG) != 0;
        (Self(user_data & !Self::CANCEL_TAG), is_cancel)
    }
}

/// Lifecycle state of an in-flight request.
#[derive(Clone, Copy, Debug)]
pub enum WaiterState {
    /// Request is active in the ring.
    Active {
        /// Absolute wheel tick by which the request must complete.
        ///
        /// If completion has not been observed by this tick, cancellation is
        /// requested. `None` means this request has no timeout deadline.
        target_tick: Option<Tick>,
    },
    /// Cancellation was requested and cancel SQE was submitted.
    CancelRequested,
}

/// State for one in-flight logical request.
struct Waiter {
    /// Stable identity of this waiter slot instance.
    id: WaiterId,
    state: WaiterState,
    /// The active request state machine.
    request: ActiveRequest,
}

/// Tracks in-flight logical requests and the state needed to complete them.
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
    /// Create an empty waiter set that can track at most `capacity` in-flight
    /// requests at once.
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

    /// Insert a request and return its assigned id.
    ///
    /// Panics if no free slot is available.
    pub fn insert(&mut self, request: ActiveRequest, target_tick: Option<Tick>) -> WaiterId {
        let id = self
            .free
            .pop()
            .expect("waiters should not exceed configured capacity");
        let index = id.index() as usize;
        let replaced = self.entries[index].replace(Waiter {
            id,
            state: WaiterState::Active { target_tick },
            request,
        });
        assert!(replaced.is_none(), "free slot should not contain waiter");
        self.len += 1;
        id
    }

    /// Request cancellation for an active waiter.
    ///
    /// Returns `true` when the waiter was successfully transitioned to
    /// cancel-requested. Returns `false` when the waiter id is stale, not
    /// present, or already cancel-requested.
    pub fn cancel(&mut self, waiter_id: WaiterId) -> bool {
        let Some(slot) = self.entries.get_mut(waiter_id.index() as usize) else {
            return false;
        };
        let Some(slot) = slot.as_mut() else {
            return false;
        };
        if slot.id != waiter_id {
            return false;
        }
        match slot.state {
            WaiterState::Active { .. } => {
                slot.state = WaiterState::CancelRequested;
                true
            }
            WaiterState::CancelRequested => false,
        }
    }

    /// Get mutable access to a request slot by user_data.
    ///
    /// Process one CQE for a waiter.
    ///
    /// Returns the request, its state, and waiter id if the slot is occupied
    /// and the generation matches.
    ///
    /// Cancel CQEs are handled internally and always return `None`.
    pub fn on_cqe(
        &mut self,
        user_data: UserData,
        result: i32,
    ) -> Option<(&mut ActiveRequest, WaiterState, WaiterId)> {
        let (waiter_id, is_cancel) = WaiterId::from_user_data(user_data);
        let index = waiter_id.index() as usize;

        let slot = self.entries[index].as_mut()?;
        if slot.id != waiter_id {
            return None;
        }

        if is_cancel {
            match result.abs() {
                0 => {
                    // Cancellation successful.
                }
                libc::EALREADY => {
                    // Cancellation is no longer possible at this stage. The target
                    // operation CQE should follow shortly.
                }
                libc::ENOENT => {
                    // Not found can mean the target already completed (common race) or
                    // stale/invalid user_data.
                }
                libc::EINVAL => {
                    panic!("async cancel SQE rejected by kernel: EINVAL");
                }
                result => {
                    warn!(result, "unexpected async cancel CQE result");
                }
            }

            // Cancel CQEs acknowledge cancel requests but do not complete waiters.
            return None;
        }

        let state = slot.state;
        Some((&mut slot.request, state, waiter_id))
    }

    /// Get mutable access to a request by waiter id.
    ///
    /// Used by the loop to build SQEs for requests that are already in the
    /// waiter table (e.g., from the ready queue).
    pub fn get_mut(&mut self, waiter_id: WaiterId) -> Option<(&mut ActiveRequest, WaiterState)> {
        let index = waiter_id.index() as usize;
        let slot = self.entries[index].as_mut()?;
        if slot.id != waiter_id {
            return None;
        }
        Some((&mut slot.request, slot.state))
    }

    /// Remove a completed request slot by waiter id.
    ///
    /// Returns the `ActiveRequest` so the caller can finish it. The slot is
    /// freed and its generation incremented for reuse.
    ///
    /// Returns `None` if the slot is empty or the generation doesn't match.
    pub fn remove(&mut self, waiter_id: WaiterId) -> Option<ActiveRequest> {
        let index = waiter_id.index() as usize;
        let slot = self.entries[index].as_ref()?;
        if slot.id != waiter_id {
            return None;
        }
        let slot = self.entries[index].take().expect("missing waiter");
        self.free.push(slot.id.next_generation());
        self.len -= 1;
        Some(slot.request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::request::{ActiveRequest, Request, SyncRequest};
    use commonware_utils::channel::oneshot;
    use std::{
        os::fd::{FromRawFd, IntoRawFd},
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Arc,
    };

    fn make_sync_request() -> (ActiveRequest, oneshot::Receiver<std::io::Result<()>>) {
        let (sock_left, _sock_right) =
            std::os::unix::net::UnixStream::pair().expect("failed to create unix socket pair");
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, rx) = oneshot::channel();
        let request = ActiveRequest::from_request(Request::Sync(SyncRequest {
            file: Arc::new(file),
            sender: tx,
        }));
        (request, rx)
    }

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

        let (req0, _rx0) = make_sync_request();
        let (req1, _rx1) = make_sync_request();
        let id0 = waiters.insert(req0, Some(5));
        let id1 = waiters.insert(req1, Some(9));
        assert_eq!((id0.index(), id1.index()), (0, 1));
        assert_eq!(waiters.len(), 2);

        // Completion for a stale generation must be ignored.
        let stale = WaiterId::new(id1.index(), id1.generation().wrapping_add(1));
        assert!(waiters.on_cqe(stale.user_data(), 0).is_none());

        // Complete id1.
        let result = waiters.on_cqe(id1.user_data(), 0);
        assert!(result.is_some());
        let request = waiters.remove(id1);
        assert!(request.is_some());
        assert_eq!(waiters.len(), 1);

        // Next allocation reuses the freed slot with incremented generation.
        let (req2, _rx2) = make_sync_request();
        let id2 = waiters.insert(req2, Some(11));
        assert_eq!(id2.index(), id1.index());
        assert_eq!(
            id2.generation(),
            id1.generation().wrapping_add(1) & (WaiterId::GENERATION_MASK as u32)
        );

        let _ = waiters.on_cqe(id0.user_data(), 0);
        let _ = waiters.remove(id0);
        let _ = waiters.on_cqe(id2.user_data(), 0);
        let _ = waiters.remove(id2);
        assert!(waiters.is_empty());
    }

    #[test]
    fn test_waiters_cancel_paths() {
        let mut waiters = Waiters::new(3);

        let (req, _rx) = make_sync_request();
        let waiter_id = waiters.insert(req, Some(2));

        let stale = WaiterId::new(waiter_id.index(), waiter_id.generation().wrapping_add(1));
        assert!(!waiters.cancel(stale));

        assert!(
            waiters.cancel(waiter_id),
            "cancel should transition active waiter"
        );

        // Cancel CQE does not complete the waiter.
        assert!(waiters
            .on_cqe(waiter_id.cancel_user_data(), -libc::ECANCELED)
            .is_none());

        // Op CQE completes the waiter.
        let result = waiters.on_cqe(waiter_id.user_data(), 0);
        assert!(result.is_some());
        let (_, state, _) = result.unwrap();
        assert!(matches!(state, WaiterState::CancelRequested));
        let _ = waiters.remove(waiter_id);
        assert!(waiters.is_empty());

        // Late cancel CQE for the already-completed waiter should be ignored.
        assert!(waiters
            .on_cqe(waiter_id.cancel_user_data(), -libc::ECANCELED)
            .is_none());
        assert!(waiters.on_cqe(0, 1).is_none());
    }

    #[test]
    fn test_waiters_insert_and_cancel_invariants() {
        let mut waiters = Waiters::new(2);

        // Inserting beyond configured capacity should panic.
        let (req0, _rx0) = make_sync_request();
        let (req1, _rx1) = make_sync_request();
        let _ = waiters.insert(req0, None);
        let _ = waiters.insert(req1, None);
        let insert_overflow = catch_unwind(AssertUnwindSafe(|| {
            let (req2, _rx2) = make_sync_request();
            let _ = waiters.insert(req2, None);
        }));
        assert!(insert_overflow.is_err());

        // Cancellation is allowed even when no deadline is tracked.
        let mut waiters = Waiters::new(2);
        let (req, _rx) = make_sync_request();
        let no_deadline = waiters.insert(req, None);
        assert!(
            waiters.cancel(no_deadline),
            "cancel should support active waiter without deadline"
        );

        // Repeated cancel on the same waiter must be ignored.
        let (req, _rx) = make_sync_request();
        let active = waiters.insert(req, Some(3));
        assert!(waiters.cancel(active));
        assert!(!waiters.cancel(active));
    }
}
