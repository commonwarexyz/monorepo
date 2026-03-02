//! Waiter identity and lifecycle state for io_uring in-flight operations.
//!
//! This module owns waiter ids, cancellation identity, and completion state
//! transitions used by the io_uring event loop.

use super::{OpBuffer, OpFd, OpIovecs, Tick, UserData};
use commonware_utils::channel::oneshot;

/// Waiter slot index type. Capacity is bounded by the ring size (`u32`).
pub type SlotIndex = u32;

/// Waiter generation used to prevent stale slot-identity collisions on reuse.
///
/// The packed waiter id reserves 31 bits for this value.
#[derive(Clone, Copy)]
pub struct WaiterGeneration(u32);

impl WaiterGeneration {
    /// Bitmask for the 31-bit generation field stored in [`WaiterId`].
    const MASK: u32 = (1u32 << 31) - 1;

    /// Create a generation value, truncating to the packed 31-bit domain.
    pub const fn new(raw: u32) -> Self {
        Self(raw & Self::MASK)
    }

    /// Return the raw generation value used in packed waiter ids.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Return the next generation, wrapping in the 31-bit domain.
    pub const fn next(self) -> Self {
        Self::new(self.0.wrapping_add(1))
    }
}

/// Stable waiter identity packed into SQE/CQE `user_data`.
///
/// Layout:
/// - bits 0..31: slot index
/// - bits 32..62: generation
/// - bit 63: reserved as cancel-tag in completion `user_data`
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WaiterId(UserData);

impl WaiterId {
    /// Number of low-order bits reserved for the waiter slot index.
    const INDEX_BITS: u32 = 32;
    /// Bitmask that extracts the waiter slot index from packed user data.
    const INDEX_MASK: UserData = u32::MAX as UserData;
    /// High-bit tag used to mark cancellation CQE user data.
    const CANCEL_TAG: UserData = 1u64 << 63;

    /// Build a waiter id from slot index and generation components.
    pub const fn from_parts(index: SlotIndex, generation: WaiterGeneration) -> Self {
        Self(((generation.as_u32() as UserData) << Self::INDEX_BITS) | (index as UserData))
    }

    /// Build a waiter id at generation zero for a slot index.
    pub const fn from_slot(index: SlotIndex) -> Self {
        Self::from_parts(index, WaiterGeneration::new(0))
    }

    /// Return the slot index component of this waiter id.
    pub const fn index(self) -> SlotIndex {
        (self.0 & Self::INDEX_MASK) as SlotIndex
    }

    /// Return the generation component of this waiter id.
    const fn generation(self) -> WaiterGeneration {
        WaiterGeneration::new((self.0 >> Self::INDEX_BITS) as u32)
    }

    /// Return the SQE/CQE user_data value for the original operation.
    pub const fn op_user_data(self) -> UserData {
        self.0
    }

    /// Return the SQE/CQE user_data value for the cancel request.
    pub const fn cancel_user_data(self) -> UserData {
        self.0 | Self::CANCEL_TAG
    }

    /// Decode CQE user data into waiter id and cancellation-tag marker.
    const fn decode_user_data(user_data: UserData) -> (Self, bool) {
        let is_cancel = (user_data & Self::CANCEL_TAG) != 0;
        (Self(user_data & !Self::CANCEL_TAG), is_cancel)
    }

    /// Return the waiter id for the same slot with incremented generation.
    const fn next_generation(self) -> Self {
        Self::from_parts(self.index(), self.generation().next())
    }
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
    /// Scheduled deadline tick, when known for active-op completion.
    pub target_tick: Option<Tick>,
}

/// Lifecycle state of an in-flight waiter across operation and cancellation handling.
#[derive(Clone, Copy, Debug)]
enum WaiterState {
    /// Operation is active in the ring.
    Active {
        /// Absolute wheel tick by which the operation must complete.
        ///
        /// If completion has not been observed by this tick, cancellation is requested.
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
            let index = SlotIndex::try_from(index).expect("slot index overflow");
            WaiterId::from_slot(index)
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

    /// Return total waiter slot capacity.
    pub const fn capacity(&self) -> usize {
        self.entries.len()
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

    /// Process one completion to waiter state.
    ///
    /// Returns a completed waiter when this completion reaches terminal state
    /// for the slot, otherwise returns `None`.
    pub fn on_completion(&mut self, user_data: UserData, result: i32) -> Option<CompletedWaiter> {
        let (waiter_id, is_cancel) = WaiterId::decode_user_data(user_data);
        let index = waiter_id.index() as usize;

        let completion = {
            let waiter = self.entries.get_mut(index)?.as_mut()?;
            if waiter.id != waiter_id {
                return None;
            }
            if is_cancel {
                None
            } else {
                match &mut waiter.state {
                    WaiterState::Active { target_tick } => Some((result, false, *target_tick)),
                    WaiterState::CancelRequested => Some((result, true, None)),
                }
            }
        };

        let (result, cancelled, target_tick) = completion?;
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

    /// Request cancellation for an active waiter.
    ///
    /// Returns cancellation CQE user_data when state transitions from active to
    /// cancel-requested; otherwise returns `None`.
    ///
    /// Panics if the slot exists but is not active.
    pub fn cancel(&mut self, waiter_id: WaiterId) -> Option<UserData> {
        let index = waiter_id.index() as usize;
        let waiter = self.entries.get_mut(index)?.as_mut()?;
        if waiter.id != waiter_id {
            return None;
        }
        match waiter.state {
            WaiterState::Active {
                target_tick: Some(_),
            } => {
                waiter.state = WaiterState::CancelRequested;
                Some(waiter_id.cancel_user_data())
            }
            WaiterState::Active { target_tick: None } => {
                panic!("cancel requested for waiter without active deadline")
            }
            WaiterState::CancelRequested => {
                panic!("cancel requested for non-active waiter")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waiter_generation_wraps_at_31_bits() {
        let max = WaiterGeneration::new(WaiterGeneration::MASK);
        assert_eq!(max.next().as_u32(), 0);
    }
}
