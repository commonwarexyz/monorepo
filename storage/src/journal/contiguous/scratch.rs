//! Per-thread scratch values that synchronous probes reuse across calls, up to a size limit.

use bytes::BytesMut;
use commonware_utils::Cached;
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    thread::LocalKey,
};

/// Bytes a scratch value may keep allocated between calls. A value that grew past this for an
/// unusually large request is freed when its guard drops, rather than staying with the thread.
pub(super) const RETAINED_BYTES: usize = 1 << 20;

/// A scratch value whose allocation can be measured.
pub(super) trait Allocation: Default {
    /// Bytes the value has allocated.
    fn allocated(&self) -> usize;
}

impl<T> Allocation for Vec<T> {
    fn allocated(&self) -> usize {
        self.capacity().saturating_mul(size_of::<T>())
    }
}

impl Allocation for BytesMut {
    fn allocated(&self) -> usize {
        self.capacity()
    }
}

/// This thread's scratch value from a `thread_local_cache!` slot. It returns to the thread when
/// dropped, unless it has grown past [RETAINED_BYTES].
pub(super) struct Scratch<T: Allocation + 'static>(Cached<T>);

impl<T: Allocation + 'static> Scratch<T> {
    /// Take this thread's value from `cache`, prepared by `reset`, or a new one.
    pub(super) fn take(
        cache: &'static LocalKey<RefCell<(bool, Option<T>)>>,
        reset: impl FnOnce(&mut T),
    ) -> Self {
        let cached = Cached::take(
            cache,
            || Ok::<_, ()>(T::default()),
            |value| {
                reset(value);
                Ok(())
            },
        )
        .expect("scratch preparation does not fail");
        Self(cached)
    }
}

impl<T: Allocation + 'static> Deref for Scratch<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Allocation + 'static> DerefMut for Scratch<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Allocation + 'static> Drop for Scratch<T> {
    fn drop(&mut self) {
        if self.0.allocated() > RETAINED_BYTES {
            *self.0 = T::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    commonware_utils::thread_local_cache!(static TEST_VEC: Vec<u8>);
    commonware_utils::thread_local_cache!(static TEST_BYTES: BytesMut);

    #[test]
    fn test_scratch_keeps_allocations_up_to_the_limit() {
        {
            let mut scratch = Scratch::take(&TEST_VEC, Vec::clear);
            scratch.resize(RETAINED_BYTES, 0);
        }
        assert_eq!(
            Scratch::take(&TEST_VEC, Vec::clear).capacity(),
            RETAINED_BYTES
        );

        // A larger allocation is freed instead of returning to the thread.
        {
            let mut scratch = Scratch::take(&TEST_VEC, Vec::clear);
            scratch.resize(RETAINED_BYTES + 1, 0);
        }
        assert_eq!(Scratch::take(&TEST_VEC, Vec::clear).capacity(), 0);
    }

    #[test]
    fn test_scratch_frees_large_byte_buffers() {
        {
            let mut scratch = Scratch::take(&TEST_BYTES, |_| {});
            scratch.resize(RETAINED_BYTES + 1, 0);
        }
        assert_eq!(Scratch::take(&TEST_BYTES, |_| {}).capacity(), 0);
    }
}
