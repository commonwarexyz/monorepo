//! Target-dependent thread-safety bounds.

/// A value that may cross a platform scheduling boundary.
///
/// Native targets may move work to another thread, so this requires [`Send`].
/// Browser WASM stays on one event-loop thread and does not.
#[cfg(not(target_arch = "wasm32"))]
pub trait PlatformSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> PlatformSend for T {}

/// A value that may cross a platform scheduling boundary.
///
/// Browser tasks remain on the current event-loop thread.
#[cfg(target_arch = "wasm32")]
pub trait PlatformSend {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> PlatformSend for T {}

/// A value that may be shared across a platform scheduling boundary.
///
/// Native targets may access shared state from multiple threads, so this
/// requires [`Sync`]. Browser WASM stays on one event-loop thread and does not.
#[cfg(not(target_arch = "wasm32"))]
pub trait PlatformSync: Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> PlatformSync for T {}

/// A value that may be shared across a platform scheduling boundary.
///
/// Browser tasks remain on the current event-loop thread.
#[cfg(target_arch = "wasm32")]
pub trait PlatformSync {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> PlatformSync for T {}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{PlatformSend, PlatformSync};

    fn assert_send<T: Send + ?Sized>() {}
    fn assert_sync<T: Sync + ?Sized>() {}

    #[test]
    fn native_platform_bounds_imply_thread_safety() {
        fn assert_platform_send<T: PlatformSend + ?Sized>() {
            assert_send::<T>();
        }

        fn assert_platform_sync<T: PlatformSync + ?Sized>() {
            assert_sync::<T>();
        }

        assert_platform_send::<usize>();
        assert_platform_sync::<usize>();
    }
}
