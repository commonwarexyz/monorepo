//! Target-dependent thread-safety bounds.

/// A value that may cross the runtime's scheduling boundary.
///
/// Native runtimes may schedule work on another thread, so this requires
/// [`Send`]. The browser runtime stays on one event-loop thread and does not.
#[cfg(not(target_arch = "wasm32"))]
pub trait PlatformSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> PlatformSend for T {}

/// A value that may cross the runtime's scheduling boundary.
///
/// Browser tasks remain on the current event-loop thread.
#[cfg(target_arch = "wasm32")]
pub trait PlatformSend {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> PlatformSend for T {}

/// A value that may be shared by runtime capabilities.
///
/// Native runtimes may access capabilities from multiple threads, so this
/// requires [`Sync`]. The browser runtime stays on one event-loop thread and
/// does not.
#[cfg(not(target_arch = "wasm32"))]
pub trait PlatformSync: Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> PlatformSync for T {}

/// A value that may be shared by runtime capabilities.
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
