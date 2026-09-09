//! Hardened storage for [crate::Secret] on Linux.
//!
//! Three owners split the work:
//!
//! - [Mapping] owns the pages and their cleanup. It never interprets the bytes
//!   as `T`, so it can erase and unmap after partial construction, extraction,
//!   or a panicking destructor.
//! - [ProtectedAllocation] owns the initialized `T` and the reader count. Its
//!   metadata, including the reader mutex, lives in ordinary memory.
//! - [HardenedSecret] is an `Arc` handle. Clones share one allocation.
//!
//! Terminology here and in the item docs: the wrapper is the public `Secret<T>`,
//! a handle is one `HardenedSecret<T>`, the allocation is its
//! `ProtectedAllocation<T>`, the mapping is the whole mmap region including
//! guards, and the data region is the page-rounded part between the guards.
//! Only the data region is locked or changes permissions.
//!
//! # Layout
//!
//! ```text
//! base             data                                  data + data_len
//! |                |                                     |
//! v                v                                     v
//! +----------------+-----------------------+-------------+----------------+
//! | leading guard  | unused data bytes     | T           | trailing guard |
//! +----------------+-----------------------+-------------+----------------+
//! |<-- one page -->|<---------- whole data pages ------->|<-- one page -->|
//!
//! Guards: NONE for the mapping's lifetime, never locked
//! Data:   locked, excluded from kernel cores, wiped in fork children
//! T:      ends at the trailing guard
//! ```
//!
//! - `data_len = round_up(max(size_of::<T>(), 1), page_size)`, so a zero-sized
//!   value still owns a data page. Checked arithmetic keeps both guards within
//!   Rust's `isize::MAX` allocation bound.
//! - The page size must be a power of two and `T`'s alignment must divide it.
//!   Rust sizes are multiples of alignment, so ending `T` at the trailing guard
//!   aligns it. A zero-sized `T` may sit exactly at the guard boundary.
//! - Unused data bytes before `T` share the data permissions, so an underrun
//!   need not reach the leading guard.
//!
//! # Lifecycle
//!
//! ```text
//!      allocate: mmap, protect(RW), madvise, mlock
//!               |
//!               v
//!      +-----------------+  copy T into the data region
//!      | SETUP       RW  |  any failure: erase, unmap, return the error
//!      +-----------------+
//!               | protect(NONE), publish
//!               v
//!      +-----------------+  lock, protect(READ) if readers == 0,   +-----------------+
//!      | IDLE      NONE  |  readers += 1, unlock                   | READABLE  READ  |
//!      | readers = 0     | --------------------------------------> | readers > 0     |
//!      |                 | <-------------------------------------- | f(&T), unlocked |
//!      +-----------------+  lock, readers -= 1,                    +-----------------+
//!               |            protect(NONE) if readers == 0, unlock
//!               |
//!               | unique extraction or final release: exclusive, so readers = 0
//!               v
//!      +-----------------+
//!      | RELEASE     RW  |  move out or drop T, erase the data region, unmap
//!      +-----------------+
//!
//!      After publication, a failed protect or a reader count overflow aborts.
//! ```
//!
//! # Fork
//!
//! `MADV_WIPEONFORK` gives a child zeroed data pages, so the secret never
//! crosses `fork`. Nothing detects the child. An inherited handle used there
//! reads zeros, and dropping it runs `T`'s destructor on those zeros before
//! erasing and unmapping the child's copy. The child also inherits the `Arc`
//! count, the reader mutex, and the reader count exactly as they were at fork,
//! so a mutex held by another parent thread at that moment stays locked forever
//! in the child. The public contract makes leaving inherited hardened values
//! alone in a child the caller's obligation.

use crate::secret::{HardenError, InlineSecret};
use commonware_utils::sync::Mutex;
use std::{
    io,
    mem::{ManuallyDrop, MaybeUninit, align_of, size_of},
    process,
    ptr::{self, NonNull},
    slice,
    sync::Arc,
};
use zeroize::Zeroize;

/// Handle to one shared protected allocation.
pub(crate) struct HardenedSecret<T> {
    inner: Arc<ProtectedAllocation<T>>,
}

impl<T> HardenedSecret<T> {
    /// Copies the inline value into protected storage, preserving it on error.
    ///
    /// # Safety
    ///
    /// On success, the returned allocation owns `T`. The caller must immediately
    /// erase and retire the source without accessing or dropping its value, and
    /// without an intervening operation that can panic. On error, the source
    /// remains its sole owner and is unchanged.
    pub(crate) unsafe fn try_from_inline(value: &mut InlineSecret<T>) -> Result<Self, HardenError> {
        let (mapping, destination) = Mapping::allocate::<T>()?;

        // Allocate metadata and prepare the reader mutex before transferring ownership.
        let mut inner = Arc::<ProtectedAllocation<T>>::new_uninit();
        let slot = Arc::get_mut(&mut inner).unwrap();
        let readers = Mutex::new(0);

        value.access(|source| {
            // SAFETY: The destination is writable, aligned, and disjoint from the
            // initialized source. This is only a raw copy. Until sealing succeeds,
            // Mapping owns cleanup and never accesses or destroys it as T.
            unsafe { ptr::copy_nonoverlapping(source, destination.as_ptr(), 1) };
        });

        mapping.protect(libc::PROT_NONE)?;

        // No fallible or panicking operations may follow the ownership transfer.
        slot.write(ProtectedAllocation {
            mapping,
            value: destination,
            readers,
        });

        Ok(Self {
            // SAFETY: The Arc's unique slot was initialized above. The caller
            // retires the inline source as required by this function's contract.
            inner: unsafe { inner.assume_init() },
        })
    }

    /// Runs `f` inside a shared readable interval.
    ///
    /// The reader mutex is not held during `f`, and unwinding releases the
    /// reader slot.
    pub(crate) fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        self.inner.access(f)
    }

    /// Moves out `T` and erases its allocation, or returns this handle if shared.
    ///
    /// A shared allocation is left untouched.
    pub(crate) fn try_extract(self) -> Result<T, Self> {
        match Arc::try_unwrap(self.inner) {
            Ok(allocation) => Ok(allocation.extract()),
            Err(inner) => Err(Self { inner }),
        }
    }
}

impl<T> Clone for HardenedSecret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Owns the raw pages independently of `T`'s initialization and destruction.
///
/// Only the data region is locked or changes permissions. The bytes are never
/// interpreted as `T`. See the module documentation for the layout and the
/// lifecycle.
struct Mapping {
    /// Start of the entire mapping, including the leading guard.
    base: NonNull<u8>,
    /// Length passed to munmap, including both guards.
    total_len: usize,
    /// First byte after the leading guard.
    data: NonNull<u8>,
    /// Page-rounded length of the data region, including unused bytes.
    data_len: usize,
}

impl Mapping {
    /// Reserves the guarded layout and returns a pointer to storage for `T`.
    ///
    /// On success, the data region is zeroed, writable, locked, excluded from
    /// dumps, and wiped in fork children. The caller has not yet written `T`.
    fn allocate<T>() -> Result<(Self, NonNull<T>), HardenError> {
        // SAFETY: sysconf has no pointer arguments or memory preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|page| page.is_power_of_two())
            .ok_or(HardenError::Layout)?;

        if align_of::<T>() > page {
            return Err(HardenError::Layout);
        }

        // Keep a data page even for zero-sized values, then round up to pages.
        let data_len = size_of::<T>()
            .max(1)
            .checked_add(page - 1)
            .map(|size| size & !(page - 1))
            .ok_or(HardenError::Layout)?;

        // Include both guards in Rust's maximum pointer-offset bound.
        let total_len = page
            .checked_mul(2)
            .and_then(|guards| data_len.checked_add(guards))
            .filter(|size| *size <= isize::MAX as usize)
            .ok_or(HardenError::Layout)?;

        // SAFETY: A null hint requests a new mapping. Length is checked above.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if base == libc::MAP_FAILED {
            return Err(HardenError::System {
                operation: "mmap",
                source: io::Error::last_os_error(),
            });
        }

        // A mapping at address zero cannot be represented as a Rust allocation.
        let Some(base) = NonNull::new(base.cast::<u8>()) else {
            // SAFETY: mmap returned this mapping and length, which we own exclusively.
            if unsafe { libc::munmap(base, total_len) } != 0 {
                process::abort();
            }
            return Err(HardenError::Layout);
        };

        // SAFETY: The data region follows the first guard within the mapping.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(page)) };

        // Cleanup erases through write access, so the data region becomes
        // writable before Drop takes over.
        // SAFETY: The page-aligned data region lies entirely inside our mapping.
        if unsafe {
            libc::mprotect(
                data.as_ptr().cast(),
                data_len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            let error = HardenError::System {
                operation: "mprotect",
                source: io::Error::last_os_error(),
            };
            // SAFETY: Nothing was written. Release the mapping we own exclusively.
            if unsafe { libc::munmap(base.as_ptr().cast(), total_len) } != 0 {
                process::abort();
            }
            return Err(error);
        }

        let mapping = Self {
            base,
            total_len,
            data,
            data_len,
        };

        // Establish all protections before writing secret bytes into the mapping.
        // SAFETY: The page-aligned data region lies entirely inside our mapping.
        if unsafe { libc::madvise(data.as_ptr().cast(), data_len, libc::MADV_DONTDUMP) } != 0 {
            return Err(HardenError::System {
                operation: "madvise(MADV_DONTDUMP)",
                source: io::Error::last_os_error(),
            });
        }

        // SAFETY: The page-aligned region is private anonymous memory, as required
        // by WIPEONFORK.
        if unsafe { libc::madvise(data.as_ptr().cast(), data_len, libc::MADV_WIPEONFORK) } != 0 {
            return Err(HardenError::System {
                operation: "madvise(MADV_WIPEONFORK)",
                source: io::Error::last_os_error(),
            });
        }

        // SAFETY: The data region is a valid, writable mapping of data_len bytes.
        if unsafe { libc::mlock(data.as_ptr().cast(), data_len) } != 0 {
            return Err(HardenError::System {
                operation: "mlock",
                source: io::Error::last_os_error(),
            });
        }

        // The size of T is a multiple of its alignment, which divides the page
        // size. Placing its end at the trailing guard therefore aligns its start
        // and leaves no gap between T and the guard.
        // SAFETY: data_len covers T, and alignment was checked, including for a ZST.
        let value =
            unsafe { NonNull::new_unchecked(data.as_ptr().add(data_len - size_of::<T>()).cast()) };

        Ok((mapping, value))
    }

    /// Changes the data region's permissions.
    ///
    /// Callers serialize transitions with exclusive ownership or the reader mutex.
    /// They must not revoke permissions required by an outstanding reference. A
    /// failed call may have changed part of the region, so callers after
    /// publication abort rather than continue with unknown permissions.
    fn protect(&self, protection: libc::c_int) -> Result<(), HardenError> {
        // SAFETY: The data pointer and length describe our page-aligned mapping.
        if unsafe { libc::mprotect(self.data.as_ptr().cast(), self.data_len, protection) } != 0 {
            return Err(HardenError::System {
                operation: "mprotect",
                source: io::Error::last_os_error(),
            });
        }

        Ok(())
    }

    /// Restores write access for extraction, destruction, or erasure, aborting on failure.
    ///
    /// Called only with exclusive ownership, when no reader remains active.
    fn make_writable(&self) {
        if self.protect(libc::PROT_READ | libc::PROT_WRITE).is_err() {
            process::abort();
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        self.make_writable();

        // SAFETY: We exclusively own the writable data region. Any T has
        // already been destroyed, moved out, or was never initialized.
        // MaybeUninit permits erasing padding without reading uninitialized bytes.
        unsafe {
            slice::from_raw_parts_mut(self.data.as_ptr().cast::<MaybeUninit<u8>>(), self.data_len)
                .zeroize();
        }

        // Unmapping also releases the memory lock. Keep the pages locked until
        // after erasure instead of unlocking them in a separate step.
        // SAFETY: This mapping belongs to this process, including a fork child's
        // private inherited copy.
        if unsafe { libc::munmap(self.base.as_ptr().cast(), self.total_len) } != 0 {
            process::abort();
        }
    }
}

/// Owns an initialized `T` and its reader count.
///
/// Construction, extraction, and destruction hold exclusive write access. After
/// publication, the first reader grants read access and the last revokes it.
struct ProtectedAllocation<T> {
    /// Guarded pages holding the value. Erased and unmapped after `T` is gone.
    mapping: Mapping,
    /// Aligned location of the initialized value within mapping's data region.
    ///
    /// Dereferenced only while a [ReadGuard] is alive or during the exclusive
    /// RW phases of construction, extraction, and destruction.
    value: NonNull<T>,
    /// Active readers across all handles to this allocation.
    ///
    /// The mutex is held across each count update and the permission change it
    /// triggers, and released before user code runs. A plain atomic would let a
    /// revoke land after the next reader's grant.
    readers: Mutex<usize>,
}

// SAFETY: T can be moved to another thread. The mapping has one owner, shared
// access is coordinated by readers, and destruction requires exclusive ownership.
unsafe impl<T: Send> Send for ProtectedAllocation<T> {}

// SAFETY: T can be shared between threads. Permission transitions and reader
// counts are serialized, and no reference outlives its read guard.
unsafe impl<T: Sync> Sync for ProtectedAllocation<T> {}

impl<T> ProtectedAllocation<T> {
    /// Holds one reader slot across the callback, including panic unwinding.
    fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        // Release the mutex before user code so nested calls cannot deadlock.
        {
            let mut readers = self.readers.lock();
            if *readers == 0 && self.mapping.protect(libc::PROT_READ).is_err() {
                process::abort();
            }

            // Wrapping to zero would allow revoking access while readers exist.
            *readers = readers.checked_add(1).unwrap_or_else(|| process::abort());
        }

        let _guard = ReadGuard(self);

        // SAFETY: The read guard keeps the initialized T readable
        // through this closure, including overlapping and nested calls.
        f(unsafe { self.value.as_ref() })
    }

    /// Moves out the value and erases the allocation before returning it.
    fn extract(self) -> T {
        self.mapping.make_writable();
        let mut owner = ManuallyDrop::new(self);
        let allocation = &mut *owner;

        // SAFETY: Exclusive ownership rules out active readers. The value is
        // initialized and readable. ManuallyDrop prevents destroying the moved-out T.
        // Explicitly drop both owning fields to erase and release the source and
        // destroy the reader mutex. The remaining field owns no resources.
        unsafe {
            let value = allocation.value.as_ptr().read();
            ptr::drop_in_place(&raw mut allocation.mapping);
            ptr::drop_in_place(&raw mut allocation.readers);
            value
        }
    }
}

impl<T> Drop for ProtectedAllocation<T> {
    fn drop(&mut self) {
        self.mapping.make_writable();

        // SAFETY: The last owner has exclusive access, permissions allow
        // destruction, and this owner is only constructed after initializing T.
        unsafe { ptr::drop_in_place(self.value.as_ptr()) };

        // Mapping::drop wipes the data region even if a destructor unwinds.
    }
}

/// Keeps the mapping readable until the last overlapping access call finishes.
struct ReadGuard<'a, T>(&'a ProtectedAllocation<T>);

impl<T> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        // Runs on return and on unwind, so a panicking callback still gives up
        // its slot.
        let mut readers = self.0.readers.lock();
        *readers -= 1;

        // The last reader revokes access. Holding the mutex across the revoke
        // keeps a concurrent first reader from granting access underneath it.
        if *readers == 0 && self.0.mapping.protect(libc::PROT_NONE).is_err() {
            process::abort();
        }
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use std::{
        os::unix::process::ExitStatusExt,
        panic::{AssertUnwindSafe, catch_unwind},
        process::{Command, Output},
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    const CHILD_ENV: &str = "COMMONWARE_HARDENED_SECRET_TEST";

    /// Creates an allocation whose mappings can be inspected by backend tests.
    fn harden<T>(value: InlineSecret<T>) -> Result<HardenedSecret<T>, HardenError> {
        let mut value = ManuallyDrop::new(value);

        // SAFETY: Success immediately retires the source without dropping T.
        // Failure leaves it initialized, so only that path runs its destructor.
        unsafe {
            match HardenedSecret::try_from_inline(&mut value) {
                Ok(hardened) => {
                    slice::from_raw_parts_mut(
                        (&raw mut *value).cast::<MaybeUninit<u8>>(),
                        size_of::<InlineSecret<T>>(),
                    )
                    .zeroize();
                    Ok(hardened)
                }
                Err(error) => {
                    ManuallyDrop::drop(&mut value);
                    Err(error)
                }
            }
        }
    }

    /// Runs one `subprocess_child` case in a fresh process and checks how it ended.
    ///
    /// Faults and aborts must kill the child with `signal`. Every other case must
    /// exit successfully.
    fn child(case: &str, signal: Option<i32>) -> Output {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hardened_secret::tests::subprocess_child",
                "--nocapture",
            ])
            .env(CHILD_ENV, case)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), signal, "{output:?}");
        if signal.is_none() {
            assert!(output.status.success(), "{output:?}");
        }
        output
    }

    #[test]
    fn protected_access_and_guards() {
        child("inaccessible", Some(libc::SIGSEGV));
        child("readonly", Some(libc::SIGSEGV));
        child("leading_guard", Some(libc::SIGSEGV));
        child("trailing_guard", Some(libc::SIGSEGV));
        child("enter_failure", Some(libc::SIGABRT));
        child("exit_failure", Some(libc::SIGABRT));
        child("cleanup_failure", Some(libc::SIGABRT));
        child("harden_seal_failure", None);
    }

    #[test]
    fn locked_memory_limit() {
        child("locked_memory_limit", None);
    }

    #[test]
    fn public_access_unwind() {
        for case in ["borrowed_panic_protection", "owned_panic_protection"] {
            let output = child(case, Some(libc::SIGSEGV));
            // A fault during recovery must not pass as the deliberate sealed-page probe.
            assert!(String::from_utf8_lossy(&output.stderr).contains("access recovered"));
        }
    }

    #[test]
    fn fork_wipes_inherited_data() {
        child("fork_wipe", None);
    }

    #[test]
    fn nested_and_concurrent_access() {
        let secret = harden(InlineSecret::new([42u8; 32])).unwrap();
        let cloned = secret.clone();
        assert!(Arc::ptr_eq(&secret.inner, &cloned.inner));
        secret.access(|value| {
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    cloned.access(|other| {
                        assert_eq!(value, other);
                        panic!("nested access panic");
                    });
                }))
                .is_err()
            );
            assert_eq!(*secret.inner.readers.lock(), 1);
            assert_eq!(value, &[42; 32]);
        });
        let barrier = Arc::new(Barrier::new(5));
        thread::scope(|scope| {
            for _ in 0..4 {
                let cloned = secret.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    cloned.access(|value| {
                        barrier.wait();
                        assert_eq!(value, &[42; 32]);
                        barrier.wait();
                    });
                });
            }
            barrier.wait();
            assert_eq!(*secret.inner.readers.lock(), 4);
            secret.access(|value| assert_eq!(value, &[42; 32]));
            barrier.wait();
        });
        assert_eq!(*secret.inner.readers.lock(), 0);
        child("panic_protection", Some(libc::SIGSEGV));
    }

    #[test]
    fn initialize_and_layout() {
        check_layout::<0>(1);
        // Const array lengths and repr(align) require compile-time page sizes.
        // Dispatch on the actual page size rather than assuming 4 KiB pages.
        macro_rules! page_cases {
            ($page:literal, $over:literal) => {{
                check_layout::<$page>(1);
                check_layout::<{ $page + 1 }>(2);
                #[repr(align($page))]
                struct Aligned([u8; 1]);
                let value = harden(InlineSecret::new(Aligned([73]))).unwrap();
                assert_eq!(value.inner.value.as_ptr().addr() % $page, 0);
                assert_eq!(value.inner.mapping.data_len, $page);
                value.access(|value| assert_eq!(value.0, [73]));
                drop(value);
                #[repr(align($over))]
                struct OverAligned([u8; 1]);
                let mut value = Secret::new(OverAligned([73]));
                assert!(matches!(value.try_harden(), Err(HardenError::Layout)));
                assert!(!value.is_hardened());
                value.access(|value| assert_eq!(value.0, [73]));
            }};
        }
        match page_size() {
            4096 => page_cases!(4096, 8192),
            8192 => page_cases!(8192, 16384),
            16384 => page_cases!(16384, 32768),
            65536 => page_cases!(65536, 131072),
            page => panic!("add layout test fixtures for {page}-byte pages"),
        }
    }

    /// Checks both ends of the allocation around a fully initialized value.
    fn check_layout<const N: usize>(pages: usize) {
        let secret = harden(InlineSecret::new([37u8; N])).unwrap();
        let mapping = &secret.inner.mapping;
        let page = page_size();
        assert_eq!(mapping.data_len, pages * page);
        assert_eq!(mapping.total_len, (pages + 2) * page);
        assert_eq!(
            mapping.data.as_ptr().addr(),
            mapping.base.as_ptr().addr() + page
        );
        assert_eq!(
            secret.inner.value.as_ptr().addr() + N,
            mapping.data.as_ptr().addr() + mapping.data_len
        );
        secret.access(|value| assert_eq!(value, &[37; N]));
        let data = mapping.data.as_ptr();
        assert_eq!(secret.try_extract().ok().unwrap(), [37; N]);
        assert_unmapped(data);
    }

    #[test]
    fn unwind_releases_mapping() {
        struct PanicOnDrop([u8; 32]);
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                assert_eq!(self.0, [99; 32]);
                panic!("destructor panic");
            }
        }
        let secret = harden(InlineSecret::new(PanicOnDrop([99; 32]))).unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        assert!(catch_unwind(AssertUnwindSafe(|| drop(secret))).is_err());
        assert_unmapped(data);
    }

    #[test]
    fn redaction_and_storage_conversion() {
        let mut secret = Secret::new([42u8; 32]);
        assert!(!secret.is_hardened());
        secret.try_harden().unwrap();
        assert!(secret.is_hardened());
        let address = secret.access(|value| value as *const _);
        secret.try_harden().unwrap();
        secret.access(|value| assert_eq!(value as *const _, address));
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        let cloned = secret.clone();
        assert!(cloned.is_hardened());
        assert_eq!(secret, cloned);
        assert_eq!(cloned.extract_or_clone(), [42u8; 32]);
        assert!(secret.is_hardened());
        assert_eq!(format!("{secret}"), "[REDACTED]");
        child("no_permission_changes", None);
    }

    /// A non-Clone inline value with a borrowed, nonsecret destruction counter.
    struct Tracked<'a> {
        bytes: [u8; 32],
        drops: &'a AtomicUsize,
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn harden_nonclone_value_in_place() {
        let drops = AtomicUsize::new(0);
        let mut secret = Secret::new(Tracked {
            bytes: [42; 32],
            drops: &drops,
        });
        let result: Result<(), HardenError> = secret.try_harden();
        result.unwrap();
        assert!(secret.is_hardened());
        secret.access(|value| assert_eq!(value.bytes, [42; 32]));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(secret);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    /// A failed attempt must not destroy or replace the original owning value.
    fn assert_harden_failure(operation: &str) {
        struct Value<'a> {
            bytes: Box<[u8; 32]>,
            drops: &'a AtomicUsize,
        }
        impl Drop for Value<'_> {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        let drops = AtomicUsize::new(0);
        let mut secret = Secret::new(Value {
            bytes: Box::new([42; 32]),
            drops: &drops,
        });
        let address = secret.access(ptr::from_ref);
        let locked = locked_kib();
        // A second attempt must also preserve ownership and release its mapping.
        for _ in 0..2 {
            let error = secret.try_harden().unwrap_err();
            assert!(
                matches!(error, HardenError::System { operation: failed, .. } if failed == operation)
            );
            assert!(!secret.is_hardened());
            secret.access(|value| {
                assert_eq!(ptr::from_ref(value), address);
                assert_eq!(*value.bytes, [42; 32]);
            });
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(locked_kib(), locked);
        }
        drop(secret);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    /// Reads the locked data size reported by Linux, in KiB.
    fn locked_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmLck:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn last_owner_destroys_value() {
        let drops = AtomicUsize::new(0);
        let secret = harden(InlineSecret::new(Tracked {
            bytes: [42; 32],
            drops: &drops,
        }))
        .unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        let clone = secret.clone();
        secret.access(|value| assert_eq!(value.bytes, [42; 32]));
        drop(secret);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(clone);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_unmapped(data);
    }

    #[test]
    fn unique_extraction_moves_nonclone_value() {
        let drops = AtomicUsize::new(0);
        let secret = harden(InlineSecret::new(Tracked {
            bytes: [42; 32],
            drops: &drops,
        }))
        .unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        let value = secret.try_extract().ok().unwrap();
        assert_unmapped(data);
        assert_eq!(value.bytes, [42; 32]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(value);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn subprocess_child() {
        let Ok(case) = std::env::var(CHILD_ENV) else {
            return;
        };
        // SAFETY: This subprocess owns its resource limits. Disabling core files
        // prevents deliberate fault tests from creating artifacts.
        unsafe {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
        }
        if case == "locked_memory_limit" {
            drop_ipc_lock_capability();
            // SAFETY: This subprocess lowers only its own locked-memory allowance.
            unsafe {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit), 0);
            }
            assert_harden_failure("mlock");
            return;
        }
        match case.as_str() {
            "exit_failure" => {
                exit_failure();
                panic!("revocation did not abort");
            }
            "harden_seal_failure" => {
                deny_mprotect(&[libc::PROT_NONE]);
                assert_harden_failure("mprotect");
                return;
            }
            "no_permission_changes" => {
                let mut public = Secret::new([42u8; 32]);
                public.try_harden().unwrap();
                let shared = harden(InlineSecret::new([73u8; 32])).unwrap();
                let clone = shared.clone();
                deny_mprotect(&[
                    libc::PROT_NONE,
                    libc::PROT_READ,
                    libc::PROT_READ | libc::PROT_WRITE,
                ]);
                public.try_harden().unwrap();
                assert!(public.is_hardened());
                let returned = shared.try_extract().unwrap_err();
                assert!(Arc::ptr_eq(&returned.inner, &clone.inner));
                assert_eq!(*returned.inner.readers.lock(), 0);
                drop(returned);
                // SAFETY: Leave the disposable subprocess without destructors.
                // Final release would require the deliberately forbidden write transition.
                unsafe { libc::_exit(0) };
            }
            "borrowed_panic_protection" | "owned_panic_protection" => {
                let mut secret = Secret::new([42u8; 32]);
                secret.try_harden().unwrap();
                let address = secret.access(|value| value as *const [u8; 32]);
                if case == "borrowed_panic_protection" {
                    assert!(catch_unwind(|| secret.access(|_| panic!("borrowed panic"))).is_err());
                } else {
                    let cloned = secret.clone();
                    assert!(
                        catch_unwind(move || cloned.access(|_| panic!("owned panic"))).is_err()
                    );
                }
                // The surviving owner remains usable after either kind of unwind.
                secret.access(|value| assert_eq!(value, &[42; 32]));
                eprintln!("access recovered");
                // SAFETY: Deliberately probe the still-owned mapping after the last
                // reader exits. This subprocess must fault on its sealed data page.
                unsafe { std::hint::black_box(address.read_volatile()) };
                return;
            }
            _ => {}
        }
        let secret = harden(InlineSecret::new([42u8; 32])).unwrap();
        match case.as_str() {
            "inaccessible" | "panic_protection" => {
                if case == "panic_protection" {
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| {
                            secret.access(|_| panic!("access panic"));
                        }))
                        .is_err()
                    );
                }
                // SAFETY: Intentionally probe our allocated, inaccessible page in
                // an isolated subprocess, expecting an operating-system fault.
                unsafe {
                    std::hint::black_box(secret.inner.value.as_ptr().read_volatile());
                }
            }
            "readonly" => secret.access(|_| {
                // SAFETY: Deliberately test the read-only mapping in a subprocess.
                unsafe {
                    secret.inner.value.as_ptr().write_volatile([0; 32]);
                }
            }),
            "leading_guard" => secret.access(|_| {
                // SAFETY: Deliberately read the mapped but inaccessible guard page.
                unsafe {
                    std::hint::black_box(secret.inner.mapping.base.as_ptr().read_volatile());
                }
            }),
            "trailing_guard" => secret.access(|_| {
                // SAFETY: The pointer is within the trailing mapped guard page.
                unsafe {
                    std::hint::black_box(
                        secret
                            .inner
                            .mapping
                            .data
                            .as_ptr()
                            .add(secret.inner.mapping.data_len)
                            .read_volatile(),
                    );
                }
            }),
            "enter_failure" => {
                // SAFETY: Remove our mapping to force mprotect failure. The next
                // operation must abort without dereferencing the stale pointer.
                unsafe {
                    assert_eq!(
                        libc::munmap(
                            secret.inner.mapping.base.as_ptr().cast(),
                            secret.inner.mapping.total_len
                        ),
                        0
                    );
                }
                secret.access(|_| ());
            }
            "cleanup_failure" => {
                // SAFETY: Remove the data region so the final owner cannot restore
                // write access. Nothing dereferences the stale pointer afterward.
                unsafe {
                    assert_eq!(
                        libc::munmap(
                            secret.inner.mapping.data.as_ptr().cast(),
                            secret.inner.mapping.data_len
                        ),
                        0
                    );
                }
                drop(secret);
                panic!("cleanup did not abort");
            }
            "fork_wipe" => {
                // SAFETY: The child inspects raw bytes, drops its inherited handle,
                // and exits without returning to the test harness.
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    let data = secret.inner.mapping.data.as_ptr();
                    let len = secret.inner.mapping.data_len;
                    // SAFETY: WIPEONFORK supplies zero pages, and the child owns
                    // this private mapping.
                    unsafe {
                        if libc::mprotect(data.cast(), len, libc::PROT_READ) != 0 {
                            libc::_exit(1);
                        }
                        for i in 0..len {
                            if data.add(i).read_volatile() != 0 {
                                libc::_exit(2);
                            }
                        }
                    }
                    // Dropping here is sound only because all-zero bytes are a
                    // valid [u8; 32]. The public contract forbids it in general.
                    drop(secret);
                    // SAFETY: Terminate the child without invoking the test harness.
                    unsafe { libc::_exit(0) };
                }
                wait_for_child(pid, None);
                secret.access(|value| assert_eq!(value, &[42; 32]));
                return;
            }
            _ => panic!("unknown subprocess case: {case}"),
        }
        panic!("expected subprocess fault: {case}");
    }

    /// Forces revocation failure without assuming a particular page size.
    fn exit_failure() {
        // A ZST still owns one data page. Its reference occupies no bytes, so
        // removing that page leaves no live reference into unmapped data.
        let secret = harden(InlineSecret::new(())).unwrap();
        secret.access(|_| {
            // SAFETY: Remove the test's data page to force last-reader mprotect
            // failure. The ZST's trailing-guard address stays mapped.
            unsafe {
                assert_eq!(
                    libc::munmap(
                        secret.inner.mapping.data.as_ptr().cast(),
                        secret.inner.mapping.data_len,
                    ),
                    0
                );
            }
        });
    }

    /// Rejects selected permission transitions at the syscall boundary.
    /// The filter is installed only in a disposable subprocess, without test hooks
    /// in the allocator. Other syscall numbers and permissions remain allowed.
    fn deny_mprotect(protections: &[libc::c_int]) {
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |k, jt, jf| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        // seccomp_data.nr is at offset 0 and args[2] at offset 32. Reading the
        // low word of the protection argument works on little-endian hosts.
        #[cfg(target_endian = "little")]
        let protection_offset = 32;
        #[cfg(target_endian = "big")]
        let protection_offset = 36;
        let count = u8::try_from(protections.len()).unwrap();
        let mut filter = vec![
            stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
            jump(libc::SYS_mprotect as u32, 0, count + 1),
            stmt(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                protection_offset,
            ),
        ];
        for (index, protection) in protections.iter().enumerate() {
            // A match skips the remaining comparisons and the ALLOW instruction.
            filter.push(jump(*protection as u32, count - index as u8, 0));
        }
        filter.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ALLOW,
        ));
        filter.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: This thread permanently narrows its own syscall permissions.
        // The kernel copies the valid filter while prctl runs.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
    }

    /// Removes effective CAP_IPC_LOCK from the child thread before lowering its limit.
    fn drop_ipc_lock_capability() {
        // Linux's version 3 capability syscall ABI uses a header and two words.
        #[repr(C)]
        struct Header {
            version: u32,
            pid: libc::pid_t,
        }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Capabilities {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let mut data = [Capabilities::default(); 2];
        // SAFETY: Version 3 writes two capability words. pid 0 selects this thread.
        unsafe {
            assert_eq!(
                libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()),
                0
            );
            // CAP_IPC_LOCK is bit 14. UID alone does not determine this privilege.
            if data[0].effective & (1 << 14) != 0 {
                data[0].effective &= !(1 << 14);
                assert_eq!(
                    libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()),
                    0
                );
                assert_eq!(
                    libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()),
                    0
                );
            }
        }
        assert_eq!(data[0].effective & (1 << 14), 0);
    }

    /// Returns the kernel's base page size used by the allocation under test.
    fn page_size() -> usize {
        // SAFETY: sysconf has no memory preconditions.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        assert!(page.is_power_of_two());
        page
    }

    /// Checks release without reading through a pointer whose allocation is gone.
    fn assert_unmapped(address: *mut u8) {
        let page = page_size();
        // SAFETY: mincore checks virtual mappings
        // without dereferencing the queried address in userspace.
        unsafe {
            let base = address.map_addr(|address| address & !(page - 1));
            let mut resident = 0;
            assert_eq!(libc::mincore(base.cast(), page, &mut resident), -1);
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOMEM)
            );
        }
    }

    /// Waits for the isolated fork branch and checks its exact termination mode.
    fn wait_for_child(pid: libc::pid_t, signal: Option<i32>) {
        let mut status = 0;
        // SAFETY: pid is our child and status is a writable output location.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        if let Some(signal) = signal {
            assert!(libc::WIFSIGNALED(status), "child status: {status}");
            assert_eq!(libc::WTERMSIG(status), signal);
        } else {
            assert!(libc::WIFEXITED(status), "child status: {status}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}
