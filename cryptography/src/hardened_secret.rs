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
    use crate::{HardenError, Secret};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        ptr,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    /// A value with a borrowed, nonsecret destruction counter.
    #[derive(Clone)]
    struct Tracked<'a> {
        bytes: [u8; 32],
        drops: &'a AtomicUsize,
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    const fn tracked(drops: &AtomicUsize) -> Tracked<'_> {
        Tracked {
            bytes: [42; 32],
            drops,
        }
    }

    #[test]
    fn test_harden_and_extract() {
        let drops = AtomicUsize::new(0);

        // Hardening moves the value without destroying it, and hardening again
        // keeps the same allocation.
        let mut secret = Secret::new(tracked(&drops));
        secret.try_harden().unwrap();
        assert!(secret.is_hardened());
        let address = secret.access(ptr::from_ref);
        secret.try_harden().unwrap();
        secret.access(|value| {
            assert_eq!(ptr::from_ref(value), address);
            assert_eq!(value.bytes, [42; 32]);
        });
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // Unique extraction moves the value out instead of destroying it.
        let value = secret.try_extract().ok().unwrap();
        assert_eq!(value.bytes, [42; 32]);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(value);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_clones_share_one_allocation() {
        let drops = AtomicUsize::new(0);
        let mut secret = Secret::new(tracked(&drops));
        secret.try_harden().unwrap();
        let clone = secret.clone();

        // Both handles see the same value at the same address.
        let address = secret.access(ptr::from_ref);
        assert!(clone.is_hardened());
        clone.access(|value| assert_eq!(ptr::from_ref(value), address));

        // A shared value cannot be moved out, and the handle comes back unchanged.
        let Err(secret) = secret.try_extract() else {
            panic!("shared value moved out");
        };
        secret.access(|value| assert_eq!(ptr::from_ref(value), address));

        // Dropping one handle destroys nothing. The last one destroys the value
        // exactly once.
        drop(secret);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        clone.access(|value| assert_eq!(value.bytes, [42; 32]));
        drop(clone);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_nested_and_concurrent_access() {
        let mut secret = Secret::new([42u8; 32]);
        secret.try_harden().unwrap();
        let cloned = secret.clone();

        // Nested calls through the same handle or another one see the value, and
        // a panic in an inner call leaves the outer one usable.
        secret.access(|value| {
            secret.access(|inner| assert!(ptr::eq(value, inner)));
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    cloned.access(|other| {
                        assert!(ptr::eq(value, other));
                        panic!("nested access panic");
                    });
                }))
                .is_err()
            );
            assert_eq!(value, &[42; 32]);
        });

        // Readers on other threads see the value while the main thread reads too.
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
            secret.access(|value| assert_eq!(value, &[42; 32]));
            barrier.wait();
        });
        secret.access(|value| assert_eq!(value, &[42; 32]));
    }

    #[test]
    fn test_protections() {
        let mut secret = Secret::new([42u8; 32]);
        secret.try_harden().unwrap();

        // The value is smaller than a page, so its data region is the one page
        // containing it, with a guard page on each side.
        let page = page_size();
        let data = secret
            .access(ptr::from_ref)
            .cast::<u8>()
            .map_addr(|address| address & !(page - 1));
        let leading = data.map_addr(|address| address - page);
        let trailing = data.map_addr(|address| address + page);

        // Idle data pages are inaccessible, locked, excluded from core dumps, and
        // wiped on fork. Both guards are inaccessible and never locked.
        let (permissions, flags) = mapping_info(data);
        assert_eq!(permissions, "---");
        for flag in ["lo", "dd", "wf"] {
            assert!(
                flags.iter().any(|f| f == flag),
                "missing {flag} in {flags:?}"
            );
        }
        for guard in [leading, trailing] {
            let (permissions, flags) = mapping_info(guard);
            assert_eq!(permissions, "---");
            assert!(!flags.iter().any(|f| f == "lo"), "guard locked: {flags:?}");
        }

        // A callback makes the data pages readable but not writable and leaves
        // the guards alone. Access is revoked on return and on unwind.
        secret.access(|_| {
            assert_eq!(mapping_info(data).0, "r--");
            assert_eq!(mapping_info(leading).0, "---");
            assert_eq!(mapping_info(trailing).0, "---");
        });
        assert_eq!(mapping_info(data).0, "---");
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                secret.access(|_| panic!("access panic"));
            }))
            .is_err()
        );
        assert_eq!(mapping_info(data).0, "---");
    }

    #[test]
    fn test_sizes_and_alignment() {
        // A zero-sized value hardens like any other.
        round_trip::<0>();

        // Const array lengths and repr(align) require compile-time page sizes.
        // Dispatch on the actual page size rather than assuming 4 KiB pages.
        macro_rules! page_cases {
            ($page:literal, $over:literal) => {{
                // Values of exactly one page and of one byte more both round-trip.
                round_trip::<$page>();
                round_trip::<{ $page + 1 }>();

                // Page alignment is the most the mapping can honor.
                #[repr(align($page))]
                struct Aligned([u8; 1]);
                let mut value = Secret::new(Aligned([73]));
                value.try_harden().unwrap();
                value.access(|value| assert_eq!(value.0, [73]));

                // Stricter alignment is rejected, and the inline value stays usable.
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
            page => panic!("add fixtures for {page}-byte pages"),
        }
    }

    /// Hardens a byte array, reads it back, and moves it out again.
    fn round_trip<const N: usize>() {
        let mut secret = Secret::new([37u8; N]);
        secret.try_harden().unwrap();
        secret.access(|value| assert_eq!(value, &[37; N]));
        assert_eq!(secret.try_extract().unwrap(), [37; N]);
    }

    /// Returns the kernel's page size.
    fn page_size() -> usize {
        // SAFETY: sysconf has no memory preconditions.
        usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap()
    }

    /// Returns the permissions and `VmFlags` of the mapping containing `address`
    /// from `/proc/self/smaps`.
    fn mapping_info(address: *const u8) -> (String, Vec<String>) {
        let address = address.addr();
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut lines = smaps.lines();
        while let Some(line) = lines.next() {
            // Each entry starts with "start-end perms ..." followed by attribute
            // lines, of which VmFlags is the last.
            let Some((range, rest)) = line.split_once(' ') else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                continue;
            };
            if !(start..end).contains(&address) {
                continue;
            }
            let flags = lines
                .find_map(|line| line.strip_prefix("VmFlags:"))
                .unwrap()
                .split_whitespace()
                .map(str::to_string)
                .collect();
            return (rest[..3].to_string(), flags);
        }
        panic!("address {address:#x} is not mapped");
    }
}
