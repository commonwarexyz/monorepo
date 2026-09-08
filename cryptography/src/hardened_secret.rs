//! Shared secret storage backed by Linux memory protections.
//!
//! [HardenedSecret] keeps a value in a dedicated mapping that is locked against
//! swapping, excluded from core dumps, and inaccessible between operations.
//! Clones share the mapping. See the type's documentation for its costs, type
//! requirements, and behavior across `fork`.
//!
//! This module is available only on Linux with the `std` feature. Construction
//! requires `MADV_WIPEONFORK`, available since Linux 4.14, and permission to use
//! all required memory operations. Successful construction establishes every
//! protection. See [HardenedSecret::try_from_inline] for construction and cleanup failures.

use crate::secret::{HardenError, InlineSecret};
use commonware_utils::sync::Mutex;
use core::{
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit, align_of, size_of},
    ptr::{self, NonNull},
};
use ctutils::CtEq;
#[cfg(test)]
use rand::RngExt as _;
#[cfg(not(test))]
use rand::{TryRng as _, rngs::SysRng};
use std::{
    io, process,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};
use zeroize::Zeroize;

/// A shared secret whose backing pages are inaccessible between access calls.
///
/// The value is stored in a dedicated allocation with these protections:
///
/// - [mlock](https://man7.org/linux/man-pages/man2/mlock.2.html) keeps the data
///   pages resident, preventing them from being swapped out.
/// - [MADV_DONTDUMP](https://man7.org/linux/man-pages/man2/madvise.2.html)
///   excludes the data pages from kernel-generated core dumps.
/// - `mprotect` makes the data pages read-only during [Self::access] and
///   inaccessible between calls. Construction, extraction, and destruction
///   have write access.
/// - Inaccessible guard pages surround the data region. A random canary immediately
///   before `T` detects writes that change it when the canary is next checked.
///
/// `Debug` prints `HardenedSecret([REDACTED])` and `Display` prints `[REDACTED]`.
/// When `T: CtEq`, equality accesses both values and calls `T`'s constant-time comparison.
///
/// # Ownership and cost
///
/// Cloning shares the existing allocation without cloning `T`, allocating memory,
/// or changing permissions. Dropping the last owner calls `T`'s destructor, zeroizes the
/// entire data region, and releases the mapping. Erasure also runs if that
/// destructor unwinds. Leaking the last handle prevents this cleanup.
///
/// Each allocation locks at least one whole data page, even for a zero-sized
/// value, and reserves two additional guard pages in the virtual address space.
/// The value and canary can require multiple data pages. Access calls synchronize
/// a reader count, with a permission syscall on entry to the first call and exit
/// from the last. Keep access scopes short, while avoiding repeated calls within
/// a single operation.
///
/// # Requirements and limits
///
/// Store sensitive bytes directly in `T`. Memory reached through pointers, such
/// as a `Vec` or `Box` allocation, receives no protection or erasure from this
/// wrapper. Operations on `&T` must not write to `T`'s storage, including through
/// interior mutability, because its pages are read-only. Such writes can terminate
/// the process. `T`'s destructor must not panic, so failures before transferring
/// ownership from inline storage can finish erasing the input.
///
/// Protection applies to this allocation. Earlier copies, exported values, and
/// temporary values created by computations remain outside it. During access,
/// the pages are readable throughout the process, including by other threads.
/// These protections do not defend against arbitrary code execution, privileged
/// memory inspection, or hibernation images.
///
/// Construction reports errors through [HardenError]. After construction, a
/// failed permission change or detected canary corruption aborts the process.
/// Cleanup also aborts if it cannot restore write access or release the mapping.
/// Aborting does not run destructors or guarantee erasure.
///
/// # Forking
///
/// `MADV_WIPEONFORK` replaces the child's data pages with zeroes. Inherited
/// handles cannot access or move out the value: access aborts before touching
/// the reader mutex or reading `T`. The final release in the child only
/// unmaps its copy, without calling `T`'s destructor on the wiped bytes. The
/// parent's allocation is unaffected.
///
/// A caller using an unsafe fork API during access must ensure that the child
/// never uses references into the inherited allocation. Their bytes have been
/// wiped and may no longer represent a valid `T`. Returning through an inherited
/// read guard in the child also aborts. These restrictions do not replace
/// the fork API's own safety requirements.
///
pub(crate) struct HardenedSecret<T> {
    inner: Arc<ProtectedAllocation<T>>,
}

impl<T> HardenedSecret<T> {
    /// Consumes `value` and moves it into a new protected allocation.
    ///
    /// On success, the consumed inline storage is erased after the move. On
    /// error, the input is dropped and its inline storage erased, subject to the
    /// type's nonpanicking-destructor requirement. The input is not returned.
    /// Earlier locations left behind by moving the argument cannot be erased here.
    /// For byte arrays, [Self::try_init] can initialize the value directly in
    /// protected memory.
    ///
    /// # Errors
    ///
    /// Returns [HardenError::Layout] if a suitable mapping cannot be represented,
    /// including when `T`'s alignment exceeds the system page size. Returns
    /// [HardenError::System] if mapping, canary generation, or a required memory
    /// operation fails. Locking is subject to the process's `RLIMIT_MEMLOCK`
    /// allowance, even when ordinary memory is available.
    ///
    /// Allocating the shared ownership metadata uses the ordinary Rust allocator
    /// and follows its allocation-failure behavior. Cleanup failures abort as
    /// described in the type's documentation.
    pub(crate) fn try_from_inline(value: InlineSecret<T>) -> Result<Self, HardenError> {
        ProtectedAllocation::try_new(value).map(|inner| Self {
            inner: Arc::new(inner),
        })
    }

    /// Passes a shared reference to the stored value to `f` and returns its result.
    ///
    /// The first active call makes the data pages read-only. Nested and concurrent
    /// calls, including through other clones, keep them readable until the last
    /// call ends. Returning from this call does not revoke access while another
    /// call remains active. The reader mutex is not held while `f` runs.
    ///
    /// Borrows into the stored value cannot escape the closure. Copied values,
    /// raw pointers, and references already stored inside `T` can escape and
    /// receive no additional protection. Operations on `&T` must not modify its
    /// storage, even through interior mutability.
    ///
    /// # Panics
    ///
    /// A panic from `f` propagates. During unwinding, access is revoked if no
    /// other call remains active. Failed permission changes or detected canary
    /// corruption abort the process.
    pub(crate) fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        self.inner.access(f)
    }

    /// Moves out `T` and erases its allocation, or returns this handle if shared.
    ///
    /// The returned value is unprotected. A failed ownership check leaves the
    /// allocation and its permissions unchanged. Extraction failures abort as
    /// described in the type's documentation.
    pub(crate) fn try_extract(self) -> Result<T, Self> {
        match Arc::try_unwrap(self.inner) {
            Ok(allocation) => Ok(allocation.extract()),
            Err(inner) => Err(Self { inner }),
        }
    }
}

impl<const N: usize> HardenedSecret<[u8; N]> {
    /// Initializes a byte array directly in a new protected allocation.
    ///
    /// Calls `f` with a zeroed array after locking the data pages and excluding
    /// them from core dumps. The array is writable during initialization and
    /// inaccessible when construction completes. Any bytes left untouched by `f`
    /// remain zero. The closure's own temporaries are outside the allocation.
    ///
    /// # Errors
    ///
    /// Returns the same construction errors as [Self::try_from_inline]. The initializer
    /// is not called if allocation or initial protection setup fails. If a later
    /// step fails, the initialized array is erased before returning the error.
    ///
    /// # Panics
    ///
    /// A panic from `f` propagates. During unwinding, the allocation is erased
    /// and released. Cleanup failures abort as described in the type's documentation.
    ///
    pub(crate) fn try_init(f: impl FnOnce(&mut [u8; N])) -> Result<Self, HardenError> {
        ProtectedAllocation::try_init(f).map(|inner| Self {
            inner: Arc::new(inner),
        })
    }
}

impl<T> Clone for HardenedSecret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Debug for HardenedSecret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("HardenedSecret([REDACTED])")
    }
}

impl<T> Display for HardenedSecret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: CtEq> PartialEq for HardenedSecret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.access(|a| other.access(|b| a.ct_eq(b).into()))
    }
}

impl<T: CtEq> Eq for HardenedSecret<T> {}

const CANARY_SIZE: usize = 16;

/// Captures errno immediately after a failed memory operation.
fn system(operation: &'static str) -> HardenError {
    HardenError::System {
        operation,
        source: io::Error::last_os_error(),
    }
}

/// Handles cleanup syscalls whose failure cannot be returned to the caller.
fn abort_on_error(result: libc::c_int) {
    if result != 0 {
        process::abort();
    }
}

/// Generates the pattern placed immediately before the value to detect corruption.
fn random_canary() -> Result<[u8; CANARY_SIZE], HardenError> {
    let mut canary = [0; CANARY_SIZE];
    #[cfg(test)]
    {
        commonware_utils::test_rng().fill(&mut canary);
    }
    #[cfg(not(test))]
    SysRng
        .try_fill_bytes(&mut canary)
        .map_err(|error| HardenError::System {
            operation: "getrandom",
            source: error.into(),
        })?;
    Ok(canary)
}

/// Owns the raw mapping and erases it independently of `T`'s initialization or drop.
///
/// The data region is rounded up to whole pages. Its layout places `T` against
/// the trailing guard, with the canary immediately before it:
///
/// ```text
/// | guard page | unused bytes | canary | T | guard page |
///              <------- data_len -------->
/// <-------------------- total_len -------------------->
/// ```
///
/// Guards always remain inaccessible. Only the data region is locked or has its
/// permissions changed. This owner never interprets those bytes as `T`, so it
/// can clean up both partially constructed allocations and destroyed values.
struct Mapping {
    /// Start of the entire mapping, including the leading guard.
    base: NonNull<u8>,
    /// Length passed to munmap, including both guards.
    total_len: usize,
    /// First byte after the leading guard.
    data: NonNull<u8>,
    /// Page-rounded length of the data region, including unused bytes and canary.
    data_len: usize,
    /// Process that created the mapping, used to reject inherited handles.
    pid: libc::pid_t,
    // Last permissions successfully applied to the whole data region, or -1 if
    // uncertain. The reader mutex or exclusive ownership serializes changes, so
    // relaxed atomic access suffices for updates through shared references.
    protection: AtomicI32,
    // Set before the first write. Earlier construction failures can just unmap
    // the untouched pages without restoring write access for erasure.
    dirty: bool,
}

impl Mapping {
    /// Reserves the guarded layout and returns a pointer to storage for `T`.
    ///
    /// On success, the data region is zeroed, writable, locked, excluded from
    /// dumps, and wiped in fork children. The caller has not yet written `T` or
    /// the expected canary into it.
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
        // Reserve the canary even for zero-sized values, then round to pages.
        let data_len = size_of::<T>()
            .checked_add(CANARY_SIZE)
            .and_then(|size| size.checked_add(page - 1))
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
            return Err(system("mmap"));
        }
        // A mapping at address zero cannot be represented as a Rust allocation.
        let Some(base) = NonNull::new(base.cast::<u8>()) else {
            // SAFETY: mmap returned this mapping and length, which we own exclusively.
            unsafe { abort_on_error(libc::munmap(base, total_len)) };
            return Err(HardenError::Layout);
        };
        // SAFETY: The data region follows the first guard within the mapping.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(page)) };
        let mapping = Self {
            base,
            total_len,
            data,
            data_len,
            // SAFETY: getpid has no preconditions.
            pid: unsafe { libc::getpid() },
            protection: AtomicI32::new(libc::PROT_NONE),
            dirty: false,
        };
        // Establish all protections before writing secret bytes into the mapping.
        mapping.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        // SAFETY: The page-aligned data region lies entirely inside our mapping.
        if unsafe { libc::madvise(data.as_ptr().cast(), data_len, libc::MADV_DONTDUMP) } != 0 {
            return Err(system("madvise(MADV_DONTDUMP)"));
        }
        // SAFETY: The page-aligned region is private anonymous memory, as required
        // by WIPEONFORK. Child-side access rejects the resulting invalid T bytes
        // before constructing references or touching the inherited reader mutex.
        if unsafe { libc::madvise(data.as_ptr().cast(), data_len, libc::MADV_WIPEONFORK) } != 0 {
            return Err(system("madvise(MADV_WIPEONFORK)"));
        }
        // SAFETY: The data region is a valid, writable mapping of data_len bytes.
        if unsafe { libc::mlock(data.as_ptr().cast(), data_len) } != 0 {
            return Err(system("mlock"));
        }
        // The size of T is a multiple of its alignment, which divides the page
        // size. Placing its end at the trailing guard therefore aligns its start
        // and leaves no gap between T and the guard.
        // SAFETY: data_len includes the value and canary, and alignment was checked.
        let value =
            unsafe { NonNull::new_unchecked(data.as_ptr().add(data_len - size_of::<T>()).cast()) };
        Ok((mapping, value))
    }

    /// Changes data permissions and records whether the entire operation succeeded.
    ///
    /// Callers serialize transitions with exclusive ownership or the reader mutex.
    /// They must not revoke permissions required by an outstanding reference.
    fn protect(&self, protection: libc::c_int) -> Result<(), HardenError> {
        // A failed mprotect can have changed part of a region. Cleanup must
        // reestablish writable permissions unless the full operation succeeded.
        self.protection.store(-1, Ordering::Relaxed);
        // SAFETY: The data pointer and length describe our page-aligned mapping.
        if unsafe { libc::mprotect(self.data.as_ptr().cast(), self.data_len, protection) } != 0 {
            return Err(system("mprotect"));
        }
        self.protection.store(protection, Ordering::Relaxed);
        Ok(())
    }

    /// Restores write access for extraction, destruction, or erasure, aborting on failure.
    ///
    /// Called only with exclusive ownership, when no reader remains active.
    fn make_writable(&self) {
        if self.protection.load(Ordering::Relaxed) != (libc::PROT_READ | libc::PROT_WRITE)
            && self.protect(libc::PROT_READ | libc::PROT_WRITE).is_err()
        {
            process::abort();
        }
    }

    /// Checks whether this is the original mapping or a wiped fork-child copy.
    fn in_creator(&self) -> bool {
        // SAFETY: getpid has no preconditions.
        self.pid == unsafe { libc::getpid() }
    }

    /// Rejects child-side access before touching inherited state or wiped bytes.
    fn require_creator(&self) {
        if !self.in_creator() {
            process::abort();
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if self.in_creator() && self.dirty {
            self.make_writable();
            // SAFETY: We exclusively own the writable data region. Any T has
            // already been destroyed, moved out, or was never initialized.
            // MaybeUninit permits erasing padding without reading uninitialized bytes.
            unsafe {
                core::slice::from_raw_parts_mut(
                    self.data.as_ptr().cast::<MaybeUninit<u8>>(),
                    self.data_len,
                )
                .zeroize();
            }
        }
        // Unmapping also releases the memory lock. Keep the pages locked until
        // after erasure instead of unlocking them in a separate step.
        // SAFETY: This mapping belongs to this process. In a fork child, unmapping
        // its private inherited copy does not touch the parent's backing pages.
        unsafe { abort_on_error(libc::munmap(self.base.as_ptr().cast(), self.total_len)) };
    }
}

/// Owns an initialized `T` and coordinates its readable lifetime.
///
/// Construction, extraction, and destruction have exclusive write access. After publication,
/// the first reader grants read access and the last reader revokes it. The mutex
/// serializes those transitions, but is released while callbacks run.
struct ProtectedAllocation<T> {
    mapping: Mapping,
    /// Aligned location of the initialized value within mapping's data region.
    value: NonNull<T>,
    /// Expected canary, kept outside the protected data region for comparison.
    canary: [u8; CANARY_SIZE],
    /// Active readers across all handles to this allocation.
    readers: Mutex<usize>,
    /// Records ownership of T for drop checking, including any borrowed lifetimes.
    marker: PhantomData<T>,
}

// SAFETY: T can be moved to another thread. The mapping has one owner, shared
// access is coordinated by readers, and destruction requires exclusive ownership.
unsafe impl<T: Send> Send for ProtectedAllocation<T> {}
// SAFETY: T can be shared between threads. Permission transitions and reader
// counts are serialized, and no reference outlives its read guard.
unsafe impl<T: Sync> Sync for ProtectedAllocation<T> {}

impl<T> ProtectedAllocation<T> {
    /// Allocates writable storage and initializes its canary, leaving `T` uninitialized.
    ///
    /// Mapping alone owns cleanup until the caller initializes `T` and constructs
    /// a ProtectedAllocation. Any early return therefore erases raw bytes only.
    fn allocate() -> Result<(Mapping, NonNull<T>, [u8; CANARY_SIZE]), HardenError> {
        let canary = random_canary()?;
        let (mut mapping, value) = Mapping::allocate::<T>()?;
        mapping.dirty = true;
        // SAFETY: Construction owns the writable mapping, and the checked layout
        // reserves CANARY_SIZE bytes immediately before the aligned value.
        unsafe {
            let canary_ptr = value.as_ptr().cast::<u8>().sub(CANARY_SIZE);
            ptr::copy_nonoverlapping(canary.as_ptr(), canary_ptr, CANARY_SIZE);
        }
        Ok((mapping, value, canary))
    }

    /// Transfers the inline value after setup succeeds, then revokes access.
    fn try_new(value: InlineSecret<T>) -> Result<Self, HardenError> {
        let (mapping, destination, canary) = Self::allocate()?;
        // SAFETY: The mapping is writable, aligned for T, and disjoint from the
        // source. Ownership transfers into its previously uninitialized storage.
        unsafe {
            value.move_into(destination.as_ptr());
        }
        // Transfer cleanup to the typed owner before protection can fail.
        let allocation = Self {
            mapping,
            value: destination,
            canary,
            readers: Mutex::new(0),
            marker: PhantomData,
        };
        allocation.mapping.protect(libc::PROT_NONE)?;
        Ok(allocation)
    }

    /// Locates the canary without accessing the potentially inaccessible mapping.
    const fn canary_ptr(&self) -> *mut u8 {
        // SAFETY: Layout reserves CANARY_SIZE bytes before the value.
        unsafe { self.value.as_ptr().cast::<u8>().sub(CANARY_SIZE) }
    }

    /// Aborts on corruption. Callers must first make the data region readable.
    fn check_canary(&self) {
        // SAFETY: Called only while the data region is readable. The canary is
        // initialized before publication and has exactly CANARY_SIZE bytes.
        let actual = unsafe { core::slice::from_raw_parts(self.canary_ptr(), CANARY_SIZE) };
        if actual != self.canary {
            process::abort();
        }
    }

    /// Holds one reader slot across the callback, including panic unwinding.
    fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        // A fork child can inherit a held mutex. Reject it before locking or
        // constructing a reference to the wiped value.
        self.mapping.require_creator();
        // Release the mutex before user code so nested calls cannot deadlock.
        {
            let mut readers = self.readers.lock();
            if *readers == 0 {
                if self.mapping.protect(libc::PROT_READ).is_err() {
                    process::abort();
                }
                self.check_canary();
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
        self.mapping.require_creator();
        self.mapping.make_writable();
        self.check_canary();
        let mut allocation = ManuallyDrop::new(self);
        // SAFETY: Exclusive ownership rules out active readers. The value is
        // initialized and readable. ManuallyDrop prevents destroying the moved-out T.
        // Explicitly drop both owning fields to erase and release the source and
        // destroy the reader mutex. The remaining fields own no resources.
        unsafe {
            let value = allocation.value.as_ptr().read();
            ptr::drop_in_place(&raw mut allocation.mapping);
            ptr::drop_in_place(&raw mut allocation.readers);
            value
        }
    }
}

impl<const N: usize> ProtectedAllocation<[u8; N]> {
    /// Creates an owner for the zeroed array before running the initializer.
    fn try_init(f: impl FnOnce(&mut [u8; N])) -> Result<Self, HardenError> {
        let (mapping, value, canary) = Self::allocate()?;
        // Anonymous mappings are zeroed, so the array is already a valid value.
        // Its owner must exist before the initializer can unwind.
        let mut allocation = Self {
            mapping,
            value,
            canary,
            readers: Mutex::new(0),
            marker: PhantomData,
        };
        // SAFETY: Construction exclusively owns the writable, zeroed byte array.
        f(unsafe { allocation.value.as_mut() });
        allocation.check_canary();
        allocation.mapping.protect(libc::PROT_NONE)?;
        Ok(allocation)
    }
}

impl<T> Drop for ProtectedAllocation<T> {
    fn drop(&mut self) {
        // The child's wiped bytes may not represent a valid T. Mapping::drop
        // still runs after this return and releases the inherited mapping.
        if !self.mapping.in_creator() {
            return;
        }
        self.mapping.make_writable();
        self.check_canary();
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
        // An unsafe fork inside the callback can also inherit this guard.
        self.0.mapping.require_creator();
        let mut readers = self.0.readers.lock();
        *readers -= 1;
        if *readers == 0 {
            self.0.check_canary();
            if self.0.mapping.protect(libc::PROT_NONE).is_err() {
                process::abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use std::{
        os::unix::process::ExitStatusExt,
        panic::{AssertUnwindSafe, catch_unwind},
        process::Command,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    const CHILD_ENV: &str = "COMMONWARE_HARDENED_SECRET_TEST";

    /// Runs deliberate memory faults in a subprocess so the test runner survives.
    fn child(case: &str, signal: Option<i32>) {
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
    }

    #[test]
    fn protected_access_and_guards() {
        child("inaccessible", Some(libc::SIGSEGV));
        child("readonly", Some(libc::SIGSEGV));
        child("leading_guard", Some(libc::SIGSEGV));
        child("trailing_guard", Some(libc::SIGSEGV));
        child("canary", Some(libc::SIGABRT));
        child("extract_canary", Some(libc::SIGABRT));
        child("enter_failure", Some(libc::SIGABRT));
        child("exit_failure", Some(libc::SIGABRT));
    }

    #[test]
    fn locked_memory_limit() {
        child("locked_memory_limit", None);
    }

    #[test]
    fn fork_wipes_and_rejects_inherited_handles() {
        child("fork_drop", None);
        child("fork_access", None);
        child("fork_extract", None);
    }

    #[test]
    fn nested_and_concurrent_access() {
        let secret = HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])).unwrap();
        let cloned = secret.clone();
        assert!(Arc::ptr_eq(&secret.inner, &cloned.inner));
        secret.access(|value| cloned.access(|other| assert_eq!(value, other)));
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
        let secret = Secret::<[u8; 8193]>::try_init(|value| value.fill(37)).unwrap();
        assert!(secret.is_hardened());
        secret.access(|value| assert_eq!(value, &[37; 8193]));
        let empty = HardenedSecret::try_from_inline(InlineSecret::new([0u8; 0])).unwrap();
        empty.access(|value| assert!(value.is_empty()));
        assert_eq!(empty.try_extract().unwrap(), []);
        let panic = catch_unwind(|| {
            let _ = Secret::<[u8; 32]>::try_init(|value| {
                value.fill(99);
                panic!("initializer panic");
            });
        });
        assert!(panic.is_err());
        let usable = HardenedSecret::try_from_inline(InlineSecret::new([1; 32])).unwrap();
        usable.access(|value| assert_eq!(value[0], 1));
    }

    #[test]
    fn redaction_and_storage_conversion() {
        let secret = Secret::new([42u8; 32]);
        assert!(!secret.is_hardened());
        let secret = secret.try_harden().unwrap();
        assert!(secret.is_hardened());
        let secret = secret.try_harden().unwrap();
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        let cloned = secret.clone();
        assert!(cloned.is_hardened());
        assert_eq!(secret, cloned);
        assert_eq!(cloned.extract_or_clone(), [42u8; 32]);
        assert!(secret.is_hardened());
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Tracked([u8; 32]);
    impl Drop for Tracked {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn last_owner_destroys_value() {
        let secret = HardenedSecret::try_from_inline(InlineSecret::new(Tracked([42; 32]))).unwrap();
        let clone = secret.clone();
        secret.access(|value| assert_eq!(value.0, [42; 32]));
        drop(secret);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
        drop(clone);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
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
            // SAFETY: This subprocess lowers only its own locked-memory allowance.
            unsafe {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit), 0);
            }
            assert!(matches!(
                HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])),
                Err(HardenError::System {
                    operation: "mlock",
                    ..
                })
            ));
            return;
        }
        let secret = HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])).unwrap();
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
            "canary" | "extract_canary" => {
                secret
                    .inner
                    .mapping
                    .protect(libc::PROT_READ | libc::PROT_WRITE)
                    .unwrap();
                // SAFETY: The test owns the writable canary and deliberately corrupts it.
                unsafe {
                    let canary = secret.inner.canary_ptr();
                    canary.write(canary.read() ^ 1);
                }
                secret.inner.mapping.protect(libc::PROT_NONE).unwrap();
                if case == "extract_canary" {
                    let _ = secret.try_extract();
                } else {
                    secret.access(|_| ());
                }
            }
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
            "exit_failure" => exit_failure(),
            "fork_drop" | "fork_access" | "fork_extract" => {
                // SAFETY: The child only invokes the hardened handle's explicit
                // child rejection/drop path, raw mapping syscalls, and _exit.
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    if case == "fork_access" {
                        secret.access(|_| ());
                    }
                    if case == "fork_extract" {
                        let _ = secret.try_extract();
                        // SAFETY: Reaching this point means child rejection failed.
                        unsafe { libc::_exit(3) };
                    }
                    let data = secret.inner.mapping.data.as_ptr();
                    let len = secret.inner.mapping.data_len;
                    // SAFETY: Inspect raw bytes, never an inherited T. WIPEONFORK
                    // supplies zero pages, and the child owns this private mapping.
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
                    drop(secret);
                    // SAFETY: Terminate the child without invoking the test harness.
                    unsafe {
                        libc::_exit(0);
                    }
                }
                let mut status = 0;
                // SAFETY: pid identifies our child and status is writable.
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                if case != "fork_drop" {
                    assert!(libc::WIFSIGNALED(status));
                    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
                } else {
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 0);
                }
                secret.access(|value| assert_eq!(value, &[42; 32]));
                return;
            }
            _ => panic!("unknown subprocess case: {case}"),
        }
        panic!("expected subprocess fault: {case}");
    }

    /// Forces revocation to fail after a readable access scope has already started.
    fn exit_failure() {
        let secret = HardenedSecret::try_from_inline(InlineSecret::new([42u8; 131073])).unwrap();
        secret.access(|_| {
            // SAFETY: Deliberately unmap the last data page in this subprocess,
            // leaving the canary readable. Revoking access must abort when
            // mprotect encounters the gap, without accessing the missing page.
            unsafe {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                assert_eq!(
                    libc::munmap(
                        secret
                            .inner
                            .mapping
                            .data
                            .as_ptr()
                            .add(secret.inner.mapping.data_len - page)
                            .cast(),
                        page
                    ),
                    0
                );
            }
        });
    }
}
