//! Linux storage ownership, permissions, and fork invariants.
//!
//! The public contract is in [crate::secret]. This module owns the OS mappings
//! behind that contract. [HardenedSecret] shares a [ProtectedAllocation] through
//! `Arc`. Its metadata, including the reader mutex, lives in ordinary memory.
//! [Mapping] independently owns raw data cleanup, so erasure does not depend on
//! `T` being initialized or its destructor returning normally.
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
//! |<-- one page -->|<---------- whole data pages -------->|<-- one page -->|
//!
//! Guards: NONE throughout the mapping's lifetime
//! Data:   locked, excluded from kernel cores, wiped in fork children
//! T:      ends at the trailing guard, with its alignment validated
//!
//! Separate identity mapping: one readable, unlocked page, also wiped on fork
//! ```
//!
//! `data_len = round_up(max(size_of::<T>(), 1), page_size)`. Checked arithmetic
//! includes both guards within Rust's `isize::MAX` allocation bound. Page size
//! must be a power of two, and `T`'s alignment must divide it. Since Rust sizes
//! are multiples of alignment, placing `T` against the trailing guard aligns it.
//! A zero-sized value still owns a data page. Its non-null aligned pointer can
//! coincide with the start of the trailing guard because it occupies no bytes.
//! Unused data immediately before `T` shares the data permissions, so an underrun
//! need not reach the leading guard.
//!
//! # Permission and ownership states
//!
//! ```text
//! SETUP RW
//!   establish required protections before sensitive writes
//!   mark data dirty before moving T or invoking an initializer
//!   install typed owner as soon as T is valid
//!   for zeroed byte arrays, install owner before initializer callback
//!        |
//!        | protect(NONE), then publish
//!        v
//! IDLE NONE, readers = 0
//!        |
//!        | first reader: protect(READ), increment count
//!        v
//! READABLE READ, readers > 0
//!        | nested/concurrent readers share the readable interval
//!        | last reader: decrement to zero, protect(NONE)
//!        v
//! IDLE NONE
//!        |
//!        | unique extraction or final release
//!        v
//! RELEASE RW -> move out or destroy T -> erase data -> UNMAPPED
//! ```
//!
//! `UNMAPPED` is terminal. Non-final handle drops may occur while another handle
//! is reading. Final release and successful unique extraction require exclusive
//! ownership, so no reader remains. Shared extraction failure returns its handle
//! without entering this state machine or reading protected memory.
//!
//! Hold the reader mutex across permission changes and count updates. Release it
//! before calling user code, allowing nested and overlapping access. [ReadGuard]
//! closes the interval on return or unwind. A plain atomic counter would not
//! serialize revocation against the next reader's permission grant.
//!
//! Permission state records the last fully successful transition, or an unknown
//! state before a syscall whose failure may leave partial changes. Cleanup must
//! restore write access after an unknown transition. Already writable data needs
//! no redundant syscall. `dirty` is independent of initialization validity and
//! is set before the first sensitive write. Raw cleanup erases all data bytes,
//! including unused bytes and uninitialized padding, then unmaps while still
//! locked. It never interprets bytes as `T`.
//!
//! Setup, including final sealing, can return an error if cleanup succeeds. The
//! typed owner is installed before final sealing, so its failure destroys `T`
//! before raw erasure. A failed seal does not inherently imply abort. Published
//! access or extraction permission failures, count overflow, and cleanup failures
//! abort. Abort does not run destructors or guarantee erasure.
//!
//! # Fork identity
//!
//! ```text
//! Parent allocation                  Inherited child allocation
//! +----------------------+           +----------------------+
//! | initialized T        | --fork--> | wiped data bytes     |
//! | identity byte = 1    |           | identity byte = 0    |
//! +----------------------+           +----------------------+
//! parent remains usable              reject typed access before mutex/ref
//!                                    reject inherited read-guard return
//!                                    final release unmaps without T::drop
//! ```
//!
//! Each allocation retains its creator PID and its own [ForkIdentity] mapping.
//! The readable marker is initialized once and never reset. It rejects inherited
//! storage even when PID reuse or namespaces produce the same numeric PID. New
//! allocations created in a child get independent markers. No process-global
//! sentinel or inherited lock is needed to establish identity.
//!
//! Check identity before the reader mutex, typed access, unique extraction, and
//! typed destruction. Check again when an access guard or initializer returns,
//! because its callback may have forked. Child final release skips `T::drop` and
//! erasure of already wiped data, then releases both mappings. Keep the identity
//! mapping alive until data cleanup has finished. PID collisions in tests are
//! simulated against real fork-wiped pages, without waiting for kernel PID reuse.
//!
//! These checks supplement the caller's fork safety obligations. References
//! already inside a callback must never be used in the child. Wiped bytes may
//! not be a valid `T`, and permission changes cannot enforce reference lifetimes.

use crate::secret::{HardenError, InlineSecret};
use commonware_utils::sync::Mutex;
use core::{
    fmt::{Debug, Formatter},
    mem::{ManuallyDrop, MaybeUninit, align_of, size_of},
    ptr::{self, NonNull},
};
use std::{
    io, process,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};
use zeroize::Zeroize;

/// Shares one protected value without reallocating or cloning it.
///
/// OS-specific ownership and permission transitions stay behind this wrapper.
/// See the module documentation for invariants and [crate::secret] for the public
/// guarantees, type requirements, costs, and operational limits.
pub(crate) struct HardenedSecret<T> {
    inner: Arc<ProtectedAllocation<T>>,
}

impl<T> HardenedSecret<T> {
    /// Moves the inline value into protected storage, erasing its consumed source.
    ///
    /// Layout and OS failures consume the input. Setup can fail before transfer,
    /// or final sealing can fail after the typed owner has taken responsibility
    /// for destruction. Ordinary `Arc` allocation follows Rust allocator policy.
    pub(crate) fn try_from_inline(value: InlineSecret<T>) -> Result<Self, HardenError> {
        ProtectedAllocation::try_new(value).map(|inner| Self {
            inner: Arc::new(inner),
        })
    }

    /// Keeps the data readable for `f`, sharing the interval with other readers.
    ///
    /// The callback runs without the reader mutex held. Unwinding releases its
    /// reader slot. Published permission failures and inherited use abort.
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
    /// Initializes zeroed bytes after protection setup, before publication.
    ///
    /// The typed owner exists before user code can unwind or final sealing can
    /// fail. Both paths erase the data and release the mappings if cleanup succeeds.
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

/// Owns a readable marker that distinguishes this allocation from fork copies.
///
/// The creator writes one once. WIPEONFORK supplies zero in every descendant,
/// including when its numeric PID matches the creator's. An inherited marker is
/// never reset. A child can create new allocations with independent markers.
/// This page contains no secret and is not locked against swapping.
struct ForkIdentity {
    address: NonNull<u8>,
    page: usize,
}

impl ForkIdentity {
    /// Creates a read-only marker before the secret allocation is initialized.
    fn new(page: usize) -> Result<Self, HardenError> {
        // SAFETY: A null hint requests a fresh private mapping of one valid page.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(system("mmap"));
        }
        let Some(address) = NonNull::new(address.cast::<u8>()) else {
            // SAFETY: Release the mapping that cannot form a non-null Rust pointer.
            unsafe { abort_on_error(libc::munmap(address, page)) };
            return Err(HardenError::Layout);
        };
        let identity = Self { address, page };
        // SAFETY: The marker is a page-aligned private anonymous mapping we own.
        if unsafe { libc::madvise(address.as_ptr().cast(), page, libc::MADV_WIPEONFORK) } != 0 {
            return Err(system("madvise(MADV_WIPEONFORK)"));
        }
        // SAFETY: Construction exclusively owns this writable marker page.
        unsafe { address.as_ptr().write(1) };
        // SAFETY: No writable references remain. Identity checks only read the marker.
        if unsafe { libc::mprotect(address.as_ptr().cast(), page, libc::PROT_READ) } != 0 {
            return Err(system("mprotect"));
        }
        Ok(identity)
    }

    /// Checks the marker before any inherited mutex or typed value can be used.
    fn is_original(&self) -> bool {
        // SAFETY: The mapping remains readable for this owner's lifetime. A fork
        // child gets initialized zero bytes. Volatile prevents reusing a read
        // made before a fork that occurs in a caller's access callback.
        unsafe { self.address.as_ptr().read_volatile() == 1 }
    }
}

impl Drop for ForkIdentity {
    fn drop(&mut self) {
        // SAFETY: This owner releases only its own private mapping, including in
        // a child. The marker remains live until the secret mapping is released.
        unsafe { abort_on_error(libc::munmap(self.address.as_ptr().cast(), self.page)) };
    }
}

/// Owns raw pages independently of the initialization and destruction of `T`.
///
/// Only the data region is locked or changes permissions. This owner never
/// interprets its bytes as `T`, allowing cleanup after partial construction,
/// extraction, or a panicking destructor. See the module layout and state diagram.
struct Mapping {
    /// Start of the entire mapping, including the leading guard.
    base: NonNull<u8>,
    /// Length passed to munmap, including both guards.
    total_len: usize,
    /// First byte after the leading guard.
    data: NonNull<u8>,
    /// Page-rounded length of the data region, including unused bytes.
    data_len: usize,
    /// Process that created the mapping, used to reject inherited handles.
    pid: libc::pid_t,
    /// Allocation-specific identity, independent of numeric PID reuse or namespaces.
    identity: ForkIdentity,
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
        let identity = ForkIdentity::new(page)?;
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
            identity,
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
        // SAFETY: data_len covers T, and alignment was checked, including for a ZST.
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
        self.pid == unsafe { libc::getpid() } && self.identity.is_original()
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
    /// Active readers across all handles to this allocation.
    readers: Mutex<usize>,
}

// SAFETY: T can be moved to another thread. The mapping has one owner, shared
// access is coordinated by readers, and destruction requires exclusive ownership.
unsafe impl<T: Send> Send for ProtectedAllocation<T> {}
// SAFETY: T can be shared between threads. Permission transitions and reader
// counts are serialized, and no reference outlives its read guard.
unsafe impl<T: Sync> Sync for ProtectedAllocation<T> {}

impl<T> ProtectedAllocation<T> {
    /// Transfers the inline value after setup succeeds, then revokes access.
    fn try_new(value: InlineSecret<T>) -> Result<Self, HardenError> {
        let (mut mapping, destination) = Mapping::allocate::<T>()?;
        // Cleanup must erase even if a later permission change fails.
        mapping.dirty = true;
        // SAFETY: The mapping is writable, aligned for T, and disjoint from the
        // source. Ownership transfers into its previously uninitialized storage.
        unsafe {
            value.move_into(destination.as_ptr());
        }
        // Transfer cleanup to the typed owner before protection can fail.
        let allocation = Self {
            mapping,
            value: destination,
            readers: Mutex::new(0),
        };
        allocation.mapping.protect(libc::PROT_NONE)?;
        Ok(allocation)
    }

    /// Holds one reader slot across the callback, including panic unwinding.
    fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        // A fork child can inherit a held mutex. Reject it before locking or
        // constructing a reference to the wiped value.
        self.mapping.require_creator();
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
        self.mapping.require_creator();
        self.mapping.make_writable();
        let mut owner = ManuallyDrop::new(self);
        let allocation = &mut *owner;
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
        let (mut mapping, value) = Mapping::allocate::<[u8; N]>()?;
        mapping.dirty = true;
        // Anonymous mappings are zeroed, so the array is already a valid value.
        // Its owner must exist before the initializer can unwind.
        let mut allocation = Self {
            mapping,
            value,
            readers: Mutex::new(0),
        };
        // SAFETY: Construction exclusively owns the writable, zeroed byte array.
        f(unsafe { allocation.value.as_mut() });
        // The initializer may have forked. Reject its return in the child before
        // publishing a handle whose array has been wiped.
        allocation.mapping.require_creator();
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

    /// Runs deliberate memory faults in a subprocess so the test runner survives.
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
        child("final_seal_failure", None);
        child("post_move_failure", None);
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
    fn fork_wipes_and_rejects_inherited_handles() {
        child("fork_drop", None);
        child("fork_access", None);
        child("fork_extract", None);
        child("fork_init", None);
        child("fork_guard", None);
        child("fork_collision_access", None);
        child("fork_collision_locked", None);
        child("fork_collision_extract", None);
        child("fork_collision_drop", None);
        child("fork_new_allocation", None);
    }

    #[test]
    fn fork_identity_survives_pid_collision() {
        child("fork_pid_collision", None);
    }

    #[test]
    fn nested_and_concurrent_access() {
        let secret = HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])).unwrap();
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
            assert_eq!(
                secret.inner.mapping.protection.load(Ordering::Relaxed),
                libc::PROT_READ
            );
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
        assert_eq!(
            secret.inner.mapping.protection.load(Ordering::Relaxed),
            libc::PROT_NONE
        );
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
                let value =
                    HardenedSecret::try_from_inline(InlineSecret::new(Aligned([73]))).unwrap();
                assert_eq!(value.inner.value.as_ptr().addr() % $page, 0);
                assert_eq!(value.inner.mapping.data_len, $page);
                value.access(|value| assert_eq!(value.0, [73]));
                drop(value);
                #[repr(align($over))]
                struct OverAligned;
                assert!(matches!(
                    HardenedSecret::try_from_inline(InlineSecret::new(OverAligned)),
                    Err(HardenError::Layout)
                ));
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

    /// Checks both ends of the allocation and initializes every value byte.
    fn check_layout<const N: usize>(pages: usize) {
        let secret = HardenedSecret::<[u8; N]>::try_init(|value| {
            assert_eq!(value, &[0; N]);
            value.fill(37);
        })
        .unwrap();
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
        let marker = mapping.identity.address.as_ptr();
        assert_eq!(secret.try_extract().unwrap(), [37; N]);
        assert_unmapped(data);
        assert_unmapped(marker);
    }

    #[test]
    fn unwind_releases_mapping() {
        let mut address = ptr::null_mut();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = Secret::<[u8; 32]>::try_init(|value| {
                    value.fill(99);
                    address = value.as_mut_ptr();
                    panic!("initializer panic");
                });
            }))
            .is_err()
        );
        assert!(!address.is_null());
        assert_unmapped(address);

        struct PanicOnDrop([u8; 32]);
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                assert_eq!(self.0, [99; 32]);
                panic!("destructor panic");
            }
        }
        let secret =
            HardenedSecret::try_from_inline(InlineSecret::new(PanicOnDrop([99; 32]))).unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        let marker = secret.inner.mapping.identity.address.as_ptr();
        assert!(catch_unwind(AssertUnwindSafe(|| drop(secret))).is_err());
        assert_unmapped(data);
        assert_unmapped(marker);
    }

    #[test]
    fn redaction_and_storage_conversion() {
        let secret = Secret::new([42u8; 32]);
        assert!(!secret.is_hardened());
        let secret = secret.try_harden().unwrap();
        assert!(secret.is_hardened());
        let address = secret.access(|value| value as *const _);
        let secret = secret.try_harden().unwrap();
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
    fn last_owner_destroys_value() {
        let drops = AtomicUsize::new(0);
        let secret = HardenedSecret::try_from_inline(InlineSecret::new(Tracked {
            bytes: [42; 32],
            drops: &drops,
        }))
        .unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        let marker = secret.inner.mapping.identity.address.as_ptr();
        let clone = secret.clone();
        secret.access(|value| assert_eq!(value.bytes, [42; 32]));
        drop(secret);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(clone);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_unmapped(data);
        assert_unmapped(marker);
    }

    #[test]
    fn unique_extraction_moves_nonclone_value() {
        let drops = AtomicUsize::new(0);
        let secret = HardenedSecret::try_from_inline(InlineSecret::new(Tracked {
            bytes: [42; 32],
            drops: &drops,
        }))
        .unwrap();
        let data = secret.inner.mapping.data.as_ptr();
        let marker = secret.inner.mapping.identity.address.as_ptr();
        let value = secret.try_extract().unwrap();
        assert_unmapped(data);
        assert_unmapped(marker);
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
            assert!(matches!(
                HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])),
                Err(HardenError::System {
                    operation: "mlock",
                    ..
                })
            ));
            return;
        }
        if case == "fork_pid_collision" {
            let mut allocation =
                ProtectedAllocation::try_new(InlineSecret::new([42u8; 32])).unwrap();
            // SAFETY: The child only checks mapping identity and exits. It never
            // interprets the wiped allocation as T or enters inherited locks.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                // Simulate a reused or namespace-relative PID with real fork-wiped
                // pages. Waiting for actual numeric PID reuse would be unreliable.
                // SAFETY: getpid and _exit have no memory preconditions.
                unsafe {
                    allocation.mapping.pid = libc::getpid();
                    libc::_exit(if allocation.mapping.in_creator() {
                        1
                    } else {
                        0
                    });
                }
            }
            let mut status = 0;
            // SAFETY: pid names our child and status is writable.
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            allocation.access(|value| assert_eq!(value, &[42; 32]));
            return;
        }
        match case.as_str() {
            "exit_failure" => {
                exit_failure();
                panic!("revocation did not abort");
            }
            "final_seal_failure" | "cleanup_failure" => {
                let mut address = ptr::null_mut();
                let result = Secret::<[u8; 32]>::try_init(|bytes| {
                    bytes.fill(71);
                    address = bytes.as_mut_ptr();
                    if case == "cleanup_failure" {
                        deny_mprotect(&[libc::PROT_NONE, libc::PROT_READ | libc::PROT_WRITE]);
                    } else {
                        deny_mprotect(&[libc::PROT_NONE]);
                    }
                });
                assert!(matches!(
                    result,
                    Err(HardenError::System {
                        operation: "mprotect",
                        ..
                    })
                ));
                assert_unmapped(address);
                return;
            }
            "post_move_failure" => {
                let drops = AtomicUsize::new(0);
                let address = AtomicUsize::new(0);
                struct Value<'a> {
                    drops: &'a AtomicUsize,
                    address: &'a AtomicUsize,
                }
                impl Drop for Value<'_> {
                    fn drop(&mut self) {
                        self.address
                            .store(self as *const Self as usize, Ordering::Relaxed);
                        self.drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                deny_mprotect(&[libc::PROT_NONE]);
                let result = HardenedSecret::try_from_inline(InlineSecret::new(Value {
                    drops: &drops,
                    address: &address,
                }));
                assert!(matches!(
                    result,
                    Err(HardenError::System {
                        operation: "mprotect",
                        ..
                    })
                ));
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert_unmapped(address.load(Ordering::Relaxed) as *mut u8);
                return;
            }
            "no_permission_changes" => {
                let public = Secret::new([42u8; 32]).try_harden().unwrap();
                let shared =
                    HardenedSecret::try_from_inline(InlineSecret::new([73u8; 32])).unwrap();
                let clone = shared.clone();
                deny_mprotect(&[
                    libc::PROT_NONE,
                    libc::PROT_READ,
                    libc::PROT_READ | libc::PROT_WRITE,
                ]);
                let public = public.try_harden().unwrap();
                assert!(public.is_hardened());
                let returned = shared.try_extract().unwrap_err();
                assert!(Arc::ptr_eq(&returned.inner, &clone.inner));
                assert_eq!(*returned.inner.readers.lock(), 0);
                assert_eq!(
                    returned.inner.mapping.protection.load(Ordering::Relaxed),
                    libc::PROT_NONE
                );
                drop(returned);
                // SAFETY: Leave the disposable subprocess without destructors.
                // Final release would require the deliberately forbidden write transition.
                unsafe { libc::_exit(0) };
            }
            "borrowed_panic_protection" | "owned_panic_protection" => {
                let secret = Secret::new([42u8; 32]).try_harden().unwrap();
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
            "fork_init" => {
                let mut pid = -1;
                let secret = Secret::<[u8; 32]>::try_init(|bytes| {
                    bytes.fill(42);
                    // SAFETY: Neither branch uses the array after fork. The child
                    // returns only to the constructor's explicit rejection check.
                    pid = unsafe { libc::fork() };
                    assert!(pid >= 0);
                })
                .unwrap();
                wait_for_child(pid, Some(libc::SIGABRT));
                secret.access(|value| assert_eq!(value, &[42; 32]));
                return;
            }
            "fork_guard" => {
                let secret =
                    HardenedSecret::try_from_inline(InlineSecret::new([42u8; 32])).unwrap();
                let mut pid = -1;
                secret.access(|_| {
                    // SAFETY: The child returns directly to inherited-guard rejection
                    // without using a reference to the fork-wiped value.
                    pid = unsafe { libc::fork() };
                    assert!(pid >= 0);
                });
                wait_for_child(pid, Some(libc::SIGABRT));
                secret.access(|value| assert_eq!(value, &[42; 32]));
                return;
            }
            "fork_collision_access"
            | "fork_collision_locked"
            | "fork_collision_extract"
            | "fork_collision_drop"
            | "fork_new_allocation" => {
                fork_collision(&case);
                return;
            }
            _ => {}
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

    /// Forces revocation failure without assuming a particular page size.
    fn exit_failure() {
        // A ZST still owns one data page. Its reference occupies no bytes, so
        // removing that page leaves no live reference into unmapped data.
        let secret = HardenedSecret::try_from_inline(InlineSecret::new(())).unwrap();
        secret.access(|_| {
            // SAFETY: Remove the test's data page to force last-reader mprotect
            // failure. The marker and the ZST's trailing-guard address stay mapped.
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

    /// Exercises inherited state with a simulated PID match and real wiped pages.
    fn fork_collision(case: &str) {
        struct Value([u8; 32]);
        impl Drop for Value {
            fn drop(&mut self) {
                // Wiped bytes must never reach typed destruction in the child.
                assert_eq!(self.0, [42; 32]);
            }
        }
        let mut allocation =
            ProtectedAllocation::try_new(InlineSecret::new(Value([42; 32]))).unwrap();
        // SAFETY: The child only executes explicit rejection/drop paths or creates
        // independent storage. It never uses a borrowed inherited value.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: Alter only child-local metadata to model a numeric collision.
            allocation.mapping.pid = unsafe { libc::getpid() };
            match case {
                "fork_collision_access" => {
                    // Model forking during an overlapping read. Identity must be
                    // rejected even when first-reader permission setup is skipped.
                    *allocation.readers.lock() = 1;
                    allocation.access(|_| ());
                }
                "fork_collision_locked" => {
                    // A held inherited mutex must not be touched. An alarm turns
                    // accidental blocking into a distinct, bounded test failure.
                    let _held = allocation.readers.lock();
                    // SAFETY: Set a child-local timeout for a potential deadlock.
                    unsafe { libc::alarm(5) };
                    allocation.access(|_| ());
                }
                "fork_collision_extract" => {
                    let _ = allocation.extract();
                }
                "fork_collision_drop" => drop(allocation),
                "fork_new_allocation" => {
                    let fresh =
                        HardenedSecret::try_from_inline(InlineSecret::new([73u8; 32])).unwrap();
                    fresh.access(|bytes| assert_eq!(bytes, &[73; 32]));
                    drop(fresh);
                    assert!(!allocation.mapping.in_creator());
                    drop(allocation);
                }
                _ => unreachable!(),
            }
            // SAFETY: Leave without running the inherited test harness.
            unsafe { libc::_exit(0) };
        }
        let signal = if matches!(case, "fork_collision_drop" | "fork_new_allocation") {
            None
        } else {
            Some(libc::SIGABRT)
        };
        wait_for_child(pid, signal);
        allocation.access(|value| assert_eq!(value.0, [42; 32]));
    }
}
