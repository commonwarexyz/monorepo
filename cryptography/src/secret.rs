//! Secret values with explicit access and erasure of their retained storage.
//!
//! [Secret] provides two storage modes through one wrapper. [Secret::new] stores
//! `T` inline without allocating. [Secret::try_harden] moves it into protected
//! memory on Linux with `std`. [Secret::try_init] initializes a byte array directly
//! in that memory. [Secret::is_hardened] reports the mode without accessing the
//! value or changing permissions.
//!
//! # Ownership and access
//!
//! Inline clones call `T::clone` and own separate values. Hardened clones share
//! one allocation without copying `T` or changing its permissions. The public
//! `Secret<T>: Clone` implementation requires `T: Clone` for both modes.
//!
//! ```text
//! Inline storage                         Hardened storage
//!
//! Secret A       Secret B                Secret A       Secret B
//! +----------+   +----------+             +--------+     +--------+
//! | T        |   | T::clone |             | handle |     | handle |
//! +----------+   +----------+             +----+---+     +---+----+
//!                                             |             |
//! Separate values, each with                  +------+------+
//! its own destruction and erasure                    |
//!                                                    v
//!                                         shared allocation metadata
//!                                                    |
//!                                                    v
//!                                      protected data containing one T
//!                                      erased on final release
//! ```
//!
//! Allocation metadata lives in ordinary memory. The secret-storage protections
//! apply to the data containing `T`. A separate readable page records fork
//! identity, contains no secret, and is not locked. Public cached values belong
//! outside protected data.
//!
//! [Secret::access] lends `&T` to a closure. Borrows into `T` cannot escape, but
//! copies, raw pointers, and references already stored inside `T` can escape.
//! These results receive no protection. The wrapper redacts its own `Debug` and
//! `Display` output. Callers can still print the value inside the closure.
//! Equality uses `T`'s constant-time comparison when `T: CtEq`.
//!
//! [Secret::try_extract] consumes a uniquely owned wrapper, moves out ordinary
//! `T`, erases its source, and releases any protected allocation. It never clones.
//! If hardened storage is shared, it returns `Err(self)` unchanged without
//! reading `T` or changing permissions. [Secret::extract_or_clone] instead clones
//! through an access callback when shared. Both produce an unprotected value
//! whose cleanup belongs to the caller, for example through [zeroize::Zeroizing].
//!
//! # Hardened storage
//!
//! Hardening requires Linux with `std` and support for `MADV_WIPEONFORK`, introduced
//! in Linux 4.14. Construction must establish every required protection. It may
//! fail under the process's actual locked-memory allowance or syscall policy.
//! Hardening leaves the value and its storage unchanged on error, including on
//! unsupported platforms. Earlier inline clones and exported bytes are unaffected.
//! Hardening an already hardened value keeps its existing allocation.
//!
//! | Measure | Protection and limits |
//! |---|---|
//! | [mlock](https://man7.org/linux/man-pages/man2/mlock.2.html) | Keeps data pages out of swap, without protecting earlier copies or hibernation images. |
//! | [MADV_DONTDUMP](https://man7.org/linux/man-pages/man2/madvise.2.html) | Excludes these data pages from kernel-generated core dumps, leaving stack, heap, and computation copies unaffected. |
//! | `MADV_WIPEONFORK` and allocation identity | Wipe inherited bytes and reject typed use of invalid wiped values in descendants. |
//! | [mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html) | Blocks ordinary loads while idle and permits read-only access during callbacks. |
//! | Guard pages | Fault accesses reaching either data-region boundary, without catching all underruns within unused data bytes or arbitrary pointer jumps. |
//! | Erasure and unmapping | Clear current retained storage during cleanup, subject to the limits below. |
//!
//! The first active callback makes the data pages readable. Nested or concurrent
//! callbacks through any clone keep them readable until the last callback ends.
//! Pages are readable throughout the process during that interval, including to
//! other threads. Shared access must not write to the stored value, even through
//! interior mutability, because the read-only mapping can make such writes fatal.
//!
//! These measures do not promise protection against arbitrary code execution,
//! general speculative-execution attacks, or authorized debugger-style inspection.
//! Page permissions are not the debugger access-control boundary. Same-user
//! inspection depends on credentials, dumpability, capabilities, and security
//! policy. See [Linux ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html).
//!
//! # Forking and failures
//!
//! Fork children inherit zeroed data. Each allocation also has a read-only marker
//! that is wiped in descendants and never reset. This rejects inherited handles
//! even if PID reuse or PID namespaces produce a numeric creator-PID match. New
//! allocations in a child have independent markers and remain usable.
//!
//! Inherited access and unique extraction abort before touching the reader mutex
//! or interpreting wiped bytes as `T`. Returning through an inherited access guard
//! or initializer also aborts. Shared `try_extract` may return `Err(self)` without
//! accessing the allocation. Final release in a child unmaps its copy without
//! calling `T`'s destructor. The parent's allocation remains usable.
//!
//! A caller using an unsafe fork API must obey that API's safety rules and must
//! never use an inherited reference into `T` in the child. Wiped bytes may no
//! longer represent a valid value. These checks cannot revoke references already
//! handed to a callback.
//!
//! Construction returns [HardenError] if setup or final sealing fails and cleanup
//! succeeds. After publication, permission failures, reader-count overflow, and
//! inherited typed use abort. Cleanup also aborts if it cannot restore write access
//! or release mappings. Abort does not run destructors or guarantee erasure.
//!
//! # Stored types and erasure
//!
//! Store sensitive bytes directly in `T`, for example in an array or a struct of
//! arrays. Protection and erasure cover `T`'s own storage, including padding. They
//! do not extend to allocations behind `Vec`, `String`, `Box`, or other pointers.
//! Cleanup of those allocations depends on `T`'s destructor.
//!
//! Each inline value is destroyed and then erased. A panicking inline destructor
//! can prevent that erasure. In hardened storage, the final owner destroys `T`,
//! then erases and unmaps the data.
//! The raw mapping owner still performs cleanup if `T`'s destructor or a byte-array
//! initializer unwinds, provided cleanup succeeds and the process keeps unwinding.
//! Dropping a shared handle does not erase storage still owned by another handle.
//! [Secret] implements [zeroize::ZeroizeOnDrop] for this erasure on final release,
//! without requiring a zeroization trait on `T`.
//!
//! Moves, registers, stacks, serialized exports, and cryptographic scratch memory
//! can contain other copies outside the wrapper's control. Leaks and termination
//! without cleanup also prevent erasure. Protecting retained storage does not
//! protect every step of a computation that uses it.
//!
//! # Costs and trait bounds
//!
//! Each allocation locks `round_up(max(size_of::<T>(), 1), page_size)` data bytes,
//! reserves two additional virtual guard pages, and allocates one unlocked page
//! for fork identity. Mappings also consume kernel bookkeeping and address space.
//! With 4 KiB pages, a 64 KiB lock allowance, and no other locked memory, sixteen
//! one-data-page allocations exhaust that allowance. Actual allowances vary.
//!
//! Hardened access synchronizes a reader count and changes permissions on first
//! entry and last exit. Inline access uses neither synchronization nor syscalls.
//! The inline variant keeps even hardened handles proportional to `size_of::<T>()`.
//!
//! Trait bounds are the same on every platform, including builds without `std`:
//!
//! | Trait on `Secret<T>` | Required traits on `T` |
//! |---|---|
//! | `Clone` | `Clone` |
//! | `Debug`, `Display`, `ZeroizeOnDrop` | None |
//! | `PartialEq`, `Eq` | `CtEq` |
//! | `Send`, `Sync` | `Send + Sync` |
//! | `Unpin` | `Unpin` |
//! | `RefUnwindSafe` | `RefUnwindSafe` |
//! | `UnwindSafe` | `UnwindSafe + RefUnwindSafe` |
//!
//! Sending or sharing a secret between threads requires both thread traits because
//! hardened handles can share ownership. Non-thread-safe values remain usable
//! locally, but the wrapper cannot be sent or shared across threads:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::cell::Cell;
//!
//! fn require_send<T: Send>() {}
//! require_send::<Secret<Cell<u8>>>();
//! ```
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::cell::Cell;
//!
//! fn require_sync<T: Sync>() {}
//! require_sync::<Secret<Cell<u8>>>();
//! ```
//!
//! A payload that supports shared access but cannot move between threads, such
//! as a mutex guard, also prevents either thread trait on the wrapper:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use std::sync::MutexGuard;
//!
//! fn require_send<T: Send>() {}
//! fn require_sync<T: Sync>() {}
//! require_sync::<MutexGuard<'static, ()>>();
//! require_send::<Secret<MutexGuard<'static, ()>>>();
//! ```
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use std::sync::MutexGuard;
//!
//! fn require_sync<T: Sync>() {}
//! require_sync::<MutexGuard<'static, ()>>();
//! require_sync::<Secret<MutexGuard<'static, ()>>>();
//! ```
//!
//! Access guards restore the reader count and permissions during unwinding. They
//! do not repair invariants inside `T`. Even when a closure owns its handle,
//! another hardened clone can observe the same value after a caught panic, so
//! owned unwind safety also requires `T: RefUnwindSafe`:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::{cell::Cell, panic::UnwindSafe};
//!
//! fn require_unwind_safe<T: UnwindSafe>() {}
//! require_unwind_safe::<Box<Cell<u8>>>();
//! require_unwind_safe::<Secret<Box<Cell<u8>>>>();
//! ```
//!
//! Borrowed access likewise retains `T`'s unwind-safety requirement:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::{cell::Cell, panic::RefUnwindSafe};
//!
//! fn require_ref_unwind_safe<T: RefUnwindSafe>() {}
//! require_ref_unwind_safe::<Secret<Cell<u8>>>();
//! ```
//!
//! Owned unwind safety additionally preserves `T: UnwindSafe`. A mutable
//! reference can satisfy the borrowed bound while failing the owned bound:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::panic::{RefUnwindSafe, UnwindSafe};
//!
//! fn require_ref_unwind_safe<T: RefUnwindSafe>() {}
//! fn require_unwind_safe<T: UnwindSafe>() {}
//! require_ref_unwind_safe::<Secret<&'static mut ()>>();
//! require_unwind_safe::<Secret<&'static mut ()>>();
//! ```
//!
//! Inline storage contains `T` directly, so the wrapper also preserves its
//! pinning requirements:
//!
//! ```compile_fail
//! use commonware_cryptography::Secret;
//! use core::marker::PhantomPinned;
//!
//! fn require_unpin<T: Unpin>() {}
//! require_unpin::<Secret<PhantomPinned>>();
//! ```

#[cfg(all(target_os = "linux", feature = "std"))]
use crate::hardened_secret::HardenedSecret;
use core::{
    fmt::{Debug, Display, Formatter},
    mem::{ManuallyDrop, MaybeUninit},
    panic::{RefUnwindSafe, UnwindSafe},
};
use ctutils::CtEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Failure to construct hardened secret storage.
///
/// These errors report failures during setup. Once hardened storage has been
/// constructed, failures to change its memory permissions abort the process.
///
/// `Layout` and `System` are available only on Linux with `std`. `Unsupported`
/// is available on every platform, including builds where it is never returned.
#[derive(Debug, Error)]
pub enum HardenError {
    /// Hardening was requested without both Linux and the `std` feature.
    ///
    /// A Linux kernel that rejects a required operation produces an operating-system
    /// error instead.
    #[error("memory hardening requires Linux and the std feature")]
    Unsupported,
    /// The allocator cannot represent a valid mapping for the value.
    ///
    /// This includes unsupported page sizes or alignment, size overflow, and
    /// mappings that exceed Rust's address or allocation-size constraints.
    #[cfg(all(target_os = "linux", feature = "std"))]
    #[error("unsupported protected allocation layout")]
    Layout,
    /// Allocation or a required memory protection failed.
    #[cfg(all(target_os = "linux", feature = "std"))]
    #[error("{operation}: {source}")]
    System {
        /// The operation that failed, including the advice flag for `madvise`.
        operation: &'static str,
        /// The error reported by that operation.
        #[source]
        source: std::io::Error,
    },
}

/// A secret stored inline or in protected memory.
///
/// [Self::new] stores values inline without allocating. After successful [Self::try_harden],
/// clones share a protected allocation. Inline clones instead call `T::clone`.
/// `Debug` prints `Secret([REDACTED])` and `Display` prints `[REDACTED]`.
/// See the [module documentation](self) for requirements on `T`.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::Secret;
///
/// let secret = Secret::new([42u8; 32]);
/// assert!(!secret.is_hardened());
/// secret.access(|bytes| assert_eq!(bytes.len(), 32));
/// let cloned = secret.clone();
/// assert_eq!(secret, cloned);
/// ```
#[derive(Clone)]
pub struct Secret<T> {
    storage: Storage<T>,
}

/// Storage selection kept private so callers access values through Secret's methods.
#[derive(Clone)]
enum Storage<T> {
    /// A value stored directly in this enum, without OS memory protections.
    Inline(InlineSecret<T>),
    /// A handle to shared, protected storage.
    #[cfg(all(target_os = "linux", feature = "std"))]
    Hardened(HardenedSecret<T>),
}

impl<T> Secret<T> {
    /// Stores `value` inline. No protected allocation is made until hardening.
    pub const fn new(value: T) -> Self {
        Self {
            storage: Storage::Inline(InlineSecret::new(value)),
        }
    }

    /// Returns whether this value uses hardened storage.
    ///
    /// Does not access the value, allocate, or change memory permissions. Always
    /// returns `false` on builds without Linux and `std`.
    #[inline]
    pub const fn is_hardened(&self) -> bool {
        match &self.storage {
            Storage::Inline(_) => false,
            #[cfg(all(target_os = "linux", feature = "std"))]
            Storage::Hardened(_) => true,
        }
    }

    /// Grants `f` temporary access to the stored value, making hardened storage read-only.
    ///
    /// Borrows into the stored value cannot escape the closure. Copied values,
    /// raw pointers, and references already stored inside `T` can escape and
    /// receive no additional protection.
    ///
    /// For hardened storage, nested and concurrent calls through any clone
    /// keep the allocation readable until the last call ends. Returning from
    /// one callback does not revoke access while another remains active. Shared
    /// access must not write to hardened storage, even through interior mutability.
    ///
    /// # Panics
    ///
    /// A panic from `f` propagates. During unwinding, hardened storage becomes
    /// inaccessible if no other call remains active. Failed permission changes
    /// abort the process.
    ///
    /// # Examples
    ///
    /// A borrow into the stored value cannot be returned:
    ///
    /// ```compile_fail
    /// use commonware_cryptography::Secret;
    ///
    /// let secret = Secret::new([42u8; 32]);
    /// let bytes = secret.access(|value| &value[..]);
    /// ```
    #[inline]
    pub fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        match &self.storage {
            Storage::Inline(value) => value.access(f),
            #[cfg(all(target_os = "linux", feature = "std"))]
            Storage::Hardened(value) => value.access(f),
        }
    }

    /// Consumes the wrapper and moves out `T` if its storage is uniquely owned.
    ///
    /// The returned value is ordinary, unprotected `T`. The caller is responsible
    /// for its erasure. The source storage is erased without running `T`'s destructor.
    /// Inline storage always succeeds. Hardened storage also releases its allocation
    /// on success. This method never clones `T`.
    ///
    /// # Errors
    ///
    /// Returns `Err(self)` unchanged if another handle shares the hardened allocation.
    /// In that case, no value is read and no memory permissions are changed.
    /// Use [Self::extract_or_clone] to clone the value when shared and `T: Clone`.
    ///
    /// Permission failures or moving out an inherited fork-child value abort the
    /// process, as described in the [module documentation](self).
    ///
    /// # Examples
    ///
    /// Extraction does not require `Clone`:
    ///
    /// ```
    /// use commonware_cryptography::Secret;
    ///
    /// struct Value([u8; 32]);
    /// let secret = Secret::new(Value([42; 32]));
    /// let value = secret.try_extract().unwrap();
    /// assert_eq!(value.0, [42; 32]);
    /// ```
    pub fn try_extract(self) -> Result<T, Self> {
        match self.storage {
            Storage::Inline(value) => Ok(value.extract()),
            #[cfg(all(target_os = "linux", feature = "std"))]
            Storage::Hardened(value) => value.try_extract().map_err(|value| Self {
                storage: Storage::Hardened(value),
            }),
        }
    }

    /// Consumes the wrapper, moving out `T` when uniquely owned or cloning it otherwise.
    ///
    /// The returned value is ordinary, unprotected `T`. The caller is responsible
    /// for its erasure. Inline and uniquely owned hardened values follow
    /// [Self::try_extract], which erases the source storage. Shared hardened values
    /// call `T::clone` through [Self::access], then release this handle. Other handles
    /// keep their protected storage.
    ///
    /// # Panics
    ///
    /// A panic from `T::clone` propagates after the access call ends and this handle
    /// is released. Permission and cleanup failures abort as described in the
    /// [module documentation](self).
    ///
    /// # Examples
    ///
    /// Use [zeroize::Zeroizing] to erase the extracted bytes when they are dropped:
    ///
    /// ```
    /// use commonware_cryptography::Secret;
    /// use zeroize::Zeroizing;
    ///
    /// let secret = Secret::new([42u8; 32]);
    /// let bytes = Zeroizing::new(secret.extract_or_clone());
    /// assert_eq!(*bytes, [42; 32]);
    /// ```
    pub fn extract_or_clone(self) -> T
    where
        T: Clone,
    {
        self.try_extract()
            .unwrap_or_else(|secret| secret.access(Clone::clone))
    }

    /// Moves an inline value into hardened storage, or keeps an existing allocation.
    ///
    /// Hardening an already hardened value performs no allocation or permission
    /// change. Other wrappers, including earlier inline clones, are unaffected.
    ///
    /// # Errors
    ///
    /// Returns [HardenError::Unsupported] without Linux and `std`. On supported
    /// builds, returns a layout error if a suitable mapping cannot be represented,
    /// including when `T`'s alignment exceeds the system page size. Mapping and
    /// memory-protection failures return an operating-system error. Locking is
    /// subject to the process's `RLIMIT_MEMLOCK` allowance.
    /// An error leaves the value and its storage unchanged.
    ///
    /// Allocating shared ownership metadata follows the ordinary Rust allocator's
    /// allocation-failure behavior. Cleanup failures abort as described in the
    /// [module documentation](self).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use commonware_cryptography::{HardenError, Secret};
    ///
    /// # fn main() -> Result<(), HardenError> {
    /// let mut secret = Secret::new([42u8; 32]);
    /// secret.try_harden()?;
    /// assert!(secret.is_hardened());
    /// secret.access(|bytes| assert_eq!(bytes[0], 42));
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_harden(&mut self) -> Result<(), HardenError> {
        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            let hardened = match &mut self.storage {
                // SAFETY: On success, the source is erased and overwritten below
                // without dropping its value or invoking any code that can panic.
                Storage::Inline(value) => unsafe { HardenedSecret::try_from_inline(value)? },
                Storage::Hardened(_) => return Ok(()),
            };
            let storage = &raw mut self.storage;
            // SAFETY: The sealed allocation now owns T. Erase the entire old
            // storage, including padding, without dropping T. Use the raw pointer
            // to replace the temporarily invalid bytes without forming a reference.
            unsafe {
                zeroize_ptr(storage);
                storage.write(Storage::Hardened(hardened));
            }
            Ok(())
        }
        #[cfg(not(all(target_os = "linux", feature = "std")))]
        {
            Err(HardenError::Unsupported)
        }
    }
}

impl<const N: usize> Secret<[u8; N]> {
    /// Initializes a byte array directly in hardened storage.
    ///
    /// Calls `f` with a zeroed array after locking its pages and excluding them
    /// from core dumps. The array is writable during initialization and inaccessible
    /// when construction completes. Untouched bytes remain zero. The closure's
    /// own temporaries are outside the allocation.
    ///
    /// # Errors
    ///
    /// Returns the same construction errors as [Self::try_harden]. The initializer
    /// is not called if hardening is unsupported or initial setup fails. If a later
    /// step fails, the array is erased before returning the error.
    ///
    /// # Panics
    ///
    /// A panic from `f` propagates. During unwinding, the allocation is erased
    /// and released. Cleanup failures abort as described in the [module documentation](self).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use commonware_cryptography::{HardenError, Secret};
    ///
    /// # fn main() -> Result<(), HardenError> {
    /// let secret = Secret::<[u8; 32]>::try_init(|bytes| bytes.fill(42))?;
    /// assert!(secret.is_hardened());
    /// secret.access(|bytes| assert_eq!(bytes[0], 42));
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_init(f: impl FnOnce(&mut [u8; N])) -> Result<Self, HardenError> {
        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            HardenedSecret::try_init(f).map(|value| Self {
                storage: Storage::Hardened(value),
            })
        }
        #[cfg(not(all(target_os = "linux", feature = "std")))]
        {
            let _ = f;
            Err(HardenError::Unsupported)
        }
    }
}

impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T> Display for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: CtEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.access(|a| other.access(|b| a.ct_eq(b).into()))
    }
}

impl<T: CtEq> Eq for Secret<T> {}

impl<T> ZeroizeOnDrop for Secret<T> {}

// SAFETY: Inline ownership can move across threads when T is Send. Hardened
// handles share ownership, so T must also be Sync even when moving one handle.
unsafe impl<T: Send + Sync> Send for Secret<T> {}

// SAFETY: Inline shared access requires T: Sync. Hardened handles may outlive
// each other on different threads, so transferring final ownership also needs Send.
unsafe impl<T: Send + Sync> Sync for Secret<T> {}

// User code runs outside the reader mutex, and read guards restore its count
// and permissions during unwinding. Invariants inside T still require RefUnwindSafe.
impl<T: RefUnwindSafe> RefUnwindSafe for Secret<T> {}

// An owned hardened handle can leave other clones observing T after a panic.
// Both inline ownership and shared observation must be unwind-safe.
impl<T: UnwindSafe + RefUnwindSafe> UnwindSafe for Secret<T> {}

/// Erases the storage for `T`, including padding, using volatile writes.
///
/// This does not run `T`'s destructor and need not leave a valid `T` behind.
///
/// # Safety
///
/// `ptr` must be non-null and permit exclusive writes to `size_of::<T>()` bytes
/// within one live allocation. Those bytes may be uninitialized. No live value
/// may subsequently be read or dropped from that storage without reinitialization.
#[inline]
unsafe fn zeroize_ptr<T>(ptr: *mut T) {
    // SAFETY: The caller guarantees that `ptr` is valid for writes of `size_of::<T>()` bytes.
    // MaybeUninit permits erasing padding without reading uninitialized bytes.
    unsafe {
        let slice = core::slice::from_raw_parts_mut(
            ptr.cast::<MaybeUninit<u8>>(),
            core::mem::size_of::<T>(),
        );
        slice.zeroize();
    }
}

/// Owns inline `T` so moving between storage variants preserves automatic cleanup.
///
/// Drop destroys the value, then erases its bytes and padding. A destructor panic
/// skips erasure. Clone creates an independent value. No OS protections apply.
pub(crate) struct InlineSecret<T>(ManuallyDrop<T>);

impl<T> InlineSecret<T> {
    /// Takes ownership of `value` and stores it inline.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(ManuallyDrop::new(value))
    }

    /// Passes a shared reference to the stored value to `f` and returns its result.
    ///
    /// The borrow of the stored value is limited to the call. The closure can
    /// still copy values or raw pointers out, or return references already stored
    /// inside `T`. Such results receive no protection from this wrapper.
    /// Shared access also permits any interior mutability provided by `T`.
    ///
    #[inline]
    pub fn access<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
        f(&self.0)
    }

    /// Moves out `T` and erases this wrapper's storage without destroying the value.
    #[inline]
    fn extract(self) -> T {
        let mut this = ManuallyDrop::new(self);
        let source = &raw mut *this.0;
        // SAFETY: We exclusively own an initialized T. ManuallyDrop prevents
        // destroying the moved-out value, and its source storage stays writable
        // until erasure completes.
        unsafe {
            let value = source.read();
            zeroize_ptr(source);
            value
        }
    }
}

impl<T> Drop for InlineSecret<T> {
    fn drop(&mut self) {
        let ptr = &raw mut *self.0;
        // SAFETY: We exclusively own an initialized T and keep its storage live
        // until erasure finishes. After destruction, zeroize_ptr accesses only
        // raw storage and does not require a valid T.
        unsafe {
            core::ptr::drop_in_place(ptr);
            zeroize_ptr(ptr);
        }
    }
}

impl<T: Clone> Clone for InlineSecret<T> {
    fn clone(&self) -> Self {
        self.access(|v| Self::new(v.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[cfg(not(all(target_os = "linux", feature = "std")))]
    #[test]
    fn test_harden_unsupported_preserves_value() {
        struct Value([u8; 32]);
        let mut secret = Secret::new(Value([42; 32]));
        assert!(matches!(secret.try_harden(), Err(HardenError::Unsupported)));
        assert!(!secret.is_hardened());
        secret.access(|value| assert_eq!(value.0, [42; 32]));
    }

    #[test]
    fn test_traits() {
        fn assert_traits<
            T: Clone
                + Debug
                + Display
                + Eq
                + Send
                + Sync
                + Unpin
                + core::panic::UnwindSafe
                + core::panic::RefUnwindSafe
                + zeroize::ZeroizeOnDrop,
        >() {
        }
        assert_traits::<Secret<[u8; 32]>>();

        // Erasure and redaction impose no requirements on the stored type.
        fn assert_unbounded<T>() {
            fn check<U: Debug + Display + zeroize::ZeroizeOnDrop>() {}
            check::<Secret<T>>();
        }
        assert_unbounded::<Cell<u8>>();

        // Thread bounds do not prevent local use of interior-mutable values.
        let secret = Secret::new(Cell::new(7));
        secret.access(|value| value.set(9));
        assert_eq!(secret.access(Cell::get), 9);
    }

    #[test]
    fn test_inline_drop_erases_padding() {
        #[repr(C)]
        struct Padded {
            first: u8,
            second: u32,
        }

        // A typed write need not initialize padding. Cleanup must handle it as
        // MaybeUninit bytes, then leave every storage byte initialized to zero.
        let mut storage = MaybeUninit::new(InlineSecret::new(Padded {
            first: 0x71,
            second: 0x12345678,
        }));
        let address = storage.as_mut_ptr();
        // SAFETY: The value is initialized and uniquely owned. The MaybeUninit
        // allocation stays live after destruction and does not drop it again.
        unsafe {
            core::ptr::drop_in_place(address);
            let erased = core::slice::from_raw_parts(
                address.cast::<u8>(),
                core::mem::size_of::<InlineSecret<Padded>>(),
            );
            assert!(erased.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn test_try_extract_non_clone() {
        // Owning a heap value detects premature destruction during extraction.
        struct Value<'a> {
            bytes: Box<[u8; 32]>,
            drops: &'a Cell<usize>,
        }

        impl Drop for Value<'_> {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }

        fn check(secret: Secret<Value<'_>>, drops: &Cell<usize>) {
            let before = drops.get();
            let value = secret.try_extract().unwrap();
            assert_eq!(*value.bytes, [42; 32]);
            assert_eq!(drops.get(), before);
            drop(value);
            assert_eq!(drops.get(), before + 1);
        }

        let drops = Cell::new(0);
        check(
            Secret::new(Value {
                bytes: Box::new([42; 32]),
                drops: &drops,
            }),
            &drops,
        );
        #[cfg(all(target_os = "linux", feature = "std", not(miri)))]
        {
            let mut secret = Secret::new(Value {
                bytes: Box::new([42; 32]),
                drops: &drops,
            });
            secret.try_harden().unwrap();
            check(secret, &drops);
        }
    }

    #[test]
    fn test_extract_or_clone() {
        #[derive(Debug)]
        struct Value<'a> {
            clones: &'a Cell<usize>,
            drops: &'a Cell<usize>,
        }

        impl Clone for Value<'_> {
            fn clone(&self) -> Self {
                self.clones.set(self.clones.get() + 1);
                Self {
                    clones: self.clones,
                    drops: self.drops,
                }
            }
        }

        impl Drop for Value<'_> {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }

        let clones = Cell::new(0);
        let drops = Cell::new(0);
        let secret = Secret::new(Value {
            clones: &clones,
            drops: &drops,
        });
        let value = secret.extract_or_clone();
        assert_eq!(clones.get(), 0);
        assert_eq!(drops.get(), 0);
        drop(value);
        assert_eq!(drops.get(), 1);

        #[cfg(all(target_os = "linux", feature = "std", not(miri)))]
        {
            let mut secret = Secret::new(Value {
                clones: &clones,
                drops: &drops,
            });
            secret.try_harden().unwrap();
            let shared = secret.clone();
            assert_eq!(clones.get(), 0);

            let secret = secret.try_extract().unwrap_err();
            assert!(secret.is_hardened());
            secret.access(|value| assert!(core::ptr::eq(value.clones, &clones)));

            let copied = secret.extract_or_clone();
            assert_eq!(clones.get(), 1);
            assert_eq!(drops.get(), 1);

            // Releasing the other handle makes the remaining value movable.
            let moved = shared.extract_or_clone();
            assert_eq!(clones.get(), 1);
            assert_eq!(drops.get(), 1);
            drop(copied);
            drop(moved);
            assert_eq!(drops.get(), 3);
        }
    }

    #[test]
    fn test_debug_redacted() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        assert_eq!(format!("{:?}", secret), "Secret([REDACTED])");
    }

    #[test]
    fn test_display_redacted() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        assert_eq!(format!("{}", secret), "[REDACTED]");
    }

    #[test]
    fn test_access() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        secret.access(|v| {
            assert_eq!(v, &[1u8, 2, 3, 4]);
        });
    }

    #[test]
    fn test_clone() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let cloned = secret.clone();
        secret.access(|a| {
            cloned.access(|b| {
                assert_eq!(a, b);
            });
        });
    }

    #[test]
    fn test_equality() {
        let s1 = Secret::new([1u8, 2, 3, 4]);
        let s2 = Secret::new([1u8, 2, 3, 4]);
        let s3 = Secret::new([5u8, 6, 7, 8]);
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_multiple_access() {
        let secret = Secret::new([42u8; 32]);

        // First access
        secret.access(|v| {
            assert_eq!(v[0], 42);
        });

        // Second access
        secret.access(|v| {
            assert_eq!(v[31], 42);
        });
    }
}
