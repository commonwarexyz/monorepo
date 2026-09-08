//! Secret values with explicit access and erasure on drop.
//!
//! - [Secret] supports inline and hardened storage through a single public wrapper.
//!   It starts inline and can be converted to hardened storage with [Secret::try_harden].
//!   Conversion consumes the wrapper, including on failure. Existing clones and
//!   previously exported values are unaffected.
//! - `InlineSecret<T>` is the private implementation of inline storage. Dropping
//!   the wrapper destroys `T`, then zeroizes its storage. Cloning calls `T::clone`
//!   and places the result in a separate wrapper.
//! - `HardenedSecret<T>` is the private implementation of hardened storage.
//!   It stores `T` in locked memory excluded from core dumps.
//!   The allocation is read-only during `access()` calls and inaccessible between
//!   them. Clones share the allocation, which is erased when the last owner drops.
//!   Hardened storage is available on Linux with `std`.
//!
//! All three redact `Debug` output and provide access to `T` through a closure taking `&T`.
//! Borrows into the stored value cannot escape that closure. Copies, raw pointers,
//! and references already stored inside `T` can escape. The wrappers do not erase
//! or protect values copied out by the caller. When `T: CtEq`, equality delegates
//! to `T`'s constant-time comparison.
//!
//! [Secret::try_extract] and [Secret::extract_or_clone] consume the wrapper and
//! return an ordinary, unprotected `T`. The caller becomes responsible for its
//! erasure. Moving a value out erases the source storage without destroying `T`.
//! If hardened storage is shared, `try_extract` returns the wrapper unchanged,
//! while `extract_or_clone` clones the value through `access()`.
//!
//! # Choosing the stored type
//!
//! Store sensitive bytes directly in `T`, for example in an array or a struct of
//! arrays. Protection covers the storage occupied by `T`, including its padding.
//! It does not extend to memory reached through pointers. Wrapping a `Vec`,
//! `String`, or `Box` does not make its heap allocation protected or zeroize it.
//! Any cleanup of referenced allocations depends on `T`'s own destructor.
//!
//! For hardened storage, operations on `&T` must not write to its storage, even
//! through interior mutability. The pages are read-only during access, so such
//! writes can terminate the process. `T`'s destructor must not panic, since a
//! panic can interrupt erasure of inline storage, including during a failed
//! hardening attempt. Callers must choose types that meet these requirements.
//!
//! # Limits of erasure
//!
//! Erasure covers the wrapper's current storage. Moving a value can leave bytes
//! at earlier locations, and computations can leave copies in registers or on
//! the stack. Those copies are outside the wrapper's control. Explicitly manage
//! exported sensitive values, for example with [zeroize::Zeroizing]. Cleanup
//! also requires the wrapper to be dropped, so leaking it or terminating the
//! process without running destructors prevents erasure by the wrapper.
//!
//! # Hardened storage
//!
//! Hardening requires Linux with `std` and a kernel supporting `MADV_WIPEONFORK`
//! (Linux 4.14 or later). Construction establishes all required protections before
//! storing sensitive bytes in the allocation:
//!
//! - [mlock](https://man7.org/linux/man-pages/man2/mlock.2.html) keeps data pages
//!   resident, preventing them from being swapped out.
//! - [MADV_DONTDUMP](https://man7.org/linux/man-pages/man2/madvise.2.html) excludes
//!   them from kernel-generated core dumps.
//! - `mprotect` grants read-only access during the callback and revokes it afterward.
//!   Initialization, extraction, and destruction have write access.
//! - Guard pages surround the data region. A random canary before the value detects
//!   writes that change it when the canary is next checked.
//!
//! Each allocation locks at least one data page and reserves two virtual guard
//! pages, even for a zero-sized value. Clones share this allocation. `access()` calls
//! synchronize a reader count and change permissions when the first call begins
//! and the last ends. The allocation stays readable throughout overlapping calls,
//! including those through other clones.
//!
//! Dropping the last owner destroys the value, zeroizes the entire data region, and
//! releases the mapping. Erasure also runs if that destructor unwinds. Failures
//! to change permissions after construction, detected canary corruption, or
//! failures to restore write access or release memory during cleanup abort the
//! process. Aborting does not run destructors or guarantee erasure.
//!
//! During an `access()` call, the pages are readable throughout the process. Hardening
//! does not defend against arbitrary code execution, privileged memory
//! inspection, or hibernation images.
//!
//! # Forking with hardened storage
//!
//! `MADV_WIPEONFORK` replaces the child's data pages with zeroes. Accessing or moving
//! out an inherited hardened value aborts before touching its reader mutex or
//! reading `T`. The final release in the child only unmaps its copy, without calling
//! `T`'s destructor on the wiped bytes. The parent's allocation is unaffected.
//!
//! A caller using an unsafe fork API during an `access()` call must ensure that the child
//! never uses references into the inherited allocation. Its bytes have been wiped
//! and may no longer represent a valid `T`. Returning through an inherited
//! read guard also aborts in the child. These restrictions do not replace
//! the fork API's own safety requirements.

#[cfg(all(target_os = "linux", feature = "std"))]
use crate::hardened_secret::HardenedSecret;
use core::{
    fmt::{Debug, Display, Formatter},
    mem::{ManuallyDrop, MaybeUninit},
};
use ctutils::CtEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Failure to construct hardened secret storage.
///
/// These errors report failures during setup. Once hardened storage has been
/// constructed, failures to change its memory permissions abort the process.
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
    /// Allocation, canary generation, or a required memory protection failed.
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
    /// or detected canary corruption abort the process.
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
    /// Permission failures, canary corruption, or moving out an inherited fork-child
    /// value abort the process, as described in the [module documentation](self).
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
    /// is released. Permission failures, canary corruption, and cleanup failures
    /// abort as described in the [module documentation](self).
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
    /// including when `T`'s alignment exceeds the system page size. Mapping,
    /// canary generation, and memory-protection failures return an operating-system
    /// error. Locking is subject to the process's `RLIMIT_MEMLOCK` allowance.
    /// An error consumes and drops the input instead of returning it to the caller.
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
    /// let secret = Secret::new([42u8; 32]).try_harden()?;
    /// assert!(secret.is_hardened());
    /// secret.access(|bytes| assert_eq!(bytes[0], 42));
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_harden(self) -> Result<Self, HardenError> {
        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            match self.storage {
                Storage::Inline(value) => HardenedSecret::try_from_inline(value).map(|value| Self {
                    storage: Storage::Hardened(value),
                }),
                Storage::Hardened(_) => Ok(self),
            }
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

/// A value stored inline with explicit access and erasure on drop.
///
/// The wrapper adds no allocation or OS memory protections. It calls `T`'s
/// destructor, then zeroizes the bytes occupied by `T`, including padding.
/// `Debug` prints `InlineSecret([REDACTED])` and `Display` prints `[REDACTED]`.
/// Cloning calls `T::clone` and stores the result in a separate wrapper.
///
/// Store sensitive bytes directly in `T`. Referenced allocations are not erased
/// by this wrapper. `T`'s destructor must not panic, since that would skip the
/// subsequent erasure. Earlier copies and locations left behind by moves are
/// also outside its control. See the [module documentation](self) for details.
///
pub(crate) struct InlineSecret<T>(ManuallyDrop<T>);

impl<T> InlineSecret<T> {
    /// Transfers `T` into caller-owned storage and erases this consumed wrapper.
    ///
    /// Does not run `T`'s destructor. Locations left by earlier moves of the wrapper
    /// are outside this operation's control.
    ///
    /// # Safety
    ///
    /// `destination` must be non-null, aligned for `T`, and writable for
    /// `size_of::<T>()` bytes. Non-nullness and alignment also apply to zero-sized
    /// types. The destination must accept a new `T` without dropping its previous
    /// contents. It must not overlap the source or be accessed through any other
    /// pointer or reference during the transfer. The caller takes ownership of
    /// the initialized `T` and must arrange its destruction.
    #[cfg(all(target_os = "linux", feature = "std"))]
    pub(crate) unsafe fn move_into(self, destination: *mut T) {
        let mut value = ManuallyDrop::new(self);
        let source = &raw mut *value.0;
        // SAFETY: The caller supplies valid, disjoint storage. The source stays
        // at its original address until wiped and is never moved or dropped again.
        unsafe {
            core::ptr::copy_nonoverlapping(source, destination, 1);
            zeroize_ptr(source);
        }
    }

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

impl<T> Debug for InlineSecret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("InlineSecret([REDACTED])")
    }
}

impl<T> Display for InlineSecret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> ZeroizeOnDrop for InlineSecret<T> {}

impl<T: Clone> Clone for InlineSecret<T> {
    fn clone(&self) -> Self {
        self.access(|v| Self::new(v.clone()))
    }
}

impl<T: CtEq> PartialEq for InlineSecret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.access(|a| other.access(|b| a.ct_eq(b).into()))
    }
}

impl<T: CtEq> Eq for InlineSecret<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

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
        #[cfg(all(target_os = "linux", feature = "std"))]
        check(
            Secret::new(Value {
                bytes: Box::new([42; 32]),
                drops: &drops,
            })
            .try_harden()
            .unwrap(),
            &drops,
        );
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

        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            let secret = Secret::new(Value {
                clones: &clones,
                drops: &drops,
            })
            .try_harden()
            .unwrap();
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
