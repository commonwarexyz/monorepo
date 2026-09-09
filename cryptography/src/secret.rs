//! Secret values with scoped access and erasure on drop.
//!
//! [Secret] redacts its `Debug` and `Display` output, lends its value only to
//! closures passed to [Secret::access], and erases its storage when the last
//! owner is dropped. The value lives inline by default. On Linux,
//! [Secret::try_harden] moves it into locked, non-dumpable memory that is
//! unreadable between accesses.
//!
//! # What is protected
//!
//! Both storage modes cover only `T`'s own storage, including padding. Anything
//! `T` reaches through a pointer, such as the contents of a `Vec`, `String`, or
//! `Box`, is ordinary memory that the wrapper neither locks, hides, nor erases,
//! and its cleanup depends on `T`'s destructor. Store sensitive bytes directly
//! in `T` as arrays or structs of arrays, and keep public derived values such as
//! cached public keys outside it.
//!
//! Only the retained value is covered. Moves, registers, stacks, serialized
//! exports, and cryptographic scratch memory can hold other copies, and the
//! location a value was moved in from is not erased. Whatever a closure returns
//! from [Secret::access], whether a copy, a raw pointer, or a reference already
//! stored inside `T`, receives no protection, and the closure can print the
//! value it is given. Leaks and termination without cleanup also prevent erasure.
//!
//! Inline storage adds only redaction, scoped access, and erasure on drop.
//! Hardening also reduces the exposure of the idle value to swap, kernel core
//! dumps, fork children, and memory-disclosure bugs elsewhere in the process:
//!
//! | Measure | Protection and limits |
//! |---|---|
//! | [mlock](https://man7.org/linux/man-pages/man2/mlock.2.html) | Keeps the data pages out of swap. Earlier copies and hibernation images are unaffected. |
//! | [MADV_DONTDUMP](https://man7.org/linux/man-pages/man2/madvise.2.html) | Excludes the data pages from kernel core dumps. Stack, heap, and computation copies remain. |
//! | [MADV_WIPEONFORK](https://man7.org/linux/man-pages/man2/madvise.2.html) | Zeroes the data pages in fork children. |
//! | [mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html) | Blocks ordinary loads while idle and permits read-only access during callbacks. |
//! | Guard pages | Fault accesses that cross either boundary of the data region. Underruns into unused data bytes and arbitrary pointer jumps are not caught. |
//! | Erasure and unmapping | Clear the retained storage during cleanup, within the limits described below. |
//!
//! None of this defends against arbitrary code execution, speculative-execution
//! attacks, or debugger-style inspection. Page permissions are not the `ptrace`
//! access-control boundary. Whether another same-user process can read this
//! one's memory depends on credentials, dumpability, capabilities, and security
//! policy. See [Linux ptrace access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html).
//!
//! # Inline and hardened storage
//!
//! ```text
//! Inline (every platform)               Hardened (Linux)
//!
//! Secret A     Secret B (clone)         Secret A     Secret B (clone)
//! +--------+   +----------+             +--------+   +--------+
//! | T      |   | T::clone |             | handle |   | handle |
//! +--------+   +----------+             +---+----+   +---+----+
//!                                           |            |
//! Each wrapper owns and                     +-----+------+
//! erases its own value                            v
//!                                       +---------------------+
//!                                       | protected data      |
//!                                       | pages holding one T |
//!                                       +---------------------+
//!                                       erased when the last
//!                                       handle is released
//! ```
//!
//! Inline storage holds `T` in the wrapper. Cloning calls `T::clone`, access is
//! a plain borrow, and each wrapper destroys and erases its own value.
//!
//! Hardened clones are handles to one shared allocation. Cloning copies nothing
//! and changes no permissions. The first active callback makes the data pages
//! readable, and they stay readable to every thread in the process until the
//! last nested or concurrent callback through any handle ends. Callbacks must
//! not write to the value, even through interior mutability, because the pages
//! are mapped read-only. The last handle destroys `T`, then erases and unmaps
//! the pages. Dropping a shared handle erases nothing.
//!
//! Hardening is all or nothing. It requires `MADV_WIPEONFORK`, introduced in
//! Linux 4.14, and may fail under the process's locked-memory allowance or
//! syscall policy. On error, including on unsupported platforms, the inline
//! value and its storage are unchanged. Hardening an already hardened value
//! keeps its allocation. Earlier inline clones and exported bytes are never
//! affected.
//!
//! [Secret::try_extract] moves `T` out of uniquely owned storage without
//! cloning, erases the source, and releases any allocation. Shared hardened
//! storage returns `Err(self)` without reading `T` or changing permissions.
//! [Secret::extract_or_clone] clones through a callback instead. Both hand the
//! caller an unprotected value whose erasure is the caller's responsibility.
//!
//! # Failure modes
//!
//! [Secret::try_harden] is the only fallible operation. It returns [HardenError]
//! when setting up or sealing the allocation fails and cleanup succeeds, and it
//! leaves the inline value in place. Cleanup that cannot restore write access
//! or release mappings aborts the process, as do failures once a value is
//! hardened: a failed permission change or reader-count overflow. Abort runs no
//! destructors and guarantees no erasure.
//!
//! Panics unwind normally. Access guards restore the reader count and
//! permissions, and the pages are still erased and unmapped when `T`'s
//! destructor unwinds, provided cleanup succeeds. A panicking inline
//! destructor skips erasure of that value.
//!
//! Hardened data pages are zeroed in fork children, so the hardened value does
//! not cross `fork`. Inline values are copied into the child like any other
//! memory. Nothing detects the child, and an inherited hardened handle must not
//! be accessed or dropped there: its pages hold zeros, and it shares the
//! parent's reader mutex state as of the fork. A child that goes on to run
//! destructors, rather than calling `exec` or `_exit`, must forget its handles
//! first. The parent's allocation is unaffected, and new allocations in the
//! child work normally.
//!
//! # Costs
//!
//! Each hardened allocation locks `round_up(max(size_of::<T>(), 1), page_size)`
//! bytes and reserves two guard pages of address space, plus kernel
//! bookkeeping. Locked bytes count against
//! `RLIMIT_MEMLOCK`, so many small secrets may exhaust a small allowance
//! quickly. The wrapper is an enum over both storage modes, so a hardened
//! wrapper still occupies at least `size_of::<T>()` bytes.
//!
//! Hardened access takes a mutex and changes page permissions on the first
//! entry and last exit of an access interval. Inline access costs nothing extra.
//!
//! # Trait bounds
//!
//! Bounds are the same on every platform:
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
//! Hardened handles share ownership, so sending or sharing a wrapper across
//! threads requires both thread traits, and an owned wrapper can leave other
//! handles observing `T` after a caught panic, so owned unwind safety also
//! requires `RefUnwindSafe`. Values that fail these bounds remain usable on one
//! thread. Equality is constant time through `CtEq`, and erasure needs no
//! zeroization trait on `T`.

#[cfg(all(target_os = "linux", feature = "std"))]
use crate::hardened_secret::HardenedSecret;
use cfg_if::cfg_if;
use core::{
    fmt::{Debug, Display, Formatter},
    mem::{ManuallyDrop, MaybeUninit},
    panic::{RefUnwindSafe, UnwindSafe},
};
use ctutils::CtEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Failure to move a value into hardened storage.
///
/// `Layout` and `System` exist only on Linux. Failures after hardening abort the
/// process instead of returning an error.
#[derive(Debug, Error)]
pub enum HardenError {
    /// Hardening was requested on an unsupported system.
    #[error("hardening is not supported on this system")]
    Unsupported,
    /// No valid mapping layout exists for the value.
    ///
    /// The page size or `T`'s alignment is unsupported, or the mapping size
    /// overflows.
    #[cfg(all(target_os = "linux", feature = "std"))]
    #[error("unsupported protected allocation layout")]
    Layout,
    /// Allocation or a required memory protection failed.
    #[cfg(all(target_os = "linux", feature = "std"))]
    #[error("{operation}: {source}")]
    System {
        /// The failed call: `mmap`, `mprotect`, `madvise(MADV_DONTDUMP)`,
        /// `madvise(MADV_WIPEONFORK)`, or `mlock`.
        operation: &'static str,
        /// The error it reported.
        #[source]
        source: std::io::Error,
    },
}

/// A secret stored inline or in protected memory.
///
/// `Debug` prints `Secret([REDACTED])` and `Display` prints `[REDACTED]`. The
/// value is reachable only through [Self::access] and the extraction methods.
/// [Self::new] stores it inline, and on Linux [Self::try_harden] moves it into
/// protected memory. Clones of an inline value each own a copy. Clones of a
/// hardened value share its single allocation.
///
/// Protection covers `T`'s own bytes only. Memory behind pointers inside `T`,
/// copies made outside the wrapper, and values inherited by fork children are
/// outside it. The [module documentation](self) states the full contract,
/// including failure modes, costs, and trait bounds.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{HardenError, Hasher, Secret, Sha256};
/// use zeroize::Zeroizing;
///
/// # fn main() -> Result<(), HardenError> {
/// let mut secret = Secret::new([42u8; 32]);
/// match secret.try_harden() {
///     Ok(()) => assert!(secret.is_hardened()),
///     // Unsupported platforms keep the inline value.
///     Err(HardenError::Unsupported) => assert!(!secret.is_hardened()),
///     Err(error) => return Err(error),
/// }
///
/// // Use the value inside the callback. Equality on the wrapper is constant time.
/// let digest = secret.access(|key| Sha256::hash(&[key]));
/// assert_eq!(secret, Secret::new([42u8; 32]));
///
/// // Extracted values leave the wrapper. Erase them separately.
/// let key = Zeroizing::new(secret.extract_or_clone());
/// assert_eq!(Sha256::hash(&[key.as_slice()]), digest);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Secret<T> {
    storage: Storage<T>,
}

/// Storage mode, private so that values are reached only through `Secret`'s methods.
#[derive(Clone)]
enum Storage<T> {
    /// The value itself, without OS memory protections.
    Inline(InlineSecret<T>),
    /// A handle to shared, protected storage.
    #[cfg(all(target_os = "linux", feature = "std"))]
    Hardened(HardenedSecret<T>),
}

impl<T> Secret<T> {
    /// Stores `value` inline.
    ///
    /// The location `value` is moved in from is not erased.
    pub const fn new(value: T) -> Self {
        Self {
            storage: Storage::Inline(InlineSecret::new(value)),
        }
    }

    /// Returns whether the value is in hardened storage. Always `false` outside Linux.
    #[inline]
    pub const fn is_hardened(&self) -> bool {
        match &self.storage {
            Storage::Inline(_) => false,
            #[cfg(all(target_os = "linux", feature = "std"))]
            Storage::Hardened(_) => true,
        }
    }

    /// Lends the stored value to `f`.
    ///
    /// Borrows into the value cannot escape the closure. Copies, raw pointers,
    /// and references already stored inside `T` can, and receive no protection.
    /// Hardened data pages stay readable until the last nested or concurrent
    /// call through any handle ends. `f` must not write through interior
    /// mutability: inline storage tolerates it, but hardened pages are read-only,
    /// the write is fatal, and whether a value is hardened is decided at runtime.
    ///
    /// # Panics
    ///
    /// A panic from `f` propagates after the access interval is closed. A failed
    /// permission change aborts the process.
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
    /// The source storage is erased without running `T`'s destructor, and a
    /// hardened allocation is released. The returned value is unprotected, and
    /// its erasure is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns `Err(self)` unchanged when another handle shares the hardened
    /// allocation. Nothing is read and no permissions change. Use
    /// [Self::extract_or_clone] to clone in that case.
    ///
    /// # Examples
    ///
    /// Extraction does not require `Clone`:
    ///
    /// ```
    /// use commonware_cryptography::Secret;
    /// use ctutils::CtEq;
    ///
    /// struct Value([u8; 32]);
    /// let secret = Secret::new(Value([42; 32]));
    /// let value = secret.try_extract().unwrap();
    /// assert!(bool::from(value.0.ct_eq(&[42; 32])));
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

    /// Consumes the wrapper, moving out `T` when uniquely owned and cloning it
    /// otherwise.
    ///
    /// Uniquely owned storage follows [Self::try_extract]. Shared hardened
    /// storage clones `T` through [Self::access] and releases this handle,
    /// leaving the others intact. The returned value is unprotected, and its
    /// erasure is the caller's responsibility.
    ///
    /// # Examples
    ///
    /// Use [zeroize::Zeroizing] to erase the extracted bytes on drop:
    ///
    /// ```
    /// use commonware_cryptography::Secret;
    /// use ctutils::CtEq;
    /// use zeroize::Zeroizing;
    ///
    /// let secret = Secret::new([42u8; 32]);
    /// let bytes = Zeroizing::new(secret.extract_or_clone());
    /// assert!(bool::from(bytes.ct_eq(&[42; 32])));
    /// ```
    pub fn extract_or_clone(self) -> T
    where
        T: Clone,
    {
        self.try_extract()
            .unwrap_or_else(|secret| secret.access(Clone::clone))
    }

    /// Moves an inline value into hardened storage.
    ///
    /// An already hardened value is left as is. Other wrappers, including
    /// earlier inline clones, are unaffected.
    ///
    /// Only `T`'s own bytes move into protected memory, and protection covers
    /// the retained value rather than copies made while computing with it. Fork
    /// children inherit zeroed pages and must not access or drop the value. See
    /// the [module documentation](self) for the full contract.
    ///
    /// # Errors
    ///
    /// Returns [HardenError::Unsupported] outside Linux, `HardenError::Layout`
    /// when `T`'s alignment exceeds the page size or no valid mapping size
    /// exists, and `HardenError::System` when a mapping or protection call
    /// fails, including `mlock` beyond the `RLIMIT_MEMLOCK` allowance. On error
    /// the value and its storage are unchanged.
    #[allow(clippy::missing_const_for_fn)]
    pub fn try_harden(&mut self) -> Result<(), HardenError> {
        cfg_if! {
            if #[cfg(all(target_os = "linux", feature = "std"))] {
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
            } else {
                Err(HardenError::Unsupported)
            }
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

/// Compares in constant time through `CtEq`. Both operands are accessed, so
/// hardened pages are readable for the duration.
impl<T: CtEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.access(|a| other.access(|b| a.ct_eq(b).into()))
    }
}

impl<T: CtEq> Eq for Secret<T> {}

/// Erasure of `T`'s own storage when the last owner drops, without requiring a
/// zeroization trait on `T`. Dropping a shared hardened handle erases nothing,
/// and a panicking inline destructor skips erasure of that value.
impl<T> ZeroizeOnDrop for Secret<T> {}

// SAFETY: Inline ownership can move across threads when T is Send. Hardened
// handles share ownership, so T must also be Sync even when moving one handle.
unsafe impl<T: Send + Sync> Send for Secret<T> {}

// SAFETY: Inline shared access requires T: Sync. Hardened handles may outlive
// each other on different threads, so transferring final ownership also needs Send.
unsafe impl<T: Send + Sync> Sync for Secret<T> {}

/// Access guards restore the reader count and permissions during unwinding.
impl<T: RefUnwindSafe> RefUnwindSafe for Secret<T> {}

/// An owned hardened handle can leave other handles observing `T` after a
/// caught panic, so owned unwind safety also requires `T: RefUnwindSafe`.
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

/// Owns an inline `T` so that both storage modes share automatic cleanup.
///
/// Drop destroys the value, then erases its bytes and padding. A destructor
/// panic skips erasure. Clone creates an independent value, and no OS
/// protections apply. Holding `T` directly also makes the wrapper inherit its
/// pinning requirement.
pub(crate) struct InlineSecret<T>(ManuallyDrop<T>);

impl<T> InlineSecret<T> {
    /// Stores `value` inline.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(ManuallyDrop::new(value))
    }

    /// Lends the stored value to `f`.
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

        // Payload traits that the compile-fail examples on the trait impls rely on.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_unwind_safe<T: core::panic::UnwindSafe>() {}
        fn assert_ref_unwind_safe<T: core::panic::RefUnwindSafe>() {}
        assert_send::<Cell<u8>>();
        assert_sync::<std::sync::MutexGuard<'static, ()>>();
        assert_unwind_safe::<Box<Cell<u8>>>();
        assert_ref_unwind_safe::<&'static mut ()>();
        assert_ref_unwind_safe::<Secret<&'static mut ()>>();

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
