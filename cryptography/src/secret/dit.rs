//! Data-independent timing for computations on secret data.
//!
//! Cores that implement FEAT_DIT, including Apple silicon, may complete some instructions in
//! operand-dependent time unless the thread's `PSTATE.DIT` bit is set. A [`Guard`] sets the bit
//! for its lifetime and restores the previous state when dropped. The bit is per thread and only
//! slows the instructions it covers, so it is set only around secret computations. Other
//! architectures expose no user-space equivalent: Intel's data operand independent timing mode
//! is an operating-system control. The guard is a no-op where the bit cannot be used: on other
//! architectures, on AArch64 cores without FEAT_DIT, and in `no_std` builds, which cannot detect
//! the feature.
//!
//! The guard does not make variable-time code constant-time: the computation it covers must
//! already perform the same sequence of operations and memory accesses for every secret. Hold
//! it in a local for the whole computation, in the thread that performs it:
//!
//! ```
//! use commonware_cryptography::secret::dit::Guard;
//!
//! fn derive(secret: &[u8; 32]) -> u8 {
//!     let _dit = Guard::begin();
//!     secret.iter().fold(0, |acc, byte| acc ^ byte)
//! }
//!
//! assert_eq!(derive(&[0x5a; 32]), 0);
//! ```
//!
//! Guards nest, and must be dropped in the reverse order of their creation, as locals are. A
//! guard is bound to the thread that created it, so it cannot be held across an `await` in a
//! future that moves between threads.

/// Enables data-independent timing on the current thread until dropped.
#[must_use = "dropping the guard immediately ends data-independent timing"]
pub struct Guard {
    /// Whether this guard set `PSTATE.DIT` and must clear it again. A guard that found the bit
    /// already set leaves it to whoever set it, so guards nest.
    clear_on_drop: bool,
    /// Pins the guard to its thread: the bit it restores on drop belongs to that thread alone.
    thread: core::marker::PhantomData<*const ()>,
}

impl Guard {
    /// Begins data-independent timing on the current thread.
    #[inline]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only on targets where the guard is a no-op"
    )]
    pub fn begin() -> Self {
        let clear_on_drop = dit_supported() && !dit_is_set();
        if clear_on_drop {
            set_dit(true);
        }
        Self {
            clear_on_drop,
            thread: core::marker::PhantomData,
        }
    }
}

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        if self.clear_on_drop {
            set_dit(false);
        }
    }
}

#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn dit_supported() -> bool {
    std::arch::is_aarch64_feature_detected!("dit")
}

// The raw encodings below avoid requiring the assembler's `dit` extension for a feature that is
// only detected at runtime. Both instructions are permitted at EL0 on cores with FEAT_DIT, touch
// no memory, and leave the condition flags unchanged.

/// Returns whether `PSTATE.DIT` is set, which `MRS X0, DIT` reports in bit 24, or `false` on
/// cores without FEAT_DIT.
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn dit_is_set() -> bool {
    if !dit_supported() {
        return false;
    }
    let pstate: u64;
    // SAFETY: FEAT_DIT was checked above; the instruction only writes `x0`.
    unsafe {
        core::arch::asm!(
            ".inst 0xd53b42a0",
            out("x0") pstate,
            options(nomem, nostack, preserves_flags)
        );
    }
    pstate & (1 << 24) != 0
}

/// Sets `PSTATE.DIT` with `MSR DIT, #1` or clears it with `MSR DIT, #0`. Only called after
/// [`dit_supported`] returned `true`.
///
/// A write to `PSTATE` takes effect for every later instruction in program order, but an
/// instruction barrier also keeps the computation's instructions from running speculatively
/// before the bit is set, and from still running when it is cleared. Declaring memory access
/// makes the write a compiler barrier too, so no load or store of the computation moves across
/// it.
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn set_dit(value: bool) {
    // SAFETY: a `Guard` only sets the bit after checking FEAT_DIT and only clears what it set;
    // the instructions change only this thread's `PSTATE.DIT` bit.
    unsafe {
        if value {
            core::arch::asm!(".inst 0xd503415f", "isb", options(nostack, preserves_flags));
        } else {
            core::arch::asm!("isb", ".inst 0xd503405f", options(nostack, preserves_flags));
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn dit_supported() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn dit_is_set() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn set_dit(_value: bool) {}

#[cfg(test)]
mod tests {
    use super::{Guard, dit_is_set, dit_supported};

    /// The bit is set exactly while a guard lives, a nested guard leaves it to the outer one, and
    /// the previous state comes back afterwards. Without FEAT_DIT every step is a no-op.
    #[test]
    fn guard_sets_and_restores_dit() {
        let before = dit_is_set();
        let while_guarded = dit_supported() || before;
        {
            let _outer = Guard::begin();
            assert_eq!(dit_is_set(), while_guarded);
            {
                let _inner = Guard::begin();
                assert_eq!(dit_is_set(), while_guarded);
            }
            assert_eq!(dit_is_set(), while_guarded);
        }
        assert_eq!(dit_is_set(), before);
    }
}
