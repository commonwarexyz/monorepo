//! Data-independent timing on AArch64.
//!
//! Cores that implement FEAT_DIT, including Apple silicon, may complete some instructions in
//! operand-dependent time unless the thread's `PSTATE.DIT` bit is set. A [`Guard`] sets the bit
//! for the duration of a secret-key operation and restores the previous state when dropped, so
//! the constant-time scalar multiplications and the scalar arithmetic around them also run in
//! data-independent time on those cores. The bit is per thread and only slows the instructions
//! it covers, so it is set only around secret computations.
//!
//! The guard is a no-op where the bit cannot be used: on other architectures, on AArch64 cores
//! without FEAT_DIT, and in `no_std` builds, which cannot detect the feature.

/// Enables data-independent timing until dropped.
#[must_use = "dropping the guard immediately restores the previous timing mode"]
pub struct Guard {
    /// Whether this guard set the bit and must clear it again. A guard that found the bit
    /// already set leaves it to whoever set it.
    clear_on_drop: bool,
}

impl Guard {
    /// Sets `PSTATE.DIT` if the CPU supports it and it is not already set.
    #[inline]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only on targets where the guard is a no-op"
    )]
    pub fn enable_if_supported() -> Self {
        let clear_on_drop = supported() && !is_set();
        if clear_on_drop {
            set(true);
        }
        Self { clear_on_drop }
    }
}

impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        if self.clear_on_drop {
            set(false);
        }
    }
}

#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn supported() -> bool {
    std::arch::is_aarch64_feature_detected!("dit")
}

// The raw encodings below avoid requiring the assembler's `dit` extension for a feature that is
// only detected at runtime. Both instructions are permitted at EL0 on cores with FEAT_DIT, touch
// no memory, and leave the condition flags unchanged.

/// Returns whether `PSTATE.DIT` is set, which `MRS X0, DIT` reports in bit 24, or `false` on
/// cores without FEAT_DIT.
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn is_set() -> bool {
    if !supported() {
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
/// [`supported`] returned `true`.
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn set(value: bool) {
    // SAFETY: a `Guard` only sets the bit after checking FEAT_DIT and only clears what it set;
    // the instruction changes only this thread's `PSTATE.DIT` bit.
    unsafe {
        if value {
            core::arch::asm!(".inst 0xd503415f", options(nomem, nostack, preserves_flags));
        } else {
            core::arch::asm!(".inst 0xd503405f", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn supported() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn is_set() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", feature = "std")))]
const fn set(_value: bool) {}

#[cfg(test)]
mod tests {
    use super::{Guard, is_set, supported};

    /// The bit is set exactly while a guard lives, a nested guard leaves it to the outer one, and
    /// the previous state comes back afterwards. Without FEAT_DIT every step is a no-op.
    #[test]
    fn guard_sets_and_restores_dit() {
        let before = is_set();
        let while_guarded = supported() || before;
        {
            let _outer = Guard::enable_if_supported();
            assert_eq!(is_set(), while_guarded);
            {
                let _inner = Guard::enable_if_supported();
                assert_eq!(is_set(), while_guarded);
            }
            assert_eq!(is_set(), while_guarded);
        }
        assert_eq!(is_set(), before);
    }
}
