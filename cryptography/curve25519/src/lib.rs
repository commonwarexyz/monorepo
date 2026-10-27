//! Curve25519 field/group arithmetic, the Ed25519 signature scheme, and X25519 key exchange,
//! implemented natively.
//!
//! # Randomness
//!
//! Cryptographic operations that accept an RNG require a cryptographically secure and
//! unpredictable source unless documented otherwise. A weak or predictable RNG may compromise
//! security. Pass the RNG by mutable reference: an RNG moved into a call is dropped without
//! zeroization and may keep a copy of the secret bytes it produced.
//!
//! # Zeroization
//!
//! Secret key types zeroize themselves when dropped, and the signing and key-exchange code keeps
//! the secrets it names, such as seeds, nonces, and products with the private scalar, in buffers
//! that are zeroized as well.
//!
//! Key derivation, signing, and key exchange also run out of line and overwrite a fixed budget of
//! stack below their own frames before returning. In optimized builds on the tested targets that
//! budget covers every frame those computations use, so the intermediate values of the field and
//! scalar arithmetic and the temporaries the compiler spills during them do not outlive the call.
//!
//! The clearing is best effort: how much stack a computation uses depends on the target, the
//! optimization level, and the compiler, and unoptimized builds use far more than the budget.
//! Registers, and copies of secret inputs that callers hold, are never cleared.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
// Every public item here is currently ALPHA, so the `commonware_stability_BETA`+ builds (which
// compile everything out) legitimately have no live callers of the internal modules below.
#![cfg_attr(
    any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    ),
    allow(dead_code, unused_imports)
)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Bytes of stack that key derivation, signing, and key exchange clear with
/// [`zeroize::zeroize_stack`] before returning.
///
/// Each of those computations runs in an `#[inline(never)]` function, so once it returns its
/// frames lie in the dead stack below the caller, where the scrub reaches them. Signing reaches
/// the deepest of the three, under 3 KiB in release builds on the tested targets, so this leaves
/// a margin at the cost of one 4 KiB write per call. The release-mode tests check the budget on
/// the backend they run on. Unoptimized builds exceed it many times over.
const STACK_SCRUB_BYTES: usize = 4096;

commonware_macros::stability_mod!(ALPHA, mod curve);
commonware_macros::stability_mod!(ALPHA, pub mod key_exchange);
commonware_macros::stability_mod!(ALPHA, pub mod signing);

commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod test;
});
