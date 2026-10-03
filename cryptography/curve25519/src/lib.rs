//! Curve25519 field/group arithmetic, the Ed25519 signature scheme, and X25519 key exchange,
//! implemented natively.
//!
//! # Randomness
//!
//! Cryptographic operations that accept an RNG require a cryptographically secure and
//! unpredictable source unless documented otherwise. A weak or predictable RNG may compromise
//! security.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
// Higher stability builds can leave internal arithmetic without live callers.
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

commonware_macros::stability_mod!(BETA, mod curve);
commonware_macros::stability_mod!(BETA, pub mod batch);
commonware_macros::stability_mod!(ALPHA, pub mod key_exchange);
commonware_macros::stability_mod!(ALPHA, pub mod signing);

commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod test;
});
