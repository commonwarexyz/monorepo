//! Curve25519 field/group arithmetic, the Ed25519 signature scheme, and X25519 key exchange,
//! implemented natively.
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

commonware_macros::stability_mod!(ALPHA, mod curve);
commonware_macros::stability_mod!(ALPHA, pub mod key_exchange);
commonware_macros::stability_mod!(ALPHA, pub mod signing);

commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
});
