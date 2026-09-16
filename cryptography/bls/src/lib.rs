//! Native BLS12-381 and Banderwagon arithmetic, pairings, and BLS signatures.
//!
//! Both curve families use the shared [VROOM](commonware_cryptography_vroom) field core,
//! with portable and AVX-512 IFMA kernels. Banderwagon coordinates use the
//! BLS12-381 scalar field; Banderwagon scalars have their own distinct modulus.
//!
//! # Randomness
//!
//! Cryptographic operations that accept an RNG require a cryptographically secure and
//! unpredictable source unless documented otherwise. A weak or predictable RNG may compromise
//! security.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_mod!(ALPHA, pub mod bls12381);
commonware_macros::stability_mod!(ALPHA, pub mod banderwagon);
commonware_macros::stability_mod!(ALPHA, mod hash);

commonware_macros::stability_scope!(ALPHA {
    extern crate alloc;

    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod test;
});
