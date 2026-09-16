//! Prime-field arithmetic using VROOM's rotated residue-number-system representation.
//!
//! Supported moduli share portable scalar and AVX-512 IFMA kernels. Each modulus
//! supplies sealed, precomputed parameters with a bounded integer representation.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_mod!(ALPHA, mod field);
commonware_macros::stability_mod!(ALPHA, mod parameters);
commonware_macros::stability_mod!(ALPHA, pub mod rns);
commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;

    pub use field::{Element, Modulus, SignedTerm};
    pub use parameters::{BanderScalar, Bls12381, BlsScalar, Curve25519};
    pub use rns::{Backend, WithBackend, with_backend};
});
