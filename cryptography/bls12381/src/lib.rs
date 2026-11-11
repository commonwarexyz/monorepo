//! BLS12-381 cryptography.
//!
//! [`G1`], [`G2`], and their scalar field [`Scalar`] implement the `commonware-math` algebra
//! traits, and [`pairing`], [`pairings`], and [`multi_pairing`] map them into the target group
//! [`GT`].
//!
//! [`G1`] and [`G2`] hold canonical projective coordinates. Each operation runs as one SIMD
//! kernel on the best available backend. Operations over slices of elements ([`G1::sum`],
//! [`G1::mul_each`], [`Space::msm`](commonware_math::algebra::Space::msm), and
//! [`pairings`]) hold one element per lane, so they fill every lane and amortize the
//! conversions at the kernel boundary that single operations pay every time.
//!
//! Multiplications by scalars run in constant time, except
//! [`Space::msm`](commonware_math::algebra::Space::msm), which runs in variable time because its
//! scalars are public in every intended use (Lagrange coefficients in threshold recovery and
//! random weights in batch verification).
//!
//! Elements arise only from the generators through the group operations, so every element lies
//! in the subgroup of prime order `r`.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(ALPHA {
    extern crate alloc;
});

commonware_macros::stability_mod!(ALPHA, mod core);
commonware_macros::stability_mod!(ALPHA, mod group);
commonware_macros::stability_mod!(ALPHA, mod montgomery);

commonware_macros::stability_scope!(ALPHA {
    #[cfg(feature = "fuzz")]
    pub mod fuzz;
});

commonware_macros::stability_scope!(ALPHA {
    pub use group::{G1, G2, GT, Scalar, multi_pairing, pairing, pairings};
});
