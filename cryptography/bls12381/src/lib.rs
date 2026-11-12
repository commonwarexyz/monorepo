//! BLS12-381 cryptography: the groups [`G1`] and [`G2`], their scalar field [`Scalar`], and
//! the pairing into the target group [`GT`].
//!
//! # Usage
//!
//! Operators need no imports and take their right operand by reference: `a + &b`, `a - &b`, and
//! `-a` in [`G1`], [`G2`], and [`Scalar`]; `p * &k` for an element `p` of [`G1`] or [`G2`] and
//! a [`Scalar`] `k`; `a * &b` in [`Scalar`] and [`GT`]; and `==`. The other operations are
//! methods of the algebra traits of [`commonware_math::algebra`]; import the traits whose methods
//! you call:
//!
//! - [`G1`] and [`G2`]: [`CryptoGroup::generator`], [`Additive::zero`], [`Additive::double`],
//!   [`Additive::scale`], and [`Space::msm`].
//! - [`Scalar`]: [`Field::inv`], [`Ring::exp`], [`Multiplicative::square`], [`FieldNTT`] for
//!   roots of unity, and [`Random::random`] for sampling. The inherent [`Scalar::from_bytes`]
//!   and [`Scalar::to_bytes`] convert the canonical big-endian encoding, as do the traits of
//!   `commonware-codec`.
//! - [`GT`]: [`Multiplicative::square`]. [`GT::ONE`] is the identity.
//!
//! Operations over slices cost less per element than the same operation repeated on single
//! elements, so prefer them when the inputs are available together:
//!
//! - [`G1::sum`] and [`G2::sum`] add many elements, as when aggregating keys or signatures.
//! - [`G1::mul_each`] and [`G2::mul_each`] multiply each element by its own scalar.
//! - [`Space::msm`] returns the sum of the elements times their scalars, as in threshold recovery
//!   or batch verification. Its strategy decides whether it runs on the calling thread
//!   ([`Sequential`](commonware_parallel::Sequential)) or splits the work into batches of at
//!   least 256 elements that run in parallel (`Rayon`, with the `std` feature of
//!   `commonware-parallel`).
//!
//! Three functions compute pairings:
//!
//! - [`multi_pairing`] returns the product of the pairings of several pairs with one final
//!   exponentiation, so it costs less than multiplying separate pairings. Use it for
//!   verification equations: check `e(a, b) = e(c, d)` as `multi_pairing(&[(a, b), (-c, d)])`
//!   equal to [`GT::ONE`].
//! - [`pairings`] computes the pairings of independent pairs, as when verifying many signatures
//!   separately, at less cost per pair than [`pairing`].
//! - [`pairing`] returns a single pairing.
//!
//! # Guarantees
//!
//! Elements of [`G1`], [`G2`], and [`GT`] arise only from the generators through the group
//! operations and pairings, so every element lies in the subgroup of prime order `r`. The crate
//! does not decode elements of [`G1`] or [`G2`] from bytes.
//!
//! Multiplication of an element by a scalar (`*`, [`Additive::scale`], and `mul_each`) runs
//! in time independent of the scalar's value, as does arithmetic in [`Scalar`] except
//! [`Ring::exp`] and [`Additive::scale`] on a [`Scalar`], whose running time depends on the
//! exponent or multiplier. [`Space::msm`] runs in variable time: its running time and memory
//! accesses depend on the scalars, which must therefore be public, as Lagrange coefficients in
//! threshold recovery and random weights in batch verification are. The pairing functions skip
//! pairs that contain an identity element, so their running time depends on which inputs are the
//! identity.
//!
//! # Example
//!
//! ```
//! use commonware_cryptography_bls12381::{G1, G2, GT, Scalar, multi_pairing, pairing};
//! use commonware_math::algebra::{CryptoGroup, Space};
//! use commonware_parallel::Sequential;
//!
//! // A public key in G1 and a signature in G2 on a message point `h`.
//! let secret = Scalar::from_u64(42);
//! let public = G1::generator() * &secret;
//! let h = G2::generator() * &Scalar::from_u64(7);
//! let signature = h * &secret;
//!
//! // Check e(public, h) = e(generator, signature) with one product of pairings.
//! assert_eq!(
//!     multi_pairing(&[(public, h), (-G1::generator(), signature)]),
//!     GT::ONE
//! );
//! assert_eq!(pairing(&public, &h), pairing(&G1::generator(), &signature));
//!
//! // 2 G + 3 public = (2 + 3 * 42) G.
//! let points = [G1::generator(), public];
//! let scalars = [Scalar::from_u64(2), Scalar::from_u64(3)];
//! assert_eq!(
//!     G1::msm(&points, &scalars, &Sequential),
//!     G1::generator() * &Scalar::from_u64(2 + 3 * 42)
//! );
//! ```
//!
//! # Features
//!
//! - `std` (default): links the standard library; without it the crate is `no_std`.
//! - `fuzz`: exposes the module `fuzz` of fuzzing operations.
//!
//! [`Additive::zero`]: commonware_math::algebra::Additive::zero
//! [`Additive::double`]: commonware_math::algebra::Additive::double
//! [`Additive::scale`]: commonware_math::algebra::Additive::scale
//! [`CryptoGroup::generator`]: commonware_math::algebra::CryptoGroup::generator
//! [`Field::inv`]: commonware_math::algebra::Field::inv
//! [`FieldNTT`]: commonware_math::algebra::FieldNTT
//! [`Multiplicative::square`]: commonware_math::algebra::Multiplicative::square
//! [`Random::random`]: commonware_math::algebra::Random::random
//! [`Ring::exp`]: commonware_math::algebra::Ring::exp
//! [`Space::msm`]: commonware_math::algebra::Space::msm

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
