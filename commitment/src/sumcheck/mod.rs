//! Sumcheck protocol for polynomial proximity testing.
//!
//! The sumcheck protocol reduces a claim about the sum of a multilinear
//! polynomial to a claim about its evaluation at a random point,
//! using O(n) rounds of interaction (made non-interactive via Fiat-Shamir).
//!
//! This module contains:
//! - [`polys`]: Polynomial induction for batched basis polynomials.
//! - [`verifier`]: Stateful sumcheck verifier instance.
//! - [`eval`]: Evaluation proofs via sumcheck.

pub mod eval;
pub mod polys;
pub mod verifier;
