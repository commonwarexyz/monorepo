//! Private-payments backend built on the native Pari proof system over
//! BLS12-381.
//!
//! The transfer statement is a batched range proof: one proof shows that a
//! transferred amount and the sender's remaining balance are each in
//! `[0, 2^64)` and that they open the ledger's payment commitments. See
//! [`range`] for the relation and [`payments`] for the [`crate::payments`]
//! backend.

pub mod payments;
pub mod range;

#[cfg(any(test, feature = "simulator"))]
pub mod simulator;

#[cfg(test)]
mod tests;
