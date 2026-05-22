//! Distributed Key Generation (DKG) and Resharing protocols for BLS12-381.
//!
//! This module provides two constructions:
//!
//! - [`feldman_desmedt`]: a synchronous, two-round protocol with direct dealer-player messages,
//! - [`golden`]: an asynchronous, one-round protocol using encryption and zero-knowledge proofs.
//!
//! [`feldman_desmedt`] is simpler and cheaper, but relies on synchrony to bound
//! revealed shares. [`golden`] removes that assumption at higher computational cost.

pub mod feldman_desmedt;
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // ALPHA
pub mod golden;
