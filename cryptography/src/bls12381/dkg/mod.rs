//! Distributed Key Generation (DKG) and Resharing protocols specific to BLS12-381.
//!
//! [`golden`] is an asynchronous, one-round protocol using encryption and zero-knowledge proofs.
//! [`feldman_desmedt`](crate::bls::dkg::feldman_desmedt) is simpler and cheaper, but relies on
//! synchrony to bound revealed shares. [`golden`] removes that assumption at higher computational
//! cost.

#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // ALPHA
pub mod golden;
