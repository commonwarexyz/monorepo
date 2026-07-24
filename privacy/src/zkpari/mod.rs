//! ZK-Pari: Pari with vanishing-polynomial masks, a zero-knowledge SNARK for
//! Square R1CS with committed inputs.
//!
//! This implements the masked, committed-input variant of
//! [Pari](https://eprint.iacr.org/2024/1245.pdf):
//!
//! - The assignment is split into ordinary public inputs, committed payment
//!   values, and private witnesses.
//! - The committed inputs are grouped into independently committed *blocks*:
//!   block `j` has its own trapdoor `delta_j` and its commitment `C_ci_j` is
//!   a Pedersen vector commitment under the basis `(Sigma_ci_j, Gamma_ci_j)`,
//!   hidden by a vanishing-polynomial direction `rho_ci_j * v_K(X)` on the
//!   B-side.
//! - Two further vanishing directions `h(X) * v_K(X)` with `h(X) = eta_1 +
//!   eta_2 * X` mask the A-side, giving the honest-verifier simulator
//!   independent randomness at the verifier challenge and at the SRS trapdoor.
//! - A single Glock-style opening proof accounts for both the ordinary Pari
//!   commitment and the exposed committed-input commitments, so a proof is
//!   `(2 + #blocks) G1 + 1 F` elements.
//!
//! The fixed relation is the batched payments range relation
//! ([`range`]): two committed values are 64-bit range-checked and bound to
//! the aggregate `v_theta = v_1 + theta v_2` in a second block whose basis
//! doubles as the ledger payment basis. The block-1 aggregate commitment
//! `ledger[0] + theta ledger[1]` is recomputable from public state, so the
//! wire proof ([`range::RangeProof`]) is `3 G1 + 1 F` elements and a
//! verification [`Claim`] carries `(proof, theta, ledger)`.
//!
//! The scheme is statistically honest-verifier zero-knowledge with simulation
//! distance at most `1 / (|F| - |K|)`.
//!
//! Verification checks the 5-pairing equation
//!
//! ```text
//! e(c_hat, delta_1 H) * e(com_theta, delta_2 H) * e(T, delta_w H)
//!     = e(U, tau H - r H) * e(v_a alpha G + v_R beta G, H)
//! ```
//!
//! with `v_R = (v_a + x_A(r))^2 - x_B(r)` computed by the verifier
//! (`x_B = 0` after SR1CS instance outlining). The Fiat-Shamir challenge `r`
//! binds the ledger commitments rather than the derived aggregate, so batch
//! verification folds the aggregation into its accumulation MSM.
//!
use ark_ec::pairing::Pairing;
use ark_std::marker::PhantomData;

mod batch_verify;
pub mod data_structures;
mod generator;
pub mod payments;
mod prover;
pub mod range;
mod rng;
#[cfg(any(test, feature = "simulator"))]
mod simulator;
pub mod utils;
mod verifier;

#[cfg(test)]
mod tests;

pub use data_structures::{
    Claim, CommittedInputOpening, Proof, ProvingKey, SuccinctIndex, Trapdoor, VerifyingKey,
};

/// The ZK-Pari SNARK.
pub struct ZkPari<E: Pairing> {
    _p: PhantomData<E>,
}

impl<E: Pairing> ZkPari<E> {
    /// Transcript domain separator.
    pub const SNARK_NAME: &'static [u8] = b"ZK-Pari";
}
