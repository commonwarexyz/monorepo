use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::Radix2EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core::ops::{Add, Sub};

/// The proving key for Pari (vanishing-polynomial mask construction).
///
/// Notation follows the ZK-Pari note: the columns of the Square R1CS matrices
/// are interpolated over the domain `K`, the basis is extended with the mask
/// directions `a_{k+2} = v_K(X)`, `a_{k+3} = X v_K(X)` (A-side) and
/// `b_{k+1} = v_K(X)` (B-side, folded into the committed-input commitments).
///
/// The committed payment values are grouped into independently committed
/// *blocks*: block `j` has its own trapdoor `delta_j`, commitment key
/// `sigma_ci[j]`, blinding generator `gamma_ci[j]`, and commitment `C_ci_j` in
/// the proof.
#[derive(CanonicalSerialize, Clone)]
pub struct ProvingKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    /// Per-block committed-input commitment keys
    /// `Sigma_ci_j = [(alpha a_i(tau) + beta b_i(tau))/delta_j G]_{i in block j}`,
    /// in declaration order.
    pub sigma_ci: Vec<Vec<E::G1Affine>>,
    /// Per-block blinding generators `Gamma_ci_j = (beta v_K(tau)/delta_j) G`.
    pub gamma_ci: Vec<E::G1Affine>,
    /// Per-block witness indices of the committed inputs in the fixed range
    /// relation.
    pub committed_witness_indices: Vec<Vec<usize>>,
    /// Witness commitment key
    /// `Sigma_W = [(alpha a_i(tau) + beta b_i(tau))/delta_w G]` for the
    /// ordinary (non-committed) witnesses, in ascending witness-index order.
    pub sigma_w: Vec<E::G1Affine>,
    /// A-side mask key for `eta_1`: `(alpha v_K(tau)/delta_w) G` (direction `a_{k+2} = v_K`).
    pub sigma_mask_const: E::G1Affine,
    /// A-side mask key for `eta_2`: `(alpha tau v_K(tau)/delta_w) G` (direction `a_{k+3} = X v_K`).
    pub sigma_mask_linear: E::G1Affine,
    /// Quotient commitment key `Sigma_Q^comm = [(beta v_K(tau) tau^i/delta_w) G]_{i=0}^{m+2}`.
    pub sigma_q_comm: Vec<E::G1Affine>,
    /// A-side opening key `Sigma_A = [alpha tau^i G]_{i=0}^{m}`.
    pub sigma_a: Vec<E::G1Affine>,
    /// Batched B-side/quotient opening key `Sigma_R = [beta tau^i G]_{i=0}^{2m+1}`.
    pub sigma_r: Vec<E::G1Affine>,
    pub verifying_key: VerifyingKey<E>,
}

/// The verifying key for Pari.
#[derive(Clone, Debug)]
pub struct VerifyingKey<E: Pairing> {
    pub succinct_index: SuccinctIndex,
    pub g: E::G1Affine,
    pub alpha_g: E::G1Affine,
    pub beta_g: E::G1Affine,
    /// Per-block `delta_j H`.
    pub delta_h: Vec<E::G2Affine>,
    pub delta_h_prep: Vec<E::G2Prepared>,
    pub delta_w_h: E::G2Affine,
    pub delta_w_h_prep: E::G2Prepared,
    pub tau_h: E::G2Affine,
    pub tau_h_prep: E::G2Prepared,
    pub h: E::G2Affine,
    pub h_prep: E::G2Prepared,
    pub domain: Radix2EvaluationDomain<E::ScalarField>,
}

impl<E: Pairing> CanonicalSerialize for VerifyingKey<E> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.succinct_index
            .serialize_with_mode(&mut writer, compress)?;
        self.alpha_g.serialize_with_mode(&mut writer, compress)?;
        self.beta_g.serialize_with_mode(&mut writer, compress)?;
        self.delta_h.serialize_with_mode(&mut writer, compress)?;
        self.delta_w_h.serialize_with_mode(&mut writer, compress)?;
        self.tau_h.serialize_with_mode(&mut writer, compress)?;
        self.g.serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let mut size = 0;
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.succinct_index, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.alpha_g, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.beta_g, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.delta_h, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.delta_w_h, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.tau_h, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.g, compress);
        size += ark_serialize::CanonicalSerialize::serialized_size(&self.h, compress);
        size
    }
}

/// The succinct index for Pari.
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct SuccinctIndex {
    /// Number of SR1CS constraints (after instance outlining).
    pub num_constraints: usize,
    /// Number of instance variables (including the leading constant one).
    pub instance_len: usize,
    /// Sizes of the committed-input blocks in the fixed relation.
    pub committed_input_blocks: Vec<usize>,
}

impl SuccinctIndex {
    /// Total number of committed inputs across all blocks.
    pub fn num_committed_inputs(&self) -> usize {
        self.committed_input_blocks.iter().sum()
    }
}

/// The setup trapdoor `(alpha, beta, delta_j, delta_w, tau)` plus the instance
/// polynomial evaluations at `tau`.
///
/// This is the toxic waste of the trusted setup. An honest setup discards it;
/// retaining it breaks soundness, since it lets [`crate::zkpari::ZkPari::simulate`]
/// forge accepting transcripts for any committed-input commitment without a
/// witness. Use it only for the honest-verifier zero-knowledge simulator in
/// tests — never in a real deployment.
#[derive(Clone, Debug)]
pub struct Trapdoor<E: Pairing> {
    /// A-side trapdoor scalar.
    pub alpha: E::ScalarField,
    /// B-side trapdoor scalar.
    pub beta: E::ScalarField,
    /// Per-block committed-input trapdoors `delta_j`.
    pub deltas: Vec<E::ScalarField>,
    /// Witness-commitment trapdoor `delta_w`.
    pub delta_w: E::ScalarField,
    /// Evaluation point trapdoor `tau`.
    pub tau: E::ScalarField,
    /// CRS generator `G`.
    pub g: E::G1Affine,
    /// `a_i(tau)` for the instance variables (index `0` is the constant one).
    pub instance_a_at_tau: Vec<E::ScalarField>,
    /// `b_i(tau)` for the instance variables (zero after instance outlining,
    /// retained for generality).
    pub instance_b_at_tau: Vec<E::ScalarField>,
}

/// A Pari proof: `(2 + #blocks) G1 + 1 F` elements.
///
/// Any block commitment that the verifier can recompute from public state
/// (e.g. an aggregate of ledger commitments) need not be transmitted: the
/// verifier reassembles the proof with the recomputed point. The transmitted
/// material is then `2 G1 + 1 F` plus one `G1` per *fresh* block commitment.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Proof<E: Pairing> {
    /// Per-block committed-input commitments `C_ci_j` (hiding Pedersen vector
    /// commitments).
    pub c_ci: Vec<E::G1Affine>,
    /// Witness/mask/quotient commitment `T`.
    pub t_g: E::G1Affine,
    /// Batched KZG opening proof `U`.
    pub u_g: E::G1Affine,
    /// Masked A-side evaluation `v_a = z_A(r) - x_A(r)`.
    pub v_a: E::ScalarField,
}

/// Opening (blinding) randomness `rho_ci_j` of a committed-input commitment
/// `C_ci_j = sum_i x_i Sigma_ci_j[i] + rho_ci_j Gamma_ci_j`.
///
/// If the proof creates a fresh commitment, `rho_ci_j` is sampled by the
/// prover; if the application already fixes `C_ci_j`, the matching opening is
/// supplied as auxiliary input via [`crate::zkpari::ZkPari::prove_with_openings`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedInputOpening<F: Field> {
    pub rho: F,
}

impl<F: Field> CommittedInputOpening<F> {
    pub fn rand<R: RngCore>(rng: &mut R) -> Self {
        Self { rho: F::rand(rng) }
    }

    pub fn zero() -> Self {
        Self { rho: F::zero() }
    }
}

impl<F: Field> Add for &CommittedInputOpening<F> {
    type Output = CommittedInputOpening<F>;

    fn add(self, rhs: Self) -> CommittedInputOpening<F> {
        CommittedInputOpening {
            rho: self.rho + rhs.rho,
        }
    }
}

impl<F: Field> Sub for &CommittedInputOpening<F> {
    type Output = CommittedInputOpening<F>;

    fn sub(self, rhs: Self) -> CommittedInputOpening<F> {
        CommittedInputOpening {
            rho: self.rho - rhs.rho,
        }
    }
}

impl<E: Pairing> ProvingKey<E> {
    /// Pedersen-commit to a vector of committed-input values under the CRS
    /// basis of block `block`:
    ///
    /// `C_ci_j = sum_i values[i] * Sigma_ci_j[i] + opening.rho * Gamma_ci_j`
    ///
    /// The values must be in declaration order. This equals
    /// `proof.c_ci[block]` when the same values are assigned to the block's
    /// declared variables and the same opening is supplied via
    /// [`crate::zkpari::ZkPari::prove_with_openings`].
    pub fn pedersen_commit(
        &self,
        block: usize,
        values: &[E::ScalarField],
        opening: &CommittedInputOpening<E::ScalarField>,
    ) -> E::G1Affine {
        assert!(
            block < self.sigma_ci.len(),
            "block index {block} out of range ({} blocks)",
            self.sigma_ci.len()
        );
        assert_eq!(
            values.len(),
            self.sigma_ci[block].len(),
            "expected {} committed-input values for block {block}, got {}",
            self.sigma_ci[block].len(),
            values.len()
        );
        let acc = E::G1::msm_unchecked(&self.sigma_ci[block], values);
        (acc + self.gamma_ci[block] * opening.rho).into()
    }
}
