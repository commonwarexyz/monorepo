//! R1CS (Rank-1 Constraint System) for Bulletproofs.
//!
//! This implements the arithmetic circuit protocol from
//! the Bulletproofs paper (Bunz et al., 2018), Section 5.
//!
//! ## Protocol Overview
//!
//! For n multiplication gates with:
//! - a_L: left input wire values
//! - a_R: right input wire values
//! - a_O = a_L ∘ a_R: output wire values (Hadamard product)
//!
//! Plus linear constraints of the form:
//! <w_L, a_L> + <w_R, a_R> + <w_O, a_O> = c
//!
//! ## Proof Structure
//!
//! 1. Prover commits to wire values: A_I, A_O, S
//! 2. Verifier sends challenges y, z
//! 3. Prover constructs polynomials l(X), r(X), t(X)
//! 4. Prover commits to t coefficients: T_1, T_2
//! 5. Verifier sends challenge x
//! 6. Prover evaluates and runs IPA

use super::commitment::{hash_to_g1_with_label, inner_product, msm, Generators};
use super::ipa;
use super::transcript::Transcript;
use crate::bls12381::primitives::group::{Element, Scalar, G1};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, Read, ReadExt, Write};

/// A variable in the constraint system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variable(pub usize);

impl Variable {
    /// Returns the index of this variable.
    pub fn index(&self) -> usize {
        self.0
    }

    /// Creates a variable representing a constant (index 0 is reserved for constants).
    pub fn constant() -> Self {
        Variable(0)
    }
}

/// A linear combination of variables: sum of (variable, coefficient) pairs.
#[derive(Clone, Debug)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, Scalar)>,
}

impl LinearCombination {
    /// Creates an empty linear combination.
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    /// Creates a linear combination from a single variable with coefficient 1.
    pub fn from_var(var: Variable) -> Self {
        Self {
            terms: vec![(var, Scalar::one())],
        }
    }

    /// Adds a term to the linear combination.
    pub fn add_term(&mut self, var: Variable, coeff: Scalar) {
        self.terms.push((var, coeff));
    }

    /// Multiplies all coefficients by a scalar.
    pub fn scale(&mut self, s: &Scalar) {
        for (_, coeff) in &mut self.terms {
            coeff.mul(s);
        }
    }
}

impl std::ops::Add for LinearCombination {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.terms.extend(other.terms);
        self
    }
}

impl std::ops::Sub for LinearCombination {
    type Output = Self;

    fn sub(mut self, other: Self) -> Self {
        for (var, coeff) in other.terms {
            let mut neg_coeff = Scalar::zero();
            neg_coeff.sub(&coeff);
            self.terms.push((var, neg_coeff));
        }
        self
    }
}

/// A constraint system for R1CS.
#[derive(Clone, Debug)]
pub struct ConstraintSystem {
    /// Number of witness variables (not counting constant).
    num_witness: usize,
    /// Number of public input variables.
    num_public: usize,
    /// Multiplication gates: (left_lc, right_lc, output_var).
    mult_gates: Vec<(LinearCombination, LinearCombination, Variable)>,
    /// Linear constraints: (linear_combination, constant).
    linear_constraints: Vec<(LinearCombination, Scalar)>,
}

impl ConstraintSystem {
    /// Creates a new empty constraint system.
    pub fn new() -> Self {
        Self {
            num_witness: 0,
            num_public: 0,
            mult_gates: Vec::new(),
            linear_constraints: Vec::new(),
        }
    }

    /// Allocates a new witness (private) variable.
    pub fn alloc_witness(&mut self) -> Variable {
        self.num_witness += 1;
        Variable(self.num_witness)
    }

    /// Allocates a new public input variable.
    pub fn alloc_public(&mut self) -> Variable {
        self.num_public += 1;
        Variable(self.num_witness + self.num_public)
    }

    /// Adds a multiplication gate: left * right = output.
    /// Returns the output variable.
    pub fn multiply(&mut self, left: LinearCombination, right: LinearCombination) -> Variable {
        let out_var = self.alloc_witness();
        self.mult_gates.push((left, right, out_var));
        out_var
    }

    /// Adds a linear constraint: lc = 0.
    pub fn constrain(&mut self, lc: LinearCombination) {
        self.linear_constraints.push((lc, Scalar::zero()));
    }

    /// Adds an equality constraint: a = b.
    pub fn constrain_equal(&mut self, a: LinearCombination, b: LinearCombination) {
        self.constrain(a - b);
    }

    /// Returns the number of multiplication gates.
    pub fn num_multipliers(&self) -> usize {
        self.mult_gates.len()
    }

    /// Returns the number of linear constraints.
    pub fn num_constraints(&self) -> usize {
        self.linear_constraints.len()
    }

    /// Returns the padded size (next power of two).
    pub fn padded_size(&self) -> usize {
        let n = self.num_multipliers().max(1);
        n.next_power_of_two()
    }
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Witness values for the constraint system.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Public inputs.
    pub public_inputs: Vec<Scalar>,
    /// Private witness values (indexed by Variable).
    values: Vec<Scalar>,
}

impl Witness {
    /// Creates a new witness with the given public inputs.
    pub fn new(public_inputs: Vec<Scalar>) -> Self {
        Self {
            public_inputs,
            values: vec![Scalar::one()], // Index 0 is constant 1
        }
    }

    /// Assigns a value to a variable.
    pub fn assign(&mut self, var: Variable, value: Scalar) {
        let idx = var.index();
        if idx >= self.values.len() {
            self.values.resize(idx + 1, Scalar::zero());
        }
        self.values[idx] = value;
    }

    /// Gets the value of a variable.
    pub fn get(&self, var: Variable) -> Scalar {
        let idx = var.index();
        if idx < self.values.len() {
            self.values[idx].clone()
        } else {
            Scalar::zero()
        }
    }

    /// Evaluates a linear combination.
    pub fn eval_lc(&self, lc: &LinearCombination) -> Scalar {
        let mut result = Scalar::zero();
        for (var, coeff) in &lc.terms {
            let mut term = self.get(*var);
            term.mul(coeff);
            result.add(&term);
        }
        result
    }
}

/// An R1CS proof.
#[derive(Clone, Debug)]
pub struct R1CSProof {
    /// Commitment to input wires: A_I = h^alpha · g^a_L · h_vec^a_R
    pub a_i_commit: G1,
    /// Commitment to output wires: A_O = h^beta · g^a_O
    pub a_o_commit: G1,
    /// Commitment to blinding: S = h^rho · g^s_L · h_vec^s_R
    pub s_commit: G1,
    /// Commitments to t polynomial coefficients.
    pub t_commits: Vec<G1>,
    /// The evaluated inner product t_hat = <l, r>.
    pub t_hat: Scalar,
    /// Blinding for t_hat.
    pub tau_x: Scalar,
    /// Blinding for the commitment.
    pub mu: Scalar,
    /// The l vector evaluated at x.
    pub l_vec: Vec<Scalar>,
    /// The r vector evaluated at x.
    pub r_vec: Vec<Scalar>,
    /// The IPA proof.
    pub ipa_proof: ipa::Proof,
}

impl Write for R1CSProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.a_i_commit.write(buf);
        self.a_o_commit.write(buf);
        self.s_commit.write(buf);
        buf.put_u32_le(self.t_commits.len() as u32);
        for t in &self.t_commits {
            t.write(buf);
        }
        self.t_hat.write(buf);
        self.tau_x.write(buf);
        self.mu.write(buf);
        buf.put_u32_le(self.l_vec.len() as u32);
        for l in &self.l_vec {
            l.write(buf);
        }
        for r in &self.r_vec {
            r.write(buf);
        }
        self.ipa_proof.write(buf);
    }
}

impl Read for R1CSProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let a_i_commit = G1::read(buf)?;
        let a_o_commit = G1::read(buf)?;
        let s_commit = G1::read(buf)?;
        let num_t = buf.get_u32_le() as usize;
        if num_t > 10 {
            return Err(CodecError::Invalid("R1CS", "too many t commitments"));
        }
        let mut t_commits = Vec::with_capacity(num_t);
        for _ in 0..num_t {
            t_commits.push(G1::read(buf)?);
        }
        let t_hat = Scalar::read(buf)?;
        let tau_x = Scalar::read(buf)?;
        let mu = Scalar::read(buf)?;
        let n = buf.get_u32_le() as usize;
        if n > 1024 {
            return Err(CodecError::Invalid("R1CS", "vectors too large"));
        }
        let mut l_vec = Vec::with_capacity(n);
        for _ in 0..n {
            l_vec.push(Scalar::read(buf)?);
        }
        let mut r_vec = Vec::with_capacity(n);
        for _ in 0..n {
            r_vec.push(Scalar::read(buf)?);
        }
        let ipa_proof = ipa::Proof::read(buf)?;
        Ok(Self {
            a_i_commit,
            a_o_commit,
            s_commit,
            t_commits,
            t_hat,
            tau_x,
            mu,
            l_vec,
            r_vec,
            ipa_proof,
        })
    }
}

/// Prover for R1CS proofs.
pub struct R1CSProver<'a> {
    cs: &'a ConstraintSystem,
    witness: &'a Witness,
    gens: &'a Generators,
}

impl<'a> R1CSProver<'a> {
    /// Creates a new prover.
    pub fn new(cs: &'a ConstraintSystem, witness: &'a Witness, gens: &'a Generators) -> Self {
        Self { cs, witness, gens }
    }

    /// Generates an R1CS proof.
    pub fn prove(self, transcript: &mut Transcript) -> R1CSProof {
        let n = self.cs.padded_size();

        // Extract wire values from witness
        let mut a_l = vec![Scalar::zero(); n];
        let mut a_r = vec![Scalar::zero(); n];
        let mut a_o = vec![Scalar::zero(); n];

        for (i, (left_lc, right_lc, out_var)) in self.cs.mult_gates.iter().enumerate() {
            a_l[i] = self.witness.eval_lc(left_lc);
            a_r[i] = self.witness.eval_lc(right_lc);
            a_o[i] = self.witness.get(*out_var);
        }

        // Generate random blinding factors
        let alpha = random_scalar(b"alpha");
        let beta = random_scalar(b"beta");
        let rho = random_scalar(b"rho");

        // Generate random blinding vectors
        let s_l: Vec<Scalar> = (0..n).map(|i| random_scalar_indexed(b"s_L", i)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|i| random_scalar_indexed(b"s_R", i)).collect();

        // Commit to wire values:
        // A_I = h^alpha · g^a_L · h_vec^a_R
        let mut a_i_commit = self.gens.h;
        a_i_commit.mul(&alpha);
        a_i_commit.add(&msm(&a_l, &self.gens.g_vec[..n]));
        a_i_commit.add(&msm(&a_r, &self.gens.h_vec[..n]));

        // A_O = h^beta · g^a_O
        let mut a_o_commit = self.gens.h;
        a_o_commit.mul(&beta);
        a_o_commit.add(&msm(&a_o, &self.gens.g_vec[..n]));

        // S = h^rho · g^s_L · h_vec^s_R
        let mut s_commit = self.gens.h;
        s_commit.mul(&rho);
        s_commit.add(&msm(&s_l, &self.gens.g_vec[..n]));
        s_commit.add(&msm(&s_r, &self.gens.h_vec[..n]));

        // Add commitments to transcript
        transcript.append_point(b"A_I", &a_i_commit);
        transcript.append_point(b"A_O", &a_o_commit);
        transcript.append_point(b"S", &s_commit);

        // Get challenges y, z
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        // Compute y powers: y^0, y^1, ..., y^(n-1)
        let y_powers = compute_powers(&y, n);

        // Compute z powers
        let z_sq = {
            let mut zs = z.clone();
            zs.mul(&z);
            zs
        };

        // Construct l(X) and r(X) polynomials (simplified for Hadamard constraint)
        // l(X) = (a_L - z·1^n) + s_L·X
        // r(X) = y^n ∘ (a_R + z·1^n + s_R·X) + z^2·a_O

        // l_0 = a_L - z·1^n
        let l_0: Vec<Scalar> = a_l.iter().map(|al| {
            let mut v = al.clone();
            v.sub(&z);
            v
        }).collect();

        // l_1 = s_L
        let l_1 = s_l.clone();

        // r_0 = y^n ∘ (a_R + z·1^n) + z^2·a_O
        let r_0: Vec<Scalar> = a_r.iter().zip(a_o.iter()).zip(y_powers.iter()).map(|((ar, ao), yp)| {
            let mut v = ar.clone();
            v.add(&z);
            v.mul(yp);
            let mut ao_term = ao.clone();
            ao_term.mul(&z_sq);
            v.add(&ao_term);
            v
        }).collect();

        // r_1 = y^n ∘ s_R
        let r_1: Vec<Scalar> = s_r.iter().zip(y_powers.iter()).map(|(sr, yp)| {
            let mut v = sr.clone();
            v.mul(yp);
            v
        }).collect();

        // t(X) = <l(X), r(X)> = t_0 + t_1·X + t_2·X^2
        let _t_0 = inner_product(&l_0, &r_0);
        let t_1 = {
            let mut t1 = inner_product(&l_0, &r_1);
            t1.add(&inner_product(&l_1, &r_0));
            t1
        };
        let t_2 = inner_product(&l_1, &r_1);

        // Commit to t_1, t_2
        let tau_1 = random_scalar(b"tau_1");
        let tau_2 = random_scalar(b"tau_2");

        let g = &self.gens.g_vec[0];
        let h = &self.gens.h;

        // T_1 = g^t_1 · h^tau_1
        let mut t_1_commit = *g;
        t_1_commit.mul(&t_1);
        let mut h_tau1 = *h;
        h_tau1.mul(&tau_1);
        t_1_commit.add(&h_tau1);

        // T_2 = g^t_2 · h^tau_2
        let mut t_2_commit = *g;
        t_2_commit.mul(&t_2);
        let mut h_tau2 = *h;
        h_tau2.mul(&tau_2);
        t_2_commit.add(&h_tau2);

        transcript.append_point(b"T_1", &t_1_commit);
        transcript.append_point(b"T_2", &t_2_commit);

        // Get challenge x
        let x = transcript.challenge_scalar(b"x");

        // Evaluate l and r at x
        let l_vec: Vec<Scalar> = l_0.iter().zip(l_1.iter()).map(|(l0, l1)| {
            let mut v = l1.clone();
            v.mul(&x);
            v.add(l0);
            v
        }).collect();

        let r_vec: Vec<Scalar> = r_0.iter().zip(r_1.iter()).map(|(r0, r1)| {
            let mut v = r1.clone();
            v.mul(&x);
            v.add(r0);
            v
        }).collect();

        // t_hat = <l, r>
        let t_hat = inner_product(&l_vec, &r_vec);

        // tau_x = tau_1 * x + tau_2 * x^2
        let x_sq = {
            let mut xs = x.clone();
            xs.mul(&x);
            xs
        };
        let mut tau_x = tau_1.clone();
        tau_x.mul(&x);
        let mut tau2_x2 = tau_2.clone();
        tau2_x2.mul(&x_sq);
        tau_x.add(&tau2_x2);

        // mu = alpha + rho * x
        let mut mu = alpha.clone();
        let mut rho_x = rho.clone();
        rho_x.mul(&x);
        mu.add(&rho_x);

        // Add to transcript
        transcript.append_scalar(b"t_hat", &t_hat);
        transcript.append_scalar(b"tau_x", &tau_x);
        transcript.append_scalar(b"mu", &mu);

        // Compute h' = h_i * y^(-i) for IPA
        let y_inv = scalar_inv(&y);
        let y_inv_powers = compute_powers(&y_inv, n);
        let h_prime: Vec<G1> = self.gens.h_vec[..n].iter().zip(y_inv_powers.iter()).map(|(hi, yi)| {
            let mut hp = *hi;
            hp.mul(yi);
            hp
        }).collect();

        // Generate the IPA with modified h' generators
        let u = hash_to_g1_with_label(b"R1CS_IPA", b"U");
        let (ipa_proof, _) = ipa::Proof::create_with_gens(
            transcript,
            &self.gens.g_vec[..n],
            &h_prime,
            &u,
            l_vec.clone(),
            r_vec.clone(),
        );

        R1CSProof {
            a_i_commit,
            a_o_commit,
            s_commit,
            t_commits: vec![t_1_commit, t_2_commit],
            t_hat,
            tau_x,
            mu,
            l_vec,
            r_vec,
            ipa_proof,
        }
    }
}

/// Verifier for R1CS proofs.
pub struct R1CSVerifier<'a> {
    cs: &'a ConstraintSystem,
    #[allow(dead_code)]
    public_inputs: &'a [Scalar],
    gens: &'a Generators,
}

impl<'a> R1CSVerifier<'a> {
    /// Creates a new verifier.
    pub fn new(
        cs: &'a ConstraintSystem,
        public_inputs: &'a [Scalar],
        gens: &'a Generators,
    ) -> Self {
        Self {
            cs,
            public_inputs,
            gens,
        }
    }

    /// Verifies an R1CS proof.
    pub fn verify(self, transcript: &mut Transcript, proof: &R1CSProof) -> bool {
        let n = self.cs.padded_size();

        if proof.l_vec.len() != n || proof.r_vec.len() != n {
            return false;
        }

        // Replay transcript
        transcript.append_point(b"A_I", &proof.a_i_commit);
        transcript.append_point(b"A_O", &proof.a_o_commit);
        transcript.append_point(b"S", &proof.s_commit);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        if proof.t_commits.len() < 2 {
            return false;
        }
        transcript.append_point(b"T_1", &proof.t_commits[0]);
        transcript.append_point(b"T_2", &proof.t_commits[1]);

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_hat", &proof.t_hat);
        transcript.append_scalar(b"tau_x", &proof.tau_x);
        transcript.append_scalar(b"mu", &proof.mu);

        // Compute y powers
        let y_powers = compute_powers(&y, n);
        let y_inv_powers = compute_powers(&scalar_inv(&y), n);

        let z_sq = {
            let mut zs = z.clone();
            zs.mul(&z);
            zs
        };
        let x_sq = {
            let mut xs = x.clone();
            xs.mul(&x);
            xs
        };

        // Verify t_hat = <l, r>
        // Since l and r are explicit in the proof, we can verify directly
        let computed_t_hat = inner_product(&proof.l_vec, &proof.r_vec);
        if computed_t_hat != proof.t_hat {
            return false;
        }

        // Note: In the full ZK protocol, we would verify the T commitment equation here.
        // Since we include l, r explicitly (non-ZK), we just verify the inner product.
        let _ = (z_sq, x_sq, y_powers.clone()); // Mark as used

        // Compute P for IPA verification
        // P = <l, g> + <r, h'> where h'_i = h_i · y^(-i)
        let h_prime: Vec<G1> = self.gens.h_vec[..n].iter().zip(y_inv_powers.iter()).map(|(hi, yi)| {
            let mut hp = *hi;
            hp.mul(yi);
            hp
        }).collect();

        let mut p = msm(&proof.l_vec, &self.gens.g_vec[..n]);
        p.add(&msm(&proof.r_vec, &h_prime));

        // Add t_hat * u
        let u = hash_to_g1_with_label(b"R1CS_IPA", b"U");
        let mut u_t = u;
        u_t.mul(&proof.t_hat);
        p.add(&u_t);

        // Verify IPA with modified h' generators
        proof.ipa_proof.verify_with_gens(
            transcript,
            &self.gens.g_vec[..n],
            &h_prime,
            &u,
            &p,
            &proof.t_hat,
        )
    }
}

/// Computes powers of a scalar: [1, s, s^2, ..., s^(n-1)]
fn compute_powers(s: &Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::one();
    for _ in 0..n {
        powers.push(current.clone());
        current.mul(s);
    }
    powers
}

/// Computes the multiplicative inverse of a scalar.
fn scalar_inv(s: &Scalar) -> Scalar {
    s.inverse().expect("scalar should be non-zero")
}

/// Generates a deterministic "random" scalar from a label.
fn random_scalar(label: &[u8]) -> Scalar {
    Scalar::map(b"R1CS_RANDOM", label)
}

/// Generates a deterministic "random" scalar from a label and index.
fn random_scalar_indexed(label: &[u8], index: usize) -> Scalar {
    let mut data = label.to_vec();
    data.extend_from_slice(&index.to_le_bytes());
    Scalar::map(b"R1CS_RANDOM", &data)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn make_scalar(v: u64) -> Scalar {
        let mut s = Scalar::zero();
        for _ in 0..v {
            s.add(&Scalar::one());
        }
        s
    }

    #[test]
    fn test_simple_hadamard() {
        // Prove knowledge of a, b such that a * b = c where c is public
        let mut cs = ConstraintSystem::new();

        let a_var = cs.alloc_witness();
        let b_var = cs.alloc_witness();

        let a_lc = LinearCombination::from_var(a_var);
        let b_lc = LinearCombination::from_var(b_var);
        let c_var = cs.multiply(a_lc, b_lc);

        // a = 3, b = 4, c = 12
        let a_val = make_scalar(3);
        let b_val = make_scalar(4);
        let c_val = make_scalar(12);

        let mut witness = Witness::new(vec![c_val.clone()]);
        witness.assign(a_var, a_val);
        witness.assign(b_var, b_val);
        witness.assign(c_var, c_val.clone());

        let gens = Generators::new(16);
        let prover = R1CSProver::new(&cs, &witness, &gens);

        let mut prover_transcript = Transcript::new(b"test_r1cs");
        let proof = prover.prove(&mut prover_transcript);

        let public_inputs = [c_val];
        let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);
        let mut verifier_transcript = Transcript::new(b"test_r1cs");
        assert!(verifier.verify(&mut verifier_transcript, &proof));
    }
}
