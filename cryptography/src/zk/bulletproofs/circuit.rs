//! This module provides a Bulletproofs circuit proof built on top of the
//! [inner product argument](super::ipa).
//!
//! # Background
//!
//! We start with Pedersen commitments to committed values `v_i`:
//!
//! `V_i = v_i * B + v_blind_i * B_blind`.
//!
//! A [`Circuit`] then constrains these committed values using:
//!
//! - multiplication gates `l_i * r_i = o_i`, and
//! - linear constraints over the concatenated vector
//!   `1 | committed values | left wires | right wires | output wires`.
//!
//! Concretely, the circuit stores a sparse weight matrix `W`, where each row
//! enforces a linear relation over that concatenated vector.
//!
//! Given a set of commitments, the prover wants to convince the verifier that
//! the committed values satisfy the circuit, without revealing the committed
//! values, their Pedersen blindings, or the internal wire values.
//!
//! # Usage
//!
//! First construct a [`Setup`]. This wraps an IPA [`super::ipa::Setup`] and
//! adds two generators used for Pedersen commitments.
//!
//! Next, describe the constraint system as a [`SparseMatrix`], and turn it
//! into a [`Circuit`] with [`Circuit::new`]. The circuit fixes the column
//! layout to:
//!
//! `1 | committed values | left wires | right wires | output wires`
//!
//! A prover-side assignment is represented by [`Witness`]. [`Witness::new`]
//! checks that the value vectors have compatible lengths, and
//! [`Witness::claim`] derives the public [`Claim`] for those committed values.
//!
//! Given a [`Setup`], [`Circuit`], [`Claim`], and [`Witness`], create a
//! [`Proof`] with [`prove`].
//!
//! The proof is bound to the current [`Transcript`] state. The verifier must
//! replay the same transcript history before calling [`verify`].
//!
//! Use [`verify`] to construct the returned [`Synthetic`] verification equation
//! and [`Setup::eval`] to evaluate it against the concrete setup.
//!
//! ## Example
//!
//! ```rust
//! # use commonware_cryptography::{
//! #     bls12381::primitives::group::{G1, Scalar},
//! #     transcript::Transcript,
//! #     zk::bulletproofs::{
//! #         circuit::{prove, verify, Circuit, Setup, SparseMatrix, Witness},
//! #         ipa,
//! #     },
//! # };
//! # use commonware_math::algebra::{Additive, CryptoGroup, Random, Ring};
//! # use commonware_parallel::Sequential;
//! # use commonware_utils::test_rng;
//! # type F = Scalar;
//! # type G = G1;
//! # let generators: [G; 5] =
//! #     core::array::from_fn(|i| G::generator() * &F::from(i as u64 + 1));
//!
//! // This is a toy setup for documentation. Real generators must not have
//! // known discrete-log relationships.
//! let setup = Setup::new(
//!     ipa::Setup::new(
//!         generators[0].clone(),
//!         [(generators[1].clone(), generators[2].clone())],
//!     ),
//!     generators[3].clone(),
//!     generators[4].clone(),
//! );
//!
//! // Build a one-gate circuit proving that the committed values are 3 and 4,
//! // with a product wire fixed to 12.
//! let mut weights = SparseMatrix::default();
//! weights[(0, 1)] = F::one();
//! weights[(0, 3)] = -F::one();
//! weights[(1, 2)] = F::one();
//! weights[(1, 4)] = -F::one();
//! weights[(2, 0)] = F::from(12u64);
//! weights[(2, 5)] = -F::one();
//! let circuit = Circuit::new(2, weights).expect("matrix width should fit");
//!
//! let mut prover_rng = test_rng();
//! let witness = Witness::new(
//!     vec![F::from(3u64), F::from(4u64)],
//!     vec![F::random(&mut prover_rng), F::random(&mut prover_rng)],
//!     vec![F::from(3u64)],
//!     vec![F::from(4u64)],
//!     vec![F::from(12u64)],
//! )
//! .expect("witness lengths should match");
//! let claim = witness.claim(&setup);
//!
//! let mut prover_transcript = Transcript::new(b"circuit-example");
//! prover_transcript.commit(b"context".as_slice());
//! let proof = prove(
//!     &mut prover_rng,
//!     &mut prover_transcript,
//!     &setup,
//!     &circuit,
//!     &claim,
//!     &witness,
//!     &Sequential,
//! )
//! .expect("witness should satisfy the claim and circuit");
//!
//! let mut verifier_rng = test_rng();
//! let mut verifier_transcript = Transcript::new(b"circuit-example");
//! verifier_transcript.commit(b"context".as_slice());
//! let valid = setup
//!     .eval(
//!         |vs| verify(&mut verifier_rng, &mut verifier_transcript, vs, &circuit, &claim, proof, &Sequential),
//!         &Sequential,
//!     )
//!     .map(|g| g == G::zero())
//!     .unwrap_or(false);
//! assert!(valid);
//! ```
//!
//! # References
//!
//! The [Dalek crate notes](https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html)
//! were useful prior art when implementing and documenting the IPA layer used by
//! this module.
//!
//! The original [Bulletproofs paper](https://eprint.iacr.org/2017/1066) and the
//! implementation notes from the IPA module are also useful background for this file.

use super::ipa;
use crate::transcript::Transcript;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, Write};
use commonware_math::{
    algebra::{powers, Additive, CryptoGroup, Field, HashToGroup, Random, Ring, Space},
    synthetic::Synthetic,
};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::ordered::Set;
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    ops::{Index, IndexMut, Mul},
};

/// A sparse matrix indexed by `(row, column)`.
///
/// Missing entries are treated as 0.
pub struct SparseMatrix<F> {
    width: usize,
    height: usize,
    weights: BTreeMap<(usize, usize), F>,
    /// This exists so that we can return a reference when indexing.
    zero: F,
}

impl<F> SparseMatrix<F> {
    /// The width of this matrix.
    ///
    /// This is determined solely by the highest column with a non-zero entry.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// The height of this matrix.
    ///
    /// This is determined solely by the highest row with a non-zero entry.
    pub const fn height(&self) -> usize {
        self.height
    }

    /// Pad this matrix to have at least these dimensions.
    pub fn pad(&mut self, width: usize, height: usize) {
        self.width = self.width.max(width);
        self.height = self.height.max(height);
    }
}

impl<F> IntoIterator for SparseMatrix<F> {
    type Item = ((usize, usize), F);

    type IntoIter = <BTreeMap<(usize, usize), F> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.weights.into_iter()
    }
}

impl<F: Additive> Default for SparseMatrix<F> {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            weights: Default::default(),
            zero: F::zero(),
        }
    }
}

impl<F: Additive> Index<(usize, usize)> for SparseMatrix<F> {
    type Output = F;

    fn index(&self, idx: (usize, usize)) -> &Self::Output {
        self.weights.get(&idx).unwrap_or(&self.zero)
    }
}

impl<F: Additive> IndexMut<(usize, usize)> for SparseMatrix<F> {
    fn index_mut(&mut self, idx: (usize, usize)) -> &mut Self::Output {
        self.height = self
            .height
            .max(idx.0.checked_add(1).expect("row index overflow"));
        self.width = self
            .width
            .max(idx.1.checked_add(1).expect("column index overflow"));
        self.weights.entry(idx).or_insert(F::zero())
    }
}

impl<F: Ring> Mul<&[F]> for &SparseMatrix<F> {
    type Output = Vec<F>;

    fn mul(self, rhs: &[F]) -> Self::Output {
        let mut out = vec![F::zero(); self.height];
        for (&(i, j), weight) in &self.weights {
            let Some(value) = rhs.get(j) else {
                continue;
            };
            out[i] += &(weight.clone() * value);
        }
        out
    }
}

impl<F: Write> Write for SparseMatrix<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.weights.write(buf);
    }
}

impl<F: EncodeSize> EncodeSize for SparseMatrix<F> {
    fn encode_size(&self) -> usize {
        self.weights.encode_size()
    }
}

/// A circuit describing the constraints the prover must satisfy.
pub struct Circuit<F> {
    committed_vars: usize,
    internal_vars: usize,
    weights: SparseMatrix<F>,
}

impl<F: Write> Write for Circuit<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.committed_vars.write(buf);
        self.weights.write(buf);
    }
}

impl<F: Encode> Circuit<F> {
    fn commit(&self, transcript: &mut Transcript) {
        transcript.commit(self.encode());
    }
}

impl<F: EncodeSize> EncodeSize for Circuit<F> {
    fn encode_size(&self) -> usize {
        self.committed_vars.encode_size() + self.weights.encode_size()
    }
}

impl<F: Ring> Circuit<F> {
    /// Create a new circuit from a committed-value count and a weight matrix.
    ///
    /// The circuit enforces:
    ///
    /// - `l_i * r_i = o_i`, and
    /// - one linear constraint per row of `weights`.
    ///
    /// The columns are interpreted as:
    ///
    /// `1 | committed values | left wires | right wires | output wires`
    ///
    /// This returns `None` if the matrix width is incompatible with that layout.
    pub fn new(committed_vars: usize, weights: SparseMatrix<F>) -> Option<Self> {
        let remaining_vars = weights.width.checked_sub(committed_vars.checked_add(1)?)?;
        if remaining_vars % 3 != 0 {
            return None;
        }
        let internal_vars = remaining_vars / 3;
        Some(Self {
            committed_vars,
            internal_vars,
            weights,
        })
    }

    /// Number of left/right/output internal wires.
    pub const fn internal_vars(&self) -> usize {
        self.internal_vars
    }

    /// Number of committed values.
    pub const fn committed_vars(&self) -> usize {
        self.committed_vars
    }

    /// Checks whether a certain assignment to committed variables satisfies this circuit.
    ///
    /// This returns false if the assignment has the wrong length, rather than
    /// implicitly truncating or padding the assignment.
    #[must_use]
    pub fn is_satisfied(
        &self,
        committed_values: &[F],
        left_values: &[F],
        right_values: &[F],
    ) -> bool {
        if committed_values.len() != self.committed_vars
            || left_values.len() != self.internal_vars
            || right_values.len() != self.internal_vars
        {
            return false;
        }
        let mut output = Vec::with_capacity(1 + self.committed_vars + 3 * self.internal_vars);
        output.push(F::one());
        output.extend_from_slice(committed_values);
        output.extend_from_slice(left_values);
        output.extend_from_slice(right_values);
        output.extend(
            left_values
                .iter()
                .zip(right_values)
                .map(|(l_i, r_i)| l_i.clone() * r_i),
        );
        let mut res = vec![F::zero(); self.weights.height];
        for (&(i, j), w_ij) in &self.weights.weights {
            res[i] += &(output[j].clone() * w_ij);
        }
        let zero = F::zero();
        res.iter().all(|r_i| r_i == &zero)
    }
}

/// A rank-1 constraint system.
///
/// The matrices encode constraints of the form `<A_i, z> * <B_i, z> = <C_i, z>`,
/// where `z_0` is the constant `1`.
pub struct R1cs<F> {
    /// The left-side linear combinations.
    pub a: SparseMatrix<F>,
    /// The right-side linear combinations.
    pub b: SparseMatrix<F>,
    /// The output linear combinations.
    pub c: SparseMatrix<F>,
}

impl<F> R1cs<F> {
    /// Make sure that the matrices have the same shapes, by zero-padding.
    pub fn normalize(&mut self) {
        let width = self.width();
        let height = self.height();
        for m in [&mut self.a, &mut self.b, &mut self.c] {
            m.pad(width, height);
        }
    }

    /// The width of each matrix.
    pub fn width(&self) -> usize {
        self.a.width.max(self.b.width).max(self.c.width)
    }

    /// The height of each matrix.
    pub fn height(&self) -> usize {
        self.a.height.max(self.b.height).max(self.c.height)
    }
}

fn r1cs_to_circuit_maybe_witness<F: Ring>(
    mut r1cs: R1cs<F>,
    committed_indices: &[usize],
    witness: Option<(Vec<F>, Vec<F>)>,
) -> (Circuit<F>, Option<Witness<F>>) {
    // The R1CS circuit is of the form:
    //
    //   <A_ij, z_j> <B_ij, z_j> = <C_ij, z_j>
    //
    // with `z_0 = 1` (the Arkworks convention). Some of the remaining
    // witness indices of `z` are to become our v vector.
    //
    // We set:
    //
    //   l_i = <A_ij, z_j>
    //   r_i = <B_ij, z_j>
    //   o_i = <C_ij, z_j>
    //
    // Then, the l_i * r_i = o_i part of bulletproofs will enforce this.
    // Next, we need to enforce that they were constructed correctly.
    // To do so, we use additional l_i wires for non-committed witness values.
    // The corresponding r_i and o_i wires are not used anywhere else, so they
    // do not need additional linear constraints.
    //
    // The bulletproof circuit reserves output position 0 for the constant
    // `1` with the same meaning as Arkworks's `z_0`, so contributions from
    // R1CS column 0 are routed straight to bulletproof column 0 rather
    // than being placed in a free internal wire (which would let a
    // malicious prover pick `z_0` freely and bypass any constraint that
    // depends on the constant).
    r1cs.normalize();
    let (r1cs_width, r1cs_height) = (r1cs.width(), r1cs.height());
    let committed_indices = Set::from_iter_dedup(committed_indices.iter().cloned());
    assert!(
        committed_indices.iter().next().is_none_or(|&i| i > 0),
        "R1CS column 0 (the constant `1`) cannot be a committed value"
    );
    let v_len = committed_indices.len();
    // The R1CS witness indices `1..r1cs_width` get partitioned into v
    // (committed) and x (free internal-wire) slots. Index 0 is the
    // constant `1` and is not represented as a witness wire.
    let non_const_width = r1cs_width.saturating_sub(1);
    let x_len = non_const_width - v_len;
    // Mapping from R1CS column index `j > 0` into either a v slot or an
    // x slot. Stored at `old_to_new[j - 1]`.
    let old_to_new = {
        let mut out = vec![(true, 0usize); non_const_width];
        // What index the current v value is at.
        let mut v_i = 0;
        // What index the current x value is at.
        let mut x_i = 0;
        let mut committed_indices = committed_indices.iter().peekable();
        for (j, out_j) in out.iter_mut().enumerate() {
            let r1cs_index = j + 1;
            let (in_v, counter) = if committed_indices.next_if(|&&k| k == r1cs_index).is_some() {
                (true, &mut v_i)
            } else {
                (false, &mut x_i)
            };
            *out_j = (in_v, *counter);
            *counter += 1;
        }
        out
    };
    // The length of the l, r and o vectors.
    let internal_len = x_len + r1cs.height();
    let witness = witness.map(|(witness, blinding)| {
        debug_assert!(
            witness.first().is_none_or(|w| w == &F::one()),
            "R1CS witness slot 0 must be the constant 1"
        );
        let mut left = &r1cs.a * witness.as_slice();
        let mut right = &r1cs.b * witness.as_slice();
        let mut out = &r1cs.c * witness.as_slice();
        let mut x = vec![F::zero(); x_len];
        let mut values = vec![F::zero(); v_len];
        // Skip the constant slot at index 0; it is implicit in the
        // bulletproof circuit's output position 0.
        for (i, w_i) in witness.into_iter().enumerate().skip(1) {
            let (in_v, i_new) = old_to_new[i - 1];
            let array = if in_v { &mut values } else { &mut x };
            array[i_new] = w_i;
        }
        left.extend(x);
        right.resize(left.len(), F::zero());
        out.resize(left.len(), F::zero());
        Witness::new(values, blinding, left, right, out)
            .expect("should be able to construct witness")
    });
    // We'll build up the weights, row by row.
    let mut weights = SparseMatrix::default();
    weights.pad(1 + v_len + 3 * internal_len, 3 * r1cs.height());
    let minus_one = -F::one();
    // The non-committed witness values `x` are stored in the trailing slots
    // of the LEFT wires region (positions `r1cs_height..r1cs_height + x_len`
    // within that region). The right and out regions only carry the linear
    // combinations of A, B, C with zeros padding the rest, so any lookup of a
    // non-committed witness must go to the LEFT wires region regardless of
    // which matrix (A/B/C) we are currently emitting weights for.
    let x_col_base = 1 + v_len + r1cs_height;
    for (row_start, col_start, m) in [
        (0, 1 + v_len, r1cs.a),
        (r1cs_height, 1 + v_len + internal_len, r1cs.b),
        (2 * r1cs_height, 1 + v_len + 2 * internal_len, r1cs.c),
    ] {
        for ((i, j), m_ij) in m {
            let col = if j == 0 {
                // R1CS column 0 is the constant `1`, which lives at the
                // bulletproof circuit's output position 0.
                0
            } else {
                let (in_v, j_new) = old_to_new[j - 1];
                if in_v {
                    // In this case, we just have a v value, and those start at index 1.
                    j_new + 1
                } else {
                    // Non-committed witness values live in `x`, which is stored
                    // at the tail of the LEFT wires region.
                    x_col_base + j_new
                }
            };
            weights[(row_start + i, col)] = m_ij;
        }
        // Now, add in the weights to force the left, right, resp. out wires
        // to be equal to the linear combinations we've set up above.
        for i in 0..r1cs_height {
            weights[(row_start + i, col_start + i)] = minus_one.clone();
        }
    }
    let circuit = Circuit::new(v_len, weights).expect("circuit construction should succeed");
    (circuit, witness)
}

/// Convert an R1CS into a circuit, treating the witness positions named by
/// `committed_indices` as committed values.
///
/// `committed_indices` must match what the prover passed to
/// [`r1cs_to_circuit_and_witness`], otherwise the resulting [`Circuit`] will
/// not match the prover's and proofs against it will fail.
pub fn r1cs_to_circuit<F: Ring>(r1cs: R1cs<F>, committed_indices: &[usize]) -> Circuit<F> {
    r1cs_to_circuit_maybe_witness(r1cs, committed_indices, None).0
}

/// Convert an R1CS and full R1CS assignment into a circuit and witness.
///
/// The witness vector is the Ark R1CS witness assignment, excluding the
/// constant `1`. The returned witness commits to the values at
/// `committed_indices`.
pub fn r1cs_to_circuit_and_witness<F: Ring + Random>(
    blinding_rng: Option<&mut impl CryptoRngCore>,
    r1cs: R1cs<F>,
    witness: Vec<F>,
    committed_indices: &[usize],
) -> (Circuit<F>, Witness<F>) {
    let blinding = blinding_rng.map_or_else(
        || vec![F::zero(); committed_indices.len()],
        |rng| {
            (0..committed_indices.len())
                .map(|_| F::random(&mut *rng))
                .collect::<Vec<_>>()
        },
    );
    let (circuit, witness) =
        r1cs_to_circuit_maybe_witness(r1cs, committed_indices, Some((witness, blinding)));
    let witness = witness.expect("witness should be present because we passed witness");
    (circuit, witness)
}

/// Generators used by the circuit proof system.
///
/// This wraps the underlying IPA setup and adds two Pedersen generators used
/// for commitments to committed values and blindings.
#[derive(PartialEq)]
pub struct Setup<G> {
    ipa: ipa::Setup<G>,
    value_generator: G,
    blinding_generator: G,
}

impl<G> Setup<G> {
    /// Create a new [`Setup`] from an [`ipa::Setup`] and two Pedersen generators.
    ///
    /// You MUST ensure that all generators are unique.
    pub const fn new(ipa: ipa::Setup<G>, value_generator: G, blinding_generator: G) -> Self {
        Self {
            ipa,
            value_generator,
            blinding_generator,
        }
    }

    pub const fn value_generator(&self) -> &G {
        &self.value_generator
    }

    pub const fn blinding_generator(&self) -> &G {
        &self.blinding_generator
    }

    /// Check if this setup supports claims of a given length.
    pub const fn supports(&self, lg_len: u8) -> bool {
        self.ipa.supports(lg_len)
    }

    /// Construct a [`Setup`] of size `2^lg_len`, deterministically deriving
    /// the IPA generators, the product generator, and the blinding generator
    /// from `domain_separator` via [`HashToGroup`]. The caller supplies the
    /// `value_generator` so external commitments (e.g. `value * G1::generator()`)
    /// can line up with the Pedersen commitments produced by
    /// [`Witness::claim`].
    ///
    /// Each hashed generator is derived with a unique label, so the
    /// discrete-log relations between them are unknown (assuming a properly
    /// modelled hash-to-curve). The caller is responsible for ensuring the
    /// supplied `value_generator` has unknown discrete log relative to the
    /// blinding generator (e.g. by using a system-fixed generator distinct
    /// from any hashed point).
    pub fn hashed(domain_separator: &[u8], lg_len: u8, value_generator: G) -> Self
    where
        G: HashToGroup,
    {
        let n: usize = 1usize << lg_len;
        let product_generator = G::hash_to_group(domain_separator, b"product");
        let blinding_generator = G::hash_to_group(domain_separator, b"blinding");
        let g_and_h = (0..n).map(|i| {
            let i_bytes = (i as u64).to_le_bytes();
            let mut g_msg = Vec::with_capacity(2 + i_bytes.len());
            g_msg.extend_from_slice(b"g/");
            g_msg.extend_from_slice(&i_bytes);
            let mut h_msg = Vec::with_capacity(2 + i_bytes.len());
            h_msg.extend_from_slice(b"h/");
            h_msg.extend_from_slice(&i_bytes);
            (
                G::hash_to_group(domain_separator, &g_msg),
                G::hash_to_group(domain_separator, &h_msg),
            )
        });
        Self::new(
            ipa::Setup::new(product_generator, g_and_h),
            value_generator,
            blinding_generator,
        )
    }

    /// Build the virtual setup and the flat array of concrete generators
    /// used to evaluate any [`Synthetic`] produced against this setup.
    fn build_virtual<F: Field>(&self) -> (Setup<Synthetic<F, G>>, Vec<G>)
    where
        G: Clone,
    {
        let n = self.ipa.g().len();
        let mut gens = Synthetic::<F, G>::generators();
        let vg: Vec<_> = (0..n)
            .map(|_| gens.next().expect("generators is infinite"))
            .collect();
        let vh: Vec<_> = (0..n)
            .map(|_| gens.next().expect("generators is infinite"))
            .collect();
        let vq = gens.next().expect("generators is infinite");
        let ipa_vs = ipa::Setup::new(vq, vg.into_iter().zip(vh));
        let pv = gens.next().expect("generators is infinite");
        let pb = gens.next().expect("generators is infinite");
        let vs = Setup::new(ipa_vs, pv, pb);
        let mut flat = Vec::with_capacity(2 * n + 3);
        flat.extend_from_slice(self.ipa.g());
        flat.extend_from_slice(self.ipa.h());
        flat.push(self.ipa.product_generator().clone());
        flat.push(self.value_generator.clone());
        flat.push(self.blinding_generator.clone());
        (vs, flat)
    }

    /// Build a virtual setup, call `f` to obtain a verification equation,
    /// and evaluate it against the concrete generators in `self`.
    pub fn eval<F: Field>(
        &self,
        f: impl FnOnce(&Setup<Synthetic<F, G>>) -> Option<Synthetic<F, G>>,
        strategy: &impl Strategy,
    ) -> Option<G>
    where
        G: Space<F>,
    {
        let (vs, flat) = self.build_virtual::<F>();
        f(&vs).map(|v| v.eval(&flat, strategy))
    }

    /// Build a virtual setup, call `f` to obtain a list of per-item
    /// verification equations, and check each of them in a way that batches
    /// MSMs as much as possible.
    ///
    /// The strategy is:
    ///
    /// 1. Pre-scale every per-item equation by an independent random scalar
    ///    so that scalar zero-ness is preserved with overwhelming
    ///    probability and any subset sum is sound on its own.
    /// 2. Sum every (scaled) equation into a single [`Synthetic`] and
    ///    evaluate it with **one** MSM. If the result is the group
    ///    identity, every item is valid.
    /// 3. Otherwise, recursively split the failing range in half and
    ///    re-evaluate the sum on each half (still one MSM per check). The
    ///    recursion bottoms out at a single item, at which point any
    ///    remaining failure is attributed to that item.
    ///
    /// This costs one MSM in the all-valid case and `O(k log n)` MSMs when
    /// `k` items are invalid (vs. `n` MSMs for naive per-item checking).
    ///
    /// Returning `None` from `f` indicates that the whole batch is malformed
    /// and produces an outer `None`. Individual `None` entries within the
    /// returned `Vec` indicate that the corresponding item is structurally
    /// invalid; they are reported as `false` in the result without ever
    /// being included in any subset sum.
    pub fn eval_check_batched<F: Field + Random, R: CryptoRngCore>(
        &self,
        rng: &mut R,
        f: impl FnOnce(&Setup<Synthetic<F, G>>, &mut R) -> Option<Vec<Option<Synthetic<F, G>>>>,
        strategy: &impl Strategy,
    ) -> Option<Vec<bool>>
    where
        G: Space<F> + PartialEq,
    {
        let (vs, flat) = self.build_virtual::<F>();
        let synths = f(&vs, &mut *rng)?;
        let n = synths.len();

        // Pre-scale each present synthetic by an independent random scalar.
        // None entries stay None; they are reported as `false` and never
        // contribute to any subset sum.
        let scaled: Vec<Option<Synthetic<F, G>>> = synths
            .into_iter()
            .map(|opt| opt.map(|s| s * &F::random(&mut *rng)))
            .collect();

        // Indices of items eligible for batched checking.
        let active: Vec<usize> = (0..n).filter(|&i| scaled[i].is_some()).collect();

        // Sum the scaled synthetics for `range` and evaluate to a single MSM.
        let check = |range: &[usize]| -> bool {
            let mut acc = Synthetic::<F, G>::default();
            for &i in range {
                acc += scaled[i].as_ref().expect("active indices are Some");
            }
            acc.eval(&flat, strategy) == G::zero()
        };

        // Iterative DFS over contiguous index ranges. A range that checks
        // out marks every contained item as valid; a failing range of
        // length > 1 splits in half; a failing range of length 1 leaves
        // its (single) item marked invalid.
        let mut valid = vec![false; n];
        let mut stack: Vec<&[usize]> = Vec::new();
        if !active.is_empty() {
            stack.push(&active);
        }
        while let Some(range) = stack.pop() {
            if check(range) {
                for &i in range {
                    valid[i] = true;
                }
            } else if range.len() > 1 {
                let mid = range.len() / 2;
                let (left, right) = range.split_at(mid);
                stack.push(right);
                stack.push(left);
            }
        }
        Some(valid)
    }
}

impl<G: Write> Write for Setup<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.ipa.write(buf);
        self.value_generator.write(buf);
        self.blinding_generator.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Setup<G> {
    fn encode_size(&self) -> usize {
        self.ipa.encode_size()
            + self.value_generator.encode_size()
            + self.blinding_generator.encode_size()
    }
}

impl<G: Read> Read for Setup<G>
where
    G::Cfg: Clone,
{
    type Cfg = (usize, G::Cfg);

    fn read_cfg(buf: &mut impl Buf, (max_len, cfg): &Self::Cfg) -> Result<Self, Error> {
        let ipa = ipa::Setup::read_cfg(buf, &(*max_len, cfg.clone()))?;
        let value_generator = G::read_cfg(buf, cfg)?;
        let blinding_generator = G::read_cfg(buf, cfg)?;
        Ok(Self::new(ipa, value_generator, blinding_generator))
    }
}

/// A prover-side assignment for a circuit proof.
///
/// This contains the committed values, their Pedersen blindings, and the
/// internal left, right, and output wire values.
#[allow(dead_code)]
pub struct Witness<F> {
    values: Vec<F>,
    blinding: Vec<F>,
    left: Vec<F>,
    right: Vec<F>,
    out: Vec<F>,
}

impl<F> Witness<F> {
    /// Create a new witness, given all committed values, and internal values.
    ///
    /// This is a very low level method, with the only safety guard being to check
    /// that certain vectors have matching lengths. Beyond that, we don't check
    /// that the values satisfy a circuit relationship, or match the commitments.
    pub fn new(
        values: Vec<F>,
        blinding: Vec<F>,
        left: Vec<F>,
        right: Vec<F>,
        out: Vec<F>,
    ) -> Option<Self> {
        if values.len() != blinding.len() {
            return None;
        }
        if left.len() != right.len() || right.len() != out.len() {
            return None;
        }
        Some(Self {
            values,
            blinding,
            left,
            right,
            out,
        })
    }

    pub fn values(&self) -> &[F] {
        &self.values
    }

    /// Check whether this witness's wires satisfy the given [`Circuit`].
    ///
    /// Useful as a debugging aid: if this returns `false`, the prover and
    /// circuit are inconsistent and any [`prove`] result will not verify.
    #[must_use]
    pub fn is_satisfied(&self, circuit: &Circuit<F>) -> bool
    where
        F: Ring,
    {
        circuit.is_satisfied(&self.values, &self.left, &self.right)
    }

    /// Create the public claim corresponding to this witness for the given setup.
    ///
    /// The resulting claim contains Pedersen commitments to the witness's
    /// committed values and blindings.
    pub fn claim<G: Space<F>>(&self, setup: &Setup<G>) -> Claim<G> {
        Claim {
            commitments: self
                .values
                .iter()
                .zip(&self.blinding)
                .map(|(value, blind)| {
                    setup.value_generator.clone() * value
                        + &(setup.blinding_generator.clone() * blind)
                })
                .collect(),
        }
    }
}

/// The public claim for the protocol.
///
/// The claim consists of Pedersen commitments to values, which the prover claims
/// satisfy a [`Circuit`].
///
/// The claim does not contain the [`Circuit`] itself, so that the verifier is
/// in control of what properties they want the committed values to satisfy.
pub struct Claim<G> {
    pub commitments: Vec<G>,
}

impl<G: Write> Write for Claim<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitments.write(buf);
    }
}

impl<G: EncodeSize> EncodeSize for Claim<G> {
    fn encode_size(&self) -> usize {
        self.commitments.encode_size()
    }
}

/// A proof demonstrating knowledge of a [`Witness`] satisfying a [`Claim`] relative
/// to a [`Circuit`].
///
/// See [`prove`] and [`verify`].
#[allow(dead_code)]
#[derive(Clone)]
pub struct Proof<F, G> {
    m_big: G,
    o_big: G,
    m_big_tilde: G,
    t_big: [G; 5],
    s_tilde: F,
    t_x: F,
    t_tilde_x: F,
    p_big: G,
    ipa_proof: ipa::Proof<F, G>,
}

impl<F: Write, G: Write> Write for Proof<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.m_big.write(buf);
        self.o_big.write(buf);
        self.m_big_tilde.write(buf);
        for t in &self.t_big {
            t.write(buf);
        }
        self.s_tilde.write(buf);
        self.t_x.write(buf);
        self.t_tilde_x.write(buf);
        self.p_big.write(buf);
        self.ipa_proof.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Proof<F, G> {
    fn encode_size(&self) -> usize {
        self.m_big.encode_size()
            + self.o_big.encode_size()
            + self.m_big_tilde.encode_size()
            + self.t_big.iter().map(|t| t.encode_size()).sum::<usize>()
            + self.s_tilde.encode_size()
            + self.t_x.encode_size()
            + self.t_tilde_x.encode_size()
            + self.p_big.encode_size()
            + self.ipa_proof.encode_size()
    }
}

impl<F: Read, G: Read> Read for Proof<F, G>
where
    F::Cfg: Clone,
    G::Cfg: Clone,
{
    /// `(max_len, (g_cfg, f_cfg))` where `max_len` bounds the IPA round count.
    type Cfg = (usize, (G::Cfg, F::Cfg));

    fn read_cfg(buf: &mut impl Buf, cfg @ (_, (g_cfg, f_cfg)): &Self::Cfg) -> Result<Self, Error> {
        let m_big = G::read_cfg(buf, g_cfg)?;
        let o_big = G::read_cfg(buf, g_cfg)?;
        let m_big_tilde = G::read_cfg(buf, g_cfg)?;
        let t_big = [
            G::read_cfg(buf, g_cfg)?,
            G::read_cfg(buf, g_cfg)?,
            G::read_cfg(buf, g_cfg)?,
            G::read_cfg(buf, g_cfg)?,
            G::read_cfg(buf, g_cfg)?,
        ];
        let s_tilde = F::read_cfg(buf, f_cfg)?;
        let t_x = F::read_cfg(buf, f_cfg)?;
        let t_tilde_x = F::read_cfg(buf, f_cfg)?;
        let p_big = G::read_cfg(buf, g_cfg)?;
        let ipa_proof = ipa::Proof::read_cfg(buf, cfg)?;
        Ok(Self {
            m_big,
            o_big,
            m_big_tilde,
            t_big,
            s_tilde,
            t_x,
            t_tilde_x,
            p_big,
            ipa_proof,
        })
    }
}

/// Prove that a given [`Witness`] satisfies a [`Circuit`] and matches a [`Claim`].
///
/// The proof is bound to the transcript state at the time of the call, so the
/// verifier must replay the same transcript history before verification.
///
/// This returns `None` if the setup does not support the circuit size, if the
/// witness lengths are inconsistent with the circuit, or if the claim does not
/// match the witness.
pub fn prove<F: Field + Encode + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<G>,
    circuit: &Circuit<F>,
    claim: &Claim<G>,
    witness: &Witness<F>,
    strategy: &impl Strategy,
) -> Option<Proof<F, G>> {
    // To set the stage, we're trying to convince the verifier that:
    //
    //   - we know v_i, ~v_i, l_i, r_i, o_i such that...
    //   - v_i B + ~v_i ~B = V_i,
    //   - l_i r_i = o_i,
    //   - c_i + <Θ_ij, v_j> + <Λ_ij, l_j> + <Ρ_ij, r_j> + <Ω_ij, o_j> = 0.
    //
    // Before we get back any challenges from the verifier, we need to commit to
    // the circuit, our claim, and the internal variables we're using. We create a commitment:
    //
    //   M := <l_i, G_i> + <r_i, H_i> + m ~B
    //   O := <o_i, G_i> + ~o ~B
    //
    // we'll also be introducing some blinding factors ~l_i, ~r_i later, and we need
    // to commit to these now as well:
    //
    //   ~M := <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // After sending all of these to the verifier, we get:
    // y, and z, which we use to reduce the constraints to:
    //
    //   <y^i, l_i r_i - o_i> +
    //   <z z^i, c_i + <Θ_ij, v_j> + <Λ_ij, l_j> + <Ρ_ij, r_j> + <Ω_ij, o_j>> = 0
    //
    // (By y^i, we mean a vector whose ith entry is y to the power of i. For small fields,
    // generating more challenges is needed instead, but for large fields, using powers lets us
    // sample less randomness.)
    //
    // At this point, it's convenient to fold these challenges into the weights:
    //
    //   θ_j := <Θ_ij, z z^i>
    //   λ_j := <Λ_ij, z z^i>
    //   ρ_j := <Ρ_ij, z z^i>
    //   ω_j := <Ω_ij, z z^i>
    //   κ := <c_i, z z^i>
    //
    // giving us:
    //
    //   <y^i, l_i r_i - o_i> + κ + <θ_i, v_i> + <λ_i, l_i> + <ρ_i, r_i> + <ω_i, o_i> = 0
    //
    // It's useful to have the terms concerning the committed variables on one side,
    // and the internal variables on the other:
    //
    //   -κ - <θ_i, v_i> = <y^i, l_i r_i - o_i> + <λ_i, l_i> + <ρ_i, r_i> + <ω_i, o_i>
    //
    // next, merge the terms with o_i:
    //
    //  ... = <y^i, l_i r_i> + ... + <ω_i - y^i, o_i>
    //
    // next, we can move one part of the l_i r_i term to the other side:
    //
    //   ... = <y^i r_i, l_i> + ...
    //
    // then, we can create another y^i r_i term:
    //
    //   ... = ... + <y^-i ρ_i, y^i r_i> + ...
    //
    // merging these terms we get:
    //
    //   -κ - <θ_i, v_i> = <l_i + y^-i ρ_i, y^i r_i> + <λ_i, l_i> + <ω_i - y^i, o_i>
    //
    // if we define:
    //
    //   δ(y, z) := <y^-i ρ_i, λ_i>
    //
    // we can add this to both sides, and merge the λ_i terms, giving us:
    //
    //  -κ - <θ_i, v_i> + δ(y, z) =
    //  <l_i + y^-i ρ_i, y^i r_i> + <l_i + y^-i ρ_i, λ_i> + <ω_i - y^i, o_i> =
    //  <l_i + y^-i ρ_i, y^i r_i + λ_i> + <ω_i - y^i, o_i>
    //
    // Now, we deploy a trick, in order to turn a statement about a sum:
    //
    //   <a_i, b_i> + <c_i, d_i>
    //
    // into a single inner product. The trick is that if we create polynomials:
    //
    //   f_i(X) := a_i X + c_i X^2
    //   g_i(X) := b_i X + d_i
    //
    // then the 2nd degree of <f_i(X), g_i(X)> is <a_i, b_i> + <c_i, d_i>.
    //
    // So, we can check that:
    //
    //   t X^2 = <f_i(X), g_i(X)>
    //
    // as polynomials. To check equality of polynomials, we can commit to them,
    // and then have the verifier send us a random evaluation point.
    //
    // Let's apply that to our situation.
    //
    //   f_i(X) := (l_i + y^-i ρ_i) X + o_i X^2
    //   g_i(X) := (y^i r_i + λ_i) X + (ω_i - y^i)
    //   t(X) := <f_i(X), g_i(X)>
    //   deg2(t(X)) = -κ - <θ_i, v_i> + δ(y, z)
    //
    // Our goal at this point is to convince the verifier that:
    //
    //   - deg2(t(X)) = -κ - <θ_i, v_i> + δ(y, z),
    //   - f_i(X) and g_i(X) are correctly constructed,
    //   - t(X) = <f_i(X), g_i(X)>.
    //
    // We want to make sure that our proof is still zero-knowledge, so we can't just
    // send a commitment to the polynomial as is, because it leaks information about
    // the l_i, r_i, and o_i values. To get around this, we introduce blinding factors
    // ~l_i, ~r_i:
    //
    //   f_i(X) := ((l_i + ~l_i X^2) + y^-i ρ_i) X + o_i X^2
    //   g_i(X) := (y^i (r_i + ~r_i X^2) + λ_i) X + (ω_i - y^i)
    //
    // we use a factor of X^2 so that this blinding doesn't interfere with the
    // second degree of <f_i(X), g_i(X)>. When the verifier sees f_i(x) and g_i(x)
    // for a random challenge point, they will have a masking factor of ~l_i x^3
    // (respectively, y^i ~r_i x^3), hiding things completely.
    //
    // Expanding this out, we get:
    //
    //   t(X) := <f_i(X), g_i(X)> =
    //   <l_i + y^-i ρ_i, ω_i - y^i> X +
    //   (<l_i + y^-i ρ_i, y^i r_i + λ_i> + <o_i, ω_i - y^i>) X^2 +
    //   (<~l_i, ω_i - y^i> + <o_i, y^i r_i + λ_i>) X^3 +
    //   (<~l_i, y^i r_i + λ_i> + <l_i + y^-i ρ_i, y^i ~r_i>) X^4 +
    //   <o_i, y^i ~r_i> X^5 +
    //   <~l_i, y^i ~r_i> X^6
    //
    // thus, we can create commitments T_1, T_3, T_4, T_5, T_6 to these elements,
    // (skipping the X^2 factor), using blinding factors ~t_i.
    //
    // Then, for a random challenge, x, the verifier can check that the second degree is correct:
    //
    //  t(x) B + ~t(x) ~B =?
    //  (-κ + δ(y, z)) x^2 B - x^2 <θ_i, V_i> + Σ_{i != 2} x^i T_i
    //
    // for ~t(x), we use the synthetic blinding factors ~t_i for x^1, x^3, ...
    // and for x^2, we use -<θ_i, ~v_i>, so that the equation above works.
    //
    // The right hand side is checking the second degree in the exponent, behind
    // the Pedersen commitments, and the left hand side is our opening of the polynomial,
    // at a random point.
    //
    // Before getting this challenge, we also want to provide the necessary commitments
    // to f_i(X) and g_i(X) as well, so that those can be checked.
    //
    // Eventually, we want to prove the inner product <f_i(x), g_i(x)>, and the IPA
    // protocol expects to see <f_i(x), G_i> + <g_i(x), H_i>. Expanding that, out,
    // using the indeterminate X (rather than the challenge x), we get:
    //
    //   <f_i(X), G_i> = <l_i + y^-i ρ_i, G_i> X + <o_i, G_i> X^2 + <~l_i, G_i> X^3
    //   <g_i(X), H_i> = <ω_i - y^i, H_i> + <y^i r_i + λ_i, H_i> X + <y^i ~r_i, H_i> X^3
    //
    // The natural commitments involve grouping things by coefficient, and by public
    // vs secret values:
    //
    //   P_0 := <ω_i - y^i, H_i>
    //   P_1 := <y^-i ρ_i, G_i> + <λ_i, H_i>
    //   S_1 := <l_i, G_i> + <y^i r_i, H_i>
    //   S_2 := <o_i, G_i>
    //   S_3 := <~l_i, G_i> + <y^i ~r_i, H_i>
    //
    // Recall that we've already sent the verifier:
    //
    //   M := <l_i, G_i> + <r_i, H_i> + m ~B
    //   O := <o_i, G_i> + ~o ~B
    //  ~M := <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // It seems like we're stuck here, because <r_i, H_i> doesn't match the <y^i r_i, H_i>
    // that we need inside of S_1. However, the IPA already lets us treat the right-side
    // basis as y^-i H_i by setting claim.y = y^-1. In terms of the original H_i that this
    // implementation uses in its MSMs, the public pieces become:
    //
    //   P_0 = <y^-i ω_i - 1, H_i>
    //   P_1 = <y^-i ρ_i, G_i> + <y^-i λ_i, H_i>
    //   M   = <l_i, G_i> + <r_i, H_i> + m ~B
    //   O   = <o_i, G_i> + ~o ~B
    //  ~M   = <~l_i, G_i> + <~r_i, H_i> + ~m ~B
    //
    // but, the bottom three are equal to:
    //
    //   M = S_1 +  m ~B
    //   O = S_2 + ~o ~B
    //  ~M = S_3 + ~m ~B
    //
    // Thus, we can reveal ~s := x m + x^2 ~o + x^3 ~m, and have the verifier calculate
    //
    //   P := -~s ~B + P_0 + x (P_1 + M) + x^2 O + x^3 ~M
    //      = <f_i(x), G_i> + <g_i(x), y^-i H_i>
    //
    // (Rather than the verifier calculating this, the prover can provide it, and the verifier
    // can check this equation. This turns it into an MSM check, which can be more efficiently
    // combined with other such checks).
    //
    // Finally, we run the IPA protocol, using t(x) as the claimed inner product,
    // and P as the commitment to the vectors, and G_i, H'_i as the generators
    // for this commitment.
    //
    // Concretely, we reuse the ordinary IPA setup and set ipa_claim.y = y^-1.
    // This keeps the right-side basis change inside the IPA, while the public MSM
    // checks above stay written against the original H_i.
    //
    // # Padding
    //
    // The IPA protocol requires the input vectors to be padded to a power of 2.
    // To do this, we'll pad the l_i, r_i, ~l_i, ~r_i with 0s. This forces the
    // o_i to be padded with 0 as well. In order to explicitly not consider these
    // values, we make sure that the weights are padded with columns of 0s.
    // Because we compress the weight matrices into vectors by taking a combination
    // of rows, we can pad the resulting vectors with 0s.
    //
    // Looking at t(X), the value doesn't change with the padding, because we always
    // have a zero value on one side of each inner product for the new indices.
    //
    // P_0 on the other hand, will end up with some extra -1 values we'll have
    // to take into account. Because this is the only changed value, we can handle
    // this one as a special case.
    //
    // Now, let's write some Rust.
    //
    // First, let's commit to our internal variables, and to our masks:
    let l_tilde = (0..circuit.internal_vars)
        .map(|_| F::random(&mut *rng))
        .collect::<Vec<_>>();
    let r_tilde = (0..circuit.internal_vars)
        .map(|_| F::random(&mut *rng))
        .collect::<Vec<_>>();
    let m = F::random(&mut *rng);
    let o_tilde = F::random(&mut *rng);
    let m_tilde = F::random(&mut *rng);
    let g_internal = &setup.ipa.g()[..circuit.internal_vars];
    let h_internal = &setup.ipa.h()[..circuit.internal_vars];
    let m_big = G::msm(g_internal, &witness.left, strategy)
        + &G::msm(h_internal, &witness.right, strategy)
        + &(setup.blinding_generator.clone() * &m);
    let o_big =
        G::msm(g_internal, &witness.out, strategy) + &(setup.blinding_generator.clone() * &o_tilde);
    let m_big_tilde = G::msm(g_internal, &l_tilde, strategy)
        + &G::msm(h_internal, &r_tilde, strategy)
        + &(setup.blinding_generator.clone() * &m_tilde);
    // Now, commit to all the this information.
    circuit.commit(transcript);
    transcript.commit(claim.encode());
    transcript.commit(m_big.encode());
    transcript.commit(o_big.encode());
    transcript.commit(m_big_tilde.encode());
    let padded_vars = circuit.internal_vars.next_power_of_two();
    let y = F::random(transcript.noise(b"y"));
    let y_powers = powers(F::one(), &y).take(padded_vars).collect::<Vec<_>>();
    let y_inv = y.inv();
    let y_inv_powers = powers(F::one(), &y_inv)
        .take(padded_vars)
        .collect::<Vec<_>>();
    let z = F::random(transcript.noise(b"z"));
    let z_powers = powers(z.clone(), &z)
        .take(circuit.weights.height())
        .collect::<Vec<_>>();
    let (kappa, theta, lambda, rho, omega) = {
        let mut kappa = F::zero();
        let mut theta = vec![F::zero(); circuit.committed_vars];
        let mut lambda = vec![F::zero(); circuit.internal_vars];
        let mut rho = vec![F::zero(); circuit.internal_vars];
        let mut omega = vec![F::zero(); circuit.internal_vars];
        let theta_start = 1;
        let lambda_start = theta_start + circuit.committed_vars;
        let rho_start = lambda_start + circuit.internal_vars;
        let omega_start = rho_start + circuit.internal_vars;
        for (&(i, j), w_ij) in &circuit.weights.weights {
            let w_ij = w_ij.clone();
            if j >= omega_start {
                omega[j - omega_start] += &(w_ij * &z_powers[i]);
            } else if j >= rho_start {
                rho[j - rho_start] += &(w_ij * &z_powers[i]);
            } else if j >= lambda_start {
                lambda[j - lambda_start] += &(w_ij * &z_powers[i]);
            } else if j >= theta_start {
                theta[j - theta_start] += &(w_ij * &z_powers[i]);
            } else {
                kappa += &(w_ij * &z_powers[i]);
            }
        }
        (kappa, theta, lambda, rho, omega)
    };

    // We cache a few quantities, which we'll need for MSMs later anyways.
    let mut omega_minus_y = omega
        .iter()
        .cloned()
        .zip(&y_powers)
        .map(|(omega_i, y_i)| omega_i - y_i)
        .collect::<Vec<_>>();
    omega_minus_y.extend(
        y_powers
            .iter()
            .skip(circuit.internal_vars)
            .cloned()
            .map(|y_i| -y_i),
    );
    let y_inv_rho = y_inv_powers
        .iter()
        .cloned()
        .zip(&rho)
        .map(|(y_inv_i, rho_i)| y_inv_i * rho_i)
        .collect::<Vec<_>>();
    let y_inv_lambda = y_inv_powers
        .iter()
        .cloned()
        .zip(&lambda)
        .map(|(y_inv_i, lambda_i)| y_inv_i * lambda_i)
        .collect::<Vec<_>>();
    let y_inv_omega_minus_y = y_inv_powers
        .iter()
        .cloned()
        .zip(&omega_minus_y)
        .map(|(y_inv_i, omega_minus_y_i)| y_inv_i * omega_minus_y_i)
        .collect::<Vec<_>>();
    let y_r = y_powers
        .iter()
        .cloned()
        .zip(&witness.right)
        .map(|(y_i, r_i)| y_i * r_i)
        .collect::<Vec<_>>();
    let y_r_tilde = y_powers
        .iter()
        .cloned()
        .zip(&r_tilde)
        .map(|(y_i, r_i)| y_i * r_i)
        .collect::<Vec<_>>();

    let delta_y_z = <F as Space<F>>::msm(&y_inv_rho, &lambda, strategy);

    // t_1, t_2, t_3, t_4, t_5, t_6
    let t = {
        let mut t = std::array::from_fn::<_, 6, _>(|_| F::zero());
        // t_1
        for i in 0..circuit.internal_vars {
            t[0] += &((witness.left[i].clone() + &y_inv_rho[i]) * &omega_minus_y[i]);
        }
        // t_2
        t[1] = delta_y_z - &kappa - &<F as Space<F>>::msm(&theta, &witness.values, strategy);
        // t_3
        for i in 0..circuit.internal_vars {
            t[2] += &(l_tilde[i].clone() * &omega_minus_y[i]);
            t[2] += &(witness.out[i].clone() * &(y_r[i].clone() + &lambda[i]));
        }
        // t_4
        for i in 0..circuit.internal_vars {
            t[3] += &(l_tilde[i].clone() * &(y_r[i].clone() + &lambda[i]));
            t[3] += &((witness.left[i].clone() + &y_inv_rho[i]) * &y_r_tilde[i]);
        }
        // t_5
        t[4] = <F as Space<F>>::msm(&witness.out, &y_r_tilde, strategy);
        // t_6
        t[5] = <F as Space<F>>::msm(&l_tilde, &y_r_tilde, strategy);
        t
    };
    let t_tilde = std::array::from_fn::<_, 6, _>(|i| {
        if i == 1 {
            -<F as Space<F>>::msm(&theta, &witness.blinding, strategy)
        } else {
            F::random(&mut *rng)
        }
    });
    let t_big = std::array::from_fn::<_, 5, _>(|i| {
        // Skip the second element
        let i = if i >= 1 { i + 1 } else { i };
        setup.value_generator.clone() * &t[i] + &(setup.blinding_generator.clone() * &t_tilde[i])
    });

    // The IPA generators may be larger than `padded_vars` for setups that
    // support multiple circuit sizes. Restrict to the prefix actually used.
    let p_0 = G::msm(
        &setup.ipa.h()[..padded_vars],
        &y_inv_omega_minus_y,
        strategy,
    );
    let h_internal = &setup.ipa.h()[..circuit.internal_vars];
    let p_1 =
        G::msm(g_internal, &y_inv_rho, strategy) + &G::msm(h_internal, &y_inv_lambda, strategy);

    // Now, we can commit the t commitments, along with the secret commitments.
    // The public commitments will be recomputed by the verifier.
    for t_big_i in &t_big {
        transcript.commit(t_big_i.encode());
    }
    let x = F::random(transcript.noise(b"x"));
    let x = powers(x.clone(), &x).take(6).collect::<Vec<_>>();
    let s_tilde = m * &x[0] + &(o_tilde * &x[1]) + &(m_tilde * &x[2]);
    let p = setup.blinding_generator.clone() * &(-s_tilde.clone())
        + &p_0
        + &((p_1 + &m_big) * &x[0])
        + &(o_big.clone() * &x[1])
        + &(m_big_tilde.clone() * &x[2]);
    let t_x = <F as Space<F>>::msm(&t, &x, strategy);
    let t_tilde_x = <F as Space<F>>::msm(&t_tilde, &x, strategy);
    let ipa_claim = ipa::Claim {
        commitment: p.clone(),
        product: t_x.clone(),
        y: y_inv,
        log_len: padded_vars.ilog2().try_into().ok()?,
    };
    let mut f_x = (0..circuit.internal_vars)
        .map(|i| {
            (witness.left[i].clone() + &y_inv_rho[i]) * &x[0]
                + &(witness.out[i].clone() * &x[1])
                + &(l_tilde[i].clone() * &x[2])
        })
        .collect::<Vec<_>>();
    f_x.resize(padded_vars, F::zero());
    let mut g_x = (0..circuit.internal_vars)
        .map(|i| {
            (y_r[i].clone() + &lambda[i]) * &x[0]
                + &omega_minus_y[i]
                + &(y_r_tilde[i].clone() * &x[2])
        })
        .collect::<Vec<_>>();
    g_x.extend_from_slice(&omega_minus_y[circuit.internal_vars..]);
    let witness = ipa::Witness::new(f_x.into_iter().zip(g_x))?;
    let ipa_proof = ipa::prove(transcript, &setup.ipa, &ipa_claim, witness, strategy)?;
    Some(Proof {
        m_big,
        o_big,
        m_big_tilde,
        t_big,
        s_tilde,
        t_x,
        t_tilde_x,
        p_big: p,
        ipa_proof,
    })
}

/// Construct the verification equation for a circuit proof.
///
/// The returned [`Synthetic`] should evaluate to zero for a correct proof.
/// Use [`Setup::eval`] to create the virtual setup and evaluate the result.
///
/// The extra randomness is used to compress the circuit-specific checks into a
/// single equation before combining them with the inner product argument.
pub fn verify<F: Field + Encode + Random, G: CryptoGroup<Scalar = F> + Encode>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    setup: &Setup<Synthetic<F, G>>,
    circuit: &Circuit<F>,
    claim: &Claim<G>,
    proof: Proof<F, G>,
    strategy: &impl Strategy,
) -> Option<Synthetic<F, G>> {
    let Proof {
        m_big,
        o_big,
        m_big_tilde,
        t_big,
        s_tilde,
        t_x,
        t_tilde_x,
        ipa_proof,
        p_big: p,
    } = proof;
    circuit.commit(transcript);
    transcript.commit(claim.encode());
    transcript.commit(m_big.encode());
    transcript.commit(o_big.encode());
    transcript.commit(m_big_tilde.encode());
    let padded_vars = circuit.internal_vars.next_power_of_two();
    let y = F::random(transcript.noise(b"y"));
    let y_powers = powers(F::one(), &y).take(padded_vars).collect::<Vec<_>>();
    let y_inv = y.inv();
    let y_inv_powers = powers(F::one(), &y_inv)
        .take(padded_vars)
        .collect::<Vec<_>>();
    let z = F::random(transcript.noise(b"z"));
    let z_powers = powers(z.clone(), &z)
        .take(circuit.weights.height())
        .collect::<Vec<_>>();
    let (kappa, theta, lambda, rho, omega) = {
        let mut kappa = F::zero();
        let mut theta = vec![F::zero(); circuit.committed_vars];
        let mut lambda = vec![F::zero(); circuit.internal_vars];
        let mut rho = vec![F::zero(); circuit.internal_vars];
        let mut omega = vec![F::zero(); circuit.internal_vars];
        let theta_start = 1;
        let lambda_start = theta_start + circuit.committed_vars;
        let rho_start = lambda_start + circuit.internal_vars;
        let omega_start = rho_start + circuit.internal_vars;
        for (&(i, j), w_ij) in &circuit.weights.weights {
            let w_ij = w_ij.clone();
            if j >= omega_start {
                omega[j - omega_start] += &(w_ij * &z_powers[i]);
            } else if j >= rho_start {
                rho[j - rho_start] += &(w_ij * &z_powers[i]);
            } else if j >= lambda_start {
                lambda[j - lambda_start] += &(w_ij * &z_powers[i]);
            } else if j >= theta_start {
                theta[j - theta_start] += &(w_ij * &z_powers[i]);
            } else {
                kappa += &(w_ij * &z_powers[i]);
            }
        }
        (kappa, theta, lambda, rho, omega)
    };

    // We cache a few quantities, which we'll need for MSMs later anyways.
    let mut omega_minus_y = omega
        .iter()
        .cloned()
        .zip(&y_powers)
        .map(|(omega_i, y_i)| omega_i - y_i)
        .collect::<Vec<_>>();
    omega_minus_y.extend(
        y_powers
            .iter()
            .skip(circuit.internal_vars)
            .cloned()
            .map(|y_i| -y_i),
    );
    let y_inv_rho = y_inv_powers
        .iter()
        .cloned()
        .zip(&rho)
        .map(|(y_inv_i, rho_i)| y_inv_i * rho_i)
        .collect::<Vec<_>>();
    let y_inv_lambda = y_inv_powers
        .iter()
        .cloned()
        .zip(&lambda)
        .map(|(y_inv_i, lambda_i)| y_inv_i * lambda_i)
        .collect::<Vec<_>>();
    let y_inv_omega_minus_y = y_inv_powers
        .iter()
        .cloned()
        .zip(&omega_minus_y)
        .map(|(y_inv_i, omega_minus_y_i)| y_inv_i * omega_minus_y_i)
        .collect::<Vec<_>>();

    let delta_y_z = <F as Space<F>>::msm(&y_inv_rho, &lambda, strategy);

    for t_big_i in &t_big {
        transcript.commit(t_big_i.encode());
    }
    let x = F::random(transcript.noise(b"x"));
    let x = powers(x.clone(), &x).take(6).collect::<Vec<_>>();

    let ipa_g = setup.ipa.g();
    let ipa_h = setup.ipa.h();

    let value_generator = &setup.value_generator;
    let blinding_generator = &setup.blinding_generator;

    let t_check = Synthetic::msm(
        &[value_generator.clone(), blinding_generator.clone()],
        &[t_x.clone(), t_tilde_x],
        &Sequential,
    ) - &(value_generator.clone() * &((-kappa + &delta_y_z) * &x[1]))
        + &(Synthetic::concrete(theta.iter().cloned().zip(claim.commitments.iter().cloned()))
            * &x[1])
        - &Synthetic::concrete(std::iter::once(&x[0]).chain(&x[2..]).cloned().zip(t_big));

    let p_check = {
        // Match the prover: only the first `padded_vars` generators are used.
        let p_0 = Synthetic::msm(&ipa_h[..padded_vars], &y_inv_omega_minus_y, &Sequential);
        let p_1 = Synthetic::msm(&ipa_g[..circuit.internal_vars], &y_inv_rho, &Sequential)
            + &Synthetic::msm(&ipa_h[..circuit.internal_vars], &y_inv_lambda, &Sequential);
        Synthetic::concrete([
            (F::one(), p.clone()),
            (-x[0].clone(), m_big),
            (-x[1].clone(), o_big),
            (-x[2].clone(), m_big_tilde),
        ]) - &p_0
            - &(p_1 * &x[0])
            + &(blinding_generator.clone() * &s_tilde)
    };

    let ipa_claim = ipa::Claim {
        commitment: p,
        product: t_x,
        y: y_inv,
        log_len: padded_vars
            .ilog2()
            .try_into()
            .expect("should be less than 2^256 rows"),
    };

    let ipa_check = ipa::verify(transcript, &setup.ipa, &ipa_claim, ipa_proof)?;

    let final_check =
        ipa_check + &(p_check * &F::random(&mut *rng)) + &(t_check * &F::random(&mut *rng));
    Some(final_check)
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::{
        algebra::{Additive, Ring},
        test::{F, G},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::sync::OnceLock;

    const NUM_GENERATORS: usize = 5;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_CIRCUIT";

    pub(super) fn test_setup() -> &'static Setup<G> {
        static TEST_SETUP: OnceLock<Setup<G>> = OnceLock::new();
        TEST_SETUP.get_or_init(|| {
            let generators = (1..=NUM_GENERATORS)
                .map(|i| G::generator() * &F::from(i as u8))
                .collect::<Vec<_>>();
            Setup::new(
                ipa::Setup::new(
                    generators[0],
                    generators[1..3]
                        .chunks_exact(2)
                        .map(|chunk| (chunk[0], chunk[1])),
                ),
                generators[3],
                generators[4],
            )
        })
    }

    fn quadratic_value(a: F, b: F, c: F, x: F) -> F {
        a * &x * &x + &(b * &x) + &c
    }

    fn quadratic_circuit(a: F, b: F, c: F) -> Circuit<F> {
        let mut weights = SparseMatrix::default();

        // Bind l_0 = x.
        weights[(0, 1)] = F::one();
        weights[(0, 3)] = -F::one();

        // Bind r_0 = x.
        weights[(1, 1)] = F::one();
        weights[(1, 4)] = -F::one();

        // Enforce y = a x^2 + b x + c.
        weights[(2, 0)] = c;
        weights[(2, 1)] = b;
        weights[(2, 2)] = -F::one();
        weights[(2, 5)] = a;

        Circuit::new(2, weights).expect("quadratic circuit layout should be valid")
    }

    struct Case {
        circuit: Circuit<F>,
        witness: Witness<F>,
    }

    impl Case {
        fn prove(&self, setup: &Setup<G>) -> (Claim<G>, Proof<F, G>) {
            let mut rng = test_rng();
            let mut transcript = Transcript::new(NAMESPACE);
            let claim = self.witness.claim(setup);
            let proof = super::prove(
                &mut rng,
                &mut transcript,
                setup,
                &self.circuit,
                &claim,
                &self.witness,
                &Sequential,
            )
            .expect("generated case should always create a proof");
            (claim, proof)
        }

        fn is_satisfied(&self) -> bool {
            self.circuit.is_satisfied(
                &self.witness.values,
                &self.witness.left,
                &self.witness.right,
            )
        }

        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            let a = u.arbitrary::<F>()?;
            let b = u.arbitrary::<F>()?;
            let c = u.arbitrary::<F>()?;
            let x = u.arbitrary::<F>()?;
            let valid = u.arbitrary::<bool>()?;
            let mut y = quadratic_value(a, b, c, x);
            if !valid {
                let mut tweak = u.arbitrary::<F>()?;
                if tweak == F::zero() {
                    tweak = F::one()
                }
                y += &tweak;
            }

            let x_sq = x * &x;
            let witness = Witness::new(
                vec![x, y],
                vec![u.arbitrary::<F>()?, u.arbitrary::<F>()?],
                vec![x],
                vec![x],
                vec![x_sq],
            )
            .expect("quadratic witness should have matching vector lengths");
            let circuit = quadratic_circuit(a, b, c);
            let out = Self { circuit, witness };
            assert_eq!(
                out.is_satisfied(),
                valid,
                "quadratic case should match requested validity",
            );
            Ok(out)
        }
    }

    pub struct Plan {
        case: Case,
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                case: Case::arbitrary(u)?,
            })
        }
    }

    fn assert_verify_matches_satisfaction(case: &Case) {
        let mut rng = test_rng();
        let setup = test_setup();
        let (claim, proof) = case.prove(setup);
        let mut transcript = Transcript::new(NAMESPACE);
        let verified = setup
            .eval(
                |vs| {
                    verify(
                        &mut rng,
                        &mut transcript,
                        vs,
                        &case.circuit,
                        &claim,
                        proof,
                        &Sequential,
                    )
                },
                &Sequential,
            )
            .map(|g| g == G::zero())
            .unwrap_or(false);
        assert_eq!(verified, case.is_satisfied());
    }

    impl Plan {
        pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            assert_verify_matches_satisfaction(&self.case);
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{fuzz, r1cs_to_circuit, Circuit, R1cs, Setup, SparseMatrix, Witness};
    use commonware_codec::{Decode, Encode};
    use commonware_invariants::minifuzz;
    use commonware_math::{
        algebra::{Additive, Ring},
        test::{F, G},
    };

    #[test]
    fn test_random_r1cs_minifuzz() {
        const N: usize = 2;
        const M: usize = 4;

        minifuzz::test(|u| {
            let a = u.arbitrary::<[[F; N]; M]>()?;
            let b = u.arbitrary::<[[F; N]; M]>()?;
            let c = u.arbitrary::<[[F; N]; M]>()?;
            let z = u.arbitrary::<[F; N]>()?;
            let mut left = [F::zero(); M];
            let mut right = [F::zero(); M];
            let mut satisfied = true;
            for i in 0..M {
                let mut acc = F::zero();
                for j in 0..N {
                    left[i] += &(a[i][j] * &z[j]);
                    right[i] += &(b[i][j] * &z[j]);
                    acc += &(c[i][j] * &z[j]);
                }
                satisfied = satisfied && acc == left[i] * &right[i];
            }
            let mut k = 0;
            let mut weights = SparseMatrix::default();

            // Bind the left values:
            for i in 0..M {
                weights[(k, 1 + N + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = a[i][j];
                }
                k += 1;
            }
            // Bind the right values:
            for i in 0..M {
                weights[(k, 1 + N + M + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = b[i][j];
                }
                k += 1;
            }
            // Bind the product values:
            for i in 0..M {
                weights[(k, 1 + N + 2 * M + i)] = -F::one();
                for j in 0..N {
                    weights[(k, 1 + j)] = c[i][j];
                }
                k += 1;
            }
            assert_eq!(
                satisfied,
                Circuit::new(N, weights)
                    .expect("should be able to make circuit")
                    .is_satisfied(&z, &left, &right)
            );
            Ok(())
        });
    }

    #[test]
    fn test_setup_roundtrip() {
        let setup = fuzz::test_setup();
        let encoded = setup.encode();
        let decoded: Setup<G> = Setup::decode_cfg(encoded.clone(), &(setup.ipa.g().len(), ()))
            .expect("setup should decode with its own length bound");
        assert!(setup == &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn test_fuzz() {
        minifuzz::test(|u| {
            u.arbitrary::<fuzz::Plan>()?.run(u)?;
            Ok(())
        });
    }

    /// Regression test for an R1CS-to-circuit conversion soundness bug:
    /// `r1cs_to_circuit` did not preserve the constant column `z_0 = 1`
    /// of the Arkworks-style R1CS witness. R1CS column 0 was being
    /// routed to a free internal wire (`x[0]`) of the bulletproof
    /// circuit instead of the circuit's hard-coded constant column
    /// (output position 0), letting a malicious prover pick `z_0`
    /// freely and trivially satisfy any constraint that depended on
    /// the constant.
    ///
    /// Here we encode the R1CS constraint
    ///
    /// ```text
    /// (z_0 + z_1) * z_0 = 4 * z_0
    /// ```
    ///
    /// Under the standard `z_0 = 1` convention, the only satisfying
    /// assignment has `z_1 = 3`. We treat `z_1` as a committed value,
    /// build the verifier-side circuit, and confirm that a maliciously
    /// hand-crafted witness corresponding to `z_0 = 0`, `z_1 = 0` is
    /// rejected.
    #[test]
    fn r1cs_to_circuit_enforces_constant_column() {
        // R1CS over F: (z_0 + z_1) * z_0 = 4 * z_0
        let mut a = SparseMatrix::<F>::default();
        a[(0, 0)] = F::one();
        a[(0, 1)] = F::one();
        let mut b = SparseMatrix::<F>::default();
        b[(0, 0)] = F::one();
        let mut c = SparseMatrix::<F>::default();
        c[(0, 0)] = F::from(4u8);
        let r1cs = R1cs { a, b, c };

        // Treat z_1 (R1CS column 1) as the committed value.
        let circuit = r1cs_to_circuit(r1cs, &[1usize]);

        // Hand-craft a witness as a malicious prover would: commit to
        // `v[0] = 0` (i.e. `z_1 = 0`) and pretend every internal wire
        // is zero. Under the standard `z_0 = 1` convention this would
        // violate the R1CS (the only honest solution is `z_1 = 3`).
        let malicious = Witness::new(
            vec![F::zero()], // v = [z_1] = [0]
            vec![F::zero()], // blinding
            vec![F::zero()], // left wires
            vec![F::zero()], // right wires
            vec![F::zero()], // out wires
        )
        .expect("witness lengths must match the circuit");

        assert!(
            !malicious.is_satisfied(&circuit),
            "circuit derived from an R1CS that depends on the constant \
             column must reject witnesses corresponding to z_0 != 1"
        );
    }
}
