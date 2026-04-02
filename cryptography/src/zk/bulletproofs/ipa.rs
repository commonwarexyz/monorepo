//! # References
//!
//! The [Dalek crate](https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html)
//! was an invaluable reference when implementing and documenting this module.

use crate::transcript::Transcript;
use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, Field, Random, Space};
use commonware_parallel::Strategy;

pub struct Setup<G> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub product_generator: G,
}

pub struct Statement<F, G> {
    pub commitment: G,
    pub product: F,
}

pub struct Witness<F> {
    pub a: Vec<F>,
    pub b: Vec<F>,
}

pub struct Proof<F, G> {
    l_r_coms: Vec<(G, G)>,
    a_final: F,
    b_final: F,
}

fn sample_challenge<F: Field + Random>(transcript: &Transcript) -> F {
    let mut noise = transcript.noise(b"challenge");
    let mut challenge = F::zero();
    while challenge == F::zero() {
        challenge = F::random(&mut noise);
    }
    challenge
}

pub fn prove<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    setup: &Setup<G>,
    statement: &Statement<F, G>,
    witness: Witness<F>,
    strategy: &impl Strategy,
) -> Proof<F, G> {
    assert_eq!(setup.g.len(), setup.h.len());
    assert_eq!(setup.g.len(), witness.a.len());
    assert_eq!(witness.a.len(), witness.b.len());
    assert!(setup.g.len().is_power_of_two());
    // TODO: commit to the statement.

    let mut l_r_coms = Vec::<(G, G)>::new();
    let mut a = witness.a;
    let mut b = witness.b;
    let mut g = setup.g.clone();
    let mut h = setup.h.clone();
    let mut product = setup.product_generator.clone() * &statement.product + &statement.commitment;
    while a.len() > 1 {
        let half_len = a.len() / 2;
        let (a_lo, a_hi) = a.split_at_mut(half_len);
        let (b_lo, b_hi) = b.split_at_mut(half_len);
        let (g_lo, g_hi) = g.split_at_mut(half_len);
        let (h_lo, h_hi) = h.split_at_mut(half_len);
        let l = G::msm(g_hi, a_lo, strategy)
            + &G::msm(h_lo, b_hi, strategy)
            + &(setup.product_generator.clone() * &F::msm(a_lo, b_hi, strategy));
        let r = G::msm(g_lo, a_hi, strategy)
            + &G::msm(h_hi, b_lo, strategy)
            + &(setup.product_generator.clone() * &F::msm(a_hi, b_lo, strategy));
        l_r_coms.push((l.clone(), r.clone()));
        transcript.commit(l.encode());
        transcript.commit(r.encode());
        let mut u = sample_challenge::<F>(transcript);
        let mut u_inv = u.inv();

        for (a_lo_i, a_hi_i) in a_lo.iter_mut().zip(a_hi.iter_mut()) {
            *a_lo_i *= &u;
            *a_lo_i += &(u_inv.clone() * a_hi_i);
        }
        a.truncate(half_len);

        for (b_lo_i, b_hi_i) in b_lo.iter_mut().zip(b_hi.iter_mut()) {
            *b_lo_i *= &u_inv;
            *b_lo_i += &(u.clone() * b_hi_i);
        }
        b.truncate(half_len);

        for (g_lo_i, g_hi_i) in g_lo.iter_mut().zip(g_hi.iter_mut()) {
            *g_lo_i *= &u_inv;
            *g_lo_i += &(g_hi_i.clone() * &u);
        }
        g.truncate(half_len);

        for (h_lo_i, h_hi_i) in h_lo.iter_mut().zip(h_hi.iter_mut()) {
            *h_lo_i *= &u;
            *h_lo_i += &(h_hi_i.clone() * &u_inv);
        }
        h.truncate(half_len);

        let u2 = {
            u.square();
            u
        };
        let u_inv2 = {
            u_inv.square();
            u_inv
        };

        product += &(l * &u2 + &(r * &u_inv2));
    }
    let a_final = a.pop().expect("a should not be empty");
    let b_final = b.pop().expect("b should not be empty");
    Proof {
        l_r_coms,
        a_final,
        b_final,
    }
}

#[must_use]
pub fn verify<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    setup: &Setup<G>,
    statement: &Statement<F, G>,
    proof: Proof<F, G>,
    strategy: &impl Strategy,
) -> bool {
    assert_eq!(setup.g.len(), setup.h.len());
    assert!(setup.g.len().is_power_of_two());

    let rounds = setup.g.len().ilog2() as usize;
    let Proof {
        l_r_coms,
        a_final,
        b_final,
    } = proof;
    if l_r_coms.len() != rounds {
        return false;
    }

    // We reduce verification down to one MSM which needs to equal 0:
    // commitment + product * U + sum(u_i^2 * L_i + u_i^-2 * R_i)
    // - a_final * g_final - b_final * h_final - a_final * b_final * U = 0.
    let capacity = setup.g.len() + setup.h.len() + 2 * rounds + 1;
    let mut points = Vec::<G>::with_capacity(capacity);
    let mut weights = Vec::<F>::with_capacity(capacity);
    let mut us = Vec::<(F, F)>::with_capacity(rounds);

    for (l, r) in l_r_coms {
        transcript.commit(l.encode());
        transcript.commit(r.encode());
        let u = sample_challenge::<F>(transcript);
        let u_inv = u.inv();
        us.push((u.clone(), u_inv.clone()));
        let u2 = {
            let mut out = u;
            out.square();
            out
        };
        let u_inv2 = {
            let mut out = u_inv;
            out.square();
            out
        };
        points.push(l);
        weights.push(u2);
        points.push(r);
        weights.push(u_inv2);
    }

    points.extend_from_slice(&setup.g);
    points.extend_from_slice(&setup.h);
    points.push(setup.product_generator.clone());

    let g_h_weights_start = weights.len();
    weights.push(F::one());
    for (u, u_inv) in us.into_iter().rev() {
        let end = weights.len();
        weights.extend_from_within(g_h_weights_start..end);
        for left_i in &mut weights[g_h_weights_start..end] {
            *left_i *= &u_inv;
        }
        for right_i in &mut weights[end..] {
            *right_i *= &u;
        }
    }
    let g_end = weights.len();
    weights.extend_from_within(g_h_weights_start..g_end);
    weights[g_end..].reverse();

    let g_weight_tweak = -a_final.clone();
    for g_w_i in &mut weights[g_h_weights_start..g_end] {
        *g_w_i *= &g_weight_tweak;
    }

    let h_weight_tweak = -b_final.clone();
    for h_w_i in &mut weights[g_end..] {
        *h_w_i *= &h_weight_tweak;
    }

    weights.push(statement.product.clone() - &(a_final * &b_final));

    G::msm(&points, &weights, strategy) == -statement.commitment.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_invariants::minifuzz;
    use commonware_math::test::{F, G};
    use commonware_parallel::Sequential;

    const MAX_VECTOR_LG: u8 = 5;
    const MAX_VECTOR_LEN: usize = 1 << MAX_VECTOR_LG;
    const NUM_GENERATORS: usize = 2 * MAX_VECTOR_LEN + 1;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_IPA_MINIFUZZ";

    #[derive(Debug)]
    struct Plan {
        a: Vec<F>,
        b: Vec<F>,
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let lg_len = u.int_in_range(0..=MAX_VECTOR_LG)?;
            let len = 1usize << lg_len;
            let a = (0..len)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<Vec<_>>>()?;
            let b = (0..len)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<Vec<_>>>()?;
            Ok(Self { a, b })
        }
    }

    impl Plan {
        fn run(self, generators: &[G]) -> arbitrary::Result<()> {
            let strategy = Sequential;
            let len = self.a.len();

            let setup = Setup {
                g: generators[..len].to_vec(),
                h: generators[len..2 * len].to_vec(),
                product_generator: generators[2 * MAX_VECTOR_LEN],
            };
            let commitment =
                G::msm(&setup.g, &self.a, &strategy) + &G::msm(&setup.h, &self.b, &strategy);
            let product = F::msm(&self.a, &self.b, &strategy);
            let statement = Statement {
                commitment,
                product,
            };
            let witness = Witness {
                a: self.a,
                b: self.b,
            };

            let mut prover_transcript = Transcript::new(NAMESPACE);
            let proof = prove(
                &mut prover_transcript,
                &setup,
                &statement,
                witness,
                &strategy,
            );
            let mut verifier_transcript = Transcript::new(NAMESPACE);
            assert!(verify(
                &mut verifier_transcript,
                &setup,
                &statement,
                proof,
                &strategy,
            ));
            Ok(())
        }
    }

    #[test]
    fn test_honest_prover_convince_honest_verifier() {
        let generators = (1..=NUM_GENERATORS)
            .map(|i| G::generator() * &F::from(i as u8))
            .collect::<Vec<_>>();
        minifuzz::test(move |u| u.arbitrary::<Plan>()?.run(&generators));
    }
}
