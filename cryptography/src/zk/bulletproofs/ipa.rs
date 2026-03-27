//! # References
//!
//! The [Dalek crate](https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html)
//! was an invaluable reference when implementing and documenting this module.

use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, Field, Random, Space};
use commonware_parallel::Strategy;

use crate::transcript::Transcript;

pub struct Setup<G> {
    pub g: Vec<G>,
    pub h: Vec<G>,
    pub product_generator: G,
}

pub struct Statement<F, G> {
    pub setup: Setup<G>,
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

pub fn prove<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    statement: &Statement<F, G>,
    witness: Witness<F>,
    strategy: &impl Strategy,
) -> Proof<F, G> {
    assert_eq!(statement.setup.g.len(), statement.setup.h.len());
    assert_eq!(statement.setup.g.len(), witness.a.len());
    assert_eq!(witness.a.len(), witness.b.len());
    assert!(statement.setup.g.len().is_power_of_two());
    // TODO: commit to the statement.

    let mut l_r_coms = Vec::<(G, G)>::new();
    let mut a = witness.a;
    let mut b = witness.b;
    let mut g = statement.setup.g.clone();
    let mut h = statement.setup.h.clone();
    let mut product =
        statement.setup.product_generator.clone() * &statement.product + &statement.commitment;
    while a.len() > 1 {
        let half_len = a.len() / 2;
        let (a_lo, a_hi) = a.split_at_mut(half_len);
        let (b_lo, b_hi) = b.split_at_mut(half_len);
        let (g_lo, g_hi) = g.split_at_mut(half_len);
        let (h_lo, h_hi) = h.split_at_mut(half_len);
        let l = G::msm(g_hi, a_lo, strategy)
            + &G::msm(h_lo, b_hi, strategy)
            + &(statement.setup.product_generator.clone() * &F::msm(a_lo, b_hi, strategy));
        let r = G::msm(g_lo, a_hi, strategy)
            + &G::msm(h_hi, b_lo, strategy)
            + &(statement.setup.product_generator.clone() * &F::msm(a_hi, b_lo, strategy));
        l_r_coms.push((l.clone(), r.clone()));
        transcript.commit(l.encode());
        transcript.commit(r.encode());
        let mut u = F::random(transcript.noise(b"challenge"));
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
            *h_lo_i *= &u_inv;
            *h_lo_i += &(h_hi_i.clone() * &u);
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
    statement: &Statement<F, G>,
    proof: Proof<F, G>,
    _strategy: &impl Strategy,
) -> bool {
    assert_eq!(statement.setup.g.len(), statement.setup.h.len());
    assert!(statement.setup.g.len().is_power_of_two());

    let mut g = statement.setup.g.clone();
    let mut h = statement.setup.h.clone();
    let mut product =
        statement.setup.product_generator.clone() * &statement.product + &statement.commitment;
    let mut l_r_coms = proof.l_r_coms;
    l_r_coms.reverse();
    while g.len() > 1 {
        let half_len = g.len() / 2;
        let (g_lo, g_hi) = g.split_at_mut(half_len);
        let (h_lo, h_hi) = h.split_at_mut(half_len);
        let Some((l, r)) = l_r_coms.pop() else {
            return false;
        };
        transcript.commit(l.encode());
        transcript.commit(r.encode());
        let mut u = F::random(transcript.noise(b"challenge"));
        let mut u_inv = u.inv();

        for (g_lo_i, g_hi_i) in g_lo.iter_mut().zip(g_hi.iter_mut()) {
            *g_lo_i *= &u_inv;
            *g_lo_i += &(g_hi_i.clone() * &u);
        }
        g.truncate(half_len);

        for (h_lo_i, h_hi_i) in h_lo.iter_mut().zip(h_hi.iter_mut()) {
            *h_lo_i *= &u_inv;
            *h_lo_i += &(h_hi_i.clone() * &u);
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
    let g_final = g.pop().expect("g should be non empty");
    let h_final = h.pop().expect("h should be non empty");
    let expected_product = g_final * &proof.a_final
        + &(h_final * &proof.b_final)
        + &(statement.setup.product_generator.clone() * &(proof.a_final * &proof.b_final));
    expected_product == product
}
