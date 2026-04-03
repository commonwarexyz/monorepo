//! # References
//!
//! The [Dalek crate](https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html)
//! was an invaluable reference when implementing and documenting this module.

use crate::transcript::Transcript;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, Write};
use commonware_math::algebra::{CryptoGroup, Field, Random, Space};
use commonware_parallel::Strategy;

/// A setup decides on what group elements we use to commit to vectors and their product.
///
/// A setup for an inner product argument for `c = <a_i, b_i>` needs generators
/// to commit to `a_i`, which we call `G_i`, generators for `b_i`, which we call
/// `H_i`, and a generator for the product, `c`, which we call `Q`, or "the product generator".
///
/// We can support inner products of different sizes, as long as we have enough generators.
///
/// To construct this type, see [`Self::new`].
pub struct Setup<G> {
    g: Vec<G>,
    h: Vec<G>,
    product_generator: G,
}

impl<G: Write> Write for Setup<G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.product_generator.write(buf);
        self.g.len().write(buf);
        for (g_i, h_i) in self.g.iter().zip(&self.h) {
            g_i.write(buf);
            h_i.write(buf);
        }
    }
}

impl<G: EncodeSize> EncodeSize for Setup<G> {
    fn encode_size(&self) -> usize {
        self.product_generator.encode_size()
            + self.g.len().encode_size()
            + self
                .g
                .iter()
                .zip(&self.h)
                .map(|(g_i, h_i)| g_i.encode_size() + h_i.encode_size())
                .sum::<usize>()
    }
}

impl<G: Read> Read for Setup<G> {
    type Cfg = (usize, G::Cfg);

    fn read_cfg(buf: &mut impl Buf, (max_len, cfg): &Self::Cfg) -> Result<Self, Error> {
        let product_generator = G::read_cfg(buf, cfg)?;
        let len = usize::read_cfg(buf, &RangeCfg::new(..=*max_len))?;
        let mut g = Vec::with_capacity(len);
        let mut h = Vec::with_capacity(len);
        for _ in 0..len {
            g.push(G::read_cfg(buf, cfg)?);
            h.push(G::read_cfg(buf, cfg)?);
        }
        Ok(Self {
            g,
            h,
            product_generator,
        })
    }
}

impl<G> Setup<G> {
    /// Create a new [`Setup`], given specific choices of the generator.
    ///
    /// You MUST ensure that all of the values provided to this function are unique.
    pub fn new(product_generator: G, g_and_h: impl IntoIterator<Item = (G, G)>) -> Self {
        let (g, h): (Vec<G>, Vec<G>) = g_and_h.into_iter().collect();
        Self {
            g,
            h,
            product_generator,
        }
    }

    /// The left-side generators `G_i`.
    pub fn g(&self) -> &[G] {
        &self.g
    }

    /// The right-side generators `H_i`.
    pub fn h(&self) -> &[G] {
        &self.h
    }

    /// The product generator `Q`.
    pub const fn product_generator(&self) -> &G {
        &self.product_generator
    }
}

/// The public claim we're making about the inner product.
///
/// We claim that our commitment `P` is equal to `<a_i, G_i> + <b_i, H_i>`,
/// and that our product `c` is equal to `<a_i, b_i>`.
pub struct Claim<F, G> {
    pub commitment: G,
    pub product: F,
}

impl<F: Write, G: Write> Write for Claim<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.product.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Claim<F, G> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.product.encode_size()
    }
}

impl<F: Read, G: Read> Read for Claim<F, G> {
    type Cfg = (G::Cfg, F::Cfg);

    fn read_cfg(buf: &mut impl Buf, (g_cfg, f_cfg): &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            commitment: G::read_cfg(buf, g_cfg)?,
            product: F::read_cfg(buf, f_cfg)?,
        })
    }
}

/// The witness contains the actual vectors `a_i` and `b_i` for the inner product argument.
///
/// This struct guarantees that their lengths are equal, and a power of two.
pub struct Witness<F> {
    a: Vec<F>,
    b: Vec<F>,
}

impl<F> Witness<F> {
    /// Create a new witness, from the two vectors whose product we're taking.
    ///
    /// This function returns `None` if the iterator does not produce a power of
    /// two number of elements.
    pub fn new(elements: impl IntoIterator<Item = (F, F)>) -> Option<Self> {
        let (a, b): (Vec<F>, Vec<F>) = elements.into_iter().collect();
        if !a.len().is_power_of_two() {
            return None;
        }
        Some(Self { a, b })
    }
}

impl<F: Field> Witness<F> {
    /// Like [`Self::new`], but also produces a [`Claim`], for convenience.
    ///
    /// In some situations, you have a claim from somewhere else, using the
    /// proof system in this module as just one step in some larger proof.
    ///
    /// If you don't have a claim, this lets you compute a valid one.
    ///
    /// To do so, you need a [`Setup`], which can be reused across different
    /// witnesses.
    pub fn new_with_claim<G: Space<F>>(
        setup: &Setup<G>,
        elements: impl IntoIterator<Item = (F, F)>,
    ) -> Option<(Self, Claim<F, G>)> {
        let witness = Self::new(elements)?;
        // By invariant, h has the same len as g, and b has the same len as a,
        // so we can just check this.
        if setup.g.len() < witness.a.len() {
            return None;
        }
        let claim = {
            let mut commitment = G::zero();
            let mut product = F::zero();
            for (((a_i, b_i), g_i), h_i) in
                witness.a.iter().zip(&witness.b).zip(&setup.g).zip(&setup.h)
            {
                commitment += &(g_i.clone() * a_i + &(h_i.clone() * b_i));
                product += &(a_i.clone() * b_i);
            }
            Claim {
                commitment,
                product,
            }
        };
        Some((witness, claim))
    }
}

/// A proof for the inner product argument.
pub struct Proof<F, G> {
    l_r_coms: Vec<(G, G)>,
    a_final: F,
    b_final: F,
}

impl<F: Write, G: Write> Write for Proof<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.l_r_coms.write(buf);
        self.a_final.write(buf);
        self.b_final.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Proof<F, G> {
    fn encode_size(&self) -> usize {
        self.l_r_coms.encode_size() + self.a_final.encode_size() + self.b_final.encode_size()
    }
}

impl<F: Read, G: Read> Read for Proof<F, G> {
    type Cfg = (usize, (G::Cfg, F::Cfg));

    fn read_cfg(buf: &mut impl Buf, (max_len, (g_cfg, f_cfg)): &Self::Cfg) -> Result<Self, Error> {
        let max_rounds = if *max_len == 0 {
            0
        } else {
            max_len.ilog2() as usize
        };
        Ok(Self {
            l_r_coms: Vec::<(G, G)>::read_cfg(
                buf,
                &(RangeCfg::new(..=max_rounds), (g_cfg.clone(), g_cfg.clone())),
            )?,
            a_final: F::read_cfg(buf, f_cfg)?,
            b_final: F::read_cfg(buf, f_cfg)?,
        })
    }
}

fn sample_challenge<F: Field + Random>(transcript: &Transcript) -> F {
    let mut noise = transcript.noise(b"challenge");
    let mut challenge = F::zero();
    while challenge == F::zero() {
        challenge = F::random(&mut noise);
    }
    challenge
}

/// Prove that a given [`Witness`] is valid, relative to a [`Claim`] and [`Setup`].
///
/// We also take in a transcript, allowing us to tie in this proof to a specific context.
/// This is useful when using this argument in the context of a larger proof.
pub fn prove<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    setup: &Setup<G>,
    claim: &Claim<F, G>,
    witness: Witness<F>,
    strategy: &impl Strategy,
) -> Proof<F, G>
where
    Claim<F, G>: Encode,
{
    assert_eq!(setup.g.len(), witness.a.len());
    transcript.commit(claim.encode());

    let mut l_r_coms = Vec::<(G, G)>::new();
    let mut a = witness.a;
    let mut b = witness.b;
    let mut g = setup.g.clone();
    let mut h = setup.h.clone();
    let mut product = setup.product_generator.clone() * &claim.product + &claim.commitment;
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

/// Check a [`Proof`], relative to a [`Claim`] and [`Setup`].
///  
/// If the check succeeds, we are convinced that the prover knows a valid
/// [`Witness`] to this particular [`Claim`].
///
/// It's important that the verifier uses a [`Setup`] that they know to be
/// correct, rather than one that the prover is telling them to use. For example,
/// by using one generated from a deterministic seed that's agreed upon, or
/// something similar.
#[must_use]
pub fn verify<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    setup: &Setup<G>,
    claim: &Claim<F, G>,
    proof: Proof<F, G>,
    strategy: &impl Strategy,
) -> bool
where
    Claim<F, G>: Encode,
{
    assert!(setup.g.len().is_power_of_two());
    transcript.commit(claim.encode());

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

    weights.push(claim.product.clone() - &(a_final * &b_final));

    G::msm(&points, &weights, strategy) == -claim.commitment.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_codec::{Decode, DecodeExt};
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

            let setup = Setup::new(
                generators[0],
                generators[1..]
                    .chunks_exact(2)
                    .take(len)
                    .map(|chunk| (chunk[0], chunk[1])),
            );
            let (witness, claim) = Witness::new_with_claim(&setup, self.a.into_iter().zip(self.b))
                .expect("plan vectors are powers of two and fit the setup");
            let setup = <Setup<G> as Decode>::decode_cfg(setup.encode(), &(len, ()))
                .expect("setup should roundtrip");
            let claim = <Claim<F, G> as DecodeExt<((), ())>>::decode(claim.encode())
                .expect("claim should roundtrip");

            let mut prover_transcript = Transcript::new(NAMESPACE);
            let proof = prove(&mut prover_transcript, &setup, &claim, witness, &strategy);
            let proof = <Proof<F, G> as Decode>::decode_cfg(proof.encode(), &(len, ((), ())))
                .expect("proof should roundtrip");
            let mut verifier_transcript = Transcript::new(NAMESPACE);
            assert!(verify(
                &mut verifier_transcript,
                &setup,
                &claim,
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
