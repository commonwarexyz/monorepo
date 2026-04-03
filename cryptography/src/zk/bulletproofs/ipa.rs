//! This module provides an "Inner Product Argument", using [Bulletproofs](https://eprint.iacr.org/2017/1066).
//!
//! # Background
//!
//! We have a cryptographic group `G`, with associated scalar field `F`.
//!
//! Prior to this, we have agreed on distinct group elements `G_i`, `H_i`, and `Q`.
//!
//! A prover has two vectors of field elements `a_i` and `b_i`. They have created
//! a commitment `P` to these vectors, defined as `P = <a_i, G_i> + <b_i, H_i>`.
//! They want to convince the verifier that the product of the vectors that `P`
//! commits to is equal to `c = <a_i, b_i>`.
//!
//! One way to do this is to simply send the vectors `a_i` and `b_i`. The goal
//! of the Bulletproofs IPA is to convince the verifier while sending less information.
//! The result is that we can convince the verifier while sending `O(lg N)` group elements
//! rather than `O(N)` field elements.
//!
//! Importantly, this argument is NOT zero-knowledge. The verifier learns information
//! about the vectors. This argument can be used as part of a broader zero-knowledge
//! protocol though, but this step by itself does not provide that property.
//!
//! The prover's work is mostly `O(N)` scalar multiplications, and the verifier's
//! work is mostly an MSM of size `O(N)`. The verifier gets to be a bit faster because
//! they can do a large MSM rather than many individual scalar multiplications,
//! but the asymptotic complexity is the same.
//!
//! # Usage
//!
//! Let's look at the concrete API now.
//!
//! We need group elements we can use to create commitments. This is what [`Setup`]
//! is for. A single [`Setup`] can support arguments for vectors of various sizes.
//! [`Setup::new`] creates a setup by explicitly providing all of the generators
//! we need.
//!
//! Next, we need to actual vectors we want to make a proof over. This is the
//! [`Witness`] type. This can be constructed with [`Witness::new`], which enforces
//! that the vectors have the same length, and that this length is a power of two.
//! This is a technical requirement for the Bulletproofs IPA. Padding should be
//! handled at the layer above.
//!
//! Next, we need the public statement, represented by [`Claim`]. This contains
//! the claimed product `c`, and the commitment `P`. For a honest prover that
//! wants to generate a claim from a witness, you can use [`Witness::new_with_claim`],
//! which makes sure that the witness satisfies the same conditions as [`Witness::new`],
//! while also calculating the claim.
//!
//! This is not necessarily what you want to do in all situations. When using
//! the Bulletproofs IPA as a step in a larger proof system, you might have a claim
//! and witness which come from previous steps. Because of that, you can construct
//! a [`Claim`] directly, using its public fields.
//!
//! Because a single [`Setup`] can support vectors of different lengths, the claim
//! also needs to contain information about the length of these vectors.
//!
//! Given a [`Setup`], [`Witness`], and [`Claim`], you can create a [`Proof`]
//! with [`prove`].
//!
//! Both [`prove`] and [`verify`] also take a [`Transcript`]. The proof is only
//! valid for the transcript state used to produce it, so the verifier must
//! replay the same transcript history before calling [`verify`].
//!
//! On the verifier side, we don't have a [`Witness`], and can instead check
//! that the prover had a valid witness, using their [`Proof`], through [`verify`].
//!
//! ## Example
//!
//! ```rust
//! # use commonware_cryptography::{
//! #     bls12381::primitives::group::{G1, Scalar},
//! #     transcript::Transcript,
//! #     zk::bulletproofs::ipa::{prove, verify, Setup, Witness},
//! # };
//! # use commonware_math::algebra::CryptoGroup;
//! # use commonware_parallel::Sequential;
//! # type F = Scalar;
//! # type G = G1;
//! # #[allow(non_snake_case)]
//! # let GENERATORS: [G; 9] = core::array::from_fn(|i| G::generator() * &F::from(i as u64 + 1));
//!
//! // It's important that these generators have no known discrete logarithm
//! // relationships relative to each other. For example, multipying a single
//! // generator would be insecure!
//! let setup = Setup::new(
//!     GENERATORS[0].clone(),
//!     GENERATORS[1..]
//!         .chunks_exact(2)
//!         .map(|chunk| (chunk[0].clone(), chunk[1].clone())),
//! );
//!
//! // Witness vectors must have the same power-of-two length.
//! let (witness, claim) = Witness::new_with_claim(
//!     &setup,
//!     [
//!         (F::from(3u64), F::from(4u64)),
//!         (F::from(5u64), F::from(6u64)),
//!         (F::from(7u64), F::from(8u64)),
//!         (F::from(9u64), F::from(10u64)),
//!     ],
//! )
//! .expect("witness should fit the setup");
//!
//! // The proof is bound to this transcript state.
//! let mut prover_transcript = Transcript::new(b"ipa-example");
//! prover_transcript.commit(b"context".as_slice());
//!
//! // Any Strategy works here. Sequential is simplest; a parallel strategy can
//! // reduce wall-clock time on larger inputs without changing the proof.
//! let strategy = Sequential;
//! let proof = prove(&mut prover_transcript, &setup, &claim, witness, &strategy)
//!     .expect("claim should match the witness and setup");
//!
//! // Verification must replay the same transcript state.
//! let mut verifier_transcript = Transcript::new(b"ipa-example");
//! verifier_transcript.commit(b"context".as_slice());
//! assert!(verify(
//!     &mut verifier_transcript,
//!     &setup,
//!     &claim,
//!     proof,
//!     &strategy,
//! ));
//! ```
//!
//! # References
//!
//! The [Dalek crate](https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html)
//! was an invaluable reference when implementing and documenting this module.

use crate::transcript::Transcript;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
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
    /// The claimed vector length, stored as `log2(len)`.
    ///
    /// Inner product arguments require power-of-two vector lengths, so storing
    /// the logarithm is enough to recover the full claimed length.
    pub log_len: u8,
}

impl<F: Write, G: Write> Write for Claim<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.product.write(buf);
        self.log_len.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Claim<F, G> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.product.encode_size() + self.log_len.encode_size()
    }
}

impl<F: Read, G: Read> Read for Claim<F, G> {
    type Cfg = (G::Cfg, F::Cfg);

    fn read_cfg(buf: &mut impl Buf, (g_cfg, f_cfg): &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            commitment: G::read_cfg(buf, g_cfg)?,
            product: F::read_cfg(buf, f_cfg)?,
            log_len: u8::read(buf)?,
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
                log_len: witness.a.len().ilog2() as u8,
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
/// We also take in a transcript. The proof is bound to the transcript state at
/// the time of this call, so the verifier must replay the same transcript
/// history before calling [`verify`].
///
/// This returns `None` if the setup is too short for the witness, or if the
/// claim's vector length does not match the witness length.
pub fn prove<F: Field + Random, G: CryptoGroup<Scalar = F> + Encode>(
    transcript: &mut Transcript,
    setup: &Setup<G>,
    claim: &Claim<F, G>,
    witness: Witness<F>,
    strategy: &impl Strategy,
) -> Option<Proof<F, G>>
where
    Claim<F, G>: Encode,
{
    let witness_len = witness.a.len();
    let claimed_len = 1usize.checked_shl(u32::from(claim.log_len))?;
    if claimed_len != witness_len || setup.g.len() < witness_len {
        return None;
    }
    transcript.commit(claim.encode());

    let mut l_r_coms = Vec::<(G, G)>::new();
    let mut a = witness.a;
    let mut b = witness.b;
    let mut g = setup.g[..witness_len].to_vec();
    let mut h = setup.h[..witness_len].to_vec();
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
    Some(Proof {
        l_r_coms,
        a_final,
        b_final,
    })
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
    let rounds = usize::from(claim.log_len);
    let Some(claimed_len) = 1usize.checked_shl(u32::from(claim.log_len)) else {
        return false;
    };
    let Proof {
        l_r_coms,
        a_final,
        b_final,
    } = proof;
    if l_r_coms.len() != rounds {
        return false;
    }
    if setup.g.len() < claimed_len || setup.h.len() < claimed_len {
        return false;
    }
    transcript.commit(claim.encode());

    // We reduce verification down to one MSM which needs to equal 0:
    // commitment + product * U + sum(u_i^2 * L_i + u_i^-2 * R_i)
    // - a_final * g_final - b_final * h_final - a_final * b_final * U = 0.
    let capacity = 2 * claimed_len + 2 * rounds + 1;
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

    points.extend_from_slice(&setup.g[..claimed_len]);
    points.extend_from_slice(&setup.h[..claimed_len]);
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
        fn run(self, setup: &Setup<G>) -> arbitrary::Result<()> {
            let strategy = Sequential;
            let setup_len = setup.g().len();
            let (witness, claim) = Witness::new_with_claim(setup, self.a.into_iter().zip(self.b))
                .expect("plan vectors are powers of two and fit the setup");
            let setup = <Setup<G> as Decode>::decode_cfg(setup.encode(), &(setup_len, ()))
                .expect("setup should roundtrip");
            let claim = <Claim<F, G> as DecodeExt<((), ())>>::decode(claim.encode())
                .expect("claim should roundtrip");

            let mut prover_transcript = Transcript::new(NAMESPACE);
            let proof = prove(&mut prover_transcript, &setup, &claim, witness, &strategy)
                .expect("setup is large enough and claim length matches the witness");
            let proof = <Proof<F, G> as Decode>::decode_cfg(proof.encode(), &(setup_len, ((), ())))
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
    fn test_honest_prover_convinces_honest_verifier() {
        let generators = (1..=NUM_GENERATORS)
            .map(|i| G::generator() * &F::from(i as u8))
            .collect::<Vec<_>>();
        let setup = Setup::new(
            generators[0],
            generators[1..]
                .chunks_exact(2)
                .map(|chunk| (chunk[0], chunk[1])),
        );
        minifuzz::test(move |u| u.arbitrary::<Plan>()?.run(&setup));
    }
}
