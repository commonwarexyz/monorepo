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

use crate::transcript::{Summary, Transcript};
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
#[derive(Debug, PartialEq)]
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

#[cfg(any(test, feature = "arbitrary"))]
impl<G> arbitrary::Arbitrary<'_> for Setup<G>
where
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let g_and_h = u.arbitrary::<Vec<(G, G)>>()?;
        Ok(Self::new(u.arbitrary()?, g_and_h))
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
#[derive(Debug, PartialEq)]
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

#[cfg(any(test, feature = "arbitrary"))]
impl<F, G> arbitrary::Arbitrary<'_> for Claim<F, G>
where
    F: for<'a> arbitrary::Arbitrary<'a>,
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commitment: u.arbitrary()?,
            product: u.arbitrary()?,
            log_len: u.arbitrary()?,
        })
    }
}

/// The witness contains the actual vectors `a_i` and `b_i` for the inner product argument.
///
/// This struct guarantees that their lengths are equal, and a power of two.
#[derive(Clone)]
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
#[derive(Debug, PartialEq)]
pub struct Proof<F, G> {
    l_r_coms: Vec<(G, G)>,
    /// Summary of the transcript after the public statement and all proof messages.
    ///
    /// This binds even zero-round exchanges to the transcript.
    transcript_summary: Summary,
    a_final: F,
    b_final: F,
}

impl<F: Write, G: Write> Write for Proof<F, G> {
    fn write(&self, buf: &mut impl BufMut) {
        self.l_r_coms.write(buf);
        self.transcript_summary.write(buf);
        self.a_final.write(buf);
        self.b_final.write(buf);
    }
}

impl<F: EncodeSize, G: EncodeSize> EncodeSize for Proof<F, G> {
    fn encode_size(&self) -> usize {
        self.l_r_coms.encode_size()
            + self.transcript_summary.encode_size()
            + self.a_final.encode_size()
            + self.b_final.encode_size()
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
            transcript_summary: Summary::read(buf)?,
            a_final: F::read_cfg(buf, f_cfg)?,
            b_final: F::read_cfg(buf, f_cfg)?,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<F, G> arbitrary::Arbitrary<'_> for Proof<F, G>
where
    F: for<'a> arbitrary::Arbitrary<'a>,
    G: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let rounds = u.int_in_range(0..=usize::BITS as usize - 1)?;
        let l_r_coms = (0..rounds)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            l_r_coms,
            transcript_summary: u.arbitrary()?,
            a_final: u.arbitrary()?,
            b_final: u.arbitrary()?,
        })
    }
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
    // Okay, let's explain the math behind how this proof system works.
    //
    // (Once again, https://doc-internal.dalek.rs/bulletproofs/notes/inner_product_proof/index.html,
    // is a useful reference, inspiring much of this documentation).
    //
    // We'll describe the protocol as if it were interactive. We turn it into
    // a non-interactive protocol using the venerable Fiat-Shamir transform.
    // The Transcript abstraction helps us with that.
    //
    // We have vectors a_i and b_i, in our claim, we have:
    //
    //   P = <a_i, G_i> + <b_i, H_i>
    //   c = <a_i, b_i>
    //
    // for recursion, it's convenient to have a statement about one commitment
    // instead.
    //
    // We can have the verifier give us a challenge w, compressing this into:
    //
    //  P = <a_i, G_i> + <b_i, H_i> + c * w * Q
    //
    // where Q is the additional generator from our setup.
    //
    // For the recursion, the idea is that at each round, we have:
    //
    //   P_k = <a_k_i, G_k_i> + <b_k_i, H_k_i> + <a_k_i, b_k_i> w Q
    //
    // and our goal is to turn (P_k, a_k_i, b_k_i) into (P_(k-1), a_(k-1)_i, b_(k-1)_i)
    // at each round, with the vectors halving in size. Eventually, we'll just
    // have a single element, which is trivial to prove just by sending it over.
    //
    // Not having a good explanation for why the following trick works, let's shut
    // up and calculate. Assume we have some folding coefficient u_k:
    //
    //   a_(k-1)_i := u_k    a_i + u_k^-1 a_(mid + i)
    //   b_(k-1)_i := u_k^-1 b_i + u_k    b_(mid + i)
    //   G_(k-1)_i := u_k^-1 G_i + u_k    G_(mid + i)
    //   H_(k-1)_i := u_k    H_i + u_k^-1 H_(mid + i)
    //
    // (the new vectors are half the size, and mid is the new midpoint)
    //
    // then, we get:
    //
    //   P_(k-1) =
    //     <u_k    a_i + u_k^-1 a_(mid + i), u_k^-1 G_i + u_k    G_(mid + i)> +
    //     <u_k^-1 b_i + u_k    b_(mid + i), u_k    H_i + u_k^-1 H_(mid + i)> +
    //     <u_k    a_i + u_k^-1 a_(mid + i), u_k^-1 b_i + u_k    b_(mid + i)>
    //
    // shutting up and calculating, we get:
    //
    //   <a_i, G_i> + <u_k^2  a_i, G_(mid + i)> + <u_k^-2 a_(mid + i), G_i> + <a_(mid + i), G_(mid + i)> +
    //   <b_i, H_i> + <u_k^-2 b_i, H_(mid + i)> + <u_k^2  b_(mid + i), H_i> + <b_(mid + i), H_(mid + i)> +
    //   <a_i, b_i> + <u_k^2  a_i, b_(mid + i)> + <u_k^-2 a_(mid + i), b_i> + <a_(mid + i), b_(mid + i)>
    //
    // we can group terms by coefficient, and notice that we have:
    //
    //           <a_i, G_i> + <a_(mid + i), G_(mid + i)> +
    //           <b_i, H_i> + <b_(mid + i), H_(mid + i)> +
    //           <a_i, b_i> + <a_(mid + i), b_(mid + i)> +
    //   u_k^2  (<a_i, G_(mid + i)> + <b_(mid + i), H_i> + <a_i, b_(mid + i)>) +
    //   u_k^-2 (<a_(mid + i), G_i> + <b_i, H_(mid + i)> + <a_(mid + i), b_i>)
    //
    // However, the first few lines of this are just P_k, so we have:
    //
    //   P_(k-1) = P_k + u_k^2 L_k + u_k^-2 R_k
    //
    // defining L_k and R_k as shorthand to the terms above.
    //
    // How do we use this fact? We have the prover calculate L_k and R_k, send
    // them over to the verifier, who responds with a challenge u_k. We can then
    // use that challenge to calculate the new vectors a_(k-1)_i,...
    //
    // The verifier can also check the provers work, by verifying:
    //
    //   P_k + u_k^2 L_k + u_k^-2 R_k =? P_(k-1)
    //
    // In fact, we don't even need to send P_(k-1) either. The prover
    // knows what P_(k-1) needs to equal, thus determining what P_(k-2) should
    // be, and so on, until we reach a final value P_0.
    //
    // For that final value, we have vectors of size 1, so we can send them over,
    // and have the verifier check:
    //
    //   P_0 =? a_0 G_0 + b_0 H_0 + a_0 b_0 w B
    //
    // with P_0 being calculated by the verifier, from the initial generators,
    // claim, and the challenges.
    let witness_len = witness.a.len();
    let claimed_len = 1usize.checked_shl(u32::from(claim.log_len))?;
    if claimed_len != witness_len || setup.g.len() < witness_len {
        return None;
    }
    // At this point, we've committed to the claim we're trying to prove, so
    // we can't pull any shenanigans by modifying the claim based on the challenges.
    transcript.commit(claim.encode());
    let w = F::random(&mut transcript.noise(b"w challenge"));
    let w_q = setup.product_generator.clone() * &w;

    let mut l_r_coms = Vec::<(G, G)>::new();
    let mut a = witness.a;
    let mut b = witness.b;
    let mut g = setup.g[..witness_len].to_vec();
    let mut h = setup.h[..witness_len].to_vec();
    while a.len() > 1 {
        let mid = a.len() / 2;
        let (a_lo, a_hi) = a.split_at_mut(mid);
        let (b_lo, b_hi) = b.split_at_mut(mid);
        let (g_lo, g_hi) = g.split_at_mut(mid);
        let (h_lo, h_hi) = h.split_at_mut(mid);
        let l = G::msm(g_hi, a_lo, strategy)
            + &G::msm(h_lo, b_hi, strategy)
            + &(w_q.clone() * &F::msm(a_lo, b_hi, strategy));
        let r = G::msm(g_lo, a_hi, strategy)
            + &G::msm(h_hi, b_lo, strategy)
            + &(w_q.clone() * &F::msm(a_hi, b_lo, strategy));
        l_r_coms.push((l.clone(), r.clone()));
        transcript.commit(l.encode());
        transcript.commit(r.encode());
        let u = F::random(&mut transcript.noise(b"u challenge"));
        let u_inv = u.inv();

        for (a_lo_i, a_hi_i) in a_lo.iter_mut().zip(a_hi.iter_mut()) {
            *a_lo_i *= &u;
            *a_lo_i += &(u_inv.clone() * a_hi_i);
        }
        a.truncate(mid);

        for (b_lo_i, b_hi_i) in b_lo.iter_mut().zip(b_hi.iter_mut()) {
            *b_lo_i *= &u_inv;
            *b_lo_i += &(u.clone() * b_hi_i);
        }
        b.truncate(mid);

        for (g_lo_i, g_hi_i) in g_lo.iter_mut().zip(g_hi.iter_mut()) {
            *g_lo_i *= &u_inv;
            *g_lo_i += &(g_hi_i.clone() * &u);
        }
        g.truncate(mid);

        for (h_lo_i, h_hi_i) in h_lo.iter_mut().zip(h_hi.iter_mut()) {
            *h_lo_i *= &u;
            *h_lo_i += &(h_hi_i.clone() * &u_inv);
        }
        h.truncate(mid);
    }
    let a_final = a.pop().expect("a should not be empty");
    let b_final = b.pop().expect("b should not be empty");
    Some(Proof {
        l_r_coms,
        transcript_summary: transcript.summarize(),
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
    // See the prove function for some more explanation of the math.
    // If you read that function's documentation naively, you might come under
    // the impression that we have to naively follow the prover, folding the
    // generators at each step, in order to produce the final value P_0, which
    // we can then use to check that final a_0 and b_0. This is not ideal,
    // because it's more efficient to do scalar multiplications as a batch, using
    // an MSM. Our goal will thus be to reduce all of our work to hashing, in order
    // to get the challenges, and a single large MSM.
    //
    // The final check we have is:
    //
    //   P_0 =? a_0 G_0 + b_0 H_0 + a_0 b_0 w Q
    //
    // What is P_0? Well, it must be equal to:
    //
    //   P_1 - u_1^2 L_1 - u_1^-2 R_1
    //
    // we can unravel P_1, and so, on, to get:
    //
    //   P_0 = P + c w Q - <u_k^2, L_k> - <u_k^-2, R_k>
    //
    // and that's nice and ready for an MSM. The issue is now how to figure out
    // G_0 and H_0. Intuitively, this should be possible to do as a large MSM
    // of the original G_i and H_i. This is because each folding step is just a linear
    // transformation of the prior vectors. Composing these will still result in
    // a linear transformation. We just need to figure out the weights for this.
    //
    // For vectors of size 1, this is trivial, the weights are just 1.
    //
    // Let's say we've figured out the weights for G_(k-1), what should the weights
    // for G_k be? We want:
    //
    //   <g_(k-1)_j, G_(k-1)_j> = <g_k_i, G_k_i>
    //
    // i.e. the weights we want should produce the same result as folding, and then
    // using the weights we know exist by induction. (If this is not easy to understand,
    // imagine that the next layer beneath us is just the trivial layer, with one element,
    // and a single weight equal to 1).
    //
    // We can expand the result of folding, to get:
    //
    //   <g_(k-1)_j, u_k^-1 G_k_j + u_k G_k_(mid + j)>
    //
    // but, this gives us the weights we need, defining:
    //
    //   g_k_i := u_k^{if i < mid { -1 } else { 1 }} g_(k - 1)_(i % mid)
    //
    // Another way of visualizing what's happening here: at each iteration, as
    // we double the size of the weights, what we're doing is copying the existing
    // weights, and then multiplying the left side by u_k^-1, and the right side
    // by u_k.
    //
    // Here's an example progression:
    //
    // 1
    //
    // 1, 1
    // u_1^-1, u_1
    //
    // u_1^-1, u_1, u_1^-1, u_1
    // u_1^-1 u_2^-1, u_1 u_2^-1, u_1^-1 u_2, u_1 u_2
    //
    // Now, we don't actually need to do anything special for H, because it turns
    // out that the weights we need are just the ones we've calculated for G, just
    // in reverse order! To see why, note that the only difference with H is that
    // we need to use u_k on the left, and u_k^-1 on the right. The vector we
    // have at each step is the result of copying the previous vector, doubling its size,
    // and then multiplying with one value and the left, and the other on the right.
    // If we reverse this vector, the result we get is the same as if we had reversed
    // the previous step's vector, copied it, and then multiplied with u_k on the left,
    // and u_k^-1 on the right, which is exactly what we need to do.
    let rounds = usize::from(claim.log_len);
    let Some(claimed_len) = 1usize.checked_shl(u32::from(claim.log_len)) else {
        return false;
    };
    let Proof {
        l_r_coms,
        transcript_summary,
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

    let w = F::random(&mut transcript.noise(b"w challenge"));
    let w_q = setup.product_generator.clone() * &w;

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
        let u = F::random(transcript.noise(b"u challenge"));
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
    if transcript.summarize() != transcript_summary {
        return false;
    }

    points.extend_from_slice(&setup.g[..claimed_len]);
    points.extend_from_slice(&setup.h[..claimed_len]);
    points.push(w_q);

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

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::{Claim, Proof, Setup};
    use commonware_codec::conformance::CodecConformance;
    use commonware_math::test::{F as TestF, G as TestG};

    commonware_conformance::conformance_tests! {
        CodecConformance<Setup<TestG>>,
        CodecConformance<Claim<TestF, TestG>>,
        CodecConformance<Proof<TestF, TestG>>,
    }
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    #[cfg(test)]
    use commonware_codec::Decode;
    use commonware_math::{
        algebra::Additive,
        test::{F, G},
    };
    use commonware_parallel::Sequential;
    use std::sync::OnceLock;

    const MAX_VECTOR_LG: u8 = 5;
    const MAX_VECTOR_LEN: usize = 1 << MAX_VECTOR_LG;
    const MAX_SETUP_VECTOR_LEN: usize = 2 * MAX_VECTOR_LEN;
    const NUM_GENERATORS: usize = 2 * MAX_SETUP_VECTOR_LEN + 1;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_IPA";
    const BAD_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_BULLETPROOFS_IPA_BUT_DIFFERENT";

    fn test_setup() -> &'static Setup<G> {
        static TEST_SETUP: OnceLock<Setup<G>> = OnceLock::new();
        TEST_SETUP.get_or_init(|| {
            let generators = (1..=NUM_GENERATORS)
                .map(|i| G::generator() * &F::from(i as u8))
                .collect::<Vec<_>>();
            Setup::new(
                generators[0],
                generators[1..]
                    .chunks_exact(2)
                    .map(|chunk| (chunk[0], chunk[1])),
            )
        })
    }

    struct Prover<'a> {
        setup: &'a Setup<G>,
        witness: Witness<F>,
        claim: Claim<F, G>,
        proof: Proof<F, G>,
        bad_namespace: bool,
        honest: bool,
    }

    impl<'a> Prover<'a> {
        fn new(setup: &'a Setup<G>, a: &[F], b: &[F]) -> Self {
            let (witness, claim) =
                Witness::new_with_claim(setup, a.iter().zip(b).map(|(&a, &b)| (a, b)))
                    .expect("prover expects arguments to match setup");
            let proof = prove(
                &mut Transcript::new(NAMESPACE),
                setup,
                &claim,
                witness.clone(),
                &Sequential,
            )
            .expect("proving should work");
            Self {
                setup,
                witness,
                claim,
                proof,
                bad_namespace: false,
                honest: true,
            }
        }

        #[allow(clippy::missing_const_for_fn)]
        fn bad_namespace(&mut self) {
            self.honest = false;
            self.bad_namespace = true;
        }

        fn tweak_product(&mut self, delta: F) {
            if delta == F::zero() {
                return;
            }
            self.honest = false;
            // Normally, we compress the separate product by doing:
            //
            //   c w Q + P
            //
            // but, if you know w in advance, you can do:
            //
            //   (c + d) w Q + (P - d w Q)
            //
            // i.e. tweak your commitment to change the product, without changing
            // the actual vectors that make up your witness.
            //
            // One simple case where you know w is if the implementor forgets to multiply
            // the product generator by this challenge. (I made this mistake myself).
            self.claim.product -= &delta;
            self.claim.commitment += &(*self.setup.product_generator() * &delta);
            self.proof = prove(
                &mut Transcript::new(NAMESPACE),
                self.setup,
                &self.claim,
                self.witness.clone(),
                &Sequential,
            )
            .expect("proving should work after tweaking the public claim");
        }

        fn increase_length(&mut self) {
            self.honest = false;
            let longer_log_len = self
                .claim
                .log_len
                .checked_add(1)
                .expect("test vectors should support doubling the witness length");
            let longer_len = 1usize
                .checked_shl(u32::from(longer_log_len))
                .expect("witness length should fit into usize");
            self.witness.a.resize_with(longer_len, F::zero);
            self.witness.b.resize_with(longer_len, F::zero);

            // Padding with zeros preserves the commitment and product, but the
            // regenerated proof is now bound to a different claimed length.
            let longer_claim = Claim {
                commitment: self.claim.commitment,
                product: self.claim.product,
                log_len: longer_log_len,
            };
            self.proof = prove(
                &mut Transcript::new(NAMESPACE),
                self.setup,
                &longer_claim,
                self.witness.clone(),
                &Sequential,
            )
            .expect("proving should work after increasing the witness length");
        }

        fn tweak_l_r_coms<'b>(&mut self, u: &mut Unstructured<'b>) -> arbitrary::Result<()> {
            let Some(last_round) = self.proof.l_r_coms.len().checked_sub(1) else {
                return Ok(());
            };
            let round = u.int_in_range(0..=last_round)?;
            let tweak_left = u.arbitrary::<bool>()?;
            let delta = u.arbitrary::<G>()?;
            if delta == G::zero() {
                return Ok(());
            }

            self.honest = false;
            let (l, r) = &mut self.proof.l_r_coms[round];
            if tweak_left {
                *l += &delta;
            } else {
                *r += &delta;
            }
            Ok(())
        }

        #[allow(clippy::missing_const_for_fn)]
        fn honest(&self) -> bool {
            self.honest
        }

        fn verify(self) -> bool {
            let ns = if self.bad_namespace {
                BAD_NAMESPACE
            } else {
                NAMESPACE
            };
            verify(
                &mut Transcript::new(ns),
                self.setup,
                &self.claim,
                self.proof,
                &Sequential,
            )
        }
    }

    #[derive(Debug)]
    pub struct Plan {
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
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            let setup = test_setup();
            let mut prover = Prover::new(setup, &self.a, &self.b);
            // is the prover going to be malicious at all?
            if u.arbitrary::<bool>()? {
                match u.arbitrary::<u8>()? {
                    x if x < 64 => prover.tweak_product(u.arbitrary::<F>()?),
                    x if x < 128 => prover.increase_length(),
                    x if x < 192 => prover.tweak_l_r_coms(u)?,
                    _ => prover.bad_namespace(),
                }
            }
            match (prover.honest(), prover.verify()) {
                (true, true) | (false, false) => {}
                (true, false) => panic!("prover honest, but proof didn't verify"),
                (false, true) => panic!("prover malicious, but proof verifies!!!"),
            }
            Ok(())
        }
    }

    #[cfg(test)]
    fn assert_setup_roundtrip(setup: &Setup<G>) {
        let encoded = setup.encode();
        let decoded: Setup<G> = Setup::decode_cfg(encoded.clone(), &(setup.g.len(), ()))
            .expect("setup should decode with its own length bound");
        assert_eq!(setup, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    #[cfg(test)]
    fn assert_claim_roundtrip(claim: &Claim<F, G>) {
        let encoded = claim.encode();
        let decoded: Claim<F, G> = Claim::decode_cfg(encoded.clone(), &((), ()))
            .expect("claim should decode with unit cfg");
        assert_eq!(claim, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    #[cfg(test)]
    fn assert_proof_roundtrip(proof: &Proof<F, G>) {
        let max_len = if proof.l_r_coms.is_empty() {
            0
        } else {
            1usize
                .checked_shl(proof.l_r_coms.len() as u32)
                .expect("proof arbitrary bounds rounds to fit in usize")
        };
        let encoded = proof.encode();
        let decoded: Proof<F, G> = Proof::decode_cfg(encoded.clone(), &(max_len, ((), ())))
            .expect("proof should decode with a matching round bound");
        assert_eq!(proof, &decoded);
        assert_eq!(decoded.encode(), encoded);
    }

    #[cfg(test)]
    #[test]
    fn test_codec_roundtrip() {
        commonware_invariants::minifuzz::test(|u| {
            assert_setup_roundtrip(&u.arbitrary::<Setup<G>>()?);
            assert_claim_roundtrip(&u.arbitrary::<Claim<F, G>>()?);
            assert_proof_roundtrip(&u.arbitrary::<Proof<F, G>>()?);
            Ok(())
        });
    }

    #[test]
    fn test_fuzz() {
        commonware_invariants::minifuzz::test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
