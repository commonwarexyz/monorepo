//! Shared utilities: MSM helpers, batched field inversion, the Fiat-Shamir
//! transcript, and the protocol's challenge derivation.

pub mod transcript;

use crate::zkpari::data_structures::VerifyingKey;
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField};
use transcript::IOPTranscript;

/// Takes as input a struct, and converts them to a series of bytes. All traits
/// that implement `CanonicalSerialize` can be automatically converted to bytes
/// in this manner.
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}
pub(crate) use to_bytes;

/////////////////////////// Fiat-Shamir challenge ///////////////////////////

/// Compute the Fiat-Shamir challenge `r`. Binds the verifying key, the
/// public input, and all first-message commitments `(C_ci_1, ..., C_ci_J, T)`.
pub(crate) fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    c_cis: &[E::G1Affine],
    t_g: &E::G1Affine,
) -> E::ScalarField {
    let mut transcript =
        IOPTranscript::<E::ScalarField>::new(crate::zkpari::ZkPari::<E>::SNARK_NAME);
    let _ = transcript.append_serializable_element(b"vk", vk);
    append_input_and_comms::<E>(&mut transcript, public_input, c_cis, t_g);
    transcript.get_and_append_challenge("r".as_bytes()).unwrap()
}

/// Pre-seed a transcript with the VK. Clone the result for each proof to avoid
/// re-serializing the VK N times during batch verification.
pub(crate) fn seed_transcript_with_vk<E: Pairing>(
    vk: &VerifyingKey<E>,
) -> IOPTranscript<E::ScalarField> {
    let mut transcript =
        IOPTranscript::<E::ScalarField>::new(crate::zkpari::ZkPari::<E>::SNARK_NAME);
    let _ = transcript.append_serializable_element(b"vk", vk);
    transcript
}

/// Compute the Fiat-Shamir challenge from a pre-seeded transcript (already
/// contains the VK). Clones the base transcript so the caller can reuse it.
pub(crate) fn compute_chall_from_transcript<E: Pairing>(
    base_transcript: &IOPTranscript<E::ScalarField>,
    public_input: &[E::ScalarField],
    c_cis: &[E::G1Affine],
    t_g: &E::G1Affine,
) -> E::ScalarField {
    let mut transcript = base_transcript.clone();
    append_input_and_comms::<E>(&mut transcript, public_input, c_cis, t_g);
    transcript.get_and_append_challenge("r".as_bytes()).unwrap()
}

fn append_input_and_comms<E: Pairing>(
    transcript: &mut IOPTranscript<E::ScalarField>,
    public_input: &[E::ScalarField],
    c_cis: &[E::G1Affine],
    t_g: &E::G1Affine,
) {
    let _ = transcript.append_serializable_element(b"input", &public_input.to_vec());
    for c_ci in c_cis {
        let _ = transcript.append_serializable_element(b"comm_ci", c_ci);
    }
    let _ = transcript.append_serializable_element(b"comm", t_g);
}

/////////////////////////// MSM helpers ///////////////////////////

/// Compute an MSM using the windowed non-adjacent form.
pub fn msm_bigint_wnaf<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    scalars: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    const C: usize = 2;
    let digits_count = const { (V::ScalarField::MODULUS_BIT_SIZE as usize).div_ceil(C) };
    let radix: u64 = 1 << C;
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits::<C>(s, digits_count, radix))
        .collect::<Vec<_>>();
    let zero = V::zero();
    let mut window_sums = (0..digits_count).map(|i| {
        let mut buckets = [zero; 1 << C];
        for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
            use ark_std::cmp::Ordering;
            let scalar = digits[i];
            match 0.cmp(&scalar) {
                Ordering::Less => buckets[(scalar - 1) as usize] += base,
                Ordering::Greater => buckets[(-scalar - 1) as usize] -= base,
                Ordering::Equal => (),
            }
        }

        let mut running_sum = V::zero();
        let mut res = V::zero();
        buckets.into_iter().rev().for_each(|b| {
            running_sum += &b;
            res += &running_sum;
        });
        res
    });

    // We store the sum for the lowest window.
    let lowest = window_sums.next().unwrap();

    // We're traversing windows from high to low.
    lowest
        + window_sums.rev().fold(zero, |mut total, sum_i| {
            total += sum_i;
            for _ in 0..C {
                total.double_in_place();
            }
            total
        })
}

// From: https://github.com/arkworks-rs/gemini/blob/main/src/kzg/msm/variable_base.rs#L20
#[inline]
fn make_digits<const W: usize>(
    a: &impl BigInteger,
    digits_count: usize,
    radix: u64,
) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    (0..digits_count).map(move |i| {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * W;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let scalar_at_idx = scalar[u64_idx];
        let bit_buf = if bit_idx < 64 - W || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar_at_idx >> bit_idx
        } else {
            let scalar_at_idx_next = scalar[1 + u64_idx];
            // Combine the current u64's bits with the bits from the next u64
            (scalar_at_idx >> bit_idx) | (scalar_at_idx_next << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> W;
        let mut digit = (coef as i64) - (carry << W) as i64;

        if i == digits_count - 1 {
            digit += (carry << W) as i64;
        }
        digit
    })
}

/// Pippenger MSM with configurable scalar bit-length.
///
/// For batch verification with 128-bit random challenges, pass `scalar_bits = 128`
/// to halve the number of Pippenger windows compared to full-size scalars.
pub fn msm_pippenger<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    scalars: &[<V::ScalarField as PrimeField>::BigInt],
    scalar_bits: usize,
) -> V {
    let size = bases.len().min(scalars.len());
    if size == 0 || scalar_bits == 0 {
        return V::zero();
    }

    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    let zero = V::zero();
    let num_buckets = (1 << c) - 1;

    let window_sums: Vec<_> = (0..scalar_bits)
        .step_by(c)
        .map(|w_start| {
            let mut buckets = vec![zero; num_buckets];

            for (scalar, base) in scalars[..size].iter().zip(&bases[..size]) {
                if scalar.is_zero() {
                    continue;
                }
                let mut s = *scalar;
                s >>= w_start as u32;
                let idx = (s.as_ref()[0] & ((1u64 << c) - 1)) as usize;
                if idx != 0 {
                    buckets[idx - 1] += base;
                }
            }

            let mut running_sum = V::zero();
            let mut res = V::zero();
            for b in buckets.into_iter().rev() {
                running_sum += &b;
                res += &running_sum;
            }
            res
        })
        .collect();

    let lowest = window_sums[0];
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(V::zero(), |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

const fn ln_without_floats(a: usize) -> usize {
    let log2a = (usize::BITS - a.leading_zeros()) as usize;
    log2a * 69 / 100
}

/// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}.
/// This method is explicitly single-threaded.
pub fn batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    // Montgomery's Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2
    // but with an optimization to multiply every element in the returned vector by
    // coeff

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = F::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp *= f;
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

    // Multiply product by coeff, so all inverses will be scaled by coeff
    tmp *= coeff;

    // Second pass: iterate backwards to compute inverses
    for (f, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|f| !f.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(F::one())))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}
