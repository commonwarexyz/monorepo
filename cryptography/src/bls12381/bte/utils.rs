use crate::bls12381::primitives::group::{Scalar, G1, G2, GT};
use blst::{blst_final_exp, blst_fp12, blst_fp12_mul, blst_miller_loop};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, Field, FieldNTT, Ring, Space};

/// Compute the pairing e(g1, g2) -> GT.
pub fn pairing(g1: &G1, g2: &G2) -> GT {
    let p1_affine = g1.as_blst_p1_affine();
    let p2_affine = g2.as_blst_p2_affine();

    let mut result = blst_fp12::default();
    let ptr = &raw mut result;
    // SAFETY: blst_final_exp supports in-place (ret==f). Raw pointer avoids aliased refs.
    unsafe {
        blst_miller_loop(ptr, &p2_affine, &p1_affine);
        blst_final_exp(ptr, ptr);
    }

    GT::from_blst_fp12(result)
}

/// Compute the product of multiple pairings: prod(e(g1_i, g2_i)) -> GT.
///
/// Uses a single final exponentiation for efficiency.
pub fn multi_pairing(pairs: &[(G1, G2)]) -> GT {
    assert!(!pairs.is_empty());

    let mut acc = blst_fp12::default();
    let acc_ptr = &raw mut acc;

    // First pairing
    let p1_affine = pairs[0].0.as_blst_p1_affine();
    let p2_affine = pairs[0].1.as_blst_p2_affine();
    // SAFETY: Valid affine points; miller_loop writes to acc_ptr.
    unsafe {
        blst_miller_loop(acc_ptr, &p2_affine, &p1_affine);
    }

    // Remaining pairings
    for &(ref g1, ref g2) in &pairs[1..] {
        let p1_affine = g1.as_blst_p1_affine();
        let p2_affine = g2.as_blst_p2_affine();
        let mut tmp = blst_fp12::default();
        // SAFETY: Valid affine points; miller_loop writes to tmp. blst_fp12_mul supports
        // in-place (ret==a).
        unsafe {
            blst_miller_loop(&mut tmp, &p2_affine, &p1_affine);
            blst_fp12_mul(acc_ptr, acc_ptr, &tmp);
        }
    }

    // Single final exponentiation
    // SAFETY: blst_final_exp supports in-place (ret==f).
    unsafe {
        blst_final_exp(acc_ptr, acc_ptr);
    }

    GT::from_blst_fp12(acc)
}

/// Serialize a G1 element to bytes.
fn g1_bytes(g: &G1) -> bytes::Bytes {
    g.encode()
}

/// Serialize a G2 element to bytes.
fn g2_bytes(g: &G2) -> bytes::Bytes {
    g.encode()
}

/// Serialize a Scalar to bytes.
fn scalar_bytes(s: &Scalar) -> bytes::Bytes {
    s.encode()
}

/// Hash arbitrary bytes to 32 bytes via blake3.
pub fn hash_to_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash a G1 element to 32 bytes.
pub fn hash_g1(g: &G1) -> [u8; 32] {
    hash_to_bytes(&g1_bytes(g))
}

/// Hash a GT element to 32 bytes.
pub fn hash_gt(g: &GT) -> [u8; 32] {
    hash_to_bytes(&g.as_slice())
}

/// XOR two byte slices of equal length.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// A simple transcript for Fiat-Shamir, wrapping blake3.
pub struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Append labeled data to the transcript.
    pub fn append(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(data);
    }

    /// Append a G1 element to the transcript.
    pub fn append_g1(&mut self, label: &[u8], g: &G1) {
        self.append(label, &g1_bytes(g));
    }

    /// Append a G2 element to the transcript.
    pub fn append_g2(&mut self, label: &[u8], g: &G2) {
        self.append(label, &g2_bytes(g));
    }

    /// Append a Scalar to the transcript.
    pub fn append_scalar(&mut self, label: &[u8], s: &Scalar) {
        self.append(label, &scalar_bytes(s));
    }

    /// Derive challenge bytes from the current transcript state.
    pub fn challenge_bytes(&self, output: &mut [u8]) {
        let mut reader = self.hasher.clone().finalize_xof();
        reader.fill(output);
    }
}

/// Lagrange interpolation: given evaluations at `given_domain` points,
/// evaluate the interpolating polynomial at each point in `target_domain`.
///
/// Works for any type T that supports addition and scalar multiplication
/// by Scalar (e.g., Scalar itself, G1, G2).
pub fn lagrange_interp_eval<T>(
    given_domain: &[Scalar],
    target_domain: &[Scalar],
    evals: &[T],
) -> Vec<T>
where
    T: Additive + Space<Scalar> + Clone,
{
    debug_assert_eq!(
        given_domain.len(),
        evals.len(),
        "Evals length does not match given_domain length"
    );

    let mut result = Vec::new();
    for point in target_domain.iter() {
        let mut lagrange_coeffs = vec![Scalar::one(); given_domain.len()];

        for i in 0..given_domain.len() {
            let mut num = Scalar::one();
            let mut denom = Scalar::one();
            for j in 0..given_domain.len() {
                if given_domain[i] != given_domain[j] {
                    num = num * &(point.clone() - &given_domain[j]);
                    denom = denom * &(given_domain[i].clone() - &given_domain[j]);
                }
            }
            lagrange_coeffs[i] = num * &denom.inv();
        }

        let mut point_eval = T::zero();
        for i in 0..given_domain.len() {
            let tmp = evals[i].clone() * &lagrange_coeffs[i];
            point_eval += &tmp;
        }

        result.push(point_eval);
    }

    result
}

/// Evaluate a polynomial (given as coefficients) at a point using Horner's method.
pub fn poly_eval(coeffs: &[Scalar], point: &Scalar) -> Scalar {
    let mut result = Scalar::zero();
    for c in coeffs.iter().rev() {
        result = result * point + c;
    }
    result
}

/// An FFT domain over roots of unity in the BLS12-381 scalar field.
pub struct Domain {
    lg_size: u8,
    omega: Scalar,
    omega_inv: Scalar,
    size_inv: Scalar,
}

impl Domain {
    /// Create a new domain of at least `min_size` elements (rounded up to power of 2).
    pub fn new(min_size: usize) -> Self {
        let size = min_size.next_power_of_two();
        let lg_size = size.ilog2() as u8;
        let omega = Scalar::root_of_unity(lg_size).expect("domain too large for NTT");
        let omega_inv = omega.inv();
        let size_inv = Scalar::from_u64(size as u64).inv();
        Self {
            lg_size,
            omega,
            omega_inv,
            size_inv,
        }
    }

    /// The size of this domain (always a power of 2).
    pub fn size(&self) -> usize {
        1 << self.lg_size
    }

    /// The primitive root of unity (omega) for this domain.
    pub fn group_gen(&self) -> Scalar {
        self.omega.clone()
    }

    /// The i-th element of the domain: omega^i.
    pub fn element(&self, i: usize) -> Scalar {
        self.omega.exp(&[i as u64])
    }

    /// Forward FFT: coefficients -> evaluations at roots of unity.
    pub fn fft<T>(&self, input: &[T]) -> Vec<T>
    where
        T: Additive + Space<Scalar> + Clone,
    {
        let n = self.size();
        let mut data = Vec::with_capacity(n);
        data.extend_from_slice(input);
        data.resize(n, T::zero());
        fft_in_place(&mut data, &self.omega, self.lg_size);
        data
    }

    /// Inverse FFT: evaluations at roots of unity -> coefficients.
    pub fn ifft<T>(&self, input: &[T]) -> Vec<T>
    where
        T: Additive + Space<Scalar> + Clone,
    {
        let n = self.size();
        let mut data = Vec::with_capacity(n);
        data.extend_from_slice(input);
        data.resize(n, T::zero());
        fft_in_place(&mut data, &self.omega_inv, self.lg_size);
        // Divide by N
        for x in &mut data {
            *x *= &self.size_inv;
        }
        data
    }
}

/// In-place Cooley-Tukey radix-2 DIT FFT.
///
/// Works generically over any type supporting addition and scalar multiplication.
fn fft_in_place<T>(data: &mut [T], root: &Scalar, lg_n: u8)
where
    T: Additive + Space<Scalar> + Clone,
{
    let n = data.len();
    assert_eq!(n, 1 << lg_n);

    // Bit-reversal permutation
    for i in 0..n {
        let j = (i as u64).reverse_bits() >> (64 - lg_n as u32);
        if i < j as usize {
            data.swap(i, j as usize);
        }
    }

    // Butterfly stages
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        // w_len = root^(n/len), the principal len-th root of unity
        let w_len = root.exp(&[(n / len) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = Scalar::one();
            for j in 0..half {
                let u = data[k + j].clone();
                let v = data[k + j + half].clone() * &w;
                data[k + j] = u.clone() + &v;
                data[k + j + half] = u - &v;
                w = w * &w_len;
            }
            k += len;
        }
        len <<= 1;
    }
}

/// Computes all KZG opening proofs in O(n log n) time using FK22 amortized technique.
///
/// See <https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf>
pub fn open_all_values(y: &[G1], f: &[Scalar], domain: &Domain) -> Vec<G1> {
    let n = domain.size();
    let top_domain = Domain::new(2 * n);

    // v = {(n+1 0s), f1, ..., fd}
    let mut v = vec![Scalar::zero(); n + 1];
    v.extend_from_slice(&f[1..]);
    debug_assert_eq!(v.len(), 2 * n);
    let v = top_domain.fft(&v);

    // h = y * v (pointwise scalar multiplication)
    let h: Vec<G1> = y.iter().zip(v.iter()).map(|(&yi, vi)| yi * vi).collect();

    // inverse FFT on h
    let mut h = top_domain.ifft(&h);
    h.truncate(n);

    // FFT on h to get KZG proofs
    domain.fft(&h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn open_all_test() {
        let mut rng = test_rng();

        let domain_size = 1 << 5;
        let domain = Domain::new(domain_size);

        let mut dealer =
            super::super::dealer::Dealer::new(domain_size, 1 << 5, domain_size / 2 - 1, &mut rng);
        let (crs, _) = dealer.setup(&mut rng);

        let f: Vec<Scalar> = (0..domain_size).map(|_| Scalar::random(&mut rng)).collect();

        let com = G1::msm(&crs.powers_of_g, &f, &Sequential);
        let pi = open_all_values(&crs.y, &f, &domain);

        // verify the KZG proofs
        let g = G1::generator();
        let h = G2::generator();

        for i in 0..domain_size {
            let eval = poly_eval(&f, &domain.element(i));
            let lhs = pairing(&(com - &(g * &eval)), &h);
            let rhs = pairing(&pi[i], &(crs.htau - &(h * &domain.element(i))));
            assert_eq!(lhs, rhs);
        }
    }

    #[test]
    fn lagrange_interp_eval_test() {
        let mut rng = test_rng();
        let domain_size = 1 << 2;
        let domain: Vec<Scalar> = (0..domain_size)
            .map(|i| Scalar::from_u64(i as u64))
            .collect();

        let points: Vec<Scalar> = (0..domain_size / 2)
            .map(|i| Scalar::from_u64((domain_size + i) as u64))
            .collect();

        let f_coeffs: Vec<Scalar> = (0..domain_size).map(|_| Scalar::random(&mut rng)).collect();

        let evals: Vec<Scalar> = domain.iter().map(|e| poly_eval(&f_coeffs, e)).collect();

        let computed_evals = lagrange_interp_eval(&domain, &points, &evals);
        let should_be_evals: Vec<Scalar> =
            points.iter().map(|p| poly_eval(&f_coeffs, p)).collect();

        for i in 0..points.len() {
            assert_eq!(computed_evals[i], should_be_evals[i]);
        }
    }

    #[test]
    fn fft_roundtrip_scalar() {
        let mut rng = test_rng();
        let n = 1 << 4;
        let domain = Domain::new(n);

        let coeffs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let evals = domain.fft(&coeffs);
        let recovered = domain.ifft(&evals);

        for i in 0..n {
            assert_eq!(coeffs[i], recovered[i]);
        }
    }

    #[test]
    fn fft_roundtrip_g1() {
        let mut rng = test_rng();
        let n = 1 << 4;
        let domain = Domain::new(n);

        let points: Vec<G1> = (0..n)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();
        let evals = domain.fft(&points);
        let recovered = domain.ifft(&evals);

        for i in 0..n {
            assert_eq!(points[i], recovered[i]);
        }
    }
}
