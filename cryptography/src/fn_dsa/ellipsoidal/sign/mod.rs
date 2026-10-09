//! Checked weighted LDL sampling with exact integer lattice reconstruction.

mod flr;
mod poly;
mod sampler;

use super::{
    KeyMaterial,
    alloc::{vec, vec::Vec},
};
use flr::FLR;
use fn_dsa_comm::mq;
use sampler::Sampler;
use zeroize::Zeroizing;

const LOGN: u32 = 9;
const N: usize = 512;
const WEIGHT: i64 = 1296;
const DETERMINANT: i64 = 195_721_299_216;
const NORM_LIMIT: u64 = 1_225_250_136;
const INV_SIGMA: FLR = FLR::scaled(6956347512113097, -60);

pub(super) struct Prepared<'a> {
    key: &'a KeyMaterial,
    tree: Zeroizing<Vec<FLR>>,
    f: Zeroizing<[FLR; N]>,
    big_f: Zeroizing<[FLR; N]>,
}

pub(super) fn acceptable_fg(f: &[i8; N], g: &[i8; N]) -> bool {
    if !valid_fg(f, g) {
        return false;
    }
    let f = fft(f);
    let g = fft(g);
    build_tree(&f, &g, None).is_some()
}

pub(super) fn check_key(key: &KeyMaterial) -> bool {
    Prepared::new(key).is_some()
}

impl<'a> Prepared<'a> {
    pub(super) fn new(key: &'a KeyMaterial) -> Option<Self> {
        if !valid_fg(&key.f, &key.g)
            || key
                .big_f
                .iter()
                .chain(&key.big_g)
                .any(|v| v.unsigned_abs() > 2047)
            || !exact_equation(key)
        {
            return None;
        }
        let f = fft(&key.f);
        let g = fft(&key.g);
        let big_f = fft(&key.big_f);
        let big_g = fft(&key.big_g);
        let tree = build_tree(&f, &g, Some((&big_f, &big_g)))?;
        Some(Self {
            key,
            tree,
            f,
            big_f,
        })
    }

    /// Outer failure denotes an arithmetic-domain violation; inner failure is rejection.
    pub(super) fn sample(
        &self,
        target: &[u16; N],
        seed: &[u8; 40],
    ) -> Option<Option<Zeroizing<[i16; N]>>> {
        let mut t0 = fft(target);
        let mut t1 = Zeroizing::new(*t0);
        poly::poly_mul_fft(LOGN, &mut *t0, &*self.big_f);
        poly::poly_mul_fft(LOGN, &mut *t1, &*self.f);
        let inverse_q = FLR::ONE / FLR::from_i64(12289);
        for i in 0..N {
            t0[i] *= -inverse_q;
            t1[i] *= inverse_q;
        }
        let mut scratch = Zeroizing::new(vec![FLR::ZERO; 4 * N]);
        let mut sampler = Sampler::new(seed);
        sample_tree(
            LOGN,
            &self.tree,
            &mut t0[..],
            &mut t1[..],
            &mut sampler,
            &mut scratch,
        )?;
        poly::iFFT(LOGN, &mut *t0);
        poly::iFFT(LOGN, &mut *t1);
        let mut z0 = Zeroizing::new([0i64; N]);
        let mut z1 = Zeroizing::new([0i64; N]);
        for i in 0..N {
            if !bounded(t0[i], 1 << 28) || !bounded(t1[i], 1 << 28) {
                return None;
            }
            z0[i] = t0[i].rint();
            z1[i] = t1[i].rint();
        }

        // Integer products make the lattice equation exact even after FFT rounding.
        // With |z| <= 2^28 and |F|,|G| <= 2047, each sum is below 2^50.
        let mut s = Zeroizing::new([0i64; N]);
        let mut residual = Zeroizing::new([0i64; N]);
        add_product(&z0, &self.key.f, &mut s, 1);
        add_product(&z1, &self.key.big_f, &mut s, 1);
        add_product(&z0, &self.key.g, &mut residual, -1);
        add_product(&z1, &self.key.big_g, &mut residual, -1);
        let mut in_range = true;
        for i in 0..N {
            residual[i] += i64::from(target[i]);
            in_range &= s[i].unsigned_abs() <= 972 && residual[i].unsigned_abs() <= 35003;
        }
        if !in_range {
            return Some(None);
        }
        let mut norm = 0u64;
        let mut out = Zeroizing::new([0i16; N]);
        for i in 0..N {
            norm += (WEIGHT * s[i] * s[i] + residual[i] * residual[i]) as u64;
            out[i] = s[i] as i16;
        }
        Some((norm <= NORM_LIMIT).then_some(out))
    }
}

fn valid_fg(f: &[i8; N], g: &[i8; N]) -> bool {
    let mut weight = 0u32;
    let mut norm = 0i64;
    let mut parity = 0i32;
    let mut valid = true;
    for i in 0..N {
        valid &= f[i].unsigned_abs() <= 1 && g[i] != i8::MIN;
        weight += u32::from(f[i] != 0);
        norm += WEIGHT * i64::from(f[i]).pow(2) + i64::from(g[i]).pow(2);
        parity += i32::from(g[i]);
    }
    let mut scratch = Zeroizing::new([0; N]);
    valid
        && weight == 233
        && norm <= 605000
        && parity & 1 == 1
        && mq::mqpoly_small_is_invertible(LOGN, f, &mut *scratch)
}

fn exact_equation(key: &KeyMaterial) -> bool {
    let f = Zeroizing::new(key.f.map(i64::from));
    let g = Zeroizing::new(key.g.map(i64::from));
    let mut determinant = Zeroizing::new([0i64; N]);
    add_product(&f, &key.big_g, &mut determinant, 1);
    add_product(&g, &key.big_f, &mut determinant, -1);
    determinant[0] == 12289 && determinant[1..].iter().all(|v| *v == 0)
}

fn add_product<T: Copy + Into<i64>>(a: &[i64; N], b: &[T; N], out: &mut [i64; N], sign: i64) {
    for i in 0..N {
        for j in 0..N {
            let value = sign * a[i] * b[j].into();
            if i + j < N {
                out[i + j] += value;
            } else {
                out[i + j - N] -= value;
            }
        }
    }
}

fn fft<T: Copy + Into<i64>>(values: &[T; N]) -> Zeroizing<[FLR; N]> {
    let mut out = Zeroizing::new(values.map(|v| FLR::from_i64(v.into())));
    poly::FFT(LOGN, &mut *out);
    out
}

const fn bounded(value: FLR, maximum: i64) -> bool {
    value.bits() & 0x7FFF_FFFF_FFFF_FFFF <= FLR::from_i64(maximum).bits()
}

const fn positive(value: FLR, minimum: i64, maximum: i64) -> bool {
    value.bits() >= FLR::from_i64(minimum).bits() && value.bits() <= FLR::from_i64(maximum).bits()
}

const fn tree_size(logn: u32) -> usize {
    (logn as usize + 1) << logn
}

fn build_tree(
    f: &[FLR; N],
    g: &[FLR; N],
    basis: Option<(&[FLR; N], &[FLR; N])>,
) -> Option<Zeroizing<Vec<FLR>>> {
    let mut a = Zeroizing::new([FLR::ZERO; N]);
    let mut d = Zeroizing::new([FLR::ZERO; N]);
    let mut tree = Zeroizing::new(vec![FLR::ZERO; tree_size(LOGN)]);
    let mut orthogonal_norm = FLR::ZERO;
    let weight = FLR::from_i64(WEIGHT);
    for i in 0..N / 2 {
        a[i] = g[i].square()
            + g[i + N / 2].square()
            + weight * (f[i].square() + f[i + N / 2].square());
        if !positive(a[i], 256, 1 << 30) {
            return None;
        }
        d[i] = FLR::from_i64(DETERMINANT) / a[i];
        if !positive(d[i], 256, 1 << 30) {
            return None;
        }
        orthogonal_norm += d[i];
        if let Some((big_f, big_g)) = basis {
            let real = g[i] * big_g[i]
                + g[i + N / 2] * big_g[i + N / 2]
                + weight * (f[i] * big_f[i] + f[i + N / 2] * big_f[i + N / 2]);
            let imaginary = g[i + N / 2] * big_g[i] - g[i] * big_g[i + N / 2]
                + weight * (f[i + N / 2] * big_f[i] - f[i] * big_f[i + N / 2]);
            tree[i] = real / a[i];
            tree[i + N / 2] = -imaginary / a[i];
            if !bounded(tree[i], 1 << 30) || !bounded(tree[i + N / 2], 1 << 30) {
                return None;
            }
        }
    }
    if !positive(orthogonal_norm, 1, 605000 * (N as i64 / 2)) {
        return None;
    }
    let mut scratch = Zeroizing::new(vec![FLR::ZERO; 3 * N]);
    build_children(LOGN, &a[..], &d[..], &mut tree, &mut scratch)?;
    Some(tree)
}

fn build_children(
    logn: u32,
    a: &[FLR],
    d: &[FLR],
    tree: &mut [FLR],
    scratch: &mut [FLR],
) -> Option<()> {
    if logn == 1 {
        if !positive(a[0], 300000, 605000) || !positive(d[0], 300000, 605000) {
            return None;
        }
        let inverse_sigma = INV_SIGMA / FLR::from_i64(6);
        tree[2] = a[0].sqrt() * inverse_sigma;
        tree[3] = d[0].sqrt() * inverse_sigma;
        return Some(());
    }
    let n = 1usize << logn;
    let hn = n / 2;
    let (g00, rest) = scratch.split_at_mut(hn);
    let (g01, rest) = rest.split_at_mut(hn);
    let (g11, recursion) = rest.split_at_mut(hn);
    let (_, children) = tree.split_at_mut(n);
    let (left, right) = children.split_at_mut(tree_size(logn - 1));
    poly::poly_split_selfadj_fft(logn, g00, g01, a);
    g11.copy_from_slice(g00);
    build_node(logn - 1, g00, g01, g11, left, recursion)?;
    poly::poly_split_selfadj_fft(logn, g00, g01, d);
    g11.copy_from_slice(g00);
    build_node(logn - 1, g00, g01, g11, right, recursion)
}

fn build_node(
    logn: u32,
    a: &mut [FLR],
    b: &mut [FLR],
    d: &mut [FLR],
    tree: &mut [FLR],
    scratch: &mut [FLR],
) -> Option<()> {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        if !positive(a[i], 256, 1 << 30)
            || !positive(d[i], 256, 1 << 30)
            || !bounded(b[i], 1 << 30)
            || !bounded(b[i + hn], 1 << 30)
        {
            return None;
        }
        let real = b[i] / a[i];
        let imaginary = b[i + hn] / a[i];
        d[i] -= real * b[i] + imaginary * b[i + hn];
        if !positive(d[i], 256, 1 << 30) {
            return None;
        }
        d[i + hn] = FLR::ZERO;
        tree[i] = real;
        tree[i + hn] = -imaginary;
    }
    build_children(logn, a, d, tree, scratch)
}

fn sample_tree(
    logn: u32,
    tree: &[FLR],
    t0: &mut [FLR],
    t1: &mut [FLR],
    sampler: &mut Sampler,
    scratch: &mut [FLR],
) -> Option<()> {
    if logn == 1 {
        if !bounded(t1[0], 1 << 30) || !bounded(t1[1], 1 << 30) {
            return None;
        }
        let z1_re = FLR::from_i64(i64::from(sampler.next(t1[0], tree[3])));
        let z1_im = FLR::from_i64(i64::from(sampler.next(t1[1], tree[3])));
        let re = t1[0] - z1_re;
        let im = t1[1] - z1_im;
        t0[0] += re * tree[0] - im * tree[1];
        t0[1] += re * tree[1] + im * tree[0];
        if !bounded(t0[0], 1 << 30) || !bounded(t0[1], 1 << 30) {
            return None;
        }
        t1[0] = z1_re;
        t1[1] = z1_im;
        t0[0] = FLR::from_i64(i64::from(sampler.next(t0[0], tree[2])));
        t0[1] = FLR::from_i64(i64::from(sampler.next(t0[1], tree[2])));
        return Some(());
    }
    let n = 1usize << logn;
    let hn = n / 2;
    let (split, rest) = scratch.split_at_mut(n);
    let (z1, recursion) = rest.split_at_mut(n);
    let (w0, w1) = split.split_at_mut(hn);
    let (coupling, children) = tree.split_at(n);
    let (left, right) = children.split_at(tree_size(logn - 1));
    poly::poly_split_fft(logn, w0, w1, t1);
    sample_tree(logn - 1, right, w0, w1, sampler, recursion)?;
    poly::poly_merge_fft(logn, z1, w0, w1);
    for i in 0..n {
        split[i] = t1[i] - z1[i];
        t1[i] = z1[i];
    }
    poly::poly_mul_fft(logn, split, coupling);
    for i in 0..n {
        t0[i] += split[i];
    }
    let (w0, w1) = split.split_at_mut(hn);
    poly::poly_split_fft(logn, w0, w1, t0);
    sample_tree(logn - 1, left, w0, w1, sampler, recursion)?;
    poly::poly_merge_fft(logn, t0, w0, w1);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("metric_key_fixture.rs");

    #[test]
    fn leaf_bounds_control_gaussian_parameters() {
        let mut tree = [FLR::ZERO; 4];
        for value in [300000, 605000] {
            let diagonal = [FLR::from_i64(value), FLR::ZERO];
            build_children(1, &diagonal, &diagonal, &mut tree, &mut []).unwrap();
            let width = 1.0 / f64::from_bits(tree[2].bits());
            assert!((1.2778336969128337..=1.8205).contains(&width));
        }
        for value in [299999, 605001] {
            let diagonal = [FLR::from_i64(value), FLR::ZERO];
            assert!(build_children(1, &diagonal, &diagonal, &mut tree, &mut []).is_none());
        }
    }

    #[test]
    fn rejects_nonfinite_and_negative_arithmetic_inputs() {
        for raw in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
            let value = FLR::decode(&raw.to_le_bytes()).unwrap();
            assert!(!positive(value, 256, 1 << 30));
            if !raw.is_finite() {
                assert!(!bounded(value, 1 << 30));
            }
        }
    }

    fn tree_energy(logn: u32, tree: &[FLR], z0: &[FLR], z1: &[FLR]) -> f64 {
        let n = 1 << logn;
        let mut adjusted = z1.to_vec();
        poly::poly_mul_fft(logn, &mut adjusted, &tree[..n]);
        for i in 0..n {
            adjusted[i] += z0[i];
        }
        if logn == 1 {
            let inverse_sigma = f64::from_bits((INV_SIGMA / FLR::from_i64(6)).bits());
            let d0 = (f64::from_bits(tree[2].bits()) / inverse_sigma).powi(2);
            let d1 = (f64::from_bits(tree[3].bits()) / inverse_sigma).powi(2);
            return d0
                * adjusted
                    .iter()
                    .map(|v| f64::from_bits(v.bits()).powi(2))
                    .sum::<f64>()
                + d1 * z1
                    .iter()
                    .map(|v| f64::from_bits(v.bits()).powi(2))
                    .sum::<f64>();
        }
        let hn = n / 2;
        let mut split = vec![FLR::ZERO; n];
        let (low, high) = split.split_at_mut(hn);
        let (_, children) = tree.split_at(n);
        let (left, right) = children.split_at(tree_size(logn - 1));
        poly::poly_split_fft(logn, low, high, &adjusted);
        let e0 = tree_energy(logn - 1, left, low, high);
        poly::poly_split_fft(logn, low, high, z1);
        e0 + tree_energy(logn - 1, right, low, high)
    }

    #[test]
    fn recursive_ldl_preserves_the_original_quadratic_form() {
        for logn in 2..=LOGN {
            let n = 1 << logn;
            let hn = n / 2;
            let original_a: Vec<_> = (0..n)
                .map(|i| {
                    FLR::from_i64(if i < hn {
                        400000 + (i % 7) as i64 * 1000
                    } else {
                        0
                    })
                })
                .collect();
            let original_b: Vec<_> = (0..n)
                .map(|i| FLR::from_i64((i % 5) as i64 * 2500 - 5000))
                .collect();
            let original_d: Vec<_> = (0..n)
                .map(|i| {
                    FLR::from_i64(if i < hn {
                        480000 - (i % 11) as i64 * 1000
                    } else {
                        0
                    })
                })
                .collect();
            let (mut a, mut b, mut d) =
                (original_a.clone(), original_b.clone(), original_d.clone());
            let mut tree = vec![FLR::ZERO; tree_size(logn)];
            let mut scratch = vec![FLR::ZERO; 3 * n];
            build_node(logn, &mut a, &mut b, &mut d, &mut tree, &mut scratch).unwrap();
            let z0: Vec<_> = (0..n).map(|i| FLR::from_i64((i % 17) as i64 - 8)).collect();
            let z1: Vec<_> = (0..n).map(|i| FLR::from_i64((i % 13) as i64 - 6)).collect();
            let mut expected = 0.0;
            for i in 0..hn {
                let x = f64::from_bits(z0[i].bits());
                let y = f64::from_bits(z0[i + hn].bits());
                let u = f64::from_bits(z1[i].bits());
                let v = f64::from_bits(z1[i + hn].bits());
                let a = f64::from_bits(original_a[i].bits());
                let d = f64::from_bits(original_d[i].bits());
                let b = f64::from_bits(original_b[i].bits());
                let c = f64::from_bits(original_b[i + hn].bits());
                expected += a * (x * x + y * y)
                    + d * (u * u + v * v)
                    + 2.0 * ((x * b - y * c) * u + (x * c + y * b) * v);
            }
            expected *= 2.0 / n as f64;
            let actual = tree_energy(logn, &tree, &z0, &z1);
            assert!(
                (actual - expected).abs() < expected * 1e-12,
                "logn={logn}: {actual} != {expected}"
            );
        }
    }

    #[test]
    fn root_metric_matches_physical_quadratic_form() {
        let key = METRIC_KEY;
        let prepared = Prepared::new(&key).expect("captured key must satisfy admission");
        let f = fft(&key.f);
        let g = fft(&key.g);
        let big_f = fft(&key.big_f);
        let big_g = fft(&key.big_g);
        let z0: Vec<_> = (0..N).map(|i| FLR::from_i64((i % 17) as i64 - 8)).collect();
        let z1: Vec<_> = (0..N).map(|i| FLR::from_i64((i % 13) as i64 - 6)).collect();
        let mut expected = 0.0;
        for i in 0..N / 2 {
            let complex = |x: &[FLR]| {
                (
                    f64::from_bits(x[i].bits()),
                    f64::from_bits(x[i + N / 2].bits()),
                )
            };
            let (x, y) = complex(&z0);
            let (u, v) = complex(&z1);
            let norm = |a: &[FLR], b: &[FLR]| {
                let (ar, ai) = complex(a);
                let (br, bi) = complex(b);
                let re = x * ar - y * ai + u * br - v * bi;
                let im = x * ai + y * ar + u * bi + v * br;
                re * re + im * im
            };
            expected += norm(&g[..], &big_g[..]) + 1296.0 * norm(&f[..], &big_f[..]);
        }
        expected *= 2.0 / N as f64;
        let actual = tree_energy(LOGN, &prepared.tree, &z0, &z1);
        let relative_error = (actual - expected).abs() / expected;
        std::println!(
            "ROOT_METRIC actual={actual:.17e} expected={expected:.17e} relative_error={relative_error:.17e}"
        );
        assert!(
            relative_error < 1e-12,
            "root metric: {actual} != {expected}"
        );
    }

    #[test]
    fn negacyclic_products_use_integer_wrap_signs() {
        let mut a = [0; N];
        let mut b = [0i16; N];
        a[0] = 2;
        a[N - 1] = 3;
        b[0] = 5;
        b[1] = 7;
        let mut product = [0; N];
        add_product(&a, &b, &mut product, 1);
        assert_eq!(product[0], -11);
        assert_eq!(product[1], 14);
        assert_eq!(product[N - 1], 15);
        assert!(product[2..N - 1].iter().all(|v| *v == 0));
    }
}
