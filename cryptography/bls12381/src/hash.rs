//! Shared RFC 9380 message expansion, SSWU candidates, and isogeny evaluation.

use crate::{
    curve::{Curve, Projective},
    fp::{Arithmetic, Fp, lanes::MAX_LANES, power_of_two},
};
use commonware_math::algebra::{Additive, Ring};
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Builds a constant from canonical little-endian words.
pub(crate) const fn fp(words: [u64; 6]) -> Fp {
    match Fp::from_words(words) {
        Some(value) => value,
        None => panic!("canonical hash-to-curve constant"),
    }
}

/// Reduces a 512-bit big-endian integer with two 256-bit halves.
fn reduce(bytes: &[u8]) -> Fp {
    const RADIX: Fp = fp(power_of_two(256));
    let mut high = [0; 6];
    let mut low = [0; 6];
    for i in 0..4 {
        high[3 - i] = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        low[3 - i] = u64::from_be_bytes(bytes[32 + i * 8..40 + i * 8].try_into().unwrap());
    }
    fp(high).mul(RADIX).add(fp(low))
}

/// Expands a message to a whole number of SHA-256 blocks with SHA-256 (RFC 9380, 5.3.1 and 5.3.3).
pub(crate) fn expand_message_xmd<const N: usize>(dst: &[u8], message: &[u8]) -> [u8; N] {
    assert!(N > 0 && N.is_multiple_of(32) && N <= 255 * 32);
    let shortened;
    let dst = if dst.len() > 255 {
        let mut hash = Sha256::new();
        hash.update(b"H2C-OVERSIZE-DST-");
        hash.update(dst);
        shortened = hash.finalize();
        shortened.as_slice()
    } else {
        dst
    };
    let dst_len = [dst.len() as u8];
    let mut hash = Sha256::new();
    hash.update([0u8; 64]);
    hash.update(message);
    hash.update((N as u16).to_be_bytes());
    hash.update([0]);
    hash.update(dst);
    hash.update(dst_len);
    let b0 = hash.finalize();
    let mut previous = [0u8; 32];
    let mut output = [0u8; N];
    for i in 0..N / 32 {
        let mut input = [0u8; 32];
        for j in 0..32 {
            input[j] = b0[j] ^ previous[j];
        }
        let mut hash = Sha256::new();
        hash.update(input);
        hash.update([i as u8 + 1]);
        hash.update(dst);
        hash.update(dst_len);
        previous.copy_from_slice(&hash.finalize());
        output[i * 32..(i + 1) * 32].copy_from_slice(&previous);
    }
    output
}

/// Hashes to `N` base-field elements, each reduced from 64 bytes (RFC 9380, 5.2).
pub(crate) fn hash_to_field<const N: usize, const BYTES: usize>(
    dst: &[u8],
    message: &[u8],
) -> [Fp; N] {
    assert_eq!(BYTES, N * 64);
    let uniform = expand_message_xmd::<BYTES>(dst, message);
    let mut elements = [Fp::ZERO; N];
    for (i, element) in elements.iter_mut().enumerate() {
        *element = reduce(&uniform[i * 64..(i + 1) * 64]);
    }
    elements
}

/// The two homogeneous x candidates and the first candidate's curve equation.
pub(crate) struct Swu<E> {
    pub zuu: E,
    pub x1: E,
    pub x2: E,
    pub denominator: E,
    pub d3: E,
    pub numerator: E,
}

/// Computes the SSWU candidates on `y^2 = x^3 + a*x + b`.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn swu<F: Arithmetic>(
    curve: &Curve<F>,
    u: F::Element,
    a: F::Scalar,
    b: F::Scalar,
    z: F::Scalar,
) -> Swu<F::Element>
where
    F::Scalar: ConditionallySelectable + ConstantTimeEq,
{
    let f = curve.field;
    let a = f.constant(a);
    let b = f.constant(b);
    let zuu = f.mul(f.constant(z), f.square(u));
    let t = f.add(f.square(zuu), zuu);
    let x1 = f.mul(b, f.add(t, f.constant(F::Scalar::one())));
    let x2 = f.mul(zuu, x1);

    // The exceptional denominator is Z * A when t = 0.
    let mut ts = [F::Scalar::zero(); MAX_LANES];
    f.store(f.neg(t), &mut ts);
    for t in &mut ts[..F::LANES] {
        *t = F::Scalar::conditional_select(t, &z, t.ct_eq(&F::Scalar::zero()));
    }
    let denominator = f.mul(a, f.load(&ts, z));
    let d2 = f.square(denominator);
    let d3 = f.mul(d2, denominator);
    let numerator = f.add(f.mul(f.add(f.square(x1), f.mul(a, d2)), x1), f.mul(b, d3));
    Swu {
        zuu,
        x1,
        x2,
        denominator,
        d3,
        numerator,
    }
}

/// Evaluates z^degree * polynomial(x / z) with Horner's rule.
#[cfg_attr(not(debug_assertions), inline(always))]
fn evaluate<F: Arithmetic>(
    curve: &Curve<F>,
    x: F::Element,
    z: F::Element,
    coefficients: &[F::Scalar],
) -> F::Element {
    let f = curve.field;
    let mut value = f.constant(coefficients[coefficients.len() - 1]);
    let mut power = z;
    for coefficient in coefficients[..coefficients.len() - 1].iter().rev() {
        value = f.add(f.mul(value, x), f.mul(f.constant(*coefficient), power));
        power = f.mul(power, z);
    }
    value
}

/// Applies an isogeny whose x numerator has one more degree than its denominator.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn isogeny<F: Arithmetic>(
    curve: &Curve<F>,
    p: Projective<F::Element>,
    x_num: &[F::Scalar],
    x_den: &[F::Scalar],
    y_num: &[F::Scalar],
    y_den: &[F::Scalar],
) -> Projective<F::Element>
where
    F::Scalar: ConditionallySelectable + ConstantTimeEq,
{
    let f = curve.field;
    let xn = evaluate(curve, p.x, p.z, x_num);
    let xd = f.mul(evaluate(curve, p.x, p.z, x_den), p.z);
    let yn = f.mul(evaluate(curve, p.x, p.z, y_num), p.y);
    let yd = f.mul(evaluate(curve, p.x, p.z, y_den), p.z);
    let point = Projective {
        x: f.mul(xn, yd),
        y: f.mul(yn, xd),
        z: f.mul(xd, yd),
    };

    // A pole of either rational function maps to the identity.
    let mut points = [Projective {
        x: F::Scalar::zero(),
        y: F::Scalar::one(),
        z: F::Scalar::zero(),
    }; MAX_LANES];
    curve.store(point, &mut points);
    for point in &mut points[..F::LANES] {
        let infinity = point.z.ct_eq(&F::Scalar::zero());
        point.x = F::Scalar::conditional_select(&point.x, &F::Scalar::zero(), infinity);
        point.y = F::Scalar::conditional_select(&point.y, &F::Scalar::one(), infinity);
    }
    curve.load(&points[..F::LANES])
}
