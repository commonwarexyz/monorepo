//! X25519 scalar multiplication on the Montgomery form of curve25519.

use super::F;
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

/// `(A - 2) / 4 = 121665`, where `A = 486662` is the coefficient of the Montgomery curve
/// `v^2 = u^3 + A*u^2 + u`.
const A24: F = F([121665, 0, 0, 0, 0]);

/// The X25519 function of [RFC 7748]: multiplies the point with u-coordinate `u` by `scalar`.
///
/// The scalar is clamped before use, and bit 255 of `u` is ignored, both per the RFC. The
/// output is the u-coordinate of the resulting point, or all zeros when that point is the
/// identity, which happens exactly when the input point has low order.
///
/// The Montgomery ladder performs the same field operations for every scalar, selecting
/// values with masks rather than secret-dependent branches or indexing.
///
/// [RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748#section-5
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut scalar = Zeroizing::new(*scalar);
    // Clearing the three low bits makes the scalar a multiple of the cofactor, 8. Forcing bit
    // 254 on and bit 255 off gives every scalar the same bit length.
    scalar[0] &= 0b1111_1000;
    scalar[31] &= 0b0111_1111;
    scalar[31] |= 0b0100_0000;
    let x1 = F::from_bytes(u);
    let mut x2 = F::ONE;
    let mut z2 = F::ZERO;
    let mut x3 = x1;
    let mut z3 = F::ONE;

    // Each step conditionally swaps (x2, z2) with (x3, z3) so that the pair holding k*P for the
    // scalar's processed prefix k is always the one the formulas expect. Tracking the XOR of
    // consecutive bits performs one swap per iteration instead of two.
    let mut swap = Choice::from(0);
    // A clamped scalar has bit 255 clear, so 255 iterations cover every bit that can be set.
    for t in (0..255).rev() {
        let bit = Choice::from((scalar[t / 8] >> (t % 8)) & 1);
        swap ^= bit;
        F::conditional_swap(&mut x2, &mut x3, swap);
        F::conditional_swap(&mut z2, &mut z3, swap);
        swap = bit;

        // One combined doubling of (x2, z2) and differential addition of (x2, z2) and (x3, z3),
        // following the formulas of RFC 7748, section 5.
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(A24.mul(e)));
    }

    let x2 = F::conditional_select(&x2, &x3, swap);
    let z2 = F::conditional_select(&z2, &z3, swap);
    // When the result is the identity, z2 is zero, and so is its "inverse" z2^(p - 2), making
    // the output all zeros.
    x2.mul(z2.invert()).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::x25519;
    use commonware_formatting::hex;

    #[test]
    fn rfc7748_vector_1() {
        let scalar = hex!("0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex!("0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = hex!("0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_vector_2() {
        let scalar = hex!("0x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        // Bit 255 of this coordinate is set, checking that it gets ignored.
        let u = hex!("0xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = hex!("0x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_iterated() {
        let mut k = hex!("0x0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for i in 1..=1000 {
            let next = x25519(&k, &u);
            u = k;
            k = next;
            if i == 1 {
                let after_one =
                    hex!("0x422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
                assert_eq!(k, after_one);
            }
        }
        let after_thousand =
            hex!("0x684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        assert_eq!(k, after_thousand);
    }
}
