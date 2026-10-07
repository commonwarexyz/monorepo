//! Single-point products shared between the integer and NEON execution units.
//!
//! Two independent products use a NEON tile while the remaining products use scalar `u128`.
//! Coordinates retain the scalar field representation, with every limb below `2^52`.

use super::{
    Backend, Regs, digit_mac, digit_product, digit_times19, mul19, pack_pair, reduce_columns,
    split_pairs, square_regs, unpack_pair,
};
use crate::curve::{F, G, GCompleted, GProjective, Niels, ProjectiveNiels, basepoint};
use core::arch::aarch64::*;

impl crate::curve::Backend for Backend {
    type Extended = G;
    type Projective = GProjective;
    type Completed = GCompleted;
    type Cached = ProjectiveNiels;

    #[inline(always)]
    fn load(self, point: &G) -> G {
        *point
    }

    #[inline(always)]
    fn store(self, point: G) -> G {
        point
    }

    #[inline(always)]
    fn store_projective(self, point: GProjective) -> GProjective {
        point
    }

    #[inline(always)]
    fn identity(self) -> G {
        G::IDENTITY
    }

    #[inline(always)]
    fn project(self, point: G) -> GProjective {
        point.to_projective()
    }

    #[inline(always)]
    fn double(self, point: GProjective) -> GCompleted {
        let [a, b] = square_pair(point.x, point.y);
        let c = point.z.square();
        let c = c.add(c);
        let e = point.x.add(point.y).square().sub(a).sub(b);
        let g = b.sub(a);
        let f = g.sub(c);
        let h = a.neg().sub(b);
        GCompleted {
            x: e,
            y: h,
            z: g,
            t: f,
        }
    }

    #[inline(always)]
    fn to_projective(self, point: GCompleted) -> GProjective {
        let [x, y] = mul_pair(point.x, point.t, point.z, point.y);
        GProjective {
            x,
            y,
            z: point.t.mul(point.z),
        }
    }

    #[inline(always)]
    fn to_extended(self, point: GCompleted) -> G {
        let [x, y] = mul_pair(point.x, point.t, point.z, point.y);
        G {
            x,
            y,
            t: point.x.mul(point.y),
            z: point.t.mul(point.z),
        }
    }

    #[inline(always)]
    fn cache(self, point: G) -> ProjectiveNiels {
        point.to_projective_niels()
    }

    #[inline(always)]
    fn add_cached(self, point: G, cached: ProjectiveNiels, negate: bool) -> GCompleted {
        let cached = if negate { cached.negate() } else { cached };
        let [a, b] = mul_pair(
            point.y.sub(point.x),
            cached.diff,
            point.y.add(point.x),
            cached.sum,
        );
        let c = point.t.mul(cached.t2d);
        let d = point.z.mul(cached.z);
        GCompleted::from_products(a, b, c, d.add(d))
    }

    #[inline(always)]
    fn add_niels(self, point: G, niels: &Niels, negate: bool) -> GCompleted {
        let niels = if negate { niels.negate() } else { *niels };
        add_niels(point, niels)
    }

    #[inline(always)]
    fn add_selected(self, point: G, row: &[Niels; 8], digit: i8) -> GCompleted {
        add_niels(point, basepoint::select(row, digit))
    }
}

/// The completed mixed-addition formula with the `A` and `B` products on the tile.
#[inline(always)]
fn add_niels(point: G, niels: Niels) -> GCompleted {
    let [a, b] = mul_pair(
        point.y.sub(point.x),
        niels.diff,
        point.y.add(point.x),
        niels.sum,
    );
    let c = point.t.mul(niels.t2d);
    GCompleted::from_products(a, b, c, point.z.add(point.z))
}

/// Returns `[a * b, c * d]` with one tile multiplication.
#[inline(always)]
fn mul_pair(a: F, b: F, c: F, d: F) -> [F; 2] {
    unpack_pair(mul_karatsuba(pack_pair([a, c]), pack_pair([b, d])))
}

/// Returns `[a^2, b^2]` with one tile squaring.
#[inline(always)]
fn square_pair(a: F, b: F) -> [F; 2] {
    unpack_pair(square_regs(pack_pair([a, b])))
}

/// Five-column convolution with columns above four folded by `2^255 = 19 (mod p)`.
/// Each input digit is below `2^27`, so scaling by 19 fits `u32` and columns fit `u64`.
#[inline(always)]
fn convolution(a: [uint32x2_t; 5], b: [uint32x2_t; 5]) -> [uint64x2_t; 5] {
    let b1 = digit_times19(b[1]);
    let b2 = digit_times19(b[2]);
    let b3 = digit_times19(b[3]);
    let b4 = digit_times19(b[4]);
    let mut c0 = digit_product(a[0], b[0]);
    c0 = digit_mac(c0, a[1], b4);
    c0 = digit_mac(c0, a[2], b3);
    c0 = digit_mac(c0, a[3], b2);
    c0 = digit_mac(c0, a[4], b1);
    let mut c1 = digit_product(a[0], b[1]);
    c1 = digit_mac(c1, a[1], b[0]);
    c1 = digit_mac(c1, a[2], b4);
    c1 = digit_mac(c1, a[3], b3);
    c1 = digit_mac(c1, a[4], b2);
    let mut c2 = digit_product(a[0], b[2]);
    c2 = digit_mac(c2, a[1], b[1]);
    c2 = digit_mac(c2, a[2], b[0]);
    c2 = digit_mac(c2, a[3], b4);
    c2 = digit_mac(c2, a[4], b3);
    let mut c3 = digit_product(a[0], b[3]);
    c3 = digit_mac(c3, a[1], b[2]);
    c3 = digit_mac(c3, a[2], b[1]);
    c3 = digit_mac(c3, a[3], b[0]);
    c3 = digit_mac(c3, a[4], b4);
    let mut c4 = digit_product(a[0], b[4]);
    c4 = digit_mac(c4, a[1], b[3]);
    c4 = digit_mac(c4, a[2], b[2]);
    c4 = digit_mac(c4, a[3], b[1]);
    c4 = digit_mac(c4, a[4], b[0]);
    [c0, c1, c2, c3, c4]
}

/// Multiplies two field elements per tile with three 25-product convolutions.
///
/// Splitting each limb at bit 26 gives low and high parts at most `M = 2^26 - 1`.
/// The sum convolution is at most `77*(2*M)^2 < 2^61`, and subtracting the low and high
/// convolutions leaves the nonnegative cross terms. The reconstructed columns satisfy
/// the bounds of `reduce_columns`, which restores limbs below `2^52`.
#[inline(always)]
fn mul_karatsuba(a: Regs, b: Regs) -> Regs {
    let a = split_pairs(a);
    let b = split_pairs(b);

    // SAFETY: AArch64 provides NEON. Half sums fit 27 bits, column arithmetic fits u64,
    // and the low and high convolutions are disjoint subsets of the sum convolution.
    unsafe {
        let a_sum = [
            vadd_u32(a[0].lo, a[0].hi),
            vadd_u32(a[1].lo, a[1].hi),
            vadd_u32(a[2].lo, a[2].hi),
            vadd_u32(a[3].lo, a[3].hi),
            vadd_u32(a[4].lo, a[4].hi),
        ];
        let b_sum = [
            vadd_u32(b[0].lo, b[0].hi),
            vadd_u32(b[1].lo, b[1].hi),
            vadd_u32(b[2].lo, b[2].hi),
            vadd_u32(b[3].lo, b[3].hi),
            vadd_u32(b[4].lo, b[4].hi),
        ];
        let lo = convolution(a.map(|p| p.lo), b.map(|p| p.lo));
        let hi = convolution(a.map(|p| p.hi), b.map(|p| p.hi));
        let sum = convolution(a_sum, b_sum);
        reduce_columns([
            vaddq_u64(lo[0], vshlq_n_u64::<1>(mul19(hi[4]))),
            vsubq_u64(vsubq_u64(sum[0], lo[0]), hi[0]),
            vaddq_u64(lo[1], vshlq_n_u64::<1>(hi[0])),
            vsubq_u64(vsubq_u64(sum[1], lo[1]), hi[1]),
            vaddq_u64(lo[2], vshlq_n_u64::<1>(hi[1])),
            vsubq_u64(vsubq_u64(sum[2], lo[2]), hi[2]),
            vaddq_u64(lo[3], vshlq_n_u64::<1>(hi[2])),
            vsubq_u64(vsubq_u64(sum[3], lo[3]), hi[3]),
            vaddq_u64(lo[4], vshlq_n_u64::<1>(hi[3])),
            vsubq_u64(vsubq_u64(sum[4], lo[4]), hi[4]),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(values: [F; 4]) {
        let [a, b, c, d] = values;
        for (actual, expected) in mul_pair(a, b, c, d).into_iter().zip([a.mul(b), c.mul(d)]) {
            assert!(actual.0.iter().all(|limb| *limb < 1 << 52));
            assert_eq!(actual.to_bytes(), expected.to_bytes());
        }
        for (actual, expected) in square_pair(a, c).into_iter().zip([a.square(), c.square()]) {
            assert!(actual.0.iter().all(|limb| *limb < 1 << 52));
            assert_eq!(actual.to_bytes(), expected.to_bytes());
        }
    }

    #[test]
    fn tile_products_match_scalar() {
        let max = F([(1 << 52) - 1; 5]);
        for a in [F::ZERO, F::ONE, max] {
            for b in [F::ZERO, F::ONE, max] {
                check([a, b, b, a]);
            }
        }
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(512)
            .test(|u| {
                let values: [[u64; 5]; 4] = u.arbitrary()?;
                check(values.map(|v| F(v.map(|limb| limb & ((1 << 52) - 1)))));
                Ok(())
            });
    }
}
