//! Plain-Rust field and group arithmetic, usable on any target.

use super::{F, FBackend, FVec, GAffineVec, GBackend, GVec, LANES};

/// The low 51 bits: what a limb holds once carries have been propagated out of it.
const MASK_51: u64 = (1 << 51) - 1;

/// The portable backend token.
///
/// This is the correctness reference for accelerated backends, so its implementation favors
/// obviously correct arithmetic over backend-specific optimizations. All operations are
/// variable-time because they operate only on public data.
///
/// Freely constructible: unlike the accelerated backends, the portable one needs no CPU
/// feature, so possession proves nothing and gates nothing.
#[derive(Clone, Copy)]
pub(super) struct Backend;

impl Backend {
    pub(super) const fn new() -> Self {
        Self
    }
}

/// `2d` in every lane, for the `C = 2d*T1*T2` term of point addition.
const EDWARDS_D2: FVec = F::EDWARDS_D2.splat();

/// Applies a per-lane limb function across all lanes of one input.
fn map1(a: FVec, f: impl Fn([u64; 5]) -> [u64; 5]) -> FVec {
    let mut out = FVec {
        limbs: [[0; LANES]; 5],
    };
    for lane in 0..LANES {
        let result = f(a.limbs.map(|limb| limb[lane]));
        for (row, limb) in out.limbs.iter_mut().zip(result) {
            row[lane] = limb;
        }
    }
    out
}

/// Applies a per-lane limb function across all lanes of two inputs.
fn map2(a: FVec, b: FVec, f: impl Fn([u64; 5], [u64; 5]) -> [u64; 5]) -> FVec {
    let mut out = FVec {
        limbs: [[0; LANES]; 5],
    };
    for lane in 0..LANES {
        let result = f(
            a.limbs.map(|limb| limb[lane]),
            b.limbs.map(|limb| limb[lane]),
        );
        for (row, limb) in out.limbs.iter_mut().zip(result) {
            row[lane] = limb;
        }
    }
    out
}

/// One carry pass: restores the `< 2^52` invariant for any input with limbs `< 2^63`.
const fn carry(mut l: [u64; 5]) -> [u64; 5] {
    // Move each limb's overflow (bits 51 and up) into the next limb. Sweeping upward once is
    // enough: after limb i is masked it is < 2^51, and the carry added to limb i+1 is < 2^12
    // (inputs are < 2^63), which cannot push a subsequent masked limb anywhere near 2^52.
    l[1] += l[0] >> 51;
    l[0] &= MASK_51;
    l[2] += l[1] >> 51;
    l[1] &= MASK_51;
    l[3] += l[2] >> 51;
    l[2] &= MASK_51;
    l[4] += l[3] >> 51;
    l[3] &= MASK_51;
    // The carry out of limb 4 has weight 2^255 = 19 (mod p), so it re-enters at limb 0
    // multiplied by 19. It is < 2^12, so limb 0 ends < 2^51 + 19*2^12 < 2^52: the invariant
    // holds with no second pass.
    l[0] += 19 * (l[4] >> 51);
    l[4] &= MASK_51;
    l
}

/// `a + b` for one lane.
fn add_lane(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    // Limb-wise sums of two < 2^52 values are < 2^53: no u64 overflow, and well within what
    // `carry` accepts.
    carry(core::array::from_fn(|i| a[i] + b[i]))
}

/// `16*p`, decomposed limb-wise. The decomposition telescopes:
///
/// ```text
/// 16*(2^51 - 19) + sum_{i=1..4} 16*(2^51 - 1)*2^(51*i) = 16*(2^255 - 19) = 16*p
/// ```
const BIAS_16P: [u64; 5] = [
    16 * ((1 << 51) - 19),
    16 * ((1 << 51) - 1),
    16 * ((1 << 51) - 1),
    16 * ((1 << 51) - 1),
    16 * ((1 << 51) - 1),
];

/// `-a` for one lane.
fn neg_lane(a: [u64; 5]) -> [u64; 5] {
    // -a = 16p - a (mod p). Computing against a multiple of p large enough that every limb of
    // the bias (~2^55) exceeds every possible input limb (< 2^52) makes each limb-wise
    // subtraction underflow-free; the result's limbs are < 2^55, within what `carry` accepts.
    carry(core::array::from_fn(|i| BIAS_16P[i] - a[i]))
}

/// `a * b` for one lane.
fn mul_lane(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    // Schoolbook product. With a = sum_i a_i*2^(51i) and b = sum_j b_j*2^(51j):
    //
    //   a*b = sum_k c_k * 2^(51k),  where  c_k = sum_{i+j=k} a_i*b_j,  k = 0..=8
    //
    // Each a_i*b_j < 2^104 and a column has at most 5 terms, so c_k < 2^107: comfortably
    // inside u128.
    let mut c = [0u128; 9];
    for (i, a) in a.into_iter().enumerate() {
        for (c, b) in c[i..].iter_mut().zip(b) {
            *c += u128::from(a) * u128::from(b);
        }
    }

    // Fold the high columns down: 2^255 = 19 (mod p) means 2^(51k) = 19 * 2^(51(k-5)) for
    // k >= 5. Afterwards c_k < 2^107 + 19*2^107 < 2^112.
    let (low, high) = c.split_at_mut(5);
    for (low, high) in low.iter_mut().zip(high) {
        *low += 19 * *high;
    }

    // The same carry sweep as `carry`, in u128 because the columns are wide.
    const MASK: u128 = MASK_51 as u128;
    c[1] += c[0] >> 51;
    c[0] &= MASK;
    c[2] += c[1] >> 51;
    c[1] &= MASK;
    c[3] += c[2] >> 51;
    c[2] &= MASK;
    c[4] += c[3] >> 51;
    c[3] &= MASK;
    // The overflow out of column 4 is < 2^(112-51) = 2^61, so its 19-fold into column 0 is
    // < 2^66 -- too big to leave in place, hence one extra carry step out of column 0. That
    // carry is < 2^15, so column 1 ends < 2^51 + 2^15 < 2^52 and everything else is masked:
    // the invariant holds.
    c[0] += 19 * (c[4] >> 51);
    c[4] &= MASK;
    c[1] += c[0] >> 51;
    c[0] &= MASK;

    core::array::from_fn(|i| c[i] as u64)
}

impl FBackend for Backend {
    fn add(self, a: FVec, b: FVec) -> FVec {
        map2(a, b, add_lane)
    }

    fn neg(self, a: FVec) -> FVec {
        map1(a, neg_lane)
    }

    fn mul(self, a: FVec, b: FVec) -> FVec {
        map2(a, b, mul_lane)
    }

    // `sub` and `square` use the trait defaults: `a + (-b)` and `a * a` are the obviously
    // correct choices for a reference backend, at the cost of a redundant carry pass (sub) and
    // a missed squaring shortcut (square).
}

impl GBackend for Backend {
    fn g_add(self, p: GVec, q: GVec) -> GVec {
        // Unified extended-coordinates addition (Hisil-Wong-Carter-Dawson, "Twisted Edwards
        // Curves Revisited", the "add-2008-hwcd-3" formula specialized to a = -1):
        //
        //   A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
        //   B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
        //   C = 2d * T1 * T2                 G = D + C        Z3 = F*G
        //   D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
        //
        // Completeness: up to the nonzero factor 2*Z1*Z2, F and G are the projective forms of
        // 1 -+ d*x1*x2*y1*y2, and |d*x1*x2*y1*y2| = 1 would force d to be a square mod p,
        // which it is not. So F, G != 0 for every pair of curve points and the formula needs
        // no special cases. The output invariant T3*Z3 = X3*Y3 holds identically:
        // (E*H)*(F*G) = (E*F)*(G*H).
        let a = self.mul(self.sub(p.y, p.x), self.sub(q.y, q.x));
        let b = self.mul(self.add(p.y, p.x), self.add(q.y, q.x));
        let c = self.mul(self.mul(p.t, q.t), EDWARDS_D2);
        let zz = self.mul(p.z, q.z);
        let d = self.add(zz, zz);
        let e = self.sub(b, a);
        let f = self.sub(d, c);
        let g = self.add(d, c);
        let h = self.add(b, a);
        GVec {
            x: self.mul(e, f),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(f, g),
        }
    }

    fn g_add_mixed(self, p: GVec, q: GAffineVec) -> GVec {
        // The same formula as `g_add`, exploiting Z2 = 1 (so T2 is exactly x2*y2) to save two
        // multiplications: D = 2*Z1 needs no product, and C = T1 * t2d is a single one because
        // the affine point's stored t2d = 2d*x2*y2 premultiplies the constant.
        let a = self.mul(self.sub(p.y, p.x), self.sub(q.y, q.x));
        let b = self.mul(self.add(p.y, p.x), self.add(q.y, q.x));
        let c = self.mul(p.t, q.t2d);
        let d = self.add(p.z, p.z);
        let e = self.sub(b, a);
        let f = self.sub(d, c);
        let g = self.add(d, c);
        let h = self.add(b, a);
        GVec {
            x: self.mul(e, f),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(f, g),
        }
    }

    // `g_double` uses the trait default: because `g_add` is complete, adding a point to itself
    // is already correct, and a dedicated doubling formula would only be a speedup.
}

impl super::Backend for Backend {}
