//! The AVX-512 backend: all eight lanes of an [`super::FVec`] limb row in one 512-bit register,
//! with field multiplication built on IFMA's 52-bit multiply-accumulates.

use super::{
    BIAS_16P as SUB_BIAS, F, FBackend, FVec, G, GAffine, LANES, MASK_51, WithBackend, msm,
};
use core::arch::x86_64::*;

/// One field element per lane, as five limb rows.
type Regs = [__m512i; 5];

/// One extended point per lane, as `[x, y, t, z]`.
type Point = [Regs; 4];

/// One affine point per lane, as `[x, y, t2d]`.
type Affine = [Regs; 3];

/// `2d` in every lane, for the `C = 2d*T1*T2` term of point addition.
const EDWARDS_D2: FVec = FVec::splat(F::EDWARDS_D2);

/// The AVX-512 backend token.
///
/// The private field ensures this can only be constructed after checking the required CPU
/// features with [`available`].
#[derive(Clone, Copy)]
pub(super) struct Backend(());

/// Feature set this backend requires: AVX-512F for the 512-bit integer add/shift/mask operations,
/// and AVX-512 IFMA for the 52x52-bit multiply-accumulates.
fn available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
}

/// Loads 5 rows of 8 packed `u64` limbs into zmm registers.
#[inline]
#[target_feature(enable = "avx512f")]
fn load(limbs: &[[u64; LANES]; 5]) -> [__m512i; 5] {
    // SAFETY: each row is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
    // `loadu` places no alignment requirement on the source.
    unsafe { core::array::from_fn(|i| _mm512_loadu_si512(limbs[i].as_ptr().cast())) }
}

/// Stores 5 zmm registers into 5 rows of 8 packed `u64` limbs.
#[inline]
#[target_feature(enable = "avx512f")]
fn store(regs: [__m512i; 5]) -> [[u64; LANES]; 5] {
    let mut limbs = [[0u64; LANES]; 5];
    for (row, reg) in limbs.iter_mut().zip(regs) {
        // SAFETY: `row` is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
        // `storeu` places no alignment requirement on the destination.
        unsafe { _mm512_storeu_si512(row.as_mut_ptr().cast(), reg) };
    }
    limbs
}

/// `19*z` via `(z << 4) + (z << 1) + z`.
///
/// # Correctness
///
/// `z` must be less than `2^59` per lane so `19*z` fits in `u64`.
///
/// The explicit instruction sequence prevents LLVM from recognizing a packed `u64` multiplication
/// and expanding it into two packed 32-bit multiplications, two shifts, and an addition. These
/// four AVX-512F instructions preserve the shift-and-add calculation directly.
#[inline]
#[target_feature(enable = "avx512f")]
fn mul19(z: __m512i) -> __m512i {
    let result;

    // Typed scratch outputs: discarded `_` operands are printed as general-purpose registers
    // when AVX-512VL is enabled for the whole build, which the assembler rejects.
    let _times16: __m512i;
    let _doubled: __m512i;

    // SAFETY: AVX-512F is enabled. The instructions only read their register input, write
    // their register outputs, preserve flags, and stay within the documented limb bound.
    unsafe {
        core::arch::asm!(
            "vpsllq {times16}, {z}, 4",
            "vpsllq {doubled}, {z}, 1",
            "vpaddq {doubled}, {doubled}, {times16}",
            "vpaddq {result}, {doubled}, {z}",
            z = in(zmm_reg) z,
            times16 = out(zmm_reg) _times16,
            doubled = out(zmm_reg) _doubled,
            result = lateout(zmm_reg) result,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    result
}

/// Reduces each radix-`2^51` lane with one parallel carry pass.
///
/// All five carry-outs are computed from the original limbs at once, then added to the adjacent
/// masked limbs, with limb 4's carry folded onto limb 0 via `2^255 = 19`.
///
/// # Correctness
///
/// Inputs must have limbs below `2^63`. Outputs then have limbs below `2^52`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn reduce_regs(l: [__m512i; 5]) -> [__m512i; 5] {
    let mask = _mm512_set1_epi64(MASK_51 as i64);
    let c: [__m512i; 5] = core::array::from_fn(|i| _mm512_srli_epi64(l[i], 51));

    // Each carry is below 2^12, so IFMA computes the folded carry exactly.
    [
        _mm512_madd52lo_epu64(_mm512_and_si512(l[0], mask), c[4], _mm512_set1_epi64(19)),
        _mm512_add_epi64(_mm512_and_si512(l[1], mask), c[0]),
        _mm512_add_epi64(_mm512_and_si512(l[2], mask), c[1]),
        _mm512_add_epi64(_mm512_and_si512(l[3], mask), c[2]),
        _mm512_add_epi64(_mm512_and_si512(l[4], mask), c[3]),
    ]
}

/// Register-level schoolbook multiply, folded onto five radix-`2^51` limbs but left unreduced.
///
/// `vpmadd52luq` and `vpmadd52huq` split each product at bit 52. Since the field radix is 51,
/// high halves land on the next column with coefficient 2. Columns 5 through 9 fold back via
/// `2^255 = 19`.
///
/// At the adversarial input bound (`2^52 - 1`), each accumulator contains at most five 52-bit
/// halves, so both `lo[k]` and `hi[k]` are below `5 * 2^52`. Thus `z[k] = lo[k] + 2*hi[k]` is
/// below `15 * 2^52 < 2^56`, and the folded output is below `20 * 2^56 < 2^61`. This is within
/// `reduce_regs`'s input bound, and each `mul19` input is below `2^56`.
///
/// # Correctness
///
/// Every input limb must be less than `2^52` so IFMA does not discard significant bits and the
/// accumulator bounds above hold.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_regs_loose(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    let mut lo = [_mm512_setzero_si512(); 10];
    let mut hi = [_mm512_setzero_si512(); 10];
    for i in 0..5 {
        for j in 0..5 {
            lo[i + j] = _mm512_madd52lo_epu64(lo[i + j], a[i], b[j]);
            hi[i + j + 1] = _mm512_madd52hi_epu64(hi[i + j + 1], a[i], b[j]);
        }
    }

    let z: [__m512i; 10] =
        core::array::from_fn(|k| _mm512_add_epi64(lo[k], _mm512_add_epi64(hi[k], hi[k])));
    core::array::from_fn(|k| _mm512_add_epi64(z[k], mul19(z[k + 5])))
}

/// Register-level multiply followed by a carry pass.
///
/// # Correctness
///
/// Every input limb must be less than `2^52`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_regs(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    reduce_regs(mul_regs_loose(a, b))
}

/// Register-level squaring, folded onto five radix-`2^51` limbs but left unreduced.
///
/// Each cross product is computed once and doubled, reducing the operation from 50 to 30
/// multiply-accumulates.
///
/// # Correctness
///
/// Every input limb must be less than `2^52` so IFMA does not discard significant bits. The
/// resulting accumulator bounds are no larger than in [`mul_regs_loose`].
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn square_regs_loose(a: [__m512i; 5]) -> [__m512i; 5] {
    let mut c1 = [_mm512_setzero_si512(); 10];
    let mut c2 = [_mm512_setzero_si512(); 10];
    let mut c4 = [_mm512_setzero_si512(); 10];
    for i in 0..5 {
        c1[2 * i] = _mm512_madd52lo_epu64(c1[2 * i], a[i], a[i]);
        c2[2 * i + 1] = _mm512_madd52hi_epu64(c2[2 * i + 1], a[i], a[i]);
        for j in (i + 1)..5 {
            c2[i + j] = _mm512_madd52lo_epu64(c2[i + j], a[i], a[j]);
            c4[i + j + 1] = _mm512_madd52hi_epu64(c4[i + j + 1], a[i], a[j]);
        }
    }

    let z: [__m512i; 10] = core::array::from_fn(|k| {
        _mm512_add_epi64(
            c1[k],
            _mm512_add_epi64(_mm512_add_epi64(c2[k], c2[k]), _mm512_slli_epi64(c4[k], 2)),
        )
    });
    core::array::from_fn(|k| _mm512_add_epi64(z[k], mul19(z[k + 5])))
}

/// Register-level square followed by a carry pass.
///
/// # Correctness
///
/// Every input limb must be less than `2^52`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn square_regs(a: [__m512i; 5]) -> [__m512i; 5] {
    reduce_regs(square_regs_loose(a))
}

/// Elementwise addition without a carry pass.
///
/// # Correctness
///
/// The sum must not wrap around `u64` if it is to represent integer addition.
#[inline]
#[target_feature(enable = "avx512f")]
fn add_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| _mm512_add_epi64(a[i], b[i]))
}

/// Elementwise subtraction as `a + 16p - b`, without a carry pass.
///
/// # Correctness
///
/// Every limb of `b` must be less than `2^52`, and the biased sum must not wrap around `u64`.
#[inline]
#[target_feature(enable = "avx512f")]
fn sub_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| {
        let biased = _mm512_add_epi64(a[i], _mm512_set1_epi64(SUB_BIAS[i] as i64));
        _mm512_sub_epi64(biased, b[i])
    })
}

/// Negates the lanes selected by `mask` with reduced output, preserving every unselected lane.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn neg_lanes(value: Regs, mask: __mmask8) -> Regs {
    let zero = [_mm512_setzero_si512(); 5];
    let negated = reduce_regs(sub_raw(zero, value));
    let mut result = value;
    for limb in 0..5 {
        result[limb] = _mm512_mask_blend_epi64(mask, value[limb], negated[limb]);
    }
    result
}

/// The identity point in every lane.
#[inline]
#[target_feature(enable = "avx512f")]
fn identity() -> Point {
    let zero = [_mm512_setzero_si512(); 5];
    let mut one = zero;
    one[0] = _mm512_set1_epi64(1);
    [zero, one, zero, one]
}

/// Mixed addition of an affine point using its precomputed `2d*x*y` coordinate.
///
/// # Correctness
///
/// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below `reduce_regs`'s
/// `2^63` bound, and every right operand of `sub_raw` is reduced below `2^52`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn add_mixed_regs([x1, y1, t1, z1]: Point, [x2, y2, t2d]: Affine) -> Point {
    // The steps of `add_lanes` with `Z2 = 1`: the affine operand supplies `2d*T2`, so `C`
    // takes one multiplication and `D = 2*Z1` takes none.
    //
    // `B` and `D` are left unreduced: they appear only in sums and as the minuend of
    // `sub_raw`, whose results are reduced before multiplying.
    let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
    let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
    let c = mul_regs(t1, t2d);
    let d = add_raw(z1, z1);
    let e = reduce_regs(sub_raw(b, a));
    let f = reduce_regs(sub_raw(d, c));
    let g = reduce_regs(add_raw(d, c));
    let h = reduce_regs(add_raw(b, a));
    [
        mul_regs(e, f),
        mul_regs(g, h),
        mul_regs(e, h),
        mul_regs(f, g),
    ]
}

/// Transposes eight rows of eight `u64`s: lane `j` of output row `i` is lane `i` of input row `j`.
#[target_feature(enable = "avx512f")]
fn transpose(r: [__m512i; 8]) -> [__m512i; 8] {
    // Interleave row pairs within each 128-bit block, then regroup 128-bit blocks twice.
    //
    // Block `b` of `t[2m]` holds column `2b` of rows `2m` and `2m + 1`, and block `b` of
    // `t[2m + 1]` holds column `2b + 1` of the same rows.
    let t = [
        _mm512_unpacklo_epi64(r[0], r[1]),
        _mm512_unpackhi_epi64(r[0], r[1]),
        _mm512_unpacklo_epi64(r[2], r[3]),
        _mm512_unpackhi_epi64(r[2], r[3]),
        _mm512_unpacklo_epi64(r[4], r[5]),
        _mm512_unpackhi_epi64(r[4], r[5]),
        _mm512_unpacklo_epi64(r[6], r[7]),
        _mm512_unpackhi_epi64(r[6], r[7]),
    ];

    // Selector `0x88` takes blocks 0 and 2 of each source and `0xdd` takes blocks 1 and 3. For
    // `k < 4`, `u[k]` holds column `k` in its even blocks and column `k + 4` in its odd blocks,
    // from rows 0..4; `u[k + 4]` holds the same columns from rows 4..8.
    let u = [
        _mm512_shuffle_i64x2::<0x88>(t[0], t[2]),
        _mm512_shuffle_i64x2::<0x88>(t[1], t[3]),
        _mm512_shuffle_i64x2::<0xdd>(t[0], t[2]),
        _mm512_shuffle_i64x2::<0xdd>(t[1], t[3]),
        _mm512_shuffle_i64x2::<0x88>(t[4], t[6]),
        _mm512_shuffle_i64x2::<0x88>(t[5], t[7]),
        _mm512_shuffle_i64x2::<0xdd>(t[4], t[6]),
        _mm512_shuffle_i64x2::<0xdd>(t[5], t[7]),
    ];

    // Joining the even blocks of `u[k]` and `u[k + 4]` completes column `k` in row order, and
    // joining their odd blocks completes column `k + 4`.
    [
        _mm512_shuffle_i64x2::<0x88>(u[0], u[4]),
        _mm512_shuffle_i64x2::<0x88>(u[1], u[5]),
        _mm512_shuffle_i64x2::<0x88>(u[2], u[6]),
        _mm512_shuffle_i64x2::<0x88>(u[3], u[7]),
        _mm512_shuffle_i64x2::<0xdd>(u[0], u[4]),
        _mm512_shuffle_i64x2::<0xdd>(u[1], u[5]),
        _mm512_shuffle_i64x2::<0xdd>(u[2], u[6]),
        _mm512_shuffle_i64x2::<0xdd>(u[3], u[7]),
    ]
}

// The point loaders below read `G` as 20 consecutive limbs and `GAffine` as 15.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<G>() == 20 * 8 && size_of::<GAffine>() == 15 * 8);
    assert!(offset_of!(G, y) == 40 && offset_of!(G, t) == 80 && offset_of!(G, z) == 120);
    assert!(offset_of!(GAffine, y) == 40 && offset_of!(GAffine, t2d) == 80);
};

/// Loads the point behind each lane's pointer into that lane.
///
/// # Safety
///
/// Every pointer must be valid for reads of a [`G`].
#[target_feature(enable = "avx512f")]
unsafe fn load_points(points: [*const G; LANES]) -> Point {
    let limbs = points.map(|point| point.cast::<u64>());
    let mut a = [_mm512_setzero_si512(); LANES];
    let mut b = a;
    let mut c = a;

    // Lane `l`'s point fills row `l` of three 8x8 limb blocks: limbs 0..8 in `a`, 8..16 in `b`,
    // and 16..20 in `c`.
    // SAFETY: `G` is 20 consecutive limbs (`x`, `y`, `t`, and `z`, five each), so each pointer is
    // valid for limbs 0..20. The final load masks off limbs 20..24.
    unsafe {
        for lane in 0..LANES {
            let p = limbs[lane];
            a[lane] = _mm512_loadu_si512(p.cast());
            b[lane] = _mm512_loadu_si512(p.add(8).cast());
            c[lane] = _mm512_maskz_loadu_epi64(0x0f, p.add(16).cast());
        }
    }

    // After transposing, row `i` of `a`, `b`, and `c` holds limb `i`, `8 + i`, and `16 + i` of
    // every lane's point, so the 20 limb rows split into `x`, `y`, `t`, and `z` five at a time.
    let (a, b, c) = (transpose(a), transpose(b), transpose(c));
    [
        [a[0], a[1], a[2], a[3], a[4]],
        [a[5], a[6], a[7], b[0], b[1]],
        [b[2], b[3], b[4], b[5], b[6]],
        [b[7], c[0], c[1], c[2], c[3]],
    ]
}

/// Stores each lane selected by `mask` through that lane's pointer.
///
/// # Safety
///
/// Every pointer whose lane `mask` selects must be valid for writes of a [`G`].
#[target_feature(enable = "avx512f")]
unsafe fn store_points([x, y, t, z]: Point, points: [*mut G; LANES], mask: __mmask8) {
    // Transpose the 20 limb rows back into three 8x8 blocks whose row `l` holds limbs 0..8,
    // 8..16, and 16..20 of lane `l`'s point. The zero padding in `c` lands on limbs 20..24,
    // which the masked store skips.
    let zero = _mm512_setzero_si512();
    let a = transpose([x[0], x[1], x[2], x[3], x[4], y[0], y[1], y[2]]);
    let b = transpose([y[3], y[4], t[0], t[1], t[2], t[3], t[4], z[0]]);
    let c = transpose([z[1], z[2], z[3], z[4], zero, zero, zero, zero]);

    // Pointers of unselected lanes need not be valid, so only the lanes in `mask` are written.
    for lane in 0..LANES {
        if mask & (1 << lane) != 0 {
            let p = points[lane].cast::<u64>();
            // SAFETY: the caller guarantees `p` is valid for writes of the 20 limbs of a `G`. The
            // final store masks off limbs 20..24.
            unsafe {
                _mm512_storeu_si512(p.cast(), a[lane]);
                _mm512_storeu_si512(p.add(8).cast(), b[lane]);
                _mm512_mask_storeu_epi64(p.add(16).cast(), 0x0f, c[lane]);
            }
        }
    }
}

/// Loads the affine point behind each lane's pointer into that lane.
///
/// # Safety
///
/// Every pointer must be valid for reads of a [`GAffine`].
#[target_feature(enable = "avx512f")]
unsafe fn load_affines(points: [*const GAffine; LANES]) -> Affine {
    let limbs = points.map(|point| point.cast::<u64>());
    let mut a = [_mm512_setzero_si512(); LANES];
    let mut b = a;

    // Lane `l`'s point fills row `l` of two 8x8 limb blocks: limbs 0..8 in `a` and 8..15 in `b`.
    // SAFETY: `GAffine` is 15 consecutive limbs (`x`, `y`, and `t2d`, five each), so each pointer
    // is valid for limbs 0..15. The second load masks off limb 15.
    unsafe {
        for lane in 0..LANES {
            let p = limbs[lane];
            a[lane] = _mm512_loadu_si512(p.cast());
            b[lane] = _mm512_maskz_loadu_epi64(0x7f, p.add(8).cast());
        }
    }

    // After transposing, row `i` of `a` and `b` holds limb `i` and `8 + i` of every lane's
    // point, so the 15 limb rows split into `x`, `y`, and `t2d` five at a time.
    let (a, b) = (transpose(a), transpose(b));
    [
        [a[0], a[1], a[2], a[3], a[4]],
        [a[5], a[6], a[7], b[0], b[1]],
        [b[2], b[3], b[4], b[5], b[6]],
    ]
}

impl FBackend for Backend {
    #[inline(always)]
    fn add(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.add_field(a, b) }
    }

    #[inline(always)]
    fn neg(self, a: FVec) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.neg_field(a) }
    }

    #[inline(always)]
    fn sub(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.sub_field(a, b) }
    }

    #[inline(always)]
    fn mul(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.mul_field(a, b) }
    }

    #[inline(always)]
    fn pow2k(self, a: FVec, k: u32) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.pow2k_field(a, k) }
    }

    #[inline(always)]
    fn square(self, a: FVec) -> FVec {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.square_field(a) }
    }
}

impl Backend {
    /// Constructs the backend if the required CPU features are available.
    pub(super) fn new() -> Option<Self> {
        available().then_some(Self(()))
    }

    /// Runs an entire computation with AVX-512F and AVX-512 IFMA enabled.
    ///
    /// Enabling the target features around the whole computation lets backend operations inline
    /// without crossing a target-feature boundary for every operation.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) fn call<F: WithBackend>(self, f: F) -> F::Output {
        f.call(self)
    }

    /// Unified extended-coordinates addition (Hisil-Wong-Carter-Dawson):
    ///
    /// ```text
    /// A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
    /// B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
    /// C = 2d * T1 * T2                 G = D + C        Z3 = F*G
    /// D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
    /// ```
    ///
    /// # Correctness
    ///
    /// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below `reduce_regs`'s
    /// `2^63` bound, and every right operand of `sub_raw` is reduced below `2^52`.
    #[inline(always)]
    fn add_lanes(self, [x1, y1, t1, z1]: Point, [x2, y2, t2, z2]: Point) -> Point {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe {
            // Every lane adds its own pair of points. `B` and `D` are left unreduced: they
            // appear only in sums and as the minuend of `sub_raw`, whose results are reduced
            // before multiplying.
            let two_d = load(&EDWARDS_D2.limbs);
            let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
            let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
            let c = mul_regs(mul_regs(t1, t2), two_d);
            let zz = mul_regs_loose(z1, z2);
            let d = add_raw(zz, zz);
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));
            [
                mul_regs(e, f),
                mul_regs(g, h),
                mul_regs(e, h),
                mul_regs(f, g),
            ]
        }
    }

    /// Adds each term's signed affine point to the bucket its digit selects, one wave of
    /// [`LANES`] terms at a time.
    ///
    /// Lane `l` owns stripe `l`, so a wave's buckets are distinct. They are transposed into
    /// lanes, updated with one mixed addition, and transposed back.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn fill<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (&GAffine, i16),
    ) {
        // The slot arithmetic below relies on one stripe of `nb` buckets per lane.
        assert_eq!(Some(buckets.len()), LANES.checked_mul(nb));
        let base = buckets.as_mut_ptr();

        // Lanes without a nonzero digit load these identities, and their sums are never stored.
        let identity = G::IDENTITY;
        let affine_identity = GAffine::IDENTITY;
        for wave in terms.chunks(LANES) {
            // Point each lane with a nonzero digit at its term's point and at the bucket the
            // digit's magnitude selects in the lane's own stripe. The masks record which lanes
            // are active and which subtract their point.
            let mut incoming = [&raw const affine_identity; LANES];
            let mut current = [&raw const identity; LANES];
            let mut slots = [core::ptr::null_mut(); LANES];
            let mut active = 0;
            let mut negative = 0;
            for (lane, item) in wave.iter().enumerate() {
                let (point, digit) = term(item);
                if digit == 0 {
                    continue;
                }
                let magnitude = usize::from(digit.unsigned_abs());
                assert!(magnitude <= nb);
                // SAFETY: `lane < LANES` and `1 <= magnitude <= nb` keep the slot in `buckets`.
                let slot = unsafe { base.add(lane * nb + magnitude - 1) };
                incoming[lane] = core::ptr::from_ref(point);
                current[lane] = slot.cast_const();
                slots[lane] = slot;
                active |= 1 << lane;
                negative |= u8::from(digit < 0) << lane;
            }

            // A wave whose digits are all zero changes no bucket.
            if active == 0 {
                continue;
            }

            // Load each lane's bucket and point, negate the subtracted points (negating `x`
            // also negates `2d*x*y`), add, and store only the active lanes back.
            // SAFETY: every pointer is a bucket in `buckets`, a term's point, or a live local
            // point.
            let (p, [x, y, t2d]) = unsafe { (load_points(current), load_affines(incoming)) };
            let sum = add_mixed_regs(p, [neg_lanes(x, negative), y, neg_lanes(t2d, negative)]);
            // SAFETY: the selected lanes hold distinct buckets in `buckets`.
            unsafe { store_points(sum, slots, active) };
        }
    }

    /// Runs a native-lane computation with AVX-512 enabled for the entire entry point.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn call_lanes<C: msm::WithLanes>(self, computation: C) -> C::Output {
        computation.call::<Self, LANES>(self)
    }

    /// Returns the sum of every lane of `point`.
    #[inline(never)]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn sum_lanes(self, mut point: Point) -> G {
        // Each round moves lanes `half..2 * half` onto lanes `0..half` and adds them in, so lane 0
        // ends with the sum of every lane.
        let mut half = LANES / 2;
        while half > 0 {
            let lanes = <Self as msm::Lanes<LANES>>::store(self, point);
            let upper = <Self as msm::Lanes<LANES>>::load_extended(
                self,
                core::array::from_fn(|lane| {
                    if lane < half {
                        &lanes[lane + half]
                    } else {
                        &G::IDENTITY
                    }
                }),
            );
            point = self.add_lanes(point, upper);
            half /= 2;
        }
        <Self as msm::Lanes<LANES>>::store(self, point)[0]
    }

    /// Runs the window recombination chain in lane 0 with AVX-512 enabled for the whole chain.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn combine_lanes(
        self,
        partials: impl IntoIterator<Item = (usize, G)>,
        windows: usize,
        width: u32,
    ) -> G {
        // Each partial enters lane 0, and the other lanes hold the identity.
        let in_lane_zero = |point: &G| {
            <Self as msm::Lanes<LANES>>::load_extended(
                self,
                core::array::from_fn(|lane| if lane == 0 { point } else { &G::IDENTITY }),
            )
        };
        let chain = msm::combine_windows(
            identity(),
            |a, b| self.add_lanes(a, b),
            |point| <Self as msm::Lanes<LANES>>::double(self, point),
            partials
                .into_iter()
                .map(|(window, partial)| (window, in_lane_zero(&partial))),
            windows,
            width,
        );
        <Self as msm::Lanes<LANES>>::store(self, chain)[0]
    }

    // Field operations require inputs within FVec's limb bound. This keeps raw field
    // arithmetic within its documented ranges and every IFMA operand below its 2^52 ceiling.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_field(self, a: FVec, b: FVec) -> FVec {
        FVec {
            limbs: store(reduce_regs(add_raw(load(&a.limbs), load(&b.limbs)))),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn neg_field(self, a: FVec) -> FVec {
        let zero = [_mm512_setzero_si512(); 5];
        FVec {
            limbs: store(reduce_regs(sub_raw(zero, load(&a.limbs)))),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn sub_field(self, a: FVec, b: FVec) -> FVec {
        FVec {
            limbs: store(reduce_regs(sub_raw(load(&a.limbs), load(&b.limbs)))),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mul_field(self, a: FVec, b: FVec) -> FVec {
        FVec {
            limbs: store(mul_regs(load(&a.limbs), load(&b.limbs))),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn pow2k_field(self, a: FVec, k: u32) -> FVec {
        let mut value = load(&a.limbs);
        for _ in 0..k {
            value = square_regs(value);
        }
        FVec {
            limbs: store(value),
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn square_field(self, a: FVec) -> FVec {
        FVec {
            limbs: store(square_regs(load(&a.limbs))),
        }
    }
}

impl super::Backend for Backend {
    /// One lane-wise square-root chain covers both encodings, costing less than two scalar
    /// chains.
    fn decompress_pair(self, encodings: [&[u8; 32]; 2]) -> Option<[GAffine; 2]> {
        let points = GAffine::decompress_batch(self, &core::array::from_fn(|i| *encodings[i % 2]));
        Some([points[0]?, points[1]?])
    }
}

impl super::msm::Backend for Backend {
    const STRIPES: usize = LANES;
    const STRAUS_TERM_CUTOFF: usize = 384;
    const PARALLEL_STRAUS_TERM_CUTOFF: usize = 1024;

    #[inline(always)]
    fn fill_buckets<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (&GAffine, i16),
    ) {
        // SAFETY: `Backend` construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.fill(buckets, nb, terms, term) }
    }

    /// Runs the chain in lane 0 of the native lanes. One eight-lane IFMA operation is cheaper
    /// than the scalar formula, so the idle lanes cost nothing.
    #[inline(always)]
    fn combine_windows(
        self,
        partials: impl IntoIterator<Item = (usize, G)>,
        windows: usize,
        width: u32,
    ) -> G {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.combine_lanes(partials, windows, width) }
    }

    #[inline(always)]
    fn with_lanes<C: msm::WithLanes>(self, computation: C) -> C::Output {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.call_lanes(computation) }
    }
}

impl msm::Lanes<LANES> for Backend {
    type Point = Point;
    type Affine = Affine;

    // An eight-term group almost never has only zero digits, so the scan would not pay.
    const SKIP_ZERO_GROUPS: bool = false;

    #[inline(always)]
    fn identity(self) -> Point {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { identity() }
    }

    #[inline(always)]
    fn load(self, points: [&GAffine; LANES]) -> Affine {
        let mut rows = [core::ptr::null(); LANES];
        for (row, point) in rows.iter_mut().zip(points) {
            *row = core::ptr::from_ref(point);
        }

        // SAFETY: Backend construction checks the CPU features, and every pointer is a live
        // affine point supplied by the caller.
        unsafe { load_affines(rows) }
    }

    #[inline(always)]
    fn load_extended(self, points: [&G; LANES]) -> Point {
        // SAFETY: Backend construction checks the CPU features, and every pointer is a live point
        // supplied by the caller.
        unsafe { load_points(points.map(core::ptr::from_ref)) }
    }

    #[inline(always)]
    fn store(self, point: Point) -> [G; LANES] {
        let mut points = [G::IDENTITY; LANES];
        // SAFETY: Backend construction checks AVX-512F support, and every pointer is an element of
        // `points`, valid for writes.
        unsafe { store_points(point, points.each_mut().map(core::ptr::from_mut), 0xff) };
        points
    }

    #[inline(always)]
    fn add_mixed(self, point: Point, affine: Affine) -> Point {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { add_mixed_regs(point, affine) }
    }

    #[inline(always)]
    fn add(self, a: Point, b: Point) -> Point {
        self.add_lanes(a, b)
    }

    /// Point doubling using the dedicated `dbl-2008-hwcd` formula.
    ///
    /// # Correctness
    ///
    /// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below `reduce_regs`'s
    /// `2^63` bound, and every right operand of `sub_raw` is reduced below `2^52`.
    #[inline(always)]
    fn double(self, [x, y, _, z]: Point) -> Point {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe {
            // `dbl-2008-hwcd` for curve parameter `a = -1`, which folds
            // `D = a*A` into `G` and `H`:
            //
            //   A = X1^2        E = (X1 + Y1)^2 - A - B        X3 = E*F
            //   B = Y1^2        G = B - A                      Y3 = G*H
            //   C = 2*Z1^2      F = G - C                      T3 = E*H
            //                   H = -A - B                     Z3 = F*G
            //
            // `Z1^2` and `(X1 + Y1)^2` skip the carry pass because each is reduced right after
            // its addition or subtraction.
            let a = square_regs(x);
            let b = square_regs(y);
            let c0 = square_regs_loose(z);
            let c = reduce_regs(add_raw(c0, c0));
            let xy2 = square_regs_loose(reduce_regs(add_raw(x, y)));
            let e = reduce_regs(sub_raw(sub_raw(xy2, a), b));
            let g = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(g, c));
            let zero = [_mm512_setzero_si512(); 5];
            let h = reduce_regs(sub_raw(sub_raw(zero, a), b));
            [
                mul_regs(e, f),
                mul_regs(g, h),
                mul_regs(e, h),
                mul_regs(f, g),
            ]
        }
    }

    #[inline(always)]
    fn add_signed(self, point: Point, table: &[Point], digits: [i16; LANES]) -> Point {
        // A Point has 20 rows of LANES limbs. Entry e's limb in row r and lane l is at
        // (e * 20 + r) * LANES + l. The gather base supplies r; each offset supplies e and l.
        const ENTRY_LIMBS: usize = 20 * LANES;
        let mut offsets = [0i64; LANES];
        let mut negative = 0;
        for (lane, (offset, digit)) in offsets.iter_mut().zip(digits).enumerate() {
            let entry = usize::from(digit.unsigned_abs());
            assert!(entry < table.len());
            *offset = (entry * ENTRY_LIMBS + lane) as i64;
            negative |= u8::from(digit < 0) << lane;
        }

        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        // offsets has eight i64s, and every entry is below table.len(), so each lane's
        // offset plus the row stays inside table.
        unsafe {
            // Gather one limb row at a time. Lane `l` reads lane `l` of that row in entry
            // `|digits[l]|`, so `selected` holds each lane's own table entry.
            let offsets = _mm512_loadu_si512(offsets.as_ptr().cast());
            let base = table.as_ptr().cast::<i64>();
            let mut selected: Point = [[_mm512_setzero_si512(); 5]; 4];
            for (coordinate, row) in selected.iter_mut().enumerate() {
                for (limb, value) in row.iter_mut().enumerate() {
                    *value = _mm512_i64gather_epi64::<8>(
                        offsets,
                        base.add((coordinate * 5 + limb) * LANES),
                    );
                }
            }

            // Lanes with negative digits subtract their entry by negating its `X` and `T`.
            let [x, y, t, z] = selected;
            self.add_lanes(
                point,
                [neg_lanes(x, negative), y, neg_lanes(t, negative), z],
            )
        }
    }

    #[inline(always)]
    fn select(self, point: Point, keep: [bool; LANES]) -> Point {
        // Bit `l` of the mask is set when lane `l` is kept. The blend takes `point`'s limbs for
        // set bits and the identity's limbs for clear bits.
        let mask = keep
            .iter()
            .enumerate()
            .fold(0, |mask, (lane, &keep)| mask | (u8::from(keep) << lane));
        // SAFETY: Backend construction checks AVX-512F support.
        unsafe {
            let identity = identity();
            core::array::from_fn(|coordinate| {
                core::array::from_fn(|limb| {
                    _mm512_mask_blend_epi64(
                        mask,
                        identity[coordinate][limb],
                        point[coordinate][limb],
                    )
                })
            })
        }
    }

    #[inline(always)]
    fn sum(self, point: Point) -> G {
        // SAFETY: Backend construction checks AVX-512F and AVX-512 IFMA support.
        unsafe { self.sum_lanes(point) }
    }
}
