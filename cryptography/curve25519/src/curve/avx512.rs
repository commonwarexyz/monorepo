//! The AVX-512 backend: all eight lanes of an [`super::FVec`] limb row in one 512-bit register,
//! with field multiplication built on IFMA's 52-bit multiply-accumulates.

use super::{
    BIAS_16P as SUB_BIAS, F, FBackend, FVec, GAffineVec, GBackend, GVec, LANES, MASK_51,
    WithBackend,
};
use core::arch::x86_64::*;

/// `2d` in every lane, for the `C = 2d*T1*T2` term of point addition.
const EDWARDS_D2: FVec = FVec::splat(F::EDWARDS_D2);

/// The AVX-512 backend token.
///
/// The private field ensures this can only be constructed after checking the required CPU
/// features with [`available`].
#[derive(Clone, Copy)]
pub(super) struct Backend(());

impl Backend {
    /// Constructs the backend if the required CPU features are available.
    pub(super) fn new() -> Option<Self> {
        available().then_some(Self(()))
    }

    /// Runs an entire computation with AVX-512F and AVX-512 IFMA enabled.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) fn call<F: WithBackend>(self, f: F) -> F::Output {
        f.call(self)
    }
}

/// Feature set this backend requires: AVX-512F for the 512-bit integer add/shift/mask operations,
/// and AVX-512 IFMA for the 52x52-bit multiply-accumulates.
fn available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
}

/// Loads 5 rows of 8 packed `u64` limbs into zmm registers.
#[target_feature(enable = "avx512f")]
fn load(limbs: &[[u64; LANES]; 5]) -> [__m512i; 5] {
    // SAFETY: each row is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
    // `loadu` places no alignment requirement on the source.
    unsafe { core::array::from_fn(|i| _mm512_loadu_si512(limbs[i].as_ptr().cast())) }
}

/// Stores 5 zmm registers into 5 rows of 8 packed `u64` limbs.
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
/// `z` must be less than `2^60` per lane so the shifts do not discard significant bits.
#[target_feature(enable = "avx512f")]
fn mul19(z: __m512i) -> __m512i {
    _mm512_add_epi64(
        _mm512_add_epi64(_mm512_slli_epi64(z, 4), _mm512_slli_epi64(z, 1)),
        z,
    )
}

/// Reduces each radix-`2^51` lane with one parallel carry pass.
///
/// All five carry-outs are computed from the original limbs at once, then added to the adjacent
/// masked limbs, with limb 4's carry folded onto limb 0 via `2^255 = 19`.
///
/// # Correctness
///
/// Inputs must have limbs below `2^63`. Outputs then have limbs below `2^52`.
#[target_feature(enable = "avx512f")]
fn reduce_regs(l: [__m512i; 5]) -> [__m512i; 5] {
    let mask = _mm512_set1_epi64(MASK_51 as i64);
    let c: [__m512i; 5] = core::array::from_fn(|i| _mm512_srli_epi64(l[i], 51));
    [
        _mm512_add_epi64(_mm512_and_si512(l[0], mask), mul19(c[4])),
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
#[target_feature(enable = "avx512f,avx512ifma")]
fn square_regs(a: [__m512i; 5]) -> [__m512i; 5] {
    reduce_regs(square_regs_loose(a))
}

/// Elementwise addition without a carry pass.
///
/// # Correctness
///
/// The sum must not wrap around `u64` if it is to represent integer addition.
#[target_feature(enable = "avx512f")]
fn add_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| _mm512_add_epi64(a[i], b[i]))
}

/// Elementwise subtraction as `a + 16p - b`, without a carry pass.
///
/// # Correctness
///
/// Every limb of `b` must be less than `2^52`, and the biased sum must not wrap around `u64`.
#[target_feature(enable = "avx512f")]
fn sub_raw(a: [__m512i; 5], b: [__m512i; 5]) -> [__m512i; 5] {
    core::array::from_fn(|i| {
        let biased = _mm512_add_epi64(a[i], _mm512_set1_epi64(SUB_BIAS[i] as i64));
        _mm512_sub_epi64(biased, b[i])
    })
}

/// # Correctness
///
/// Every input must satisfy [`FVec`]'s limb bound. That bound keeps raw field arithmetic within
/// its documented ranges and keeps every IFMA operand below its `2^52` ceiling.
impl FBackend for Backend {
    fn add(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            FVec {
                limbs: store(reduce_regs(add_raw(load(&a.limbs), load(&b.limbs)))),
            }
        }
    }

    fn neg(self, a: FVec) -> FVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            let zero = [_mm512_setzero_si512(); 5];
            FVec {
                limbs: store(reduce_regs(sub_raw(zero, load(&a.limbs)))),
            }
        }
    }

    fn sub(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            FVec {
                limbs: store(reduce_regs(sub_raw(load(&a.limbs), load(&b.limbs)))),
            }
        }
    }

    fn mul(self, a: FVec, b: FVec) -> FVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            FVec {
                limbs: store(mul_regs(load(&a.limbs), load(&b.limbs))),
            }
        }
    }

    fn square(self, a: FVec) -> FVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            FVec {
                limbs: store(square_regs(load(&a.limbs))),
            }
        }
    }
}

// These methods need forced inlining: without it, optimized `WithBackend` computations retain a
// call to each group operation across the target-feature boundary.
impl GBackend for Backend {
    /// Fused point addition with every intermediate held in registers.
    ///
    /// # Correctness
    ///
    /// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below
    /// `reduce_regs`'s `2^63` bound, and every right operand of `sub_raw` is reduced below
    /// `2^52`.
    #[inline(always)]
    fn g_add(self, p: GVec, q: GVec) -> GVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            let (x1, y1, z1, t1) = (
                load(&p.x.limbs),
                load(&p.y.limbs),
                load(&p.z.limbs),
                load(&p.t.limbs),
            );
            let (x2, y2, z2, t2) = (
                load(&q.x.limbs),
                load(&q.y.limbs),
                load(&q.z.limbs),
                load(&q.t.limbs),
            );
            let two_d = load(&EDWARDS_D2.limbs);

            // Unified extended-coordinates addition (Hisil-Wong-Carter-Dawson):
            //
            //   A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
            //   B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
            //   C = 2d * T1 * T2                 G = D + C        Z3 = F*G
            //   D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
            let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
            let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
            let c = mul_regs(mul_regs(t1, t2), two_d);
            let zz = mul_regs_loose(z1, z2);
            let d = add_raw(zz, zz);
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));

            GVec {
                x: FVec {
                    limbs: store(mul_regs(e, f)),
                },
                y: FVec {
                    limbs: store(mul_regs(g, h)),
                },
                t: FVec {
                    limbs: store(mul_regs(e, h)),
                },
                z: FVec {
                    limbs: store(mul_regs(f, g)),
                },
            }
        }
    }

    /// Fused mixed point addition with every intermediate held in registers.
    ///
    /// # Correctness
    ///
    /// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below
    /// `reduce_regs`'s `2^63` bound, and every right operand of `sub_raw` is reduced below
    /// `2^52`.
    #[inline(always)]
    fn g_add_mixed(self, p: GVec, q: GAffineVec) -> GVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            let (x1, y1, z1, t1) = (
                load(&p.x.limbs),
                load(&p.y.limbs),
                load(&p.z.limbs),
                load(&p.t.limbs),
            );
            let (x2, y2, t2d) = (load(&q.x.limbs), load(&q.y.limbs), load(&q.t2d.limbs));

            let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
            let b = mul_regs_loose(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
            let c = mul_regs(t1, t2d);
            let d = add_raw(z1, z1);
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));

            GVec {
                x: FVec {
                    limbs: store(mul_regs(e, f)),
                },
                y: FVec {
                    limbs: store(mul_regs(g, h)),
                },
                t: FVec {
                    limbs: store(mul_regs(e, h)),
                },
                z: FVec {
                    limbs: store(mul_regs(f, g)),
                },
            }
        }
    }

    /// Fused point doubling using the dedicated `dbl-2008-hwcd` formula.
    ///
    /// # Correctness
    ///
    /// All input limbs satisfy `FVec`'s bound; every loose intermediate stays below
    /// `reduce_regs`'s `2^63` bound, and every right operand of `sub_raw` is reduced below
    /// `2^52`.
    #[inline(always)]
    fn g_double(self, p: GVec) -> GVec {
        // SAFETY: `Backend` can only be constructed when AVX-512F and AVX-512 IFMA are available.
        unsafe {
            let (x, y, z) = (load(&p.x.limbs), load(&p.y.limbs), load(&p.z.limbs));

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

            GVec {
                x: FVec {
                    limbs: store(mul_regs(e, f)),
                },
                y: FVec {
                    limbs: store(mul_regs(g, h)),
                },
                t: FVec {
                    limbs: store(mul_regs(e, h)),
                },
                z: FVec {
                    limbs: store(mul_regs(f, g)),
                },
            }
        }
    }
}

impl super::Backend for Backend {}
