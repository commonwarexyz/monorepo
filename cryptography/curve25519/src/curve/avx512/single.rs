//! One point packed across the four 64-bit lanes of a 256-bit register, implementing
//! [`Single`] for single-signature verification and fixed-base multiplication.
//!
//! Register `k` holds limb `k` (radix `2^51`) of a point's coordinates, one coordinate per lane,
//! so each multiplication level of a point addition or doubling is one lane-wise IFMA
//! multiplication. Products are folded but not carried, leaving limbs below `300 * 2^52`; every
//! operation applies its additions and subtractions to such limbs and carries once before it
//! multiplies, so IFMA only ever sees limbs below `2^52`.

use super::Backend;
use crate::curve::{BIAS_16P, F, G, GAffine, GProjective, LANES, MASK_51, Niels, Single};
use core::arch::x86_64::*;

/// Five limb registers, one coordinate per lane.
type Rows = [__m256i; 5];

/// An extended or projective point, as lanes `[X, Y, Z, T]` with limbs below `300 * 2^52`.
///
/// Doubling ignores the `T` lane, so the same value serves both coordinate systems.
#[derive(Clone, Copy)]
pub(super) struct Point(Rows);

/// An addition operand, as lanes `[Y - X, Y + X, 2d*T, 2*Z]` with limbs below `2^52`.
#[derive(Clone, Copy)]
pub(super) struct Cached(Rows);

/// The operands of a point's final multiplication: lanes `[E, G, F, E]` and `[F, H, G, H]` in
/// [`G::add`]'s notation, with limbs below `2^52`, whose product is `[X3, Y3, Z3, T3]`.
#[derive(Clone, Copy)]
pub(super) struct Operands(Rows, Rows);

/// The single-point operations of the AVX-512 backend.
///
/// Holding a [`Backend`] proves that the CPU supports AVX-512F, AVX-512VL, and AVX-512 IFMA, so
/// every method may use their intrinsics. The methods are forced inline so that, once the
/// algorithms inline into the backend's target-feature entry, the intrinsics inline there too.
#[derive(Clone, Copy)]
pub(super) struct Packed(Backend);

/// `1024p`, limb-wise. Every limb exceeds every unreduced product limb, so subtracting such a limb
/// from it never underflows, and a sum of three terms below `2^61.3` stays below `2^63`.
const BIAS: [u64; 5] = [
    1024 * (MASK_51 - 18),
    1024 * MASK_51,
    1024 * MASK_51,
    1024 * MASK_51,
    1024 * MASK_51,
];

/// `2p`, limb-wise. For a carried limb `x` (at most `2^51 + 19 * 2^12`), `2p - x` lies in
/// `[0, 2^52)`, so negating a cached operand needs no carry.
const TWO_P: [u64; 5] = [
    2 * (MASK_51 - 18),
    2 * MASK_51,
    2 * MASK_51,
    2 * MASK_51,
    2 * MASK_51,
];

/// The `vpermq` immediate placing lanes `a, b, c, d` of the source in lanes 0 to 3.
const fn order(a: i32, b: i32, c: i32, d: i32) -> i32 {
    a | b << 2 | c << 4 | d << 6
}

/// `19*z` via `(z << 4) + (z << 1) + z`.
///
/// `z` must be below `2^59` per lane. The explicit sequence keeps LLVM from recognizing a packed
/// `u64` multiplication and expanding it into two 32-bit multiplications, two shifts, and an
/// addition.
#[inline]
#[target_feature(enable = "avx512f,avx512vl")]
fn mul19(z: __m256i) -> __m256i {
    let result;
    let _times16: __m256i;
    let _doubled: __m256i;

    // SAFETY: AVX-512VL is enabled. The instructions only read their register input, write
    // their register outputs, and preserve flags.
    unsafe {
        core::arch::asm!(
            "vpsllq {times16}, {z}, 4",
            "vpsllq {doubled}, {z}, 1",
            "vpaddq {doubled}, {doubled}, {times16}",
            "vpaddq {result}, {doubled}, {z}",
            z = in(ymm_reg) z,
            times16 = out(ymm_reg) _times16,
            doubled = out(ymm_reg) _doubled,
            result = lateout(ymm_reg) result,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    result
}

/// Merge-masked lane additions and subtractions, each one instruction.
///
/// LLVM lowers the intrinsics with a constant mask to an unmasked operation and a blend; a single
/// masked instruction shortens the linear steps between the two multiplication levels.
macro_rules! masked {
    ($name:ident, $instruction:literal) => {
        #[inline]
        #[target_feature(enable = "avx512f,avx512vl")]
        fn $name(src: __m256i, k: __mmask8, a: __m256i, b: __m256i) -> __m256i {
            let mut result = src;
            // SAFETY: AVX-512VL is enabled. The instruction only reads its register and mask
            // inputs, merges into its register output, and preserves flags.
            unsafe {
                core::arch::asm!(
                    concat!($instruction, " {result}{{{k}}}, {a}, {b}"),
                    result = inout(ymm_reg) result,
                    k = in(kreg) k,
                    a = in(ymm_reg) a,
                    b = in(ymm_reg) b,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            result
        }
    };
}
masked!(mask_add, "vpaddq");
masked!(mask_sub, "vpsubq");

/// Lanes of `a` where `k` is set and of `src` elsewhere, as one register-to-register move.
///
/// Secret masks select lanes only through this helper and the masked arithmetic above, so they
/// gate register operands alone: LLVM folds a load feeding the equivalent intrinsic into a masked
/// load, whose memory access would then depend on the mask.
#[inline]
#[target_feature(enable = "avx512f,avx512vl")]
fn mask_mov(src: __m256i, k: __mmask8, a: __m256i) -> __m256i {
    let mut result = src;
    // SAFETY: AVX-512VL is enabled. The instruction only reads its register and mask inputs,
    // merges into its register output, and preserves flags.
    unsafe {
        core::arch::asm!(
            "vmovdqa64 {result}{{{k}}}, {a}",
            result = inout(ymm_reg) result,
            k = in(kreg) k,
            a = in(ymm_reg) a,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    result
}

/// Decompresses two encodings with one lane-wise square-root chain over the backend's eight
/// lanes, which costs less than two scalar chains, returning `None` when either is invalid.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn decompress_pair(backend: Backend, encodings: [&[u8; 32]; 2]) -> Option<[GAffine; 2]> {
    let mut lanes = [[0u8; 32]; LANES];
    for (lane, encoding) in lanes.iter_mut().zip(encodings.iter().cycle()) {
        *lane = **encoding;
    }
    let points = GAffine::decompress_batch(backend, &lanes);
    Some([points[0]?, points[1]?])
}

// SAFETY (every unsafe block in this impl): `self` holds a `Backend`, which is only constructed
// after detecting AVX-512F, AVX-512VL, and AVX-512 IFMA, the features of every intrinsic and
// helper used here.
impl Packed {
    pub(super) const fn new(backend: Backend) -> Self {
        Self(backend)
    }

    /// Splats each limb into every lane.
    #[inline(always)]
    fn splat(self, limbs: [u64; 5]) -> Rows {
        // SAFETY: see the impl.
        unsafe {
            [
                _mm256_set1_epi64x(limbs[0] as i64),
                _mm256_set1_epi64x(limbs[1] as i64),
                _mm256_set1_epi64x(limbs[2] as i64),
                _mm256_set1_epi64x(limbs[3] as i64),
                _mm256_set1_epi64x(limbs[4] as i64),
            ]
        }
    }

    /// Restores the `2^52` limb bound with one parallel carry pass.
    ///
    /// Inputs below `2^63` have carries below `2^12`, so the outputs are below `2^51 + 2^12`,
    /// and limb 0, which takes the carry out of limb 4 times 19, below `2^51 + 19 * 2^12`.
    #[inline(always)]
    fn carry(self, l: Rows) -> Rows {
        // SAFETY: see the impl.
        unsafe {
            let mask = _mm256_set1_epi64x(MASK_51 as i64);
            let c = [
                _mm256_srli_epi64::<51>(l[0]),
                _mm256_srli_epi64::<51>(l[1]),
                _mm256_srli_epi64::<51>(l[2]),
                _mm256_srli_epi64::<51>(l[3]),
                _mm256_srli_epi64::<51>(l[4]),
            ];

            // IFMA computes the folded carry exactly because it is below 2^12.
            [
                _mm256_madd52lo_epu64(_mm256_and_si256(l[0], mask), c[4], _mm256_set1_epi64x(19)),
                _mm256_add_epi64(_mm256_and_si256(l[1], mask), c[0]),
                _mm256_add_epi64(_mm256_and_si256(l[2], mask), c[1]),
                _mm256_add_epi64(_mm256_and_si256(l[3], mask), c[2]),
                _mm256_add_epi64(_mm256_and_si256(l[4], mask), c[3]),
            ]
        }
    }

    /// Lane-wise product, folded onto five limbs but not carried.
    ///
    /// IFMA splits each product at bit 52, so high halves weigh twice the next column. With
    /// inputs below `2^52`, every column accumulator is below `5 * 2^52`, each column
    /// `lo + 2*hi` below `15 * 2^52`, and each folded limb `z[k] + 19*z[k+5]` below
    /// `300 * 2^52 < 2^60.3`. The products for columns 5 to 9 are issued first, so their fold
    /// overlaps the remaining products.
    #[inline(always)]
    fn mul_wide(self, a: &Rows, b: &Rows) -> Rows {
        // SAFETY: see the impl.
        unsafe {
            let mut lo = [_mm256_setzero_si256(); 10];
            let mut hi = [_mm256_setzero_si256(); 10];
            let mut folded = [_mm256_setzero_si256(); 5];
            for high in [true, false] {
                for i in 0..5 {
                    for j in 0..5 {
                        if (i + j >= 4) == high {
                            hi[i + j + 1] = _mm256_madd52hi_epu64(hi[i + j + 1], a[i], b[j]);
                        }
                        if (i + j >= 5) == high {
                            lo[i + j] = _mm256_madd52lo_epu64(lo[i + j], a[i], b[j]);
                        }
                    }
                }
                if high {
                    for k in 0..5 {
                        let column =
                            _mm256_add_epi64(lo[k + 5], _mm256_add_epi64(hi[k + 5], hi[k + 5]));
                        folded[k] = mul19(column);
                    }
                }
            }
            for k in 0..5 {
                let column = _mm256_add_epi64(lo[k], _mm256_add_epi64(hi[k], hi[k]));
                folded[k] = _mm256_add_epi64(column, folded[k]);
            }
            folded
        }
    }

    /// Lane-wise square, folded but not carried, with each cross product computed once.
    ///
    /// Column `k` is `c1[k] + 2*c2[k] + 4*c4[k]`; the doubled cross products and the weights of
    /// high halves give each column the same bound as in [`Packed::mul_wide`], whose ordering
    /// this follows.
    #[inline(always)]
    fn square_wide(self, a: &Rows) -> Rows {
        // SAFETY: see the impl.
        unsafe {
            let mut c1 = [_mm256_setzero_si256(); 10];
            let mut c2 = [_mm256_setzero_si256(); 10];
            let mut c4 = [_mm256_setzero_si256(); 10];
            let mut folded = [_mm256_setzero_si256(); 5];
            for high in [true, false] {
                for i in 0..5 {
                    if (2 * i >= 5) == high {
                        c1[2 * i] = _mm256_madd52lo_epu64(c1[2 * i], a[i], a[i]);
                    }
                    if (2 * i + 1 >= 5) == high {
                        c2[2 * i + 1] = _mm256_madd52hi_epu64(c2[2 * i + 1], a[i], a[i]);
                    }
                    for j in (i + 1)..5 {
                        if (i + j >= 5) == high {
                            c2[i + j] = _mm256_madd52lo_epu64(c2[i + j], a[i], a[j]);
                        }
                        if (i + j + 1 >= 5) == high {
                            c4[i + j + 1] = _mm256_madd52hi_epu64(c4[i + j + 1], a[i], a[j]);
                        }
                    }
                }
                if high {
                    for k in 0..5 {
                        let column = _mm256_add_epi64(
                            c1[k + 5],
                            _mm256_add_epi64(
                                _mm256_add_epi64(c2[k + 5], c2[k + 5]),
                                _mm256_slli_epi64::<2>(c4[k + 5]),
                            ),
                        );
                        folded[k] = mul19(column);
                    }
                }
            }
            for k in 0..5 {
                let column = _mm256_add_epi64(
                    c1[k],
                    _mm256_add_epi64(
                        _mm256_add_epi64(c2[k], c2[k]),
                        _mm256_slli_epi64::<2>(c4[k]),
                    ),
                );
                folded[k] = _mm256_add_epi64(column, folded[k]);
            }
            folded
        }
    }

    /// `[Y - X, Y + X, T, Z]`, carried, from lanes `[X, Y, Z, T]` with limbs below `2^61`.
    #[inline(always)]
    fn diff_sum(self, p: &Rows) -> Rows {
        let bias = self.splat(BIAS);
        let mut out = [p[0]; 5];
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                let swapped = _mm256_shuffle_epi32::<0x4e>(p[k]); // [Y, X, T, Z]
                let negated = mask_sub(p[k], 0b0001, bias[k], p[k]); // [-X, Y, Z, T]
                out[k] = mask_add(swapped, 0b0011, swapped, negated); // [Y - X, X + Y, T, Z]
            }
        }
        self.carry(out)
    }

    /// [`G::add_projective_niels`] up to its final products: `A, B, C, D` from one multiplication
    /// of `[Y1 - X1, Y1 + X1, T1, Z1]` by `[Y2 - X2, Y2 + X2, 2d*T2, 2*Z2]`, then `E = B - A`,
    /// `H = B + A`, `F = D - C`, and `G = D + C`, rearranged as the final operands.
    #[inline(always)]
    fn add(self, p: &Rows, q: &Rows) -> Operands {
        let products = self.mul_wide(&self.diff_sum(p), q); // [A, B, C, D]
        let bias = self.splat(BIAS);
        let mut s = products;
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                let swapped = _mm256_shuffle_epi32::<0x4e>(products[k]); // [B, A, D, C]
                let negated = mask_sub(products[k], 0b0101, bias[k], products[k]); // [-A, B, -C, D]
                s[k] = _mm256_add_epi64(swapped, negated); // [E, H, F, G]
            }
        }
        let s = self.carry(s);
        let mut left = s;
        let mut right = s;
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                left[k] = _mm256_permute4x64_epi64::<{ order(0, 3, 2, 0) }>(s[k]); // [E, G, F, E]
                right[k] = _mm256_permute4x64_epi64::<{ order(2, 1, 3, 1) }>(s[k]); // [F, H, G, H]
            }
        }
        Operands(left, right)
    }

    /// [`GProjective::double`] up to its final products.
    ///
    /// One multiplication squares `[X, Y, Z, X + Y]` to `[A, B, Z^2, K]`. The operands then hold
    /// `E' = A + B - K`, `F' = A - B + 2Z^2`, `G' = A - B`, and `H' = A + B`, which are
    /// `-E, -F, -G, -H` of the scalar formula, so every final product is unchanged.
    #[inline(always)]
    fn double(self, p: &Rows) -> Operands {
        let mut s = *p;
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                let x = _mm256_permute4x64_epi64::<{ order(0, 1, 2, 0) }>(p[k]); // [X, Y, Z, X]
                let y = _mm256_permute4x64_epi64::<{ order(0, 0, 0, 1) }>(p[k]); // [., ., ., Y]
                s[k] = mask_add(x, 0b1000, x, y); // [X, Y, Z, X + Y]
            }
        }
        let squares = self.square_wide(&self.carry(s)); // [A, B, Z^2, K]

        let bias = self.splat(BIAS);
        let mut left = squares;
        let mut right = squares;
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                let a = _mm256_permute4x64_epi64::<{ order(0, 0, 0, 0) }>(squares[k]);
                let b = _mm256_permute4x64_epi64::<{ order(1, 1, 1, 1) }>(squares[k]);
                let c = _mm256_permute4x64_epi64::<{ order(3, 2, 2, 3) }>(squares[k]); // [K, Z^2, Z^2, K]
                let z2 = _mm256_permute4x64_epi64::<{ order(2, 2, 2, 2) }>(squares[k]);

                // Left: [A + B - K, A - B, A - B + 2Z^2, A + B - K].
                let signed_b = mask_sub(b, 0b0110, bias[k], b);
                let terms = mask_sub(c, 0b1001, bias[k], c);
                let terms = mask_add(terms, 0b0100, terms, c);
                let sum = _mm256_add_epi64(a, signed_b);
                left[k] = mask_add(sum, 0b1101, sum, terms);

                // Right: [A - B + 2Z^2, A + B, A - B, A + B].
                let signed_b = mask_sub(b, 0b0101, bias[k], b);
                let sum = _mm256_add_epi64(a, signed_b);
                right[k] = mask_add(sum, 0b0001, sum, _mm256_add_epi64(z2, z2));
            }
        }
        Operands(self.carry(left), self.carry(right))
    }

    /// Negates the operand when `mask` selects all four lanes (it must select all or none):
    /// swaps `Y - X` with `Y + X` and replaces `2d*T` by `bias - 2d*T`.
    ///
    /// With `2p` as the bias the operand's limbs must be at most `2p`'s, as every carried limb is,
    /// and the result is below `2^52`. With `16p` any limbs below `2^52` work, but the result needs
    /// a carry.
    #[inline(always)]
    fn negate(self, q: &Rows, mask: __mmask8, bias: [u64; 5]) -> Rows {
        let bias = self.splat(bias);
        let mut out = *q;
        // SAFETY: see the impl.
        unsafe {
            for k in 0..5 {
                let swapped = _mm256_shuffle_epi32::<0x4e>(q[k]);
                let swapped = mask_mov(q[k], mask & 0b0011, swapped);
                out[k] = mask_sub(swapped, mask & 0b0100, bias[k], swapped);
            }
        }
        out
    }

    /// Converts a [`Niels`] point to the operand `[y - x, y + x, 2d*x*y, 2]`, negated when `mask`
    /// selects all four lanes (it must select all or none). The limbs may be any below `2^52`.
    ///
    /// The fifteen limbs, `y + x`, `y - x`, and `2d*x*y` in order, arrive in four registers, four
    /// limbs each.
    #[inline(always)]
    fn niels_operand(self, [r0, r1, r2, r3]: [__m256i; 4], mask: __mmask8) -> Rows {
        // Limb `k` of `y + x`, `y - x`, and `2d*x*y` is limb `k`, `5 + k`, and `10 + k` of the
        // fifteen, and register `j` holds limbs `4j..4j + 4`, so row `k` gathers `y - x` and
        // `y + x` from the registers holding limbs `5 + k` and `k`, then `2d*x*y` from the one
        // holding limb `10 + k`.
        let mut rows = [
            self.gather([r0, r1, r2], [5, 0, 6]),
            self.gather([r0, r1, r2], [6, 1, 7]),
            self.gather([r0, r1, r3], [7, 2, 4]),
            self.gather([r0, r2, r3], [4, 3, 5]),
            self.gather([r1, r2, r3], [5, 0, 6]),
        ];

        // `Z = 1`, so lane 3 holds `2*Z = 2`.
        // SAFETY: see the impl.
        rows[0] = unsafe { _mm256_mask_mov_epi64(rows[0], 0b1000, _mm256_set1_epi64x(2)) };
        self.carry(self.negate(&rows, mask, BIAS_16P))
    }

    /// Selects lanes 0 and 1 from `a` and `b` by `first` and `second`, then lane 2 from `c` by
    /// `third`, with lane 3 zero. An index `i < 4` selects lane `i` of `a` (for `third`, of the
    /// lanes selected so far), and `4 + i` lane `i` of `b` (for `third`, of `c`).
    #[inline(always)]
    fn gather(self, [a, b, c]: [__m256i; 3], [first, second, third]: [i64; 3]) -> __m256i {
        // SAFETY: see the impl.
        unsafe {
            let pair = _mm256_permutex2var_epi64(a, _mm256_set_epi64x(0, 0, second, first), b);
            _mm256_maskz_permutex2var_epi64(0b0111, pair, _mm256_set_epi64x(0, third, 1, 0), c)
        }
    }

    /// The masks selecting entry `k` of a table row when `|digit| = k + 1`, and the mask negating
    /// the selection when `digit` is negative, each covering all four lanes or none.
    ///
    /// The magnitude and sign reach vector comparisons through an optimization barrier, so the
    /// compiler cannot turn the masked selection into branches or indexing on `digit`.
    #[inline(always)]
    fn digit_masks(self, digit: i8) -> ([__mmask8; 8], __mmask8) {
        // The sign bit, and `|digit|` computed with the two's complement identity.
        let negative = (digit as u8) >> 7;
        let magnitude = ((digit as u8) ^ 0u8.wrapping_sub(negative)).wrapping_add(negative);

        // SAFETY: see the impl.
        unsafe {
            let magnitude = core::hint::black_box(_mm256_set1_epi64x(i64::from(magnitude)));
            let negative = core::hint::black_box(_mm256_set1_epi64x(i64::from(negative)));
            let mut masks = [0; 8];
            for (k, mask) in (1..).zip(&mut masks) {
                *mask = _mm256_cmpeq_epi64_mask(magnitude, _mm256_set1_epi64x(k));
            }
            (
                masks,
                _mm256_cmpeq_epi64_mask(negative, _mm256_set1_epi64x(1)),
            )
        }
    }

    /// Loads a [`Niels`] point's fifteen limbs, four per register with the sixteenth lane zero.
    #[inline(always)]
    fn load_niels(self, niels: &Niels) -> [__m256i; 4] {
        let limbs = core::ptr::from_ref(niels).cast::<i64>();
        // SAFETY: see the impl for the features. `Niels` is three consecutive `F`s, fifteen
        // `u64` limbs, so limbs 0..15 are readable; `loadu` needs no alignment, and the masked
        // load reads only limbs 12..15.
        unsafe {
            [
                _mm256_loadu_si256(limbs.cast()),
                _mm256_loadu_si256(limbs.add(4).cast()),
                _mm256_loadu_si256(limbs.add(8).cast()),
                _mm256_maskz_loadu_epi64(0b0111, limbs.add(12)),
            ]
        }
    }

    /// Returns `digit * P` for `row[k] = (k + 1) * P` and `digit` in `[-8, 8]` as an operand.
    ///
    /// Every entry is loaded in full and merged in registers under a mask from `digit`, and the
    /// negation is masked too, so neither the memory accesses nor the control flow depend on
    /// `digit`.
    #[inline(always)]
    fn select(self, row: &[Niels; 8], digit: i8) -> Rows {
        let (masks, negate) = self.digit_masks(digit);
        // SAFETY: see the impl.
        let selected = unsafe {
            // The identity's `y + x` and `y - x` are one: limbs 0 and 5.
            let mut selected = [
                _mm256_set_epi64x(0, 0, 0, 1),
                _mm256_set_epi64x(0, 0, 1, 0),
                _mm256_setzero_si256(),
                _mm256_setzero_si256(),
            ];
            for (mask, entry) in masks.into_iter().zip(row) {
                let limbs = self.load_niels(entry);
                for i in 0..4 {
                    selected[i] = mask_mov(selected[i], mask, limbs[i]);
                }
            }
            selected
        };
        self.niels_operand(selected, negate)
    }

    /// Converts a point to lanes `[X, Y, Z, T]`.
    #[inline(always)]
    fn load(self, point: &G) -> Rows {
        let (x, y, z, t) = (point.x.0, point.y.0, point.z.0, point.t.0);
        let mut rows = [[0i64; 4]; 5];
        for k in 0..5 {
            rows[k] = [x[k] as i64, y[k] as i64, z[k] as i64, t[k] as i64];
        }
        // SAFETY: see the impl.
        unsafe {
            [
                _mm256_set_epi64x(rows[0][3], rows[0][2], rows[0][1], rows[0][0]),
                _mm256_set_epi64x(rows[1][3], rows[1][2], rows[1][1], rows[1][0]),
                _mm256_set_epi64x(rows[2][3], rows[2][2], rows[2][1], rows[2][0]),
                _mm256_set_epi64x(rows[3][3], rows[3][2], rows[3][1], rows[3][0]),
                _mm256_set_epi64x(rows[4][3], rows[4][2], rows[4][1], rows[4][0]),
            ]
        }
    }

    /// Carries lanes `[X, Y, Z, T]` and returns the four coordinates.
    #[inline(always)]
    fn store(self, point: &Rows) -> [F; 4] {
        let rows = self.carry(*point);
        let mut lanes = [[0u64; 4]; 5];
        for k in 0..5 {
            // SAFETY: see the impl for the features. Each destination is four `u64`s, one
            // register, and `storeu` needs no alignment.
            unsafe { _mm256_storeu_si256(lanes[k].as_mut_ptr().cast(), rows[k]) };
        }
        let mut coordinates = [F::ZERO; 4];
        for (lane, coordinate) in coordinates.iter_mut().enumerate() {
            for (limb, lanes) in coordinate.0.iter_mut().zip(&lanes) {
                *limb = lanes[lane];
            }
        }
        coordinates
    }

    /// Prepares lanes `[X, Y, Z, T]` as an operand with one multiplication by `[1, 1, 2d, 2]`.
    #[inline(always)]
    fn cache(self, point: &Rows) -> Rows {
        let d2 = F::EDWARDS_D2.0.map(|limb| limb as i64);
        // SAFETY: see the impl.
        let factors = unsafe {
            [
                _mm256_set_epi64x(2, d2[0], 1, 1),
                _mm256_set_epi64x(0, d2[1], 0, 0),
                _mm256_set_epi64x(0, d2[2], 0, 0),
                _mm256_set_epi64x(0, d2[3], 0, 0),
                _mm256_set_epi64x(0, d2[4], 0, 0),
            ]
        };
        self.carry(self.mul_wide(&self.diff_sum(point), &factors))
    }
}

impl Single for Packed {
    type Extended = Point;
    type Projective = Point;
    type Completed = Operands;
    type Cached = Cached;

    #[inline(always)]
    fn load(self, point: &G) -> Point {
        Point(self.load(point))
    }

    #[inline(always)]
    fn store(self, point: Point) -> G {
        let [x, y, z, t] = self.store(&point.0);
        G { x, y, t, z }
    }

    #[inline(always)]
    fn store_projective(self, point: Point) -> GProjective {
        let [x, y, z, _] = self.store(&point.0);
        GProjective { x, y, z }
    }

    #[inline(always)]
    fn identity(self) -> Point {
        Point(self.load(&G::IDENTITY))
    }

    #[inline(always)]
    fn project(self, point: Point) -> Point {
        point
    }

    #[inline(always)]
    fn double(self, point: Point) -> Operands {
        self.double(&point.0)
    }

    #[inline(always)]
    fn to_projective(self, point: Operands) -> Point {
        Point(self.mul_wide(&point.0, &point.1))
    }

    #[inline(always)]
    fn to_extended(self, point: Operands) -> Point {
        Point(self.mul_wide(&point.0, &point.1))
    }

    #[inline(always)]
    fn cache(self, point: Point) -> Cached {
        Cached(self.cache(&point.0))
    }

    #[inline(always)]
    fn add(self, point: Point, cached: Cached, negate: bool) -> Operands {
        let operand = if negate {
            self.negate(&cached.0, 0xff, TWO_P)
        } else {
            cached.0
        };
        self.add(&point.0, &operand)
    }

    #[inline(always)]
    fn add_niels(self, point: Point, niels: &Niels, negate: bool) -> Operands {
        let mask = if negate { 0xff } else { 0 };
        self.add(&point.0, &self.niels_operand(self.load_niels(niels), mask))
    }

    #[inline(always)]
    fn add_selected(self, point: Point, row: &[Niels; 8], digit: i8) -> Operands {
        self.add(&point.0, &self.select(row, digit))
    }

    #[inline(always)]
    fn decompress_pair(self, encodings: [&[u8; 32]; 2]) -> Option<[GAffine; 2]> {
        // SAFETY: `self` holds a `Backend`, constructed only after the feature check.
        unsafe { decompress_pair(self.0, encodings) }
    }
}
