//! Variable-time twisted Edwards point arithmetic for batch verification.
//!
//! Point formulas match curve25519-dalek's serial backend (`curve_models`):
//! extended coordinates (X : Y : Z : T) with x = X/Z, y = Y/Z, T = XY/Z, the
//! P1xP1 "completed" intermediate, and cached (Niels) operands for cheap
//! re-addition. The unified addition formulas are complete on this curve, so
//! identity and small-order points need no special cases.
//!
//! [`decompress_batch`] is the reason this module exists: it validates and
//! decompresses many encoded points at once through the interleaved
//! square-root kernel in [`super::fe`], with byte-exact dalek/ZIP215
//! semantics (non-canonical y accepted, high bit is the x sign, sign bit on
//! x = 0 accepted).

use super::fe::{sqrt_ratio_i_w, Fe, EDWARDS_D, EDWARDS_D2, WIDTH};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A point in affine coordinates, the output of decompression.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Affine {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
}

/// A point in extended coordinates (X : Y : Z : T).
#[derive(Copy, Clone, Debug)]
pub(crate) struct Extended {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// A point in projective coordinates (X : Y : Z), used between doublings.
#[derive(Copy, Clone)]
struct Projective {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// A point in the P1xP1 model, the output of addition and doubling.
struct Completed {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// An affine point cached for repeated mixed addition: (y+x, y-x, 2dxy).
#[derive(Copy, Clone)]
pub(crate) struct CachedAffine {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

/// An extended point cached for repeated addition: (Y+X, Y-X, Z, 2dT).
#[derive(Copy, Clone)]
pub(crate) struct CachedExtended {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl CachedExtended {
    /// The cache of the negated point: (Y-X, Y+X, Z, -2dT).
    pub(crate) fn neg(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            z: self.z,
            t2d: -&self.t2d,
        }
    }
}

impl Affine {
    /// The negated point (-x, y).
    pub(crate) fn neg(&self) -> Self {
        Self {
            x: -&self.x,
            y: self.y,
        }
    }

    pub(crate) fn to_extended(self) -> Extended {
        Extended {
            x: self.x,
            y: self.y,
            z: Fe::ONE,
            t: self.x.mul(&self.y),
        }
    }

    pub(crate) fn to_cached(self) -> CachedAffine {
        CachedAffine {
            y_plus_x: &self.y + &self.x,
            y_minus_x: &self.y - &self.x,
            xy2d: self.x.mul(&self.y).mul(&EDWARDS_D2),
        }
    }
}

impl CachedAffine {
    /// The cache of the negated point: (y-x, y+x, -2dxy).
    pub(crate) fn neg(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: -&self.xy2d,
        }
    }
}

impl Completed {
    fn to_extended(&self) -> Extended {
        Extended {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }

    fn to_projective(&self) -> Projective {
        Projective {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
        }
    }
}

impl Projective {
    fn double(&self) -> Completed {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz2 = self.z.square2();
        let x_plus_y_sq = (&self.x + &self.y).square();
        let yy_plus_xx = &yy + &xx;
        let yy_minus_xx = &yy - &xx;
        Completed {
            x: &x_plus_y_sq - &yy_plus_xx,
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: &zz2 - &yy_minus_xx,
        }
    }
}

impl Extended {
    pub(crate) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Mixed addition with a cached affine operand.
    pub(crate) fn add_cached(&self, other: &CachedAffine) -> Self {
        let y_plus_x = &self.y + &self.x;
        let y_minus_x = &self.y - &self.x;
        let pp = y_plus_x.mul(&other.y_plus_x);
        let mm = y_minus_x.mul(&other.y_minus_x);
        let txy2d = self.t.mul(&other.xy2d);
        let z2 = &self.z + &self.z;
        Completed {
            x: &pp - &mm,
            y: &pp + &mm,
            z: &z2 + &txy2d,
            t: &z2 - &txy2d,
        }
        .to_extended()
    }

    /// Cache this point for repeated addition.
    pub(crate) fn to_cached(self) -> CachedExtended {
        CachedExtended {
            y_plus_x: &self.y + &self.x,
            y_minus_x: &self.y - &self.x,
            z: self.z,
            t2d: self.t.mul(&EDWARDS_D2),
        }
    }

    /// Addition with a cached extended operand.
    pub(crate) fn add_cached_extended(&self, other: &CachedExtended) -> Self {
        let y_plus_x = &self.y + &self.x;
        let y_minus_x = &self.y - &self.x;
        let pp = y_plus_x.mul(&other.y_plus_x);
        let mm = y_minus_x.mul(&other.y_minus_x);
        let tt2d = self.t.mul(&other.t2d);
        let zz = self.z.mul(&other.z);
        let zz2 = &zz + &zz;
        Completed {
            x: &pp - &mm,
            y: &pp + &mm,
            z: &zz2 + &tt2d,
            t: &zz2 - &tt2d,
        }
        .to_extended()
    }

    /// General addition of two extended points.
    pub(crate) fn add(&self, other: &Self) -> Self {
        self.add_cached_extended(&other.to_cached())
    }

    /// Multiply by 2^k via repeated doubling.
    pub(crate) fn mul_by_pow_2(&self, k: u32) -> Self {
        debug_assert!(k > 0);
        let mut p = Projective {
            x: self.x,
            y: self.y,
            z: self.z,
        };
        for _ in 0..k - 1 {
            p = p.double().to_projective();
        }
        p.double().to_extended()
    }

    /// Dehomogenize to affine coordinates (one field inversion).
    pub(crate) fn to_affine(self) -> Affine {
        let zinv = self.z.invert();
        Affine {
            x: self.x.mul(&zinv),
            y: self.y.mul(&zinv),
        }
    }

    /// Canonical compressed encoding (y with the sign of x in the high bit).
    pub(crate) fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut s = y.to_bytes();
        s[31] ^= (x.is_negative() as u8) << 7;
        s
    }
}

/// Decompress one lane group of `W` encodings into `out`. Returns false if any
/// lane is not a curve point.
fn decompress_chunk<const W: usize>(chunk: &[[u8; 32]; W], out: &mut Vec<Affine>) -> bool {
    let mut ys = [Fe::ZERO; W];
    let mut us = [Fe::ZERO; W];
    let mut vs = [Fe::ZERO; W];
    for i in 0..W {
        let y = Fe::from_bytes(&chunk[i]);
        let yy = y.square();
        us[i] = &yy - &Fe::ONE;
        vs[i] = &yy.mul(&EDWARDS_D) + &Fe::ONE;
        ys[i] = y;
    }
    let (ok, xs) = sqrt_ratio_i_w(&us, &vs);
    for i in 0..W {
        if !ok[i] {
            return false;
        }
        // sqrt_ratio_i_w returns the nonnegative root. Negate it when the
        // encoding's sign bit is set, like dalek, even when x is zero.
        let mut x = xs[i];
        if chunk[i][31] >> 7 == 1 {
            x = -&x;
        }
        out.push(Affine { x, y: ys[i] });
    }
    true
}

/// Decompress one lane group of four encodings into `out` using the NEON
/// square-root kernel. Returns false if any lane is not a curve point.
#[cfg(target_arch = "aarch64")]
fn decompress_chunk_neon(chunk: &[[u8; 32]; 4], out: &mut Vec<Affine>) -> bool {
    let mut ys = [Fe::ZERO; 4];
    let mut us = [Fe::ZERO; 4];
    let mut vs = [Fe::ZERO; 4];
    for i in 0..4 {
        let y = Fe::from_bytes(&chunk[i]);
        let yy = y.square();
        us[i] = &yy - &Fe::ONE;
        vs[i] = &yy.mul(&EDWARDS_D) + &Fe::ONE;
        ys[i] = y;
    }
    let (ok, xs) = super::neon::sqrt_ratio_i_x4(&us, &vs);
    for i in 0..4 {
        if !ok[i] {
            return false;
        }
        let mut x = xs[i];
        if chunk[i][31] >> 7 == 1 {
            x = -&x;
        }
        out.push(Affine { x, y: ys[i] });
    }
    true
}

/// Decompress one lane group of four encodings into `out` using the AVX-512
/// IFMA square-root kernel when the CPU has it, and the scalar kernel
/// otherwise. Returns false if any lane is not a curve point.
#[cfg(target_arch = "x86_64")]
fn decompress_chunk_ifma(chunk: &[[u8; 32]; 4], out: &mut Vec<Affine>) -> bool {
    if !super::ifma::supported() {
        return decompress_chunk(chunk, out);
    }
    let mut ys = [Fe::ZERO; 4];
    let mut us = [Fe::ZERO; 4];
    let mut vs = [Fe::ZERO; 4];
    for i in 0..4 {
        let y = Fe::from_bytes(&chunk[i]);
        let yy = y.square();
        us[i] = &yy - &Fe::ONE;
        vs[i] = &yy.mul(&EDWARDS_D) + &Fe::ONE;
        ys[i] = y;
    }
    // SAFETY: `supported` returned true above.
    let (ok, xs) = unsafe { super::ifma::sqrt_ratio_i_x4(&us, &vs) };
    for i in 0..4 {
        if !ok[i] {
            return false;
        }
        let mut x = xs[i];
        if chunk[i][31] >> 7 == 1 {
            x = -&x;
        }
        out.push(Affine { x, y: ys[i] });
    }
    true
}

/// Decompress one encoded point, `None` if it is not a curve point. Accepts
/// exactly the encodings dalek's `decompress` accepts.
pub(crate) fn decompress(input: &[u8; 32]) -> Option<Affine> {
    let mut out = Vec::with_capacity(1);
    decompress_chunk(&[*input], &mut out).then(|| out[0])
}

/// Decompress a batch of encoded points, `None` if any encoding is not a
/// curve point. Accepts exactly the encodings dalek's `decompress` accepts.
pub(crate) fn decompress_batch(
    mut inputs: impl ExactSizeIterator<Item = [u8; 32]>,
) -> Option<Vec<Affine>> {
    let mut out = Vec::with_capacity(inputs.len());
    loop {
        let mut chunk = [[0u8; 32]; WIDTH];
        let mut filled = 0;
        for slot in &mut chunk {
            match inputs.next() {
                Some(bytes) => {
                    *slot = bytes;
                    filled += 1;
                }
                None => break,
            }
        }
        if filled == WIDTH {
            #[cfg(target_arch = "aarch64")]
            let ok = decompress_chunk_neon(&chunk, &mut out);
            #[cfg(target_arch = "x86_64")]
            let ok = decompress_chunk_ifma(&chunk, &mut out);
            #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
            let ok = decompress_chunk(&chunk, &mut out);
            if !ok {
                return None;
            }
        } else {
            for bytes in chunk.iter().take(filled) {
                if !decompress_chunk(&[*bytes], &mut out) {
                    return None;
                }
            }
            return Some(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::test_rng;
    use curve25519_dalek::{
        constants::EIGHT_TORSION, edwards::CompressedEdwardsY, EdwardsPoint, Scalar,
    };
    use rand::RngExt as _;

    /// Decompress `bytes` with dalek and with this module, asserting equal
    /// accept/reject behavior and, on accept, an equal point.
    fn assert_parity(bytes: [u8; 32]) {
        let theirs = CompressedEdwardsY(bytes).decompress();
        let mine = decompress_batch([bytes].into_iter());
        assert_eq!(theirs.is_some(), mine.is_some(), "{bytes:02x?}");
        if let (Some(p), Some(points)) = (theirs, mine) {
            assert_eq!(
                p.compress().0,
                points[0].to_extended().compress(),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn test_decompress_matches_dalek() {
        let mut rng = test_rng();
        // Valid points, both x signs.
        for i in 1u64..=512 {
            assert_parity(EdwardsPoint::mul_base(&Scalar::from(i)).compress().0);
        }
        // Mostly invalid encodings.
        for _ in 0..4096 {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            assert_parity(bytes);
        }
    }

    #[test]
    fn test_decompress_edge_encodings() {
        // y = 0 and y = 1 (the identity), with and without the sign bit.
        for byte0 in [0u8, 1] {
            for sign in [0u8, 0x80] {
                let mut b = [0u8; 32];
                b[0] = byte0;
                b[31] = sign;
                assert_parity(b);
            }
        }
        // Non-canonical encodings p + k (and all-ones), both signs.
        for k in 0u8..19 {
            for sign in [0u8, 0x80] {
                let mut b = [0xffu8; 32];
                b[0] = 0xed + k;
                b[31] = 0x7f | sign;
                assert_parity(b);
            }
        }
        // The eight torsion points.
        for p in EIGHT_TORSION {
            assert_parity(p.compress().0);
        }
    }

    #[test]
    fn test_decompress_batch_rejects_any_invalid() {
        // A batch with one off-curve encoding fails wholesale, regardless of
        // its lane position.
        let valid: Vec<[u8; 32]> = (1u64..=9)
            .map(|i| EdwardsPoint::mul_base(&Scalar::from(i)).compress().0)
            .collect();
        let mut invalid = [0u8; 32];
        invalid[0] = 3;
        invalid[5] = 0xaa;
        assert!(CompressedEdwardsY(invalid).decompress().is_none());
        for pos in 0..=valid.len() {
            let mut batch = valid.clone();
            batch.insert(pos, invalid);
            assert!(decompress_batch(batch.iter().copied()).is_none());
        }
        assert!(decompress_batch(valid.iter().copied()).is_some());
    }

    #[test]
    fn test_point_ops_match_dalek() {
        let mut rng = test_rng();
        let ours = |p: &EdwardsPoint| -> Extended {
            decompress_batch([p.compress().0].into_iter()).unwrap()[0].to_extended()
        };
        for i in 1u64..=32 {
            let a = EdwardsPoint::mul_base(&Scalar::from(i));
            let mut sb = [0u8; 32];
            rng.fill(&mut sb);
            let b = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(sb));
            let (oa, ob) = (ours(&a), ours(&b));
            // General and mixed addition.
            assert_eq!(oa.add(&ob).compress(), (a + b).compress().0);
            let cached = decompress_batch([b.compress().0].into_iter()).unwrap()[0].to_cached();
            assert_eq!(oa.add_cached(&cached).compress(), (a + b).compress().0);
            assert_eq!(
                oa.add_cached(&cached.neg()).compress(),
                (a - b).compress().0
            );
            // Identity edges of the unified formulas.
            assert_eq!(oa.add(&Extended::IDENTITY).compress(), a.compress().0);
            assert_eq!(oa.add(&oa).compress(), (a + a).compress().0);
            // Doubling chains.
            assert_eq!(oa.mul_by_pow_2(1).compress(), (a + a).compress().0);
            assert_eq!(
                oa.mul_by_pow_2(3).compress(),
                a.mul_by_cofactor().compress().0
            );
        }
        // Small-order points exercise the completeness of the formulas.
        for p in EIGHT_TORSION {
            for q in EIGHT_TORSION {
                let (op, oq) = (ours(&p), ours(&q));
                assert_eq!(op.add(&oq).compress(), (p + q).compress().0);
            }
        }
        assert_eq!(
            Extended::IDENTITY.compress(),
            EdwardsPoint::default().compress().0
        );
    }
}
