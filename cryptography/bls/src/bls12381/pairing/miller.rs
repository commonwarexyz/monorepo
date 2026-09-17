// Adapted from VROOM/src/miller.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! Homogeneous Miller points, with affine coordinates (X/Z, Y/Z).

use crate::bls12381::extension::{
    bounded::{Fp2LeftStandard, Fp2Ring, Fp2Standard},
    fp12,
};
use commonware_cryptography_vroom::{
    Backend, Bls12381,
    rns::{Expanded, Ring, Standard, bounds::Range},
};

#[derive(Clone, Copy)]
pub(super) struct State<B: Backend> {
    pub(super) x: Fp2Standard,
    pub(super) y: Fp2Standard,
    pub(super) z: Fp2Standard,
    qx: Fp2LeftStandard<B>,
    qy: Fp2LeftStandard<B>,
    pub(super) px: Standard<Bls12381>,
    pub(super) py: Standard<Bls12381>,
    three_px: Expanded<Bls12381, Range<0, 2>, Range<0, 3>>,
    minus_two_py: Expanded<Bls12381, Range<0, 2>, Range<0, 2>>,
}

impl<B: Backend> State<B> {
    #[inline(always)]
    pub(super) fn new(
        px: Standard<Bls12381>,
        py: Standard<Bls12381>,
        qx: Fp2Standard,
        qy: Fp2Standard,
        ring: &Ring<Bls12381, B>,
    ) -> Self {
        let fp2 = Fp2Ring::new(ring);
        Self {
            x: qx,
            y: qy,
            z: crate::bls12381::extension::Fp2::ONE.into(),
            qx: fp2.prep_left_standard(qx),
            qy: fp2.prep_left_standard(qy),
            px,
            py,
            three_px: ring.prep_standard(px.scale::<3>()).recast_rns(),
            minus_two_py: ring
                .prep_standard(ring.standard_negate(py).scale::<2>())
                .recast_rns(),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(super) fn double(&mut self, f: &mut fp12::Fp12<1>, ring: &Ring<Bls12381, B>) {
        let fp2 = Fp2Ring::new(ring);
        let px = fp2.prep_left(self.x);
        let py = fp2.prep_left(self.y);
        let pz = fp2.prep_left(self.z);
        let [xx, yy, zz, xy, yz] = fp2.batch_reduce_expand(&[
            fp2.ready::<800>(px.square()),
            fp2.ready::<800>(py.square()),
            fp2.ready::<800>(pz.square()),
            fp2.ready::<800>(px * py.to_fp2()),
            fp2.ready::<800>(py * pz.to_fp2()),
        ]);

        let eight_yy = fp2.prep_left(yy.scale::<8>());
        let b3_zz = fp2.prep(fp2.mul_3b(zz));
        let line_c = fp2.prep(b3_zz - yy);
        let yy_plus_b3_zz = fp2.prep(yy + b3_zz);
        let yy_minus_b9_zz = fp2.prep_left(yy - b3_zz.scale::<3>());
        let two_xy = fp2.prep(xy.scale::<2>());

        let y3 = (yy_minus_b9_zz * yy_plus_b3_zz).mul_accumulate(eight_yy, b3_zz);
        let [line_x, line_y, x3, y3, z3] = fp2.batch_reduce_expand(&[
            fp2.ready::<800>(fp2.mul_by_fp(xx, self.three_px)),
            fp2.ready::<800>(fp2.mul_by_fp(yz, self.minus_two_py)),
            fp2.ready::<800>(yy_minus_b9_zz * two_xy),
            fp2.ready::<800>(y3),
            fp2.ready::<800>(eight_yy * yz),
        ]);
        *f = fp12::mul_by_014(f, line_c, line_x, line_y, ring);
        self.x = x3;
        self.y = y3;
        self.z = z3;
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(super) fn add(&mut self, f: &mut fp12::Fp12<1>, ring: &Ring<Bls12381, B>) {
        let fp2 = Fp2Ring::new(ring);
        let [x2x1, x2y1, x2z1, y2x1, y2y1, y2z1] = fp2.batch_reduce_expand(&[
            fp2.ready::<800>(self.qx * self.x),
            fp2.ready::<800>(self.qx * self.y),
            fp2.ready::<800>(self.qx * self.z),
            fp2.ready::<800>(self.qy * self.x),
            fp2.ready::<800>(self.qy * self.y),
            fp2.ready::<800>(self.qy * self.z),
        ]);

        let line_c = fp2.prep(x2y1 - y2x1);
        let xq_coefficient = fp2.prep(y2z1 - self.y);
        let yq_coefficient = fp2.prep(self.x - x2z1);
        let x2y1_plus_y2x1 = fp2.prep_left(x2y1 + y2x1);
        let y2z1_plus_y1 = fp2.prep(y2z1 + self.y);
        let three_x2x1 = fp2.prep(x2x1.scale::<3>());
        let b3z1 = fp2.prep(fp2.mul_3b(self.z));
        let y2y1_plus_b3z1 = fp2.prep_left(y2y1 + b3z1);
        let y2y1_minus_b3z1 = fp2.prep(y2y1 - b3z1);
        let b3_x2z1_plus_x1 = fp2.prep_left(fp2.mul_3b(x2z1 + self.x));

        let x3 = (x2y1_plus_y2x1 * y2y1_minus_b3z1)
            .mul_accumulate(fp2.negate_left(b3_x2z1_plus_x1), y2z1_plus_y1);
        let y3 = (b3_x2z1_plus_x1 * three_x2x1).mul_accumulate(y2y1_plus_b3z1, y2y1_minus_b3z1);
        let z3 = (y2y1_plus_b3z1 * y2z1_plus_y1).mul_accumulate(x2y1_plus_y2x1, three_x2x1);
        let [x3, y3, z3, line_x, line_y] = fp2.batch_reduce_expand(&[
            fp2.ready::<800>(x3),
            fp2.ready::<800>(y3),
            fp2.ready::<800>(z3),
            fp2.ready::<800>(fp2.mul_by_fp(xq_coefficient, self.px)),
            fp2.ready::<800>(fp2.mul_by_fp(yq_coefficient, self.py)),
        ]);
        *f = fp12::mul_by_014(f, line_c, line_x, line_y, ring);
        self.x = x3;
        self.y = y3;
        self.z = z3;
    }
}

#[inline(always)]
pub(super) fn miller_loop<B: Backend>(
    states: &mut [State<B>],
    ring: &Ring<Bls12381, B>,
) -> fp12::Fp12<1> {
    let mut result = fp12::one();
    for state in states.iter_mut() {
        state.double(&mut result, ring);
    }
    for squarings in [2, 3, 9, 32, 16] {
        for state in states.iter_mut() {
            state.add(&mut result, ring);
        }
        for _ in 0..squarings {
            result = fp12::square(&result, ring);
            for state in states.iter_mut() {
                state.double(&mut result, ring);
            }
        }
    }
    fp12::conjugate(&result, ring)
}
