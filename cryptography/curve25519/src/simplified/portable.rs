//! Plain-Rust lane adapter over scalar field and group arithmetic.

use super::{F, FBackend, FVec, G, GAffine, GAffineVec, GBackend, GVec, LANES};

/// The portable backend token.
///
/// This is the correctness reference for accelerated backends. Each vector operation applies the
/// corresponding scalar operation independently to every lane. All operations are variable-time
/// because they operate only on public data.
///
/// Freely constructible: unlike the accelerated backends, the portable one needs no CPU feature,
/// so possession proves nothing and gates nothing.
#[derive(Clone, Copy)]
pub(super) struct Backend;

impl Backend {
    pub(super) const fn new() -> Self {
        Self
    }
}

#[inline]
fn f_lane(value: &FVec, lane: usize) -> F {
    F(value.limbs.map(|limb| limb[lane]))
}

#[inline]
fn set_f_lane(value: &mut FVec, lane: usize, scalar: F) {
    for (row, limb) in value.limbs.iter_mut().zip(scalar.0) {
        row[lane] = limb;
    }
}

/// Applies a scalar field operation independently to every lane.
fn map_f1(a: FVec, f: impl Fn(F) -> F) -> FVec {
    let mut out = F::ZERO.splat();
    for lane in 0..LANES {
        set_f_lane(&mut out, lane, f(f_lane(&a, lane)));
    }
    out
}

/// Applies a scalar field operation independently to every pair of lanes.
fn map_f2(a: FVec, b: FVec, f: impl Fn(F, F) -> F) -> FVec {
    let mut out = F::ZERO.splat();
    for lane in 0..LANES {
        set_f_lane(&mut out, lane, f(f_lane(&a, lane), f_lane(&b, lane)));
    }
    out
}

#[inline]
fn g_lane(value: &GVec, lane: usize) -> G {
    G {
        x: f_lane(&value.x, lane),
        y: f_lane(&value.y, lane),
        t: f_lane(&value.t, lane),
        z: f_lane(&value.z, lane),
    }
}

#[inline]
fn set_g_lane(value: &mut GVec, lane: usize, scalar: G) {
    set_f_lane(&mut value.x, lane, scalar.x);
    set_f_lane(&mut value.y, lane, scalar.y);
    set_f_lane(&mut value.t, lane, scalar.t);
    set_f_lane(&mut value.z, lane, scalar.z);
}

#[inline]
fn g_affine_lane(value: &GAffineVec, lane: usize) -> GAffine {
    GAffine {
        x: f_lane(&value.x, lane),
        y: f_lane(&value.y, lane),
        t2d: f_lane(&value.t2d, lane),
    }
}

/// Applies a scalar group operation independently to every lane.
fn map_g1(a: GVec, f: impl Fn(G) -> G) -> GVec {
    let mut out = GVec::identity();
    for lane in 0..LANES {
        set_g_lane(&mut out, lane, f(g_lane(&a, lane)));
    }
    out
}

/// Applies a scalar group operation independently to every pair of lanes.
fn map_g2(a: GVec, b: GVec, f: impl Fn(G, G) -> G) -> GVec {
    let mut out = GVec::identity();
    for lane in 0..LANES {
        set_g_lane(&mut out, lane, f(g_lane(&a, lane), g_lane(&b, lane)));
    }
    out
}

/// Applies scalar mixed addition independently to every pair of lanes.
fn map_g_mixed(a: GVec, b: GAffineVec) -> GVec {
    let mut out = GVec::identity();
    for lane in 0..LANES {
        set_g_lane(
            &mut out,
            lane,
            g_lane(&a, lane).add_mixed(g_affine_lane(&b, lane)),
        );
    }
    out
}

impl FBackend for Backend {
    fn add(self, a: FVec, b: FVec) -> FVec {
        map_f2(a, b, F::add)
    }

    fn neg(self, a: FVec) -> FVec {
        map_f1(a, F::neg)
    }

    fn sub(self, a: FVec, b: FVec) -> FVec {
        map_f2(a, b, F::sub)
    }

    fn mul(self, a: FVec, b: FVec) -> FVec {
        map_f2(a, b, F::mul)
    }

    fn square(self, a: FVec) -> FVec {
        map_f1(a, F::square)
    }
}

impl GBackend for Backend {
    fn g_add(self, p: GVec, q: GVec) -> GVec {
        map_g2(p, q, G::add)
    }

    fn g_add_mixed(self, p: GVec, q: GAffineVec) -> GVec {
        map_g_mixed(p, q)
    }

    fn g_double(self, p: GVec) -> GVec {
        map_g1(p, G::double)
    }
}

impl super::Backend for Backend {}
