//! Plain-Rust lane adapter over scalar field and group arithmetic.
use super::{F, FBackend, FVec, G, GAffineVec, GBackend, GVec};
use core::array;

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

/// Applies a scalar field operation independently to every lane.
fn map_f(a: FVec, f: impl Fn(F) -> F) -> FVec {
    FVec::transpose(a.untranspose().map(f))
}

/// Applies a scalar field operation independently to every pair of lanes.
fn map2_f(a: FVec, b: FVec, f: impl Fn(F, F) -> F) -> FVec {
    let a = a.untranspose();
    let b = b.untranspose();
    FVec::transpose(array::from_fn(|i| f(a[i], b[i])))
}

/// Applies a scalar group operation independently to every lane.
fn map_g(a: GVec, f: impl Fn(G) -> G) -> GVec {
    GVec::transpose(a.untranspose().map(f))
}

/// Applies a scalar group operation independently to every pair of lanes.
fn map2_g(a: GVec, b: GVec, f: impl Fn(G, G) -> G) -> GVec {
    let a = a.untranspose();
    let b = b.untranspose();
    GVec::transpose(array::from_fn(|i| f(a[i], b[i])))
}

impl FBackend for Backend {
    fn add(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, F::add)
    }

    fn neg(self, a: FVec) -> FVec {
        map_f(a, F::neg)
    }

    fn sub(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, F::sub)
    }

    fn mul(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, F::mul)
    }

    fn square(self, a: FVec) -> FVec {
        map_f(a, F::square)
    }
}

impl GBackend for Backend {
    fn g_add(self, p: GVec, q: GVec) -> GVec {
        map2_g(p, q, G::add)
    }

    fn g_add_mixed(self, p: GVec, q: GAffineVec) -> GVec {
        let a = p.untranspose();
        let b = q.untranspose();
        GVec::transpose(array::from_fn(|i| a[i].add_mixed(b[i])))
    }

    fn g_double(self, p: GVec) -> GVec {
        map_g(p, G::double)
    }
}

impl super::Backend for Backend {}
