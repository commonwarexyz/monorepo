//! Plain-Rust lane adapter over scalar field and group arithmetic.

use super::{F, FBackend, FVec, G, GAffine, GBackend, GVec, msm};
#[cfg(any(test, feature = "fuzz"))]
use super::{GAffineVec, LANES};
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

    #[cfg(any(test, feature = "fuzz"))]
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

#[cfg(any(test, feature = "fuzz"))]
impl GAffineVec {
    /// Untransposes backend lanes into scalar affine points.
    fn untranspose(self) -> [GAffine; LANES] {
        let x = self.x.untranspose();
        let y = self.y.untranspose();
        let t2d = self.t2d.untranspose();
        array::from_fn(|i| GAffine {
            x: x[i],
            y: y[i],
            t2d: t2d[i],
        })
    }
}

impl super::msm::Backend for Backend {
    // One stripe per physical mixed-addition lane. Scalar arithmetic has one, so the fold has no
    // stripes to merge.
    const STRIPES: usize = 1;

    fn fill_buckets<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (&GAffine, i16),
    ) {
        msm::fill_buckets::<1, T>(
            |[current], [mut incoming], [negative]| {
                // Subtracting a point adds its negation, which negates `x` and `t2d`.
                if negative {
                    incoming.x = incoming.x.neg();
                    incoming.t2d = incoming.t2d.neg();
                }
                [current.add_mixed(incoming)]
            },
            buckets,
            nb,
            terms,
            term,
        );
    }

    /// Scalar recombination computes each point once rather than once per emulated lane.
    fn combine_windows(
        self,
        partials: impl IntoIterator<Item = (usize, G)>,
        windows: usize,
        width: u32,
    ) -> G {
        msm::combine_windows(G::IDENTITY, G::add, G::double, partials, windows, width)
    }

    fn with_lanes<C: msm::WithLanes>(self, computation: C) -> C::Output {
        computation.call::<Self, 1>(self)
    }
}

impl msm::Lanes<1> for Backend {
    type Point = G;
    type Affine = GAffine;

    // A group is a single term, so every term whose digits are all zero skips its table.
    const SKIP_ZERO_GROUPS: bool = true;

    #[inline(always)]
    fn identity(self) -> G {
        G::IDENTITY
    }

    #[inline(always)]
    fn load(self, [point]: [&GAffine; 1]) -> GAffine {
        *point
    }

    #[inline(always)]
    fn load_extended(self, [point]: [&G; 1]) -> G {
        *point
    }

    #[inline(always)]
    fn add_mixed(self, point: G, affine: GAffine) -> G {
        point.add_mixed(affine)
    }

    #[inline(always)]
    fn add(self, a: G, b: G) -> G {
        a.add(b)
    }

    #[inline(always)]
    fn double(self, point: G) -> G {
        point.double()
    }

    #[inline(always)]
    fn add_signed(self, point: G, table: &[G], [digit]: [i16; 1]) -> G {
        let mut multiple = table[usize::from(digit.unsigned_abs())];
        if digit < 0 {
            multiple = multiple.negate();
        }
        point.add(multiple)
    }

    #[inline(always)]
    fn select(self, point: G, [keep]: [bool; 1]) -> G {
        if keep { point } else { G::IDENTITY }
    }

    #[inline(always)]
    fn sum(self, point: G) -> G {
        point
    }
}
