//! Portable field, point, and multi-scalar arithmetic.

#[cfg(not(target_arch = "aarch64"))]
use super::WithBackend;
use super::{
    F, FBackend, FVec, G, GAffine, GCompleted, GProjective, Niels, ProjectiveNiels, basepoint, msm,
};
use core::array;

/// The portable backend token.
///
/// This is the correctness reference for accelerated backends. Each vector operation applies the
/// corresponding scalar operation independently to every lane. Field vector and MSM operations
/// are variable-time because they operate only on public data. Single-point operations follow the
/// timing contract of [`super::Backend`].
///
/// Freely constructible: unlike the accelerated backends, the portable one needs no CPU feature,
/// so possession proves nothing and gates nothing.
#[derive(Clone, Copy)]
pub struct Backend;

impl Backend {
    pub const fn new() -> Self {
        Self
    }

    /// Runs a portable computation outside the runtime dispatcher's stack frame.
    #[cfg(not(target_arch = "aarch64"))]
    #[inline(never)]
    pub fn call<C: WithBackend>(self, computation: C) -> C::Output {
        computation.call(self)
    }
}

/// Adds a point in Niels form, deferring the final coordinate products.
#[inline(always)]
const fn add_niels(point: G, rhs: Niels) -> GCompleted {
    // The steps of `G::add` with `Z2 = 1`. The Niels form supplies `Y2 - X2`, `Y2 + X2`, and
    // `2d*T2`, so `C` takes one multiplication and `D = 2*Z1` takes none.
    let a = point.y.sub(point.x).mul(rhs.diff);
    let b = point.y.add(point.x).mul(rhs.sum);
    let c = point.t.mul(rhs.t2d);
    let d = point.z.add(point.z);
    GCompleted::from_products(a, b, c, d)
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

impl super::Backend for Backend {
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
    fn project(self, point: G) -> GProjective {
        point.to_projective()
    }

    #[inline(always)]
    fn double(self, point: GProjective) -> GCompleted {
        let a = point.x.square();
        let b = point.y.square();
        let c = point.z.square();
        GCompleted::from_squares(a, b, c.add(c), point.x.add(point.y).square())
    }

    #[inline(always)]
    fn to_projective(self, point: GCompleted) -> GProjective {
        GProjective {
            x: point.x.mul(point.t),
            y: point.z.mul(point.y),
            z: point.t.mul(point.z),
        }
    }

    #[inline(always)]
    fn to_extended(self, point: GCompleted) -> G {
        G {
            x: point.x.mul(point.t),
            y: point.z.mul(point.y),
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
        let rhs = if negate { cached.negate() } else { cached };

        // The steps of `G::add` up to its final products, with `2d*T2` precomputed.
        let a = point.y.sub(point.x).mul(rhs.diff);
        let b = point.y.add(point.x).mul(rhs.sum);
        let c = point.t.mul(rhs.t2d);
        let zz = point.z.mul(rhs.z);
        GCompleted::from_products(a, b, c, zz.add(zz))
    }

    #[inline(always)]
    fn add_niels(self, point: G, niels: &Niels, negate: bool) -> GCompleted {
        add_niels(point, if negate { niels.negate() } else { *niels })
    }

    #[inline(always)]
    fn add_selected(self, point: G, row: &[Niels; 8], digit: i8) -> GCompleted {
        add_niels(point, basepoint::select(row, digit))
    }
}

impl super::msm::Backend for Backend {
    // One stripe per physical mixed-addition lane. Scalar arithmetic has one, so the fold has no
    // stripes to merge.
    const STRIPES: usize = 1;
    const STRAUS_TERM_CUTOFF: usize = 88;
    const PARALLEL_STRAUS_TERM_CUTOFF: usize = 160;

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
                [msm::Lanes::add_mixed(self, current, incoming)]
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
    fn store(self, point: G) -> [G; 1] {
        [point]
    }

    #[inline(always)]
    fn add_mixed(self, point: G, affine: GAffine) -> G {
        super::Backend::to_extended(
            self,
            add_niels(
                point,
                Niels {
                    sum: affine.y.add(affine.x),
                    diff: affine.y.sub(affine.x),
                    t2d: affine.t2d,
                },
            ),
        )
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
        let [point] = self.store(point);
        point
    }
}
