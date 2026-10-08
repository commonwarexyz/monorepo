//! Property suites shared by field and group backends.

use super::{
    Backend, F, FBackend, FVec, G, GAffine, GCompleted, GProjective, LANES, MASK_51, Niels,
    WithBackend,
    msm::{self, WithLanes},
};
#[cfg(test)]
use crate::test::ZIP215_POINTS;
use arbitrary::{Arbitrary, Unstructured};
use core::array;

pub(super) const MASK_52: u64 = (1 << 52) - 1;

/// A field or group arithmetic fuzzing operation.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Check field arithmetic identities.
    Field,
    /// Check group arithmetic identities.
    Group,
    /// Check single-point operations against the portable backend.
    Point,
}

impl Plan {
    /// Runs the operation with the best backend supported by this CPU.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        struct Run<'a, 'b> {
            plan: Plan,
            u: &'a mut Unstructured<'b>,
        }

        impl WithBackend for Run<'_, '_> {
            type Output = arbitrary::Result<()>;

            fn call<B: Backend>(self, backend: B) -> Self::Output {
                match self.plan {
                    Plan::Field => {
                        fuzz_field(self.u, backend)?;
                        fuzz_field_matches_portable(self.u, backend)
                    }
                    Plan::Group => {
                        fuzz_group(self.u, backend)?;
                        fuzz_group_matches_portable(self.u, backend)
                    }
                    Plan::Point => fuzz_point_matches_portable(self.u, backend),
                }
            }
        }

        super::with_backend(Run { plan: self, u })
    }
}

fn arbitrary_fvec(u: &mut Unstructured<'_>) -> arbitrary::Result<FVec> {
    let limbs: [[u64; LANES]; 5] = u.arbitrary()?;
    Ok(FVec {
        limbs: limbs.map(|row| row.map(|limb| limb & MASK_52)),
    })
}

const fn canonical(mut limbs: [u64; 5]) -> [u64; 5] {
    limbs[1] += limbs[0] >> 51;
    limbs[0] &= MASK_51;
    limbs[2] += limbs[1] >> 51;
    limbs[1] &= MASK_51;
    limbs[3] += limbs[2] >> 51;
    limbs[2] &= MASK_51;
    limbs[4] += limbs[3] >> 51;
    limbs[3] &= MASK_51;
    limbs[0] += 19 * (limbs[4] >> 51);
    limbs[4] &= MASK_51;
    limbs[1] += limbs[0] >> 51;
    limbs[0] &= MASK_51;

    // Adding 19 overflows bit 255 exactly when the carried value is at least p.
    let mut reduce = (limbs[0] + 19) >> 51;
    reduce = (limbs[1] + reduce) >> 51;
    reduce = (limbs[2] + reduce) >> 51;
    reduce = (limbs[3] + reduce) >> 51;
    reduce = (limbs[4] + reduce) >> 51;

    limbs[0] += 19 * reduce;
    limbs[1] += limbs[0] >> 51;
    limbs[0] &= MASK_51;
    limbs[2] += limbs[1] >> 51;
    limbs[1] &= MASK_51;
    limbs[3] += limbs[2] >> 51;
    limbs[2] &= MASK_51;
    limbs[4] += limbs[3] >> 51;
    limbs[3] &= MASK_51;
    limbs[4] &= MASK_51;
    limbs
}

fn assert_bounded(value: FVec) {
    assert!(
        value.limbs.into_iter().flatten().all(|limb| limb < 1 << 52),
        "backend produced a limb outside the FVec invariant"
    );
}

pub(super) fn assert_f_eq(actual: FVec, expected: FVec, property: &str) {
    assert_bounded(actual);
    assert_bounded(expected);
    for lane in 0..LANES {
        let actual = canonical(actual.limbs.map(|limbs| limbs[lane]));
        let expected = canonical(expected.limbs.map(|limbs| limbs[lane]));
        assert_eq!(actual, expected, "{property}, lane {lane}");
    }
}

/// Asserts that every coordinate of a point is within the field bound and that its Z is nonzero.
fn assert_point_bounded(point: G, property: &str) {
    for coordinate in [point.x, point.y, point.t, point.z] {
        assert!(
            coordinate.0.iter().all(|&limb| limb < 1 << 52),
            "{property}: a limb is outside the field bound"
        );
    }
    assert_ne!(
        canonical(point.z.0),
        [0; 5],
        "{property}: projective Z coordinate"
    );
}

/// Asserts that two extended points are the same group element.
fn assert_g_eq(actual: G, expected: G, property: &str) {
    assert_point_bounded(actual, property);
    assert_point_bounded(expected, property);
    for (actual_coordinate, expected_coordinate) in [
        (actual.x, expected.x),
        (actual.y, expected.y),
        (actual.t, expected.t),
    ] {
        assert_eq!(
            canonical(actual_coordinate.mul(expected.z).0),
            canonical(expected_coordinate.mul(actual.z).0),
            "{property}"
        );
    }
}

/// Asserts that an extended point satisfies the curve equation and `X*Y = T*Z`.
fn assert_on_curve(point: G) {
    assert_point_bounded(point, "curve point");
    let lhs = point.y.square().sub(point.x.square());
    let rhs = point.z.square().add(F::EDWARDS_D.mul(point.t.square()));
    assert_eq!(canonical(lhs.0), canonical(rhs.0), "curve equation");
    assert_eq!(
        canonical(point.x.mul(point.y).0),
        canonical(point.t.mul(point.z).0),
        "extended-coordinate invariant"
    );
}

/// Multiplies every lane by `scalar` with double-and-add.
fn scale<L: msm::Lanes<N>, const N: usize>(lanes: L, point: L::Point, mut scalar: u32) -> L::Point {
    let mut result = lanes.identity();
    let mut multiple = point;
    while scalar != 0 {
        if scalar & 1 == 1 {
            result = lanes.add(result, multiple);
        }
        multiple = lanes.double(multiple);
        scalar >>= 1;
    }
    result
}

fn fuzz_field<B: Backend>(u: &mut Unstructured<'_>, backend: B) -> arbitrary::Result<()> {
    let a = arbitrary_fvec(u)?;
    let b = arbitrary_fvec(u)?;
    let c = arbitrary_fvec(u)?;
    let zero = FVec::splat(F::ZERO);
    let one = FVec::splat(F::ONE);

    assert_f_eq(backend.add(a, zero), a, "additive identity");
    assert_f_eq(backend.add(a, backend.neg(a)), zero, "additive inverse");
    assert_f_eq(backend.add(a, b), backend.add(b, a), "addition commutes");
    assert_f_eq(
        backend.add(backend.add(a, b), c),
        backend.add(a, backend.add(b, c)),
        "addition associates",
    );
    assert_f_eq(
        backend.sub(a, b),
        backend.add(a, backend.neg(b)),
        "subtraction equals addition of the inverse",
    );
    assert_f_eq(backend.mul(a, one), a, "multiplicative identity");
    assert_f_eq(backend.mul(a, zero), zero, "multiplication by zero");
    assert_f_eq(
        backend.mul(a, b),
        backend.mul(b, a),
        "multiplication commutes",
    );
    assert_f_eq(
        backend.mul(backend.mul(a, b), c),
        backend.mul(a, backend.mul(b, c)),
        "multiplication associates",
    );
    assert_f_eq(
        backend.mul(backend.add(a, b), c),
        backend.add(backend.mul(a, c), backend.mul(b, c)),
        "multiplication distributes",
    );
    assert_f_eq(
        backend.square(a),
        backend.mul(a, a),
        "square equals self product",
    );
    Ok(())
}

fn fuzz_group<B: Backend>(u: &mut Unstructured<'_>, backend: B) -> arbitrary::Result<()> {
    let scalars = [
        u.arbitrary::<u16>()?,
        u.arbitrary::<u16>()?,
        u.arbitrary::<u16>()?,
    ]
    .map(u32::from);
    backend.with_lanes(GroupLaws { scalars });
    Ok(())
}

/// Group laws on a backend's native lanes, with every lane holding the same multiples of the
/// basepoint.
struct GroupLaws {
    scalars: [u32; 3],
}

impl WithLanes for GroupLaws {
    type Output = ();

    fn call<L: msm::Lanes<N>, const N: usize>(self, lanes: L) {
        let basepoint = GAffine::BASEPOINT.to_extended();
        let base = lanes.load_extended([&basepoint; N]);
        let [p, q, r] = self.scalars.map(|scalar| scale(lanes, base, scalar));
        for point in [base, p, q, r] {
            lanes.store(point).into_iter().for_each(assert_on_curve);
        }

        // Every lane of `actual` must be the same group element as that lane of `expected`.
        let assert_lanes_eq = |actual: L::Point, expected: L::Point, property: &str| {
            for (actual, expected) in lanes.store(actual).into_iter().zip(lanes.store(expected)) {
                assert_g_eq(actual, expected, property);
            }
        };
        let identity = lanes.identity();
        let negated = lanes.store(p).map(G::negate);
        let negated = lanes.load_extended(negated.each_ref());
        assert_lanes_eq(lanes.add(p, identity), p, "right identity");
        assert_lanes_eq(lanes.add(identity, p), p, "left identity");
        assert_lanes_eq(lanes.add(p, negated), identity, "additive inverse");
        assert_lanes_eq(lanes.add(p, q), lanes.add(q, p), "addition commutes");
        assert_lanes_eq(
            lanes.add(lanes.add(p, q), r),
            lanes.add(p, lanes.add(q, r)),
            "addition associates",
        );
        assert_lanes_eq(lanes.double(p), lanes.add(p, p), "doubling");
        assert_lanes_eq(
            lanes.add(p, q),
            scale(lanes, base, self.scalars[0] + self.scalars[1]),
            "scalar addition",
        );
        let affine = lanes.load([&GAffine::BASEPOINT; N]);
        assert_lanes_eq(
            lanes.add_mixed(p, affine),
            lanes.add(p, base),
            "mixed addition",
        );
    }
}

#[cfg(test)]
#[test]
fn repeated_squaring_matches_scalar() {
    #[derive(Clone, Copy)]
    struct Check;

    impl WithBackend for Check {
        type Output = ();

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let max = FVec {
                limbs: [[MASK_52; LANES]; 5],
            };
            let mixed = FVec::transpose([
                F::ZERO,
                F::ONE,
                F([MASK_52; 5]),
                F([MASK_51; 5]),
                F([19, 0, 0, 0, 0]),
                F([0, MASK_52, 0, MASK_52, 0]),
                F([1 << 51; 5]),
                F([0x123456789abcd, 7, MASK_52 - 1, 42, 1]),
            ]);
            for input in [max, mixed] {
                for k in [0, 1, 2, 5, 10, 20, 50, 100] {
                    let actual = backend.pow2k(input, k);
                    if k == 0 {
                        assert_eq!(actual.limbs, input.limbs);
                    }
                    let expected = FVec::transpose(input.untranspose().map(|v| v.pow2k(k)));
                    assert_f_eq(actual, expected, "repeated squaring");
                }
            }
        }
    }

    Check.call(super::portable::Backend::new());
    super::with_backend(Check);
}

#[cfg(test)]
#[test]
fn backend_at_bounds() {
    /// Asserts that a coordinate is within the field bound and equals `expected` as a field
    /// element.
    fn assert_coordinate_eq(actual: F, expected: F, property: &str) {
        assert!(
            actual
                .0
                .iter()
                .chain(&expected.0)
                .all(|&limb| limb < 1 << 52),
            "{property}: a limb is outside the field bound"
        );
        assert_eq!(canonical(actual.0), canonical(expected.0), "{property}");
    }

    struct CheckBackendAtBounds;

    impl WithBackend for CheckBackendAtBounds {
        type Output = ();

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let reference = super::portable::Backend::new();
            let max = FVec {
                limbs: [[MASK_52; LANES]; 5],
            };
            let zero = FVec::splat(F::ZERO);
            assert_f_eq(
                reference.add(max, max),
                backend.add(max, max),
                "backend addition at bound",
            );
            assert_f_eq(
                reference.sub(zero, max),
                backend.sub(zero, max),
                "backend subtraction at bound",
            );
            assert_f_eq(
                reference.neg(max),
                backend.neg(max),
                "backend negation at bound",
            );
            assert_f_eq(
                reference.mul(max, max),
                backend.mul(max, max),
                "backend multiplication at bound",
            );
            assert_f_eq(
                reference.square(max),
                backend.square(max),
                "backend square at bound",
            );

            // These coordinates need not form a curve point: compare the complete formulas
            // coordinate-wise to exercise their loose-intermediate bounds.
            backend.with_lanes(FormulasAtBound);
        }
    }

    /// Each lane formula on coordinates at the field bound matches the scalar formula exactly.
    struct FormulasAtBound;

    impl WithLanes for FormulasAtBound {
        type Output = ();

        fn call<L: msm::Lanes<N>, const N: usize>(self, lanes: L) {
            // Maximal loose coordinates exercise formula bounds without requiring a curve point.
            let max = F([MASK_52; 5]);
            let point = G {
                x: max,
                y: max,
                t: max,
                z: max,
            };
            let affine = GAffine {
                x: max,
                y: max,
                t2d: max,
            };
            let loaded = lanes.load_extended([&point; N]);
            let mixed = lanes.load([&affine; N]);

            // Compare every output coordinate with the scalar formula and its field bound.
            for (actual, expected) in [
                (lanes.add(loaded, loaded), point.add(point)),
                (
                    lanes.add_mixed(loaded, mixed),
                    msm::Lanes::add_mixed(super::portable::Backend::new(), point, affine),
                ),
                (lanes.double(loaded), point.double()),
            ] {
                for actual in lanes.store(actual) {
                    for (actual, expected) in [
                        (actual.x, expected.x),
                        (actual.y, expected.y),
                        (actual.t, expected.t),
                        (actual.z, expected.z),
                    ] {
                        assert_coordinate_eq(actual, expected, "group formula at bound");
                    }
                }
            }
        }
    }

    super::with_backend(CheckBackendAtBounds);
}

#[cfg(test)]
#[test]
fn minifuzz_field() {
    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| Plan::Field.run(u));
}

#[cfg(test)]
#[test]
fn minifuzz_group() {
    // Fully inlined group formulas can exceed the test harness's default stack in debug builds.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(100)
                .test(|u| Plan::Group.run(u));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Checks that a backend's field operations match the portable backend.
fn fuzz_field_matches_portable<B: Backend>(
    u: &mut Unstructured<'_>,
    backend: B,
) -> arbitrary::Result<()> {
    let reference = super::portable::Backend::new();
    let a = arbitrary_fvec(u)?;
    let b = arbitrary_fvec(u)?;
    assert_f_eq(reference.add(a, b), backend.add(a, b), "backend addition");
    assert_f_eq(
        reference.sub(a, b),
        backend.sub(a, b),
        "backend subtraction",
    );
    assert_f_eq(reference.neg(a), backend.neg(a), "backend negation");
    assert_f_eq(
        reference.mul(a, b),
        backend.mul(a, b),
        "backend multiplication",
    );
    assert_f_eq(reference.square(a), backend.square(a), "backend square");

    Ok(())
}

/// Checks that a backend's group operations match the portable backend.
fn fuzz_group_matches_portable<B: Backend>(
    u: &mut Unstructured<'_>,
    backend: B,
) -> arbitrary::Result<()> {
    let encodings: [[u8; 32]; LANES] = u.arbitrary()?;
    let decoded = GAffine::decompress_batch(backend, &encodings);
    let affine = array::from_fn(|i| {
        let scalar = GAffine::decompress(&encodings[i]);
        assert_eq!(
            decoded[i].map(|point| (point.to_extended().compress(), point.t2d.to_bytes())),
            scalar.map(|point| (point.to_extended().compress(), point.t2d.to_bytes())),
            "decompression lane {i}",
        );
        scalar.unwrap_or(GAffine::IDENTITY)
    });

    // Scale each projective input by an arbitrary nonzero factor, so the formulas see
    // coordinates other than the normalized ones.
    let scales = arbitrary_fvec(u)?
        .untranspose()
        .map(|scale| if scale.is_zero() { F::ONE } else { scale });
    let points = array::from_fn(|i| {
        let point = affine[(i + 1) % LANES].to_extended();
        G {
            x: point.x.mul(scales[i]),
            y: point.y.mul(scales[i]),
            t: point.t.mul(scales[i]),
            z: point.z.mul(scales[i]),
        }
    });
    backend.with_lanes(MatchesScalar { points, affine });
    Ok(())
}

/// Each lane's doubling of `points` matches scalar doubling, and its additions of `affine` in
/// extended and mixed form both match scalar full addition, so `affine` must hold curve points.
/// The inputs pass through the backend's native lanes `N` at a time.
struct MatchesScalar {
    points: [G; LANES],
    affine: [GAffine; LANES],
}

impl WithLanes for MatchesScalar {
    type Output = ();

    fn call<L: msm::Lanes<N>, const N: usize>(self, lanes: L) {
        const { assert!(LANES.is_multiple_of(N)) };

        // Each native group loads its points and the matching `affine` points, the latter in both
        // extended and affine form.
        let extended = self.affine.map(GAffine::to_extended);
        for start in (0..LANES).step_by(N) {
            let point = lanes.load_extended(array::from_fn(|lane| &self.points[start + lane]));
            let rhs = lanes.load_extended(array::from_fn(|lane| &extended[start + lane]));
            let affine = lanes.load(array::from_fn(|lane| &self.affine[start + lane]));
            let doubled = lanes.store(lanes.double(point));
            let added = lanes.store(lanes.add(point, rhs));
            let mixed = lanes.store(lanes.add_mixed(point, affine));

            // Scalar doubling and full addition are the per-lane oracles, and both lane additions
            // must match the full scalar sum.
            for lane in 0..N {
                let point = self.points[start + lane];
                let sum = point.add(extended[start + lane]);
                assert_g_eq(doubled[lane], point.double(), "backend doubling");
                assert_g_eq(added[lane], sum, "backend addition");
                assert_g_eq(mixed[lane], sum, "backend mixed addition");
            }
        }
    }
}

#[cfg(test)]
#[test]
fn noncanonical_field_encodings() {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    for offset in 0..19 {
        let mut canonical = [0; 32];
        canonical[0] = offset;
        for sign in [0, 0x80] {
            let mut encoded = p;
            encoded[0] += offset;
            encoded[31] |= sign;
            assert_eq!(F::from_bytes(&encoded).to_bytes(), canonical);
        }
    }
    let mut p_minus_one = p;
    p_minus_one[0] -= 1;
    assert_eq!(F::from_bytes(&p_minus_one).to_bytes(), p_minus_one);
    assert_eq!(F::ZERO.sub(F::ONE).to_bytes(), p_minus_one);
}

#[cfg(test)]
#[test]
fn zip215_decompression_and_group_laws() {
    struct Check;

    impl WithBackend for Check {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            let mut encodings = ZIP215_POINTS.to_vec();
            for offset in 0..19 {
                for sign in [0, 0x80] {
                    let mut encoding = [0xff; 32];
                    encoding[0] = 0xed + offset;
                    encoding[31] = 0x7f | sign;
                    encodings.push(encoding);
                }
            }
            for chunk in encodings.chunks(LANES) {
                let bytes = array::from_fn(|i| chunk[i % chunk.len()]);
                let decoded = GAffine::decompress_batch(backend, &bytes);
                let lanes = array::from_fn(|i| {
                    let scalar = GAffine::decompress(&bytes[i]);
                    assert_eq!(
                        decoded[i].map(|p| (p.to_extended().compress(), p.t2d.to_bytes())),
                        scalar.map(|p| (p.to_extended().compress(), p.t2d.to_bytes()))
                    );
                    scalar.unwrap_or(GAffine::IDENTITY)
                });

                // Each point's successor doubles, adds the point, and adds it in mixed form.
                backend.with_lanes(MatchesScalar {
                    points: array::from_fn(|i| lanes[(i + 1) % LANES].to_extended()),
                    affine: lanes,
                });
            }
        }
    }

    Check.call(super::portable::Backend::new());
    super::with_backend(Check);
}

/// Checks the completed, projective, and Niels forms against the extended formulas, for sums of
/// equal and opposite points and of points with low-order components.
#[cfg(test)]
#[test]
fn completed_point_operations_match_extended() {
    use super::Niels;

    fn check(p: G, q: G) {
        let niels = |point: G| {
            let affine = point.to_affine();
            Niels {
                sum: affine.y.add(affine.x),
                diff: affine.y.sub(affine.x),
                t2d: affine.t2d,
            }
        };
        let assert_matches = |actual: G, expected: G, property: &str| {
            assert_on_curve(actual);
            assert_g_eq(actual, expected, property);
        };

        let portable = super::portable::Backend::new();
        let doubled = portable.double(portable.project(p));
        assert_matches(
            portable.to_extended(doubled),
            p.double(),
            "double to extended",
        );
        assert_matches(
            portable.to_projective(doubled).to_extended(),
            p.double(),
            "double to projective",
        );
        let mut cofactored = portable.project(p);
        for _ in 0..3 {
            cofactored = portable.to_projective(portable.double(cofactored));
        }
        assert_matches(cofactored.to_extended(), p.mul_by_cofactor(), "cofactor");
        assert_eq!(cofactored.is_identity(), p.mul_by_cofactor().is_identity());

        let sum = p.add(q);
        let difference = p.add(q.negate());
        for (actual, expected, property) in [
            (portable.add_cached(p, portable.cache(q), false), sum, "sum"),
            (
                portable.add_cached(p, portable.cache(q), true),
                difference,
                "difference",
            ),
            (portable.add_niels(p, &niels(q), false), sum, "Niels sum"),
            (
                portable.add_niels(p, &niels(q), true),
                difference,
                "Niels difference",
            ),
        ] {
            assert_matches(portable.to_extended(actual), expected, property);
            assert_matches(
                portable.to_projective(actual).to_extended(),
                expected,
                property,
            );
        }
    }

    // The identity, every ZIP215 point (including each low-order point), and the basepoint with
    // a low-order component, so that `Z` is not one.
    let base = GAffine::BASEPOINT.to_extended();
    let mut points = vec![G::IDENTITY, base.add(base)];
    for encoding in &ZIP215_POINTS {
        let point = GAffine::decompress(encoding).unwrap().to_extended();
        points.extend([point, base.add(point)]);
    }
    for &p in &points {
        for &q in &points {
            check(p, q);
        }
        check(p, p.negate());
    }

    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(64)
        .test(|u| {
            let mut point = || -> arbitrary::Result<G> {
                let encoding: [u8; 32] = u.arbitrary()?;
                let point = GAffine::decompress(&encoding).unwrap_or(GAffine::BASEPOINT);
                let torsion = GAffine::decompress(u.choose(&ZIP215_POINTS)?).unwrap();
                Ok(point.to_extended().add(torsion.to_extended()))
            };
            let p = point()?;
            let q = point()?;
            check(p, q);
            check(p, p);
            check(p, p.negate());
            Ok(())
        });
}

/// Re-represents a field element with large limbs, all below `2^52`: its canonical limbs plus `p`
/// limb-wise when `choice` is odd, and otherwise with `2^51` moved down from each limb whose
/// bit of `choice` is set.
fn spread_limbs(value: F, choice: u8) -> F {
    let mut limbs = canonical(value.0);
    if choice & 1 == 1 {
        let p = [MASK_51 - 18, MASK_51, MASK_51, MASK_51, MASK_51];
        for (limb, p) in limbs.iter_mut().zip(p) {
            *limb += p;
        }
    } else {
        for i in 0..4 {
            if (choice >> (i + 1)) & 1 == 1 && limbs[i + 1] > 0 {
                limbs[i] += 1 << 51;
                limbs[i + 1] -= 1;
            }
        }
    }
    F(limbs)
}

/// Scales every coordinate by `scale`, which keeps the point, and spreads the limbs.
fn rescale(point: G, scale: F, choice: u8) -> G {
    G {
        x: spread_limbs(point.x.mul(scale), choice),
        y: spread_limbs(point.y.mul(scale), choice.rotate_left(1)),
        t: spread_limbs(point.t.mul(scale), choice.rotate_left(2)),
        z: spread_limbs(point.z.mul(scale), choice.rotate_left(3)),
    }
}

/// Asserts that two extended points have the same coordinates modulo `p`, and that `actual` is
/// within the field bound. The coordinates need not form a curve point.
fn assert_g_same(actual: G, expected: G, property: &str) {
    for (actual, expected, coordinate) in [
        (actual.x, expected.x, "X"),
        (actual.y, expected.y, "Y"),
        (actual.z, expected.z, "Z"),
        (actual.t, expected.t, "T"),
    ] {
        assert!(
            actual.0.iter().all(|&limb| limb < 1 << 52),
            "{property}: a limb is outside the field bound"
        );
        assert_eq!(
            canonical(actual.0),
            canonical(expected.0),
            "{property}: {coordinate}"
        );
    }
}

/// Asserts that two projective points have the same coordinates modulo `p`.
fn assert_projective_same(actual: GProjective, expected: GProjective, property: &str) {
    for (actual, expected, coordinate) in [
        (actual.x, expected.x, "X"),
        (actual.y, expected.y, "Y"),
        (actual.z, expected.z, "Z"),
    ] {
        assert!(
            actual.0.iter().all(|&limb| limb < 1 << 52),
            "{property}: a limb is outside the field bound"
        );
        assert_eq!(
            canonical(actual.0),
            canonical(expected.0),
            "{property}: {coordinate}"
        );
    }
}

/// Returns the affine [`Niels`] form of a point.
const fn niels(point: G) -> Niels {
    let affine = point.to_affine();
    Niels {
        sum: affine.y.add(affine.x),
        diff: affine.y.sub(affine.x),
        t2d: affine.t2d,
    }
}

/// A field element with arbitrary limbs below `2^52`.
fn arbitrary_f(u: &mut Unstructured<'_>) -> arbitrary::Result<F> {
    let limbs: [u64; 5] = u.arbitrary()?;
    Ok(F(limbs.map(|limb| limb & MASK_52)))
}

/// The most operations a fuzzed chain of single-point operations takes.
const MAX_STEPS: usize = 16;

/// Checks a backend's single-point operations, alone and in a chain, against the portable backend on
/// arbitrary points with low-order components, rescaled projective coordinates, and spread limbs,
/// and on points, affine operands, and table rows with arbitrary limbs below `2^52`, which the
/// contract admits whether or not they are on the curve.
fn fuzz_point_matches_portable<B: Backend>(
    u: &mut Unstructured<'_>,
    backend: B,
) -> arbitrary::Result<()> {
    let encodings: [[u8; 32]; 2] = u.arbitrary()?;
    let order_four = GAffine::decompress(&[0; 32]).unwrap().to_extended();
    let point = |u: &mut Unstructured<'_>| -> arbitrary::Result<G> {
        let encoding: [u8; 32] = u.arbitrary()?;
        let point = GAffine::decompress(&encoding)
            .unwrap_or(GAffine::BASEPOINT)
            .to_extended();
        let torsion = (0..u.int_in_range(0..=3)?).fold(G::IDENTITY, |sum, _| sum.add(order_four));
        let mut scale = F::from_bytes(&u.arbitrary()?);
        if scale.is_zero() {
            scale = F::ONE;
        }
        Ok(rescale(point.add(torsion), scale, u.arbitrary()?))
    };

    // Points and affine operands with arbitrary limbs, almost never on the curve.
    let coordinates = |u: &mut Unstructured<'_>| -> arbitrary::Result<G> {
        Ok(G {
            x: arbitrary_f(u)?,
            y: arbitrary_f(u)?,
            t: arbitrary_f(u)?,
            z: arbitrary_f(u)?,
        })
    };
    let affine = |u: &mut Unstructured<'_>| -> arbitrary::Result<Niels> {
        Ok(Niels {
            sum: arbitrary_f(u)?,
            diff: arbitrary_f(u)?,
            t2d: arbitrary_f(u)?,
        })
    };
    let p = if u.arbitrary()? {
        coordinates(u)?
    } else {
        point(u)?
    };
    let q = match u.int_in_range(0..=4)? {
        0 => point(u)?,
        1 => coordinates(u)?,
        2 => p,
        3 => p.negate(),
        _ => G::IDENTITY,
    };
    let niels = if u.arbitrary()? { affine(u)? } else { niels(q) };
    let row = if u.arbitrary()? {
        let mut row = [Niels::IDENTITY; 8];
        for entry in &mut row {
            *entry = affine(u)?;
        }
        row
    } else {
        super::basepoint::TABLE[u.int_in_range(0..=31)?]
    };
    let odd = u.int_in_range(0..=127)?;
    let mut chain = Vec::new();
    for _ in 0..u.int_in_range(0..=MAX_STEPS)? {
        chain.push(u.arbitrary()?);
    }
    PointMatches {
        p,
        q,
        niels,
        row,
        odd,
        chain,
        encodings,
    }
    .call(backend);
    Ok(())
}

/// A decompressed point's encoding and `2d*x*y`, for comparing decompression results.
fn key(point: Option<GAffine>) -> Option<([u8; 32], [u8; 32])> {
    point.map(|point| (point.compress(), point.t2d.to_bytes()))
}

/// Asserts that [`Backend::decompress_pair`] returns both scalar decompressions, or `None` when
/// either fails.
fn assert_pair_matches<B: Backend>(backend: B, first: &[u8; 32], second: &[u8; 32]) {
    let expected = GAffine::decompress(first).zip(GAffine::decompress(second));
    assert_eq!(
        backend
            .decompress_pair([first, second])
            .map(|[a, b]| (key(Some(a)), key(Some(b)))),
        expected.map(|(a, b)| (key(Some(a)), key(Some(b)))),
        "decompress pair"
    );
}

/// The number of caches a chain of single-point operations saves addition operands in.
const CACHES: usize = 2;

/// One operation of a chain that feeds each native result into the next operation.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// Doubles the point, finishing the previous result in projective coordinates, or in
    /// extended coordinates and then projecting it when `extended` is set.
    Double { extended: bool },
    /// Prepares the point as an addition operand and saves it in cache `slot`.
    Cache { slot: usize },
    /// Adds the operand saved in cache `slot`, negated when `negate` is set.
    Add { slot: usize, negate: bool },
    /// Adds the affine operand, negated when `negate` is set.
    AddNiels { negate: bool },
    /// Adds the row's entry that `digit` selects, negated when `digit` is negative, or the
    /// identity when `digit` is zero.
    AddSelected { digit: i8 },
}

impl<'a> Arbitrary<'a> for Step {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=4)? {
            0 => Self::Double {
                extended: u.arbitrary()?,
            },
            1 => Self::Cache {
                slot: u.int_in_range(0..=CACHES - 1)?,
            },
            2 => Self::Add {
                slot: u.int_in_range(0..=CACHES - 1)?,
                negate: u.arbitrary()?,
            },
            3 => Self::AddNiels {
                negate: u.arbitrary()?,
            },
            _ => Self::AddSelected {
                digit: u.int_in_range(-8..=8)?,
            },
        })
    }
}

/// A chain's current point, in a backend's native representation and as the portable backend computes
/// it.
enum Link<B: Backend> {
    /// A point in extended coordinates.
    Extended(B::Extended, G),
    /// The result of an addition or doubling, before its final multiplications.
    Completed(B::Completed, GCompleted),
}

impl<B: Backend> Link<B> {
    /// Finishes the point in extended coordinates, asserting that the native point stores as the
    /// portable point.
    fn extended(self, backend: B, property: &str) -> (B::Extended, G) {
        match self {
            Self::Extended(actual, expected) => (actual, expected),
            Self::Completed(actual, expected) => {
                let actual = backend.to_extended(actual);
                let expected = super::portable::Backend::new().to_extended(expected);
                assert_g_same(backend.store(actual), expected, property);
                (actual, expected)
            }
        }
    }

    /// Finishes or projects the point in projective coordinates, asserting that the native point
    /// stores as the portable point.
    fn projective(self, backend: B, property: &str) -> (B::Projective, GProjective) {
        let (actual, expected) = match self {
            Self::Extended(actual, expected) => (
                backend.project(actual),
                super::portable::Backend::new().project(expected),
            ),
            Self::Completed(actual, expected) => (
                backend.to_projective(actual),
                super::portable::Backend::new().to_projective(expected),
            ),
        };
        assert_projective_same(backend.store_projective(actual), expected, property);
        (actual, expected)
    }
}

/// Inputs for comparing every [`Backend`] point operation with the portable backend.
struct PointMatches {
    /// The point every operation starts from.
    p: G,
    /// The operand of additions in extended form.
    q: G,
    /// An affine operand.
    niels: Niels,
    /// The row that fixed-base additions select from: a row of the fixed-base table or arbitrary
    /// entries.
    row: [Niels; 8],
    /// An entry of the flattened verification table, below 128.
    odd: usize,
    /// The operations of a chain starting from `p`.
    chain: Vec<Step>,
    /// Point encodings, valid or not.
    encodings: [[u8; 32]; 2],
}

impl WithBackend for PointMatches {
    type Output = ();

    fn call<B: Backend>(self, backend: B) {
        let portable = super::portable::Backend::new();
        let p = backend.load(&self.p);
        let q = backend.load(&self.q);
        assert_g_same(backend.store(p), self.p, "load and store");
        assert_g_same(backend.store(backend.identity()), G::IDENTITY, "identity");

        // Each operation's completed point matches in both finished forms.
        let check = |actual: B::Completed, expected: GCompleted, property: &str| {
            assert_g_same(
                backend.store(backend.to_extended(actual)),
                portable.to_extended(expected),
                property,
            );
            assert_projective_same(
                backend.store_projective(backend.to_projective(actual)),
                portable.to_projective(expected),
                property,
            );
        };
        check(
            backend.double(backend.project(p)),
            portable.double(portable.project(self.p)),
            "double",
        );
        for negate in [false, true] {
            check(
                backend.add_cached(p, backend.cache(q), negate),
                portable.add_cached(self.p, portable.cache(self.q), negate),
                "add",
            );
            for niels in [&self.niels, &super::ODD_MULTIPLES.as_flattened()[self.odd]] {
                check(
                    backend.add_niels(p, niels, negate),
                    portable.add_niels(self.p, niels, negate),
                    "add Niels",
                );
            }
        }
        for digit in -8..=8 {
            check(
                backend.add_selected(p, &self.row, digit),
                portable.add_selected(self.p, &self.row, digit),
                &format!("add selected, digit {digit}"),
            );
        }

        // The chain feeds each native result into the next operation, as the algorithms do,
        // finishing it in the coordinates that operation reads, and compares every finished point
        // with the portable backend. Each cache starts as `q`.
        let mut caches = [(backend.cache(q), portable.cache(self.q)); CACHES];
        let mut link = Link::<B>::Extended(p, self.p);
        for (index, &step) in self.chain.iter().enumerate() {
            let property = format!("chain input of step {index}, {step:?}");
            link = match step {
                Step::Double { extended: false } => {
                    let (actual, expected) = link.projective(backend, &property);
                    Link::Completed(backend.double(actual), portable.double(expected))
                }
                Step::Double { extended: true } => {
                    let (actual, expected) = link.extended(backend, &property);
                    Link::Completed(
                        backend.double(backend.project(actual)),
                        portable.double(portable.project(expected)),
                    )
                }
                Step::Cache { slot } => {
                    let (actual, expected) = link.extended(backend, &property);
                    caches[slot] = (backend.cache(actual), portable.cache(expected));
                    Link::Extended(actual, expected)
                }
                Step::Add { slot, negate } => {
                    let (actual, expected) = link.extended(backend, &property);
                    let (cached, expected_cached) = caches[slot];
                    Link::Completed(
                        backend.add_cached(actual, cached, negate),
                        portable.add_cached(expected, expected_cached, negate),
                    )
                }
                Step::AddNiels { negate } => {
                    let (actual, expected) = link.extended(backend, &property);
                    Link::Completed(
                        backend.add_niels(actual, &self.niels, negate),
                        portable.add_niels(expected, &self.niels, negate),
                    )
                }
                Step::AddSelected { digit } => {
                    let (actual, expected) = link.extended(backend, &property);
                    Link::Completed(
                        backend.add_selected(actual, &self.row, digit),
                        portable.add_selected(expected, &self.row, digit),
                    )
                }
            };
        }
        if let Link::Completed(actual, expected) = link {
            check(actual, expected, "chain result");
        }

        // Decompression agrees with the scalar path, including for invalid encodings.
        let [first, second] = &self.encodings;
        assert_eq!(
            key(backend.decompress(first)),
            key(GAffine::decompress(first))
        );
        assert_pair_matches(backend, first, second);
        assert_pair_matches(backend, second, first);
    }
}

#[cfg(test)]
#[test]
fn minifuzz_point() {
    // Fully inlined point formulas can exceed the test harness's default stack in debug builds.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(400)
                .test(|u| Plan::Point.run(u));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Checks the selected backend's single-point operations against the portable backend on the identity,
/// every ZIP215 point (each low-order point among them), sums with the basepoint, equal and
/// opposite operands, every row of the fixed-base table with reduced and with spread limbs, and
/// coordinates and table entries at or near the field bound, each with every digit and through a
/// chain of every transition between operations.
#[cfg(test)]
#[test]
fn single_point_operations_match_portable() {
    struct Run(Vec<PointMatches>);

    impl WithBackend for Run {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            for check in self.0 {
                check.call(backend);
            }
        }
    }

    // Doublings finished in both coordinate systems after doublings and additions, caches of
    // finished results reused under both signs, and signed affine and selected additions.
    const CHAIN: [Step; 18] = [
        Step::Double { extended: false },
        Step::Double { extended: false },
        Step::Double { extended: true },
        Step::Cache { slot: 0 },
        Step::Add {
            slot: 0,
            negate: false,
        },
        Step::AddNiels { negate: true },
        Step::Double { extended: false },
        Step::Add {
            slot: 0,
            negate: true,
        },
        Step::Add {
            slot: 1,
            negate: false,
        },
        Step::AddSelected { digit: -8 },
        Step::Cache { slot: 1 },
        Step::Double { extended: true },
        Step::AddSelected { digit: 5 },
        Step::Add {
            slot: 1,
            negate: true,
        },
        Step::AddNiels { negate: false },
        Step::Double { extended: true },
        Step::AddSelected { digit: 0 },
        Step::Double { extended: false },
    ];

    let base = GAffine::BASEPOINT.to_extended();
    let mut points = vec![G::IDENTITY, base, base.add(base)];
    for encoding in &ZIP215_POINTS {
        let point = GAffine::decompress(encoding).unwrap().to_extended();
        points.extend([point, base.add(point)]);
    }

    // Every row of the fixed-base table, then each again with its limbs spread.
    let table = &super::basepoint::TABLE;
    let mut rows = table.to_vec();
    for (j, row) in table.iter().enumerate() {
        let choice = j as u8;
        rows.push(row.map(|entry| Niels {
            sum: spread_limbs(entry.sum, choice),
            diff: spread_limbs(entry.diff, choice.rotate_left(1)),
            t2d: spread_limbs(entry.t2d, choice.rotate_left(2)),
        }));
    }

    let encodings = [ZIP215_POINTS[0], [0xff; 32]];
    let mut checks = Vec::new();
    for (i, &p) in points.iter().enumerate() {
        let p = rescale(p, F::from_bytes(&[i as u8 + 2; 32]), i as u8);
        for q in [points[(i + 1) % points.len()], p, p.negate(), G::IDENTITY] {
            let n = checks.len();
            checks.push(PointMatches {
                p,
                q,
                niels: niels(q),
                row: rows[n % rows.len()],
                odd: n % 128,
                chain: CHAIN.to_vec(),
                encodings,
            });
        }
    }

    // Coordinates at the field bound need not form a curve point; the formulas still must match
    // coordinate-wise. The table entries near the bound are distinct, so selecting the wrong
    // entry fails too.
    let max = F([MASK_52; 5]);
    let bound = G {
        x: max,
        y: max,
        t: max,
        z: max,
    };
    let near = |offset: usize| F([MASK_52 - offset as u64; 5]);
    checks.push(PointMatches {
        p: bound,
        q: bound,
        niels: Niels {
            sum: max,
            diff: max,
            t2d: max,
        },
        row: array::from_fn(|k| Niels {
            sum: near(3 * k),
            diff: near(3 * k + 1),
            t2d: near(3 * k + 2),
        }),
        odd: 127,
        chain: CHAIN.to_vec(),
        encodings,
    });
    super::with_backend(Run(checks));
}

/// Checks the selected backend's paired decompression against two scalar decompressions for
/// every ordered pair of ZIP215 points, the basepoint, and undecodable encodings, so that the
/// first, the second, both, or neither fail.
#[cfg(test)]
#[test]
fn decompress_pair_matches_scalar() {
    struct Check(Vec<[u8; 32]>);

    impl WithBackend for Check {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            for first in &self.0 {
                for second in &self.0 {
                    assert_pair_matches(backend, first, second);
                }
            }
        }
    }

    // The ZIP215 points, the basepoint, and the first encodings that do not decode.
    let mut encodings = ZIP215_POINTS.to_vec();
    encodings.push(GAffine::BASEPOINT.compress());
    let undecodable = (2u8..)
        .map(|y| {
            let mut encoding = [0; 32];
            encoding[0] = y;
            encoding
        })
        .filter(|encoding| GAffine::decompress(encoding).is_none())
        .take(3);
    encodings.extend(undecodable);
    super::with_backend(Check(encodings));
}

/// Checks the runtime dispatch path as one multi-operation computation.
#[test]
fn with_backend_matches_portable() {
    #[derive(Clone, Copy)]
    struct DispatchComputation {
        field: FVec,
        point: G,
        affine: GAffine,
    }

    impl WithBackend for DispatchComputation {
        type Output = (FVec, G);

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let field = backend.sub(
                backend.add(
                    backend.mul(self.field, FVec::splat(self.point.x)),
                    backend.square(FVec::splat(self.point.y)),
                ),
                backend.neg(self.field),
            );
            (field, backend.with_lanes(self))
        }
    }

    impl WithLanes for DispatchComputation {
        type Output = G;

        fn call<L: msm::Lanes<N>, const N: usize>(self, lanes: L) -> G {
            let point = lanes.load_extended([&self.point; N]);
            let affine = lanes.load([&self.affine; N]);
            let chained = lanes.add_mixed(lanes.add(lanes.double(point), point), affine);
            lanes.store(chained)[0]
        }
    }

    let portable = super::portable::Backend::new();
    let point = GAffine::BASEPOINT
        .to_extended()
        .scalar_mul((0..4).rev().map(|bit| 13u32 & (1 << bit) != 0));
    let computation = DispatchComputation {
        field: FVec::splat(point.x),
        point,
        affine: GAffine::BASEPOINT,
    };
    let expected = WithBackend::call(computation, portable);
    let actual = super::with_backend(computation);
    assert_f_eq(actual.0, expected.0, "runtime-dispatched field computation");
    assert_g_eq(actual.1, expected.1, "runtime-dispatched group computation");
}

#[test]
fn bucket_fill_matches_scalar_sum_for_every_geometry() {
    fn check<const STRIPES: usize>() {
        const NB: usize = 7;
        let torsion = GAffine::decompress(&[0; 32]).unwrap();
        let mixed = GAffine::decompress(
            &GAffine::BASEPOINT
                .to_extended()
                .add(torsion.to_extended())
                .compress(),
        )
        .unwrap();
        let points = [GAffine::IDENTITY, GAffine::BASEPOINT, torsion, mixed];
        let digits = [0, 1, -1, 7, -7, 3, 3, -3, 7];
        let terms: [(GAffine, i16); 53] = array::from_fn(|i| {
            let digit = if i < 16 {
                0
            } else {
                digits[(i - 16) % digits.len()]
            };
            (points[i % points.len()], digit)
        });
        let expected = terms.iter().fold(G::IDENTITY, |sum, &(point, digit)| {
            let point = point.to_extended();
            let point = if digit < 0 { point.negate() } else { point };
            (0..digit.unsigned_abs()).fold(sum, |sum, _| sum.add(point))
        });

        for split in [0, 1, 3, 17, 31, terms.len()] {
            let mut buckets = [[G::IDENTITY; NB]; STRIPES];
            for piece in [&terms[..split], &terms[split..]] {
                super::msm::fill_buckets(
                    |current: [G; STRIPES], incoming, negative| {
                        array::from_fn(|lane| {
                            let mut point = incoming[lane];
                            if negative[lane] {
                                point.x = point.x.neg();
                                point.t2d = point.t2d.neg();
                            }
                            msm::Lanes::add_mixed(
                                super::portable::Backend::new(),
                                current[lane],
                                point,
                            )
                        })
                    },
                    buckets.as_flattened_mut(),
                    NB,
                    piece,
                    |(point, digit)| (point, *digit),
                );
            }
            let actual = buckets
                .iter()
                .flatten()
                .enumerate()
                .fold(G::IDENTITY, |sum, (i, &point)| {
                    (0..=i % NB).fold(sum, |sum, _| sum.add(point))
                });
            assert!(
                actual.add(expected.negate()).is_identity(),
                "stripes={STRIPES} split={split}"
            );
        }
    }

    check::<1>();
    check::<2>();
    check::<3>();
    check::<8>();
    check::<16>();
}

/// Each backend's lanes store exactly what they load and sum to the scalar sum of their points.
#[test]
fn lanes_store_and_sum_match_scalar() {
    struct Check;

    impl WithLanes for Check {
        type Output = ();

        fn call<L: msm::Lanes<N>, const N: usize>(self, lanes: L) {
            // Include prime-order, torsion and mixed-order points, plus identity and negation.
            let base = GAffine::BASEPOINT.to_extended();
            let torsion = GAffine::decompress(&[0; 32]).unwrap().to_extended();
            let points = [G::IDENTITY, base, torsion, base.add(torsion), base.negate()];

            // Rotate the fixtures through every active-lane mask.
            for offset in 0..points.len() {
                for mask in 0..1usize << N {
                    let inputs: [G; N] = array::from_fn(|lane| {
                        if mask & (1 << lane) != 0 {
                            points[(lane + offset) % points.len()]
                        } else {
                            G::IDENTITY
                        }
                    });
                    let loaded = lanes.load_extended(inputs.each_ref());

                    // Storage must preserve the exact coordinates, including loose field values.
                    for (stored, input) in lanes.store(loaded).into_iter().zip(inputs) {
                        assert_eq!(
                            [stored.x.0, stored.y.0, stored.t.0, stored.z.0],
                            [input.x.0, input.y.0, input.t.0, input.z.0],
                            "offset={offset} mask={mask:#x}"
                        );
                    }

                    // Summation must preserve torsion as well as the prime-order component.
                    let expected = inputs.into_iter().fold(G::IDENTITY, G::add);
                    assert!(
                        lanes.sum(loaded).add(expected.negate()).is_identity(),
                        "offset={offset} mask={mask:#x}"
                    );
                }
            }
        }
    }

    struct Run;

    impl WithBackend for Run {
        type Output = ();

        fn call<B: Backend>(self, backend: B) {
            backend.with_lanes(Check);
        }
    }

    Run.call(super::portable::Backend::new());
    super::with_backend(Run);
}
