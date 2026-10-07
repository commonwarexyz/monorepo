//! Property suites shared by field and group backends.

use super::{
    Backend, F, FBackend, FVec, G, GAffine, LANES, MASK_51, WithBackend,
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
                (lanes.add_mixed(loaded, mixed), point.add_mixed(affine)),
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
                            current[lane].add_mixed(point)
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
