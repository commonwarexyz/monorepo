//! Property suites shared by field and group backends.

use super::{Backend, F, FBackend, FVec, GAffineVec, GBackend, GVec, LANES, MASK_51, WithBackend};
use arbitrary::Unstructured;

const MASK_52: u64 = (1 << 52) - 1;

fn arbitrary_fvec(u: &mut Unstructured<'_>) -> arbitrary::Result<FVec> {
    let limbs: [[u64; LANES]; 5] = u.arbitrary()?;
    Ok(FVec {
        limbs: limbs.map(|row| row.map(|limb| limb & MASK_52)),
    })
}

fn canonical(mut limbs: [u64; 5]) -> [u64; 5] {
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

fn assert_f_eq(actual: FVec, expected: FVec, property: &str) {
    assert_bounded(actual);
    assert_bounded(expected);
    for lane in 0..LANES {
        let actual = canonical(actual.limbs.map(|limbs| limbs[lane]));
        let expected = canonical(expected.limbs.map(|limbs| limbs[lane]));
        assert_eq!(actual, expected, "{property}, lane {lane}");
    }
}

fn assert_f_nonzero(value: FVec, property: &str) {
    assert_bounded(value);
    for lane in 0..LANES {
        let value = canonical(value.limbs.map(|limbs| limbs[lane]));
        assert_ne!(value, [0; 5], "{property}, lane {lane}");
    }
}

fn identity() -> GVec {
    GVec {
        x: FVec::splat(F::ZERO),
        y: FVec::splat(F::ONE),
        t: FVec::splat(F::ZERO),
        z: FVec::splat(F::ONE),
    }
}

fn basepoint<B: FBackend>(backend: B) -> GVec {
    let x = FVec::splat(F([
        1738742601995546,
        1146398526822698,
        2070867633025821,
        562264141797630,
        587772402128613,
    ]));
    let y = FVec::splat(F([
        1801439850948184,
        1351079888211148,
        450359962737049,
        900719925474099,
        1801439850948198,
    ]));
    GVec {
        x,
        y,
        t: backend.mul(x, y),
        z: FVec::splat(F::ONE),
    }
}

fn negate<B: FBackend>(backend: B, point: GVec) -> GVec {
    GVec {
        x: backend.neg(point.x),
        y: point.y,
        t: backend.neg(point.t),
        z: point.z,
    }
}

fn scale<B: GBackend>(backend: B, point: GVec, mut scalar: u32) -> GVec {
    let mut result = identity();
    let mut multiple = point;
    while scalar != 0 {
        if scalar & 1 == 1 {
            result = backend.g_add(result, multiple);
        }
        multiple = backend.g_double(multiple);
        scalar >>= 1;
    }
    result
}

fn assert_g_eq<B: FBackend>(backend: B, actual: GVec, expected: GVec, property: &str) {
    for coordinate in [actual.x, actual.y, actual.t, actual.z] {
        assert_bounded(coordinate);
    }
    for coordinate in [expected.x, expected.y, expected.t, expected.z] {
        assert_bounded(coordinate);
    }
    assert_f_nonzero(actual.z, property);
    assert_f_nonzero(expected.z, property);
    assert_f_eq(
        backend.mul(actual.x, expected.z),
        backend.mul(expected.x, actual.z),
        property,
    );
    assert_f_eq(
        backend.mul(actual.y, expected.z),
        backend.mul(expected.y, actual.z),
        property,
    );
    assert_f_eq(
        backend.mul(actual.t, expected.z),
        backend.mul(expected.t, actual.z),
        property,
    );
}

fn assert_on_curve<B: FBackend>(backend: B, point: GVec) {
    for coordinate in [point.x, point.y, point.t, point.z] {
        assert_bounded(coordinate);
    }
    assert_f_nonzero(point.z, "projective Z coordinate");
    let lhs = backend.sub(backend.square(point.y), backend.square(point.x));
    let rhs = backend.add(
        backend.square(point.z),
        backend.mul(FVec::splat(F::EDWARDS_D), backend.square(point.t)),
    );
    assert_f_eq(lhs, rhs, "curve equation");
    assert_f_eq(
        backend.mul(point.x, point.y),
        backend.mul(point.t, point.z),
        "extended-coordinate invariant",
    );
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
    let a = u.arbitrary::<u16>()?;
    let b = u.arbitrary::<u16>()?;
    let c = u.arbitrary::<u16>()?;
    let basepoint = basepoint(backend);
    let p = scale(backend, basepoint, u32::from(a));
    let q = scale(backend, basepoint, u32::from(b));
    let r = scale(backend, basepoint, u32::from(c));

    for point in [basepoint, p, q, r] {
        assert_on_curve(backend, point);
    }
    assert_g_eq(backend, backend.g_add(p, identity()), p, "right identity");
    assert_g_eq(backend, backend.g_add(identity(), p), p, "left identity");
    assert_g_eq(
        backend,
        backend.g_add(p, negate(backend, p)),
        identity(),
        "additive inverse",
    );
    assert_g_eq(
        backend,
        backend.g_add(p, q),
        backend.g_add(q, p),
        "addition commutes",
    );
    assert_g_eq(
        backend,
        backend.g_add(backend.g_add(p, q), r),
        backend.g_add(p, backend.g_add(q, r)),
        "addition associates",
    );
    assert_g_eq(
        backend,
        backend.g_double(p),
        backend.g_add(p, p),
        "doubling",
    );
    assert_g_eq(
        backend,
        backend.g_add(p, q),
        scale(backend, basepoint, u32::from(a) + u32::from(b)),
        "scalar addition",
    );

    let affine_basepoint = GAffineVec {
        x: basepoint.x,
        y: basepoint.y,
        t2d: backend.mul(basepoint.t, FVec::splat(F::EDWARDS_D2)),
    };
    assert_g_eq(
        backend,
        backend.g_add_mixed(p, affine_basepoint),
        backend.g_add(p, basepoint),
        "mixed addition",
    );
    Ok(())
}

/// Checks the field and group properties required of every backend.
pub(super) fn fuzz_backend<B: Backend>(
    u: &mut Unstructured<'_>,
    backend: B,
) -> arbitrary::Result<()> {
    if u.arbitrary()? {
        fuzz_field(u, backend)
    } else {
        fuzz_group(u, backend)
    }
}

/// Compares field operations at the loosest input allowed by [`FVec`].
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn check_backend_at_bounds<R: Backend, B: Backend>(reference: R, backend: B) {
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
}

/// Compares a backend's field and group operations with a reference backend.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn fuzz_backend_against<R: Backend, B: Backend>(
    u: &mut Unstructured<'_>,
    reference: R,
    backend: B,
) -> arbitrary::Result<()> {
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

    let scalar = u.arbitrary::<u16>()?;
    let basepoint = basepoint(reference);
    let point = scale(reference, basepoint, u32::from(scalar));
    let affine_basepoint = GAffineVec {
        x: basepoint.x,
        y: basepoint.y,
        t2d: reference.mul(basepoint.t, FVec::splat(F::EDWARDS_D2)),
    };
    assert_g_eq(
        reference,
        reference.g_double(point),
        backend.g_double(point),
        "backend doubling",
    );
    assert_g_eq(
        reference,
        reference.g_add(point, basepoint),
        backend.g_add(point, basepoint),
        "backend addition",
    );
    assert_g_eq(
        reference,
        reference.g_add_mixed(point, affine_basepoint),
        backend.g_add_mixed(point, affine_basepoint),
        "backend mixed addition",
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct DispatchComputation {
    field: FVec,
    point: GVec,
    affine: GAffineVec,
}

impl WithBackend for DispatchComputation {
    type Output = (FVec, GVec);

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let field = backend.sub(
            backend.add(
                backend.mul(self.field, self.point.x),
                backend.square(self.point.y),
            ),
            backend.neg(self.field),
        );
        let point = backend.g_add_mixed(
            backend.g_add(backend.g_double(self.point), self.point),
            self.affine,
        );
        (field, point)
    }
}

/// Checks the runtime dispatch path as one multi-operation computation.
#[test]
fn with_backend_matches_portable() {
    let portable = super::portable::Backend::new();
    let basepoint = basepoint(portable);
    let point = scale(portable, basepoint, 13);
    let computation = DispatchComputation {
        field: point.x,
        point,
        affine: GAffineVec {
            x: basepoint.x,
            y: basepoint.y,
            t2d: portable.mul(basepoint.t, FVec::splat(F::EDWARDS_D2)),
        },
    };
    let expected = computation.call(portable);
    let actual = super::with_backend(computation);
    assert_f_eq(actual.0, expected.0, "runtime-dispatched field computation");
    assert_g_eq(
        portable,
        actual.1,
        expected.1,
        "runtime-dispatched group computation",
    );
}
