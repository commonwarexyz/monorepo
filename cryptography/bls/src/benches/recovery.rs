use commonware_codec::{Copying, Decode as _, DecodeExt as _, Encode as _};
use commonware_cryptography::bls12381::primitives::group::{
    G1 as LegacyG1, G2 as LegacyG2, Scalar as LegacyScalar, ScalarReadCfg,
};
use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    recovery::RecoveryPlan,
    scalar::Scalar,
};
use commonware_math::poly::Interpolator;
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, ordered::Map};
use criterion::{Criterion, criterion_group};
use rand_core::Rng;
use std::hint::black_box;

const COUNTS: [usize; 10] = [5, 10, 20, 50, 100, 250, 500, 1000, 2000, 4000];
const ARBITRARY_COUNTS: [usize; 3] = [5, 100, 1000];
const ARBITRARY_POINT_SEED: u64 = 0x7265_636f_7665_7279;
const ORDER_BYTES: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

fn points(count: usize) -> Vec<Scalar> {
    (1..=count).map(|i| Scalar::from_u64(i as u64)).collect()
}

fn legacy_points(count: usize) -> Vec<LegacyScalar> {
    (1..=count)
        .map(|i| LegacyScalar::from_u64(i as u64))
        .collect()
}

fn scalar_below_order(offset: u64) -> Scalar {
    let mut bytes = ORDER_BYTES;
    let mut borrow = offset;
    for byte in bytes.iter_mut().rev() {
        let part = borrow as u8;
        let (value, underflow) = byte.overflowing_sub(part);
        *byte = value;
        borrow = (borrow >> 8) + u64::from(underflow);
    }
    assert_eq!(borrow, 0);
    Scalar::from_bytes(&bytes).unwrap()
}

fn arbitrary_points(count: usize) -> Vec<Scalar> {
    assert!(count >= 5);
    let mut points = vec![scalar_below_order(1), scalar_below_order(2)];
    let mut rng = TestRng::new(ARBITRARY_POINT_SEED);
    while points.len() < count {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        let point = Scalar::from_wide_bytes(&bytes);
        if !point.is_zero() && !points.contains(&point) {
            points.push(point);
        }
    }
    points
}

fn legacy_from_native(points: &[Scalar]) -> Vec<LegacyScalar> {
    points
        .iter()
        .map(|point| {
            LegacyScalar::decode_cfg(Copying(&point.to_bytes()), &ScalarReadCfg::AllowZero).unwrap()
        })
        .collect()
}

fn evaluations(points: &[Scalar]) -> Vec<Scalar> {
    let constant = Scalar::from_u64(7);
    let linear = Scalar::from_u64(3);
    let quadratic = Scalar::from_u64(5);
    points
        .iter()
        .map(|point| {
            constant
                .add(&linear.mul(point))
                .add(&quadratic.mul(&point.mul(point)))
        })
        .collect()
}

struct RecoveryFixture<N, L> {
    plan: RecoveryPlan,
    native: Vec<N>,
    interpolator: Interpolator<usize, LegacyScalar>,
    legacy: Map<usize, L>,
}

fn g1_fixture(count: usize) -> RecoveryFixture<G1, LegacyG1> {
    let points = points(count);
    let native: Vec<_> = evaluations(&points)
        .iter()
        .map(|evaluation| G1::generator().mul(evaluation))
        .collect();
    let plan = RecoveryPlan::new(&points).unwrap();
    let interpolator = Interpolator::new(legacy_points(count).into_iter().enumerate());
    let legacy = Map::from_iter_dedup(
        native
            .iter()
            .map(|partial| LegacyG1::decode(partial.to_bytes().to_vec()).unwrap())
            .enumerate(),
    );
    let native_output = plan.recover_g1(&native).unwrap();
    let legacy_output = interpolator.interpolate(&legacy, &Sequential).unwrap();
    assert!(!native_output.is_identity());
    assert_eq!(
        native_output.to_bytes().as_slice(),
        legacy_output.encode().as_ref()
    );
    RecoveryFixture {
        plan,
        native,
        interpolator,
        legacy,
    }
}

fn g2_fixture(count: usize) -> RecoveryFixture<G2, LegacyG2> {
    let points = points(count);
    let native: Vec<_> = evaluations(&points)
        .iter()
        .map(|evaluation| G2::generator().mul(evaluation))
        .collect();
    let plan = RecoveryPlan::new(&points).unwrap();
    let interpolator = Interpolator::new(legacy_points(count).into_iter().enumerate());
    let legacy = Map::from_iter_dedup(
        native
            .iter()
            .map(|partial| LegacyG2::decode(partial.to_bytes().to_vec()).unwrap())
            .enumerate(),
    );
    let native_output = plan.recover_g2(&native).unwrap();
    let legacy_output = interpolator.interpolate(&legacy, &Sequential).unwrap();
    assert!(!native_output.is_identity());
    assert_eq!(
        native_output.to_bytes().as_slice(),
        legacy_output.encode().as_ref()
    );
    RecoveryFixture {
        plan,
        native,
        interpolator,
        legacy,
    }
}

fn bench(c: &mut Criterion) {
    for count in COUNTS {
        c.bench_function(
            &format!(
                "{}/backend=native operation=plan count={count}",
                module_path!()
            ),
            |b| {
                let points = points(count);
                b.iter(|| black_box(RecoveryPlan::new(black_box(&points)).unwrap()));
            },
        );
        c.bench_function(
            &format!(
                "{}/backend=legacy operation=plan count={count}",
                module_path!()
            ),
            |b| {
                let points = legacy_points(count);
                b.iter(|| black_box(Interpolator::new(points.iter().cloned().enumerate())));
            },
        );

        c.bench_function(
            &format!(
                "{}/backend=native operation=recover_g1 count={count}",
                module_path!()
            ),
            |b| {
                let fixture = g1_fixture(count);
                b.iter(|| black_box(fixture.plan.recover_g1(black_box(&fixture.native)).unwrap()));
            },
        );
        c.bench_function(
            &format!(
                "{}/backend=legacy operation=recover_g1 count={count}",
                module_path!()
            ),
            |b| {
                let fixture = g1_fixture(count);
                b.iter(|| {
                    black_box(
                        fixture
                            .interpolator
                            .interpolate(&fixture.legacy, &Sequential)
                            .unwrap(),
                    )
                });
            },
        );

        c.bench_function(
            &format!(
                "{}/backend=native operation=recover_g2 count={count}",
                module_path!()
            ),
            |b| {
                let fixture = g2_fixture(count);
                b.iter(|| black_box(fixture.plan.recover_g2(black_box(&fixture.native)).unwrap()));
            },
        );
        c.bench_function(
            &format!(
                "{}/backend=legacy operation=recover_g2 count={count}",
                module_path!()
            ),
            |b| {
                let fixture = g2_fixture(count);
                b.iter(|| {
                    black_box(
                        fixture
                            .interpolator
                            .interpolate(&fixture.legacy, &Sequential)
                            .unwrap(),
                    )
                });
            },
        );
    }

    for count in ARBITRARY_COUNTS {
        c.bench_function(
            &format!(
                "{}/backend=native operation=plan input=arbitrary count={count}",
                module_path!()
            ),
            |b| {
                let points = arbitrary_points(count);
                b.iter(|| black_box(RecoveryPlan::new(black_box(&points)).unwrap()));
            },
        );
        c.bench_function(
            &format!(
                "{}/backend=legacy operation=plan input=arbitrary count={count}",
                module_path!()
            ),
            |b| {
                let points = legacy_from_native(&arbitrary_points(count));
                b.iter(|| black_box(Interpolator::new(points.iter().cloned().enumerate())));
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
