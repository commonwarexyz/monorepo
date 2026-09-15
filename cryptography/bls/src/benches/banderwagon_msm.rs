use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{
    EdwardsAffine as ArkAffine, EdwardsProjective as ArkProjective, Fr as ArkScalar,
};
use ark_ff::{BigInteger, PrimeField};
use commonware_codec::{Copying, DecodeExt, Encode};
use commonware_cryptography::banderwagon::{F as ReferenceScalar, G as ReferenceGroup};
use commonware_cryptography_bls::banderwagon::{G, Scalar};
use commonware_math::algebra::Space;
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand_core::Rng;
use std::hint::black_box;

struct Fixtures {
    points: Vec<G>,
    scalars: Vec<Scalar>,
    reference_points: Vec<ReferenceGroup>,
    reference_scalars: Vec<ReferenceScalar>,
    ark_points: Vec<ArkAffine>,
    ark_scalars: Vec<ArkScalar>,
}

fn ark_scalar(scalar: &Scalar) -> ArkScalar {
    let bytes = scalar.to_bytes();
    let scalar = ArkScalar::from_le_bytes_mod_order(&bytes);
    let encoded = scalar.into_bigint().to_bytes_le();
    let mut canonical = [0; 32];
    canonical[..encoded.len()].copy_from_slice(&encoded);
    assert_eq!(canonical, bytes);
    scalar
}

fn ark_encoding(point: &ArkAffine) -> [u8; 32] {
    if point.is_zero() {
        return [0; 32];
    }
    let x = if point.y > -point.y {
        point.x
    } else {
        -point.x
    };
    let encoded = x.into_bigint().to_bytes_be();
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    bytes
}

fn scalar(rng: &mut impl Rng, bits: usize) -> Scalar {
    loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        match bits {
            128 => {
                bytes[16..].fill(0);
                bytes[15] |= 0x80;
            }
            253 => {
                bytes[31] &= 0x1f;
                bytes[31] |= 0x10;
            }
            _ => unreachable!(),
        }
        if let Some(scalar) = Scalar::from_bytes(&bytes) {
            return scalar;
        }
    }
}

fn fixtures(n: usize, bits: usize) -> Fixtures {
    let generator = G::generator();
    let mut rng = test_rng();
    let mut points = Vec::with_capacity(n);
    let mut scalars = Vec::with_capacity(n);
    let mut reference_points = Vec::with_capacity(n);
    let mut reference_scalars = Vec::with_capacity(n);
    let mut ark_points = Vec::with_capacity(n);
    let mut ark_scalars = Vec::with_capacity(n);
    for _ in 0..n {
        let weight = scalar(&mut rng, 253);
        let point = generator.mul(&weight);
        let point = G::from_bytes(&point.to_bytes()).unwrap();
        let scalar = scalar(&mut rng, bits);
        let scalar = Scalar::from_bytes(&scalar.to_bytes()).unwrap();
        let ark_point = ArkProjective::generator()
            .mul_bigint(ark_scalar(&weight).into_bigint())
            .into_affine();
        let ark_scalar = ark_scalar(&scalar);
        assert_eq!(point.to_bytes(), ark_encoding(&ark_point));
        reference_points.push(ReferenceGroup::decode(Copying(&point.to_bytes())).unwrap());
        reference_scalars.push(ReferenceScalar::decode(Copying(&scalar.to_bytes())).unwrap());
        points.push(point);
        scalars.push(scalar);
        ark_points.push(ark_point);
        ark_scalars.push(ark_scalar);
    }
    Fixtures {
        points,
        scalars,
        reference_points,
        reference_scalars,
        ark_points,
        ark_scalars,
    }
}

fn native_naive(points: &[G], scalars: &[Scalar]) -> G {
    points
        .iter()
        .zip(scalars)
        .fold(G::identity(), |sum, (point, scalar)| {
            sum.add(&point.mul(scalar))
        })
}

fn bench(c: &mut Criterion) {
    for n in [1, 10, 50, 100, 200, 1_000] {
        for bits in [128, 253] {
            let fixtures = fixtures(n, bits);
            let native = G::msm_vartime(&fixtures.points, &fixtures.scalars).unwrap();
            let naive = native_naive(&fixtures.points, &fixtures.scalars);
            let production = ReferenceGroup::msm(
                &fixtures.reference_points,
                &fixtures.reference_scalars,
                &Sequential,
            );
            let arkworks = ArkProjective::msm(&fixtures.ark_points, &fixtures.ark_scalars).unwrap();
            assert_eq!(native.to_bytes(), naive.to_bytes());
            assert_eq!(native.to_bytes().as_slice(), production.encode().as_ref());
            assert_eq!(native.to_bytes(), ark_encoding(&arkworks.into_affine()));

            c.bench_function(
                &format!("{}/n={n} bits={bits} impl=native", module_path!()),
                |b| {
                    b.iter(|| {
                        black_box(
                            G::msm_vartime(
                                black_box(&fixtures.points),
                                black_box(&fixtures.scalars),
                            )
                            .unwrap(),
                        )
                    })
                },
            );
            c.bench_function(
                &format!("{}/n={n} bits={bits} impl=native_naive", module_path!()),
                |b| {
                    b.iter(|| {
                        black_box(native_naive(
                            black_box(&fixtures.points),
                            black_box(&fixtures.scalars),
                        ))
                    })
                },
            );
            c.bench_function(
                &format!("{}/n={n} bits={bits} impl=production_naive", module_path!()),
                |b| {
                    b.iter(|| {
                        black_box(ReferenceGroup::msm(
                            black_box(&fixtures.reference_points),
                            black_box(&fixtures.reference_scalars),
                            &Sequential,
                        ))
                    })
                },
            );
            c.bench_function(
                &format!("{}/n={n} bits={bits} impl=arkworks", module_path!()),
                |b| {
                    b.iter(|| {
                        black_box(
                            ArkProjective::msm(
                                black_box(&fixtures.ark_points),
                                black_box(&fixtures.ark_scalars),
                            )
                            .unwrap(),
                        )
                    })
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
