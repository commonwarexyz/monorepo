//! Receiver-side bytes-to-validated-G1 benchmarks for the private prototypes.
//!
//! Sender encoding and pairing equations are outside this boundary. All
//! decoding, on-curve validation, and subgroup-check setup are inside it.

use super::*;
use crate::bls12381::primitives::group::Scalar;
use commonware_codec::ReadExt;
use commonware_math::algebra::Random;
use commonware_utils::TestRng;
use criterion::{BatchSize, Criterion, SamplingMode, Throughput};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
enum Method {
    StandardIndividual,
    StandardBatched,
    TripleBatched,
    Optimized,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::StandardIndividual => "standard_individual",
            Self::StandardBatched => "standard_batched",
            Self::TripleBatched => "triple_batched",
            Self::Optimized => "optimized",
        }
    }

    fn joint(self) -> bool {
        matches!(self, Self::TripleBatched | Self::Optimized)
    }
}

const METHODS: [Method; 4] = [
    Method::StandardIndividual,
    Method::StandardBatched,
    Method::TripleBatched,
    Method::Optimized,
];

// Return points only after both curve and subgroup validation have succeeded.
fn receive(bytes: &[u8], method: Method, rng: &mut impl CryptoRng) -> Option<Vec<G1>> {
    if !bytes.len().is_multiple_of(48) {
        return None;
    }
    if matches!(method, Method::StandardIndividual) {
        return bytes
            .chunks_exact(48)
            .map(|bytes| G1::read(&mut Copying(bytes)).ok())
            .collect();
    }
    let points = if method.joint() {
        triple::decode(bytes)?
    } else {
        bytes
            .chunks_exact(48)
            .map(|bytes| G1::read_unchecked(&mut Copying(bytes)).ok())
            .collect::<Option<Vec<_>>>()?
    };
    // The graph has only established a performance win from 100,000 points,
    // and its research soundness bound covers at most three million inputs.
    let valid =
        if matches!(method, Method::Optimized) && (100_000..=3_000_000).contains(&points.len()) {
            two::certified_check(&points, rng)
        } else {
            batch_in_g1(&points, 128, &Sequential, rng)
        };
    valid.then_some(points)
}

fn encode(points: &[G1], method: Method) -> Vec<u8> {
    if method.joint() {
        triple::encode(points)
    } else {
        points.iter().flat_map(Encode::encode).collect()
    }
}

#[test]
fn receiving_validates_encoding_and_subgroup_before_returning_points() {
    let mut points = benchmark_points(37);
    points[1] = points[0];
    points[4] = -points[3];
    for method in METHODS {
        assert!(receive(&[], method, &mut test_rng()).unwrap().is_empty());
        for len in [1, 2, 3, 4, 35, 36, 37] {
            let bytes = encode(&points[..len], method);
            assert_eq!(
                receive(&bytes, method, &mut test_rng()).unwrap(),
                points[..len],
                "{method:?} len={len}",
            );
            assert!(receive(&bytes[..bytes.len() - 1], method, &mut test_rng()).is_none());
        }
        let mut bytes = encode(&points, method);
        if method.joint() {
            bytes[48] |= 0x40;
        } else {
            bytes[0] &= !0x80;
        }
        assert!(receive(&bytes, method, &mut test_rng()).is_none());

        // Both order-three and order-eleven pollution must be rejected even
        // though adding them preserves the curve equation.
        for torsion in [order_three(), order_eleven()] {
            for index in [0, 1, 2, 36] {
                let mut bad = points.clone();
                bad[index] += &torsion;
                let bytes = encode(&bad, method);
                assert!(receive(&bytes, method, &mut test_rng()).is_none());
            }
        }
    }
}

#[test]
fn receiving_uses_the_complete_certified_checker_on_large_batches() {
    let mut points = benchmark_points(100_000);
    let bytes = encode(&points, Method::Optimized);
    assert_eq!(
        receive(&bytes, Method::Optimized, &mut test_rng()).unwrap(),
        points,
    );
    // A nonmember in the final one-point tail must reach the subgroup check.
    *points.last_mut().unwrap() += &order_eleven();
    let bytes = encode(&points, Method::Optimized);
    assert_eq!(triple::decode(&bytes).unwrap(), points);
    assert!(receive(&bytes, Method::Optimized, &mut test_rng()).is_none());
}

#[test]
#[ignore = "manual Criterion bytes-to-validated-points benchmark"]
fn measure_wire_to_points() {
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/criterion");
    // Running Criterion inside an ignored test keeps the research codecs and
    // checker private instead of adding production APIs for benchmark access.
    let mut criterion = Criterion::default()
        .without_plots()
        .output_directory(&output)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    let mut group = criterion.benchmark_group(module_path!());
    group.sampling_mode(SamplingMode::Flat);
    for n in [1000, 6000, 100_000] {
        let mut rng = TestRng::new(0);
        let points: Vec<G1> = (0..n)
            .map(|_| {
                loop {
                    let point = G1::generator() * &Scalar::random(&mut rng);
                    if point != G1::zero() {
                        break point;
                    }
                }
            })
            .collect();
        let standard = encode(&points, Method::StandardBatched);
        let joint = encode(&points, Method::Optimized);
        assert_eq!(standard.len(), 48 * n);
        assert_eq!(joint.len(), standard.len());
        group.throughput(Throughput::Elements(n as u64));
        for method in METHODS {
            // The two triple paths are identical below the graph crossover.
            if n < 100_000 && matches!(method, Method::TripleBatched) {
                continue;
            }
            let bytes = if method.joint() { &joint } else { &standard };
            assert_eq!(receive(bytes, method, &mut test_rng()).unwrap(), points);
            let mut seed = 0u64;
            group.bench_function(format!("method={} n={n}", method.name()), |b| {
                b.iter_batched(
                    || (),
                    |()| {
                        seed = seed.wrapping_add(1);
                        // A fresh challenge, its setup, and all temporary
                        // allocations are charged to this invocation.
                        let mut rng = TestRng::new(seed);
                        black_box(receive(black_box(bytes), method, &mut rng).unwrap())
                    },
                    // Stop timing with the validated points still available
                    // to the caller; destroy the output after the interval.
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
    criterion.final_summary();
}
